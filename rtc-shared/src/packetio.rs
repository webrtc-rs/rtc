//! A bounded packet queue with per-packet attributes: the sans-I/O counterpart of pion's
//! `packetio.Buffer`.
//!
//! [`Buffer`] queues *copies* of packets without ever combining two writes into one read.
//! Packets live back to back in a byte ring, each behind a two-byte length header; the
//! [`Attribute`]s written with a packet travel in a second ring and come back out with it. Both
//! rings grow on demand, up to a hard cap, and both are reused: once warmed up, a
//! write/read pair allocates nothing.
//!
//! The API is poll-style. Nothing blocks, no clock is read and no waker is stored: [`Buffer::read`]
//! on an empty buffer returns [`Error::Empty`], and the caller decides when to try again.
//!
//! # Limits
//!
//! * [`Buffer::set_limit_count`] bounds the number of queued packets.
//! * [`Buffer::set_limit_size`] bounds [`Buffer::size`], the queued payload bytes plus
//!   [`HEADER_SIZE`] framing bytes per packet. Attributes are not counted.
//!
//! A write that would break either limit fails with [`Error::Full`] and queues nothing. With no
//! size limit the storage stops at [`MAX_SIZE`] (one byte of which is reserved). The
//! `packetio-size-hardlimit` feature also caps explicit limits there, like pion's
//! `packetioSizeHardlimit` build tag.
//!
//! # Example
//!
//! ```
//! use rtc_shared::packetio::{Attribute, Buffer, Error};
//!
//! let mut buffer: Buffer<&str, u32> = Buffer::new();
//! buffer.write(b"hello", &[Attribute { key: "ttl", value: 64 }])?;
//!
//! let mut payload = [0u8; 16];
//! let mut attributes = Vec::new();
//! let n = buffer.read(&mut payload, &mut attributes)?;
//! assert_eq!(&payload[..n], b"hello");
//! assert_eq!(attributes[0].value, 64);
//!
//! assert_eq!(buffer.read(&mut payload, &mut attributes), Err(Error::Empty));
//! # Ok::<(), Error>(())
//! ```

use std::fmt;

/// Bytes of framing the buffer adds in front of every packet; they count towards
/// [`Buffer::size`].
pub const HEADER_SIZE: usize = 2;

/// Storage cap, in bytes, when no size limit is set (one byte of it stays unused).
pub const MAX_SIZE: usize = 4 * 1024 * 1024;

const MIN_SIZE: usize = 2048;
const CUTOFF_SIZE: usize = 128 * 1024;
const SIZE_HARD_LIMIT: bool = cfg!(feature = "packetio-size-hardlimit");

/// The largest payload a packet can carry, in bytes.
pub const MAX_PAYLOAD: usize = 0xFFFF;

/// Why a [`Buffer`] operation did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A write would exceed the size or count limit (or the storage cap); nothing was queued.
    Full,
    /// The payload is longer than [`MAX_PAYLOAD`].
    PacketTooBig,
    /// A write reached a closed buffer.
    Closed,
    /// A read found no packet and the buffer is still open: try again after the next write.
    Empty,
    /// A read found no packet and the buffer is closed and drained.
    Eof,
    /// The packet was longer than the read buffer. The packet is consumed, its attributes are
    /// complete, and `copied` bytes of its payload were written.
    ShortBuffer {
        /// Payload bytes that fit into the read buffer.
        copied: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Full => f.write_str("packetio.Buffer is full, discarding write"),
            Error::PacketTooBig => f.write_str("packet too big"),
            Error::Closed => f.write_str("io: read/write on closed pipe"),
            Error::Empty => f.write_str("no packet queued"),
            Error::Eof => f.write_str("EOF"),
            Error::ShortBuffer { .. } => f.write_str("short buffer"),
        }
    }
}

impl std::error::Error for Error {}

/// One entry of packet metadata. Keys are compared with `==`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute<K, V> {
    /// What the entry describes.
    pub key: K,
    /// The entry's value.
    pub value: V,
}

/// Lookup helpers for a packet's attribute list.
pub trait AttributesExt<K: PartialEq, V> {
    /// The first value stored under `key`.
    fn get(&self, key: &K) -> Option<&V>;
    /// Replaces the first entry for `key`, or appends one if `key` is absent.
    fn set(&mut self, key: K, value: V);
}

impl<K: PartialEq, V> AttributesExt<K, V> for Vec<Attribute<K, V>> {
    fn get(&self, key: &K) -> Option<&V> {
        self.iter().find(|a| a.key == *key).map(|a| &a.value)
    }

    fn set(&mut self, key: K, value: V) {
        match self.iter_mut().find(|a| a.key == key) {
            Some(entry) => entry.value = value,
            None => self.push(Attribute { key, value }),
        }
    }
}

/// A queue of packet copies with per-packet attributes. See the [module docs](self).
#[derive(Debug)]
pub struct Buffer<K = (), V = ()> {
    // A circular buffer. If head <= tail the useful data is [head, tail); if tail < head it is
    // [head, len) followed by [0, tail). One byte always stays unused, so head == tail means
    // empty.
    data: Vec<u8>,
    head: usize,
    tail: usize,

    closed: bool,

    count: usize,
    limit_count: usize,
    limit_size: usize,
    attributes: Vec<Vec<Attribute<K, V>>>,
    attributes_head: usize,
}

impl<K, V> Default for Buffer<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Buffer<K, V> {
    /// An empty, open buffer with no limits beyond the storage cap.
    pub fn new() -> Self {
        Buffer {
            data: Vec::new(),
            head: 0,
            tail: 0,
            closed: false,
            count: 0,
            limit_count: 0,
            limit_size: 0,
            attributes: Vec::new(),
            attributes_head: 0,
        }
    }

    /// Whether the ring can take a packet with `size` payload bytes plus its header.
    fn available(&self, size: usize) -> bool {
        let mut available = self.head as isize - self.tail as isize;
        if available <= 0 {
            available += self.data.len() as isize;
        }
        // head == tail is empty, so one byte stays free
        (size + HEADER_SIZE + 1) as isize <= available
    }

    /// Enlarges the byte ring, or reports [`Error::Full`] when a limit stops it.
    fn grow(&mut self) -> Result<(), Error> {
        let len = self.data.len();
        let mut new_size = if len < CUTOFF_SIZE {
            2 * len
        } else {
            5 * len / 4
        };
        new_size = new_size.max(MIN_SIZE);
        if (self.limit_size == 0 || SIZE_HARD_LIMIT) && new_size > MAX_SIZE {
            new_size = MAX_SIZE;
        }

        // one byte slack
        if self.limit_size > 0 && new_size - 1 > self.limit_size {
            new_size = self.limit_size.saturating_add(1);
        }

        if new_size <= len {
            return Err(Error::Full);
        }

        let mut new_data = vec![0u8; new_size];
        let n = if self.head <= self.tail {
            // data was contiguous
            let n = self.tail - self.head;
            new_data[..n].copy_from_slice(&self.data[self.head..self.tail]);
            n
        } else {
            // data was discontiguous
            let first = len - self.head;
            new_data[..first].copy_from_slice(&self.data[self.head..]);
            new_data[first..first + self.tail].copy_from_slice(&self.data[..self.tail]);
            first + self.tail
        };
        self.head = 0;
        self.tail = n;
        self.data = new_data;

        Ok(())
    }

    /// Queued bytes in the ring, headers included.
    fn used(&self) -> usize {
        if self.tail >= self.head {
            self.tail - self.head
        } else {
            self.tail + self.data.len() - self.head
        }
    }

    fn write_bytes(&mut self, src: &[u8]) {
        let n = src.len().min(self.data.len() - self.tail);
        self.data[self.tail..self.tail + n].copy_from_slice(&src[..n]);
        self.tail += n;
        if self.tail >= self.data.len() {
            let rest = &src[n..];
            self.data[..rest.len()].copy_from_slice(rest);
            self.tail = rest.len();
        }
    }

    /// Copies as much of `size` as fits into `dst` and discards the remainder.
    fn read_bytes(&mut self, dst: &mut [u8], size: usize) -> usize {
        let copied = dst.len().min(size);
        let len = self.data.len();
        if self.head + copied <= len {
            dst[..copied].copy_from_slice(&self.data[self.head..self.head + copied]);
        } else {
            let n = len - self.head;
            dst[..n].copy_from_slice(&self.data[self.head..]);
            dst[n..copied].copy_from_slice(&self.data[..copied - n]);
        }
        self.head += size;
        if self.head >= len {
            self.head -= len;
        }
        copied
    }

    fn grow_attributes(&mut self) {
        if self.count < self.attributes.len() {
            return;
        }
        let new_len = (2 * self.attributes.len()).max(1);
        let mut attributes: Vec<Vec<Attribute<K, V>>> = Vec::with_capacity(new_len);
        attributes.extend(self.attributes.drain(self.attributes_head..));
        attributes.append(&mut self.attributes);
        attributes.resize_with(new_len, Vec::new);
        self.attributes = attributes;
        self.attributes_head = 0;
    }

    /// The number of packets queued.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Queued payload bytes plus [`HEADER_SIZE`] framing bytes per packet.
    ///
    /// This measures logical packet bytes; attributes and spare capacity are excluded.
    pub fn size(&self) -> usize {
        self.used()
    }

    /// Whether no packet is queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether [`Buffer::close`] was called.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Bounds the number of queued packets; writes beyond it fail with [`Error::Full`].
    /// Zero disables the limit.
    pub fn set_limit_count(&mut self, limit: usize) {
        self.limit_count = limit;
    }

    /// Bounds [`Buffer::size`]; writes that would exceed it fail with [`Error::Full`].
    /// Attributes are excluded. Zero uses the default capacity of [`MAX_SIZE`], with one byte
    /// reserved.
    ///
    /// With the `packetio-size-hardlimit` feature the limit is capped at the default capacity.
    pub fn set_limit_size(&mut self, limit: usize) {
        self.limit_size = limit;
    }

    /// Closes the buffer. Queued packets stay readable; [`Buffer::read`] returns
    /// [`Error::Eof`] only once they are drained, and writes fail with [`Error::Closed`].
    /// Closing twice is harmless.
    pub fn close(&mut self) {
        self.closed = true;
    }
}

impl<K: Clone, V: Clone> Buffer<K, V> {
    /// Copies `payload` and `attributes` into the queue, atomically, and returns the payload
    /// length. Pass an empty slice for a packet without attributes.
    ///
    /// # Errors
    ///
    /// * [`Error::PacketTooBig`] if `payload` is longer than [`MAX_PAYLOAD`].
    /// * [`Error::Closed`] if the buffer is closed.
    /// * [`Error::Full`] if the packet would exceed the size or count limit.
    ///
    /// A failed write queues nothing.
    pub fn write(
        &mut self,
        payload: &[u8],
        attributes: &[Attribute<K, V>],
    ) -> Result<usize, Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PacketTooBig);
        }
        if self.closed {
            return Err(Error::Closed);
        }

        let size = payload.len() + HEADER_SIZE;
        let mut limit = self.limit_size;
        if limit == 0 || (SIZE_HARD_LIMIT && limit >= MAX_SIZE) {
            limit = MAX_SIZE - 1;
        }
        if (self.limit_count > 0 && self.count >= self.limit_count)
            || size > limit.saturating_sub(self.used())
        {
            return Err(Error::Full);
        }

        // grow the buffer until the packet fits
        while !self.available(payload.len()) {
            self.grow()?;
        }

        self.grow_attributes();
        self.write_bytes(&(payload.len() as u16).to_be_bytes());
        self.write_bytes(payload);
        let mut tail = self.attributes_head + self.count;
        if tail >= self.attributes.len() {
            tail -= self.attributes.len();
        }
        let slot = &mut self.attributes[tail];
        slot.clear();
        slot.extend_from_slice(attributes);
        self.count += 1;

        Ok(payload.len())
    }

    /// Consumes one packet: its payload goes into `payload_buf`, its attributes replace the
    /// contents of `attributes` (whose storage is reused), and the payload length is returned.
    ///
    /// `attributes` is cleared on every outcome, so it is empty after any error except
    /// [`Error::ShortBuffer`].
    ///
    /// # Errors
    ///
    /// * [`Error::ShortBuffer`] if `payload_buf` is too short: the packet is consumed anyway
    ///   and its attributes are complete.
    /// * [`Error::Empty`] if no packet is queued and the buffer is open.
    /// * [`Error::Eof`] if no packet is queued and the buffer is closed.
    pub fn read(
        &mut self,
        payload_buf: &mut [u8],
        attributes: &mut Vec<Attribute<K, V>>,
    ) -> Result<usize, Error> {
        attributes.clear();

        if self.head == self.tail {
            return Err(if self.closed {
                Error::Eof
            } else {
                Error::Empty
            });
        }

        let mut header = [0u8; HEADER_SIZE];
        self.read_bytes(&mut header, HEADER_SIZE);
        let payload_size = u16::from_be_bytes(header) as usize;
        let n = self.read_bytes(payload_buf, payload_size);
        // moves the entries out and leaves the slot empty, capacity kept
        attributes.append(&mut self.attributes[self.attributes_head]);
        self.attributes_head += 1;
        if self.attributes_head == self.attributes.len() {
            self.attributes_head = 0;
        }
        self.count -= 1;
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
            self.attributes_head = 0;
        }

        if n < payload_size {
            return Err(Error::ShortBuffer { copied: n });
        }
        Ok(n)
    }
}

#[cfg(test)]
#[path = "packetio_test.rs"]
mod packetio_test;
