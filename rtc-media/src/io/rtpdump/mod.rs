//! Reading and writing the RTPDump file format.
//!
//! RTPDump is the format of the classic `rtptools` `rtpdump`/`rtpplay`: a text preamble line
//! `#!rtpplay1.0 <address>/<port>\n`, a 16-byte binary header with the start of the recording,
//! the source address and port, and then one record per RTP or RTCP packet: an 8-byte header
//! (record length, packet length, offset in milliseconds) followed by the packet's bytes.
//!
//! [`Reader`](crate::io::rtpdump::Reader) and [`Writer`](crate::io::rtpdump::Writer) are
//! byte-compatible with pion's `pkg/media/rtpdump` (pion/webrtc v4.2.24) for every file pion
//! writes. Two strictnesses go beyond pion, both mandated by the issue that added this module
//! and both tested: a record whose `plen` exceeds its `length` (a truncated RTP recording, which
//! the rtptools format allows and pion's reader tolerates) and a record with an empty payload
//! are rejected instead of returned.

#[cfg(test)]
mod rtpdump_test;

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shared::error::{Error, Result};

/// The size of the binary header that follows the preamble line, in bytes.
pub const HEADER_LEN: usize = 16;
/// The size of each packet record's header, in bytes.
pub const PACKET_HEADER_LEN: usize = 8;
/// The number of leading bytes the preamble line is matched within, as pion peeks.
const PREAMBLE_WINDOW: usize = 36;
/// The largest record a 16-bit length field can describe, header included.
const MAX_RECORD_LEN: usize = u16::MAX as usize;

/// The binary header at the top of an RTPDump file: the start of the recording, the network
/// source it was recorded from, and its UDP port.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Header {
    /// The start of the recording, in GMT.
    pub start: SystemTime,
    /// The network source, an IPv4 address.
    pub source: Ipv4Addr,
    /// The UDP port.
    pub port: u16,
}

impl Header {
    /// Encodes the header as the 16 bytes that follow the preamble line.
    ///
    /// # Errors
    ///
    /// Never fails; the `Result` keeps the shape pion's API has.
    pub fn marshal(&self) -> Result<[u8; HEADER_LEN]> {
        let mut data = [0u8; HEADER_LEN];
        let (sec, usec) = unix_parts(self.start);
        data[..4].copy_from_slice(&sec.to_be_bytes());
        data[4..8].copy_from_slice(&usec.to_be_bytes());
        data[8..12].copy_from_slice(&self.source.octets());
        data[12..14].copy_from_slice(&self.port.to_be_bytes());
        // data[14..16] is padding.
        Ok(data)
    }

    /// Decodes the header from the 16 bytes that follow the preamble line.
    ///
    /// # Errors
    ///
    /// Fails if fewer than [`HEADER_LEN`] bytes are given.
    pub fn unmarshal(data: &[u8]) -> Result<Header> {
        if data.len() < HEADER_LEN {
            return Err(Error::ErrRtpDumpMalformed);
        }
        let sec = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let usec = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        Ok(Header {
            start: UNIX_EPOCH
                + Duration::from_secs(u64::from(sec))
                + Duration::from_micros(u64::from(usec)),
            source: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            port: u16::from_be_bytes([data[12], data[13]]),
            // data[14..16] is padding.
        })
    }
}

/// One RTP or RTCP packet and the time it was logged, relative to the recording's start.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The time since the start of the recording.
    pub offset: Duration,
    /// Whether the payload is RTCP (`true`) or RTP (`false`).
    pub is_rtcp: bool,
    /// The packet's bytes, which may have been truncated by the recorder.
    pub payload: Vec<u8>,
}

impl Packet {
    /// Encodes the packet as one record: its 8-byte header followed by the payload.
    ///
    /// # Errors
    ///
    /// Fails if the payload does not fit a 16-bit record length. pion would silently wrap the
    /// length and write an unreadable record; this writer refuses.
    pub fn marshal(&self) -> Result<Vec<u8>> {
        let record_len = self.payload.len() + PACKET_HEADER_LEN;
        if record_len > MAX_RECORD_LEN {
            return Err(Error::ErrRtpDumpPacketTooLarge);
        }
        let packet_len = if self.is_rtcp { 0 } else { self.payload.len() };
        let mut data = Vec::with_capacity(record_len);
        data.extend_from_slice(&(record_len as u16).to_be_bytes());
        data.extend_from_slice(&(packet_len as u16).to_be_bytes());
        data.extend_from_slice(&offset_ms(self.offset).to_be_bytes());
        data.extend_from_slice(&self.payload);
        Ok(data)
    }

    /// Decodes one record, as [`Packet::marshal`] wrote it, from `data`.
    ///
    /// # Errors
    ///
    /// Fails if the record header is shorter than 8 bytes, or `data` ends before the record's
    /// length says it should.
    pub fn unmarshal(data: &[u8]) -> Result<Packet> {
        if data.len() < PACKET_HEADER_LEN {
            return Err(Error::ErrRtpDumpMalformed);
        }
        let length = u16::from_be_bytes([data[0], data[1]]);
        let packet_length = u16::from_be_bytes([data[2], data[3]]);
        let offset = Duration::from_millis(u64::from(u32::from_be_bytes([
            data[4], data[5], data[6], data[7],
        ])));
        if (length as usize) < PACKET_HEADER_LEN {
            return Err(Error::ErrRtpDumpMalformed);
        }
        if data.len() < length as usize {
            return Err(Error::ErrRtpDumpMalformed);
        }
        Ok(Packet {
            offset,
            is_rtcp: packet_length == 0,
            payload: data[PACKET_HEADER_LEN..length as usize].to_vec(),
        })
    }
}

/// The record's offset in whole milliseconds, truncated like pion's integer division.
fn offset_ms(offset: Duration) -> u32 {
    offset.as_millis() as u32
}

/// Splits a timestamp into the seconds and microseconds a header stores, wrapping negative
/// times the way pion's `uint32` casts do.
fn unix_parts(t: SystemTime) -> (u32, u32) {
    let nanos: i128 = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    };
    // Rust's integer division truncates toward zero, like Go's.
    (
        (nanos / 1_000_000_000) as u32,
        ((nanos % 1_000_000_000) / 1_000) as u32,
    )
}

/// Reads the RTPDump file format.
pub struct Reader<R> {
    reader: R,
    /// Bytes read while looking ahead for the preamble that the stream has not consumed yet.
    pending: VecDeque<u8>,
}

/// The outcome of trying to fill a buffer completely from the stream.
enum Fill {
    /// The buffer is full.
    Full,
    /// The stream ended before any byte was read.
    Eof,
    /// The stream ended part-way through the buffer.
    Truncated,
}

impl<R: Read> Reader<R> {
    /// Opens a reader, consuming the preamble line and the binary header from the stream.
    ///
    /// # Errors
    ///
    /// Fails if the stream ends before the 36 bytes the preamble is matched within, the
    /// preamble line does not parse, or the binary header is short. I/O errors other than a
    /// clean end of file pass through.
    pub fn new(mut reader: R) -> Result<(Self, Header)> {
        let mut window = [0u8; PREAMBLE_WINDOW];
        let mut filled = 0;
        while filled < PREAMBLE_WINDOW {
            match reader.read(&mut window[filled..]) {
                Ok(0) => return Err(Error::ErrRtpDumpMalformed),
                Ok(n) => filled += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }

        if !preamble_matches(&window) {
            return Err(Error::ErrRtpDumpMalformed);
        }

        // Consume the preamble line: everything through its first newline.
        let newline = window
            .iter()
            .position(|&b| b == b'\n')
            .expect("the preamble regexp matched, so a newline is in the window");
        let mut pending = VecDeque::with_capacity(PREAMBLE_WINDOW - newline - 1);
        pending.extend(&window[newline + 1..]);

        let mut reader = Reader { reader, pending };
        let mut header_buf = [0u8; HEADER_LEN];
        match reader.fill(&mut header_buf)? {
            Fill::Eof | Fill::Truncated => return Err(Error::ErrRtpDumpMalformed),
            Fill::Full => {}
        }
        let header = Header::unmarshal(&header_buf)?;
        Ok((reader, header))
    }

    /// Reads the next packet record, or `None` at a clean end of file.
    ///
    /// # Errors
    ///
    /// Fails if the stream ends part-way through a record, or the record is malformed: a
    /// length of zero, a length shorter than the record header, a `plen` greater than the
    /// record length, or an empty payload.
    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        let mut header_buf = [0u8; PACKET_HEADER_LEN];
        match self.fill(&mut header_buf)? {
            Fill::Eof => return Ok(None),
            Fill::Truncated => return Err(Error::ErrRtpDumpMalformed),
            Fill::Full => {}
        }
        let length = u16::from_be_bytes([header_buf[0], header_buf[1]]);
        let packet_length = u16::from_be_bytes([header_buf[2], header_buf[3]]);
        let offset = Duration::from_millis(u64::from(u32::from_be_bytes([
            header_buf[4],
            header_buf[5],
            header_buf[6],
            header_buf[7],
        ])));

        if length == 0 {
            return Err(Error::ErrRtpDumpMalformed);
        }
        // A record shorter than its own header. pion would subtract 8 from the 16-bit length,
        // wrap to nearly 64 KiB, and fail reading that much — every real file gets
        // `errMalformed` from it too, just the long way around.
        if (length as usize) < PACKET_HEADER_LEN {
            return Err(Error::ErrRtpDumpMalformed);
        }
        // The record claims more packet bytes than it holds. rtptools uses this direction for
        // truncated RTP recordings, which pion's reader tolerates; this reader rejects it.
        if packet_length > length {
            return Err(Error::ErrRtpDumpMalformed);
        }
        let payload_len = length as usize - PACKET_HEADER_LEN;
        if payload_len == 0 {
            return Err(Error::ErrRtpDumpMalformed);
        }

        let mut payload = vec![0u8; payload_len];
        match self.fill(&mut payload)? {
            // The record claims more bytes than the file holds.
            Fill::Eof | Fill::Truncated => return Err(Error::ErrRtpDumpMalformed),
            Fill::Full => {}
        }

        Ok(Some(Packet {
            offset,
            is_rtcp: packet_length == 0,
            payload,
        }))
    }

    /// Fills `out` from the bytes left over from the preamble window, then the stream.
    fn fill(&mut self, mut out: &mut [u8]) -> Result<Fill> {
        let mut read = 0;
        while !out.is_empty() {
            if let Some(byte) = self.pending.pop_front() {
                out[0] = byte;
                out = &mut out[1..];
                read += 1;
                continue;
            }
            match self.reader.read(out) {
                Ok(0) => {
                    return Ok(if read == 0 {
                        Fill::Eof
                    } else {
                        Fill::Truncated
                    });
                }
                Ok(n) => {
                    out = &mut out[n..];
                    read += n;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Fill::Full)
    }
}

/// Writes the RTPDump file format.
pub struct Writer<W> {
    writer: W,
}

impl<W: Write> Writer<W> {
    /// Creates a writer and immediately writes the preamble line and the binary header.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error while writing.
    pub fn new(mut writer: W, header: &Header) -> Result<Self> {
        let preamble = format!("#!rtpplay1.0 {}/{}\n", header.source, header.port);
        writer.write_all(preamble.as_bytes())?;
        writer.write_all(&header.marshal()?)?;
        Ok(Self { writer })
    }

    /// Writes one packet record.
    ///
    /// # Errors
    ///
    /// Fails on an I/O error, or if the packet does not fit a 16-bit record length.
    pub fn write_packet(&mut self, packet: &Packet) -> Result<()> {
        self.writer.write_all(&packet.marshal()?)?;
        Ok(())
    }
}

/// Whether the window matches pion's preamble regexp
/// `#!rtpplay1\.0 \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,5}\n` anywhere within it.
fn preamble_matches(window: &[u8]) -> bool {
    const MAGIC: &[u8] = b"#!rtpplay1.0 ";
    (0..window.len()).any(|start| {
        let rest = &window[start..];
        rest.starts_with(MAGIC) && address_port_line(&rest[MAGIC.len()..])
    })
}

/// `d{1,3}.d{1,3}.d{1,3}.d{1,3}/d{1,5}\n`: an IPv4 address and a port, then a newline.
///
/// Greedy digit runs are enough: the character after them must be a separator, so the regular
/// expression's backtracking cannot rescue a match this misses.
fn address_port_line(b: &[u8]) -> bool {
    let mut rest = digits(b, 1, 3);
    for _ in 0..3 {
        match rest {
            Some(r) if r.first() == Some(&b'.') => rest = digits(&r[1..], 1, 3),
            _ => return false,
        }
    }
    match rest {
        Some(r) if r.first() == Some(&b'/') => match digits(&r[1..], 1, 5) {
            Some(r) => r.first() == Some(&b'\n'),
            None => false,
        },
        _ => false,
    }
}

/// Consumes between `min` and `max` ASCII digits, returning what follows them.
fn digits(b: &[u8], min: usize, max: usize) -> Option<&[u8]> {
    let mut rest = b;
    let mut n = 0;
    while n < max && rest.first().is_some_and(u8::is_ascii_digit) {
        rest = &rest[1..];
        n += 1;
    }
    (n >= min).then_some(rest)
}
