//! MPEG4-GENERIC RTP payload format ([RFC 3640]).
//!
//! Supports the common "AAC-hbr" configuration (`sizeLength=13;indexLength=3;
//! indexDeltaLength=3` by default, configurable via [`Mpeg4GenericPayloader::new`]/
//! [`Mpeg4GenericDepacketizer::new`] to match whatever `sizeLength`/`indexLength` the SDP
//! `fmtp` line negotiated).
//!
//! Per [RFC 3640] §3.2.3.1: "A packet SHALL carry either one or more complete Access Units, or
//! a single fragment of an Access Unit." Both are supported:
//!
//! - [`Payloader::payload`]/[`Depacketizer::depacketize`] handle the single-AU case: one raw
//!   Access Unit (e.g. a raw/ADTS-less AAC frame) per call, fragmented across several RTP
//!   packets when it doesn't fit the MTU.
//! - [`Mpeg4GenericPayloader::payload_aus`]/[`Mpeg4GenericDepacketizer::depacketize_aus`] handle
//!   bundling several complete Access Units into one packet, for callers that have more than one
//!   ready to send at once (e.g. sharing one RTP timestamp) and interop with senders that bundle
//!   this way. These aren't part of the [`Payloader`]/[`Depacketizer`] traits, since no other
//!   codec in this crate needs multi-unit-per-packet bundling.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     AU-headers-length        |   AU-size (sizeLength bits)  ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ...-Index (indexLength bits)| ... more AU-headers, then padding |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                       |
//! |                                                               |
//! :         AU data (concatenated, one per AU-header)             :
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `AU-headers-length` gives the size, in bits, of the AU Header Section that follows (padded
//! with zero bits up to the next byte boundary); it is always a multiple of `sizeLength +
//! indexLength` — one multiple of it per AU-header packed back-to-back, matching the configured
//! `sizeLength`/`indexLength`. Per [RFC 3640] §3.2.1.1, **every** packet carries this header,
//! including every fragment of an Access Unit split across several packets — a fragment's
//! AU-header states the size of the *entire* Access Unit, not of the fragment in this packet.
//! RFC 3640 has no bit that marks a fragment as specifically the *first* one; reassembly instead
//! relies on the RTP timestamp (shared by all fragments of one Access Unit) and the marker bit
//! (set only on the last fragment) — see [`Depacketizer::is_partition_head`]'s and
//! [`Depacketizer::is_partition_tail`]'s docs on this impl for how that limits what this
//! depacketizer can and can't detect on its own.
//!
//! [RFC 3640]: https://datatracker.ietf.org/doc/html/rfc3640
#[cfg(test)]
mod mpeg4_generic_test;

use crate::packetizer::{Depacketizer, Payloader};
use shared::error::{Error, Result};

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// The default `sizeLength` fmtp parameter for AAC-hbr.
pub const DEFAULT_SIZE_LENGTH_BITS: u8 = 13;
/// The default `indexLength`/`indexDeltaLength` fmtp parameter for AAC-hbr.
pub const DEFAULT_INDEX_LENGTH_BITS: u8 = 3;

/// Bytes in the `AU-headers-length` field that precedes the AU Header Section. Always 16 bits,
/// regardless of the configured `sizeLength`/`indexLength`.
const AU_HEADERS_LENGTH_SIZE: usize = 2;

/// Writes the low `num_bits` bits of `value` into `out`, MSB-first, starting at `bit_offset`
/// (counted from the start of `out`, bit 0 being the MSB of `out[0]`). `num_bits` is at most 32.
fn write_bits(out: &mut [u8], bit_offset: usize, num_bits: u32, value: u32) {
    for i in 0..num_bits {
        let bit = (value >> (num_bits - 1 - i)) & 1;
        if bit != 0 {
            let pos = bit_offset + i as usize;
            out[pos / 8] |= 1 << (7 - pos % 8);
        }
    }
}

/// Reads `num_bits` bits from `data`, MSB-first, starting at `bit_offset`. Inverse of
/// [`write_bits`].
fn read_bits(data: &[u8], bit_offset: usize, num_bits: u32) -> u32 {
    let mut value = 0u32;
    for i in 0..num_bits {
        let pos = bit_offset + i as usize;
        let bit = (data[pos / 8] >> (7 - pos % 8)) & 1;
        value = (value << 1) | bit as u32;
    }
    value
}

/// The bit-packing of AU-headers, as negotiated by the `sizeLength`/`indexLength` fmtp
/// parameters. Always packs `AU-Index` 0 for every header — i.e. no AAC-interleaving (out of
/// transmission-order delivery), just plain sequential Access Units, one or more per packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct AuHeaderFormat {
    size_length_bits: u8,
    index_length_bits: u8,
}

impl AuHeaderFormat {
    fn new(size_length_bits: u8, index_length_bits: u8) -> Result<Self> {
        if size_length_bits == 0 || size_length_bits.saturating_add(index_length_bits) > 32 {
            return Err(Error::Mpeg4GenericInvalidAuHeaderLengths(
                size_length_bits,
                index_length_bits,
            ));
        }
        Ok(AuHeaderFormat {
            size_length_bits,
            index_length_bits,
        })
    }

    /// Bits in one AU-header: `size_length_bits + index_length_bits`.
    fn header_bits(&self) -> u8 {
        self.size_length_bits + self.index_length_bits
    }

    /// Bytes in `count` AU-headers packed back-to-back, once padded up to a byte boundary.
    fn header_section_bytes(&self, count: usize) -> usize {
        (self.header_bits() as usize * count).div_ceil(8)
    }

    /// The largest Access Unit size the `sizeLength`-bit AU-size field can represent.
    fn max_au_size(&self) -> usize {
        ((1u64 << self.size_length_bits) - 1) as usize
    }

    /// Packs `sizes.len()` AU-headers (each with `AU-Index` 0), one per entry in `sizes`, back
    /// to back with zero-padding only after the last one.
    fn pack_many(&self, sizes: &[usize]) -> Vec<u8> {
        let header_bits = self.header_bits() as u32;
        let mut out = vec![0u8; self.header_section_bytes(sizes.len())];
        for (i, &size) in sizes.iter().enumerate() {
            let value = (size as u32) << self.index_length_bits;
            write_bits(&mut out, i * header_bits as usize, header_bits, value);
        }
        out
    }

    /// Unpacks `count` AU-headers' AU-size fields (ignoring `AU-Index`) from a
    /// `header_section_bytes(count)`-byte AU Header Section.
    fn unpack_many(&self, header_section: &[u8], count: usize) -> Vec<usize> {
        let header_bits = self.header_bits() as u32;
        (0..count)
            .map(|i| {
                let value = read_bits(header_section, i * header_bits as usize, header_bits);
                (value >> self.index_length_bits) as usize
            })
            .collect()
    }
}

/// Packetizes MPEG4-GENERIC Access Units, fragmenting one across several RTP packets when it
/// doesn't fit the MTU. Every packet — including every fragment — carries an AU-header stating
/// the *entire* Access Unit's size, per [RFC 3640] §3.2.1.1.
///
/// [RFC 3640]: https://datatracker.ietf.org/doc/html/rfc3640
#[derive(Debug, Copy, Clone)]
pub struct Mpeg4GenericPayloader {
    format: AuHeaderFormat,
}

impl Default for Mpeg4GenericPayloader {
    fn default() -> Self {
        Mpeg4GenericPayloader::new(DEFAULT_SIZE_LENGTH_BITS, DEFAULT_INDEX_LENGTH_BITS)
            .expect("AAC-hbr defaults are always valid")
    }
}

impl Mpeg4GenericPayloader {
    /// A payloader using the `sizeLength`/`indexLength` fmtp parameters negotiated over SDP.
    ///
    /// # Errors
    ///
    /// Fails if `size_length_bits` is 0, or `size_length_bits + index_length_bits` exceeds 32
    /// (the largest AU-header this implementation can pack).
    pub fn new(size_length_bits: u8, index_length_bits: u8) -> Result<Self> {
        Ok(Mpeg4GenericPayloader {
            format: AuHeaderFormat::new(size_length_bits, index_length_bits)?,
        })
    }

    /// Packetizes `aus` — several complete Access Units the caller has ready to send at once
    /// (e.g. sharing one RTP timestamp) — greedily bundling as many complete AUs as fit into
    /// each packet (RFC 3640 §3.2.3.1). An AU that doesn't fit in one packet even alone is
    /// fragmented across several packets of its own, same as [`Payloader::payload`] does for a
    /// single AU; per RFC 3640, a packet never mixes a fragment with other Access Units.
    ///
    /// Unlike [`Payloader::payload`], this never buffers an AU across calls: every AU passed in
    /// is fully packetized into the returned packets before this returns, so there's no held
    /// state to flush and no added latency from waiting on a future call.
    ///
    /// # Errors
    ///
    /// Fails if any AU exceeds the configured `sizeLength`'s range, or `mtu` can't fit even one
    /// AU-header.
    pub fn payload_aus(&mut self, mtu: usize, aus: &[Bytes]) -> Result<Vec<Bytes>> {
        if mtu == 0 || aus.is_empty() {
            return Ok(vec![]);
        }

        let one_header_overhead = AU_HEADERS_LENGTH_SIZE + self.format.header_section_bytes(1);
        if mtu <= one_header_overhead {
            return Err(Error::ErrShortPacket);
        }

        for au in aus {
            if au.len() > self.format.max_au_size() {
                return Err(Error::Mpeg4GenericAuTooLarge(
                    au.len(),
                    self.format.max_au_size(),
                ));
            }
        }

        let mut payloads = Vec::new();
        let mut bundle: Vec<&Bytes> = Vec::new();

        for au in aus {
            let mut candidate = bundle.clone();
            candidate.push(au);
            if self.bundle_size(&candidate) <= mtu {
                bundle = candidate;
                continue;
            }

            if !bundle.is_empty() {
                payloads.push(self.pack_bundle(&bundle));
                bundle.clear();
            }

            if AU_HEADERS_LENGTH_SIZE + self.format.header_section_bytes(1) + au.len() <= mtu {
                bundle.push(au);
            } else {
                payloads.extend(self.fragment_one(mtu, au));
            }
        }

        if !bundle.is_empty() {
            payloads.push(self.pack_bundle(&bundle));
        }

        Ok(payloads)
    }

    /// The packet size `aus`, bundled together with one AU-header each, would need.
    fn bundle_size(&self, aus: &[&Bytes]) -> usize {
        AU_HEADERS_LENGTH_SIZE
            + self.format.header_section_bytes(aus.len())
            + aus.iter().map(|au| au.len()).sum::<usize>()
    }

    /// Packs `aus` into one packet: `aus.len()` AU-headers, then their data concatenated.
    fn pack_bundle(&self, aus: &[&Bytes]) -> Bytes {
        let sizes: Vec<usize> = aus.iter().map(|au| au.len()).collect();
        let header_section = self.format.pack_many(&sizes);

        let mut buf = BytesMut::with_capacity(self.bundle_size(aus));
        buf.put_u16(self.format.header_bits() as u16 * aus.len() as u16);
        buf.put_slice(&header_section);
        for au in aus {
            buf.put_slice(au);
        }
        buf.freeze()
    }

    /// Fragments one Access Unit that doesn't fit `mtu` even alone, across several packets,
    /// each repeating an AU-header stating the whole Access Unit's size (RFC 3640 §3.2.1.1).
    /// `mtu` must be more than `AU_HEADERS_LENGTH_SIZE + self.format.header_section_bytes(1)`.
    fn fragment_one(&self, mtu: usize, au: &Bytes) -> Vec<Bytes> {
        let overhead = AU_HEADERS_LENGTH_SIZE + self.format.header_section_bytes(1);
        let au_header_bits = self.format.header_bits() as u16;
        let au_header = self.format.pack_many(&[au.len()]);

        let mut payloads = Vec::new();
        let mut offset = 0;
        loop {
            let chunk_len = std::cmp::min(mtu - overhead, au.len() - offset);

            let mut buf = BytesMut::with_capacity(overhead + chunk_len);
            buf.put_u16(au_header_bits);
            buf.put_slice(&au_header);
            buf.put_slice(&au[offset..offset + chunk_len]);
            payloads.push(buf.freeze());

            offset += chunk_len;
            if offset >= au.len() {
                break;
            }
        }

        payloads
    }
}

impl Payloader for Mpeg4GenericPayloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() {
            return Ok(vec![]);
        }
        self.payload_aus(mtu, std::slice::from_ref(payload))
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

/// Depacketizes MPEG4-GENERIC Access Units, reassembling ones fragmented across several RTP
/// packets.
#[derive(Debug, Clone)]
pub struct Mpeg4GenericDepacketizer {
    format: AuHeaderFormat,
    /// The Access Unit currently being reassembled, and the total size it was declared to be.
    partial_au: Option<(BytesMut, usize)>,
}

impl Default for Mpeg4GenericDepacketizer {
    fn default() -> Self {
        Mpeg4GenericDepacketizer::new(DEFAULT_SIZE_LENGTH_BITS, DEFAULT_INDEX_LENGTH_BITS)
            .expect("AAC-hbr defaults are always valid")
    }
}

impl Mpeg4GenericDepacketizer {
    /// A depacketizer using the `sizeLength`/`indexLength` fmtp parameters negotiated over SDP.
    ///
    /// # Errors
    ///
    /// Fails if `size_length_bits` is 0, or `size_length_bits + index_length_bits` exceeds 32
    /// (the largest AU-header this implementation can unpack).
    pub fn new(size_length_bits: u8, index_length_bits: u8) -> Result<Self> {
        Ok(Mpeg4GenericDepacketizer {
            format: AuHeaderFormat::new(size_length_bits, index_length_bits)?,
            partial_au: None,
        })
    }

    /// Depacketizes `packet`, returning each complete Access Unit it carries, in order.
    ///
    /// Per RFC 3640 §3.2.3.1, a packet carries either one or more *complete* Access Units, or a
    /// single *fragment* of one:
    /// - A packet with one AU-header behaves exactly like [`Depacketizer::depacketize`]: this
    ///   returns zero elements while a multi-packet Access Unit is still being reassembled, or
    ///   one once it completes.
    /// - A packet with several AU-headers (bundling several complete Access Units — not
    ///   supported by [`Depacketizer::depacketize`], which only ever returns one) returns all of
    ///   them, in order; none of them may be a fragment.
    ///
    /// # Errors
    ///
    /// Fails on a malformed packet: an `AU-headers-length` that isn't a multiple of the
    /// configured `sizeLength + indexLength`, or not enough data for the declared Access
    /// Unit(s).
    pub fn depacketize_aus(&mut self, packet: &Bytes) -> Result<Vec<Bytes>> {
        if packet.len() < AU_HEADERS_LENGTH_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let mut buf = packet.clone();
        let au_headers_length_bits = buf.get_u16();
        let header_bits = self.format.header_bits() as u16;
        if header_bits == 0
            || au_headers_length_bits == 0
            || !au_headers_length_bits.is_multiple_of(header_bits)
        {
            return Err(Error::Mpeg4GenericUnsupportedAuHeadersLength(
                au_headers_length_bits,
                self.format.header_bits(),
            ));
        }
        let count = (au_headers_length_bits / header_bits) as usize;

        let header_section_bytes = self.format.header_section_bytes(count);
        if buf.remaining() < header_section_bytes {
            return Err(Error::ErrShortPacket);
        }
        let mut header_section = vec![0u8; header_section_bytes];
        buf.copy_to_slice(&mut header_section);
        let sizes = self.format.unpack_many(&header_section, count);

        let data = buf;

        if count == 1 {
            return Ok(self.depacketize_single(&data, sizes[0]).into_iter().collect());
        }

        // Several complete Access Units: per spec, none of them may be a fragment here.
        let mut aus = Vec::with_capacity(count);
        let mut offset = 0;
        for size in sizes {
            if data.len() < offset + size {
                return Err(Error::ErrShortPacket);
            }
            aus.push(data.slice(offset..offset + size));
            offset += size;
        }
        Ok(aus)
    }

    /// The single-AU reassembly state machine shared by [`Depacketizer::depacketize`] and
    /// [`Self::depacketize_aus`]: `data` is one packet's (or one fragment's) Access Unit Data
    /// Section, and `au_size` is the size its AU-header declared for the whole Access Unit.
    /// Returns the reassembled Access Unit once complete, `None` while still reassembling.
    fn depacketize_single(&mut self, data: &Bytes, au_size: usize) -> Option<Bytes> {
        if let Some((partial, expected_size)) = self.partial_au.as_mut() {
            // A continuation of the Access Unit already in progress. Completion is driven by
            // `is_partition_tail` (the RTP marker bit) via the caller, not by anything in this
            // header — see the module docs for why RFC 3640 leaves it that way.
            partial.put_slice(data);
            if partial.len() >= *expected_size {
                let (partial, expected_size) = self.partial_au.take().expect("just matched Some");
                Some(partial.freeze().slice(0..expected_size))
            } else {
                None
            }
        } else if data.len() >= au_size {
            // A complete, unfragmented Access Unit.
            Some(data.slice(0..au_size))
        } else {
            // The first fragment of a new Access Unit. `au_size` is remote-controlled (up to
            // the negotiated `sizeLength`, which can be as large as 32 bits) and unrelated to
            // how much data has actually arrived, so don't pre-allocate for it — grow the
            // buffer incrementally as real fragment data comes in instead, same as `BytesMut`
            // does for any other unbounded input.
            let mut partial = BytesMut::with_capacity(data.len());
            partial.put_slice(data);
            self.partial_au = Some((partial, au_size));
            None
        }
    }
}

impl Depacketizer for Mpeg4GenericDepacketizer {
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.len() < AU_HEADERS_LENGTH_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let mut buf = packet.clone();
        let au_headers_length_bits = buf.get_u16();
        if au_headers_length_bits != self.format.header_bits() as u16 {
            return Err(Error::Mpeg4GenericUnsupportedAuHeadersLength(
                au_headers_length_bits,
                self.format.header_bits(),
            ));
        }

        let header_bytes = self.format.header_section_bytes(1);
        if buf.remaining() < header_bytes {
            return Err(Error::ErrShortPacket);
        }
        let mut header = vec![0u8; header_bytes];
        buf.copy_to_slice(&mut header);
        let au_size = self.format.unpack_many(&header, 1)[0];

        let data = buf;
        Ok(self.depacketize_single(&data, au_size).unwrap_or_default())
    }

    /// Whether this packet's AU Header Section is well-formed for the configured
    /// `sizeLength`/`indexLength`: a nonzero multiple of `sizeLength + indexLength`, with enough
    /// data present for that many AU-headers.
    ///
    /// RFC 3640 has no bit that marks a fragment as specifically the *first* one — every
    /// fragment of an Access Unit restates the same, full-size AU-header (§3.2.1.1), and a
    /// packet bundling several complete Access Units is (unlike a fragment) always both the
    /// head and the tail of its own partition — so a packet with more than one AU-header always
    /// returns `true` here, while one with exactly one AU-header can't be told apart from a
    /// stray continuation surviving after its predecessor was lost. That residual ambiguity is
    /// resolved by the caller's own timestamp-discontinuity detection, per this trait method's
    /// documented fallback. Note that [`Depacketizer::depacketize`] itself only ever accepts a
    /// single AU-header — use [`Self::depacketize_aus`] for packets bundling several.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        let header_bits = self.format.header_bits() as usize;
        if header_bits == 0 || payload.len() < AU_HEADERS_LENGTH_SIZE {
            return false;
        }
        let declared_bits = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        declared_bits != 0
            && declared_bits.is_multiple_of(header_bits)
            && payload.len() >= AU_HEADERS_LENGTH_SIZE + declared_bits.div_ceil(8)
    }

    /// Whether `marker` is set, i.e. this is the last fragment of an Access Unit — per RFC 3640
    /// §3.2.3.1: "The marker bit in the RTP header is 1 on the last fragment of an Access Unit,
    /// and 0 on all other fragments." This is the sole completion signal RFC 3640 defines; it is
    /// not derivable from the AU-header itself (see [`Self::is_partition_head`]).
    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}
