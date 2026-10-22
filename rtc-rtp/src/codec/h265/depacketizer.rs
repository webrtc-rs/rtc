//! The H.265 depacketizer: RFC 7798 payloads in, an Annex B byte stream out.
//!
//! Single NAL unit packets, aggregation packets and PACI packets each yield their NAL units
//! right away; a fragmented NAL unit yields nothing until its last fragment arrives, and is then
//! returned whole. Output NAL units are prefixed with a four-byte start code and never carry
//! DONL/DOND fields.

use bytes::{BufMut, Bytes, BytesMut};

use super::{H265NALUHeader, NAL_HEADER_SIZE};
use crate::packetizer::Depacketizer;
use shared::error::{Error, Result};

const DONL_SIZE: usize = 2;
const AGGREGATION: u8 = 48;
const FRAGMENTATION: u8 = 49;
const PACI: u8 = 50;

/// One fragmentation unit, kept until its NAL unit is complete.
#[derive(Debug, Clone)]
struct Fu {
    header: u16,
    fu_header: u8,
    payload: Bytes,
}

impl Fu {
    fn start(&self) -> bool {
        self.fu_header & 0x80 != 0
    }

    fn end(&self) -> bool {
        self.fu_header & 0x40 != 0
    }
}

/// Depacketizes an H.265 RTP stream into Annex B.
#[derive(Default, Debug, Clone)]
pub struct H265Depacketizer {
    has_donl: bool,
    partials: Vec<Fu>,
}

impl H265Depacketizer {
    /// A depacketizer for streams without DONL fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether packets may carry DONL/DOND fields, which they do when the stream's
    /// `sprop-max-don-diff` is greater than zero.
    pub fn with_donl(mut self, has_donl: bool) -> Self {
        self.has_donl = has_donl;
        self
    }

    fn annex_b(out: &mut BytesMut, header: u16, payload: &[u8]) {
        out.put_slice(&[0, 0, 0, 1]);
        out.put_u16(header);
        out.put_slice(payload);
    }

    fn single(&mut self, out: &mut BytesMut, header: u16, payload: &[u8]) {
        self.partials.clear();
        Self::annex_b(out, header, payload);
    }

    /// Splits an aggregation payload into its NAL units and writes them out.
    fn aggregation(
        &mut self,
        out: &mut BytesMut,
        has_donl: bool,
        mut payload: &[u8],
    ) -> Result<()> {
        self.partials.clear();
        let mut count = 0;
        let mut nals: Vec<(u16, &[u8])> = vec![];
        while !payload.is_empty() {
            // Every unit but the first starts with a DOND byte when DONL is in use.
            let skip_dond = has_donl && count > 0;
            let min_size = 2 + usize::from(skip_dond);
            if payload.len() < min_size {
                return Err(Error::ErrShortPacket);
            }
            if skip_dond {
                payload = &payload[1..];
            }
            let len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
            if payload.len() - 2 < len {
                return Err(Error::ErrShortPacket);
            }
            let nal = &payload[2..2 + len];
            nals.push(parse_single_nal(nal)?);
            payload = &payload[2 + len..];
            count += 1;
        }
        if nals.len() < 2 {
            return Err(Error::ErrShortPacket);
        }
        for (header, body) in nals {
            Self::annex_b(out, header, body);
        }
        Ok(())
    }

    fn fragment(&mut self, out: &mut BytesMut, fu: Fu) -> Result<()> {
        if fu.end() {
            if self.partials.is_empty() {
                return Ok(());
            }
            self.partials.push(fu);
            let first = &self.partials[0];
            if !first.start() {
                return Err(Error::ErrH265FragmentsIncomplete);
            }
            let header = (first.header & !(0x3f << 9)) | u16::from(first.fu_header & 0x3f) << 9;
            let mut payload = BytesMut::new();
            for p in &self.partials {
                payload.put_slice(&p.payload);
            }
            self.single(out, header, &payload);
            self.partials.clear();
            return Ok(());
        }

        if fu.start() {
            // A new NAL unit begins: drop whatever was left of a lost one.
            self.partials.clear();
        } else if self.partials.is_empty() {
            return Err(Error::ErrH265ExpectedFragmentationStart);
        }
        self.partials.push(fu);
        Ok(())
    }
}

/// A single NAL unit packet body (no DONL): header and payload. At least one payload byte is
/// required, the F bit must be clear, and the packet cannot itself be a container.
fn parse_single_nal(nal: &[u8]) -> Result<(u16, &[u8])> {
    if nal.len() <= NAL_HEADER_SIZE {
        return Err(Error::ErrShortPacket);
    }
    let header = u16::from_be_bytes([nal[0], nal[1]]);
    let h = H265NALUHeader(header);
    if h.f() {
        return Err(Error::ErrH265CorruptedPacket);
    }
    if h.is_fragmentation_unit() || h.is_paci_packet() || h.is_aggregation_packet() {
        return Err(Error::ErrInvalidH265PacketType);
    }
    Ok((header, &nal[2..]))
}

impl Depacketizer for H265Depacketizer {
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        if payload.len() < NAL_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }
        let header = u16::from_be_bytes([payload[0], payload[1]]);
        let nal_type = H265NALUHeader(header).nalu_type();
        let mut out = BytesMut::new();

        match nal_type {
            FRAGMENTATION => {
                // DONL only follows the FU header of the first fragment of a NAL unit.
                let has_donl = self.partials.is_empty() && self.has_donl;
                let min = NAL_HEADER_SIZE + 1 + if has_donl { DONL_SIZE } else { 0 };
                if payload.len() < min {
                    return Err(Error::ErrShortPacket);
                }
                let fu = Fu {
                    header,
                    fu_header: payload[2],
                    payload: payload.slice(min..),
                };
                self.fragment(&mut out, fu)?;
            }
            AGGREGATION => {
                let min = NAL_HEADER_SIZE + 2 * 2 + if self.has_donl { DONL_SIZE } else { 0 };
                if payload.len() < min {
                    return Err(Error::ErrShortPacket);
                }
                let start = NAL_HEADER_SIZE + if self.has_donl { DONL_SIZE } else { 0 };
                self.aggregation(&mut out, self.has_donl, &payload[start..])?;
            }
            PACI => self.paci(&mut out, header, payload)?,
            _ => {
                let min = NAL_HEADER_SIZE + if self.has_donl { DONL_SIZE } else { 0 };
                if payload.len() <= min {
                    return Err(Error::ErrShortPacket);
                }
                let h = H265NALUHeader(header);
                if h.f() {
                    return Err(Error::ErrH265CorruptedPacket);
                }
                self.single(&mut out, header, &payload[min..]);
            }
        }
        Ok(out.freeze())
    }

    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.len() < 2 {
            return false;
        }
        let header = H265NALUHeader::new(payload[0], payload[1]);
        if header.is_fragmentation_unit() {
            return payload.len() >= 3 && payload[2] & 0x80 != 0;
        }
        true
    }

    fn is_partition_tail(&self, marker: bool, payload: &Bytes) -> bool {
        if payload.len() < 3 {
            return marker;
        }
        let header = H265NALUHeader::new(payload[0], payload[1]);
        if !header.is_fragmentation_unit() {
            return marker;
        }
        payload[2] & 0x40 != 0
    }
}

impl H265Depacketizer {
    /// A PACI packet wraps another packet behind a few header extension bytes.
    fn paci(&mut self, out: &mut BytesMut, header: u16, buf: &[u8]) -> Result<()> {
        if buf.len() < NAL_HEADER_SIZE + 2 {
            return Err(Error::ErrShortPacket);
        }
        let fields = u16::from_be_bytes([buf[2], buf[3]]);
        let ctype = ((fields >> 9) & 0x3f) as u8;
        let ph_size = ((fields >> 4) & 0x1f) as usize;
        if ctype == PACI {
            return Err(Error::ErrInvalidH265PacketType);
        }
        if buf.len() < NAL_HEADER_SIZE + 2 + ph_size {
            return Err(Error::ErrShortPacket);
        }
        let inner = &buf[4 + ph_size..];

        // The inner packet's header: the PACI's A bit, the carried type, and the PACI's
        // layer id and temporal id.
        let a = fields >> 15;
        let h = H265NALUHeader(header);
        let inner_header = (a << 15)
            | (u16::from(ctype) << 9)
            | (u16::from(h.layer_id()) << 3)
            | u16::from(h.tid());
        let donl = if self.has_donl { DONL_SIZE } else { 0 };

        match ctype {
            AGGREGATION => {
                if inner.len()
                    < NAL_HEADER_SIZE + 2 * 2 + if self.has_donl { DONL_SIZE + 1 } else { 0 }
                {
                    return Err(Error::ErrShortPacket);
                }
                self.aggregation(out, self.has_donl, &inner[donl..])
            }
            FRAGMENTATION => {
                if inner.len() < NAL_HEADER_SIZE + 1 + donl {
                    return Err(Error::ErrShortPacket);
                }
                let fu = Fu {
                    header: inner_header,
                    fu_header: inner[0],
                    payload: Bytes::copy_from_slice(&inner[1 + donl..]),
                };
                self.fragment(out, fu)
            }
            _ => {
                if inner.len() < NAL_HEADER_SIZE + donl {
                    return Err(Error::ErrShortPacket);
                }
                self.single(out, inner_header, &inner[donl..]);
                Ok(())
            }
        }
    }
}
