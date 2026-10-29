//! The H.266 depacketizer: RFC 9328 payloads in, an Annex B byte stream out.
//!
//! Single NAL unit packets and aggregation packets yield their NAL units right away; a
//! fragmented NAL unit yields nothing until its last fragment arrives, and is then returned
//! whole. Output NAL units are prefixed with a four-byte start code and never carry DONL
//! fields.

use bytes::{BufMut, Bytes, BytesMut};

use super::{
    ANNEXB_START_CODE, H266NALUHeader, H266Packet, NAL_HEADER_SIZE, fu_end, fu_start,
    parse_h266_packet, rebuild_fragmentation_packets, split_aggregation_packet,
};
use crate::packetizer::Depacketizer;
use shared::error::{Error, Result};

/// Depacketizes an H.266 RTP stream into Annex B.
#[derive(Default, Debug, Clone)]
pub struct H266Depacketizer {
    has_donl: bool,
    partials: Vec<super::FragmentationPacket>,
}

impl H266Depacketizer {
    /// A depacketizer for streams without DONL fields.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether packets may carry DONL fields, which they do when the stream's
    /// `sprop-max-don-diff` is greater than zero.
    pub fn with_donl(mut self, has_donl: bool) -> Self {
        self.has_donl = has_donl;
        self
    }
}

impl Depacketizer for H266Depacketizer {
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.len() < NAL_HEADER_SIZE {
            return Err(Error::ErrShortPacket);
        }

        let parsed_header = H266NALUHeader::new(packet[0], packet[1]);

        // Only the first fragmentation unit of a NAL unit carries a DONL; whether this packet is
        // that first unit shows in the fragments buffered so far.
        let is_frag = parsed_header.is_fragmentation_unit();
        let parse_donl = self.has_donl && ((self.partials.is_empty() && is_frag) || !is_frag);

        let parsed = parse_h266_packet(packet, parse_donl)?;
        let mut output = BytesMut::new();

        if let H266Packet::Fragmentation(fragment) = parsed {
            if fu_end(fragment.fu_header) {
                self.partials.push(fragment);
                output.put_slice(&ANNEXB_START_CODE);
                let mut rebuilt = rebuild_fragmentation_packets(&self.partials)?;
                // The rebuilt unit never carries a DONL.
                rebuilt.donl = None;
                rebuilt.packetize_into(&mut output);
                self.partials.clear();
                return Ok(output.freeze());
            }

            // A start fragment discards whatever was left of a lost one.
            if fu_start(fragment.fu_header) {
                self.partials.clear();
            } else if self.partials.is_empty() {
                return Err(Error::ErrH266ExpectedFragmentationStart);
            }
            self.partials.push(fragment);
            return Ok(Bytes::new());
        }

        self.partials.clear();

        match parsed {
            H266Packet::Aggregation(aggregation) => {
                let aggregated = split_aggregation_packet(&aggregation)?;
                for mut nal in aggregated {
                    output.put_slice(&ANNEXB_START_CODE);
                    // Output units never carry a DONL.
                    nal.donl = None;
                    nal.packetize_into(&mut output);
                }
            }
            H266Packet::Single(mut single) => {
                output.put_slice(&ANNEXB_START_CODE);
                // Output units never carry a DONL.
                single.donl = None;
                single.packetize_into(&mut output);
            }
            H266Packet::Fragmentation(_) => unreachable!("handled above"),
        }
        Ok(output.freeze())
    }

    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.len() < NAL_HEADER_SIZE {
            return false;
        }
        let header = H266NALUHeader::new(payload[0], payload[1]);
        if header.is_fragmentation_unit() {
            return payload.len() >= 3 && payload[2] & 0x80 != 0;
        }
        true
    }

    fn is_partition_tail(&self, marker: bool, payload: &Bytes) -> bool {
        if payload.len() < 3 {
            return marker;
        }
        let header = H266NALUHeader::new(payload[0], payload[1]);
        if !header.is_fragmentation_unit() {
            return marker;
        }
        payload[2] & 0x40 != 0
    }
}
