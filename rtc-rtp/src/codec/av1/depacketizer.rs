//! AV1 RTP Depacketizer
//!
//! Reads AV1 RTP packets and outputs AV1 low overhead bitstream format.
//! Based on <https://aomediacodec.github.io/av1-rtp-spec/>

use bytes::{BufMut, Bytes, BytesMut};

use crate::codec::av1::leb128::read_leb128_checked;
use crate::codec::av1::obu::{
    OBU_FORBIDDEN_BIT, OBU_HAS_EXTENSION_BIT, OBU_HAS_SIZE_BIT, OBU_TYPE_MASK,
    OBU_TYPE_TEMPORAL_DELIMITER, OBU_TYPE_TILE_LIST,
};
use crate::packetizer::Depacketizer;
use shared::error::{Error, Result};

// AV1 Aggregation Header bit masks
const AV1_Z_MASK: u8 = 0b1000_0000;
const AV1_Y_MASK: u8 = 0b0100_0000;
const AV1_W_MASK: u8 = 0b0011_0000;
const AV1_N_MASK: u8 = 0b0000_1000;

/// AV1 RTP Depacketizer
///
/// Depacketizes AV1 RTP packets into low overhead bitstream format with obu_size fields.
#[derive(Default, Debug, Clone)]
pub struct Av1Depacketizer {
    /// Buffer for fragmented OBU from previous packet
    buffer: BytesMut,
    /// Z flag from aggregation header - first OBU is continuation
    pub z: bool,
    /// Y flag from aggregation header - last OBU will continue
    pub y: bool,
    /// N flag from aggregation header - new coded video sequence
    pub n: bool,
}

impl Av1Depacketizer {
    /// An AV1 depacketizer with no buffered fragments.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Depacketizer for Av1Depacketizer {
    /// Depacketize parses an AV1 RTP payload into OBU stream with obu_size_field.
    ///
    /// Reference: <https://aomediacodec.github.io/av1-rtp-spec/>
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        if payload.len() <= 1 {
            return Err(Error::ErrShortPacket);
        }

        // Aggregation header: |Z|Y| W |N|-|-|-|
        let obu_z = (payload[0] & AV1_Z_MASK) != 0;
        let obu_y = (payload[0] & AV1_Y_MASK) != 0;
        let obu_count = ((payload[0] & AV1_W_MASK) >> 4) as usize;
        let obu_n = (payload[0] & AV1_N_MASK) != 0;

        self.z = obu_z;
        self.y = obu_y;
        self.n = obu_n;

        // A new coded video sequence, or a packet that does not continue an OBU, drops any
        // fragment still waiting for its remainder.
        if obu_n || (!obu_z && !self.buffer.is_empty()) {
            self.buffer.clear();
        }

        let mut result = BytesMut::new();
        let mut offset = 1; // past the aggregation header
        let mut obu_offset = 0usize;

        while offset < payload.len() {
            let is_first = obu_offset == 0;
            let mut is_last = obu_count != 0 && obu_offset == obu_count - 1;

            // W == 0: every element carries a length. W != 0: only the last one does not.
            let length_field = if obu_count == 0 || !is_last {
                let (len, n) =
                    read_leb128_checked(&payload[offset..]).ok_or(Error::ErrShortPacket)?;
                offset += n;
                if obu_count == 0 && offset.checked_add(len) == Some(payload.len()) {
                    is_last = true;
                }
                len
            } else {
                payload.len() - offset
            };

            if offset
                .checked_add(length_field)
                .is_none_or(|end| end > payload.len())
            {
                return Err(Error::ErrShortPacket);
            }

            let obu_buffer = if is_first && obu_z {
                // The first element continues an OBU from an earlier packet.
                if self.buffer.is_empty() {
                    // That packet was lost: skip the orphaned tail.
                    if is_last {
                        break;
                    }
                    offset += length_field;
                    obu_offset += 1;
                    continue;
                }
                self.buffer
                    .extend_from_slice(&payload[offset..offset + length_field]);
                std::mem::take(&mut self.buffer).freeze()
            } else {
                payload.slice(offset..offset + length_field)
            };
            offset += length_field;

            // The last element continues in the next packet: hold it back.
            if is_last && obu_y {
                self.buffer = BytesMut::from(obu_buffer.as_ref());
                break;
            }

            if obu_buffer.is_empty() {
                obu_offset += 1;
                continue;
            }

            // OBU header: forbidden(1) type(4) extension(1) has_size(1) reserved(1) [extension(8)]
            let header = obu_buffer[0];
            if header & OBU_FORBIDDEN_BIT != 0 {
                return Err(Error::ErrInvalidObuHeader);
            }
            let has_extension = header & OBU_HAS_EXTENSION_BIT != 0;
            if has_extension && obu_buffer.len() < 2 {
                return Err(Error::ErrShortPacket);
            }
            let header_size = if has_extension { 2 } else { 1 };
            let obu_type = (header & OBU_TYPE_MASK) >> 3;

            // Temporal delimiters and tile lists carry nothing a receiver needs.
            if obu_type == OBU_TYPE_TEMPORAL_DELIMITER || obu_type == OBU_TYPE_TILE_LIST {
                obu_offset += 1;
                continue;
            }

            // obu_has_size_field should be 0 in RTP, but if an element has one that agrees with
            // the element's length it is kept; otherwise the size is recomputed.
            let payload_offset = if header & OBU_HAS_SIZE_BIT != 0 {
                let (size, n) =
                    read_leb128_checked(&obu_buffer[header_size..]).ok_or(Error::ErrShortPacket)?;
                if header_size.checked_add(size).and_then(|s| s.checked_add(n))
                    == Some(length_field)
                {
                    result.extend_from_slice(&obu_buffer);
                    if is_last {
                        break;
                    }
                    obu_offset += 1;
                    continue;
                }
                header_size + n
            } else {
                header_size
            };

            result.put_u8(header | OBU_HAS_SIZE_BIT);
            if has_extension {
                result.put_u8(obu_buffer[1]);
            }
            write_leb128(&mut result, (obu_buffer.len() - payload_offset) as u32);
            result.extend_from_slice(&obu_buffer[payload_offset..]);

            if is_last {
                break;
            }
            obu_offset += 1;
        }

        // W promised more elements than the packet held. (One more than W - 1 means the last
        // element was skipped, as a temporal delimiter is; pion reports that as an error too,
        // but nothing is wrong with the packet.)
        if obu_count != 0 && obu_offset + 1 < obu_count {
            return Err(Error::ErrShortPacket);
        }

        Ok(result.freeze())
    }

    /// Returns true if Z flag is not set (first OBU is not a continuation)
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.is_empty() {
            return false;
        }
        (payload[0] & AV1_Z_MASK) == 0
    }

    /// Returns true if marker bit is set (end of frame)
    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

/// Write LEB128 encoded value to buffer
fn write_leb128(buf: &mut BytesMut, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_depacketizer_basic() {
        let mut depacketizer = Av1Depacketizer::new();

        // Simple packet with one OBU element (W=1)
        // Aggregation header: W=1, no Z, no Y, no N = 0x10
        // OBU header: type=6 (Frame), no extension, no size = 0x30
        // Total: aggregation header + OBU header + payload
        let payload = Bytes::from(vec![
            0x10, // Aggregation header: W=1
            0x30, // OBU header: type=6 (Frame), no ext, no size
            0x01, 0x02, 0x03, // OBU payload
        ]);

        let result = depacketizer.depacketize(&payload).unwrap();
        assert!(!result.is_empty());
        // Should have size field added (OBU_HAS_SIZE_BIT = 0x02)
        assert_eq!(result[0] & OBU_HAS_SIZE_BIT, OBU_HAS_SIZE_BIT);
        // Size should be 3 (payload bytes)
        assert_eq!(result[1], 3);
        // Payload should follow
        assert_eq!(&result[2..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_depacketizer_with_w_zero() {
        let mut depacketizer = Av1Depacketizer::new();

        // Packet with W=0 means each OBU has length prefix
        // Aggregation header: W=0
        // Length field (LEB128): 4 bytes
        // OBU: header + payload
        let payload = Bytes::from(vec![
            0x00, // Aggregation header: W=0
            0x04, // Length field: 4 bytes
            0x30, // OBU header: type=6 (Frame), no ext, no size
            0x01, 0x02, 0x03, // OBU payload (3 bytes, total OBU = 4)
        ]);

        let result = depacketizer.depacketize(&payload).unwrap();
        assert!(!result.is_empty());
        // Should have size field added
        assert_eq!(result[0] & OBU_HAS_SIZE_BIT, OBU_HAS_SIZE_BIT);
    }

    #[test]
    fn test_is_partition_head() {
        let depacketizer = Av1Depacketizer::new();

        // Z=0 means partition head
        let payload = Bytes::from(vec![0x10, 0x30]);
        assert!(depacketizer.is_partition_head(&payload));

        // Z=1 means continuation
        let payload = Bytes::from(vec![0x90, 0x30]);
        assert!(!depacketizer.is_partition_head(&payload));
    }

    #[test]
    fn test_write_leb128() {
        let mut buf = BytesMut::new();

        // Test small values
        write_leb128(&mut buf, 0);
        assert_eq!(buf.as_ref(), &[0x00]);

        buf.clear();
        write_leb128(&mut buf, 127);
        assert_eq!(buf.as_ref(), &[0x7f]);

        buf.clear();
        write_leb128(&mut buf, 128);
        assert_eq!(buf.as_ref(), &[0x80, 0x01]);

        buf.clear();
        write_leb128(&mut buf, 16383);
        assert_eq!(buf.as_ref(), &[0xff, 0x7f]);
    }

    #[test]
    fn test_skip_temporal_delimiter() {
        let mut depacketizer = Av1Depacketizer::new();

        // Packet with temporal delimiter OBU (type=2) which should be skipped
        let payload = Bytes::from(vec![
            0x10, // Aggregation header: W=1
            0x12, // OBU header: type=2 (Temporal Delimiter), no ext, with size
            0x00, // Size = 0
        ]);

        let result = depacketizer.depacketize(&payload).unwrap();
        // Should be empty since temporal delimiter is skipped
        assert!(result.is_empty());
    }

    #[test]
    fn test_fragmented_obu_with_size_field() {
        let mut depacketizer = Av1Depacketizer::new();

        // Build a Frame OBU that already carries a low-overhead size field.
        let mut obu = BytesMut::new();
        obu.put_u8(0x32); // Frame OBU, no extension, has size field
        let payload = vec![0xAB; 500];
        write_leb128(&mut obu, payload.len() as u32);
        obu.extend_from_slice(&payload);
        let obu = obu.freeze();

        let first_fragment_size = 400;
        let p1 = Bytes::from_iter(
            std::iter::once(0x50) // Z=0, Y=1, W=1
                .chain(obu[..first_fragment_size].iter().copied()),
        );
        let p2 = Bytes::from_iter(
            std::iter::once(0x90) // Z=1, Y=0, W=1
                .chain(obu[first_fragment_size..].iter().copied()),
        );

        assert!(depacketizer.depacketize(&p1).unwrap().is_empty());
        let result = depacketizer.depacketize(&p2).unwrap();
        assert_eq!(result, obu);
    }
}
