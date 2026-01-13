//! AV1 RTP Depacketizer
//!
//! Reads AV1 RTP packets and outputs AV1 low overhead bitstream format.
//! Based on <https://aomediacodec.github.io/av1-rtp-spec/>

use bytes::{BufMut, Bytes, BytesMut};

use crate::codec::av1::leb128::read_leb128;
use crate::codec::av1::obu::{
    OBU_HAS_SIZE_BIT, OBU_TYPE_MASK, OBU_TYPE_TEMPORAL_DELIMITER, OBU_TYPE_TILE_LIST,
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

        // Parse aggregation header
        // |Z|Y| W |N|-|-|-|
        let obu_z = (payload[0] & AV1_Z_MASK) != 0;
        let obu_y = (payload[0] & AV1_Y_MASK) != 0;
        let obu_count = (payload[0] & AV1_W_MASK) >> 4;
        let obu_n = (payload[0] & AV1_N_MASK) != 0;

        self.z = obu_z;
        self.y = obu_y;
        self.n = obu_n;

        // Clear buffer on new coded video sequence
        if obu_n {
            self.buffer.clear();
        }

        // Clear buffer if Z is not set but we have buffered data
        if !obu_z && !self.buffer.is_empty() {
            self.buffer.clear();
        }

        let mut result = BytesMut::new();
        let mut offset = 1; // Skip aggregation header
        let mut obu_offset = 0;

        while offset < payload.len() {
            let is_first = obu_offset == 0;
            let is_last = obu_count != 0 && obu_offset == (obu_count - 1) as usize;

            // Read OBU element length
            let (length_field, is_last) = if obu_count == 0 || !is_last {
                // W=0 or not last element: length field present
                let payload_slice = payload.slice(offset..);
                let (len, n) = read_leb128(&payload_slice);
                if n == 0 {
                    return Err(Error::ErrShortPacket);
                }
                offset += n;

                // Check if this is actually the last element when W=0
                let is_last_w0 = obu_count == 0 && offset + len as usize == payload.len();
                (len as usize, is_last || is_last_w0)
            } else {
                // Last element when W != 0: no length field
                (payload.len() - offset, true)
            };

            if offset + length_field > payload.len() {
                return Err(Error::ErrShortPacket);
            }

            // Build OBU buffer
            let obu_buffer = if is_first && obu_z {
                // Continuation of previous packet's OBU
                if self.buffer.is_empty() {
                    // Lost first fragment, skip this OBU
                    if is_last {
                        break;
                    }
                    offset += length_field;
                    obu_offset += 1;
                    continue;
                }

                // Combine buffered data with current fragment
                let mut combined = std::mem::take(&mut self.buffer);
                combined.extend_from_slice(&payload[offset..offset + length_field]);
                combined.freeze()
            } else {
                payload.slice(offset..offset + length_field)
            };
            offset += length_field;

            // If this is the last OBU and Y flag is set, buffer it for next packet
            if is_last && obu_y {
                self.buffer = BytesMut::from(obu_buffer.as_ref());
                break;
            }

            // Skip empty OBUs
            if obu_buffer.is_empty() {
                if is_last {
                    break;
                }
                obu_offset += 1;
                continue;
            }

            // Parse OBU header to check type
            let obu_type = (obu_buffer[0] & OBU_TYPE_MASK) >> 3;

            // Skip temporal delimiter and tile list OBUs
            if obu_type == OBU_TYPE_TEMPORAL_DELIMITER || obu_type == OBU_TYPE_TILE_LIST {
                if is_last {
                    break;
                }
                obu_offset += 1;
                continue;
            }

            // Check if OBU has size field
            let has_size_field = (obu_buffer[0] & OBU_HAS_SIZE_BIT) != 0;
            let has_extension = (obu_buffer[0] & 0x04) != 0;
            let header_size = if has_extension { 2 } else { 1 };

            if has_size_field {
                // OBU already has size field, validate it
                let payload_slice = obu_buffer.slice(header_size..);
                let (obu_size, leb_size) = read_leb128(&payload_slice);
                let expected_size = header_size + leb_size + obu_size as usize;
                if length_field != expected_size {
                    return Err(Error::ErrShortPacket);
                }
                result.extend_from_slice(&obu_buffer);
            } else {
                // Add size field to OBU
                // Set obu_has_size_field bit
                result.put_u8(obu_buffer[0] | OBU_HAS_SIZE_BIT);

                // Copy extension header if present
                if has_extension && obu_buffer.len() > 1 {
                    result.put_u8(obu_buffer[1]);
                }

                // Write payload size as LEB128
                let payload_size = obu_buffer.len() - header_size;
                write_leb128(&mut result, payload_size as u32);

                // Copy OBU payload
                if header_size < obu_buffer.len() {
                    result.extend_from_slice(&obu_buffer[header_size..]);
                }
            }

            if is_last {
                break;
            }
            obu_offset += 1;
        }

        // Validate OBU count if W field was set
        if obu_count != 0 && obu_offset != (obu_count - 1) as usize && !self.y {
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
}
