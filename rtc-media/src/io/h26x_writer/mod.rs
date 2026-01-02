#[cfg(test)]
mod h26x_writer_test;

use std::io::Write;

use bytes::{Bytes, BytesMut};
use rtp::codec::h264::H264Packet;
use rtp::codec::h265::{H265Packet, H265Payload};
use rtp::packetizer::Depacketizer;

use crate::io::Writer;
use shared::error::Result;

const NALU_TTYPE_STAP_A: u32 = 24;
const NALU_TTYPE_SPS: u32 = 7;
const NALU_TYPE_BITMASK: u32 = 0x1F;
const ANNEXB_NALUSTART_CODE: &[u8] = &[0x00, 0x00, 0x00, 0x01];

fn is_key_frame(data: &[u8]) -> bool {
    if data.len() < 4 {
        false
    } else {
        let word = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let nalu_type = (word >> 24) & NALU_TYPE_BITMASK;
        (nalu_type == NALU_TTYPE_STAP_A && (word & NALU_TYPE_BITMASK) == NALU_TTYPE_SPS)
            || (nalu_type == NALU_TTYPE_SPS)
    }
}

enum H26xPacket {
    H264(H264Packet),
    H265(H265Packet),
}

impl H26xPacket {
    fn depacketize(&mut self, payload: &Bytes) -> Result<Bytes> {
        match self {
            H26xPacket::H264(p) => p.depacketize(payload),
            H26xPacket::H265(p) => p.depacketize(payload),
        }
    }
}

/// H26xWriter is used to take RTP packets, parse them and
/// write the data to an io.Writer.
/// Supports both H264 and H265 codecs based on the is_hevc flag.
pub struct H26xWriter<W: Write> {
    writer: W,
    packet: H26xPacket,
    is_hevc: bool,
    // H264-specific fields
    has_key_frame: bool,
    // H265-specific fields
    buffer: BytesMut,
}

impl<W: Write> H26xWriter<W> {
    /// new initializes a new H26x writer with an io.Writer output
    /// is_hevc: true for H265, false for H264
    pub fn new(writer: W, is_hevc: bool) -> Self {
        H26xWriter {
            writer,
            packet: if is_hevc {
                H26xPacket::H265(H265Packet::default())
            } else {
                H26xPacket::H264(H264Packet::default())
            },
            is_hevc,
            has_key_frame: false,
            buffer: BytesMut::new(),
        }
    }
}

impl<W: Write> Writer for H26xWriter<W> {
    /// write_rtp adds a new packet and writes the appropriate headers for it
    fn write_rtp(&mut self, packet: &rtp::Packet) -> Result<()> {
        if packet.payload.is_empty() {
            return Ok(());
        }

        if self.is_hevc {
            self.write_h265(packet)
        } else {
            self.write_h264(packet)
        }
    }

    /// close closes the underlying writer
    fn close(&mut self) -> Result<()> {
        // Flush any remaining buffered data (for H265 fragmentation units)
        if !self.buffer.is_empty() {
            self.writer.write_all(&self.buffer)?;
            self.buffer.clear();
        }
        self.writer.flush()?;
        Ok(())
    }
}

impl<W: Write> H26xWriter<W> {
    fn write_h264(&mut self, packet: &rtp::Packet) -> Result<()> {
        if !self.has_key_frame {
            self.has_key_frame = is_key_frame(&packet.payload);
            if !self.has_key_frame {
                // key frame not defined yet. discarding packet
                return Ok(());
            }
        }

        let payload = self.packet.depacketize(&Bytes::copy_from_slice(&packet.payload))?;
        self.writer.write_all(&payload)?;

        Ok(())
    }

    fn write_h265(&mut self, packet: &rtp::Packet) -> Result<()> {
        // Depacketize the H265 RTP packet
        let _data = self.packet.depacketize(&Bytes::copy_from_slice(&packet.payload))?;

        if let H26xPacket::H265(h265_packet) = &self.packet {
            match h265_packet.payload() {
                H265Payload::H265PACIPacket(_p) => {
                    // PACI packets are not commonly used, skip for now
                }
                H265Payload::H265SingleNALUnitPacket(p) => {
                    // Write start code + NAL unit
                    self.writer.write_all(ANNEXB_NALUSTART_CODE)?;
                    self.writer.write_all(&p.payload())?;
                }
                H265Payload::H265AggregationPacket(p) => {
                    // Write first unit
                    if let Some(uf) = p.first_unit() {
                        self.writer.write_all(ANNEXB_NALUSTART_CODE)?;
                        self.writer.write_all(&uf.nal_unit())?;
                    }
                    // Write other units
                    for ou in p.other_units() {
                        self.writer.write_all(ANNEXB_NALUSTART_CODE)?;
                        self.writer.write_all(&ou.nal_unit())?;
                    }
                }
                H265Payload::H265FragmentationUnitPacket(p) => {
                    // Handle fragmentation units
                    if p.fu_header().s() {
                        // Start of fragmented NAL unit
                        // Reconstruct NAL unit header from FU header
                        let nal_type = (p.fu_header().fu_type() << 1) & 0b0111_1110;

                        // Clear buffer for new NAL unit
                        self.buffer.clear();

                        // Write start code
                        self.buffer.extend_from_slice(ANNEXB_NALUSTART_CODE);
                        // Write reconstructed NAL unit header (2 bytes for H265)
                        self.buffer.extend_from_slice(&[nal_type, 0x01]);
                    }

                    // Accumulate payload
                    self.buffer.extend_from_slice(&p.payload());

                    if p.fu_header().e() {
                        // End of fragmented NAL unit - flush to writer
                        self.writer.write_all(&self.buffer)?;
                        self.buffer.clear();
                    }
                }
            }
        }

        Ok(())
    }
}
