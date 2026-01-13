#[cfg(test)]
mod ivf_writer_test;

use std::io::{Seek, SeekFrom, Write};

use byteorder::{LittleEndian, WriteBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use rtp::codec::av1::Av1Depacketizer;
use rtp::packetizer::Depacketizer;

use crate::io::Writer;
use crate::io::ivf_reader::IVFFileHeader;
use shared::error::Result;

/// Codec type for IVF writer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IvfCodec {
    #[default]
    Vp8,
    Vp9,
    Av1,
}

impl IvfCodec {
    /// Create codec from FOURCC bytes
    pub fn from_fourcc(fourcc: &[u8; 4]) -> Self {
        match fourcc {
            b"VP80" => IvfCodec::Vp8,
            b"VP90" => IvfCodec::Vp9,
            b"AV01" => IvfCodec::Av1,
            _ => IvfCodec::Vp8, // Default fallback
        }
    }

    /// Get FOURCC bytes for this codec
    pub fn fourcc(&self) -> [u8; 4] {
        match self {
            IvfCodec::Vp8 => *b"VP80",
            IvfCodec::Vp9 => *b"VP90",
            IvfCodec::Av1 => *b"AV01",
        }
    }
}

/// IVFWriter is used to take RTP packets and write them to an IVF on disk
pub struct IVFWriter<W: Write + Seek> {
    writer: W,
    count: u64,
    seen_key_frame: bool,
    current_frame: Option<BytesMut>,
    codec: IvfCodec,
    /// AV1 depacketizer (lazily initialized)
    av1_depacketizer: Option<Av1Depacketizer>,
}

impl<W: Write + Seek> IVFWriter<W> {
    /// new initialize a new IVF writer with an io.Writer output
    pub fn new(writer: W, header: &IVFFileHeader) -> Result<Self> {
        let codec = IvfCodec::from_fourcc(&header.four_cc);

        let mut w = IVFWriter {
            writer,
            count: 0,
            seen_key_frame: false,
            current_frame: None,
            codec,
            av1_depacketizer: None,
        };

        w.write_header(header)?;

        Ok(w)
    }

    fn write_header(&mut self, header: &IVFFileHeader) -> Result<()> {
        self.writer.write_all(&header.signature)?; // DKIF
        self.writer.write_u16::<LittleEndian>(header.version)?; // version
        self.writer.write_u16::<LittleEndian>(header.header_size)?; // Header size
        self.writer.write_all(&header.four_cc)?; // FOURCC
        self.writer.write_u16::<LittleEndian>(header.width)?; // Width in pixels
        self.writer.write_u16::<LittleEndian>(header.height)?; // Height in pixels
        self.writer
            .write_u32::<LittleEndian>(header.timebase_denominator)?; // Framerate denominator
        self.writer
            .write_u32::<LittleEndian>(header.timebase_numerator)?; // Framerate numerator
        self.writer.write_u32::<LittleEndian>(header.num_frames)?; // Frame count, will be updated on first Close() call
        self.writer.write_u32::<LittleEndian>(header.unused)?; // Unused

        Ok(())
    }

    /// Write VP8 packet
    fn write_vp8(&mut self, packet: &rtp::Packet) -> Result<()> {
        let mut depacketizer = rtp::codec::vp8::Vp8Packet::default();
        let payload = depacketizer.depacketize(&packet.payload)?;

        // VP8 keyframe: first bit of first byte is 0
        let is_key_frame = (payload[0] & 0x01) == 0;

        if !self.seen_key_frame && !is_key_frame {
            return Ok(());
        }
        if self.current_frame.is_none() && !depacketizer.is_partition_head(&packet.payload) {
            return Ok(());
        }

        self.seen_key_frame = true;
        self.append_to_frame(payload);

        if !packet.header.marker {
            return Ok(());
        }

        self.write_current_frame()
    }

    /// Write VP9 packet
    fn write_vp9(&mut self, packet: &rtp::Packet) -> Result<()> {
        let mut depacketizer = rtp::codec::vp9::Vp9Packet::default();
        let payload = depacketizer.depacketize(&packet.payload)?;

        // VP9 keyframe: P bit is 0 (inter-picture predicted frame = false)
        let is_key_frame = !depacketizer.p;

        if !self.seen_key_frame && !is_key_frame {
            return Ok(());
        }
        if self.current_frame.is_none() && !depacketizer.b {
            return Ok(());
        }

        self.seen_key_frame = true;
        self.append_to_frame(payload);

        if !packet.header.marker {
            return Ok(());
        }

        self.write_current_frame()
    }

    /// Write AV1 packet
    fn write_av1(&mut self, packet: &rtp::Packet) -> Result<()> {
        // Initialize depacketizer if needed
        if self.av1_depacketizer.is_none() {
            self.av1_depacketizer = Some(Av1Depacketizer::new());
        }

        let depacketizer = self.av1_depacketizer.as_mut().unwrap();
        let payload = depacketizer.depacketize(&packet.payload)?;

        if !self.seen_key_frame {
            // AV1 keyframe: N bit set or first OBU is sequence header
            // OBU type for sequence header = 1, located at bits 3-6 of first byte
            let is_key_frame =
                depacketizer.n || (!payload.is_empty() && ((payload[0] & 0x78) >> 3) == 1);
            if !is_key_frame {
                return Ok(());
            }
            self.seen_key_frame = true;
        }

        self.append_to_frame(payload);

        if !packet.header.marker {
            return Ok(());
        }

        // For AV1, prepend temporal delimiter OBU before each frame
        // Temporal delimiter: type=2, has_size=1, size=0
        // OBU header: 0b0001_0010 = 0x12 (type=2, has_size_field=1)
        let mut frame_with_delimiter = BytesMut::with_capacity(2 + self.current_frame_len());
        frame_with_delimiter.put_u8(0x12); // OBU header: temporal delimiter with size field
        frame_with_delimiter.put_u8(0x00); // Size = 0

        if let Some(current_frame) = self.current_frame.take() {
            frame_with_delimiter.extend_from_slice(&current_frame);
        }

        self.write_frame(&frame_with_delimiter)
    }

    /// Append payload to current frame
    fn append_to_frame(&mut self, payload: Bytes) {
        if let Some(current_frame) = &mut self.current_frame {
            current_frame.extend(payload);
        } else {
            let mut current_frame = BytesMut::new();
            current_frame.extend(payload);
            self.current_frame = Some(current_frame);
        }
    }

    /// Get current frame length
    fn current_frame_len(&self) -> usize {
        self.current_frame.as_ref().map_or(0, |f| f.len())
    }

    /// Write current frame to output
    fn write_current_frame(&mut self) -> Result<()> {
        if let Some(current_frame) = &self.current_frame {
            if current_frame.is_empty() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        let frame_content = self.current_frame.take().unwrap();
        self.write_frame(&frame_content)
    }

    /// Write frame data to output
    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.writer.write_u32::<LittleEndian>(frame.len() as u32)?; // Frame length
        self.writer.write_u64::<LittleEndian>(self.count)?; // PTS
        self.count += 1;
        self.writer.write_all(frame)?;
        Ok(())
    }
}

impl<W: Write + Seek> Writer for IVFWriter<W> {
    /// write_rtp adds a new packet and writes the appropriate headers for it
    fn write_rtp(&mut self, packet: &rtp::Packet) -> Result<()> {
        if packet.payload.is_empty() {
            return Ok(());
        }

        match self.codec {
            IvfCodec::Vp8 => self.write_vp8(packet),
            IvfCodec::Vp9 => self.write_vp9(packet),
            IvfCodec::Av1 => self.write_av1(packet),
        }
    }

    /// close stops the recording
    fn close(&mut self) -> Result<()> {
        // Update the frame count
        self.writer.seek(SeekFrom::Start(24))?;
        self.writer.write_u32::<LittleEndian>(self.count as u32)?;

        self.writer.flush()?;
        Ok(())
    }
}
