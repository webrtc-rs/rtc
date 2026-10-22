//! A parser for the VP9 uncompressed frame header, enough to tell key frames from inter frames
//! and to read a key frame's dimensions ([VP9 bitstream specification] §6.2).
//!
//! [VP9 bitstream specification]: https://storage.googleapis.com/downloads.webmproject.org/docs/vp9/vp9-bitstream-specification-v0.6-20160331-draft.pdf

use shared::error::{Error, Result};

/// A bit cursor over a byte slice, most significant bit first.
struct Bits<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn has_space(&self, n: usize) -> Result<()> {
        if n > self.buf.len() * 8 - self.pos {
            Err(Error::ErrVp9NotEnoughBits)
        } else {
            Ok(())
        }
    }

    fn flag(&mut self) -> Result<bool> {
        Ok(self.bits(1)? == 1)
    }

    fn bits(&mut self, n: usize) -> Result<u64> {
        self.has_space(n)?;
        let mut out = 0u64;
        for _ in 0..n {
            let bit = (self.buf[self.pos >> 3] >> (7 - (self.pos & 7))) & 1;
            out = (out << 1) | bit as u64;
            self.pos += 1;
        }
        Ok(out)
    }
}

/// The `color_config` member of a frame header.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeaderColorConfig {
    /// Whether the bit depth is 12 rather than 10 (profiles 2 and 3 only).
    pub ten_or_twelve_bit: bool,
    /// The bit depth: 8, 10 or 12.
    pub bit_depth: u8,
    /// The color space (7 is sRGB).
    pub color_space: u8,
    /// Whether the color range is full.
    pub color_range: bool,
    /// Horizontal chroma subsampling.
    pub subsampling_x: bool,
    /// Vertical chroma subsampling.
    pub subsampling_y: bool,
}

impl HeaderColorConfig {
    fn unmarshal(&mut self, profile: u8, bits: &mut Bits<'_>) -> Result<()> {
        if profile >= 2 {
            self.ten_or_twelve_bit = bits.flag()?;
            self.bit_depth = if self.ten_or_twelve_bit { 12 } else { 10 };
        } else {
            self.bit_depth = 8;
        }

        self.color_space = bits.bits(3)? as u8;

        if self.color_space != 7 {
            self.color_range = bits.flag()?;
            if profile == 1 || profile == 3 {
                bits.has_space(3)?;
                self.subsampling_x = bits.flag()?;
                self.subsampling_y = bits.flag()?;
                bits.pos += 1;
            } else {
                self.subsampling_x = true;
                self.subsampling_y = true;
            }
        } else {
            self.color_range = true;
            if profile == 1 || profile == 3 {
                self.subsampling_x = false;
                self.subsampling_y = false;
                bits.has_space(1)?;
                bits.pos += 1;
            }
        }
        Ok(())
    }
}

/// The `frame_size` member of a key frame header.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeaderFrameSize {
    /// The frame width minus one.
    pub frame_width_minus1: u16,
    /// The frame height minus one.
    pub frame_height_minus1: u16,
}

/// A VP9 uncompressed frame header.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Vp9Header {
    /// The bitstream profile, 0 to 3.
    pub profile: u8,
    /// Whether this frame only re-displays a stored frame.
    pub show_existing_frame: bool,
    /// Which stored frame to re-display.
    pub frame_to_show_map_idx: u8,
    /// Whether this is an inter frame (not a key frame).
    pub non_key_frame: bool,
    /// Whether the frame is shown.
    pub show_frame: bool,
    /// Whether error-resilient mode is on.
    pub error_resilient_mode: bool,
    /// The color configuration, on key frames.
    pub color_config: Option<HeaderColorConfig>,
    /// The frame size, on key frames.
    pub frame_size: Option<HeaderFrameSize>,
}

impl Vp9Header {
    /// Decodes a frame header from the start of a VP9 frame.
    pub fn unmarshal(buf: &[u8]) -> Result<Self> {
        let mut h = Vp9Header::default();
        let mut bits = Bits { buf, pos: 0 };

        bits.has_space(4)?;
        if bits.bits(2)? != 2 {
            return Err(Error::ErrVp9InvalidFrameMarker);
        }

        let profile_low = bits.bits(1)? as u8;
        let profile_high = bits.bits(1)? as u8;
        h.profile = (profile_high << 1) + profile_low;

        if h.profile == 3 {
            bits.has_space(1)?;
            bits.pos += 1;
        }

        h.show_existing_frame = bits.flag()?;
        if h.show_existing_frame {
            h.frame_to_show_map_idx = bits.bits(3)? as u8;
            return Ok(h);
        }

        bits.has_space(3)?;
        h.non_key_frame = bits.flag()?;
        h.show_frame = bits.flag()?;
        h.error_resilient_mode = bits.flag()?;

        if !h.non_key_frame {
            bits.has_space(24)?;
            if bits.bits(8)? != 0x49 {
                return Err(Error::ErrVp9WrongFrameSyncByte);
            }
            if bits.bits(8)? != 0x83 {
                return Err(Error::ErrVp9WrongFrameSyncByte);
            }
            if bits.bits(8)? != 0x42 {
                return Err(Error::ErrVp9WrongFrameSyncByte);
            }

            let mut cc = HeaderColorConfig::default();
            cc.unmarshal(h.profile, &mut bits)?;
            h.color_config = Some(cc);

            bits.has_space(32)?;
            h.frame_size = Some(HeaderFrameSize {
                frame_width_minus1: bits.bits(16)? as u16,
                frame_height_minus1: bits.bits(16)? as u16,
            });
        }

        Ok(h)
    }

    /// The frame width, or 0 when the header carries no frame size.
    pub fn width(&self) -> u16 {
        self.frame_size
            .as_ref()
            .map_or(0, |s| s.frame_width_minus1 + 1)
    }

    /// The frame height, or 0 when the header carries no frame size.
    pub fn height(&self) -> u16 {
        self.frame_size
            .as_ref()
            .map_or(0, |s| s.frame_height_minus1 + 1)
    }
}
