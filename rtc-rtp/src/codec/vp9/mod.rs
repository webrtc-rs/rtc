#[cfg(test)]
mod vp9_test;

mod header;

pub use header::{HeaderColorConfig, HeaderFrameSize, Vp9Header};

use crate::packetizer::{Depacketizer, Payloader};
use shared::error::{Error, Result};

use bytes::{BufMut, Bytes, BytesMut};
use std::fmt;
use std::sync::Arc;

const MAX_SPATIAL_LAYERS: u8 = 5;
const MAX_VP9REF_PICS: usize = 3;

/// InitialPictureIDFn is a function that returns random initial picture ID.
pub type InitialPictureIDFn = Arc<dyn (Fn() -> u16) + Send + Sync>;

/// Vp9Payloader payloads VP9 packets
#[derive(Default, Clone)]
pub struct Vp9Payloader {
    picture_id: u16,
    initialized: bool,

    /// Use the flexible mode (F=1), which carries no scalability structure, instead of the
    /// non-flexible mode (F=0), which announces a key frame's resolution.
    pub flexible_mode: bool,

    /// Supplies the starting picture id; randomized when absent.
    pub initial_picture_id_fn: Option<InitialPictureIDFn>,
}

impl fmt::Debug for Vp9Payloader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vp9Payloader")
            .field("picture_id", &self.picture_id)
            .field("initialized", &self.initialized)
            .field("flexible_mode", &self.flexible_mode)
            .finish()
    }
}

impl Payloader for Vp9Payloader {
    /// Payload fragments a VP9 frame across one or more payloads.
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if !self.initialized {
            if self.initial_picture_id_fn.is_none() {
                self.initial_picture_id_fn =
                    Some(Arc::new(|| -> u16 { rand::random::<u16>() % 0x7FFF }));
            }
            self.picture_id = self.initial_picture_id_fn.as_ref().map_or(0, |f| f()) & 0x7FFF;
            self.initialized = true;
        }

        let payloads = if self.flexible_mode {
            self.payload_flexible(mtu, payload)
        } else {
            self.payload_non_flexible(mtu, payload)
        };

        self.picture_id += 1;
        if self.picture_id >= 0x8000 {
            self.picture_id = 0;
        }

        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(self.clone())
    }
}

impl Vp9Payloader {
    /// Flexible mode (F=1):
    ///
    /// ```text
    ///        0 1 2 3 4 5 6 7
    ///       +-+-+-+-+-+-+-+-+
    ///       |I|P|L|F|B|E|V|Z| (REQUIRED)
    ///       +-+-+-+-+-+-+-+-+
    ///  I:   |M| PICTURE ID  | (REQUIRED)
    ///       +-+-+-+-+-+-+-+-+
    ///  M:   | EXTENDED PID  | (RECOMMENDED)
    ///       +-+-+-+-+-+-+-+-+
    /// ```
    fn payload_flexible(&self, mtu: usize, payload: &Bytes) -> Vec<Bytes> {
        const HEADER_SIZE: usize = 3;
        let max_fragment_size = mtu as isize - HEADER_SIZE as isize;
        if max_fragment_size.min(payload.len() as isize) <= 0 {
            return vec![];
        }
        let max_fragment_size = max_fragment_size as usize;

        let mut payloads = vec![];
        let mut remaining = payload.len();
        let mut index = 0;
        while remaining > 0 {
            let fragment = max_fragment_size.min(remaining);
            let mut out = BytesMut::with_capacity(HEADER_SIZE + fragment);

            let mut b0 = 0x90; // F=1, I=1
            if index == 0 {
                b0 |= 0x08; // B=1
            }
            if remaining == fragment {
                b0 |= 0x04; // E=1
            }
            out.put_u8(b0);
            out.put_u8((self.picture_id >> 8) as u8 | 0x80);
            out.put_u8(self.picture_id as u8);
            out.put_slice(&payload[index..index + fragment]);
            payloads.push(out.freeze());

            remaining -= fragment;
            index += fragment;
        }
        payloads
    }

    /// Non-flexible mode (F=0). A key frame's first packet carries the scalability structure
    /// with the frame's resolution.
    ///
    /// ```text
    ///        0 1 2 3 4 5 6 7
    ///       +-+-+-+-+-+-+-+-+
    ///       |I|P|L|F|B|E|V|Z| (REQUIRED)
    ///       +-+-+-+-+-+-+-+-+
    ///  I:   |M| PICTURE ID  | (RECOMMENDED)
    ///       +-+-+-+-+-+-+-+-+
    ///  M:   | EXTENDED PID  | (RECOMMENDED)
    ///       +-+-+-+-+-+-+-+-+
    ///  V:   | SS            |
    ///       | ..            |
    ///       +-+-+-+-+-+-+-+-+
    /// ```
    fn payload_non_flexible(&self, mtu: usize, payload: &Bytes) -> Vec<Bytes> {
        let Ok(header) = Vp9Header::unmarshal(payload) else {
            return vec![];
        };

        let mut payloads = vec![];
        let mut remaining = payload.len();
        let mut index = 0;
        while remaining > 0 {
            let with_ss = !header.non_key_frame && index == 0;
            let header_size = if with_ss { 3 + 8 } else { 3 };

            let fragment = (mtu as isize - header_size as isize).min(remaining as isize);
            if fragment <= 0 {
                return vec![];
            }
            let fragment = fragment as usize;

            let mut out = BytesMut::with_capacity(header_size + fragment);

            let mut b0 = 0x80 | 0x01; // I=1, Z=1
            if header.non_key_frame {
                b0 |= 0x40; // P=1
            }
            if index == 0 {
                b0 |= 0x08; // B=1
            }
            if remaining == fragment {
                b0 |= 0x04; // E=1
            }
            if with_ss {
                b0 |= 0x02; // V=1
            }
            out.put_u8(b0);
            out.put_u8((self.picture_id >> 8) as u8 | 0x80);
            out.put_u8(self.picture_id as u8);

            if with_ss {
                out.put_u8(0x10 | 0x08); // N_S=0, Y=1, G=1
                out.put_u16(header.width());
                out.put_u16(header.height());
                out.put_u8(0x01); // N_G=1
                out.put_u8(1 << 4 | 1 << 2); // TID=0, U=1, R=1
                out.put_u8(0x01); // P_DIFF=1
            }

            out.put_slice(&payload[index..index + fragment]);
            payloads.push(out.freeze());

            remaining -= fragment;
            index += fragment;
        }
        payloads
    }
}

/// Vp9Packet represents the VP9 header that is stored in the payload of an RTP Packet
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Vp9Packet {
    /// picture ID is present
    pub i: bool,
    /// inter-picture predicted frame.
    pub p: bool,
    /// layer indices present
    pub l: bool,
    /// flexible mode
    pub f: bool,
    /// start of frame. beginning of new vp9 frame
    pub b: bool,
    /// end of frame
    pub e: bool,
    /// scalability structure (SS) present
    pub v: bool,
    /// Not a reference frame for upper spatial layers
    pub z: bool,

    /// Recommended headers
    /// 7 or 16 bits, picture ID.
    pub picture_id: u16,

    /// Conditionally recommended headers
    /// Temporal layer ID
    pub tid: u8,
    /// Switching up point
    pub u: bool,
    /// Spatial layer ID
    pub sid: u8,
    /// Inter-layer dependency used
    pub d: bool,

    /// Conditionally required headers
    /// Reference index (F=1)
    pub pdiff: Vec<u8>,
    /// Temporal layer zero index (F=0)
    pub tl0picidx: u8,

    /// Scalability structure headers
    /// N_S + 1 indicates the number of spatial layers present in the VP9 stream
    pub ns: u8,
    /// Each spatial layer's frame resolution present
    pub y: bool,
    /// PG description present flag.
    pub g: bool,
    /// N_G indicates the number of pictures in a Picture Group (PG)
    pub ng: u8,
    /// Frame width for each spatial layer.
    pub width: Vec<u16>,
    /// Frame height for each spatial layer.
    pub height: Vec<u16>,
    /// Temporal layer ID of pictures in a Picture Group
    pub pgtid: Vec<u8>,
    /// Switching up point of pictures in a Picture Group
    pub pgu: Vec<bool>,
    /// Reference indices of pictures in a Picture Group
    pub pgpdiff: Vec<Vec<u8>>,
}

impl Depacketizer for Vp9Packet {
    /// depacketize parses the passed byte slice and stores the result in the Vp9Packet this method is called upon
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.is_empty() {
            return Err(Error::ErrShortPacket);
        }

        let b = packet[0];
        self.i = (b & 0x80) != 0;
        self.p = (b & 0x40) != 0;
        self.l = (b & 0x20) != 0;
        self.f = (b & 0x10) != 0;
        self.b = (b & 0x08) != 0;
        self.e = (b & 0x04) != 0;
        self.v = (b & 0x02) != 0;
        self.z = (b & 0x01) != 0;

        // Optional fields are cleared first so a reused `Vp9Packet` never reports a previous
        // packet's descriptor.
        self.picture_id = 0;
        (self.tid, self.u, self.sid, self.d, self.tl0picidx) = (0, false, 0, false, 0);
        self.pdiff.clear();
        (self.ns, self.y, self.g, self.ng) = (0, false, false, 0);
        self.width.clear();
        self.height.clear();
        self.pgtid.clear();
        self.pgu.clear();
        self.pgpdiff.clear();

        let mut pos = 1;
        if self.i {
            pos = self.parse_picture_id(packet, pos)?;
        }
        if self.l {
            pos = self.parse_layer_info(packet, pos)?;
        }
        if self.f && self.p {
            pos = self.parse_ref_indices(packet, pos)?;
        }
        if self.v {
            pos = self.parse_ssdata(packet, pos)?;
        }

        Ok(packet.slice(pos..))
    }

    /// is_partition_head checks whether if this is a head of the VP9 partition
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        payload.first().is_some_and(|b| b & 0x08 != 0)
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}

impl Vp9Packet {
    // Picture ID:
    //
    //      +-+-+-+-+-+-+-+-+
    // I:   |M| PICTURE ID  |   M:0 => picture id is 7 bits.
    //      +-+-+-+-+-+-+-+-+   M:1 => picture id is 15 bits.
    // M:   | EXTENDED PID  |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_picture_id(&mut self, packet: &[u8], mut pos: usize) -> Result<usize> {
        if packet.len() <= pos {
            return Err(Error::ErrShortPacket);
        }
        self.picture_id = (packet[pos] & 0x7F) as u16;
        if packet[pos] & 0x80 != 0 {
            pos += 1;
            if packet.len() <= pos {
                return Err(Error::ErrShortPacket);
            }
            self.picture_id = (self.picture_id << 8) | packet[pos] as u16;
        }
        Ok(pos + 1)
    }

    fn parse_layer_info(&mut self, packet: &[u8], pos: usize) -> Result<usize> {
        let pos = self.parse_layer_info_common(packet, pos)?;
        if self.f {
            Ok(pos)
        } else {
            self.parse_layer_info_non_flexible_mode(packet, pos)
        }
    }

    // Layer indices (flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_common(&mut self, packet: &[u8], pos: usize) -> Result<usize> {
        if packet.len() <= pos {
            return Err(Error::ErrShortPacket);
        }
        let b = packet[pos];
        self.tid = b >> 5;
        self.u = b & 0x10 != 0;
        self.sid = (b >> 1) & 0x7;
        self.d = b & 0x01 != 0;

        if self.sid >= MAX_SPATIAL_LAYERS {
            return Err(Error::ErrTooManySpatialLayers);
        }
        Ok(pos + 1)
    }

    // Layer indices (non-flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //      |   tl0picidx   |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_non_flexible_mode(&mut self, packet: &[u8], pos: usize) -> Result<usize> {
        if packet.len() <= pos {
            return Err(Error::ErrShortPacket);
        }
        self.tl0picidx = packet[pos];
        Ok(pos + 1)
    }

    // Reference indices:
    //
    //      +-+-+-+-+-+-+-+-+                P=1,F=1: At least one reference index
    // P,F: | P_DIFF      |N|  up to 3 times          has to be specified.
    //      +-+-+-+-+-+-+-+-+                    N=1: An additional P_DIFF follows
    //                                                current P_DIFF.
    //
    fn parse_ref_indices(&mut self, packet: &[u8], mut pos: usize) -> Result<usize> {
        loop {
            if packet.len() <= pos {
                return Err(Error::ErrShortPacket);
            }
            self.pdiff.push(packet[pos] >> 1);
            if packet[pos] & 0x01 == 0 {
                break;
            }
            if self.pdiff.len() >= MAX_VP9REF_PICS {
                return Err(Error::ErrTooManyPDiff);
            }
            pos += 1;
        }
        Ok(pos + 1)
    }

    // Scalability structure (SS):
    //
    //      +-+-+-+-+-+-+-+-+
    // V:   | N_S |Y|G|-|-|-|
    //      +-+-+-+-+-+-+-+-+              -|
    // Y:   |     WIDTH     | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+               . N_S + 1 times
    //      |     HEIGHT    | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+              -|
    // G:   |      N_G      | (OPTIONAL)
    //      +-+-+-+-+-+-+-+-+                           -|
    // N_G: |  T  |U| R |-|-| (OPTIONAL)                 .
    //      +-+-+-+-+-+-+-+-+              -|            . N_G times
    //      |    P_DIFF     | (OPTIONAL)    . R times    .
    //      +-+-+-+-+-+-+-+-+              -|           -|
    //
    fn parse_ssdata(&mut self, packet: &[u8], mut pos: usize) -> Result<usize> {
        if packet.len() <= pos {
            return Err(Error::ErrShortPacket);
        }

        self.ns = packet[pos] >> 5;
        self.y = packet[pos] & 0x10 != 0;
        self.g = packet[pos] & 0x08 != 0;
        pos += 1;

        let ns = self.ns as usize + 1;
        self.ng = 0;

        if self.y {
            self.width = vec![0; ns];
            self.height = vec![0; ns];
            for i in 0..ns {
                if packet.len() <= pos + 3 {
                    return Err(Error::ErrShortPacket);
                }
                self.width[i] = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
                pos += 2;
                self.height[i] = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
                pos += 2;
            }
        }

        if self.g {
            if packet.len() <= pos {
                return Err(Error::ErrShortPacket);
            }
            self.ng = packet[pos];
            pos += 1;
        }

        for i in 0..self.ng as usize {
            if packet.len() <= pos {
                return Err(Error::ErrShortPacket);
            }
            self.pgtid.push(packet[pos] >> 5);
            self.pgu.push(packet[pos] & 0x10 != 0);
            let reference = ((packet[pos] >> 2) & 0x3) as usize;
            pos += 1;

            self.pgpdiff.push(vec![]);
            if packet.len() < pos + reference {
                return Err(Error::ErrShortPacket);
            }
            for _ in 0..reference {
                self.pgpdiff[i].push(packet[pos]);
                pos += 1;
            }
        }

        Ok(pos)
    }
}
