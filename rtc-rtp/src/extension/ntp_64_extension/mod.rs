#[cfg(test)]
mod ntp_64_extension_test;

use bytes::{Buf, BufMut};
use shared::error::{Error, Result};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

/// The extension's encoded size: a full-resolution 64-bit NTP timestamp.
pub const NTP_64_EXTENSION_SIZE: usize = 8;

/// Ntp64Extension is an extension payload format described in `urn:ietf:params:rtp-hdrext:ntp-64`.
///
/// Unlike the abs-send-time extension, which truncates the NTP timestamp to a 6.18 fixed-point
/// value to fit 3 bytes, this extension carries the full 32.32 fixed-point NTP timestamp.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  ID   | len=7 |               NTP timestamp                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    NTP timestamp (cont.)                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct Ntp64Extension {
    /// The timestamp in the standard 32.32 fixed-point NTP format.
    pub timestamp: u64,
}

impl Unmarshal for Ntp64Extension {
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < NTP_64_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }

        let timestamp = buf.get_u64();

        Ok(Ntp64Extension { timestamp })
    }
}

impl MarshalSize for Ntp64Extension {
    fn marshal_size(&self) -> usize {
        NTP_64_EXTENSION_SIZE
    }
}

impl Marshal for Ntp64Extension {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < NTP_64_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }

        buf.put_u64(self.timestamp);

        Ok(NTP_64_EXTENSION_SIZE)
    }
}

impl Ntp64Extension {
    /// An ntp-64 extension carrying `timestamp`, the standard 32.32 fixed-point NTP timestamp.
    pub fn new(timestamp: u64) -> Self {
        Ntp64Extension { timestamp }
    }
}
