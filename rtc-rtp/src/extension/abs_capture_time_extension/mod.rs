#[cfg(test)]
mod abs_capture_time_extension_test;

use bytes::{Buf, BufMut};
use shared::error::{Error, Result};
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

/// The size of the mandatory `absolute_capture_timestamp` field, in bytes.
pub const ABS_CAPTURE_TIME_EXTENSION_SIZE: usize = 8;
/// The size of the optional `estimated_capture_clock_offset` field, in bytes.
pub const ABS_CAPTURE_TIME_EXTENSION_SIZE_WITH_OFFSET: usize = 16;

/// AbsCaptureTimeExtension is an extension payload format described in
/// <http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time>
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  ID   | len=7(15)   |         absolute capture timestamp       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             absolute capture timestamp (cont.)                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   estimated capture clock offset (optional, present if len=15)|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             estimated capture clock offset (cont.)            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct AbsCaptureTimeExtension {
    /// The NTP timestamp, in the standard 32.32 fixed-point format, of when the first frame in
    /// this packet was originally captured.
    pub absolute_capture_timestamp: u64,
    /// The estimated offset between the capture clock and the sender's NTP clock, in Q32.32
    /// fixed-point seconds. Only present at the first hop (the capturer); relays and mixers
    /// forward the value they received rather than recomputing it.
    pub estimated_capture_clock_offset: Option<i64>,
}

impl Unmarshal for AbsCaptureTimeExtension {
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < ABS_CAPTURE_TIME_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }
        let absolute_capture_timestamp = buf.get_u64();

        let estimated_capture_clock_offset = if buf.remaining() >= 8 {
            Some(buf.get_i64())
        } else {
            None
        };

        Ok(AbsCaptureTimeExtension {
            absolute_capture_timestamp,
            estimated_capture_clock_offset,
        })
    }
}

impl MarshalSize for AbsCaptureTimeExtension {
    fn marshal_size(&self) -> usize {
        if self.estimated_capture_clock_offset.is_some() {
            ABS_CAPTURE_TIME_EXTENSION_SIZE_WITH_OFFSET
        } else {
            ABS_CAPTURE_TIME_EXTENSION_SIZE
        }
    }
}

impl Marshal for AbsCaptureTimeExtension {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        let size = self.marshal_size();
        if buf.remaining_mut() < size {
            return Err(Error::ErrBufferTooSmall);
        }

        buf.put_u64(self.absolute_capture_timestamp);
        if let Some(offset) = self.estimated_capture_clock_offset {
            buf.put_i64(offset);
        }

        Ok(size)
    }
}

impl AbsCaptureTimeExtension {
    /// An abs-capture-time extension carrying `absolute_capture_timestamp`, an NTP timestamp in
    /// the standard 32.32 fixed-point format, with no capture-clock-offset estimate.
    pub fn new(absolute_capture_timestamp: u64) -> Self {
        AbsCaptureTimeExtension {
            absolute_capture_timestamp,
            estimated_capture_clock_offset: None,
        }
    }

    /// An abs-capture-time extension additionally carrying `estimated_capture_clock_offset`, the
    /// estimated offset between the capture clock and the sender's NTP clock, in Q32.32
    /// fixed-point seconds.
    pub fn new_with_clock_offset(
        absolute_capture_timestamp: u64,
        estimated_capture_clock_offset: i64,
    ) -> Self {
        AbsCaptureTimeExtension {
            absolute_capture_timestamp,
            estimated_capture_clock_offset: Some(estimated_capture_clock_offset),
        }
    }
}
