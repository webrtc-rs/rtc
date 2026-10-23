#[cfg(test)]
mod abs_capture_time_extension_test;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut};

/// The encoded size without the estimated capture clock offset.
pub const ABS_CAPTURE_TIME_EXTENSION_SIZE: usize = 8;
/// The encoded size with the estimated capture clock offset.
pub const ABS_CAPTURE_TIME_EXTENDED_EXTENSION_SIZE: usize = 16;

/// Seconds between the NTP epoch (1900) and the Unix epoch (1970).
const NTP_UNIX_OFFSET_SECS: u64 = 0x83AA_7E80;

/// AbsCaptureTimeExtension is an extension payload format in
/// <http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time>
///
/// The capture timestamp is a 64-bit NTP timestamp (32.32 fixed point); the optional
/// estimated capture clock offset is a signed 64-bit 32.32 fixed-point number of seconds.
#[derive(PartialEq, Eq, Debug, Default, Copy, Clone)]
pub struct AbsCaptureTimeExtension {
    /// The absolute capture time as a 64-bit NTP timestamp.
    pub timestamp: u64,
    /// The offset between the capturer's clock and the NTP clock in 32.32 fixed-point seconds,
    /// when the capturer knows it.
    pub estimated_capture_clock_offset: Option<i64>,
}

impl AbsCaptureTimeExtension {
    /// Builds the extension from a capture time (pion's `NewAbsCaptureTimeExtension`).
    pub fn new(capture_time: SystemTime) -> Self {
        AbsCaptureTimeExtension {
            timestamp: to_ntp_time(capture_time),
            estimated_capture_clock_offset: None,
        }
    }

    /// Builds the extension from a capture time and a capture clock offset in nanoseconds
    /// (pion's `NewAbsCaptureTimeExtensionWithCaptureClockOffset`).
    pub fn with_capture_clock_offset(capture_time: SystemTime, offset_nanos: i64) -> Self {
        let negative = offset_nanos < 0;
        let ns = offset_nanos.unsigned_abs() as u128;
        let secs = ((ns / 1_000_000_000) & 0xFFFF_FFFF) as i64;
        let frac = ((((ns % 1_000_000_000) << 32) / 1_000_000_000) & 0xFFFF_FFFF) as i64;
        let offset = (secs << 32) | frac;

        AbsCaptureTimeExtension {
            timestamp: to_ntp_time(capture_time),
            estimated_capture_clock_offset: Some(if negative { -offset } else { offset }),
        }
    }

    /// The capture time this extension represents (pion's `CaptureTime`).
    pub fn capture_time(&self) -> SystemTime {
        from_ntp_time(self.timestamp)
    }

    /// The estimated capture clock offset in nanoseconds, if present
    /// (pion's `EstimatedCaptureClockOffsetDuration`).
    pub fn estimated_capture_clock_offset_nanos(&self) -> Option<i64> {
        let offset = self.estimated_capture_clock_offset?;
        let abs = offset.unsigned_abs();
        let nanos = (abs >> 32) as i128 * 1_000_000_000
            + (((abs & 0xFFFF_FFFF) as u128 * 1_000_000_000) >> 32) as i128;
        let nanos = nanos as i64;

        Some(if offset < 0 { -nanos } else { nanos })
    }
}

impl Unmarshal for AbsCaptureTimeExtension {
    /// Unmarshal parses the passed byte slice and stores the result in the members.
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < ABS_CAPTURE_TIME_EXTENSION_SIZE {
            return Err(Error::ErrBufferTooSmall);
        }

        let timestamp = raw_packet.get_u64();
        let estimated_capture_clock_offset =
            if raw_packet.remaining() >= ABS_CAPTURE_TIME_EXTENSION_SIZE {
                Some(raw_packet.get_i64())
            } else {
                None
            };

        Ok(AbsCaptureTimeExtension {
            timestamp,
            estimated_capture_clock_offset,
        })
    }
}

impl MarshalSize for AbsCaptureTimeExtension {
    /// MarshalSize returns the size of the AbsCaptureTimeExtension once marshaled.
    fn marshal_size(&self) -> usize {
        if self.estimated_capture_clock_offset.is_some() {
            ABS_CAPTURE_TIME_EXTENDED_EXTENSION_SIZE
        } else {
            ABS_CAPTURE_TIME_EXTENSION_SIZE
        }
    }
}

impl Marshal for AbsCaptureTimeExtension {
    /// MarshalTo serializes the members to buffer.
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        let size = self.marshal_size();
        if buf.remaining_mut() < size {
            return Err(Error::ErrBufferTooSmall);
        }

        buf.put_u64(self.timestamp);
        if let Some(offset) = self.estimated_capture_clock_offset {
            buf.put_i64(offset);
        }

        Ok(size)
    }
}

/// The 64-bit NTP timestamp of a system time (pion's `toNtpTime`).
fn to_ntp_time(t: SystemTime) -> u64 {
    let since_epoch = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = since_epoch.as_secs() + NTP_UNIX_OFFSET_SECS;
    let frac = ((since_epoch.subsec_nanos() as u64) << 32) / 1_000_000_000;

    (secs << 32) | frac
}

/// The system time of a 64-bit NTP timestamp (pion's `toTime`).
fn from_ntp_time(t: u64) -> SystemTime {
    let secs = (t >> 32).saturating_sub(NTP_UNIX_OFFSET_SECS);
    let nanos = ((t & 0xFFFF_FFFF) * 1_000_000_000) >> 32;

    UNIX_EPOCH + Duration::new(secs, nanos as u32)
}
