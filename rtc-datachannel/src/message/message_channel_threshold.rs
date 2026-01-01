use super::*;
use shared::error::Result;

/// The data-part of an data-channel CLOSE message without the message type.
///
/// # Memory layout
///
/// ```plain
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///|  Message Type |
///+-+-+-+-+-+-+-+-+
/// ```
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum DataChannelThreshold {
    Low(u32),
    High(u32),
} // internal usage only

impl MarshalSize for DataChannelThreshold {
    fn marshal_size(&self) -> usize {
        1 + 4
    }
}

impl Marshal for DataChannelThreshold {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        match *self {
            DataChannelThreshold::Low(threshold) => {
                buf.put_u8(0);
                buf.put_u32(threshold);
            }
            DataChannelThreshold::High(threshold) => {
                buf.put_u8(1);
                buf.put_u32(threshold);
            }
        }

        Ok(self.marshal_size())
    }
}

impl Unmarshal for DataChannelThreshold {
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let t = buf.get_u8();
        let v = buf.get_u32();
        if t == 0 {
            Ok(DataChannelThreshold::Low(v))
        } else {
            Ok(DataChannelThreshold::High(v))
        }
    }
}
