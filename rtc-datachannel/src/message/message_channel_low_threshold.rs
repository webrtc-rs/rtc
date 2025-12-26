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
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct DataChannelLowThreshold(pub u32); // internal usage only

impl MarshalSize for DataChannelLowThreshold {
    fn marshal_size(&self) -> usize {
        4
    }
}

impl Marshal for DataChannelLowThreshold {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        buf.put_u32(self.0);
        Ok(self.marshal_size())
    }
}

impl Unmarshal for DataChannelLowThreshold {
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let v = buf.get_u32();
        Ok(Self(v))
    }
}
