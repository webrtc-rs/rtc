#[cfg(test)]
mod message_test;

pub mod message_channel_ack;
pub mod message_channel_close;
pub mod message_channel_low_threshold;
pub mod message_channel_open;
pub mod message_type;

use bytes::{Buf, BufMut};
use message_channel_ack::*;
use message_channel_close::*;
use message_channel_low_threshold::*;
use message_channel_open::*;
use message_type::*;
use shared::error::{Error, Result};
use shared::marshal::*;

/// A parsed DataChannel message
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Message {
    DataChannelLowThreshold(DataChannelLowThreshold), // internal usage only
    DataChannelClose(DataChannelClose),               // internal usage only
    DataChannelAck(DataChannelAck),
    DataChannelOpen(DataChannelOpen),
}

impl MarshalSize for Message {
    fn marshal_size(&self) -> usize {
        match self {
            Message::DataChannelLowThreshold(m) => m.marshal_size() + MESSAGE_TYPE_LEN, // internal usage only
            Message::DataChannelClose(m) => m.marshal_size() + MESSAGE_TYPE_LEN, // internal usage only
            Message::DataChannelAck(m) => m.marshal_size() + MESSAGE_TYPE_LEN,
            Message::DataChannelOpen(m) => m.marshal_size() + MESSAGE_TYPE_LEN,
        }
    }
}

impl Marshal for Message {
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        let mut bytes_written = 0;
        let n = self.message_type().marshal_to(buf)?;
        buf = &mut buf[n..];
        bytes_written += n;
        bytes_written += match self {
            Message::DataChannelLowThreshold(low_threshold) => low_threshold.marshal_to(buf)?, // internal usage only
            Message::DataChannelClose(_) => 0, // internal usage only
            Message::DataChannelAck(_) => 0,
            Message::DataChannelOpen(open) => open.marshal_to(buf)?,
        };
        Ok(bytes_written)
    }
}

impl Unmarshal for Message {
    fn unmarshal<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < MESSAGE_TYPE_LEN {
            return Err(Error::UnexpectedEndOfBuffer {
                expected: MESSAGE_TYPE_LEN,
                actual: buf.remaining(),
            });
        }

        match MessageType::unmarshal(buf)? {
            MessageType::DataChannelLowThreshold => Ok(Self::DataChannelLowThreshold(
                DataChannelLowThreshold::unmarshal(buf)?,
            )), // internal usage only
            MessageType::DataChannelClose => Ok(Self::DataChannelClose(DataChannelClose {})), // internal usage only
            MessageType::DataChannelAck => Ok(Self::DataChannelAck(DataChannelAck {})),
            MessageType::DataChannelOpen => {
                Ok(Self::DataChannelOpen(DataChannelOpen::unmarshal(buf)?))
            }
        }
    }
}

impl Message {
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::DataChannelLowThreshold(_) => MessageType::DataChannelLowThreshold, // internal usage only
            Self::DataChannelClose(_) => MessageType::DataChannelClose, // internal usage only
            Self::DataChannelAck(_) => MessageType::DataChannelAck,
            Self::DataChannelOpen(_) => MessageType::DataChannelOpen,
        }
    }
}
