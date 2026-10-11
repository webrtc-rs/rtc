//! Splitting a TURN byte stream back into messages (RFC 8656 §12.5).
//!
//! Over TCP or TLS, TURN sends STUN messages and ChannelData messages back to
//! back with no framing of their own: each is self-delimiting. This is not the
//! RFC 4571 length prefix that ICE-TCP uses — see [`tcp_framing`](crate::tcp_framing)
//! for that — and a stream carries one or the other, never both.
//!
//! ```text
//! STUN         00xxxxxx ........ | length (16) | magic cookie, id ... | attributes
//!              total = 20 + length
//! ChannelData  01xxxxxx ........ | length (16) | data | padding to a multiple of 4
//!              total = 4 + length rounded up to 4
//! ```
//!
//! The first two bits tell them apart. Anything else cannot be TURN, and since
//! a stream has no resynchronisation point it is an error that ends the stream.
//!
//! ```rust
//! use rtc_shared::turn_framing::TurnStreamDecoder;
//!
//! // A ChannelData message on channel 0x4000 carrying three bytes, padded to 8.
//! let wire = [0x40, 0x00, 0x00, 0x03, b'a', b'b', b'c', 0x00];
//! let mut decoder = TurnStreamDecoder::new();
//! decoder.extend_from_slice(&wire[..5]);
//! assert_eq!(decoder.next_message().unwrap(), None); // not all of it yet
//! decoder.extend_from_slice(&wire[5..]);
//! assert_eq!(decoder.next_message().unwrap(), Some(wire.to_vec()));
//! ```

use crate::error::{Error, Result};

/// Sans-IO splitter for a TURN stream: push bytes as they arrive, pop whole
/// messages. A message comes out exactly as it was on the wire, ChannelData
/// padding included, which TURN's decoders accept.
#[derive(Debug, Default)]
pub struct TurnStreamDecoder {
    buffer: Vec<u8>,
}

impl TurnStreamDecoder {
    /// Creates a decoder with an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes read from the stream.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// The next complete message, `Ok(None)` while one is still arriving, or an
    /// error when the stream holds something that is not TURN.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>> {
        // Both kinds carry their length in bytes 2..4, so four bytes decide it.
        if self.buffer.len() < CHANNEL_DATA_HEADER_LEN {
            return Ok(None);
        }
        let length = u16::from_be_bytes([self.buffer[2], self.buffer[3]]) as usize;
        let total = match self.buffer[0] >> 6 {
            0b00 => STUN_HEADER_LEN + length,
            0b01 => CHANNEL_DATA_HEADER_LEN + length.next_multiple_of(4),
            _ => {
                return Err(Error::OtherTurnErr(format!(
                    "stream byte {:#04x} starts neither a STUN nor a ChannelData message",
                    self.buffer[0]
                )));
            }
        };
        if self.buffer.len() < total {
            return Ok(None);
        }
        let message = self.buffer[..total].to_vec();
        self.buffer.drain(..total);
        Ok(Some(message))
    }

    /// Bytes held that do not yet make a whole message.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

/// A STUN header: type, length, magic cookie and transaction id (RFC 8489 §5).
const STUN_HEADER_LEN: usize = 20;
/// A ChannelData header: channel number and length (RFC 8656 §12.4).
const CHANNEL_DATA_HEADER_LEN: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    /// A STUN Binding request header with `length` bytes of attributes (zeros).
    fn stun(length: u16) -> Vec<u8> {
        let mut msg = vec![0x00, 0x01];
        msg.extend_from_slice(&length.to_be_bytes());
        msg.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        msg.extend_from_slice(&[7; 12]);
        msg.extend(std::iter::repeat_n(0u8, length as usize));
        msg
    }

    /// A ChannelData message on 0x4000 carrying `data`, padded to a multiple of 4.
    fn channel_data(data: &[u8]) -> Vec<u8> {
        let mut msg = vec![0x40, 0x00];
        msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
        msg.extend_from_slice(data);
        while msg.len() % 4 != 0 {
            msg.push(0);
        }
        msg
    }

    fn drain(decoder: &mut TurnStreamDecoder) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(msg) = decoder.next_message().unwrap() {
            out.push(msg);
        }
        out
    }

    #[test]
    fn a_stun_message_is_twenty_bytes_plus_its_length() {
        let msg = stun(8);
        let mut decoder = TurnStreamDecoder::new();
        decoder.extend_from_slice(&msg);
        assert_eq!(drain(&mut decoder), vec![msg]);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn channel_data_comes_out_with_its_padding() {
        for data in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"abcde"] {
            let msg = channel_data(data);
            let mut decoder = TurnStreamDecoder::new();
            decoder.extend_from_slice(&msg);
            assert_eq!(drain(&mut decoder), vec![msg], "{} data bytes", data.len());
            assert_eq!(decoder.buffered_len(), 0);
        }
    }

    #[test]
    fn messages_arriving_together_come_out_one_by_one() {
        let (a, b, c) = (stun(4), channel_data(b"xyz"), stun(0));
        let mut decoder = TurnStreamDecoder::new();
        decoder.extend_from_slice(&[a.clone(), b.clone(), c.clone()].concat());
        assert_eq!(drain(&mut decoder), vec![a, b, c]);
    }

    #[test]
    fn a_message_split_across_reads_waits_until_it_is_whole() {
        let msg = channel_data(b"hello");
        let mut decoder = TurnStreamDecoder::new();
        // One byte at a time, including splits inside the four-byte header.
        for (i, byte) in msg.iter().enumerate() {
            decoder.extend_from_slice(&[*byte]);
            if i + 1 < msg.len() {
                assert_eq!(decoder.next_message().unwrap(), None, "early at byte {i}");
            }
        }
        assert_eq!(drain(&mut decoder), vec![msg]);
    }

    #[test]
    fn a_partial_message_after_a_whole_one_stays_buffered() {
        let whole = stun(0);
        let next = channel_data(b"later");
        let mut decoder = TurnStreamDecoder::new();
        decoder.extend_from_slice(&[whole.clone(), next[..3].to_vec()].concat());
        assert_eq!(drain(&mut decoder), vec![whole]);
        assert_eq!(decoder.buffered_len(), 3);
        decoder.extend_from_slice(&next[3..]);
        assert_eq!(drain(&mut decoder), vec![next]);
    }

    #[test]
    fn bytes_that_are_not_turn_end_the_stream() {
        // 10xxxxxx and 11xxxxxx are neither STUN nor ChannelData.
        for first in [0x80u8, 0xbf, 0xc0, 0xff] {
            let mut decoder = TurnStreamDecoder::new();
            decoder.extend_from_slice(&[first, 0, 0, 4, 1, 2, 3, 4]);
            assert!(
                matches!(decoder.next_message(), Err(Error::OtherTurnErr(_))),
                "first byte {first:#04x} was accepted"
            );
        }
    }
}
