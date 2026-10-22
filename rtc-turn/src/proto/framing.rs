//! Cutting a TCP or TLS byte stream into TURN messages.
//!
//! Over a stream there are no datagram boundaries: STUN messages and ChannelData both have to be
//! delimited by their own length fields ([RFC 8656 §3.1] and [§12.5]). Feed the bytes received so
//! far to [`frame_length`](crate::proto::framing::frame_length) and hand each complete message to the server.
//!
//! [RFC 8656 §3.1]: https://www.rfc-editor.org/rfc/rfc8656#section-3.1
//! [§12.5]: https://www.rfc-editor.org/rfc/rfc8656#section-12.5

use shared::error::{Error, Result};

const STUN_HEADER_SIZE: usize = 20;
const CHANNEL_DATA_HEADER_SIZE: usize = 4;

/// The length of the message at the start of `buf`, padding included, once all of it has arrived.
///
/// Returns `Ok(None)` while more bytes are needed.
///
/// # Errors
///
/// Fails if `buf` starts with neither a STUN message nor ChannelData, which means the stream is
/// out of step and the connection should be closed.
pub fn frame_length(buf: &[u8]) -> Result<Option<usize>> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    let total = match first >> 6 {
        // STUN: the two high bits are zero; the length counts everything after the header.
        0b00 => {
            if buf.len() < STUN_HEADER_SIZE {
                return Ok(None);
            }
            STUN_HEADER_SIZE + u16::from_be_bytes([buf[2], buf[3]]) as usize
        }
        // ChannelData: padded to a multiple of four bytes on a stream.
        0b01 => {
            if buf.len() < CHANNEL_DATA_HEADER_SIZE {
                return Ok(None);
            }
            let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            (CHANNEL_DATA_HEADER_SIZE + length).next_multiple_of(4)
        }
        _ => return Err(Error::Other("not a TURN message".to_owned())),
    };
    Ok((buf.len() >= total).then_some(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_message_waits_for_its_whole_length() {
        let mut msg = vec![0x00, 0x01, 0x00, 0x04, 0x21, 0x12, 0xa4, 0x42];
        msg.extend_from_slice(&[7; 12]);
        msg.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(frame_length(&msg[..19]).unwrap(), None);
        assert_eq!(frame_length(&msg[..23]).unwrap(), None);
        assert_eq!(frame_length(&msg).unwrap(), Some(24));
        msg.extend_from_slice(&[9; 5]);
        assert_eq!(frame_length(&msg).unwrap(), Some(24));
    }

    #[test]
    fn channel_data_is_padded_to_four() {
        let msg = [0x40, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5, 0, 0, 0];
        assert_eq!(frame_length(&msg[..8]).unwrap(), None);
        assert_eq!(frame_length(&msg[..11]).unwrap(), None);
        assert_eq!(frame_length(&msg).unwrap(), Some(12));
    }

    #[test]
    fn garbage_is_an_error_and_nothing_is_not() {
        assert_eq!(frame_length(&[]).unwrap(), None);
        assert!(frame_length(&[0xff, 0, 0, 0]).is_err());
        assert!(frame_length(&[0x80, 0, 0, 0]).is_err());
    }
}
