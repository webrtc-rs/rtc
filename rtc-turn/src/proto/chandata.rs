#[cfg(test)]
mod chandata_test;

use super::channum::*;
use shared::error::{Error, Result};

const PADDING: usize = 4;

fn nearest_padded_value_length(l: usize) -> usize {
    let mut n = PADDING * (l / PADDING);
    if n < l {
        n += PADDING;
    }
    n
}

const CHANNEL_DATA_LENGTH_SIZE: usize = 2;
const CHANNEL_DATA_NUMBER_SIZE: usize = CHANNEL_DATA_LENGTH_SIZE;
const CHANNEL_DATA_HEADER_SIZE: usize = CHANNEL_DATA_LENGTH_SIZE + CHANNEL_DATA_NUMBER_SIZE;

/// `ChannelData` represents the `ChannelData` Message defined in
/// [RFC 5766 Section 11.4](https://www.rfc-editor.org/rfc/rfc5766#section-11.4).
#[derive(Default, Debug)]
pub struct ChannelData {
    /// The relayed payload. May be a subslice of [`Self::raw`].
    pub data: Vec<u8>, // can be subslice of Raw
    /// The channel this data belongs to, which identifies the peer.
    pub number: ChannelNumber,
    /// The full encoded message, header included.
    pub raw: Vec<u8>,
}

impl PartialEq for ChannelData {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.number == other.number
    }
}

impl ChannelData {
    /// Resets length, [`Self::data`] and [`Self::raw`] length.
    #[inline]
    pub fn reset(&mut self) {
        self.raw.clear();
        self.data.clear();
    }

    /// Encodes this to [`Self::raw`].
    pub fn encode(&mut self) {
        self.raw.clear();
        self.write_header();
        self.raw.extend_from_slice(&self.data);
        let padded = nearest_padded_value_length(self.raw.len());
        let bytes_to_add = padded - self.raw.len();
        if bytes_to_add > 0 {
            self.raw.resize(padded, 0);
        }
    }

    /// Decodes this from [`Self::raw`].
    pub fn decode(&mut self) -> Result<()> {
        let (number, payload) = Self::parse(&self.raw)?;
        self.number = number;
        // Reuse `data`'s buffer: decoding repeatedly into one `ChannelData` allocates only on growth.
        self.data.clear();
        self.data.extend_from_slice(payload);
        Ok(())
    }

    /// Parses a `ChannelData` message in place: the channel number and the payload, which is a
    /// subslice of `buf` (pion's `Decode` aliases the input the same way). Nothing is copied.
    pub fn parse(buf: &[u8]) -> Result<(ChannelNumber, &[u8])> {
        if buf.len() < CHANNEL_DATA_HEADER_SIZE {
            return Err(Error::ErrUnexpectedEof);
        }
        let number = ChannelNumber(u16::from_be_bytes([buf[0], buf[1]]));
        if !number.valid() {
            return Err(Error::ErrInvalidChannelNumber);
        }
        let l = u16::from_be_bytes([
            buf[CHANNEL_DATA_NUMBER_SIZE],
            buf[CHANNEL_DATA_NUMBER_SIZE + 1],
        ]) as usize;
        let body = &buf[CHANNEL_DATA_HEADER_SIZE..];
        if l > body.len() {
            return Err(Error::ErrBadChannelDataLength);
        }
        Ok((number, &body[..l]))
    }

    /// Appends the encoded message for `data` on channel `number` to `out`, padded to a multiple
    /// of four bytes as [`encode`](Self::encode) does, without building a `ChannelData` first.
    pub fn encode_into(number: ChannelNumber, data: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.reserve(CHANNEL_DATA_HEADER_SIZE + data.len() + PADDING);
        out.extend_from_slice(&number.0.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        let padded = start + nearest_padded_value_length(out.len() - start);
        out.resize(padded, 0);
    }

    /// Writes channel number and length.
    pub fn write_header(&mut self) {
        if self.raw.len() < CHANNEL_DATA_HEADER_SIZE {
            // Making WriteHeader call valid even when c.Raw
            // is nil or len(c.Raw) is less than needed for header.
            self.raw
                .resize(self.raw.len() + CHANNEL_DATA_HEADER_SIZE, 0);
        }
        self.raw[..CHANNEL_DATA_NUMBER_SIZE].copy_from_slice(&self.number.0.to_be_bytes());
        self.raw[CHANNEL_DATA_NUMBER_SIZE..CHANNEL_DATA_HEADER_SIZE]
            .copy_from_slice(&(self.data.len() as u16).to_be_bytes());
    }

    /// Returns `true` if `buf` looks like the `ChannelData` Message.
    pub fn is_channel_data(buf: &[u8]) -> bool {
        if buf.len() < CHANNEL_DATA_HEADER_SIZE {
            return false;
        }

        if u16::from_be_bytes([
            buf[CHANNEL_DATA_NUMBER_SIZE],
            buf[CHANNEL_DATA_NUMBER_SIZE + 1],
        ]) > buf[CHANNEL_DATA_HEADER_SIZE..].len() as u16
        {
            return false;
        }

        // Quick check for channel number.
        let num = ChannelNumber(u16::from_be_bytes([buf[0], buf[1]]));
        num.valid()
    }
}
