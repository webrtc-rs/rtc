#[cfg(test)]
mod source_description_test;

use crate::{header::*, packet::*, util::*};
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BufMut, Bytes};
use std::any::Any;
use std::fmt;

const SDES_SOURCE_LEN: usize = 4;
const SDES_TYPE_LEN: usize = 1;
const SDES_TYPE_OFFSET: usize = 0;
const SDES_OCTET_COUNT_LEN: usize = 1;
const SDES_OCTET_COUNT_OFFSET: usize = 1;
const SDES_MAX_OCTET_COUNT: usize = (1 << 8) - 1;
const SDES_TEXT_OFFSET: usize = 2;

/// SDESType is the item type used in the RTCP SDES control packet.
/// RTP SDES item types registered with IANA. See: <https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-5>
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SdesType {
    #[default]
    /// End of the SDES item list ([RFC 3550] §6.5).
    SdesEnd, // end of SDES list                RFC 3550, 6.5
    /// CNAME: the canonical end-point identifier, which ties an SSRC to a participant.
    ///
    /// The one item WebRTC always sends — it is how a receiver associates streams that belong
    /// together.
    SdesCname, // canonical name                  RFC 3550, 6.5.1
    /// NAME: the participant's display name.
    SdesName, // user name                       RFC 3550, 6.5.2
    /// EMAIL: the participant's email address.
    SdesEmail, // user's electronic mail address  RFC 3550, 6.5.3
    /// PHONE: the participant's phone number.
    SdesPhone, // user's phone number             RFC 3550, 6.5.4
    /// LOC: the participant's geographic location.
    SdesLocation, // geographic user location        RFC 3550, 6.5.5
    /// TOOL: the name and version of the sending application.
    SdesTool, // name of application or tool     RFC 3550, 6.5.6
    /// NOTE: a transient note about the source, such as "on hold".
    SdesNote, // notice about the source         RFC 3550, 6.5.7
    /// PRIV: a private extension.
    SdesPrivate, // private extensions              RFC 3550, 6.5.8  (not implemented)
    /// An item type this crate does not name; the wire value is kept so the item round-trips.
    Unknown(u8),
}

impl SdesType {
    /// The item type's wire value.
    pub fn as_u8(self) -> u8 {
        match self {
            SdesType::SdesEnd => 0,
            SdesType::SdesCname => 1,
            SdesType::SdesName => 2,
            SdesType::SdesEmail => 3,
            SdesType::SdesPhone => 4,
            SdesType::SdesLocation => 5,
            SdesType::SdesTool => 6,
            SdesType::SdesNote => 7,
            SdesType::SdesPrivate => 8,
            SdesType::Unknown(b) => b,
        }
    }
}

impl fmt::Display for SdesType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SdesType::SdesEnd => "END",
            SdesType::SdesCname => "CNAME",
            SdesType::SdesName => "NAME",
            SdesType::SdesEmail => "EMAIL",
            SdesType::SdesPhone => "PHONE",
            SdesType::SdesLocation => "LOC",
            SdesType::SdesTool => "TOOL",
            SdesType::SdesNote => "NOTE",
            SdesType::SdesPrivate => "PRIV",
            SdesType::Unknown(b) => return write!(f, "{b}"),
        };
        write!(f, "{s}")
    }
}

impl From<u8> for SdesType {
    fn from(b: u8) -> Self {
        match b {
            1 => SdesType::SdesCname,
            2 => SdesType::SdesName,
            3 => SdesType::SdesEmail,
            4 => SdesType::SdesPhone,
            5 => SdesType::SdesLocation,
            6 => SdesType::SdesTool,
            7 => SdesType::SdesNote,
            8 => SdesType::SdesPrivate,
            0 => SdesType::SdesEnd,
            b => SdesType::Unknown(b),
        }
    }
}

/// A SourceDescriptionChunk contains items describing a single RTP source
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct SourceDescriptionChunk {
    /// The source (ssrc) or contributing source (csrc) identifier this packet describes
    pub source: u32,
    /// The items describing this source.
    pub items: Vec<SourceDescriptionItem>,
}

impl SourceDescriptionChunk {
    fn raw_size(&self) -> usize {
        let mut len = SDES_SOURCE_LEN;
        for it in &self.items {
            len += it.marshal_size();
        }
        len += SDES_TYPE_LEN; // for terminating null octet
        len
    }
}

impl MarshalSize for SourceDescriptionChunk {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for SourceDescriptionChunk {
    /// Marshal encodes the SourceDescriptionChunk in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }
        /*
         *  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         *  |                          SSRC/CSRC_1                          |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                           SDES items                          |
         *  |                              ...                              |
         *  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         */

        buf.put_u32(self.source);

        for it in &self.items {
            let n = it.marshal_to(buf)?;
            buf = &mut buf[n..];
        }

        // The list of items in each chunk MUST be terminated by one or more null octets
        buf.put_u8(SdesType::SdesEnd.as_u8());

        // additional null octets MUST be included if needed to pad until the next 32-bit boundary
        for _ in 0..get_padding_size(self.raw_size()) {
            buf.put_u8(0);
        }
        Ok(self.marshal_size())
    }
}

impl Unmarshal for SourceDescriptionChunk {
    /// Unmarshal decodes the SourceDescriptionChunk from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        /*
         *  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         *  |                          SSRC/CSRC_1                          |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                           SDES items                          |
         *  |                              ...                              |
         *  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         */
        let raw = raw_packet.copy_to_bytes(raw_packet.remaining());
        Self::unmarshal_slice(&raw)
    }
}

impl SourceDescriptionChunk {
    /// Parses one chunk from the front of `raw`, which runs to the end of the packet.
    fn unmarshal_slice(raw: &[u8]) -> Result<Self> {
        if raw.len() < (SDES_SOURCE_LEN + SDES_TYPE_LEN) {
            return Err(Error::PacketTooShort);
        }

        let source = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);

        let mut items = vec![];
        let mut i = SDES_SOURCE_LEN;
        while i < raw.len() {
            if raw[i] == SdesType::SdesEnd.as_u8() {
                return Ok(SourceDescriptionChunk { source, items });
            }
            let item = SourceDescriptionItem::unmarshal_slice(&raw[i..])?;
            i += item.marshal_size();
            items.push(item);
        }

        Err(Error::PacketTooShort)
    }
}

/// A SourceDescriptionItem is a part of a SourceDescription that describes a stream.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct SourceDescriptionItem {
    /// The type identifier for this item. eg, SDESCNAME for canonical name description.
    ///
    /// Type zero or SDESEnd is interpreted as the end of an item list and cannot be used.
    pub sdes_type: SdesType,
    /// Text is a unicode text blob associated with the item. Its meaning varies based on the item's Type.
    pub text: Bytes,
}

impl MarshalSize for SourceDescriptionItem {
    fn marshal_size(&self) -> usize {
        /*
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |    CNAME=1    |     length    | user and domain name        ...
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        SDES_TYPE_LEN + SDES_OCTET_COUNT_LEN + self.text.len()
    }
}

impl Marshal for SourceDescriptionItem {
    /// Marshal encodes the SourceDescriptionItem in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        /*
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |    CNAME=1    |     length    | user and domain name        ...
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */

        if self.sdes_type == SdesType::SdesEnd {
            return Err(Error::SdesMissingType);
        }

        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        buf.put_u8(self.sdes_type.as_u8());

        if self.text.len() > SDES_MAX_OCTET_COUNT {
            return Err(Error::SdesTextTooLong);
        }
        buf.put_u8(self.text.len() as u8);
        buf.put(self.text.clone());

        //no padding for each SourceDescriptionItem
        Ok(self.marshal_size())
    }
}

impl Unmarshal for SourceDescriptionItem {
    /// Unmarshal decodes the SourceDescriptionItem from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        /*
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |    CNAME=1    |     length    | user and domain name        ...
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        let raw = raw_packet.copy_to_bytes(raw_packet.remaining());
        Self::unmarshal_slice(&raw)
    }
}

impl SourceDescriptionItem {
    fn unmarshal_slice(raw: &[u8]) -> Result<Self> {
        if raw.len() < (SDES_TYPE_LEN + SDES_OCTET_COUNT_LEN) {
            return Err(Error::PacketTooShort);
        }

        let sdes_type = SdesType::from(raw[SDES_TYPE_OFFSET]);
        let octet_count = raw[SDES_OCTET_COUNT_OFFSET] as usize;
        if SDES_TEXT_OFFSET + octet_count > raw.len() {
            return Err(Error::PacketTooShort);
        }

        let text = Bytes::copy_from_slice(&raw[SDES_TEXT_OFFSET..SDES_TEXT_OFFSET + octet_count]);
        Ok(SourceDescriptionItem { sdes_type, text })
    }
}

/// A SourceDescription (SDES) packet describes the sources in an RTP stream.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct SourceDescription {
    /// One chunk per source described by this packet.
    pub chunks: Vec<SourceDescriptionChunk>,
}

impl fmt::Display for SourceDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = "Source Description:\n".to_string();
        for c in &self.chunks {
            out += format!("\t{:x}\n", c.source).as_str();
            for it in &c.items {
                out += format!("\t\t{it:?}\n").as_str();
            }
        }
        write!(f, "{out}")
    }
}

impl Packet for SourceDescription {
    /// Header returns the Header associated with this packet.
    fn header(&self) -> Header {
        Header {
            padding: false,
            count: self.chunks.len() as u8,
            packet_type: PacketType::SourceDescription,
            length: ((self.marshal_size() / 4) - 1) as u16,
        }
    }

    /// destination_ssrc returns an array of SSRC values that this packet refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        self.chunks.iter().map(|x| x.source).collect()
    }

    fn raw_size(&self) -> usize {
        let mut chunks_length = 0;
        for c in &self.chunks {
            chunks_length += c.marshal_size();
        }

        HEADER_LENGTH + chunks_length
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<SourceDescription>() == Some(self)
    }

    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for SourceDescription {
    fn marshal_size(&self) -> usize {
        let l = self.raw_size();
        // align to 32-bit boundary
        l + get_padding_size(l)
    }
}

impl Marshal for SourceDescription {
    /// Marshal encodes the SourceDescription in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if self.chunks.len() > COUNT_MAX {
            return Err(Error::TooManyChunks);
        }
        crate::header::length_field(self.marshal_size())?;

        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        /*
         *         0                   1                   2                   3
         *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * header |V=2|P|    SC   |  PT=SDES=202  |             length            |
         *        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * chunk  |                          SSRC/CSRC_1                          |
         *   1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *        |                           SDES items                          |
         *        |                              ...                              |
         *        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * chunk  |                          SSRC/CSRC_2                          |
         *   2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *        |                           SDES items                          |
         *        |                              ...                              |
         *        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         */

        let h = self.header();
        let n = h.marshal_to(buf)?;
        buf = &mut buf[n..];

        for c in &self.chunks {
            let n = c.marshal_to(buf)?;
            buf = &mut buf[n..];
        }

        Ok(self.marshal_size())
    }
}

impl SourceDescription {
    /// Parses the chunks that follow the header. `expected` (the header's count, which the caller
    /// checks) only sizes the vector, so a well-formed packet allocates it once, exactly.
    fn unmarshal_chunks(raw: &[u8], expected: u8) -> Result<Vec<SourceDescriptionChunk>> {
        // The count comes off the wire, so it is trusted only as far as the packet could hold that
        // many chunks (each is at least a source id).
        let mut chunks = Vec::with_capacity((expected as usize).min(raw.len() / SDES_SOURCE_LEN));
        let mut i = 0;
        while i < raw.len() {
            let chunk = SourceDescriptionChunk::unmarshal_slice(&raw[i..])?;
            i += chunk.marshal_size();
            chunks.push(chunk);
        }
        Ok(chunks)
    }
}

impl Unmarshal for SourceDescription {
    /// Unmarshal decodes the SourceDescription from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        /*
         *         0                   1                   2                   3
         *         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * header |V=2|P|    SC   |  PT=SDES=202  |             length            |
         *        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * chunk  |                          SSRC/CSRC_1                          |
         *   1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *        |                           SDES items                          |
         *        |                              ...                              |
         *        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         * chunk  |                          SSRC/CSRC_2                          |
         *   2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *        |                           SDES items                          |
         *        |                              ...                              |
         *        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
         */
        let h = Header::unmarshal(raw_packet)?;
        if h.packet_type != PacketType::SourceDescription {
            return Err(Error::WrongType);
        }

        // Parse straight from the buffer when it is contiguous (it is, for `&[u8]`, `Bytes` and
        // `BytesMut`); only a fragmented buffer needs flattening into one first.
        let remaining = raw_packet.remaining();
        let chunks = if raw_packet.chunk().len() >= remaining {
            let chunks = Self::unmarshal_chunks(&raw_packet.chunk()[..remaining], h.count)?;
            raw_packet.advance(remaining);
            chunks
        } else {
            let raw = raw_packet.copy_to_bytes(remaining);
            Self::unmarshal_chunks(&raw, h.count)?
        };

        if chunks.len() != h.count as usize {
            return Err(Error::InvalidHeader);
        }

        Ok(SourceDescription { chunks })
    }
}
