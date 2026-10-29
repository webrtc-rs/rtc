use super::*;

/// UnknownReportBlock is used to store bytes for any report block
/// that has an unknown Report Block Type.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct UnknownReportBlock {
    /// The block type exactly as it appeared on the wire.
    pub block_type: u8,
    /// The type-specific bits of the block header, exactly as on the wire.
    pub type_specific: u8,
    /// The block's bytes after its header, left unparsed.
    pub bytes: Bytes,
}

impl fmt::Display for UnknownReportBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl UnknownReportBlock {
    /// The XR block header describing this block's type and length.
    pub fn xr_header(&self) -> XRHeader {
        XRHeader {
            block_type: BlockType::Unknown,
            type_specific: self.type_specific,
            block_length: (self.raw_size() / 4 - 1) as u16,
        }
    }
}

impl Packet for UnknownReportBlock {
    fn header(&self) -> Header {
        Header::default()
    }

    /// destination_ssrc returns an array of ssrc values that this report block refers to.
    fn destination_ssrc(&self) -> Vec<u32> {
        vec![]
    }

    fn raw_size(&self) -> usize {
        XR_HEADER_LENGTH + self.bytes.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn equal(&self, other: &dyn Packet) -> bool {
        other.as_any().downcast_ref::<UnknownReportBlock>() == Some(self)
    }
    fn cloned(&self) -> Box<dyn Packet> {
        Box::new(self.clone())
    }
}

impl MarshalSize for UnknownReportBlock {
    fn marshal_size(&self) -> usize {
        self.raw_size()
    }
}

impl Marshal for UnknownReportBlock {
    /// marshal_to encodes the UnknownReportBlock in binary
    fn marshal_to(&self, mut buf: &mut [u8]) -> Result<usize> {
        if buf.remaining_mut() < self.marshal_size() {
            return Err(Error::BufferTooShort);
        }

        // The wire block type cannot be expressed as `BlockType`, so write the header directly.
        buf.put_u8(self.block_type);
        buf.put_u8(self.type_specific);
        buf.put_u16(self.xr_header().block_length);

        buf.put(self.bytes.clone());

        Ok(self.marshal_size())
    }
}

impl Unmarshal for UnknownReportBlock {
    /// Unmarshal decodes the UnknownReportBlock from binary
    fn unmarshal<B>(raw_packet: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if raw_packet.remaining() < XR_HEADER_LENGTH {
            return Err(Error::PacketTooShort);
        }

        let block_type = raw_packet.get_u8();
        let type_specific = raw_packet.get_u8();
        let block_length = raw_packet.get_u16();
        let block_length = match block_length.checked_mul(4) {
            Some(length) => length,
            None => return Err(Error::InvalidBlockSize),
        };
        if raw_packet.remaining() < block_length as usize {
            return Err(Error::PacketTooShort);
        }

        let bytes = raw_packet.copy_to_bytes(block_length as usize);

        Ok(UnknownReportBlock {
            block_type,
            type_specific,
            bytes,
        })
    }
}
