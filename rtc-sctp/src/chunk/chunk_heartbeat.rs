use super::{chunk_header::*, chunk_type::*, *};
use crate::param::{param_header::*, param_type::*, *};

use bytes::{Bytes, BytesMut};
use std::fmt;

///chunkHeartbeat represents an SCTP Chunk of type HEARTBEAT
///
///An endpoint should send this chunk to its peer endpoint to probe the
///reachability of a particular destination transport address defined in
///the present association.
///
///The parameter field contains the Heartbeat Information, which is a
///variable-length opaque data structure understood only by the sender.
///
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///|   Type = 4    | Chunk  Flags  |      Heartbeat Length         |
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///|                                                               |
///|            Heartbeat Information TLV (Variable-Length)        |
///|                                                               |
///+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///Defined as a variable-length parameter using the format described
///in Section 3.2.1, i.e.:
///
///Variable Parameters                  Status     Type Value
///-------------------------------------------------------------
///heartbeat Info                       Mandatory   1
#[derive(Default, Debug)]
pub(crate) struct ChunkHeartbeat {
    pub(crate) params: Vec<Box<dyn Param>>,
}

/// makes ChunkHeartbeat printable
impl fmt::Display for ChunkHeartbeat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header())
    }
}

impl Chunk for ChunkHeartbeat {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: CT_HEARTBEAT,
            flags: 0,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(raw)?;

        if header.typ != CT_HEARTBEAT {
            return Err(Error::ErrChunkTypeNotHeartbeat);
        }

        let body = &raw.slice(CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + header.value_length as usize);

        // If the body is completely empty, accept it but don't populate params.
        if body.is_empty() {
            return Ok(ChunkHeartbeat { params: vec![] });
        }

        // A parameter header (TLV) is at least 4 bytes.
        if body.len() < PARAM_HEADER_LENGTH {
            return Err(Error::ErrHeartbeatNotLongEnoughInfo);
        }

        // The chunk must carry exactly one Heartbeat Info parameter: check the
        // parameter type before validating its advertised length, as pion does.
        let param_type = ParamType::from(u16::from_be_bytes([body[0], body[1]]));
        if param_type != ParamType::HeartbeatInfo {
            return Err(Error::ErrHeartbeatParam);
        }

        let p_header = ParamHeader::unmarshal(body).map_err(|_| Error::ErrParseParamTypeFailed)?;
        let plen = p_header.value_length as usize + PARAM_HEADER_LENGTH;
        if plen < PARAM_HEADER_LENGTH || plen > body.len() {
            return Err(Error::ErrHeartbeatNotLongEnoughInfo);
        }

        let p = build_param(&body.slice(..plen)).map_err(|_| Error::ErrHeartbeatChunkUnmarshal)?;
        let params = vec![p];

        // Any trailing bytes beyond the single param must be all zeros.
        if body[plen..].iter().any(|&b| b != 0) {
            return Err(Error::ErrHeartbeatExtraNonZero);
        }

        Ok(ChunkHeartbeat { params })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        // Exactly one Heartbeat Info param is required.
        if self.params.len() != 1 {
            return Err(Error::ErrHeartbeatMarshalNoInfo);
        }
        if self.params[0].header().typ != ParamType::HeartbeatInfo {
            return Err(Error::ErrHeartbeatParam);
        }

        self.header().marshal_to(buf)?;
        let pp = self.params[0]
            .marshal()
            .map_err(|_| Error::ErrHeartbeatChunkUnmarshal)?;
        buf.extend_from_slice(&pp);
        Ok(buf.len())
    }

    fn check(&self) -> Result<()> {
        Ok(())
    }

    fn value_length(&self) -> usize {
        self.params.iter().fold(0, |length, p| {
            length + PARAM_HEADER_LENGTH + p.value_length()
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
