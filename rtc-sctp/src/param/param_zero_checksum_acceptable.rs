use super::{param_header::*, param_type::*, *};

use bytes::{Bytes, BytesMut};

/// The Zero Checksum Acceptable parameter of [RFC 9653].
///
/// A sender of an INIT or INIT ACK chunk includes this parameter to inform its peer that
/// it is willing to accept SCTP packets whose checksum field is zero, because an
/// alternate error detection method — for WebRTC, the DTLS record protection the SCTP
/// packets ride inside — already covers them:
///
/// ```text
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0x8001 (suggested)   |          Length = 8           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Error Detection Method Identifier (EDMID)           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The EDMID names the protection that makes the checksum redundant. There is exactly one
/// defined value: 1, "SCTP over DTLS". Any other EDMID means a method this endpoint does
/// not use, so it is treated as if the parameter had not been sent.
///
/// [RFC 9653]: https://datatracker.ietf.org/doc/html/rfc9653
#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct ParamZeroChecksumAcceptable {
    /// The Error Detection Method Identifier the sender will accept in place of the CRC.
    pub(crate) edmid: u32,
}

/// The one defined EDMID: the packets are protected by DTLS.
pub(crate) const DTLS_ERROR_DETECTION_METHOD: u32 = 1;

impl fmt::Display for ParamZeroChecksumAcceptable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.header())
    }
}

impl Param for ParamZeroChecksumAcceptable {
    fn header(&self) -> ParamHeader {
        ParamHeader {
            typ: ParamType::ZeroChecksumAcceptable,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(raw: &Bytes) -> Result<Self> {
        let header = ParamHeader::unmarshal(raw)?;
        // RFC 9653 section 4: "The Length field MUST be set to 8." That is the 4-byte
        // parameter header plus the one 4-byte EDMID — anything else is malformed, and
        // accepting a different length would change which bytes the EDMID is read from.
        if header.value_length != 4 {
            return Err(Error::Other(
                "zero checksum parameter length must be 8".to_owned(),
            ));
        }
        let reader = &mut raw.slice(PARAM_HEADER_LENGTH..);
        let edmid = reader.get_u32();
        Ok(ParamZeroChecksumAcceptable { edmid })
    }

    fn marshal_to(&self, buf: &mut BytesMut) -> Result<usize> {
        self.header().marshal_to(buf)?;
        buf.extend_from_slice(&self.edmid.to_be_bytes());
        Ok(buf.len())
    }

    fn value_length(&self) -> usize {
        4
    }

    fn clone_to(&self) -> Box<dyn Param> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
