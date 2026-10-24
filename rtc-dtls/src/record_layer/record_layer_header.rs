//! The DTLS record header.
//!
//! Thirteen bytes: content type, protocol version, a 16-bit epoch, a 48-bit sequence number, and
//! the body length. The epoch is what DTLS adds over TLS here — it increments on every
//! ChangeCipherSpec, so records protected with the old and new keys can be told apart while a
//! rekey is in flight.
//!
//! The sequence number is 48 bits on the wire but held as a `u64`; [`MAX_SEQUENCE_NUMBER`](crate::record_layer::record_layer_header::MAX_SEQUENCE_NUMBER) is the
//! largest value that fits.
use crate::content::*;

use shared::error::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/// Length of the DTLS record header in bytes.
pub const RECORD_LAYER_HEADER_SIZE: usize = 13;
/// The largest sequence number the 48-bit field can hold.
pub const MAX_SEQUENCE_NUMBER: u64 = 0x0000FFFFFFFFFFFF;

/// Major version byte for DTLS 1.2.
pub const DTLS1_2MAJOR: u8 = 0xfe;
/// Minor version byte for DTLS 1.2.
pub const DTLS1_2MINOR: u8 = 0xfd;

/// Major version byte for DTLS 1.0.
pub const DTLS1_0MAJOR: u8 = 0xfe;
/// Minor version byte for DTLS 1.0.
pub const DTLS1_0MINOR: u8 = 0xff;

// VERSION_DTLS12 is the DTLS version in the same style as
// VersionTLSXX from crypto/tls
/// DTLS 1.2 as a single 16-bit value.
pub const VERSION_DTLS12: u16 = 0xfefd;

/// DTLS 1.0 as a [`ProtocolVersion`].
pub const PROTOCOL_VERSION1_0: ProtocolVersion = ProtocolVersion {
    major: DTLS1_0MAJOR,
    minor: DTLS1_0MINOR,
};
/// DTLS 1.2 as a [`ProtocolVersion`].
pub const PROTOCOL_VERSION1_2: ProtocolVersion = ProtocolVersion {
    major: DTLS1_2MAJOR,
    minor: DTLS1_2MINOR,
};

impl ProtocolVersion {
    /// Determines if two protocol versions are equal, as pion's `Version.Equal`.
    #[must_use]
    pub fn equal(&self, other: ProtocolVersion) -> bool {
        self.major == other.major && self.minor == other.minor
    }
}

/// Returns `true` if the version is supported by this crate. Only DTLS 1.2 is currently
/// supported; DTLS 1.3 is a work in progress.
#[must_use]
pub fn is_supported_bytes(major: u8, minor: u8) -> bool {
    major == DTLS1_2MAJOR && minor == DTLS1_2MINOR
}

/// Returns `true` if `version` is supported by this crate; see [`is_supported_bytes`].
#[must_use]
pub fn is_supported_version(version: ProtocolVersion) -> bool {
    version.equal(PROTOCOL_VERSION1_2)
}

/// Returns `true` if the bytes represent a valid DTLS version as defined in [RFC 9147] §5.3
/// (`legacy_version`), whether or not it is *supported* — see [`is_supported_bytes`] for that.
///
/// [RFC 9147]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.3
#[must_use]
pub fn is_valid_bytes(major: u8, minor: u8) -> bool {
    major == 0xfe && (minor == 0xff || minor == 0xfd || minor == 0xfc)
}

/// Returns `true` if `version` represents a valid DTLS version; see [`is_valid_bytes`].
#[must_use]
pub fn is_valid_version(version: ProtocolVersion) -> bool {
    version.equal(PROTOCOL_VERSION1_0)
        || version.equal(PROTOCOL_VERSION1_2)
        || version.equal(ProtocolVersion {
            major: 0xfe,
            minor: 0xfc, // DTLS 1.3
        })
}

/// ## Specifications
///
/// * [RFC 4346 §6.2.1]
///
/// [RFC 4346 §6.2.1]: https://tools.ietf.org/html/rfc4346#section-6.2.1
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct ProtocolVersion {
    /// The major version byte.
    pub major: u8,
    /// The minor version byte.
    pub minor: u8,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
/// The header on every DTLS record.
pub struct RecordLayerHeader {
    /// What the record body holds.
    pub content_type: ContentType,
    /// The record's protocol version.
    pub protocol_version: ProtocolVersion,
    /// The key epoch, incremented on each ChangeCipherSpec so old and new keys can coexist.
    pub epoch: u16,
    /// The record sequence number — a 48-bit field on the wire.
    pub sequence_number: u64, // uint48 in spec
    /// The body length in bytes.
    pub content_len: u16,
}

impl RecordLayerHeader {
    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.sequence_number > MAX_SEQUENCE_NUMBER {
            return Err(Error::ErrSequenceNumberOverflow);
        }

        writer.write_u8(self.content_type as u8)?;
        writer.write_u8(self.protocol_version.major)?;
        writer.write_u8(self.protocol_version.minor)?;
        writer.write_u16::<BigEndian>(self.epoch)?;

        let be: [u8; 8] = self.sequence_number.to_be_bytes();
        writer.write_all(&be[2..])?; // uint48 in spec

        writer.write_u16::<BigEndian>(self.content_len)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let content_type = reader.read_u8()?.into();
        let major = reader.read_u8()?;
        let minor = reader.read_u8()?;
        let epoch = reader.read_u16::<BigEndian>()?;

        // SequenceNumber is stored as uint48, make into uint64
        let mut be: [u8; 8] = [0u8; 8];
        reader.read_exact(&mut be[2..])?;
        let sequence_number = u64::from_be_bytes(be);

        let protocol_version = ProtocolVersion { major, minor };
        if protocol_version != PROTOCOL_VERSION1_0 && protocol_version != PROTOCOL_VERSION1_2 {
            return Err(Error::ErrUnsupportedProtocolVersion);
        }
        let content_len = reader.read_u16::<BigEndian>()?;

        Ok(RecordLayerHeader {
            content_type,
            protocol_version,
            epoch,
            sequence_number,
            content_len,
        })
    }
}
