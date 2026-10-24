#[cfg(test)]
mod extension_supported_versions_test;

use super::*;
use crate::record_layer::record_layer_header::*;

/// The `supported_versions` extension ([RFC 8446 §4.2.1]): the client lists the versions it
/// supports, in preference order; the server answers with the one it selected.
///
/// A single version is encoded without the list-length byte, which is the ServerHello /
/// HelloRetryRequest form; two or more use the ClientHello list form. Versions that are valid
/// DTLS `legacy_version` values but unsupported here (DTLS 1.0, DTLS 1.3) are still marshaled and
/// unmarshaled, as in pion.
///
/// [RFC 8446 §4.2.1]: https://datatracker.ietf.org/html/rfc8446#section-4.2.1
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionSupportedVersions {
    /// The offered versions, most preferred first; a single entry for the ServerHello /
    /// HelloRetryRequest selected-version form.
    pub(crate) versions: Vec<ProtocolVersion>,
}

impl ExtensionSupportedVersions {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::SupportedVersions
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2 * self.versions.len() + usize::from(self.versions.len() > 1)
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrInvalidSupportedVersionsFormat`] when no version is set or the list falls
    /// outside the `opaque versions<2..254>` bound, and [`Error::ErrInvalidDtlsVersion`] when a
    /// version is not a valid DTLS `legacy_version`, as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.versions.is_empty() {
            return Err(Error::ErrInvalidSupportedVersionsFormat);
        }

        let total_bytes = self.versions.len() * 2;

        // The 2..254 bound is defined in RFC 8446 section 4.2.1.
        if !(2..=254).contains(&total_bytes) {
            return Err(Error::ErrInvalidSupportedVersionsFormat);
        }

        // Only checking for *valid* versions, not to be confused with supported versions.
        // Error on invalid versions to protect against malformed messages/DOS attacks.
        if self.versions.iter().any(|v| !v.is_valid()) {
            return Err(Error::ErrInvalidDtlsVersion);
        }

        let mut body = Vec::with_capacity(total_bytes + 1);
        if self.versions.len() == 1 {
            // In the case that there's only one version, do not add the list length (uint8).
            body.push(self.versions[0].major);
            body.push(self.versions[0].minor);
        } else {
            body.push(total_bytes as u8);
            for version in &self.versions {
                body.push(version.major);
                body.push(version.minor);
            }
        }

        writer.write_u16::<BigEndian>(body.len() as u16)?;
        writer.write_all(&body)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Reads the extension length prefix and body; the [`Extension`] enum reads and dispatches
    /// the type code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the input is truncated,
    /// [`Error::ErrInvalidSupportedVersionsFormat`] for any other malformed body and
    /// [`Error::ErrLengthMismatch`] on trailing data inside the ClientHello list, as in pion.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let extension_len = reader
            .read_u16::<BigEndian>()
            .map_err(|_| Error::ErrBufferTooSmall)? as usize;
        let mut ext_data = vec![0u8; extension_len];
        reader
            .read_exact(&mut ext_data)
            .map_err(|_| Error::ErrBufferTooSmall)?;
        Self::unmarshal_body(&ext_data)
    }

    /// Parses the extension body, mirroring pion's cryptobyte logic and error choices.
    fn unmarshal_body(ext_data: &[u8]) -> Result<Self> {
        if ext_data.is_empty() {
            return Err(Error::ErrInvalidSupportedVersionsFormat);
        }

        // Try ClientHello list: versions<2..254> (1-byte length, then pairs).
        let list_len = ext_data[0] as usize;
        if list_len == ext_data.len() - 1 && list_len >= 2 && list_len.is_multiple_of(2) {
            let mut versions = vec![];
            let mut rest = &ext_data[1..];
            while !rest.is_empty() {
                if rest.len() < 2 {
                    return Err(Error::ErrInvalidSupportedVersionsFormat);
                }
                let version = ProtocolVersion {
                    major: rest[0],
                    minor: rest[1],
                };
                // Only checking for *valid* versions, not to be confused with supported
                // versions; invalid ones are discarded rather than rejected, as in pion.
                if version.is_valid() {
                    versions.push(version);
                }
                rest = &rest[2..];
            }

            // The list length matched the remaining bytes, so there cannot be trailing data; the
            // check mirrors pion's errLengthMismatch guard.
            if !rest.is_empty() {
                return Err(Error::ErrLengthMismatch);
            }

            return Ok(ExtensionSupportedVersions { versions });
        }

        // Otherwise, expect ServerHello/HelloRetryRequest selected_version, which should be
        // exactly 2 bytes.
        if ext_data.len() != 2 {
            return Err(Error::ErrInvalidSupportedVersionsFormat);
        }

        let version = ProtocolVersion {
            major: ext_data[0],
            minor: ext_data[1],
        };

        // Only checking for *valid* versions, not to be confused with supported versions.
        let versions = if version.is_valid() {
            vec![version]
        } else {
            vec![]
        };

        Ok(ExtensionSupportedVersions { versions })
    }
}
