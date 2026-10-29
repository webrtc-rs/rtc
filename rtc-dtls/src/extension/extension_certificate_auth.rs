#[cfg(test)]
mod extension_certificate_auth_test;

use super::*;

/// The `certificate_authorities` extension ([RFC 8446 §4.2.4]): the DNs of certificate
/// authorities a server accepts, which a client may use to pick a certificate.
///
/// [RFC 8446 §4.2.4]: https://datatracker.ietf.org/html/rfc8446#section-4.2.4
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionCertificateAuthorities {
    /// The DER-encoded distinguished names, each at least one byte.
    pub(crate) authorities: Vec<Vec<u8>>,
}

impl ExtensionCertificateAuthorities {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::CertificateAuthorities
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2
            + self
                .authorities
                .iter()
                .map(|ca| 2 + ca.len())
                .sum::<usize>()
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrInvalidCertificateAuthoritiesFormat`] when the list is empty, an authority is
    /// empty, or a length prefix would overflow, as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.authorities.is_empty() {
            return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
        }

        let mut authorities = vec![];
        for authority in &self.authorities {
            if authority.is_empty() || authority.len() > 0xffff {
                return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
            }
            authorities.extend_from_slice(&(authority.len() as u16).to_be_bytes());
            authorities.extend_from_slice(authority);
        }
        if authorities.len() > 0xffff {
            return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
        }

        let mut body = Vec::with_capacity(2 + authorities.len());
        body.extend_from_slice(&(authorities.len() as u16).to_be_bytes());
        body.extend_from_slice(&authorities);
        if body.len() > 0xffff {
            return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
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
    /// [`Error::ErrInvalidCertificateAuthoritiesFormat`] when the list is empty or an authority
    /// is malformed, and [`Error::ErrLengthMismatch`] on trailing data, as in pion.
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
        if ext_data.is_empty() || ext_data.len() < 2 {
            return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
        }

        let authorities_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
        if ext_data.len() < 2 + authorities_len {
            return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
        }
        if authorities_len == 0 {
            return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
        }
        if ext_data.len() != 2 + authorities_len {
            return Err(Error::ErrLengthMismatch);
        }
        let mut rest = &ext_data[2..];

        let mut authorities = vec![];
        while !rest.is_empty() {
            if rest.len() < 2 {
                return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
            }
            let authority_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            rest = &rest[2..];
            if authority_len == 0 || rest.len() < authority_len {
                return Err(Error::ErrInvalidCertificateAuthoritiesFormat);
            }
            authorities.push(rest[..authority_len].to_vec());
            rest = &rest[authority_len..];
        }

        Ok(ExtensionCertificateAuthorities { authorities })
    }
}
