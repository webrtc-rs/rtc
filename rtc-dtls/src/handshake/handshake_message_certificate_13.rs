#[cfg(test)]
mod handshake_message_certificate_13_test;

use super::*;
use crate::extension::*;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::io::{Read, Write};

/// The maximum value a `u24` length field can hold.
const MAX_UINT24: usize = 0xff_ffff;
/// The `certificate_request_context` is limited by its 1-byte length prefix.
const CERT_13_CONTEXT_MAX_LENGTH: usize = 255;
/// The context length field plus the `certificate_list` length field: the shortest message
/// pion accepts, as `cert13ContextLengthFieldSize + cert13CertLengthFieldSize`.
const CERT_13_MIN_LENGTH: usize = 1 + 3;

/// One certificate entry of a DTLS 1.3 `Certificate` message: the DER certificate plus the
/// per-certificate extensions ([RFC 8446 §4.4.2]).
///
/// [RFC 8446 §4.4.2]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CertificateEntry13 {
    /// The DER-encoded X.509 certificate. May be empty for certain contexts (e.g. RawPublicKey
    /// mode), though such an entry cannot be marshaled.
    pub(crate) certificate_data: Vec<u8>,
    /// Per-certificate extensions, such as OCSP status or a signed certificate timestamp.
    pub(crate) extensions: Vec<Extension>,
}

/// The `Certificate` handshake message of DTLS 1.3 / TLS 1.3 ([RFC 8446 §4.4.2]), which carries
/// the certificate chain and per-certificate extensions.
///
/// A standalone type rather than a [`HandshakeMessage`] variant, mirroring pion: the type code
/// (11) is shared with the DTLS 1.2 message, and which body it carries is decided by the
/// negotiated version, so the 1.2 dispatch is left untouched.
///
/// [RFC 8446 §4.4.2]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HandshakeMessageCertificate13 {
    /// An opaque value binding this certificate to a CertificateRequest, empty for server
    /// certificates.
    pub(crate) certificate_request_context: Vec<u8>,
    /// The certificate chain, each entry with its optional extensions.
    pub(crate) certificate_list: Vec<CertificateEntry13>,
}

impl HandshakeMessageCertificate13 {
    /// The handshake type that identifies this message on the wire.
    pub fn handshake_type(&self) -> HandshakeType {
        HandshakeType::Certificate
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        let list_len = self.certificate_list.iter().map(entry_size).sum::<usize>();
        1 + self.certificate_request_context.len() + 3 + list_len
    }

    /// Encodes this message to `writer`.
    ///
    /// Wire format:
    ///
    /// ```text
    /// [1 byte]  certificate_request_context length
    /// [0-255]   certificate_request_context data
    /// [3 bytes] certificate_list length
    /// For each certificate:
    ///   [3 bytes]  cert_data length
    ///   [variable] cert_data (DER certificate)
    ///   [2 bytes]  extensions length
    ///   [variable] extensions data
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::ErrCertificateRequestContextTooLong`] when the context exceeds 255 bytes,
    /// [`Error::ErrInvalidCertificateEntry`] when a certificate is empty or longer than
    /// 2^24-1 bytes, and [`Error::ErrCertificateListTooLong`] when the serialized list exceeds
    /// 2^24-1 bytes, as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Validate certificate_request_context length
        if self.certificate_request_context.len() > CERT_13_CONTEXT_MAX_LENGTH {
            return Err(Error::ErrCertificateRequestContextTooLong);
        }

        // Start with certificate_request_context (1-byte length prefix)
        writer.write_u8(self.certificate_request_context.len() as u8)?;
        writer.write_all(&self.certificate_request_context)?;

        // Build certificate_list
        let mut certificate_list = Vec::new();
        for entry in &self.certificate_list {
            // Add cert_data as a 3-byte length prefix
            let cert_data_len = entry.certificate_data.len();
            if cert_data_len == 0 || cert_data_len > MAX_UINT24 {
                return Err(Error::ErrInvalidCertificateEntry);
            }
            certificate_list.extend_from_slice(&(cert_data_len as u32).to_be_bytes()[1..]);
            certificate_list.extend_from_slice(&entry.certificate_data);

            // Marshal extensions (includes a 2-byte length prefix)
            marshal_extensions_block(&entry.extensions, &mut certificate_list)?;

            // Check size of certificate_list is still within bounds
            if certificate_list.len() > MAX_UINT24 {
                return Err(Error::ErrCertificateListTooLong);
            }
        }

        // Add certificate_list with 3-byte length prefix
        writer.write_u24::<BigEndian>(certificate_list.len() as u32)?;
        writer.write_all(&certificate_list)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the message is shorter than its two length fields,
    /// [`Error::ErrInvalidCertificateRequestContext`] when the context does not decode,
    /// [`Error::ErrInvalidCertificateEntry`] when the list or an entry does not decode,
    /// [`Error::ErrLengthMismatch`] on trailing data, or the error of an extension that failed
    /// to parse, as in pion.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let mut data = vec![];
        reader.read_to_end(&mut data)?;

        // pion rejects anything shorter than the context length field plus the certificate_list
        // length field up front with errBufferTooSmall.
        if data.len() < CERT_13_MIN_LENGTH {
            return Err(Error::ErrBufferTooSmall);
        }
        let mut buffer = data.as_slice();

        // Read certificate_request_context with 1-byte length prefix
        let context_len = buffer[0] as usize;
        if buffer.len() < 1 + context_len {
            return Err(Error::ErrInvalidCertificateRequestContext);
        }
        let certificate_request_context = buffer[1..1 + context_len].to_vec();
        buffer = &buffer[1 + context_len..];

        // Read certificate_list with 3-byte length prefix
        if buffer.len() < 3 {
            return Err(Error::ErrInvalidCertificateEntry);
        }
        let list_len = BigEndian::read_u24(buffer) as usize;
        buffer = &buffer[3..];
        if buffer.len() < list_len {
            return Err(Error::ErrInvalidCertificateEntry);
        }
        let mut list_data = &buffer[..list_len];

        // Ensure no trailing data
        if !buffer[list_len..].is_empty() {
            return Err(Error::ErrLengthMismatch);
        }

        // Parse certificate_list
        let mut certificate_list = vec![];
        while !list_data.is_empty() {
            certificate_list.push(parse_certificate_13_entry(&mut list_data)?);
        }

        Ok(HandshakeMessageCertificate13 {
            certificate_request_context,
            certificate_list,
        })
    }
}

/// Parses a single certificate entry from the front of `data`, advancing it. The pion helper
/// `parseCertificate13Entry`.
///
/// # Errors
///
/// [`Error::ErrInvalidCertificateEntry`] unless the entry is a non-empty, length-delimited
/// certificate followed by an extension block, or the error of an extension that failed to
/// parse.
pub(crate) fn parse_certificate_13_entry(data: &mut &[u8]) -> Result<CertificateEntry13> {
    // Read cert_data with 3-byte length prefix
    if data.len() < 3 {
        return Err(Error::ErrInvalidCertificateEntry);
    }
    let cert_data_len = BigEndian::read_u24(data) as usize;
    let str_data = &data[3..];

    // Validate cert_data length is in valid range <1..2^24-1>
    if cert_data_len == 0 || str_data.len() < cert_data_len {
        return Err(Error::ErrInvalidCertificateEntry);
    }
    let certificate_data = str_data[..cert_data_len].to_vec();
    let rest = &str_data[cert_data_len..];

    // Validate extensions length (2-byte length prefix + up to 2^16-1 bytes of data)
    if rest.len() < 2 {
        return Err(Error::ErrInvalidCertificateEntry);
    }
    let extensions_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
    if rest.len() < 2 + extensions_len {
        return Err(Error::ErrInvalidCertificateEntry);
    }

    // Unmarshal extensions data, including its 2-byte length prefix
    let extensions = unmarshal_extensions_block(&rest[..2 + extensions_len])?;
    *data = &rest[2 + extensions_len..];

    Ok(CertificateEntry13 {
        certificate_data,
        extensions,
    })
}

/// The encoded size of one certificate entry.
fn entry_size(entry: &CertificateEntry13) -> usize {
    3 + entry.certificate_data.len()
        + 2
        + entry.extensions.iter().map(Extension::size).sum::<usize>()
}
