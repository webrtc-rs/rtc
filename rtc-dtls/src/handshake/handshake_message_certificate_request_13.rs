#[cfg(test)]
mod handshake_message_certificate_request_13_test;

use super::*;
use crate::extension::*;

use byteorder::WriteBytesExt;
use std::io::{Read, Write};

/// The `certificate_request_context` is limited by its 1-byte length prefix.
const CERT_REQ_13_CONTEXT_MAX_LENGTH: usize = 255;
/// The context length field plus the extensions length field: the shortest message pion
/// accepts, as `certReq13MinLength`.
const CERT_REQ_13_MIN_LENGTH: usize = 3;

/// The `CertificateRequest` handshake message of DTLS 1.3 / TLS 1.3 ([RFC 8446 §4.3.2]), by
/// which a server asks the client to authenticate.
///
/// A standalone type rather than a [`HandshakeMessage`] variant, mirroring pion: the type code
/// (13) is shared with the DTLS 1.2 message, and which body it carries is decided by the
/// negotiated version, so the 1.2 dispatch is left untouched.
///
/// [RFC 8446 §4.3.2]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HandshakeMessageCertificateRequest13 {
    /// An opaque value the server creates to bind the client's certificate to the handshake
    /// context.
    pub(crate) certificate_request_context: Vec<u8>,
    /// The extensions; `signature_algorithms` is required by RFC 8446.
    pub(crate) extensions: Vec<Extension>,
}

impl HandshakeMessageCertificateRequest13 {
    /// The handshake type that identifies this message on the wire.
    pub fn handshake_type(&self) -> HandshakeType {
        HandshakeType::CertificateRequest
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        1 + self.certificate_request_context.len()
            + 2
            + self.extensions.iter().map(Extension::size).sum::<usize>()
    }

    /// Encodes this message to `writer`.
    ///
    /// Wire format:
    ///
    /// ```text
    /// [1 byte]  certificate_request_context length
    /// [0-255]   certificate_request_context data
    /// [2 bytes] extensions length
    /// [variable] extensions data
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::ErrCertificateRequestContextTooLong`] when the context exceeds 255 bytes,
    /// [`Error::ErrMissingSignatureAlgorithmsExtension`] when `signature_algorithms` is absent
    /// (required by RFC 8446), and [`Error::ErrInvalidExtensionsLength`] when the extensions
    /// block exceeds 65535 bytes, as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Validate certificate_request_context length
        if self.certificate_request_context.len() > CERT_REQ_13_CONTEXT_MAX_LENGTH {
            return Err(Error::ErrCertificateRequestContextTooLong);
        }

        // Validate that signature_algorithms extension is present (required by RFC 8446)
        if !self.has_signature_algorithms() {
            return Err(Error::ErrMissingSignatureAlgorithmsExtension);
        }

        // Add certificate_request_context (1-byte length prefix)
        writer.write_u8(self.certificate_request_context.len() as u8)?;
        writer.write_all(&self.certificate_request_context)?;

        // Marshal extensions (includes 2-byte length prefix, like in TLS 1.2)
        marshal_extensions_block(&self.extensions, writer)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the message is shorter than its two length fields,
    /// [`Error::ErrInvalidCertificateRequestContext`] when the context does not decode,
    /// [`Error::ErrInvalidExtensionsLength`] when fewer than two extension bytes follow the
    /// context, [`Error::ErrLengthMismatch`] when the extensions count disagrees with the
    /// bytes present, [`Error::ErrMissingSignatureAlgorithmsExtension`] when
    /// `signature_algorithms` is absent, or the error of an extension that failed to parse, as
    /// in pion.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let mut data = vec![];
        reader.read_to_end(&mut data)?;

        // pion rejects anything shorter than the context length field plus the extensions
        // length field up front with errBufferTooSmall.
        if data.len() < CERT_REQ_13_MIN_LENGTH {
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

        // Read the extensions: a u16 byte count followed by the extensions, exactly the block
        // `unmarshal_extensions_block` parses. pion reads the count itself and requires the
        // bytes after it to match exactly.
        if buffer.len() < 2 {
            return Err(Error::ErrInvalidExtensionsLength);
        }
        let extensions = unmarshal_extensions_block(buffer)?;

        let message = HandshakeMessageCertificateRequest13 {
            certificate_request_context,
            extensions,
        };

        // Validate that signature_algorithms extension is present (required by RFC 8446)
        if !message.has_signature_algorithms() {
            return Err(Error::ErrMissingSignatureAlgorithmsExtension);
        }

        Ok(message)
    }

    /// Whether the extensions carry `signature_algorithms`.
    fn has_signature_algorithms(&self) -> bool {
        self.extensions.iter().any(|extension| {
            extension.extension_value() == ExtensionValue::SupportedSignatureAlgorithms
        })
    }
}
