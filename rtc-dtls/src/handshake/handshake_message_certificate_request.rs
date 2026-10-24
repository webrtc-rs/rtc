#[cfg(test)]
mod handshake_message_certificate_request_test;

use super::*;
use crate::client_certificate_type::*;
use crate::signature_hash_algorithm::*;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

/*
A non-anonymous server can optionally request a certificate from
the client, if appropriate for the selected cipher suite.  This
message, if sent, will immediately follow the ServerKeyExchange
message (if it is sent; otherwise, this message follows the
server's Certificate message).
*/
#[derive(Clone, Debug, PartialEq, Eq)]
/// The server's request that the client authenticate, listing acceptable certificate types
/// and signature algorithms.
pub struct HandshakeMessageCertificateRequest {
    pub(crate) certificate_types: Vec<ClientCertificateType>,
    pub(crate) signature_hash_algorithms: Vec<SignatureHashAlgorithm>,
}

const HANDSHAKE_MESSAGE_CERTIFICATE_REQUEST_MIN_LENGTH: usize = 5;

impl HandshakeMessageCertificateRequest {
    /// The handshake type that identifies this message on the wire.
    pub fn handshake_type(&self) -> HandshakeType {
        HandshakeType::CertificateRequest
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        1 + self.certificate_types.len() + 2 + self.signature_hash_algorithms.len() * 2 + 2
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.certificate_types.len() > 255 {
            return Err(Error::ErrCertificateTypesTooLong);
        }

        writer.write_u8(self.certificate_types.len() as u8)?;
        for v in &self.certificate_types {
            writer.write_u8(*v as u8)?;
        }

        writer.write_u16::<BigEndian>(2 * self.signature_hash_algorithms.len() as u16)?;
        for v in &self.signature_hash_algorithms {
            writer.write_all(&v.scheme_bytes()?)?;
        }

        writer.write_all(&[0x00, 0x00])?; // Distinguished Names Length

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Unrecognized certificate types and signature schemes are silently skipped rather than
    /// failing the handshake, as in pion.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let certificate_types_length = reader.read_u8()?;

        let mut certificate_types = vec![];
        for _ in 0..certificate_types_length {
            let cert_type = reader.read_u8()?.into();
            // Skip unrecognized certificate types rather than failing the handshake.
            if cert_type != ClientCertificateType::Unsupported {
                certificate_types.push(cert_type);
            }
        }

        let signature_hash_algorithms_length = reader.read_u16::<BigEndian>()?;

        let mut signature_hash_algorithms = vec![];
        for _ in (0..signature_hash_algorithms_length).step_by(2) {
            let scheme = reader.read_u16::<BigEndian>()?;
            // Skip unrecognized schemes rather than failing the handshake (Firefox offers DSA
            // pairs, for instance).
            if let Ok(algorithm) = SignatureHashAlgorithm::from_scheme(scheme) {
                signature_hash_algorithms.push(algorithm);
            }
        }

        Ok(HandshakeMessageCertificateRequest {
            certificate_types,
            signature_hash_algorithms,
        })
    }
}
