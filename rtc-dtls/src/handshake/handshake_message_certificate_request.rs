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
/// The server's request that the client authenticate, listing acceptable certificate types,
/// signature algorithms and certificate authorities.
#[non_exhaustive]
pub struct HandshakeMessageCertificateRequest {
    pub(crate) certificate_types: Vec<ClientCertificateType>,
    pub(crate) signature_hash_algorithms: Vec<SignatureHashAlgorithm>,
    /// DER-encoded distinguished names of certificate authorities the server accepts, empty
    /// when it has no preference.
    pub(crate) certificate_authorities_names: Vec<Vec<u8>>,
}

const HANDSHAKE_MESSAGE_CERTIFICATE_REQUEST_MIN_LENGTH: usize = 5;

impl HandshakeMessageCertificateRequest {
    /// The certificate types the server accepts.
    pub fn certificate_types(&self) -> &[ClientCertificateType] {
        &self.certificate_types
    }

    /// The signature and hash pairs the server listed as acceptable.
    pub fn signature_hash_algorithms(&self) -> &[SignatureHashAlgorithm] {
        &self.signature_hash_algorithms
    }

    /// DER-encoded distinguished names of the certificate authorities the server accepts.
    pub fn certificate_authorities_names(&self) -> &[Vec<u8>] {
        &self.certificate_authorities_names
    }

    /// Replaces the acceptable signature schemes, for a `certificate_request_message_hook`.
    pub fn set_signature_hash_algorithms(&mut self, algorithms: Vec<SignatureHashAlgorithm>) {
        self.signature_hash_algorithms = algorithms;
    }

    /// Replaces the acceptable certificate types, for a `certificate_request_message_hook`.
    pub fn set_certificate_types(&mut self, certificate_types: Vec<ClientCertificateType>) {
        self.certificate_types = certificate_types;
    }

    /// Replaces the acceptable certificate authorities, for a
    /// `certificate_request_message_hook`.
    pub fn set_certificate_authorities_names(&mut self, names: Vec<Vec<u8>>) {
        self.certificate_authorities_names = names;
    }

    /// The handshake type that identifies this message on the wire.
    pub fn handshake_type(&self) -> HandshakeType {
        HandshakeType::CertificateRequest
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        1 + self.certificate_types.len()
            + 2
            + self.signature_hash_algorithms.len() * 2
            + 2
            + self
                .certificate_authorities_names
                .iter()
                .map(|ca| 2 + ca.len())
                .sum::<usize>()
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

        // Distinguished Names
        let cas_length: usize = self
            .certificate_authorities_names
            .iter()
            .map(|ca| 2 + ca.len())
            .sum();
        writer.write_u16::<BigEndian>(cas_length as u16)?;
        for ca in &self.certificate_authorities_names {
            writer.write_u16::<BigEndian>(ca.len() as u16)?;
            writer.write_all(ca)?;
        }

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
            // pairs, for instance). The hybrid encoding reads a known RSA-PSS code point as
            // its full u16 value, everything else byte-split.
            if let Ok(algorithm) = SignatureHashAlgorithm::from_scheme(scheme) {
                signature_hash_algorithms.push(algorithm);
            }
        }

        // Distinguished Names
        let cas_length = reader.read_u16::<BigEndian>()? as usize;
        let mut certificate_authorities_names = vec![];
        let mut read = 0;
        while read < cas_length {
            let ca_length = reader.read_u16::<BigEndian>()? as usize;
            read += 2 + ca_length;
            if read > cas_length {
                return Err(Error::ErrBufferTooSmall);
            }
            let mut ca = vec![0u8; ca_length];
            reader
                .read_exact(&mut ca)
                .map_err(|_| Error::ErrBufferTooSmall)?;
            certificate_authorities_names.push(ca);
        }

        Ok(HandshakeMessageCertificateRequest {
            certificate_types,
            signature_hash_algorithms,
            certificate_authorities_names,
        })
    }
}
