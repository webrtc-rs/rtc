/// The `signature_algorithms_cert` extension ([RFC 8446] §4.2.3): the signature algorithms
/// that may be used in signatures over X.509 certificates, which is separate from
/// `signature_algorithms` (handshake signatures).
///
/// [RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
#[cfg(test)]
mod extension_signature_algorithms_cert_test;

use super::*;
use crate::signature_hash_algorithm::{HashAlgorithm, SignatureAlgorithm, SignatureHashAlgorithm};

/// ## Specifications
///
/// * [RFC 8446 §4.2.3]
///
/// [RFC 8446 §4.2.3]: https://www.rfc-editor.org/rfc/rfc8446#section-4.2.3
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionSignatureAlgorithmsCert {
    /// The signature and hash pairs the sender accepts for certificate signatures.
    pub(crate) signature_hash_algorithms: Vec<SignatureHashAlgorithm>,
}

impl ExtensionSignatureAlgorithmsCert {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::SignatureAlgorithmsCert
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2 + self.signature_hash_algorithms.len() * 2
    }

    /// Encodes this message to `writer`.
    ///
    /// Entries use the hybrid encoding pion uses: TLS 1.3 RSA-PSS schemes are written as their
    /// full `u16` code point, everything else as a hash byte followed by a signature byte.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(2 + 2 * self.signature_hash_algorithms.len() as u16)?;
        writer.write_u16::<BigEndian>(2 * self.signature_hash_algorithms.len() as u16)?;
        for v in &self.signature_hash_algorithms {
            write_signature_hash_algorithm(writer, v)?;
        }

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Entries that do not name a known algorithm are skipped rather than rejected, as in pion.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when a declared length runs past the input, and
    /// [`Error::ErrLengthMismatch`] when the algorithm-list length disagrees with the
    /// extension-data length.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let ext_data_len = read_u16(reader)?;
        let mut ext_data = vec![0u8; ext_data_len as usize];
        reader.read_exact(&mut ext_data).map_err(|_| Error::ErrBufferTooSmall)?;

        if ext_data.len() < 2 {
            return Err(Error::ErrLengthMismatch);
        }
        let algorithms_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
        if 2 + algorithms_len != ext_data.len() {
            return Err(Error::ErrLengthMismatch);
        }

        let mut signature_hash_algorithms = vec![];
        let algorithms = &ext_data[2..];
        let mut offset = 0;
        while offset < algorithms.len() {
            if offset + 2 > algorithms.len() {
                return Err(Error::ErrLengthMismatch);
            }
            let value = u16::from_be_bytes([algorithms[offset], algorithms[offset + 1]]);
            if let Some(algorithm) = parse_signature_hash_algorithm(value) {
                signature_hash_algorithms.push(algorithm);
            }
            offset += 2;
        }

        Ok(ExtensionSignatureAlgorithmsCert {
            signature_hash_algorithms,
        })
    }
}

/// Reads one big-endian `u16`, mapping a truncated field to [`Error::ErrBufferTooSmall`].
fn read_u16<R: Read>(reader: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    reader
        .read_exact(&mut buf)
        .map_err(|_| Error::ErrBufferTooSmall)?;
    Ok(u16::from_be_bytes(buf))
}

/// Writes one entry: RSA-PSS schemes as their full `u16` code point, others byte-split.
fn write_signature_hash_algorithm<W: Write>(
    writer: &mut W,
    algorithm: &SignatureHashAlgorithm,
) -> Result<()> {
    if algorithm.signature.is_pss() {
        writer.write_u16::<BigEndian>(algorithm.signature as u16)?;
    } else {
        writer.write_u8(algorithm.hash as u8)?;
        writer.write_u8(algorithm.signature as u8)?;
    }
    Ok(())
}

/// Decodes one entry: a known RSA-PSS code point carries its hash, everything else is
/// byte-split. Unknown hash or signature values yield `None`, which the caller skips.
pub(crate) fn parse_signature_hash_algorithm(value: u16) -> Option<SignatureHashAlgorithm> {
    let pss = match value {
        0x0804 => Some((SignatureAlgorithm::RsaPssRsaeSha256, HashAlgorithm::Sha256)),
        0x0805 => Some((SignatureAlgorithm::RsaPssRsaeSha384, HashAlgorithm::Sha384)),
        0x0806 => Some((SignatureAlgorithm::RsaPssRsaeSha512, HashAlgorithm::Sha512)),
        0x0809 => Some((SignatureAlgorithm::RsaPssPssSha256, HashAlgorithm::Sha256)),
        0x080a => Some((SignatureAlgorithm::RsaPssPssSha384, HashAlgorithm::Sha384)),
        0x080b => Some((SignatureAlgorithm::RsaPssPssSha512, HashAlgorithm::Sha512)),
        _ => None,
    };
    if let Some((signature, hash)) = pss {
        return Some(SignatureHashAlgorithm { hash, signature });
    }

    let signature: SignatureAlgorithm = ((value & 0xFF) as u8).into();
    let hash: HashAlgorithm = ((value >> 8) as u8).into();
    if signature == SignatureAlgorithm::Unsupported || hash == HashAlgorithm::Unsupported {
        return None;
    }
    Some(SignatureHashAlgorithm { hash, signature })
}
