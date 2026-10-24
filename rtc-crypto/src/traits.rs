use std::sync::Arc;

use crate::{
    AeadAlgorithm, BlockCipherAlgorithm, CbcAlgorithm, CryptoAlgorithm, CryptoError, HashAlgorithm,
    HmacAlgorithm, KeyExchangeAlgorithm, PublicKey, SecretVec, SignatureScheme,
    StreamCipherAlgorithm,
};

/// A bundle of cryptographic operations and cryptographically secure randomness.
pub trait RTCCryptoProvider: Send + Sync {
    /// Returns a non-secret diagnostic name.
    fn name(&self) -> &'static str;

    /// Returns the cryptographic operations implementation.
    fn crypto(&self) -> &dyn RTCCrypto;

    /// Returns the cryptographically secure random source.
    fn random(&self) -> &dyn RTCRandom;
}

/// A cryptographically secure random byte generator.
pub trait RTCRandom: Send + Sync {
    /// Fills all of `output` with random bytes.
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError>;
}

/// Provider-neutral cryptographic operations.
pub trait RTCCrypto: Send + Sync {
    /// Reports whether an operation is implemented.
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool;

    /// Hashes `data`.
    fn hash(&self, algorithm: HashAlgorithm, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hash(
            algorithm,
        )))
    }

    /// Encrypts exactly one block in place.
    fn block_encrypt(
        &self,
        algorithm: BlockCipherAlgorithm,
        _key: &[u8],
        _block: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::BlockCipher(algorithm),
        ))
    }

    /// Creates a keyed MAC.
    ///
    /// This is the only HMAC entry point. Deriving the key schedule is the expensive part, so it
    /// happens here rather than per message; a caller that authenticates many messages with one
    /// key holds the returned [`Mac`]. One-shot callers simply drop it after a single `sign` or
    /// `verify`.
    fn new_hmac(&self, algorithm: HmacAlgorithm, _key: &[u8]) -> Result<Box<dyn Mac>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hmac(
            algorithm,
        )))
    }

    /// Extracts a pseudorandom key: HKDF-Extract ([RFC 5869 §2.2]), `PRK = HMAC-Hash(salt, IKM)`.
    ///
    /// Composed from [`RTCCrypto::new_hmac`] by default rather than implemented per provider:
    /// HKDF is a chain of HMACs, both built-in providers already expose hardware-accelerated
    /// HMAC, and — as with the RustCrypto fallbacks for MD5 and AES-CCM — the built-ins are
    /// composite. A provider that implements HMAC therefore implements HKDF for free; one that
    /// does not propagates [`CryptoError::UnsupportedAlgorithm`] from `new_hmac`.
    ///
    /// # Errors
    ///
    /// Returns the [`CryptoError`] of [`RTCCrypto::new_hmac`] when the provider does not
    /// implement `algorithm`.
    ///
    /// [RFC 5869 §2.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
    fn hkdf_extract(
        &self,
        algorithm: HmacAlgorithm,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut mac = self.new_hmac(algorithm, salt)?;
        let mut prk = vec![0; mac.output_len()];
        mac.sign(&[ikm], &mut prk)?;
        Ok(prk)
    }

    /// Expands a pseudorandom key: HKDF-Expand ([RFC 5869 §2.3]),
    /// `T(i) = HMAC-Hash(PRK, T(i-1) || info || i)`.
    ///
    /// Like [`RTCCrypto::hkdf_extract`] this is a default implementation composed of one
    /// [`RTCCrypto::new_hmac`] key schedule, reused for every block of the expansion.
    ///
    /// `length` may be zero, which yields an empty key. The maximum is `255 * HashLen`, the
    /// RFC 5869 limit of a single expansion.
    ///
    /// # Errors
    ///
    /// [`CryptoError::OutputTooLarge`] when `length` exceeds `255 * HashLen`, or the
    /// [`CryptoError`] of [`RTCCrypto::new_hmac`] when the provider does not implement
    /// `algorithm`.
    ///
    /// [RFC 5869 §2.3]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3
    fn hkdf_expand(
        &self,
        algorithm: HmacAlgorithm,
        prk: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let hash_len = algorithm.output_len();
        let maximum = 255 * hash_len;
        if length > maximum {
            return Err(CryptoError::OutputTooLarge {
                maximum,
                actual: length,
            });
        }
        let mut mac = self.new_hmac(algorithm, prk)?;
        let mut okm = Vec::with_capacity(length);
        let mut previous = Vec::with_capacity(hash_len);
        for counter in 1u8..=u8::MAX {
            if okm.len() >= length {
                break;
            }
            let mut block = vec![0; hash_len];
            mac.sign(&[&previous, info, &[counter]], &mut block)?;
            okm.extend_from_slice(&block);
            previous = block;
        }
        okm.truncate(length);
        Ok(okm)
    }

    /// Creates a keyed stream cipher.
    fn new_stream_cipher(
        &self,
        algorithm: StreamCipherAlgorithm,
        _key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::StreamCipher(algorithm),
        ))
    }

    /// Creates a keyed AEAD cipher.
    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        _key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Aead(
            algorithm,
        )))
    }

    /// Creates a keyed CBC cipher.
    fn new_cbc(
        &self,
        algorithm: CbcAlgorithm,
        _key: &[u8],
    ) -> Result<Box<dyn CbcCipher>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Cbc(
            algorithm,
        )))
    }

    /// Starts a one-shot ephemeral key exchange.
    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::KeyExchange(algorithm),
        ))
    }

    /// Generates an exportable signing key.
    fn generate_signing_key(
        &self,
        scheme: SignatureScheme,
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::SigningKeyGeneration(scheme),
        ))
    }

    /// Imports an exportable PKCS#8 signing key.
    fn import_signing_key(
        &self,
        scheme: SignatureScheme,
        _pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::SigningKeyImport(scheme),
        ))
    }

    /// Verifies a signature.
    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        _public_key: PublicKey<'_>,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm(
            CryptoAlgorithm::Signature(scheme),
        ))
    }
}

/// A keyed message authentication code with a reusable key schedule.
///
/// Created once per key by [`RTCCrypto::new_hmac`] and used for every message authenticated with
/// that key, so the ipad/opad derivation is paid once rather than per packet.
///
/// `Send` and mutable, like the keyed cipher traits, and for the same reason: `&mut self` lets an
/// implementation carry per-message state — a reused streaming context, a hardware session
/// handle — without interior mutability, and does not impose `Sync` on implementors that cannot
/// offer it. A caller whose own signature is fixed to `&self`, such as STUN's `Setter::add_to`,
/// can still create a local `Mac` per message and use it mutably.
pub trait Mac: Send {
    /// Returns the untruncated tag length in bytes.
    fn output_len(&self) -> usize;

    /// Writes the tag over the concatenation of `input` into `output`.
    ///
    /// `output` must be exactly [`output_len`](Self::output_len) bytes. Protocols that transmit a
    /// truncated tag — SRTP sends 80 or 32 bits of an SHA-1 tag — truncate the result themselves.
    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError>;

    /// Verifies a complete untruncated tag in constant time.
    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError>;
}

/// A keyed stream cipher with a reusable expanded key.
pub trait StreamCipher: Send {
    /// Applies the keystream in place with a fresh IV.
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError>;
}

/// A keyed authenticated cipher with detached tags.
pub trait AeadCipher: Send {
    /// Returns the detached tag length in bytes.
    fn tag_len(&self) -> usize;

    /// Encrypts and authenticates a caller-owned buffer.
    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError>;

    /// Authenticates and decrypts a caller-owned buffer.
    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError>;
}

/// A keyed CBC block cipher with a reusable expanded key.
pub trait CbcCipher: Send {
    /// Returns the block and IV length in bytes.
    fn block_len(&self) -> usize;

    /// Encrypts whole blocks in place without applying padding.
    fn encrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError>;

    /// Decrypts whole blocks in place without removing padding.
    fn decrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError>;
}

/// Provider-owned one-shot ephemeral key exchange.
pub trait ActiveKeyExchange: Send {
    /// Returns the key-exchange algorithm.
    fn algorithm(&self) -> KeyExchangeAlgorithm;

    /// Returns the encoded wire public key.
    fn public_key(&self) -> &[u8];

    /// Consumes the private key and derives the shared secret.
    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SecretVec, CryptoError>;
}

/// A provider-owned signing key, including external or non-exportable keys.
pub trait SigningKey: Send + Sync {
    /// Reports whether this key can sign with `scheme`.
    fn supports(&self, scheme: SignatureScheme) -> bool;

    /// Returns the public key with explicit encoding.
    fn public_key(&self) -> PublicKey<'_>;

    /// Signs `message`.
    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Exports PKCS#8 when supported. `Ok(None)` means the key is non-exportable.
    fn to_pkcs8_der(&self) -> Result<Option<SecretVec>, CryptoError> {
        Ok(None)
    }
}

#[cfg(all(test, any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
mod tests {
    use super::*;

    /// RFC 5869 Appendix A, Test Case 1 (SHA-256): HKDF-Extract.
    #[test]
    fn hkdf_extract_rfc5869_test_case_1() -> Result<(), CryptoError> {
        let provider = crate::default_provider()?;
        let ikm = [0x0b; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let expected = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let prk = provider
            .crypto()
            .hkdf_extract(HmacAlgorithm::Sha256, &salt, &ikm)?;
        assert_eq!(prk, expected);
        Ok(())
    }

    /// RFC 5869 Appendix A, Test Case 1 (SHA-256): HKDF-Expand, crossing two output blocks.
    #[test]
    fn hkdf_expand_rfc5869_test_case_1() -> Result<(), CryptoError> {
        let provider = crate::default_provider()?;
        let prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        let okm = provider
            .crypto()
            .hkdf_expand(HmacAlgorithm::Sha256, &prk, &info, 42)?;
        assert_eq!(okm, expected);
        Ok(())
    }

    /// The RFC 5869 single-expansion ceiling: `255 * HashLen` bytes succeeds, one more fails.
    #[test]
    fn hkdf_expand_rejects_length_over_the_rfc5869_ceiling() -> Result<(), CryptoError> {
        let provider = crate::default_provider()?;
        let prk = [0x0b; 32];
        assert!(
            provider
                .crypto()
                .hkdf_expand(HmacAlgorithm::Sha256, &prk, &[], 255 * 32)
                .is_ok()
        );
        assert_eq!(
            provider
                .crypto()
                .hkdf_expand(HmacAlgorithm::Sha256, &prk, &[], 255 * 32 + 1),
            Err(CryptoError::OutputTooLarge {
                maximum: 255 * 32,
                actual: 255 * 32 + 1
            })
        );
        Ok(())
    }

    /// A zero-length expansion is an empty key, not an error (RFC 5869 §2.3).
    #[test]
    fn hkdf_expand_zero_length_is_empty() -> Result<(), CryptoError> {
        let provider = crate::default_provider()?;
        let okm = provider
            .crypto()
            .hkdf_expand(HmacAlgorithm::Sha256, &[0x0b; 32], &[], 0)?;
        assert!(okm.is_empty());
        Ok(())
    }
}
