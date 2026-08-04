use crate::common;
use crate::common::check_tag_len;
use crate::{
    ActiveKeyExchange, AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher,
    CryptoAlgorithm, CryptoError, HashAlgorithm, HmacAlgorithm, KeyExchangeAlgorithm, Mac,
    PublicKey, PublicKeyEncoding, RTCCrypto, RTCCryptoProvider, RTCRandom, SecretVec,
    SignatureScheme, SigningKey, StreamCipher, StreamCipherAlgorithm, constant_time_eq,
};
use ::hmac::Mac as RustCryptoMac;
use ring::aead;
use ring::agreement;
use ring::digest;
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair};
use sha1::Sha1;
use std::sync::Arc;

/// The built-in Ring provider bundle.
#[derive(Default)]
pub struct RingProvider {
    crypto: RingCrypto,
    random: RingRandom,
}

impl RingProvider {
    /// Creates a Ring provider.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            crypto: RingCrypto,
            random: RingRandom,
        }
    }
}

impl RTCCryptoProvider for RingProvider {
    fn name(&self) -> &'static str {
        "ring"
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        &self.crypto
    }

    fn random(&self) -> &dyn RTCRandom {
        &self.random
    }
}

/// Ring-backed cryptographic operations, with documented RustCrypto fallbacks for primitives Ring
/// does not expose (MD5, AES block/CTR/CBC, and AES-CCM).
#[derive(Default)]
pub struct RingCrypto;

/// Ring's operating-system-backed secure random source.
#[derive(Default)]
pub struct RingRandom;

impl RTCRandom for RingRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        common::fill_random(output)
    }
}

impl RTCCrypto for RingCrypto {
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        matches!(
            algorithm,
            CryptoAlgorithm::Hash(HashAlgorithm::Md5 | HashAlgorithm::Sha256)
                | CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1 | HmacAlgorithm::Sha256)
                | CryptoAlgorithm::Aead(
                    AeadAlgorithm::Aes128Gcm
                        | AeadAlgorithm::Aes256Gcm
                        | AeadAlgorithm::Aes128Ccm
                        | AeadAlgorithm::Aes128Ccm8
                        | AeadAlgorithm::ChaCha20Poly1305,
                )
                | CryptoAlgorithm::StreamCipher(
                    StreamCipherAlgorithm::Aes128Ctr | StreamCipherAlgorithm::Aes256Ctr,
                )
                | CryptoAlgorithm::BlockCipher(
                    BlockCipherAlgorithm::Aes128 | BlockCipherAlgorithm::Aes256,
                )
                | CryptoAlgorithm::Cbc(CbcAlgorithm::Aes256Cbc)
                | CryptoAlgorithm::KeyExchange(
                    KeyExchangeAlgorithm::P256
                        | KeyExchangeAlgorithm::P384
                        | KeyExchangeAlgorithm::X25519,
                )
                | CryptoAlgorithm::Signature(
                    SignatureScheme::Ed25519
                        | SignatureScheme::EcdsaP256Sha256
                        | SignatureScheme::EcdsaP384Sha384
                        | SignatureScheme::RsaPkcs1Sha1
                        | SignatureScheme::RsaPkcs1Sha256
                        | SignatureScheme::RsaPkcs1Sha384
                        | SignatureScheme::RsaPkcs1Sha512,
                )
                | CryptoAlgorithm::SigningKeyGeneration(
                    SignatureScheme::Ed25519 | SignatureScheme::EcdsaP256Sha256,
                )
                | CryptoAlgorithm::SigningKeyImport(
                    SignatureScheme::Ed25519
                        | SignatureScheme::EcdsaP256Sha256
                        | SignatureScheme::RsaPkcs1Sha256,
                )
        )
    }

    fn hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match algorithm {
            HashAlgorithm::Md5 => Ok(common::md5(data)),
            HashAlgorithm::Sha256 => Ok(digest::digest(&digest::SHA256, data).as_ref().to_vec()),
        }
    }

    fn new_hmac(&self, algorithm: HmacAlgorithm, key: &[u8]) -> Result<Box<dyn Mac>, CryptoError> {
        match algorithm {
            // ring's SHA-1 is a software implementation and measures 3.3x slower than
            // RustCrypto's; see common::RustCryptoHmacSha1. SHA-256 stays on ring, which uses
            // the hardware instructions.
            HmacAlgorithm::Sha1 => Ok(Box::new(RustCryptoHmacSha1::new(key))),
            HmacAlgorithm::Sha256 => Ok(Box::new(RingHmac {
                key: hmac::Key::new(hmac_algorithm(algorithm), key),
                output_len: algorithm.output_len(),
            })),
        }
    }

    fn block_encrypt(
        &self,
        algorithm: BlockCipherAlgorithm,
        key: &[u8],
        block: &mut [u8],
    ) -> Result<(), CryptoError> {
        common::block_encrypt(algorithm, key, block)
    }

    fn new_stream_cipher(
        &self,
        algorithm: StreamCipherAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, CryptoError> {
        common::new_stream_cipher(algorithm, key)
    }

    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        match algorithm {
            AeadAlgorithm::Aes128Ccm | AeadAlgorithm::Aes128Ccm8 => common::new_ccm(algorithm, key),
            AeadAlgorithm::Aes128Gcm => RingAead::create(&aead::AES_128_GCM, key),
            AeadAlgorithm::Aes256Gcm => RingAead::create(&aead::AES_256_GCM, key),
            AeadAlgorithm::ChaCha20Poly1305 => RingAead::create(&aead::CHACHA20_POLY1305, key),
        }
    }

    fn new_cbc(
        &self,
        algorithm: CbcAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn CbcCipher>, CryptoError> {
        common::new_cbc(algorithm, key)
    }

    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        RingKeyExchange::start(algorithm)
    }

    fn generate_signing_key(
        &self,
        scheme: SignatureScheme,
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        RingSigningKey::generate(scheme)
    }

    fn import_signing_key(
        &self,
        scheme: SignatureScheme,
        pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        RingSigningKey::import(scheme, pkcs8_der)
    }

    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        public_key: PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify_public_key_encoding(scheme, public_key.encoding)?;
        signature::UnparsedPublicKey::new(verification_algorithm(scheme), public_key.bytes)
            .verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// A keyed HMAC holding a `ring::hmac::Key`.
///
/// `Key::new` performs the ipad/opad derivation; `Context::with_key` only clones the resulting
/// state. Keeping the key here is what moves that derivation off the per-packet path.
struct RingHmac {
    key: hmac::Key,
    output_len: usize,
}

impl Mac for RingHmac {
    fn output_len(&self) -> usize {
        self.output_len
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        common::check_tag_len(self.output_len, output.len())?;
        let mut context = hmac::Context::with_key(&self.key);
        for part in input {
            context.update(part);
        }
        output.copy_from_slice(context.sign().as_ref());
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        common::check_tag_len(self.output_len, expected.len())?;
        let mut actual = vec![0; self.output_len];
        self.sign(input, &mut actual)?;
        if constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

fn hmac_algorithm(algorithm: HmacAlgorithm) -> hmac::Algorithm {
    match algorithm {
        HmacAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        HmacAlgorithm::Sha256 => hmac::HMAC_SHA256,
    }
}

struct RingAead {
    key: aead::LessSafeKey,
}

impl RingAead {
    fn create(
        algorithm: &'static aead::Algorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        common::check_key_len(algorithm.key_len(), key.len())?;
        let key = aead::UnboundKey::new(algorithm, key)
            .map(aead::LessSafeKey::new)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        Ok(Box::new(Self { key }))
    }
}

impl AeadCipher for RingAead {
    fn tag_len(&self) -> usize {
        16
    }

    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        common::check_nonce_len(12, nonce.len())?;
        common::check_tag_len(self.tag_len(), tag_out.len())?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| {
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: nonce.len(),
            }
        })?;
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), plaintext_and_ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        tag_out.copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        common::check_nonce_len(12, nonce.len())?;
        common::check_tag_len(self.tag_len(), tag.len())?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| {
            CryptoError::InvalidNonceLength {
                expected: 12,
                actual: nonce.len(),
            }
        })?;
        let tag = aead::Tag::try_from(tag).map_err(|_| CryptoError::InvalidTagLength {
            expected: self.tag_len(),
            actual: tag.len(),
        })?;
        self.key
            .open_in_place_separate_tag(
                nonce,
                aead::Aad::from(aad),
                tag,
                ciphertext_and_plaintext,
                0..,
            )
            .map(|_| ())
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

struct RingKeyExchange {
    algorithm: KeyExchangeAlgorithm,
    backend_algorithm: &'static agreement::Algorithm,
    private_key: agreement::EphemeralPrivateKey,
    public_key: Vec<u8>,
}

impl RingKeyExchange {
    fn start(algorithm: KeyExchangeAlgorithm) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        let backend_algorithm = agreement_algorithm(algorithm);
        let private_key =
            agreement::EphemeralPrivateKey::generate(backend_algorithm, &SystemRandom::new())
                .map_err(|_| CryptoError::RandomnessFailed)?;
        let public_key = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::Provider("key exchange public-key generation failed".into()))?
            .as_ref()
            .to_vec();
        Ok(Box::new(Self {
            algorithm,
            backend_algorithm,
            private_key,
            public_key,
        }))
    }
}

impl ActiveKeyExchange for RingKeyExchange {
    fn algorithm(&self) -> KeyExchangeAlgorithm {
        self.algorithm
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn complete(self: Box<Self>, peer_public_key: &[u8]) -> Result<SecretVec, CryptoError> {
        let peer = agreement::UnparsedPublicKey::new(self.backend_algorithm, peer_public_key);
        agreement::agree_ephemeral(self.private_key, &peer, |secret| {
            SecretVec::new(secret.to_vec())
        })
        .map_err(|_| CryptoError::InvalidPublicKey)
    }
}

enum RingSigningKeyKind {
    Ed25519(signature::Ed25519KeyPair),
    EcdsaP256(signature::EcdsaKeyPair),
    Rsa(signature::RsaKeyPair),
}

struct RingSigningKey {
    scheme: SignatureScheme,
    kind: RingSigningKeyKind,
    public_key: Vec<u8>,
    public_key_encoding: PublicKeyEncoding,
    pkcs8_der: SecretVec,
}

impl RingSigningKey {
    fn generate(scheme: SignatureScheme) -> Result<Arc<dyn SigningKey>, CryptoError> {
        let rng = SystemRandom::new();
        let pkcs8 = match scheme {
            SignatureScheme::Ed25519 => signature::Ed25519KeyPair::generate_pkcs8(&rng),
            SignatureScheme::EcdsaP256Sha256 => signature::EcdsaKeyPair::generate_pkcs8(
                &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &rng,
            ),
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(
                    CryptoAlgorithm::SigningKeyGeneration(scheme),
                ));
            }
        }
        .map_err(|_| CryptoError::RandomnessFailed)?;
        Self::import(scheme, pkcs8.as_ref())
    }

    fn import(
        scheme: SignatureScheme,
        pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        let rng = SystemRandom::new();
        let (kind, public_key, public_key_encoding) = match scheme {
            SignatureScheme::Ed25519 => {
                let key = signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8_der)
                    .map_err(|_| CryptoError::InvalidPrivateKey)?;
                let public = key.public_key().as_ref().to_vec();
                (
                    RingSigningKeyKind::Ed25519(key),
                    public,
                    PublicKeyEncoding::Ed25519Raw,
                )
            }
            SignatureScheme::EcdsaP256Sha256 => {
                let key = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    pkcs8_der,
                    &rng,
                )
                .map_err(|_| CryptoError::InvalidPrivateKey)?;
                let public = key.public_key().as_ref().to_vec();
                (
                    RingSigningKeyKind::EcdsaP256(key),
                    public,
                    PublicKeyEncoding::EcUncompressedPoint,
                )
            }
            SignatureScheme::RsaPkcs1Sha256 => {
                let key = signature::RsaKeyPair::from_pkcs8(pkcs8_der)
                    .map_err(|_| CryptoError::InvalidPrivateKey)?;
                let public = key.public().as_ref().to_vec();
                (
                    RingSigningKeyKind::Rsa(key),
                    public,
                    PublicKeyEncoding::RsaPkcs1Der,
                )
            }
            _ => {
                return Err(CryptoError::UnsupportedAlgorithm(
                    CryptoAlgorithm::SigningKeyImport(scheme),
                ));
            }
        };
        Ok(Arc::new(Self {
            scheme,
            kind,
            public_key,
            public_key_encoding,
            pkcs8_der: SecretVec::new(pkcs8_der.to_vec()),
        }))
    }
}

impl SigningKey for RingSigningKey {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        self.scheme == scheme
    }

    fn public_key(&self) -> PublicKey<'_> {
        PublicKey {
            encoding: self.public_key_encoding,
            bytes: &self.public_key,
        }
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if !self.supports(scheme) {
            return Err(CryptoError::UnsupportedAlgorithm(
                CryptoAlgorithm::Signature(scheme),
            ));
        }
        match &self.kind {
            RingSigningKeyKind::Ed25519(key) => Ok(key.sign(message).as_ref().to_vec()),
            RingSigningKeyKind::EcdsaP256(key) => key
                .sign(&SystemRandom::new(), message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| CryptoError::Provider("signature generation failed".into())),
            RingSigningKeyKind::Rsa(key) => {
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(
                    &signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    message,
                    &mut signature,
                )
                .map_err(|_| CryptoError::Provider("signature generation failed".into()))?;
                Ok(signature)
            }
        }
    }

    fn to_pkcs8_der(&self) -> Result<Option<SecretVec>, CryptoError> {
        Ok(Some(self.pkcs8_der.clone()))
    }
}

fn agreement_algorithm(algorithm: KeyExchangeAlgorithm) -> &'static agreement::Algorithm {
    match algorithm {
        KeyExchangeAlgorithm::P256 => &agreement::ECDH_P256,
        KeyExchangeAlgorithm::P384 => &agreement::ECDH_P384,
        KeyExchangeAlgorithm::X25519 => &agreement::X25519,
    }
}

fn verification_algorithm(
    scheme: SignatureScheme,
) -> &'static dyn signature::VerificationAlgorithm {
    match scheme {
        SignatureScheme::Ed25519 => &signature::ED25519,
        SignatureScheme::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::RsaPkcs1Sha1 => &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        SignatureScheme::RsaPkcs1Sha256 => {
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
        }
        SignatureScheme::RsaPkcs1Sha384 => &signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureScheme::RsaPkcs1Sha512 => {
            &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
        }
    }
}

fn verify_public_key_encoding(
    scheme: SignatureScheme,
    encoding: PublicKeyEncoding,
) -> Result<(), CryptoError> {
    let valid = matches!(
        (scheme, encoding),
        (SignatureScheme::Ed25519, PublicKeyEncoding::Ed25519Raw)
            | (
                SignatureScheme::EcdsaP256Sha256 | SignatureScheme::EcdsaP384Sha384,
                PublicKeyEncoding::EcUncompressedPoint
            )
            | (
                SignatureScheme::RsaPkcs1Sha1
                    | SignatureScheme::RsaPkcs1Sha256
                    | SignatureScheme::RsaPkcs1Sha384
                    | SignatureScheme::RsaPkcs1Sha512,
                PublicKeyEncoding::RsaPkcs1Der
            )
    );
    if valid {
        Ok(())
    } else {
        Err(CryptoError::InvalidPublicKey)
    }
}

type HmacSha1 = ::hmac::Hmac<Sha1>;

/// HMAC-SHA1 backed by RustCrypto, keyed once.
///
/// `ring` exposes SHA-1 only as `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the ARMv8 SHA-1
/// instructions, measuring 4469 ns against RustCrypto's 1373 ns over a 1212-byte SRTP packet —
/// 3.3x, and the whole of the SRTP AES-CM/HMAC regression. The built-in providers are already
/// composite (AES-CTR, CCM, CBC and MD5 come from RustCrypto too), so HMAC-SHA1 is composed the
/// same way rather than making the slower backend the default. `aws-lc-rs` has fast SHA-1 and
/// keeps its own.
pub(crate) struct RustCryptoHmacSha1 {
    keyed: HmacSha1,
}

impl RustCryptoHmacSha1 {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self {
            // HMAC accepts any key length: it hashes longer keys and zero-pads shorter ones.
            keyed: <HmacSha1 as RustCryptoMac>::new_from_slice(key)
                .expect("HMAC accepts keys of any length"),
        }
    }
}

impl Mac for RustCryptoHmacSha1 {
    fn output_len(&self) -> usize {
        20
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        check_tag_len(20, output.len())?;
        let mut mac = self.keyed.clone();
        for part in input {
            mac.update(part);
        }
        output.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        check_tag_len(20, expected.len())?;
        let mut actual = [0u8; 20];
        self.sign(input, &mut actual)?;
        if crate::constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}
