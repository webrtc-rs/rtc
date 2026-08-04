/// Algorithms accepted by [`crate::RTCCrypto::hash`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// MD5, retained only for STUN long-term credential derivation.
    Md5,
    /// SHA-256.
    Sha256,
}

/// Algorithms accepted by the HMAC operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HmacAlgorithm {
    /// HMAC-SHA1.
    Sha1,
    /// HMAC-SHA256.
    Sha256,
}

impl HmacAlgorithm {
    /// Returns the native tag length in bytes.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

/// Authenticated-encryption algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AeadAlgorithm {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// AES-128-CCM with a 16-byte tag.
    Aes128Ccm,
    /// AES-128-CCM with an 8-byte tag.
    Aes128Ccm8,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// Stream-cipher algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamCipherAlgorithm {
    /// AES-128 in counter mode.
    Aes128Ctr,
    /// AES-256 in counter mode.
    Aes256Ctr,
}

/// Single-block encryption algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockCipherAlgorithm {
    /// AES-128.
    Aes128,
    /// AES-256.
    Aes256,
}

/// CBC algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CbcAlgorithm {
    /// AES-256-CBC.
    Aes256Cbc,
}

/// Ephemeral key-agreement algorithms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyExchangeAlgorithm {
    /// ECDH over NIST P-256.
    P256,
    /// ECDH over NIST P-384.
    P384,
    /// X25519.
    X25519,
}

/// Signature schemes currently used by DTLS.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// Ed25519.
    Ed25519,
    /// ECDSA P-256 with SHA-256 and ASN.1 DER signatures.
    EcdsaP256Sha256,
    /// ECDSA P-384 with SHA-384 and ASN.1 DER signatures.
    EcdsaP384Sha384,
    /// RSA PKCS#1 v1.5 with SHA-1, for legacy verification only.
    RsaPkcs1Sha1,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1Sha512,
}

/// The encoding of public-key bytes.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyEncoding {
    /// Complete DER-encoded SubjectPublicKeyInfo.
    SubjectPublicKeyInfoDer,
    /// SEC1 uncompressed elliptic-curve point.
    EcUncompressedPoint,
    /// Raw 32-byte Ed25519 public key.
    Ed25519Raw,
    /// PKCS#1 DER `RSAPublicKey`.
    RsaPkcs1Der,
}

/// Borrowed public-key bytes with an explicit encoding.
#[derive(Debug, Clone, Copy)]
pub struct PublicKey<'a> {
    /// Encoding of `bytes`.
    pub encoding: PublicKeyEncoding,
    /// Encoded public key.
    pub bytes: &'a [u8],
}

/// A provider capability identifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    /// Stateless hash operation.
    Hash(HashAlgorithm),
    /// HMAC generation and verification.
    Hmac(HmacAlgorithm),
    /// Authenticated encryption.
    Aead(AeadAlgorithm),
    /// Stream encryption.
    StreamCipher(StreamCipherAlgorithm),
    /// Single-block encryption.
    BlockCipher(BlockCipherAlgorithm),
    /// CBC encryption and decryption.
    Cbc(CbcAlgorithm),
    /// Ephemeral key agreement.
    KeyExchange(KeyExchangeAlgorithm),
    /// Signature verification.
    Signature(SignatureScheme),
    /// Signing-key generation.
    SigningKeyGeneration(SignatureScheme),
    /// PKCS#8 signing-key import.
    SigningKeyImport(SignatureScheme),
}
