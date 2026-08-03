use crate::CryptoAlgorithm;

/// A provider-neutral cryptographic failure.
#[non_exhaustive]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// No built-in default provider was compiled.
    #[error("no default crypto provider is enabled")]
    NoDefaultProvider,
    /// The provider does not implement an algorithm.
    #[error("unsupported algorithm: {0:?}")]
    UnsupportedAlgorithm(CryptoAlgorithm),
    /// A key has the wrong length.
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Required length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// A nonce or IV has the wrong length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Required length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// An authentication tag has the wrong length.
    #[error("invalid tag length: expected {expected}, got {actual}")]
    InvalidTagLength {
        /// Required length.
        expected: usize,
        /// Supplied length.
        actual: usize,
    },
    /// Public-key bytes are malformed or use the wrong encoding.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Private-key bytes are malformed or incompatible with the scheme.
    #[error("invalid private key")]
    InvalidPrivateKey,
    /// Decryption, padding, or tag authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// Signature verification failed.
    #[error("signature verification failed")]
    InvalidSignature,
    /// The cryptographically secure random source failed.
    #[error("randomness source failed")]
    RandomnessFailed,
    /// A caller-owned output buffer is too small.
    #[error("output buffer is too small: required {required}, got {actual}")]
    OutputTooSmall {
        /// Required length.
        required: usize,
        /// Supplied length.
        actual: usize,
    },
    /// Sanitized provider diagnostic context.
    #[error("provider failure: {0}")]
    Provider(String),
}
