//! Provider-neutral cryptography for the webrtc-rs RTC stack.
//!
//! The open traits in this crate allow applications to supply cryptography and randomness without
//! registering global state. Built-in providers are selected with additive Cargo features.

mod algorithm;
mod error;
mod provider;
mod secret;
mod traits;

#[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
mod common;
pub mod providers;

#[cfg(feature = "test-support")]
pub mod conformance;

pub use algorithm::*;
pub use error::CryptoError;
pub use provider::default_provider;
pub use secret::SecretVec;
pub use traits::*;

/// Compares equal-length byte strings without data-dependent early exit.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;

    left.len() == right.len() && bool::from(left.ct_eq(right))
}

const _: () = {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    fn assert_dyn_compatible(
        _provider: &dyn RTCCryptoProvider,
        _crypto: &dyn RTCCrypto,
        _random: &dyn RTCRandom,
        _mac: &dyn Mac,
        _stream: &dyn StreamCipher,
        _aead: &dyn AeadCipher,
        _cbc: &dyn CbcCipher,
        _exchange: &dyn ActiveKeyExchange,
        _signing_key: &dyn SigningKey,
    ) {
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretVec::new(vec![1, 2, 3, 4]);
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("len: 4"));
        assert!(!debug.contains("1, 2, 3, 4"));
    }

    #[test]
    fn secret_into_bytes_is_explicit() {
        let secret = SecretVec::new(vec![1, 2, 3]);
        assert_eq!(secret.into_bytes(), vec![1, 2, 3]);
    }

    #[test]
    fn errors_have_provider_neutral_text() {
        assert_eq!(
            CryptoError::AuthenticationFailed.to_string(),
            "authentication failed"
        );
        assert_eq!(
            CryptoError::InvalidSignature.to_string(),
            "signature verification failed"
        );
    }

    #[test]
    fn constant_time_equality_checks_length_and_content() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"same", b"same-longer"));
    }
}
