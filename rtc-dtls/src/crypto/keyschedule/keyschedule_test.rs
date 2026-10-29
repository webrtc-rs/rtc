//! Ported from pion/dtls v3.1.15 `pkg/crypto/keyschedule/keyschedule_test.go`.
//!
//! pion's functions take a Go `func() hash.Hash`; here the hash is
//! [`KeyscheduleHash`](super::KeyscheduleHash), and pion's nil hash is `None`.

use super::*;

use crypto::HashAlgorithm as CryptoHashAlgorithm;
use std::sync::Arc;

fn provider() -> Result<Arc<dyn crypto::RTCCryptoProvider>> {
    crypto::default_provider().map_err(|e| Error::Crypto(e.to_string()))
}

/// pion's `TestHKDFExtract_SHA256_VectorA1`: RFC 5869 Appendix A.1 (Test Case 1, SHA-256).
#[test]
fn hkdf_extract_sha256_vector_a1() -> Result<()> {
    let provider = provider()?;

    // IKM = 0x0b repeated 22 bytes (RFC 5869 A.1)
    let ikm = [0x0b; 22];

    // salt = 0x000102030405060708090a0b0c (RFC 5869 A.1)
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    // PRK expected (RFC 5869 A.1)
    let expected = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
        0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
        0xb3, 0xe5,
    ];

    let actual = hkdf_extract(
        provider.crypto(),
        Some(KeyscheduleHash::Sha256),
        &salt,
        &ikm,
    )?;
    assert_eq!(expected.as_slice(), actual.as_slice());

    Ok(())
}

/// pion's `TestHKDFExtract_Nil_Hash_Error`.
#[test]
fn hkdf_extract_nil_hash_error() -> Result<()> {
    let provider = provider()?;

    let ikm = [0x0b; 22];
    let salt = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];

    assert_eq!(
        hkdf_extract(provider.crypto(), None, &salt, &ikm).unwrap_err(),
        Error::ErrHkdfMissingHashFunction
    );

    Ok(())
}

/// pion's `TestHKDFExpandLabel_Simple`.
#[test]
fn hkdf_expand_label_simple() -> Result<()> {
    let provider = provider()?;

    let secret = [0x11; 32];
    let ctx = [0xAA, 0xBB];

    let out = hkdf_expand_label(
        provider.crypto(),
        Some(KeyscheduleHash::Sha256),
        &secret,
        "client in",
        &ctx,
        16,
    )?;
    assert!(!out.is_empty());

    Ok(())
}

/// pion's `TestHKDFLabel_Encoding_Shape`: a label pion accepts, plus the exact
/// `HkdfLabel` bytes (RFC 8446 §7.1) the call encodes.
#[test]
fn hkdf_label_encoding_shape() -> Result<()> {
    let provider = provider()?;

    let test_str = "key";

    let secret = [0u8; 32];
    let out = hkdf_expand_label(
        provider.crypto(),
        Some(KeyscheduleHash::Sha256),
        &secret,
        test_str,
        &[],
        32,
    )?;
    assert_eq!(out.len(), 32);

    // The RFC 8446 §7.1 structure the call above encoded: a u16 length, a u8-prefixed
    // "dtls13key" label (RFC 9147 §5.9's prefix), and a u8-prefixed empty context.
    assert_eq!(
        hkdf_label(32, b"dtls13key", b""),
        vec![
            0x00, 0x20, // length = 32
            0x09, // label length = 9
            b'd', b't', b'l', b's', b'1', b'3', b'k', b'e', b'y', //
            0x00, // context length = 0
        ]
    );

    Ok(())
}

/// pion's `TestHKDFLabel_Encoding_Shape_Label_Small`: "" is 0 + 6 < 7, where 6 is the length
/// of the prefix.
#[test]
fn hkdf_label_encoding_shape_label_small() -> Result<()> {
    let provider = provider()?;

    let test_str = "";

    let secret = [0u8; 32];
    assert_eq!(
        hkdf_expand_label(
            provider.crypto(),
            Some(KeyscheduleHash::Sha256),
            &secret,
            test_str,
            &[],
            32
        )
        .unwrap_err(),
        Error::ErrHkdfLabelTooSmall
    );

    Ok(())
}

/// pion's `TestHKDFLabel_Encoding_Shape_Label_Big`: 250 + 6 > 255, where 6 is the length of
/// the prefix.
#[test]
fn hkdf_label_encoding_shape_label_big() -> Result<()> {
    let provider = provider()?;

    let test_str = "a".repeat(250);

    let secret = [0u8; 32];
    assert_eq!(
        hkdf_expand_label(
            provider.crypto(),
            Some(KeyscheduleHash::Sha256),
            &secret,
            &test_str,
            &[],
            32
        )
        .unwrap_err(),
        Error::ErrHkdfLabelTooBig
    );

    Ok(())
}

/// pion's `TestHKDFLabel_Encoding_Shape_Context_Length_Zero`.
#[test]
fn hkdf_label_encoding_shape_context_length_zero() -> Result<()> {
    let provider = provider()?;

    let valid_label = "hi";
    let zero_context: Vec<u8> = Vec::new();

    let secret = [0u8; 32];
    let out = hkdf_expand_label(
        provider.crypto(),
        Some(KeyscheduleHash::Sha256),
        &secret,
        valid_label,
        &zero_context,
        32,
    )?;
    assert_eq!(out.len(), 32);

    assert_eq!(zero_context.len(), 0);

    Ok(())
}

/// pion's `TestHKDFLabel_Encoding_Shape_Context_Too_Big`.
#[test]
fn hkdf_label_encoding_shape_context_too_big() -> Result<()> {
    let provider = provider()?;

    let valid_label = "hi";
    let secret = [0u8; 32];

    let invalid_context = vec![1u8; 256];
    assert_eq!(
        hkdf_expand_label(
            provider.crypto(),
            Some(KeyscheduleHash::Sha256),
            &secret,
            valid_label,
            &invalid_context,
            32
        )
        .unwrap_err(),
        Error::ErrHkdfContextTooBig
    );
    assert_eq!(invalid_context.len(), 256);

    let invalid_context = "a".repeat(256).into_bytes();
    assert_eq!(
        hkdf_expand_label(
            provider.crypto(),
            Some(KeyscheduleHash::Sha256),
            &secret,
            valid_label,
            &invalid_context,
            32
        )
        .unwrap_err(),
        Error::ErrHkdfContextTooBig
    );
    assert_eq!(invalid_context.len(), 256);

    Ok(())
}

/// pion's `TestDeriveSecret`.
#[test]
fn test_derive_secret() -> Result<()> {
    let provider = provider()?;

    let secret = [0x11; 32];
    let ctx = [0xAA, 0xBB];

    // pion writes the context into a running SHA-256 and passes the hash; the digest of that
    // transcript is the context DeriveSecret expands.
    let transcript = provider
        .crypto()
        .hash(CryptoHashAlgorithm::Sha256, &ctx)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let out = derive_secret(
        provider.crypto(),
        Some(KeyscheduleHash::Sha256),
        &secret,
        "client in",
        Some(&transcript),
    )?;
    assert!(!out.is_empty());
    assert_eq!(out.len(), KeyscheduleHash::Sha256.size());

    Ok(())
}

/// pion's `TestDeriveSecret_Empty_Transcript`.
#[test]
fn test_derive_secret_empty_transcript() -> Result<()> {
    let provider = provider()?;

    let test_str = "key";

    let secret = [0u8; 32];
    let out = derive_secret(
        provider.crypto(),
        Some(KeyscheduleHash::Sha256),
        &secret,
        test_str,
        None,
    )?;
    assert_eq!(out.len(), KeyscheduleHash::Sha256.size());

    Ok(())
}
