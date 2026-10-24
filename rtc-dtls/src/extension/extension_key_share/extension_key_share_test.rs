//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/key_share_test.go`.
//!
//! pion's concrete `KeyShare.Unmarshal` receives the extension with its type code and validates
//! it; here the generic [`Extension::unmarshal`] path plays that role, so the fixtures are the
//! byte-for-byte pion ones and the assertions map one to one.

use super::*;

use std::io::{BufReader, BufWriter};

fn marshal(key_share: &ExtensionKeyShare) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::KeyShare(key_share.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionKeyShare> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::KeyShare(key_share) => Ok(key_share),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestKeyShare_Marshal_ClientHello_EmptyVector_RoundTrip`.
#[test]
fn key_share_marshal_client_hello_empty_vector_round_trip() -> Result<()> {
    // No fields set -> treated as ClientHello with empty client_shares vector.
    let key_share = ExtensionKeyShare::default();
    let raw = marshal(&key_share)?;

    // Expect: type, ext_len=2, vector_len=0.
    let expect = [0x00, 0x33, 0x00, 0x02, 0x00, 0x00];
    assert_eq!(raw, expect);

    let parsed = unmarshal(&raw)?;
    assert!(parsed.server_share.is_none());
    assert!(parsed.selected_group.is_none());
    assert_eq!(
        parsed.client_shares.as_ref().map_or(0, Vec::len),
        0,
        "the empty vector unmarshals to no context at all, as pion's nil slice"
    );
    Ok(())
}

/// pion's `TestKeyShare_Marshal_ClientHello_OK`.
#[test]
fn key_share_marshal_client_hello_ok() -> Result<()> {
    // X25519 public key
    let p1: [u8; 32] = [
        0xa8, 0xf1, 0xb7, 0x2d, 0x70, 0x7e, 0x58, 0xa4, 0x41, 0x73, 0x9e, 0x21, 0x7b, 0x62, 0x1e,
        0xd1, 0x4d, 0x11, 0x69, 0xa6, 0xbf, 0x72, 0x21, 0xec, 0xaf, 0x76, 0xf3, 0x4e, 0xec, 0x48,
        0x52, 0x01,
    ];
    // P-256 uncompressed point
    let p2: [u8; 65] = [
        0x04, 0xc5, 0xf5, 0xee, 0xf0, 0x1f, 0x4d, 0x53, 0xa6, 0x42, 0xd8, 0x3b, 0x3a, 0x40, 0x48,
        0x22, 0x49, 0x7f, 0x1a, 0xc7, 0xce, 0x66, 0x85, 0xfb, 0xc9, 0x91, 0x9d, 0x7f, 0x72, 0xce,
        0x88, 0x30, 0xc3, 0x3d, 0x05, 0x4c, 0x5f, 0x7a, 0xaa, 0x9d, 0xcf, 0x3b, 0x44, 0x2a, 0xc0,
        0xc9, 0x9f, 0x03, 0x2b, 0x05, 0x5b, 0xbb, 0x9c, 0x5d, 0x7f, 0xf9, 0x24, 0x51, 0x4b, 0xab,
        0x36, 0xce, 0x46, 0x55, 0x7b,
    ];

    let key_share = ExtensionKeyShare {
        client_shares: Some(vec![
            KeyShareEntry {
                group: NamedGroup::X25519,
                key_exchange: p1.to_vec(),
            },
            KeyShareEntry {
                group: NamedGroup::P256,
                key_exchange: p2.to_vec(),
            },
        ]),
        ..ExtensionKeyShare::default()
    };

    let mut expect = vec![
        0x00, 0x33, // extension type
        0x00, 0x6b, // extension length
        0x00, 0x69, // vec length
        0x00, 0x1d, // X25519
        0x00, 0x20, // length 32
    ];
    expect.extend_from_slice(&p1);
    expect.extend_from_slice(&[
        0x00, 0x17, // P-256
        0x00, 0x41, // length 65
    ]);
    expect.extend_from_slice(&p2);

    assert_eq!(marshal(&key_share)?, expect);
    Ok(())
}

/// pion's `TestKeyShare_Marshal_ClientHello_Errors`.
#[test]
fn key_share_marshal_client_hello_errors() -> Result<()> {
    // duplicate group
    let key_share = ExtensionKeyShare {
        client_shares: Some(vec![
            KeyShareEntry {
                group: NamedGroup::X25519,
                key_exchange: vec![1],
            },
            KeyShareEntry {
                group: NamedGroup::X25519,
                key_exchange: vec![2],
            },
        ]),
        ..ExtensionKeyShare::default()
    };
    assert_eq!(
        marshal(&key_share).unwrap_err(),
        Error::ErrDuplicateKeyShare
    );

    // key len = 0
    let key_share = ExtensionKeyShare {
        client_shares: Some(vec![KeyShareEntry {
            group: NamedGroup::X25519,
            key_exchange: vec![],
        }]),
        ..ExtensionKeyShare::default()
    };
    assert_eq!(
        marshal(&key_share).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );

    // key len > 65535
    let key_share = ExtensionKeyShare {
        client_shares: Some(vec![KeyShareEntry {
            group: NamedGroup::X25519,
            key_exchange: vec![0u8; 65536],
        }]),
        ..ExtensionKeyShare::default()
    };
    assert_eq!(
        marshal(&key_share).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );
    Ok(())
}

/// pion's `TestKeyShare_Marshal_ServerHello_OK`.
#[test]
fn key_share_marshal_server_hello_ok() -> Result<()> {
    // X25519 public key
    let p1: [u8; 32] = [
        0xa8, 0xf1, 0xb7, 0x2d, 0x70, 0x7e, 0x58, 0xa4, 0x41, 0x73, 0x9e, 0x21, 0x7b, 0x62, 0x1e,
        0xd1, 0x4d, 0x11, 0x69, 0xa6, 0xbf, 0x72, 0x21, 0xec, 0xaf, 0x76, 0xf3, 0x4e, 0xec, 0x48,
        0x52, 0x01,
    ];
    let key_share = ExtensionKeyShare {
        server_share: Some(KeyShareEntry {
            group: NamedGroup::X25519,
            key_exchange: p1.to_vec(),
        }),
        ..ExtensionKeyShare::default()
    };

    let mut expect = vec![
        0x00, 0x33, // extension type
        0x00, 0x24, // extension length
        0x00, 0x1d, // X25519
        0x00, 0x20, // length 32
    ];
    expect.extend_from_slice(&p1);

    assert_eq!(marshal(&key_share)?, expect);
    Ok(())
}

/// pion's `TestKeyShare_Marshal_HelloRetryRequest`.
#[test]
fn key_share_marshal_hello_retry_request() -> Result<()> {
    let key_share = ExtensionKeyShare {
        selected_group: Some(NamedGroup::P384),
        ..ExtensionKeyShare::default()
    };

    let expect = [
        0x00, 0x33, // extension type
        0x00, 0x02, // extension length
        0x00, 0x18, // P-384
    ];

    assert_eq!(marshal(&key_share)?, expect);
    Ok(())
}

/// pion's `TestKeyShare_Marshal_MultipleContexts_Error`.
#[test]
fn key_share_marshal_multiple_contexts_error() -> Result<()> {
    let key_share = ExtensionKeyShare {
        client_shares: Some(vec![KeyShareEntry {
            group: NamedGroup::X25519,
            key_exchange: vec![1],
        }]),
        server_share: Some(KeyShareEntry {
            group: NamedGroup::X25519,
            key_exchange: vec![2],
        }),
        selected_group: Some(NamedGroup::X25519),
    };

    assert_eq!(
        marshal(&key_share).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );
    Ok(())
}

/// pion's `TestKeyShare_Unmarshal_ClientHello`.
#[test]
fn key_share_unmarshal_client_hello() -> Result<()> {
    let raw = [
        0x00, 0x33, // extension type
        0x00, 0x11, // extension length
        0x00, 0x0f, // vec length
        0x00, 0x1d, // X25519
        0x00, 0x01, // group length
        0x41, 0x11, 0xff, // Non-supported group
        0x00, 0x01, // group length
        0x42, 0x00, 0x18, // P-384
        0x00, 0x01, // group length
        0x43,
    ];

    let key_share = unmarshal(&raw)?;
    assert!(key_share.server_share.is_none());
    assert!(key_share.selected_group.is_none());

    let shares = key_share.client_shares.as_ref().unwrap();
    assert_eq!(shares.len(), 3);
    assert_eq!(shares[0].group, NamedGroup::X25519);
    assert_eq!(shares[0].key_exchange, [0x41]);
    assert_eq!(shares[1].group, NamedGroup(0x11ff));
    assert_eq!(shares[1].key_exchange, [0x42]);
    assert_eq!(shares[2].group, NamedGroup::P384);
    assert_eq!(shares[2].key_exchange, [0x43]);

    // zero length keyshare vector should throw error
    let raw_zero = [
        0x00, 0x33, // extension type
        0x00, 0x07, // extension length
        0x00, 0x05, // vec length
        0x00, 0x1d, // X25519
        0x00, 0x00, // group length
        0x42,
    ];
    assert_eq!(
        unmarshal(&raw_zero).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );

    // sending duplicate valid groups should error
    let raw_dup = [
        0x00, 0x33, // extension type
        0x00, 0x11, // extension length
        0x00, 0x0f, // vec length
        0x00, 0x1d, // X25519
        0x00, 0x01, // group length
        0x41, 0x00, 0x1d, // Non-supported group
        0x00, 0x01, // group length
        0x42, 0x00, 0x18, // P-384
        0x00, 0x01, // group length
        0x43,
    ];
    assert_eq!(
        unmarshal(&raw_dup).unwrap_err(),
        Error::ErrDuplicateKeyShare
    );
    Ok(())
}

/// pion's `TestKeyShare_Unmarshal_ClientHello_TruncatedEntries`.
#[test]
fn key_share_unmarshal_client_hello_truncated_entries() -> Result<()> {
    // bad ext: vecLen=1, then a single byte to force group uint16 read error.
    let raw = [
        0x00, 0x33, // extension type
        0x00, 0x03, // ext len = 3
        0x00, 0x01, // vecLen = 1
        0xff, // only 1 byte, not enough for group uint16
    ];
    assert_eq!(
        unmarshal(&raw).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );

    // bad ext 2: one full group but key_exchange length=1 with no bytes
    let raw2 = [
        0x00, 0x33, // extension type
        0x00, 0x06, // ext len = 6 (2 vecLen + 4 bytes below)
        0x00, 0x04, // vecLen = 4
        0x00, 0x1d, // group x25519
        0x00, 0x01, // key len = 1 (but 0 bytes present) -> read fails
    ];
    assert_eq!(
        unmarshal(&raw2).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );
    Ok(())
}

/// pion's `TestKeyShare_Unmarshal_HelloRetryRequest`.
#[test]
fn key_share_unmarshal_hello_retry_request() -> Result<()> {
    let raw = [
        0x00, 0x33, // extension type
        0x00, 0x02, // extension length
        0x00, 0x1d, // X25519
    ];

    let key_share = unmarshal(&raw)?;
    assert_eq!(key_share.selected_group, Some(NamedGroup::X25519));
    assert!(key_share.server_share.is_none());
    assert!(key_share.client_shares.is_none());

    // Unsupported group in HelloRetryRequest: accepted, without a selected group.
    let raw2 = [
        0x00, 0x33, // extension type
        0x00, 0x02, // extension length
        0x00, 0x01, // unsupported group
    ];
    let key_share = unmarshal(&raw2)?;
    assert!(key_share.selected_group.is_none());

    let raw_trunc = [
        0x00, 0x33, // extension type
        0x00, 0x01, 0x00,
    ];
    assert_eq!(
        unmarshal(&raw_trunc).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );
    Ok(())
}

/// pion's `TestKeyShare_Unmarshal_ServerHello`.
#[test]
fn key_share_unmarshal_server_hello() -> Result<()> {
    let raw = [
        0x00, 0x33, // extension type
        0x00, 0x06, // extension length
        0x00, 0x1d, // X25519
        0x00, 0x02, // group length
        0x41, 0x42,
    ];

    let key_share = unmarshal(&raw)?;
    assert!(key_share.selected_group.is_none());
    assert!(key_share.client_shares.is_none());
    let share = key_share.server_share.as_ref().unwrap();
    assert_eq!(share.group, NamedGroup::X25519);
    assert_eq!(share.key_exchange, [0x41, 0x42]);

    // Trailing extra bytes after key_share
    let raw_trailing = [
        0x00, 0x33, // extension type
        0x00, 0x08, // extension length
        0x00, 0x1d, // X25519
        0x00, 0x02, // group length
        0x41, 0x42, 0x43, 0x44,
    ];
    assert_eq!(
        unmarshal(&raw_trailing).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );

    // bad key length (claims 1, provides 0)
    let raw_bad_len = [
        0x00, 0x33, // extension type
        0x00, 0x04, // ext len matches the 4 bytes below
        0x00, 0x1d, // group x25519
        0x00, 0x01, // key len = 1, but 0 bytes provided -> format error
    ];
    assert_eq!(
        unmarshal(&raw_bad_len).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );
    Ok(())
}

/// pion's `TestKeyShare_Unmarshal_Errors`.
#[test]
fn key_share_unmarshal_errors() -> Result<()> {
    // wrong extension type
    let raw_wrong = [0xff, 0xff, 0x00, 0x01, 0x00];
    assert_eq!(
        unmarshal(&raw_wrong).unwrap_err(),
        Error::ErrInvalidExtensionType
    );

    // buffer too small (no length field)
    let raw_small = [0x00, 0x33];
    assert_eq!(unmarshal(&raw_small).unwrap_err(), Error::ErrBufferTooSmall);

    // empty extData
    let raw_empty = [
        0x00, 0x33, // extension type
        0x00, 0x00, // extension length
    ];
    assert_eq!(
        unmarshal(&raw_empty).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );

    let raw_trailing = [
        0x00, 0x33, // extension type
        0x00, 0x08, // extension length
        0x00, 0x05, // vec length
        0x00, 0x1d, // X25519
        0x00, 0x01, // length
        0x42, 0x43, // trailing byte
    ];
    assert_eq!(
        unmarshal(&raw_trailing).unwrap_err(),
        Error::ErrInvalidKeyShareFormat
    );
    Ok(())
}

/// pion's `Test_hasTooManyContexts`: no more than exactly one key-share context may be set.
#[test]
fn has_too_many_contexts() {
    assert!(!super::has_too_many_contexts(false, false, false));
    assert!(!super::has_too_many_contexts(true, false, false)); // exactly one
    assert!(!super::has_too_many_contexts(false, true, false));
    assert!(!super::has_too_many_contexts(false, false, true));
    assert!(super::has_too_many_contexts(true, true, false)); // two
    assert!(super::has_too_many_contexts(true, false, true));
    assert!(super::has_too_many_contexts(false, true, true));
    assert!(super::has_too_many_contexts(true, true, true)); // three
}
