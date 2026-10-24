//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/pre_shared_key_test.go`.
//!
//! pion's concrete `PreSharedKey.Unmarshal` receives the extension with its type code and
//! validates it; here the generic [`Extension::unmarshal`] path plays that role, so the fixtures
//! are the byte-for-byte pion ones.

use super::*;

use std::io::{BufReader, BufWriter};

fn binder() -> Vec<u8> {
    (0..32u8).collect()
}

fn marshal(ext: &ExtensionPreSharedKey) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::PreSharedKey(ext.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionPreSharedKey> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::PreSharedKey(ext) => Ok(ext),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestPreSharedKey_ServerHello`.
#[test]
fn pre_shared_key_server_hello() -> Result<()> {
    let raw = [
        0x00, 0x29, // extension type
        0x00, 0x02, // extension length
        0x01, 0x42, // selected_identity
    ];

    let expect = ExtensionPreSharedKey {
        selected_identity: 0x142,
        ..ExtensionPreSharedKey::default()
    };

    let extension = unmarshal(&raw)?;
    assert_eq!(extension.selected_identity, expect.selected_identity);

    assert_eq!(marshal(&expect)?, raw);
    Ok(())
}

/// pion's `TestPreSharedKey_ClientHello`.
#[test]
fn pre_shared_key_client_hello() -> Result<()> {
    let binder_bytes = binder();

    let mut raw = vec![
        0x00, 0x29, // extension type
        0x00, 0x2d, // extension length
        0x00, 0x08, // identities length
        0x00, 0x02, // identity length
        0x42, 0x42, // identity
        0xff, 0xff, // ticket_age
        0xff, 0xff, // ticket_age
        0x00, 0x21, // binders length
        0x20, // binder entry length
    ];
    raw.extend_from_slice(&binder_bytes);

    let expect = ExtensionPreSharedKey {
        identities: vec![PskIdentity {
            identity: vec![0x42, 0x42],
            obfuscated_ticket_age: 0xffff_ffff,
        }],
        binders: vec![binder_bytes],
        ..ExtensionPreSharedKey::default()
    };

    let extension = unmarshal(&raw)?;
    assert_eq!(extension.selected_identity, 0);
    assert_eq!(extension.identities.len(), 1);
    assert_eq!(extension.identities[0], expect.identities[0]);
    assert_eq!(extension.binders.len(), 1);
    assert_eq!(extension.binders[0], expect.binders[0]);

    assert_eq!(marshal(&expect)?, raw);
    Ok(())
}

/// pion's `TestPreSharedKey_ClientHello_EmptyIdentities`.
#[test]
fn pre_shared_key_client_hello_empty_identities() -> Result<()> {
    let binder_bytes = binder();

    let mut raw = vec![
        0x00, 0x29, // extension type
        0x00, 0x2b, // extension length
        0x00, 0x06, // identities length
        0x00, 0x00, // identity length
        0xff, 0xff, // ticket_age
        0xff, 0xff, // ticket_age
        0x00, 0x21, // binders length
        0x20, // binder entry length
    ];
    raw.extend_from_slice(&binder_bytes);

    assert_eq!(unmarshal(&raw).unwrap_err(), Error::ErrPreSharedKeyFormat);
    Ok(())
}

/// pion's `TestPreSharedKey_ClientHello_MultipleIdentities`.
#[test]
fn pre_shared_key_client_hello_multiple_identities() -> Result<()> {
    let binder_bytes = binder();

    let mut raw = vec![
        0x00, 0x29, // extension type
        0x00, 0x56, // extension length
        0x00, 0x10, // identities length
        0x00, 0x02, // identity length
        0x41, 0x41, // identity
        0xaa, 0xaa, // ticket_age
        0xaa, 0xaa, // ticket_age
        0x00, 0x02, // identity length
        0x42, 0x42, // identity
        0xff, 0xff, // ticket_age
        0xff, 0xff, // ticket_age
        0x00, 0x42, // binders length
        0x20, // binder entry length
    ];
    raw.extend_from_slice(&binder_bytes);
    raw.push(0x20);
    raw.extend_from_slice(&binder_bytes);

    let expect = ExtensionPreSharedKey {
        identities: vec![
            PskIdentity {
                identity: vec![0x41, 0x41],
                obfuscated_ticket_age: 0xaaaa_aaaa,
            },
            PskIdentity {
                identity: vec![0x42, 0x42],
                obfuscated_ticket_age: 0xffff_ffff,
            },
        ],
        binders: vec![binder(), binder()],
        ..ExtensionPreSharedKey::default()
    };

    let extension = unmarshal(&raw)?;
    assert_eq!(extension.selected_identity, 0);
    assert_eq!(extension.identities.len(), 2);
    assert_eq!(extension.identities[0], expect.identities[0]);
    assert_eq!(extension.identities[1], expect.identities[1]);
    assert_eq!(extension.binders.len(), 2);
    assert_eq!(extension.binders[0], expect.binders[0]);
    assert_eq!(extension.binders[1], expect.binders[1]);

    assert_eq!(marshal(&expect)?, raw);
    Ok(())
}

/// pion's `TestPreSharedKey_ClientHello_MultipleIdentities_SingleBinder`.
#[test]
fn pre_shared_key_client_hello_multiple_identities_single_binder() -> Result<()> {
    let binder_bytes = binder();

    let mut raw = vec![
        0x00, 0x29, // extension type
        0x00, 0x0a, // extension length
        0x00, 0x10, // identities length
        0x00, 0x02, // identity length
        0x41, 0x41, // identity
        0xaa, 0xaa, // ticket_age
        0xaa, 0xaa, // ticket_age
        0x00, 0x02, // identity length
        0x42, 0x42, // identity
        0xff, 0xff, // ticket_age
        0xff, 0xff, // ticket_age
        0x00, 0x42, // binders length
        0x20, // binder entry length
    ];
    raw.extend_from_slice(&binder_bytes);

    assert_eq!(unmarshal(&raw).unwrap_err(), Error::ErrPreSharedKeyFormat);
    Ok(())
}

/// pion's `TestPreSharedKey_ClientHello_LowBinders`.
#[test]
fn pre_shared_key_client_hello_low_binders() -> Result<()> {
    let binder_bytes: Vec<u8> = (0..16u8).collect();
    let mut raw = vec![
        0x00, 0x29, // extension type
        0x00, 0x0a, // extension length
        0x00, 0x06, // identities length
        0x00, 0x02, // identity length
        0x42, 0x42, // identity
        0xff, 0xff, // ticket_age
        0xff, 0xff, // ticket_age
        0x00, 0x11, // binders length
        0x10, // binder entry length
    ];
    raw.extend_from_slice(&binder_bytes);

    assert_eq!(unmarshal(&raw).unwrap_err(), Error::ErrPreSharedKeyFormat);
    Ok(())
}
