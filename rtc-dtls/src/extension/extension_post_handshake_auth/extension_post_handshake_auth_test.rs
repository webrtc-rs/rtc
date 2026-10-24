//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/post_handshake_auth_test.go`.

use super::*;

use std::io::{BufReader, BufWriter};

fn marshal(ext: &ExtensionPostHandshakeAuth) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::PostHandshakeAuth(ext.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionPostHandshakeAuth> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::PostHandshakeAuth(ext) => Ok(ext),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestPostHandshakeAuth`.
#[test]
fn post_handshake_auth() -> Result<()> {
    let extension = ExtensionPostHandshakeAuth { enabled: true };

    let raw = marshal(&extension)?;

    let expect = [
        0x00, 0x31, // extension type
        0x00, 0x00, // extension length
    ];
    assert_eq!(raw, expect);

    let new_extension = unmarshal(&expect)?;
    assert_eq!(new_extension.enabled, extension.enabled);

    // pion's `PostHandshakeAuth{Enabled: false}.Marshal()` emits nothing at all, and the
    // extension is omitted from the message; the enum mirrors that.
    let disabled = ExtensionPostHandshakeAuth { enabled: false };
    assert!(marshal(&disabled)?.is_empty());
    assert_eq!(Extension::PostHandshakeAuth(disabled.clone()).size(), 0);
    Ok(())
}

/// pion's `TestPostHandshakeAuth_NonEmpty`.
#[test]
fn post_handshake_auth_non_empty() -> Result<()> {
    let raw = [
        0x00, 0x31, // extension type
        0x00, 0x42, // extension length
    ];
    assert_eq!(unmarshal(&raw).unwrap_err(), Error::ErrLengthMismatch);
    Ok(())
}
