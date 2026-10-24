//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/psk_key_exchange_modes_test.go`.
//!
//! pion's concrete `PskKeyExchangeModes.Unmarshal` receives the extension with its type code and
//! validates it; here the generic [`Extension::unmarshal`] path plays that role, so the fixtures
//! are the byte-for-byte pion ones.

use super::*;

use std::io::{BufReader, BufWriter};

fn marshal(ext: &ExtensionPskKeyExchangeModes) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::PskKeyExchangeModes(ext.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionPskKeyExchangeModes> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::PskKeyExchangeModes(ext) => Ok(ext),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestPskKeyExchangeModes`.
#[test]
fn psk_key_exchange_modes() -> Result<()> {
    let raw = [
        0x00, 0x2d, // extension type
        0x00, 0x02, // extension length
        0x01, // modes length
        0x00, // mode
    ];

    let expect = ExtensionPskKeyExchangeModes {
        ke_modes: vec![PskKeyExchangeMode::PSK_KE],
    };

    let extension = unmarshal(&raw)?;
    assert_eq!(extension.ke_modes.len(), 1);
    assert_eq!(extension.ke_modes[0], expect.ke_modes[0]);

    assert_eq!(marshal(&expect)?, raw);
    Ok(())
}

/// pion's `TestPskKeyExchangeModes_Empty`.
#[test]
fn psk_key_exchange_modes_empty() -> Result<()> {
    let raw = [
        0x00, 0x2d, // extension type
        0x00, 0x01, // extension length
        0x00, // modes length
    ];

    assert_eq!(
        unmarshal(&raw).unwrap_err(),
        Error::ErrPskKeyExchangeModesFormat
    );
    Ok(())
}
