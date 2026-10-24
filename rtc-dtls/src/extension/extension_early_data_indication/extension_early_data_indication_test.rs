//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/early_data_indication_test.go`.

use super::*;

use std::io::{BufReader, BufWriter};

fn marshal(ext: &ExtensionEarlyDataIndication) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::EarlyDataIndication(ext.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionEarlyDataIndication> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::EarlyDataIndication(ext) => Ok(ext),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestEarlyDataIndication_NewSessionTicket`.
#[test]
fn early_data_indication_new_session_ticket() -> Result<()> {
    let extension = ExtensionEarlyDataIndication {
        max_early_data: Some(128),
    };

    let raw = marshal(&extension)?;

    let expect = [
        0x00, 0x2a, // extension type
        0x00, 0x04, // extension length
        0x00, 0x00, // MaxEarlyData
        0x00, 0x80, // MaxEarlyData
    ];
    assert_eq!(raw, expect);

    let new_extension = unmarshal(&expect)?;
    assert_eq!(new_extension.max_early_data, extension.max_early_data);
    Ok(())
}

/// pion's `TestEarlyDataIndication_CHEE`: ClientHello and EncryptedExtensions carry the
/// extension empty.
#[test]
fn early_data_indication_chee() -> Result<()> {
    let extension = ExtensionEarlyDataIndication::default();

    let raw = marshal(&extension)?;

    let expect = [
        0x00, 0x2a, // extension type
        0x00, 0x00, // extension length
    ];
    assert_eq!(raw, expect);

    let new_extension = unmarshal(&expect)?;
    assert!(new_extension.max_early_data.is_none());
    Ok(())
}
