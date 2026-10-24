use super::*;

use std::io::{BufReader, BufWriter};

#[test]
fn test_extension_use_extended_master_secret() -> Result<()> {
    let raw_extension_use_extended_master_secret = vec![0x00, 0x00];
    let parsed_extension_use_extended_master_secret =
        ExtensionUseExtendedMasterSecret { supported: true };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        parsed_extension_use_extended_master_secret.marshal(&mut writer)?;
    }

    assert_eq!(
        raw, raw_extension_use_extended_master_secret,
        "extension_use_extended_master_secret marshal: got {raw:?}, want {raw_extension_use_extended_master_secret:?}"
    );

    let mut reader = BufReader::new(raw.as_slice());
    let new_extension_use_extended_master_secret =
        ExtensionUseExtendedMasterSecret::unmarshal(&mut reader)?;

    assert_eq!(
        new_extension_use_extended_master_secret, parsed_extension_use_extended_master_secret,
        "extension_use_extended_master_secret unmarshal: got {new_extension_use_extended_master_secret:?}, want {parsed_extension_use_extended_master_secret:?}"
    );

    Ok(())
}

// Port of pion `TestUseMasterSecret` (pion spells the type `UseMasterSecret`): the extension
// marshals to exactly its type and a zero length, and unmarshals back as supported. Unlike the
// body-level test above this goes through the full `Extension` framing, so the two type bytes
// are included, as in pion's raw bytes.
#[test]
fn test_use_master_secret() -> Result<()> {
    let extension = Extension::UseExtendedMasterSecret(ExtensionUseExtendedMasterSecret {
        supported: true,
    });

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        extension.marshal(&mut writer)?;
    }

    let expected = vec![
        0x00, 0x17, // extension type
        0x00, 0x00, // extension length
    ];
    assert_eq!(raw, expected);

    let mut reader = BufReader::new(raw.as_slice());
    let Extension::UseExtendedMasterSecret(new_extension) = Extension::unmarshal(&mut reader)?
    else {
        panic!("expected a use_extended_master_secret extension");
    };
    assert!(new_extension.supported);

    Ok(())
}

// Port of pion `TestUseMasterSecret_NonEmpty`: an extension that announces a non-empty body is
// rejected, since the format defines none.
#[test]
fn test_use_master_secret_non_empty() {
    let raw = vec![
        0x00, 0x17, // extension type
        0x00, 0x42, // extension length
    ];

    let mut reader = BufReader::new(raw.as_slice());
    assert!(matches!(
        Extension::unmarshal(&mut reader),
        Err(Error::ErrLengthMismatch)
    ));
}
