//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/cookie_test.go`.

use super::*;

use std::io::{BufReader, BufWriter};

/// pion's `TestCookieExt`.
#[test]
fn cookie_ext() -> Result<()> {
    let extension = ExtensionCookie {
        cookie: vec![0x01, 0x42],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::Cookie(extension.clone()).marshal(&mut writer)?;
    }

    let expect = [
        0x00, 0x2c, // extension type
        0x00, 0x04, // extension length
        0x00, 0x02, // vec length
        0x01, 0x42, // cookie
    ];
    assert_eq!(raw, expect);

    let new_extension = match Extension::unmarshal(&mut BufReader::new(&expect[..]))? {
        Extension::Cookie(new_extension) => new_extension,
        _ => return Err(Error::ErrInvalidExtensionType),
    };
    assert_eq!(new_extension.cookie, extension.cookie);
    Ok(())
}
