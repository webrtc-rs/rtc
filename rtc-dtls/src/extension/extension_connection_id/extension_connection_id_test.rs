//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/connection_id_test.go`.

use super::*;

use std::io::{BufReader, BufWriter};

/// pion's `TestExtensionConnectionID`.
#[test]
fn test_extension_connection_id() -> Result<()> {
    let raw_extension_connection_id: [u8; 8] = [1, 6, 8, 3, 88, 12, 2, 47];
    let parsed_extension_connection_id = ExtensionConnectionId {
        cid: raw_extension_connection_id.to_vec(),
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::ConnectionId(parsed_extension_connection_id.clone()).marshal(&mut writer)?;
    }

    let roundtrip = match Extension::unmarshal(&mut BufReader::new(raw.as_slice()))? {
        Extension::ConnectionId(roundtrip) => roundtrip,
        _ => return Err(Error::ErrInvalidExtensionType),
    };
    assert_eq!(roundtrip, parsed_extension_connection_id);
    Ok(())
}
