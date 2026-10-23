use super::*;

use std::io::{BufReader, BufWriter};

#[test]
fn test_handshake_message_client_key_exchange() -> Result<()> {
    let raw_client_key_exchange = vec![
        0x20, 0x26, 0x78, 0x4a, 0x78, 0x70, 0xc1, 0xf9, 0x71, 0xea, 0x50, 0x4a, 0xb5, 0xbb, 0x00,
        0x76, 0x02, 0x05, 0xda, 0xf7, 0xd0, 0x3f, 0xe3, 0xf7, 0x4e, 0x8a, 0x14, 0x6f, 0xb7, 0xe0,
        0xc0, 0xff, 0x54,
    ];
    let parsed_client_key_exchange = HandshakeMessageClientKeyExchange {
        identity_hint: vec![],
        public_key: raw_client_key_exchange[1..].to_vec(),
    };

    let mut reader = BufReader::new(raw_client_key_exchange.as_slice());
    let c = HandshakeMessageClientKeyExchange::unmarshal(&mut reader)?;
    assert_eq!(
        c, parsed_client_key_exchange,
        "parsedCertificateRequest unmarshal: got {c:?}, want {parsed_client_key_exchange:?}"
    );

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        c.marshal(&mut writer)?;
    }
    assert_eq!(
        raw, raw_client_key_exchange,
        "handshakeMessageClientKeyExchange marshal: got {raw:?}, want {raw_client_key_exchange:?}"
    );

    Ok(())
}

/// A PSK client may carry an empty identity (pion `TestPSK`, "Client identity empty"): the
/// marshaled message is just the two zero length bytes, and it unmarshals back.
#[test]
fn test_handshake_message_client_key_exchange_empty_psk_identity() -> Result<()> {
    let empty_identity = HandshakeMessageClientKeyExchange {
        identity_hint: vec![],
        public_key: vec![],
    };

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        empty_identity.marshal(&mut writer)?;
    }
    assert_eq!(raw, vec![0x00, 0x00], "an empty identity is a zero length");

    let mut reader = BufReader::new(raw.as_slice());
    let parsed = HandshakeMessageClientKeyExchange::unmarshal(&mut reader)?;
    assert_eq!(parsed, empty_identity);

    Ok(())
}

/// A message carrying both an identity and a public key is not one this crate can produce, and
/// marshaling it stays an error.
#[test]
fn test_handshake_message_client_key_exchange_rejects_both_fields() -> Result<()> {
    let both = HandshakeMessageClientKeyExchange {
        identity_hint: vec![0x00, 0x01],
        public_key: vec![0x02; 32],
    };

    let mut raw = vec![];
    let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
    assert!(both.marshal(&mut writer).is_err());

    Ok(())
}
