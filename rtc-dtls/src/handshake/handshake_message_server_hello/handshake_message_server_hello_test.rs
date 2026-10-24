use super::*;

use std::io::{BufReader, BufWriter};
use std::time::{Duration, SystemTime};

#[test]
fn test_handshake_message_server_hello() -> Result<()> {
    let raw_server_hello = vec![
        0xfe, 0xfd, 0x21, 0x63, 0x32, 0x21, 0x81, 0x0e, 0x98, 0x6c, 0x85, 0x3d, 0xa4, 0x39, 0xaf,
        0x5f, 0xd6, 0x5c, 0xcc, 0x20, 0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e,
        0xcf, 0x63, 0x84, 0x28, 0x00, 0xc0, 0x2b, 0x00, 0x00, 0x00,
    ];

    let gmt_unix_time = if let Some(unix_time) =
        SystemTime::UNIX_EPOCH.checked_add(Duration::new(560149025u64, 0))
    {
        unix_time
    } else {
        SystemTime::UNIX_EPOCH
    };
    let parsed_server_hello = HandshakeMessageServerHello {
        version: ProtocolVersion {
            major: 0xFE,
            minor: 0xFD,
        },
        random: HandshakeRandom {
            gmt_unix_time,
            random_bytes: [
                0x81, 0x0e, 0x98, 0x6c, 0x85, 0x3d, 0xa4, 0x39, 0xaf, 0x5f, 0xd6, 0x5c, 0xcc, 0x20,
                0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e, 0xcf, 0x63, 0x84, 0x28,
            ],
        },
        session_id: vec![],
        cipher_suite: CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        compression_method: CompressionMethodId::Null,
        extensions: vec![],
    };

    let mut reader = BufReader::new(raw_server_hello.as_slice());
    let c = HandshakeMessageServerHello::unmarshal(&mut reader)?;
    assert_eq!(
        c, parsed_server_hello,
        "handshakeMessageServerHello unmarshal: got {c:?}, want {parsed_server_hello:?}"
    );

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        c.marshal(&mut writer)?;
    }
    assert_eq!(
        raw, raw_server_hello,
        "handshakeMessageServerHello marshal: got {raw:?}, want {raw_server_hello:?}"
    );

    Ok(())
}

// Port of pion `TestHandshakeMessageServerHelloSessionID`: a hello carrying a 32-byte session
// ID parses it back out and re-marshals byte for byte.
#[test]
fn test_handshake_message_server_hello_session_id() -> Result<()> {
    let raw_server_hello = vec![
        0xfe, 0xfd, 0x21, 0x63, 0x32, 0x21, 0x81, 0x0e, 0x98, 0x6c, 0x85, 0x3d, 0xa4, 0x39, 0xaf,
        0x5f, 0xd6, 0x5c, 0xcc, 0x20, 0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e,
        0xcf, 0x63, 0x84, 0x28, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
        0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
        0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xc0, 0x2b, 0x00, 0x00, 0x00,
    ];

    let session_id = vec![
        0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee,
        0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
        0xfe, 0xff,
    ];

    let mut reader = BufReader::new(raw_server_hello.as_slice());
    let c = HandshakeMessageServerHello::unmarshal(&mut reader)?;
    assert_eq!(
        c.session_id, session_id,
        "handshakeMessageServerHello invalid SessionID"
    );

    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        c.marshal(&mut writer)?;
    }
    assert_eq!(
        raw, raw_server_hello,
        "handshakeMessageServerHello marshal: got {raw:?}, want {raw_server_hello:?}"
    );

    Ok(())
}

// Port of pion `TestHandshakeMessageServerHello_SessionIDTooLong`: the session ID is prefixed
// with a one-byte length, so more than 255 bytes cannot be marshaled.
#[test]
fn test_handshake_message_server_hello_session_id_too_long() {
    let c = HandshakeMessageServerHello {
        version: ProtocolVersion {
            major: 0xFE,
            minor: 0xFD,
        },
        random: HandshakeRandom {
            gmt_unix_time: SystemTime::UNIX_EPOCH,
            random_bytes: [0; 28],
        },
        session_id: vec![0; 256],
        cipher_suite: CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
        compression_method: CompressionMethodId::Null,
        extensions: vec![],
    };

    let mut raw = vec![];
    let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
    assert!(matches!(
        c.marshal(&mut writer),
        Err(Error::ErrSessionIdTooLong)
    ));
}
