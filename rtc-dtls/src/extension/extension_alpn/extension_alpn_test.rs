//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/alpn_test.go`.

use super::*;

use std::io::{BufReader, BufWriter};

fn protocols(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn marshal(ext: &ExtensionAlpn) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        ext.marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionAlpn> {
    ExtensionAlpn::unmarshal(&mut BufReader::new(raw))
}

/// pion's `TestALPN`.
#[test]
fn test_extension_alpn_round_trip() -> Result<()> {
    let ext = ExtensionAlpn {
        protocols: protocols(&["http/1.1", "spdy/1", "spdy/2", "spdy/3"]),
    };
    let raw = marshal(&ext)?;
    assert_eq!(raw.len(), ext.size(), "size() is the encoded length");
    assert_eq!(unmarshal(&raw)?, ext);
    Ok(())
}

#[test]
fn test_extension_alpn_wire_format() -> Result<()> {
    // extension length 4, list length 2, one protocol "A"
    let raw = [0x00, 0x04, 0x00, 0x02, 0x01, 0x41];
    let ext = unmarshal(&raw)?;
    assert_eq!(ext.protocols, protocols(&["A"]));
    assert_eq!(marshal(&ext)?, raw);
    Ok(())
}

/// pion's `TestALPNProtocolSelection`.
#[test]
fn test_alpn_protocol_selection() {
    let local = protocols(&["http/1.1", "spd/1"]);
    assert_eq!(
        alpn_protocol_selection(&local, &protocols(&["spd/1"])).unwrap(),
        Some("spd/1")
    );

    let http = protocols(&["http/1.1"]);
    assert!(matches!(
        alpn_protocol_selection(&http, &protocols(&["spd/1"])),
        Err(Error::ErrAlpnNoAppProto)
    ));

    assert_eq!(alpn_protocol_selection(&local, &[]).unwrap(), None);
    assert_eq!(
        alpn_protocol_selection(&[], &protocols(&["spd/1"])).unwrap(),
        None
    );

    // The local order decides, not the peer's.
    let ours = protocols(&["ssh/2", "http/3", "spd/1"]);
    assert_eq!(
        alpn_protocol_selection(&ours, &protocols(&["http/1.1", "spd/1", "http/3"])).unwrap(),
        Some("http/3")
    );
}

/// The seeds of pion's `FuzzALPNUnmarshal`, and the other malformed shapes: nothing panics and
/// anything accepted has at least one non-empty name.
#[test]
fn test_extension_alpn_malformed() {
    let cases: &[&[u8]] = &[
        // empty protocol name
        &[0x00, 0x04, 0x00, 0x02, 0x00, 0x00],
        // list length 0
        &[0x00, 0x02, 0x00, 0x00],
        // name longer than the list
        &[0x00, 0x04, 0x00, 0x02, 0x05, 0x41],
        // extension length disagrees with the list length
        &[
            0x00, 0x06, 0x00, 0x0a, 0x01, 0x41, 0x01, 0x42, 0x42, 0x42, 0x42, 0x42,
        ],
        // truncated
        &[0x00, 0x04, 0x00],
        &[],
        // not UTF-8
        &[0x00, 0x04, 0x00, 0x02, 0x01, 0xff],
    ];
    for raw in cases {
        assert!(unmarshal(raw).is_err(), "{raw:02x?} must be rejected");
    }
}

#[test]
fn test_extension_alpn_marshal_rejects_unsendable_names() {
    for bad in [protocols(&[""]), vec!["x".repeat(256)]] {
        assert!(matches!(
            marshal(&ExtensionAlpn { protocols: bad }),
            Err(Error::ErrAlpnInvalidFormat)
        ));
    }
}
