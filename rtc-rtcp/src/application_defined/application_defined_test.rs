use super::*;

#[test]
fn test_application_defined_round_trip() {
    for (data, size) in [
        (&b""[..], 12),
        (&b"abc"[..], 16),
        (&b"abcd"[..], 16),
        (&b"abcde"[..], 20),
    ] {
        let app = ApplicationDefined {
            sub_type: 3,
            ssrc: 0x4baae1ab,
            name: *b"NAME",
            data: Bytes::copy_from_slice(data),
        };
        let raw = app.marshal().unwrap();
        assert_eq!(raw.len(), size);
        assert_eq!(raw[1], 204);
        assert_eq!(raw[0] & 0x1f, 3);
        let mut buf = raw.freeze();
        assert_eq!(ApplicationDefined::unmarshal(&mut buf).unwrap(), app);
    }
}

#[test]
fn test_application_defined_padding_bit() {
    let app = ApplicationDefined {
        data: Bytes::from_static(b"abc"),
        ..Default::default()
    };
    let raw = app.marshal().unwrap();
    assert_eq!(
        raw[0] & 0x20,
        0x20,
        "P bit is set when the data needed padding"
    );
    assert_eq!(raw[raw.len() - 1], 1, "pad byte carries the padding count");
}

#[test]
fn test_application_defined_errors() {
    let short = Bytes::from_static(&[0x80, 0xcc, 0x00, 0x01, 0, 0, 0, 1]);
    assert_eq!(
        ApplicationDefined::unmarshal(&mut short.clone()),
        Err(Error::PacketTooShort)
    );
    // length field says 16 bytes, 12 provided
    let bad_len = Bytes::from_static(&[0x80, 0xcc, 0x00, 0x03, 0, 0, 0, 1, b'N', b'A', b'M', b'E']);
    assert_eq!(
        ApplicationDefined::unmarshal(&mut bad_len.clone()),
        Err(Error::AppDefinedInvalidLength)
    );
    // padding count larger than the data region
    let bad_pad = Bytes::from_static(&[
        0xa0, 0xcc, 0x00, 0x03, 0, 0, 0, 1, b'N', b'A', b'M', b'E', 0, 0, 0, 9,
    ]);
    assert_eq!(
        ApplicationDefined::unmarshal(&mut bad_pad.clone()),
        Err(Error::WrongPadding)
    );
}
