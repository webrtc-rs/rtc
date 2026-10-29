// Silence warning on `..Default::default()` with no effect:
#![allow(clippy::needless_update)]

use super::*;
use bytes::{Bytes, BytesMut};
use shared::error::Result;

#[test]
fn test_basic() -> Result<()> {
    let mut empty_bytes = &vec![0u8; 0][..];
    let result = Packet::unmarshal(&mut empty_bytes);
    assert!(
        result.is_err(),
        "Unmarshal did not error on zero length packet"
    );

    let raw_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x00, 0x01, 0x00,
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]);
    let parsed_packet = Packet {
        header: Header {
            version: 2,
            padding: false,
            extension: true,
            marker: true,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: vec![],
            extension_profile: 1,
            extensions: vec![Extension {
                id: 0,
                payload: Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]),
            }],
            ..Default::default()
        },
        payload: Bytes::from_static(&[0x98, 0x36, 0xbe, 0x88, 0x9e]),
    };
    let buf = &mut raw_pkt.clone();
    let packet = Packet::unmarshal(buf)?;
    assert_eq!(
        packet, parsed_packet,
        "TestBasic unmarshal: got {packet}, want {parsed_packet}"
    );
    assert_eq!(
        packet.header.marshal_size(),
        20,
        "wrong computed header marshal size"
    );
    assert_eq!(
        packet.marshal_size(),
        raw_pkt.len(),
        "wrong computed marshal size"
    );

    let raw = packet.marshal()?;
    let n = raw.len();
    assert_eq!(n, raw_pkt.len(), "wrong marshal size");

    assert_eq!(
        raw.len(),
        raw_pkt.len(),
        "wrong raw marshal size {} vs {}",
        raw.len(),
        raw_pkt.len()
    );
    assert_eq!(
        raw, raw_pkt,
        "TestBasic marshal: got {raw:?}, want {raw_pkt:?}"
    );

    Ok(())
}

#[test]
fn test_extension() -> Result<()> {
    let mut missing_extension_pkt = Bytes::from_static(&[
        0x90, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82,
    ]);
    let buf = &mut missing_extension_pkt;
    let result = Packet::unmarshal(buf);
    assert!(
        result.is_err(),
        "Unmarshal did not error on packet with missing extension data"
    );

    let mut invalid_extension_length_pkt = Bytes::from_static(&[
        0x90, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x99, 0x99, 0x99,
        0x99,
    ]);
    let buf = &mut invalid_extension_length_pkt;
    let result = Packet::unmarshal(buf);
    assert!(
        result.is_err(),
        "Unmarshal did not error on packet with invalid extension length"
    );

    let packet = Packet {
        header: Header {
            extension: true,
            extension_profile: 3,
            extensions: vec![Extension {
                id: 0,
                payload: Bytes::from_static(&[0]),
            }],
            ..Default::default()
        },
        payload: Bytes::from_static(&[]),
    };

    let mut raw = BytesMut::new();
    let result = packet.marshal_to(&mut raw);
    assert!(
        result.is_err(),
        "Marshal did not error on packet with invalid extension length"
    );
    if let Err(err) = result {
        assert_eq!(Error::ErrBufferTooSmall, err);
    }

    Ok(())
}

#[test]
fn test_padding() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0xa0, 0x60, 0x19, 0x58, 0x63, 0xff, 0x7d, 0x7c, 0x4b, 0x98, 0xd4, 0x0a, 0x67, 0x4d, 0x00,
        0x29, 0x9a, 0x64, 0x03, 0xc0, 0x11, 0x3f, 0x2c, 0xd4, 0x04, 0x04, 0x05, 0x00, 0x00, 0x03,
        0x03, 0xe8, 0x00, 0x00, 0xea, 0x60, 0x04, 0x00, 0x00, 0x03,
    ]);
    let buf = &mut raw_pkt.clone();
    let packet = Packet::unmarshal(buf)?;
    assert_eq!(&packet.payload[..], &raw_pkt[12..12 + 25]);

    let raw = packet.marshal()?;
    assert_eq!(raw, raw_pkt);

    Ok(())
}

#[test]
fn test_packet_marshal_unmarshal() -> Result<()> {
    let pkt = Packet {
        header: Header {
            extension: true,
            csrc: vec![1, 2],
            extension_profile: EXTENSION_PROFILE_TWO_BYTE,
            extensions: vec![
                Extension {
                    id: 1,
                    payload: Bytes::from_static(&[3, 4]),
                },
                Extension {
                    id: 2,
                    payload: Bytes::from_static(&[5, 6]),
                },
            ],
            ..Default::default()
        },
        payload: Bytes::from_static(&[0xFFu8; 15]),
        ..Default::default()
    };
    let mut raw = pkt.marshal()?;
    let p = Packet::unmarshal(&mut raw)?;

    assert_eq!(pkt, p);

    Ok(())
}

#[test]
fn test_rfc_8285_one_byte_extension() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xBE, 0xDE, 0x00,
        0x01, 0x50, 0xAA, 0x00, 0x00, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]);
    let buf = &mut raw_pkt.clone();
    Packet::unmarshal(buf)?;

    let p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![Extension {
                id: 5,
                payload: Bytes::from_static(&[0xAA]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: vec![],
            ..Default::default()
        },
        payload: raw_pkt.slice(20..),
    };

    let dst = p.marshal()?;
    assert_eq!(dst, raw_pkt);

    Ok(())
}

#[test]
fn test_rfc_8285_one_byte_two_extension_of_two_bytes() -> Result<()> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       0xBE    |    0xDE       |           length=1            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  ID   | L=0   |     data      |  ID   |  L=0  |   data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    let raw_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xBE, 0xDE, 0x00,
        0x01, 0x10, 0xAA, 0x20, 0xBB, // Payload
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]);
    let buf = &mut raw_pkt.clone();
    let p = Packet::unmarshal(buf)?;

    let ext1 = p.header.get_extension(1);
    let ext1_expect = Bytes::from_static(&[0xAA]);
    if let Some(ext1) = ext1 {
        assert_eq!(ext1, ext1_expect);
    } else {
        panic!("ext1 is none");
    }

    let ext2 = p.header.get_extension(2);
    let ext2_expect = Bytes::from_static(&[0xBB]);
    if let Some(ext2) = ext2 {
        assert_eq!(ext2, ext2_expect);
    } else {
        panic!("ext2 is none");
    }

    // Test Marshal
    let p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![
                Extension {
                    id: 1,
                    payload: Bytes::from_static(&[0xAA]),
                },
                Extension {
                    id: 2,
                    payload: Bytes::from_static(&[0xBB]),
                },
            ],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            csrc: vec![],
            ..Default::default()
        },
        payload: raw_pkt.slice(20..),
    };

    let dst = p.marshal()?;
    assert_eq!(dst, raw_pkt);

    Ok(())
}

#[test]
fn test_rfc_8285_one_byte_multiple_extensions_with_padding() -> Result<()> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       0xBE    |    0xDE       |           length=3            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  ID   | L=0   |     data      |  ID   |  L=1  |   data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //       ...data   |    0 (pad)    |    0 (pad)    |  ID   | L=3   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          data                                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let mut raw_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xBE, 0xDE, 0x00,
        0x03, 0x10, 0xAA, 0x21, 0xBB, 0xBB, 0x00, 0x00, 0x33, 0xCC, 0xCC, 0xCC, 0xCC,
        // Payload
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]);
    let buf = &mut raw_pkt;
    let packet = Packet::unmarshal(buf)?;
    let ext1 = packet
        .header
        .get_extension(1)
        .expect("Error getting header extension.");

    let ext1_expect = Bytes::from_static(&[0xAA]);
    assert_eq!(ext1, ext1_expect);

    let ext2 = packet
        .header
        .get_extension(2)
        .expect("Error getting header extension.");

    let ext2_expect = Bytes::from_static(&[0xBB, 0xBB]);
    assert_eq!(ext2, ext2_expect);

    let ext3 = packet
        .header
        .get_extension(3)
        .expect("Error getting header extension.");

    let ext3_expect = Bytes::from_static(&[0xCC, 0xCC, 0xCC, 0xCC]);
    assert_eq!(ext3, ext3_expect);

    let mut dst_buf: Vec<Vec<u8>> = vec![vec![0u8; 1000], vec![0xFF; 1000], vec![0xAA; 2]];

    let raw_pkg_marshal: [u8; 33] = [
        // padding is moved to the end by re-marshaling
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xBE, 0xDE, 0x00,
        0x03, 0x10, 0xAA, 0x21, 0xBB, 0xBB, 0x33, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00,
        // Payload
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    let checker = |name: &str, buf: &mut [u8], p: &Packet| -> Result<()> {
        let size = p.marshal_to(buf)?;

        assert_eq!(
            &buf[..size],
            &raw_pkg_marshal[..],
            "Marshalled fields are not equal for {name}."
        );

        Ok(())
    };

    checker("CleanBuffer", &mut dst_buf[0], &packet)?;
    checker("DirtyBuffer", &mut dst_buf[1], &packet)?;

    let result = packet.marshal_to(&mut dst_buf[2]);
    assert!(result.is_err());
    if let Err(err) = result {
        assert_eq!(Error::ErrBufferTooSmall, err);
    }

    Ok(())
}

#[test]
fn test_rfc_8285_one_byte_multiple_extension() -> Result<()> {
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       0xBE    |    0xDE       |           length=3            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |  ID=1 | L=0   |     data      |  ID=2 |  L=1  |   data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //       ...data   |  ID=3 | L=3   |           data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //             ...data             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    let raw_pkt = &[
        0x90u8, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xBE, 0xDE, 0x00,
        0x03, 0x10, 0xAA, 0x21, 0xBB, 0xBB, 0x33, 0xCC, 0xCC, 0xCC, 0xCC, 0x00, 0x00,
        // Payload
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];

    let p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![
                Extension {
                    id: 1,
                    payload: Bytes::from_static(&[0xAA]),
                },
                Extension {
                    id: 2,
                    payload: Bytes::from_static(&[0xBB, 0xBB]),
                },
                Extension {
                    id: 3,
                    payload: Bytes::from_static(&[0xCC, 0xCC, 0xCC, 0xCC]),
                },
            ],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload: raw_pkt[28..].into(),
    };

    let dst_data = p.marshal()?;
    assert_eq!(
        &dst_data[..],
        raw_pkt,
        "Marshal failed raw \nMarshaled:\n{dst_data:?}\nrawPkt:\n{raw_pkt:?}",
    );

    Ok(())
}

#[test]
fn test_rfc_8285_two_byte_extension() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x10, 0x00, 0x00,
        0x07, 0x05, 0x18, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x98,
        0x36, 0xbe, 0x88, 0x9e,
    ]);

    let _ = Packet::unmarshal(&mut raw_pkt.clone())?;

    let p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0x1000,
            extensions: vec![Extension {
                id: 5,
                payload: Bytes::from_static(&[
                    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                ]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload: raw_pkt.slice(44..),
    };

    let dst_data = p.marshal()?;
    assert_eq!(
        dst_data, raw_pkt,
        "Marshal failed raw \nMarshaled:\n{dst_data:?}\nrawPkt:\n{raw_pkt:?}"
    );
    Ok(())
}

#[test]
fn test_rfc8285_two_byte_multiple_extension_with_padding() -> Result<()> {
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       0x10    |    0x00       |           length=3            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      ID=1     |     L=0       |     ID=2      |     L=1       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       data    |    0 (pad)    |       ID=3    |      L=4      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                          data                                 |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let mut raw_pkt = Bytes::from_static(&[
        0x90u8, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x10, 0x00, 0x00,
        0x03, 0x01, 0x00, 0x02, 0x01, 0xBB, 0x00, 0x03, 0x04, 0xCC, 0xCC, 0xCC, 0xCC, 0x98, 0x36,
        0xbe, 0x88, 0x9e,
    ]);

    let p = Packet::unmarshal(&mut raw_pkt)?;

    let ext = p.header.get_extension(1);
    let ext_expect = Some(Bytes::from_static(&[]));
    assert_eq!(
        ext, ext_expect,
        "Extension has incorrect data. Got: {ext:?}, Expected: {ext_expect:?}"
    );

    let ext = p.header.get_extension(2);
    let ext_expect = Some(Bytes::from_static(&[0xBB]));
    assert_eq!(
        ext, ext_expect,
        "Extension has incorrect data. Got: {ext:?}, Expected: {ext_expect:?}"
    );

    let ext = p.header.get_extension(3);
    let ext_expect = Some(Bytes::from_static(&[0xCC, 0xCC, 0xCC, 0xCC]));
    assert_eq!(
        ext, ext_expect,
        "Extension has incorrect data. Got: {ext:?}, Expected: {ext_expect:?}"
    );

    Ok(())
}

#[test]
fn test_rfc8285_two_byte_multiple_extension_with_large_extension() -> Result<()> {
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       0x10    |    0x00       |           length=3            |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |      ID=1     |     L=0       |     ID=2      |     L=1       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       data    |       ID=3    |      L=17      |    data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //                            ...data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //                            ...data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //                            ...data...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //                            ...data...                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let raw_pkt = Bytes::from_static(&[
        0x90u8, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0x10, 0x00, 0x00,
        0x06, 0x01, 0x00, 0x02, 0x01, 0xBB, 0x03, 0x11, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // Payload
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]);

    let p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0x1000,
            extensions: vec![
                Extension {
                    id: 1,
                    payload: Bytes::from_static(&[]),
                },
                Extension {
                    id: 2,
                    payload: Bytes::from_static(&[0xBB]),
                },
                Extension {
                    id: 3,
                    payload: Bytes::from_static(&[
                        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                        0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
                    ]),
                },
            ],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload: raw_pkt.slice(40..),
    };

    let dst_data = p.marshal()?;
    assert_eq!(
        dst_data,
        raw_pkt[..],
        "Marshal failed raw \nMarshaled: {dst_data:?}, \nraw_pkt:{raw_pkt:?}"
    );

    Ok(())
}

#[test]
fn test_rfc8285_get_extension_returns_nil_when_extension_disabled() -> Result<()> {
    let payload = Bytes::from_static(&[
        // Payload
        0x98u8, 0x36, 0xbe, 0x88, 0x9e,
    ]);

    let p = Packet {
        header: Header {
            marker: true,
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let res = p.header.get_extension(1);
    assert!(
        res.is_none(),
        "Should return none on get_extension when header extension is false"
    );

    Ok(())
}

#[test]
fn test_rfc8285_del_extension() -> Result<()> {
    let payload = Bytes::from_static(&[
        // Payload
        0x98u8, 0x36, 0xbe, 0x88, 0x9e,
    ]);
    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAA]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let ext = p.header.get_extension(1);
    assert!(ext.is_some(), "Extension should exist");

    p.header.del_extension(1)?;

    let ext = p.header.get_extension(1);
    assert!(ext.is_none(), "Extension should not exist");

    let err = p.header.del_extension(1);
    assert!(
        err.is_err(),
        "Should return error when deleting extension that doesnt exist"
    );

    Ok(())
}

#[test]
fn test_rfc8285_get_extension_ids() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![
                Extension {
                    id: 1,
                    payload: Bytes::from_static(&[0xAA]),
                },
                Extension {
                    id: 2,
                    payload: Bytes::from_static(&[0xBB]),
                },
            ],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let ids = p.header.get_extension_ids();
    assert!(!ids.is_empty(), "Extenstions should exist");

    assert_eq!(
        ids.len(),
        p.header.extensions.len(),
        "The number of IDs should be equal to the number of extensions, want={}, hanve{}",
        ids.len(),
        p.header.extensions.len()
    );

    for id in ids {
        let ext = p.header.get_extension(id);
        assert!(ext.is_some(), "Extension should exist for id: {id}")
    }
}

#[test]
fn test_rfc8285_get_extension_ids_return_empty_when_extension_disabled() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let p = Packet {
        header: Header {
            marker: true,
            extension: false,
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let ids = p.header.get_extension_ids();
    assert!(ids.is_empty(), "Extenstions should not exist");
}

#[test]
fn test_rfc8285_del_extension_returns_error_when_extenstions_disabled() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: false,
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let ids = p.header.del_extension(1);
    assert!(
        ids.is_err(),
        "Should return error on del_extension when header extension field is false"
    );
}

#[test]
fn test_rfc8285_one_byte_set_extension_should_enable_extension_when_adding() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: false,
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let extension = Bytes::from_static(&[0xAAu8, 0xAA]);
    let result = p.header.set_extension(1, extension.clone());
    assert!(result.is_ok(), "Error setting extension");

    assert!(p.header.extension, "Extension should be set to true");
    assert_eq!(
        p.header.extension_profile, 0xBEDE,
        "Extension profile should be set to 0xBEDE"
    );
    assert_eq!(
        p.header.extensions.len(),
        1,
        "Extensions len should be set to 1"
    );
    assert_eq!(
        p.header.get_extension(1),
        Some(extension),
        "Extension value is not set"
    )
}

#[test]
fn test_rfc8285_set_extension_should_set_correct_extension_profile_for_16_byte_extension() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: false,
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let extension = Bytes::from_static(&[
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA,
    ]);

    let res = p.header.set_extension(1, extension);
    assert!(res.is_ok(), "Error setting extension");

    assert_eq!(
        p.header.extension_profile, 0xBEDE,
        "Extension profile should be 0xBEDE"
    );
}

#[test]
fn test_rfc8285_set_extension_should_update_existing_extension() -> Result<()> {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAA]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    assert_eq!(
        p.header.get_extension(1),
        Some([0xAA][..].into()),
        "Extension value not initialized properly"
    );

    let extension = Bytes::from_static(&[0xBBu8]);
    p.header.set_extension(1, extension.clone())?;

    assert_eq!(
        p.header.get_extension(1),
        Some(extension),
        "Extension value was not set"
    );

    Ok(())
}

#[test]
fn test_rfc8285_one_byte_set_extension_should_error_when_invalid_id_provided() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAA]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    assert!(
        p.header
            .set_extension(0, Bytes::from_static(&[0xBBu8]))
            .is_err(),
        "set_extension did not error on invalid id"
    );
    assert!(
        p.header
            .set_extension(15, Bytes::from_static(&[0xBBu8]))
            .is_err(),
        "set_extension did not error on invalid id"
    );
}

#[test]
fn test_rfc8285_one_byte_extension_terminate_processing_when_reserved_id_encountered() -> Result<()>
{
    let reserved_id_pkt = Bytes::from_static(&[
        0x90u8, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, 0x27, 0x82, 0xBE, 0xDE, 0x00,
        0x01, 0xF0, 0xAA, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ]);

    let p = Packet::unmarshal(&mut reserved_id_pkt.clone())?;

    assert_eq!(
        p.header.extensions.len(),
        0,
        "Extension should be empty for invalid ID"
    );

    // The payload starts after the whole extension block, however early parsing stopped.
    let payload = reserved_id_pkt.slice(20..);
    assert_eq!(p.payload, payload, "p.payload must be same as payload");

    Ok(())
}

#[test]
fn test_rfc8285_one_byte_set_extension_should_error_when_payload_too_large() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0xBEDE,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAAu8]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let res = p.header.set_extension(
        1,
        Bytes::from_static(&[
            0xBBu8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB,
        ]),
    );

    assert!(
        res.is_err(),
        "set_extension did not error on too large payload"
    );
}

#[test]
fn test_rfc8285_two_bytes_set_extension_should_enable_extension_when_adding() -> Result<()> {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: false,
            extension_profile: 0xBEDE,
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let extension = Bytes::from_static(&[
        0xAAu8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA,
    ]);

    p.header.set_extension(1, extension.clone())?;

    assert!(p.header.extension, "Extension should be set to true");
    assert_eq!(
        p.header.extension_profile, 0x1000,
        "Extension profile should be set to 0xBEDE"
    );
    assert_eq!(
        p.header.extensions.len(),
        1,
        "Extensions should be set to 1"
    );
    assert_eq!(
        p.header.get_extension(1),
        Some(extension),
        "Extension value is not set"
    );

    Ok(())
}

#[test]
fn test_rfc8285_two_byte_set_extension_should_update_existing_extension() -> Result<()> {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0x1000,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAA]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    assert_eq!(
        p.header.get_extension(1),
        Some(Bytes::from_static(&[0xAA])),
        "Extension value not initialized properly"
    );

    let extension = Bytes::from_static(&[
        0xBBu8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB,
    ]);

    p.header.set_extension(1, extension.clone())?;

    assert_eq!(p.header.get_extension(1), Some(extension));

    Ok(())
}

#[test]
fn test_rfc8285_two_byte_set_extension_should_error_when_payload_too_large() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0x1000,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAA]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let res = p.header.set_extension(
        1,
        Bytes::from_static(&[
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
            0xBB, 0xBB, 0xBB, 0xBB,
        ]),
    );

    assert!(
        res.is_err(),
        "Set extension did not error on too large payload"
    );
}

#[test]
fn test_rfc3550_set_extension_should_error_when_non_zero() -> Result<()> {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0x1111,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAA]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    p.header.set_extension(0, Bytes::from_static(&[0xBB]))?;
    let res = p.header.get_extension(0);
    assert_eq!(
        res,
        Some(Bytes::from_static(&[0xBB])),
        "p.get_extenstion returned incorrect value"
    );

    Ok(())
}

#[test]
fn test_rfc3550_set_extension_should_error_when_setting_non_zero_id() {
    let payload = Bytes::from_static(&[0x98u8, 0x36, 0xbe, 0x88, 0x9e]);

    let mut p = Packet {
        header: Header {
            marker: true,
            extension: true,
            extension_profile: 0x1111,
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            ..Default::default()
        },
        payload,
        ..Default::default()
    };

    let res = p.header.set_extension(1, Bytes::from_static(&[0xBB]));
    assert!(res.is_err(), "set_extension did not error on invalid id");
}

use std::collections::HashMap;

struct Cases {
    input: Bytes,
    err: Error,
}

#[test]
fn test_unmarshal_error_handling() {
    let mut cases = HashMap::new();

    cases.insert(
        "ShortHeader",
        Cases {
            input: Bytes::from_static(&[
                0x80, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, // timestamp
                0x1c, 0x64, 0x27, // SSRC (one byte missing)
            ]),
            err: Error::ErrHeaderSizeInsufficient,
        },
    );

    cases.insert(
        "MissingCSRC",
        Cases {
            input: Bytes::from_static(&[
                0x81, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, // timestamp
                0x1c, 0x64, 0x27, 0x82, // SSRC
            ]),
            err: Error::ErrHeaderSizeInsufficient,
        },
    );

    cases.insert(
        "MissingExtension",
        Cases {
            input: Bytes::from_static(&[
                0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, // timestamp
                0x1c, 0x64, 0x27, 0x82, // SSRC
            ]),
            err: Error::ErrHeaderSizeInsufficientForExtension,
        },
    );

    cases.insert(
        "MissingExtensionData",
        Cases {
            input: Bytes::from_static(&[
                0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, // timestamp
                0x1c, 0x64, 0x27, 0x82, // SSRC
                0xBE, 0xDE, 0x00, 0x03, // specified to have 3 extensions, but actually not
            ]),
            err: Error::ErrHeaderSizeInsufficientForExtension,
        },
    );

    cases.insert(
        "MissingExtensionDataPayload",
        Cases {
            input: Bytes::from_static(&[
                0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, // timestamp
                0x1c, 0x64, 0x27, 0x82, // SSRC
                0xBE, 0xDE, 0x00, 0x01, // have 1 extension
                0x12,
                0x00, // length of the payload is expected to be 3, but actually have only 1
            ]),
            err: Error::ErrHeaderSizeInsufficientForExtension,
        },
    );

    for (name, mut test_case) in cases.drain() {
        let result = Header::unmarshal(&mut test_case.input);
        let err = result.err().unwrap();
        assert_eq!(
            test_case.err, err,
            "Expected :{:?}, found: {:?} for testcase {}",
            test_case.err, err, name
        )
    }
}

#[test]
fn test_round_trip() -> Result<()> {
    let raw_pkt = Bytes::from_static(&[
        0x00u8, 0x10, 0x23, 0x45, 0x12, 0x34, 0x45, 0x67, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77,
    ]);

    let payload = raw_pkt.slice(12..);

    let p = Packet::unmarshal(&mut raw_pkt.clone())?;

    assert_eq!(
        payload, p.payload,
        "p.payload must be same as payload.\n p.payload: {:?},\nraw_pkt: {:?}",
        p.payload, payload
    );

    let buf = p.marshal()?;

    assert_eq!(
        raw_pkt, buf,
        "buf must be the same as raw_pkt. \n buf: {buf:?},\nraw_pkt: {raw_pkt:?}",
    );
    assert_eq!(
        payload, p.payload,
        "p.payload must be the same as payload. \n payload: {:?},\np.payload: {:?}",
        payload, p.payload,
    );

    Ok(())
}

#[test]
fn test_unmarshal_reuse_matches_unmarshal_and_keeps_allocations() {
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0x7e57);
    let mut reused = Packet::default();
    let mut capacity_seen = 0;
    for round in 0..5_000 {
        let mut header = Header {
            version: 2,
            marker: rng.random(),
            payload_type: rng.random_range(0..128),
            sequence_number: rng.random(),
            timestamp: rng.random(),
            ssrc: rng.random(),
            csrc: (0..rng.random_range(0..3)).map(|_| rng.random()).collect(),
            ..Default::default()
        };
        if rng.random_bool(0.6) {
            header.extension = true;
            header.extension_profile = EXTENSION_PROFILE_ONE_BYTE;
            for id in 1..=rng.random_range(1..4u8) {
                let _ = header.set_extension(id, Bytes::from(vec![id; rng.random_range(1..=4)]));
            }
        }
        let packet = Packet {
            header,
            payload: Bytes::from(
                (0..rng.random_range(0..40))
                    .map(|i| i as u8)
                    .collect::<Vec<_>>(),
            ),
        };
        let mut raw = packet.marshal().unwrap().to_vec();
        // Now and then corrupt it, so the error paths agree too.
        if rng.random_bool(0.2) && !raw.is_empty() {
            let i = rng.random_range(0..raw.len());
            raw[i] = rng.random();
        }
        let raw = Bytes::from(raw);

        let fresh = Packet::unmarshal(&mut raw.clone());
        let status = reused.unmarshal_reuse(&raw);
        match (fresh, status) {
            (Ok(expected), Ok(())) => {
                assert_eq!(reused, expected, "round {round}: {raw:02x?}");
                capacity_seen = capacity_seen.max(reused.header.extensions.capacity());
            }
            (Err(expected), Err(got)) => assert_eq!(got, expected, "round {round}: {raw:02x?}"),
            (a, b) => panic!("round {round}: unmarshal {a:?} but unmarshal_reuse {b:?}"),
        }
    }
    // The extension table was reused, not rebuilt: it only ever grows.
    assert!(reused.header.extensions.capacity() >= capacity_seen);
}

// pion TestRFC8285ClearExtensions.
#[test]
fn test_rfc_8285_clear_extensions() -> Result<()> {
    let mut header = Header {
        marker: true,
        extension: true,
        extension_profile: 0xBEDE,
        extensions: vec![
            Extension {
                id: 1,
                payload: Bytes::from_static(&[0xAA]),
            },
            Extension {
                id: 2,
                payload: Bytes::from_static(&[0xBB]),
            },
        ],
        version: 2,
        payload_type: 96,
        sequence_number: 27023,
        timestamp: 3653407706,
        ssrc: 476325762,
        ..Default::default()
    };

    assert!(header.get_extension(1).is_some());
    assert!(header.get_extension(2).is_some());
    header.clear_extensions();
    assert!(header.get_extension(1).is_none());
    assert!(header.get_extension(2).is_none());
    assert!(!header.extension, "the extension flag should be cleared");
    assert!(header.extensions.is_empty());
    assert_eq!(0, header.extension_profile, "the profile should be reset");
    Ok(())
}

// pion TestRFC8285OneByteExtensionTerminateProcessingWhenPaddingWithSizeEncountered:
// a one-byte element with id 0 and a non-zero length ends the extension block;
// the rest of the block is not an extension.
#[test]
fn test_rfc_8285_one_byte_extension_terminate_processing_when_padding_with_size_encountered()
-> Result<()> {
    let raw = vec![
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, //
        0x27, 0x82, 0xBE, 0xDE, 0x00, 0x01, 0x01, 0xAA, 0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];
    let packet = Packet::unmarshal(&mut &raw[..])?;
    assert!(
        packet.header.extensions.is_empty(),
        "extensions should be empty for a non-zero padding-size element"
    );
    assert_eq!(&raw[20..], &packet.payload[..]);
    Ok(())
}

// pion TestUnmarshal_{OneByte,TwoByte,NonStandard,Empty*}ExtensionWithoutRTPPayload:
// a header extension block with nothing after it parses.
#[test]
fn test_unmarshal_extensions_without_rtp_payload() -> Result<()> {
    let cases: Vec<Vec<u8>> = vec![
        // One-byte, id 0 with length (terminates), then data.
        vec![
            0x10, 0x64, 0x57, 0x49, 0x00, 0x00, 0x01, 0x90, 0x12, 0x34, 0xAB, 0xCD, //
            0xBE, 0xDE, 0x00, 0x01, 0x02, 0x01, 0x02, 0x03,
        ],
        // Two-byte, id 2 len 2, then data.
        vec![
            0x10, 0x64, 0x57, 0x49, 0x00, 0x00, 0x01, 0x90, 0x12, 0x34, 0xAB, 0xCD, //
            0x10, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x03,
        ],
        // Non-standard profile 0xAAAA, opaque payload.
        vec![
            0x10, 0x64, 0x57, 0x49, 0x00, 0x00, 0x01, 0x90, 0x12, 0x34, 0xAB, 0xCD, //
            0xAA, 0xAA, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04,
        ],
        // Empty one-byte block.
        vec![
            0x10, 0x64, 0x57, 0x49, 0x00, 0x00, 0x01, 0x90, 0x12, 0x34, 0xAB, 0xCD, //
            0xBE, 0xDE, 0x00, 0x00,
        ],
        // Empty two-byte block.
        vec![
            0x10, 0x64, 0x57, 0x49, 0x00, 0x00, 0x01, 0x90, 0x12, 0x34, 0xAB, 0xCD, //
            0x10, 0x00, 0x00, 0x00,
        ],
        // Empty non-standard block.
        vec![
            0x10, 0x64, 0x57, 0x49, 0x00, 0x00, 0x01, 0x90, 0x12, 0x34, 0xAB, 0xCD, //
            0xAA, 0xAA, 0x00, 0x00,
        ],
    ];
    for raw in cases {
        assert!(
            Packet::unmarshal(&mut &raw[..]).is_ok(),
            "should unmarshal {:02x?}",
            raw
        );
    }
    Ok(())
}

// pion TestCloneHeader: a clone is independent of later changes to the
// original (pion mutates the original's slices; rtc-rtp replaces through
// `set_extension`/`csrc.push`, which never touches the clone's state).
#[test]
fn test_clone_header() {
    let mut header = Header {
        marker: true,
        extension: true,
        extension_profile: 1,
        extensions: vec![Extension {
            id: 0,
            payload: Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]),
        }],
        version: 2,
        payload_type: 96,
        sequence_number: 27023,
        timestamp: 3653407706,
        ssrc: 476325762,
        ..Default::default()
    };
    let clone = header.clone();
    assert_eq!(header, clone);

    header.csrc.push(1);
    assert_ne!(clone.csrc.len(), header.csrc.len());
    // pion mutates the original's extension payload in place; rtc-rtp's
    // payloads are `Bytes` (immutable), so the equivalent is replacing the
    // element payload directly.
    header.extensions[0].payload = Bytes::from_static(&[0x1F]);
    assert_eq!(
        Some(Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF])),
        clone.get_extension(0),
        "the clone's extension should be unchanged"
    );
    assert_eq!(
        Some(Bytes::from_static(&[0x1F])),
        header.get_extension(0),
        "the original was changed"
    );
}

// pion TestClonePacket.
#[test]
fn test_clone_packet() {
    let raw = vec![
        0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, //
        0x27, 0x82, 0xBE, 0xDE, 0x00, 0x01, 0x50, 0xAA, 0x00, 0x00, //
        0x98, 0x36, 0xbe, 0x88, 0x9e,
    ];
    let packet = Packet {
        payload: Bytes::copy_from_slice(&raw[20..]),
        ..Packet::default()
    };

    let clone = packet.clone();
    assert_eq!(packet, clone);

    // Replacing the original's payload cannot disturb the clone (pion mutates
    // the slice in place; `Bytes` is replaced, never mutated).
    let mut packet = packet;
    packet.payload = Bytes::from_static(&[0x1F]);
    assert_ne!(clone.payload, Bytes::from_static(&[0x1F]));
}

// pion TestMarshalRTPPacketFuncs: the header/packet marshal-size helpers agree
// with what lands on the wire (pion: MarshalPacketTo / PacketMarshalSize /
// HeaderAndPacketMarshalSize; rtc-rtp: Packet::marshal_to / marshal_size and
// Header::marshal_size).
#[test]
fn test_marshal_rtp_packet_funcs() -> Result<()> {
    // Packet with only padding.
    let raw = vec![
        0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, //
        0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, //
        0x00, 0x00, 0x00, 0x00, 0x05,
    ];
    let packet = Packet {
        header: Header {
            padding: true,
            marker: true,
            extension: true,
            extension_profile: 1,
            extensions: vec![Extension {
                id: 0,
                payload: Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            padding_size: 5,
            ..Default::default()
        },
        payload: Bytes::new(),
    };

    let mut buf = vec![0u8; 100];
    let n = packet.marshal_to(&mut buf)?;
    assert_eq!(raw.len(), n);
    assert_eq!(&raw[..], &buf[..n]);
    assert_eq!(n, packet.marshal_size());
    assert_eq!(packet.header.marshal_size() + packet.payload.len() + 5, n);
    Ok(())
}

// pion TestDeprecatedPaddingSizeField, adapted: rtc-rtp has no deprecated
// Packet-level PaddingSize (the header field is the only one), so the port
// pins that the header field survives a marshal and a clone.
#[test]
fn test_deprecated_padding_size_field() -> Result<()> {
    let raw = vec![
        0xb0, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64, //
        0x27, 0x82, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, //
        0x00, 0x00, 0x00, 0x00, 0x05,
    ];
    let mut packet = Packet {
        header: Header {
            padding: true,
            marker: true,
            extension: true,
            extension_profile: 1,
            extensions: vec![Extension {
                id: 0,
                payload: Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]),
            }],
            version: 2,
            payload_type: 96,
            sequence_number: 27023,
            timestamp: 3653407706,
            ssrc: 476325762,
            padding_size: 5,
            ..Default::default()
        },
        payload: Bytes::new(),
    };

    let mut buf = BytesMut::with_capacity(packet.marshal_size());
    buf.resize(packet.marshal_size(), 0);
    let n = packet.marshal_to(&mut buf)?;
    assert_eq!(&raw[..], &buf[..n]);
    assert_eq!(raw.len(), packet.marshal_size());

    // rtc-rtp keeps the header's padding_size after marshalling, so a second
    // marshal produces the same bytes (pion clears its deprecated packet-level
    // field instead, which would change the padding on re-marshal).
    let mut buf2 = BytesMut::with_capacity(packet.marshal_size());
    buf2.resize(packet.marshal_size(), 0);
    let n2 = packet.marshal_to(&mut buf2)?;
    assert_eq!(n, n2);
    assert_eq!(&buf[..], &buf2[..]);

    let clone = packet.clone();
    assert_eq!(5, clone.header.padding_size);
    let _ = &mut packet;
    Ok(())
}

// Found by a differential run against pion v1.10.6: switching profile after an
// extension was set used to leave stale padding that marshaled an extra word.
#[test]
fn test_profile_switch_pads_like_pion() -> Result<()> {
    use shared::marshal::Marshal;

    let mut header = Header {
        version: 2,
        payload_type: 96,
        sequence_number: 1,
        timestamp: 2,
        ssrc: 3,
        ..Default::default()
    };
    header.set_extension(14, Bytes::from_static(&[0x98]))?;
    header.set_extension_with_profile(
        14,
        Bytes::from_static(&[0xac, 0xbf, 0x7e, 0x7d]),
        EXTENSION_PROFILE_TWO_BYTE,
    )?;
    let raw = header.marshal()?;
    assert_eq!(
        raw.as_ref(),
        &[
            0x90, 0x60, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0x10, 0x00, 0, 2, 0x0e, 4, 0xac, 0xbf, 0x7e,
            0x7d, 0, 0
        ][..]
    );
    assert_eq!(raw.len(), header.marshal_size());

    // Deleting down to the last extension leaves no stale padding either.
    header.set_extension(1, Bytes::from_static(&[1, 2, 3]))?;
    header.del_extension(14)?;
    let raw = header.marshal()?;
    assert_eq!(raw.len(), 12 + 4 + 8);
    Ok(())
}

// pion TestSetExtensionWithProfile.
#[test]
fn test_set_extension_with_profile() -> Result<()> {
    // Upgrade: a payload over 16 bytes forces the two-byte profile.
    {
        let mut header = Header::default();
        header.set_extension(1, Bytes::from(vec![0u8; 2]))?;
        header.set_extension(2, Bytes::from(vec![0u8; 3]))?;
        header.set_extension_with_profile(
            3,
            Bytes::from(vec![0u8; 20]),
            EXTENSION_PROFILE_TWO_BYTE,
        )?;
        assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);
    }

    // Upgrade: an id above 14 forces the two-byte profile.
    {
        let mut header = Header::default();
        header.set_extension(1, Bytes::from(vec![0u8; 2]))?;
        header.set_extension(2, Bytes::from(vec![0u8; 3]))?;
        header.set_extension_with_profile(
            16,
            Bytes::from(vec![0u8; 4]),
            EXTENSION_PROFILE_TWO_BYTE,
        )?;
        assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);
    }

    // Downgrade: a two-byte header re-encoded under the one-byte profile.
    {
        let raw = vec![
            0x90, 0x60, 0x00, 0x01, // V=2, X=1, CC=0; M=0, PT=96; sequence=1
            0x00, 0x00, 0x00, 0x01, // timestamp=1
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x10, 0x00, 0x00, 0x01, // two-byte profile, 1 word
            0x01, 0x02, 0x00, 0x01, // id=1, len=2, data=00 01
        ];
        let mut header = Header::unmarshal(&mut &raw[..])?;
        assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);

        header.set_extension_with_profile(
            1,
            Bytes::from_static(&[0x02, 0x03]),
            EXTENSION_PROFILE_ONE_BYTE,
        )?;
        assert_eq!(EXTENSION_PROFILE_ONE_BYTE, header.extension_profile);

        let mut buf = BytesMut::with_capacity(header.marshal_size());
        buf.resize(header.marshal_size(), 0);
        let n = header.marshal_to(&mut buf)?;
        assert_eq!(n, buf.len());
        assert_eq!(
            &[
                0x90, 0x60, 0x00, 0x01, //
                0x00, 0x00, 0x00, 0x01, //
                0x12, 0x34, 0x56, 0x78, //
                0xbe, 0xde, 0x00, 0x01, //
                0x11, 0x02, 0x03, 0x00,
            ][..],
            &buf[..]
        );
    }

    // A downgrade that an existing extension cannot fit is refused, and the
    // header is left untouched.
    {
        let mut header = Header {
            extension: true,
            extension_profile: EXTENSION_PROFILE_TWO_BYTE,
            extensions: vec![Extension {
                id: 20,
                payload: Bytes::from_static(&[0x01]),
            }],
            ..Header::default()
        };
        assert!(
            header
                .set_extension_with_profile(
                    1,
                    Bytes::from_static(&[0x02]),
                    EXTENSION_PROFILE_ONE_BYTE
                )
                .is_err()
        );
        assert_eq!(EXTENSION_PROFILE_TWO_BYTE, header.extension_profile);
    }
    Ok(())
}

// pion TestMarshalSizePanic: a header with the extension flag set but no
// extensions sizes and marshals without panicking (pion issue #315).
#[test]
fn test_marshal_size_panic() {
    let header = Header {
        extension: true,
        ..Header::default()
    };
    assert_eq!(16, header.marshal_size());
}

// pion TestMarshalToPanic.
#[test]
fn test_marshal_to_panic() -> Result<()> {
    let header = Header {
        extension: true,
        ..Header::default()
    };
    let mut buf = vec![0u8; 16];
    let n = header.marshal_to(&mut buf)?;
    assert_eq!(16, n);
    Ok(())
}

// pion TestMarshalToInitializesPadding: padding octets are written (zeroes and
// the count in the last one) and nothing beyond the packet is touched.
#[test]
fn test_marshal_to_initializes_padding() -> Result<()> {
    for padding_size in [0u8, 1, 4, 255] {
        let packet = Packet {
            header: Header {
                version: 2,
                padding: padding_size > 0,
                padding_size,
                ..Header::default()
            },
            payload: Bytes::from_static(&[1, 2, 3]),
        };

        // A fresh allocation provides the expected wire encoding.
        let expected = packet.marshal()?;
        assert_eq!(
            expected.len(),
            packet.marshal_size(),
            "padding {padding_size}"
        );
        if padding_size > 0 {
            assert_eq!(padding_size, expected[expected.len() - 1]);
        }

        // MarshalTo into a dirty buffer writes exactly the packet and leaves
        // the tail untouched (reusing buffers once exposed media data).
        let mut buf = vec![0xa5u8; expected.len() + 16];
        let n = packet.marshal_to(&mut buf)?;
        assert_eq!(expected.len(), n, "padding {padding_size}");
        assert_eq!(&expected[..], &buf[..n], "padding {padding_size}");
        assert_eq!(
            &vec![0xa5u8; 16][..],
            &buf[n..],
            "bytes beyond the packet must be untouched"
        );
    }
    Ok(())
}
