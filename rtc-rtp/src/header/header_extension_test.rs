//! pion rtp `header_extension_test.go`, ported. pion exercises the RFC 8285
//! element codecs through standalone `OneByteHeaderExtension` /
//! `TwoByteHeaderExtension` / `RawExtension` types fed raw extension blocks;
//! rtc-rtp folds the same element logic into [`Header`], so each port wraps
//! pion's raw block in a minimal RTP header, parses it, and asserts on
//! `get_extension` / `marshal`.

use bytes::{Bytes, BytesMut};

use super::*;
use shared::marshal::{Marshal, MarshalSize, Unmarshal};

/// Wraps a raw extension block in a minimal RTP header (V=2, X=1, no CSRC) and
/// parses it back into a `Header`.
fn header_from_block(block: &[u8]) -> Header {
    let mut raw = vec![
        0x90, 0x60, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78,
    ];
    raw.extend_from_slice(block);
    Header::unmarshal(&mut &raw[..]).expect("parse the wrapped block")
}

/// The extension block bytes of a marshaled header (after the 12 fixed octets).
fn block_of(header: &Header) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(header.marshal_size());
    buf.resize(header.marshal_size(), 0);
    let n = header.marshal_to(&mut buf).expect("marshal");
    assert_eq!(n, header.marshal_size());
    buf[12..].to_vec()
}

// pion TestHeaderExtension_RFC8285OneByteExtension.
#[test]
fn test_header_extension_rfc8285_one_byte_extension() -> Result<()> {
    let raw_block: &[u8] = &[
        0xBE, 0xDE, 0x00, 0x01, 0x50, 0xAA, 0x00, 0x00, //
    ];
    let header = header_from_block(raw_block);
    assert_eq!(Some(Bytes::from_static(&[0xAA])), header.get_extension(5));
    assert_eq!(raw_block, block_of(&header));
    Ok(())
}

// pion TestHeaderExtension_RFC8285OneByteTwoExtensionOfTwoBytes.
#[test]
fn test_header_extension_rfc8285_one_byte_two_extension_of_two_bytes() -> Result<()> {
    let raw_block: &[u8] = &[
        0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x20, 0xBB, //
    ];
    let header = header_from_block(raw_block);
    assert_eq!(Some(Bytes::from_static(&[0xAA])), header.get_extension(1));
    assert_eq!(Some(Bytes::from_static(&[0xBB])), header.get_extension(2));
    assert_eq!(raw_block, block_of(&header));
    Ok(())
}

// pion TestHeaderExtension_RFC8285OneByteMultipleExtensionsWithPadding.
//
// rtc-rtp re-lays the elements out on marshal, so interior padding moves to
// the end of the block (the same bytes, same total length, valid RFC 8285);
// pion splices in place and reproduces the interior padding byte-for-byte.
// The port asserts the same block length and the same element payloads.
#[test]
fn test_header_extension_rfc8285_one_byte_multiple_extensions_with_padding() -> Result<()> {
    let raw_block: &[u8] = &[
        0xBE, 0xDE, 0x00, 0x03, 0x10, 0xAA, 0x21, 0xBB, //
        0xBB, 0x00, 0x00, 0x33, 0xCC, 0xCC, 0xCC, 0xCC,
    ];
    let header = header_from_block(raw_block);
    assert_eq!(Some(Bytes::from_static(&[0xAA])), header.get_extension(1));
    assert_eq!(
        Some(Bytes::from_static(&[0xBB, 0xBB])),
        header.get_extension(2)
    );
    assert_eq!(
        Some(Bytes::from_static(&[0xCC, 0xCC, 0xCC, 0xCC])),
        header.get_extension(3)
    );

    let marshaled = block_of(&header);
    assert_eq!(raw_block.len(), marshaled.len(), "same block length");
    let re_header = header_from_block(&marshaled);
    assert_eq!(
        Some(Bytes::from_static(&[0xAA])),
        re_header.get_extension(1)
    );
    assert_eq!(
        Some(Bytes::from_static(&[0xBB, 0xBB])),
        re_header.get_extension(2)
    );
    assert_eq!(
        Some(Bytes::from_static(&[0xCC, 0xCC, 0xCC, 0xCC])),
        re_header.get_extension(3)
    );
    Ok(())
}

// pion TestHeaderExtension_RFC8285TwoByteExtension.
#[test]
fn test_header_extension_rfc8285_two_byte_extension() -> Result<()> {
    let raw_block: &[u8] = &[
        0x10, 0x00, 0x00, 0x07, 0x05, 0x18, 0xAA, 0xAA, //
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //
        0xAA, 0xAA, 0x00, 0x00,
    ];
    let header = header_from_block(raw_block);
    let expected: Vec<u8> = std::iter::repeat_n(0xAA, 24).collect();
    assert_eq!(Some(Bytes::from(expected)), header.get_extension(5));
    assert_eq!(raw_block, block_of(&header));
    Ok(())
}

// pion TestHeaderExtension_RFC8285TwoByteMultipleExtensionsWithPadding.
#[test]
fn test_header_extension_rfc8285_two_byte_multiple_extensions_with_padding() -> Result<()> {
    let raw_block: &[u8] = &[
        0x10, 0x00, 0x00, 0x03, 0x01, 0x00, 0x02, 0x01, //
        0xBB, 0x00, 0x03, 0x04, 0xCC, 0xCC, 0xCC, 0xCC,
    ];
    let header = header_from_block(raw_block);
    assert_eq!(Some(Bytes::new()), header.get_extension(1));
    assert_eq!(Some(Bytes::from_static(&[0xBB])), header.get_extension(2));
    assert_eq!(
        Some(Bytes::from_static(&[0xCC, 0xCC, 0xCC, 0xCC])),
        header.get_extension(3)
    );
    Ok(())
}

// pion TestHeaderExtension_RFC8285TwoByteMultipleExtensionsWithLargeExtension.
#[test]
fn test_header_extension_rfc8285_two_byte_multiple_extensions_with_large_extension() -> Result<()> {
    let raw_block: &[u8] = &[
        0x10, 0x00, 0x00, 0x06, 0x01, 0x00, 0x02, 0x01, //
        0xBB, 0x03, 0x11, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    ];
    let header = header_from_block(raw_block);
    assert_eq!(Some(Bytes::new()), header.get_extension(1));
    assert_eq!(Some(Bytes::from_static(&[0xBB])), header.get_extension(2));
    let expected: Vec<u8> = std::iter::repeat_n(0xCC, 17).collect();
    assert_eq!(Some(Bytes::from(expected)), header.get_extension(3));
    assert_eq!(raw_block, block_of(&header));
    Ok(())
}

// pion TestHeaderExtension_Invalid: the id and size rules of both profiles.
#[test]
fn test_header_extension_invalid() {
    let mut one_byte = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        ..Header::default()
    };
    assert!(one_byte.set_extension(0, Bytes::new()).is_err());
    assert!(one_byte.set_extension(15, Bytes::new()).is_err());
    assert!(
        one_byte
            .set_extension(10, Bytes::from(vec![0u8; 17]))
            .is_err(),
        "one-byte payloads cap at 16 bytes"
    );

    let mut two_byte = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        ..Header::default()
    };
    assert!(two_byte.set_extension(0, Bytes::new()).is_err());
    assert!(
        two_byte
            .set_extension(10, Bytes::from(vec![0u8; 256]))
            .is_err(),
        "two-byte payloads cap at 255 bytes"
    );
}

// pion TestHeaderExtension_RFC8285OneByteDelExtension.
#[test]
fn test_header_extension_rfc8285_one_byte_del_extension() -> Result<()> {
    let mut header = header_from_block(&[0xBE, 0xDE, 0x00, 0x00]);
    header.set_extension(1, Bytes::from_static(&[0xBB]))?;
    assert!(header.get_extension(1).is_some());
    header.del_extension(1)?;
    assert!(header.get_extension(1).is_none());
    assert!(header.del_extension(1).is_err());
    Ok(())
}

// pion TestHeaderExtension_RFC8285TwoByteDelExtension.
#[test]
fn test_header_extension_rfc8285_two_byte_del_extension() -> Result<()> {
    let mut header = header_from_block(&[0x10, 0x00, 0x00, 0x00]);
    header.set_extension(1, Bytes::from_static(&[0xBB]))?;
    assert!(header.get_extension(1).is_some());
    header.del_extension(1)?;
    assert!(header.get_extension(1).is_none());
    assert!(header.del_extension(1).is_err());
    Ok(())
}

// pion TestHeaderExtension_GetIds.
#[test]
fn test_header_extension_get_ids() {
    let mut one_byte = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_ONE_BYTE,
        ..Header::default()
    };
    one_byte
        .set_extension(1, Bytes::from_static(&[0xBB]))
        .unwrap();
    one_byte
        .set_extension(3, Bytes::from_static(&[0xAA]))
        .unwrap();
    one_byte
        .set_extension(5, Bytes::from_static(&[0xFF]))
        .unwrap();
    assert_eq!(vec![1, 3, 5], one_byte.get_extension_ids());

    let mut two_byte = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        ..Header::default()
    };
    two_byte
        .set_extension(1, Bytes::from_static(&[0xBB]))
        .unwrap();
    two_byte
        .set_extension(3, Bytes::from_static(&[0xAA]))
        .unwrap();
    two_byte
        .set_extension(5, Bytes::from_static(&[0xFF]))
        .unwrap();
    assert_eq!(vec![1, 3, 5], two_byte.get_extension_ids());
}

// pion TestHeaderExtension_RFC8285OneByteExtensionRewrite: re-setting an id
// rewrites its element in place, and a new id appends after it.
#[test]
fn test_header_extension_rfc8285_one_byte_extension_rewrite() -> Result<()> {
    let mut header = Header::default();
    header.set_extension(1, Bytes::from_static(&[0x01, 0x02, 0x03]))?;
    assert_eq!(
        [0xBE, 0xDE, 0x00, 0x01, 0x12, 0x01, 0x02, 0x03],
        block_of(&header)[..]
    );

    header.set_extension(1, Bytes::from_static(&[0x04, 0x05, 0x06]))?;
    assert_eq!(
        [0xBE, 0xDE, 0x00, 0x01, 0x12, 0x04, 0x05, 0x06],
        block_of(&header)[..]
    );

    header.set_extension(3, Bytes::from_static(&[0x07, 0x08, 0x09]))?;
    assert_eq!(
        [
            0xBE, 0xDE, 0x00, 0x02, 0x12, 0x04, 0x05, 0x06, 0x32, 0x07, 0x08, 0x09
        ],
        block_of(&header)[..]
    );
    Ok(())
}

// pion TestHeaderExtension_RFC8285TwoByteExtensionRewrite. pion's standalone
// extension marshal writes the extension count into the length field and no
// padding; rtc-rtp writes the length the packet-level encoding uses (32-bit
// words, padded), which is what pion's own Packet marshal produces.
#[test]
fn test_header_extension_rfc8285_two_byte_extension_rewrite() -> Result<()> {
    let mut header = Header {
        extension: true,
        extension_profile: EXTENSION_PROFILE_TWO_BYTE,
        ..Header::default()
    };
    header.set_extension(200, Bytes::from_static(&[0x01, 0x02, 0x03]))?;
    assert_eq!(
        [
            0x10, 0x00, 0x00, 0x02, 0xc8, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00
        ],
        block_of(&header)[..]
    );

    header.set_extension(200, Bytes::from_static(&[0x04, 0x05, 0x06]))?;
    assert_eq!(
        [
            0x10, 0x00, 0x00, 0x02, 0xc8, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00
        ],
        block_of(&header)[..]
    );

    header.set_extension(50, Bytes::from_static(&[0x07, 0x08, 0x09]))?;
    assert_eq!(
        [
            0x10, 0x00, 0x00, 0x03, 0xc8, 0x03, 0x04, 0x05, 0x06, 0x32, 0x03, 0x07, 0x08, 0x09,
            0x00, 0x00
        ],
        block_of(&header)[..]
    );
    Ok(())
}

// pion TestHeaderExtension_Raw: an RFC 3550 profile that is neither 0xBEDE
// nor 0x1000 carries one opaque, already-padded payload under id 0. pion's
// payload is the whole block; rtc-rtp stores the block content (what follows
// the profile and length), so the round-trip is the same bytes.
#[test]
fn test_header_extension_raw() -> Result<()> {
    let raw_block: &[u8] = &[0xBE, 0xEF, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
    let mut header = header_from_block(raw_block);

    assert_eq!(
        Some(Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD])),
        header.get_extension(0)
    );
    assert_eq!(vec![0], header.get_extension_ids());
    assert_eq!(raw_block, &block_of(&header)[..]);

    // Only id 0 is addressable under a raw profile.
    assert!(
        header
            .set_extension(5, Bytes::from_static(&[0xBE, 0xEF, 0x00, 0x00]))
            .is_err()
    );

    // A too-small buffer is refused (pion: MarshalTo(nil) -> short buffer).
    assert!(header.marshal_to(&mut []).is_err());

    header.del_extension(0)?;
    assert_eq!(header.get_extension(0), None);
    Ok(())
}
