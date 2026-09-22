use super::*;
use crate::textattrs::TextAttribute;

use crate::attributes::ATTR_SOFTWARE;

#[test]
fn fingerprint_uses_crc_32_iso_hdlc() -> Result<()> {
    let mut m = Message::new();

    let a = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: "software".to_owned(),
    };
    a.add_to(&mut m)?;
    m.write_header();

    FINGERPRINT.add_to(&mut m)?;
    m.write_header();

    assert_eq!(&m.raw[0..m.raw.len()-8], b"\x00\x00\x00\x14\x21\x12\xA4\x42\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x22\x00\x08\x73\x6F\x66\x74\x77\x61\x72\x65");

    assert_eq!(m.raw[m.raw.len() - 4..], [0xe4, 0x4c, 0x33, 0xd9]);

    Ok(())
}

#[test]
fn test_fingerprint_check() -> Result<()> {
    let mut m = Message::new();
    let a = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: "software".to_owned(),
    };
    a.add_to(&mut m)?;
    m.write_header();

    FINGERPRINT.add_to(&mut m)?;
    m.write_header();
    FINGERPRINT.check(&m)?;
    m.raw[3] += 1;

    let result = FINGERPRINT.check(&m);
    assert!(result.is_err(), "should error");

    Ok(())
}

#[test]
fn test_fingerprint_check_bad() -> Result<()> {
    let mut m = Message::new();
    let a = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: "software".to_owned(),
    };
    a.add_to(&mut m)?;
    m.write_header();

    let result = FINGERPRINT.check(&m);
    assert!(result.is_err(), "should error");

    m.add(ATTR_FINGERPRINT, &[1, 2, 3]);

    let result = FINGERPRINT.check(&m);
    if let Err(err) = result {
        assert!(
            is_attr_size_invalid(&err),
            "IsAttrSizeInvalid should be true"
        );
    } else {
        panic!("Expected error, but got ok");
    }

    Ok(())
}

#[test]
fn fingerprint_value_matches_the_check_value() {
    // CRC-32/ISO-HDLC of "123456789" is 0xCBF43926 (the catalogue's check value).
    assert_eq!(
        fingerprint_value(b"123456789"),
        0xCBF4_3926 ^ FINGERPRINT_XOR_VALUE
    );
}

/// The accelerated CRC agrees with the table-driven `crc` implementation it replaced, at every
/// length through a full MTU and at every alignment of the start within a 16-byte vector.
#[test]
fn fingerprint_value_matches_the_table_driven_crc() {
    use crc::{CRC_32_ISO_HDLC, Crc, Table};
    static REFERENCE: Crc<u32, Table<16>> = Crc::<u32, Table<16>>::new(&CRC_32_ISO_HDLC);

    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let data: Vec<u8> = (0..1600)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    for offset in 0..16 {
        for len in 0..=1500 {
            let input = &data[offset..offset + len];
            assert_eq!(
                fingerprint_value(input),
                REFERENCE.checksum(input) ^ FINGERPRINT_XOR_VALUE,
                "offset {offset}, length {len}"
            );
        }
    }
}
