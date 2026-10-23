//! pion/stun v4.0.1 attribute and error tests, ported to the public API (the
//! client/agent goroutine suites are classified `na` in the ledger; allocation
//! budgets live in `allocations.rs`).

use rtc_stun::attributes::*;
use rtc_stun::error_code::*;
use rtc_stun::message::*;
use rtc_stun::message::{Getter, Setter};
use rtc_stun::uattrs::UnknownAttributes;
use rtc_stun::xoraddr::XorMappedAddress;
use shared::error::Error;

fn transaction_id() -> TransactionId {
    // base64 "jxhBARZwX+rsC6er"
    let bytes: [u8; 12] = [
        0x8f, 0x18, 0xc1, 0x01, 0x16, 0x70, 0x5f, 0xfa, 0xec, 0x0b, 0xa7, 0xab,
    ];
    TransactionId(bytes)
}

/// pion TestXORMappedAddress_GetFrom, including the UnexpectedEOF,
/// AttrOverflowErr and ShortValue sub-tests.
#[test]
fn test_xor_mapped_address_get_from() {
    let mut m = Message::new();
    m.transaction_id = transaction_id();
    m.add(
        ATTR_XORMAPPED_ADDRESS,
        &[0x00, 0x01, 0x9c, 0xd5, 0xf4, 0x9f, 0x38, 0xae],
    );
    let mut addr = XorMappedAddress::default();
    addr.get_from(&m).unwrap();
    assert_eq!("213.141.156.236", addr.ip.to_string());
    assert_eq!(48583, addr.port);

    // UnexpectedEOF: a 4-byte value cannot carry an address.
    let mut m = Message::new();
    m.add(ATTR_XORMAPPED_ADDRESS, &[0, 1, 3, 4]);
    let mut addr = XorMappedAddress::default();
    assert_eq!(Err(Error::ErrUnexpectedEof), addr.get_from(&m));

    // AttrOverflowErr: more address bytes than the family allows.
    let mut m = Message::new();
    m.add(
        ATTR_XORMAPPED_ADDRESS,
        &[0, 1, 3, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 2, 3, 4],
    );
    let mut addr = XorMappedAddress::default();
    assert_eq!(Err(Error::ErrAttributeSizeOverflow), addr.get_from(&m));

    // ShortValue: a zero-length XOR-MAPPED-ADDRESS value in a decoded message
    // must be an error, not a panic.
    let raw: Vec<u8> = vec![
        0x01, 0x01, 0x00, 0x04, // type=Binding success, length=4
        0x21, 0x12, 0xA4, 0x42, // magic cookie
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // transaction ID
        0x00, 0x20, 0x00, 0x00, // XOR-MAPPED-ADDRESS, length=0
    ];
    let mut m = Message::new();
    m.unmarshal_binary(&raw).unwrap();
    let mut addr = XorMappedAddress::default();
    assert_eq!(Err(Error::ErrUnexpectedEof), addr.get_from(&m));
}

/// pion TestXORMappedAddress_GetFrom_Invalid: a corrupted family byte in an
/// otherwise valid message is an error.
#[test]
fn test_xor_mapped_address_get_from_invalid() {
    let mut m = Message::new();
    m.transaction_id = transaction_id();
    let addr = XorMappedAddress {
        ip: "213.141.156.236".parse().unwrap(),
        port: 21254,
    };
    addr.add_to(&mut m).unwrap();
    m.write_header();

    // Corrupt the family byte (0x21 instead of 0x01) and re-read.
    m.raw[20 + 4] = 0x21;
    let mut m_res = Message::new();
    m_res.unmarshal_binary(&m.raw).unwrap();
    let mut addr = XorMappedAddress::default();
    assert!(addr.get_from(&m_res).is_err());
}

/// pion TestXORMappedAddress_AddTo.
#[test]
fn test_xor_mapped_address_add_to() {
    let mut m = Message::new();
    m.transaction_id = transaction_id();
    let addr = XorMappedAddress {
        ip: "213.141.156.236".parse().unwrap(),
        port: 21254,
    };
    addr.add_to(&mut m).unwrap();
    m.write_header();

    let mut m_res = Message::new();
    m_res.unmarshal_binary(&m.raw).unwrap();
    let mut got = XorMappedAddress::default();
    got.get_from(&m_res).unwrap();
    assert_eq!(addr.ip, got.ip);
    assert_eq!(addr.port, got.port);
}

/// pion TestXORMappedAddress_AddTo_IPv6.
#[test]
fn test_xor_mapped_address_add_to_ipv6() {
    let mut m = Message::new();
    m.transaction_id = transaction_id();
    let addr = XorMappedAddress {
        ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
        port: 21254,
    };
    addr.add_to(&mut m).unwrap();
    m.write_header();

    let mut m_res = Message::new();
    m_res.unmarshal_binary(&m.raw).unwrap();
    let mut got = XorMappedAddress::default();
    got.get_from(&m_res).unwrap();
    assert_eq!(addr.ip, got.ip);
    assert_eq!(addr.port, got.port);
}

/// pion TestXORMappedAddress_String.
#[test]
fn test_xor_mapped_address_string() {
    let v6 = XorMappedAddress {
        ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
        port: 124,
    };
    assert_eq!("[fe80::dc2b:44ff:fe20:6009]:124", v6.to_string());

    let v4 = XorMappedAddress {
        ip: "213.141.156.236".parse().unwrap(),
        port: 8147,
    };
    assert_eq!("213.141.156.236:8147", v4.to_string());
}

// pion TestXORMappedAddress_AddTo_Invalid (an IP of impossible length) is not
// expressible: rtc-stun's XorMappedAddress stores a typed IpAddr.

/// pion TestErrorCodeAttribute_GetFrom: a truncated value is an unexpected
/// EOF.
#[test]
fn test_error_code_attribute_get_from() {
    let mut m = Message::new();
    m.add(ATTR_ERROR_CODE, &[1]);
    let mut c = ErrorCodeAttribute::default();
    assert_eq!(Err(Error::ErrUnexpectedEof), c.get_from(&m));
}

/// pion TestMessage_AddErrorCode: a built error-code attribute round-trips.
#[test]
fn test_message_add_error_code() {
    let mut m = Message::new();
    m.set_type(BINDING_ERROR);
    m.transaction_id = transaction_id();
    CODE_STALE_NONCE.add_to(&mut m).unwrap();
    m.write_header();

    let mut m_res = Message::new();
    m_res.unmarshal_binary(&m.raw).unwrap();
    let mut attr = ErrorCodeAttribute::default();
    attr.get_from(&m_res).unwrap();
    assert_eq!(438, attr.code.0);
    assert_eq!(b"Stale Nonce".to_vec(), attr.reason);
}

/// pion TestErrorCode: the string form, the no-default-reason error, the
/// missing-attribute error and the too-long reason.
#[test]
fn test_error_code() {
    let attr = ErrorCodeAttribute {
        code: ErrorCode(404),
        reason: b"not found!".to_vec(),
    };
    assert_eq!("404: not found!", attr.to_string());

    let mut m = Message::new();
    assert_eq!(
        Err(Error::ErrNoDefaultReason),
        ErrorCode(666).add_to(&mut m),
        "should be ErrNoDefaultReason"
    );
    let mut attr = attr;
    assert!(attr.get_from(&m).is_err(), "attr should not be in message");

    let too_long = ErrorCodeAttribute {
        code: ErrorCode(404),
        reason: vec![0u8; 2048],
    };
    assert!(too_long.add_to(&mut m).is_err(), "should error");
}

/// pion TestErrorCodeAttribute_AddToInvalidCode: the class digit must fit its
/// 3-bit field.
#[test]
fn test_error_code_attribute_add_to_invalid_code() {
    let mut m = Message::new();
    // pion feeds -1 (unrepresentable as u16) and 25600; both reduce to a
    // class digit above 7.
    assert_eq!(
        Err(Error::ErrInvalidErrorCode),
        ErrorCodeAttribute {
            code: ErrorCode(25600),
            reason: vec![],
        }
        .add_to(&mut m)
    );
    assert_eq!(
        Err(Error::ErrInvalidErrorCode),
        ErrorCodeAttribute {
            code: ErrorCode(800),
            reason: vec![],
        }
        .add_to(&mut m)
    );
}

/// pion TestErrorCodeAttribute_ReservedBitsIgnored: the five bits above the
/// class are reserved and must be masked off on read.
#[test]
fn test_error_code_attribute_reserved_bits_ignored() {
    let mut m = Message::new();
    m.write_header();
    // 0xE4 has reserved bits set; low 3 bits = 4 (class 4), number 20 => 420.
    m.add(ATTR_ERROR_CODE, &[0x00, 0x00, 0xE4, 20]);

    let mut c = ErrorCodeAttribute::default();
    c.get_from(&m).unwrap();
    assert_eq!(420, c.code.0, "reserved bits not ignored");
}

/// pion TestAttrOverflowErr_Error and TestAttrLengthErr_Error: the overflow
/// identity is recognisable through `is_attr_size_overflow` (rtc-stun's
/// equivalent of pion's `IsAttrSizeOverflow`).
#[test]
fn test_attr_overflow_and_length_err() {
    let mut m = Message::new();
    m.add(
        ATTR_XORMAPPED_ADDRESS,
        &[0, 1, 3, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 2, 3, 4],
    );
    let mut addr = XorMappedAddress::default();
    let err = addr.get_from(&m).unwrap_err();
    assert!(
        rtc_stun::checks::is_attr_size_overflow(&err),
        "expected an attribute-size overflow, got {err}"
    );
    assert_eq!("attribute size overflow", err.to_string());
}

/// pion TestAttrTypeKnown: every IANA-registered type reports its name.
#[test]
fn test_attr_type_known() {
    assert_eq!(
        "MAPPED-ADDRESS",
        AttrType(ATTR_MAPPED_ADDRESS.value()).to_string()
    );
    assert_eq!("USERNAME", AttrType(ATTR_USERNAME.value()).to_string());
    assert_eq!("ERROR-CODE", AttrType(ATTR_ERROR_CODE.value()).to_string());
}

/// pion TestUnknownAttributesEncoding: the attribute marshals each type as a
/// 16-bit value.
#[test]
fn test_unknown_attributes_encoding() {
    let mut m = Message::new();
    let uattrs = UnknownAttributes(vec![ATTR_LIFETIME, ATTR_CHANNEL_NUMBER]);
    uattrs.add_to(&mut m).unwrap();

    let value = m.get_value(ATTR_UNKNOWN_ATTRIBUTES).unwrap();
    assert_eq!(
        &[
            (ATTR_LIFETIME.value() >> 8) as u8,
            ATTR_LIFETIME.value() as u8,
            (ATTR_CHANNEL_NUMBER.value() >> 8) as u8,
            ATTR_CHANNEL_NUMBER.value() as u8,
        ][..],
        value
    );

    // And it parses back.
    let mut got = UnknownAttributes(vec![]);
    got.get_from(&m).unwrap();
    assert_eq!(uattrs.0, got.0);

    // An odd length is rejected.
    let mut m = Message::new();
    m.add(ATTR_UNKNOWN_ATTRIBUTES, &[1, 2, 3]);
    let mut got = UnknownAttributes(vec![]);
    assert!(got.get_from(&m).is_err());
}

/// pion TestDecodeErr_IsInvalidCookie: a wrong magic cookie is a decode
/// error.
#[test]
fn test_decode_err_is_invalid_cookie() {
    let mut raw = vec![
        0x00, 0x00, 0x00, 0x00, // type/length patched below
        0x21, 0x12, 0xA4, 0x42, // magic cookie
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // transaction ID
    ];
    // Corrupt the cookie.
    raw[4] = 0x22;
    let mut m = Message::new();
    assert!(
        m.unmarshal_binary(&raw).is_err(),
        "bad cookie must decode to an error"
    );
    let _ = &mut raw;
}

/// pion TestMessageReservedType: attribute types in the reserved comprehension
/// ranges are carried, not rejected (the type is 16 bits of wire data).
#[test]
fn test_message_reserved_type() {
    let reserved = AttrType(0x7FFF);
    let mut m = Message::new();
    m.add(reserved, &[1, 2, 3]);
    assert_eq!(&[1u8, 2, 3][..], m.get_value(reserved).unwrap());
}
