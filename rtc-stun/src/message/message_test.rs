use super::*;
use crate::xoraddr::*;

use crate::fingerprint::FINGERPRINT;
use crate::integrity::MessageIntegrity;
use crate::textattrs::TextAttribute;
use std::io::{BufReader, BufWriter};

/// A message holding `attrs`, in order, encoded the usual way.
fn message_of(attrs: &[(u16, &[u8])]) -> Message {
    let mut m = Message::default();
    for (typ, value) in attrs {
        m.add(AttrType(*typ), value);
    }
    m
}

#[test]
fn test_message_buffer() -> Result<()> {
    let mut m = Message::new();
    m.typ = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    m.transaction_id = TransactionId::new();
    m.add(ATTR_ERROR_CODE, &[0xff, 0xfe, 0xfa]);
    m.write_header();

    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(m.raw.as_slice());
    m_decoded.read_from(&mut reader)?;

    assert_eq!(m_decoded, m, "{m_decoded} != {m}");

    Ok(())
}

#[test]
fn test_message_type_value() -> Result<()> {
    let tests = vec![
        (
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_REQUEST,
            },
            0x0001,
        ),
        (
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_SUCCESS_RESPONSE,
            },
            0x0101,
        ),
        (
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_ERROR_RESPONSE,
            },
            0x0111,
        ),
        (
            MessageType {
                method: Method(0xb6d),
                class: MessageClass(0x3),
            },
            0x2ddd,
        ),
    ];

    for (input, output) in tests {
        let b = input.value();
        assert_eq!(b, output, "Value({input}) -> {b}, want {output}");
    }

    Ok(())
}

#[test]
fn test_message_type_read_value() -> Result<()> {
    let tests = vec![
        (
            0x0001,
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_REQUEST,
            },
        ),
        (
            0x0101,
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_SUCCESS_RESPONSE,
            },
        ),
        (
            0x0111,
            MessageType {
                method: METHOD_BINDING,
                class: CLASS_ERROR_RESPONSE,
            },
        ),
    ];

    for (input, output) in tests {
        let mut m = MessageType::default();
        m.read_value(input);
        assert_eq!(m, output, "ReadValue({input}) -> {m}, want {output}");
    }

    Ok(())
}

#[test]
fn test_message_type_read_write_value() -> Result<()> {
    let tests = vec![
        MessageType {
            method: METHOD_BINDING,
            class: CLASS_REQUEST,
        },
        MessageType {
            method: METHOD_BINDING,
            class: CLASS_SUCCESS_RESPONSE,
        },
        MessageType {
            method: METHOD_BINDING,
            class: CLASS_ERROR_RESPONSE,
        },
        MessageType {
            method: Method(0x12),
            class: CLASS_ERROR_RESPONSE,
        },
    ];

    for test in tests {
        let mut m = MessageType::default();
        let v = test.value();
        m.read_value(v);
        assert_eq!(m, test, "ReadValue({test} -> {v}) = {m}, should be {test}");
    }

    Ok(())
}

#[test]
fn test_message_write_to() -> Result<()> {
    let mut m = Message::new();
    m.typ = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    m.transaction_id = TransactionId::new();
    m.add(ATTR_ERROR_CODE, &[0xff, 0xfe, 0xfa]);
    m.write_header();
    let mut buf = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(buf.as_mut());
        m.write_to(&mut writer)?;
    }

    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(buf.as_slice());
    m_decoded.read_from(&mut reader)?;
    assert_eq!(m_decoded, m, "{m_decoded} != {m}");

    Ok(())
}

#[test]
fn test_message_cookie() -> Result<()> {
    let buf = vec![0; 20];
    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(buf.as_slice());
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should error");

    Ok(())
}

#[test]
fn test_message_length_less_header_size() -> Result<()> {
    let buf = vec![0; 8];
    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(buf.as_slice());
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should error");

    Ok(())
}

#[test]
fn test_message_bad_length() -> Result<()> {
    let m_type = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    let mut m = Message {
        typ: m_type,
        length: 4,
        transaction_id: TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        ..Default::default()
    };
    m.add(AttrType(0x1), &[1, 2]);
    m.write_header();
    m.raw[20 + 3] = 10; // set attr length = 10

    let mut m_decoded = Message::new();
    let result = m_decoded.write(&m.raw);
    assert!(result.is_err(), "should error");

    Ok(())
}

#[test]
fn test_message_attr_length_less_than_header() -> Result<()> {
    let m_type = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    let mut m = message_of(&[(0x1, &[1, 2])]);
    m.typ = m_type;
    m.transaction_id = TransactionId::new();
    m.encode();

    let mut m_decoded = Message::new();
    m.raw[3] = 2; // rewrite to bad length

    let mut reader = BufReader::new(&m.raw[..20 + 2]);
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_message_attr_size_less_than_length() -> Result<()> {
    let m_type = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    let mut m = message_of(&[(0x1, &[1, 2, 3, 4])]);
    m.typ = m_type;
    m.transaction_id = TransactionId::new();
    m.write_attributes();
    m.write_header();
    m.raw[3] = 5; // rewrite to bad length

    let mut m_decoded = Message::new();
    let mut reader = BufReader::new(&m.raw[..20 + 5]);
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_message_read_from_error() -> Result<()> {
    let mut m_decoded = Message::new();
    let buf = vec![];
    let mut reader = BufReader::new(buf.as_slice());
    let result = m_decoded.read_from(&mut reader);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_message_class_string() -> Result<()> {
    let v = vec![
        CLASS_REQUEST,
        CLASS_ERROR_RESPONSE,
        CLASS_SUCCESS_RESPONSE,
        CLASS_INDICATION,
    ];

    for k in v {
        if k.to_string() == *"unknown message class" {
            panic!("bad stringer {k}");
        }
    }

    // should panic
    let p = MessageClass(0x05).to_string();
    assert_eq!(p, "unknown message class", "should be error {p}");

    Ok(())
}

#[test]
fn test_attr_type_string() -> Result<()> {
    let v = vec![
        ATTR_MAPPED_ADDRESS,
        ATTR_USERNAME,
        ATTR_ERROR_CODE,
        ATTR_MESSAGE_INTEGRITY,
        ATTR_UNKNOWN_ATTRIBUTES,
        ATTR_REALM,
        ATTR_NONCE,
        ATTR_XORMAPPED_ADDRESS,
        ATTR_SOFTWARE,
        ATTR_ALTERNATE_SERVER,
        ATTR_FINGERPRINT,
    ];
    for k in v {
        assert!(!k.to_string().starts_with("0x"), "bad stringer");
    }

    let v_non_standard = AttrType(0x512);
    assert!(
        v_non_standard.to_string().starts_with("0x512"),
        "bad prefix"
    );

    Ok(())
}

#[test]
fn test_method_string() -> Result<()> {
    assert_eq!(
        METHOD_BINDING.to_string(),
        "Binding".to_owned(),
        "binding is not binding!"
    );
    assert_eq!(
        Method(0x616).to_string(),
        "0x616".to_owned(),
        "Bad stringer {}",
        Method(0x616)
    );

    Ok(())
}

#[test]
fn test_attribute_equal() -> Result<()> {
    let a = RawAttribute {
        length: 2,
        value: vec![0x1, 0x2],
        ..Default::default()
    };
    let b = RawAttribute {
        length: 2,
        value: vec![0x1, 0x2],
        ..Default::default()
    };
    assert_eq!(a, b, "should equal");

    assert_ne!(
        a,
        RawAttribute {
            typ: AttrType(0x2),
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        RawAttribute {
            length: 0x2,
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        RawAttribute {
            length: 0x3,
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        RawAttribute {
            length: 0x2,
            value: vec![0x1, 0x3],
            ..Default::default()
        },
        "should not equal"
    );

    Ok(())
}

#[test]
fn test_message_equal() -> Result<()> {
    let a = message_of(&[(0x1, &[0x1, 0x2])]);
    let b = message_of(&[(0x1, &[0x1, 0x2])]);
    assert_eq!(a, b, "should equal");
    assert_ne!(
        a,
        Message {
            typ: MessageType {
                class: MessageClass(128),
                ..Default::default()
            },
            ..Default::default()
        },
        "should not equal"
    );

    let t_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    assert_ne!(
        a,
        Message {
            transaction_id: t_id,
            ..Default::default()
        },
        "should not equal"
    );
    assert_ne!(
        a,
        Message {
            length: 3,
            ..Default::default()
        },
        "should not equal"
    );

    assert_ne!(a, message_of(&[(0x1, &[0x1])]), "a shorter value");
    assert_ne!(a, message_of(&[(0x2, &[0x1, 0x1])]), "another type");
    assert_ne!(a, message_of(&[(0x1, &[0x1, 0x3])]), "another value");

    //"Nil attributes"
    {
        let none = Message {
            length: a.length,
            ..Default::default()
        };
        let mut b = a.clone();

        assert_ne!(none, b, "should not equal");
        assert_ne!(b, none, "should not equal");
        b.attributes = Attributes::default();
        assert_eq!(none, b, "should equal");
    }

    //"Attributes length"
    {
        let one = message_of(&[(0x1, &[0x1, 0x2])]);
        let two = message_of(&[(0x1, &[0x1, 0x2]), (0x1, &[0x1, 0x2])]);
        assert_ne!(one, two, "should not equal");
    }

    //"Attributes values"
    {
        let a = message_of(&[(0x1, &[0x1, 0x2]), (0x1, &[0x1, 0x2])]);
        let b = message_of(&[(0x1, &[0x1, 0x2]), (0x1, &[0x1, 0x1])]);
        assert_ne!(a, b, "should not equal");
    }

    //"Same attributes at other offsets"
    {
        let mut b = message_of(&[(0x7, &[9]), (0x1, &[0x1, 0x2])]);
        b.pop_attribute();
        b.pop_attribute();
        b.add(AttrType(0x1), &[0x1, 0x2]);
        assert_eq!(a, b, "equality reads the values, not where they sit");
    }

    Ok(())
}

#[test]
fn test_message_grow() -> Result<()> {
    let mut m = Message::new();
    m.grow(512, false);
    assert_eq!(m.raw.len(), 512, "Bad length {}", m.raw.len());

    Ok(())
}

#[test]
fn test_message_grow_smaller() -> Result<()> {
    let mut m = Message::new();
    m.grow(2, false);
    assert!(m.raw.capacity() >= 20, "Bad capacity {}", m.raw.capacity());

    assert!(m.raw.len() >= 20, "Bad length {}", m.raw.len());

    Ok(())
}

#[test]
fn test_message_string() -> Result<()> {
    let m = Message::new();
    assert_ne!(m.to_string(), "", "bad string");

    Ok(())
}

#[test]
fn test_is_message() -> Result<()> {
    let mut m = Message::new();
    let a = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: "software".to_owned(),
    };
    a.add_to(&mut m)?;
    m.write_header();

    let tests = vec![
        (vec![], false),                           // 0
        (vec![1, 2, 3], false),                    // 1
        (vec![1, 2, 4], false),                    // 2
        (vec![1, 2, 4, 5, 6, 7, 8, 9, 20], false), // 3
        (m.raw.to_vec(), true),                    // 5
        (
            vec![
                0, 0, 0, 0, 33, 18, 164, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            true,
        ), // 6
    ];

    for (input, output) in tests {
        let got = is_stun_message(&input);
        assert_eq!(got, output, "IsMessage({input:?}) {got} != {output}");
    }

    Ok(())
}

#[test]
fn test_message_contains() -> Result<()> {
    let mut m = Message::new();
    m.add(ATTR_SOFTWARE, "value".as_bytes());

    assert!(m.contains(ATTR_SOFTWARE), "message should contain software");
    assert!(!m.contains(ATTR_NONCE), "message should not contain nonce");

    Ok(())
}

#[test]
fn test_message_full_size() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0])),
        Box::new(TextAttribute::new(
            ATTR_SOFTWARE,
            "webrtc-rs/stun".to_owned(),
        )),
        Box::new(MessageIntegrity::new_long_term_integrity_with_provider(
            "username".to_owned(),
            "realm".to_owned(),
            "password".to_owned(),
            crypto::default_provider()
                .expect("a built-in provider is enabled for tests")
                .crypto(),
        )?),
        Box::new(FINGERPRINT),
    ])?;
    let l = m.raw.len();
    m.raw = m.raw[..l - 10].to_vec();

    let mut decoder = Message::new();
    let l = m.raw.len();
    decoder.raw = m.raw[..l - 10].to_vec();
    let result = decoder.decode();
    assert!(result.is_err(), "decode on truncated buffer should error");

    Ok(())
}

#[test]
fn test_message_clone_to() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0])),
        Box::new(TextAttribute::new(
            ATTR_SOFTWARE,
            "webrtc-rs/stun".to_owned(),
        )),
        Box::new(MessageIntegrity::new_long_term_integrity_with_provider(
            "username".to_owned(),
            "realm".to_owned(),
            "password".to_owned(),
            crypto::default_provider()
                .expect("a built-in provider is enabled for tests")
                .crypto(),
        )?),
        Box::new(FINGERPRINT),
    ])?;
    m.encode();

    let mut b = Message::new();
    m.clone_to(&mut b)?;
    assert_eq!(b, m, "not equal");

    //TODO: Corrupting m and checking that b is not corrupted.
    /*let (mut s, ok) = b.attributes.get(ATTR_SOFTWARE);
    assert!(ok, "no software attribute");
    s.value[0] = b'k';
    s.add_to(&mut b)?;
    assert_ne!(b, m, "should not be equal");*/

    Ok(())
}

#[test]
fn test_message_add_to() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0])),
        Box::new(FINGERPRINT),
    ])?;
    m.encode();

    let mut b = Message::new();
    m.clone_to(&mut b)?;

    m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 2, 0]);
    assert_ne!(b, m, "should not be equal");

    m.add_to(&mut b)?;
    assert_eq!(b, m, "should be equal");

    Ok(())
}

#[test]
fn test_decode() -> Result<()> {
    let mut m = Message::new();
    m.typ = MessageType {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
    };
    m.transaction_id = TransactionId::new();
    m.add(ATTR_ERROR_CODE, &[0xff, 0xfe, 0xfa]);
    m.write_header();

    let mut m_decoded = Message::new();
    m_decoded.raw.clear();
    m_decoded.raw.extend_from_slice(&m.raw);
    m_decoded.decode()?;
    assert_eq!(
        m_decoded, m,
        "decoded result is not equal to encoded message"
    );

    Ok(())
}

#[test]
fn test_message_marshal_binary() -> Result<()> {
    let mut m = Message::new();
    m.build(&[
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "software".to_owned())),
        Box::new(XorMappedAddress {
            ip: "213.1.223.5".parse().unwrap(),
            port: 0,
        }),
    ])?;

    let mut data = m.marshal_binary()?;
    // Reset m.Raw to check retention.
    for i in 0..m.raw.len() {
        m.raw[i] = 0;
    }
    m.unmarshal_binary(&data)?;

    // Reset data to check retention.
    #[allow(clippy::needless_range_loop)]
    for i in 0..data.len() {
        data[i] = 0;
    }

    m.decode()?;

    Ok(())
}

/// Decoding into a long-lived message reuses its attribute slots; whatever was in them before
/// must never leak into the next message.
#[test]
fn test_decode_into_reused_message_never_leaks_previous_attributes() -> Result<()> {
    let build = |attrs: Vec<(AttrType, &str)>| -> Result<Vec<u8>> {
        let mut m = Message::default();
        let mut setters: Vec<Box<dyn Setter>> =
            vec![Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)];
        for (typ, text) in attrs {
            setters.push(Box::new(TextAttribute::new(typ, text.to_owned())));
        }
        m.build(&setters)?;
        Ok(m.raw.clone())
    };
    let three = build(vec![
        (ATTR_USERNAME, "alice:bob"),
        (ATTR_REALM, "example.org"),
        (ATTR_SOFTWARE, "a long software string"),
    ])?;
    let one = build(vec![(ATTR_USERNAME, "x")])?;
    let none = build(vec![])?;

    let mut reused = Message::default();
    for raw in [&three, &one, &none, &three, &one] {
        reused.write(raw)?;
        let mut fresh = Message::default();
        fresh.write(raw)?;
        assert_eq!(reused.attributes, fresh.attributes);
        assert_eq!(reused.length, fresh.length);
    }
    assert_eq!(reused.get_value(ATTR_USERNAME)?, b"x");
    assert!(reused.get_value(ATTR_REALM).is_err());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Attribute value buffers are recycled across `reset`; none of that may show.

fn build(m: &mut Message, attrs: &[(u16, &[u8])]) {
    for (typ, value) in attrs {
        m.add(AttrType(*typ), value);
    }
    m.write_header();
}

#[test]
fn test_reset_recycles_value_buffers_without_leaking_old_bytes() {
    let mut reused = Message::new();
    // A long value first, so the buffer it leaves behind is bigger than what follows.
    build(
        &mut reused,
        &[(0x0006, b"a-rather-long-username"), (0x0014, b"realm")],
    );
    reused.reset();
    build(&mut reused, &[(0x0006, b"ab"), (0x0015, b"n")]);

    let mut fresh = Message::new();
    build(&mut fresh, &[(0x0006, b"ab"), (0x0015, b"n")]);

    assert_eq!(reused.attributes.len(), 2);
    let found: Vec<_> = reused
        .iter_attributes()
        .map(|a| (a.typ.0, a.value))
        .collect();
    assert_eq!(found, [(0x0006, &b"ab"[..]), (0x0015, &b"n"[..])]);
    assert_eq!(
        reused.raw[..],
        fresh.raw[..],
        "the encoding is the same bytes"
    );
    assert_eq!(reused, fresh);
}

#[test]
fn test_padding_after_a_reset_is_zero() {
    // The encoding's padding bytes must not be whatever the buffer held before.
    let mut m = Message::new();
    build(&mut m, &[(0x0006, &[0xff; 9])]);
    m.reset();
    build(&mut m, &[(0x0006, &[0xaa; 5])]);
    let value_start = MESSAGE_HEADER_SIZE + ATTRIBUTE_HEADER_SIZE;
    assert_eq!(&m.raw[value_start..value_start + 5], &[0xaa; 5]);
    assert_eq!(&m.raw[value_start + 5..value_start + 8], &[0, 0, 0]);
    assert_eq!(m.length, (ATTRIBUTE_HEADER_SIZE + 8) as u32);
}

#[test]
fn test_reset_keeps_the_buffers_for_the_next_message() {
    let mut m = Message::new();
    build(&mut m, &[(0x0006, b"u"), (0x0014, b"r"), (0x0015, b"n")]);
    let (raw, spans) = (m.raw.capacity(), m.attributes.0.capacity());
    for _ in 0..100 {
        m.reset();
        build(&mut m, &[(0x0006, b"u"), (0x0014, b"r"), (0x0015, b"n")]);
    }
    assert_eq!((m.raw.capacity(), m.attributes.0.capacity()), (raw, spans));
}

#[test]
fn test_pop_attribute_takes_back_the_last_one() -> Result<()> {
    let mut m = message_of(&[(0x0006, b"user"), (0x0014, b"odd")]);
    m.write_header();
    let one = message_of(&[(0x0006, b"user")]);
    assert_eq!(m.pop_attribute(), Some(AttrType(0x0014)));
    assert_eq!(m.length, one.length);
    assert_eq!(m.raw.len(), MESSAGE_HEADER_SIZE + m.length as usize);
    assert_eq!(m.raw[2..4], (m.length as u16).to_be_bytes());
    assert_eq!(m.get_value(AttrType(0x0006))?, b"user");
    assert!(!m.contains(AttrType(0x0014)));
    assert_eq!(m.pop_attribute(), Some(AttrType(0x0006)));
    assert_eq!(m.pop_attribute(), None);
    assert_eq!(m.length, 0);
    Ok(())
}

#[test]
fn test_encode_closes_the_gaps_decode_left() -> Result<()> {
    // MESSAGE-INTEGRITY, then a USERNAME that decode drops, then FINGERPRINT.
    let mut m = Message::new();
    m.add(ATTR_MESSAGE_INTEGRITY, &[7; 20]);
    m.add(ATTR_USERNAME, b"dropped");
    m.add(ATTR_FINGERPRINT, &[1, 2, 3, 4]);
    m.write_header();
    let mut decoded = Message::new();
    decoded.unmarshal_binary(&m.raw)?;
    assert_eq!(decoded.attributes.len(), 2);

    decoded.encode();
    let mut again = Message::new();
    again.unmarshal_binary(&decoded.raw)?;
    assert_eq!(again, decoded);
    assert_eq!(again.get_value(ATTR_FINGERPRINT)?, [1, 2, 3, 4]);
    assert_eq!(decoded.raw.len(), MESSAGE_HEADER_SIZE + 24 + 8);
    Ok(())
}

#[test]
fn test_decode_after_a_build_cycle_is_unaffected() -> Result<()> {
    let mut m = Message::new();
    build(&mut m, &[(0x0006, b"user"), (0x0014, b"realm")]);
    m.reset();
    build(&mut m, &[(0x0015, b"nonce")]);

    let mut decoded = Message::new();
    decoded.raw = m.raw.clone();
    decoded.decode()?;
    assert_eq!(decoded.attributes.0.len(), 1);
    assert_eq!(decoded.get_value(AttrType(0x0015))?, b"nonce");
    Ok(())
}
