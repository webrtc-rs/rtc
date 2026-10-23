use super::*;

#[test]
fn test_generic_fmtp_parse() {
    let tests: Vec<(&str, &str, Box<dyn Fmtp>)> = vec![
        (
            "OneParam",
            "key-name=value",
            Box::new(GenericFmtp {
                mime_type: "generic".to_owned(),
                clock_rate: 0,
                channels: 0,
                parameters: [("key-name".to_owned(), "value".to_owned())]
                    .iter()
                    .cloned()
                    .collect(),
            }),
        ),
        (
            "OneParamWithWhiteSpeces",
            "\tkey-name=value ",
            Box::new(GenericFmtp {
                mime_type: "generic".to_owned(),
                clock_rate: 0,
                channels: 0,
                parameters: [("key-name".to_owned(), "value".to_owned())]
                    .iter()
                    .cloned()
                    .collect(),
            }),
        ),
        (
            "TwoParams",
            "key-name=value;key2=value2",
            Box::new(GenericFmtp {
                mime_type: "generic".to_owned(),
                clock_rate: 0,
                channels: 0,
                parameters: [
                    ("key-name".to_owned(), "value".to_owned()),
                    ("key2".to_owned(), "value2".to_owned()),
                ]
                .iter()
                .cloned()
                .collect(),
            }),
        ),
        (
            "TwoParamsWithWhiteSpeces",
            "key-name=value;  \n\tkey2=value2 ",
            Box::new(GenericFmtp {
                mime_type: "generic".to_owned(),
                clock_rate: 0,
                channels: 0,
                parameters: [
                    ("key-name".to_owned(), "value".to_owned()),
                    ("key2".to_owned(), "value2".to_owned()),
                ]
                .iter()
                .cloned()
                .collect(),
            }),
        ),
    ];

    for (name, input, expected) in tests {
        let f = parse("generic", 0, 0, input);
        assert_eq!(&f, &expected, "{name} failed");

        assert_eq!(f.mime_type(), "generic");
    }
}

#[test]
fn test_generic_fmtp_compare() {
    let consist_string: HashMap<bool, String> = [
        (true, "consist".to_owned()),
        (false, "inconsist".to_owned()),
    ]
    .iter()
    .cloned()
    .collect();

    let tests = vec![
        (
            "Equal",
            "key1=value1;key2=value2;key3=value3",
            "key1=value1;key2=value2;key3=value3",
            true,
        ),
        (
            "EqualWithWhitespaceVariants",
            "key1=value1;key2=value2;key3=value3",
            "  key1=value1;  \nkey2=value2;\t\nkey3=value3",
            true,
        ),
        (
            "EqualWithCase",
            "key1=value1;key2=value2;key3=value3",
            "key1=value1;key2=Value2;Key3=value3",
            true,
        ),
        (
            "OneHasExtraParam",
            "key1=value1;key2=value2;key3=value3",
            "key1=value1;key2=value2;key3=value3;key4=value4",
            true,
        ),
        (
            "Inconsistent",
            "key1=value1;key2=value2;key3=value3",
            "key1=value1;key2=different_value;key3=value3",
            false,
        ),
        (
            "Inconsistent_OneHasExtraParam",
            "key1=value1;key2=value2;key3=value3;key4=value4",
            "key1=value1;key2=different_value;key3=value3",
            false,
        ),
    ];

    for (name, a, b, consist) in tests {
        let check = |a, b| {
            let aa = parse("", 0, 0, a);
            let bb = parse("", 0, 0, b);

            // test forward case here
            let c = aa.match_fmtp(&*bb);
            assert_eq!(
                c,
                consist,
                "{}: '{}' and '{}' are expected to be {:?}, but treated as {:?}",
                name,
                a,
                b,
                consist_string.get(&consist),
                consist_string.get(&c),
            );

            // test reverse case here
            let c = bb.match_fmtp(&*aa);
            assert_eq!(
                c,
                consist,
                "{}: '{}' and '{}' are expected to be {:?}, but treated as {:?}",
                name,
                a,
                b,
                consist_string.get(&consist),
                consist_string.get(&c),
            );
        };

        check(a, b);
    }
}

#[test]
fn test_generic_fmtp_compare_mime_type_case_mismatch() {
    let a = parse("video/vp8", 0, 0, "");
    let b = parse("video/VP8", 0, 0, "");

    assert!(
        b.match_fmtp(&*a),
        "fmtp lines should match even if they use different casing"
    );
}

#[test]
fn test_generic_fmtp_clock_rate_and_channels() {
    // pion `TestMatch`: an omitted channel count is inferred, different clock rates or channel
    // counts never match, and the parameters must still agree.
    let m = |a: (u32, u16, &str), b: (u32, u16, &str)| {
        let (a, b) = (
            parse("generic", a.0, a.1, a.2),
            parse("generic", b.0, b.1, b.2),
        );
        let forward = a.match_fmtp(&*b);
        assert_eq!(forward, b.match_fmtp(&*a));
        forward
    };
    assert!(m((0, 1, "k=v"), (0, 0, "k=v")), "inferred channels");
    assert!(!m((90000, 0, ""), (48000, 0, "")), "different clock rate");
    assert!(!m((90000, 2, ""), (90000, 1, "")), "different channels");
    assert!(!m((0, 0, "k=a"), (0, 0, "k=b")), "different parameters");
    // The telephone-event clock rates are different formats.
    let ev = |rate| parse("audio/telephone-event", rate, 0, "0-16");
    assert!(!ev(8000).match_fmtp(&*ev(48000)));
    assert!(ev(8000).match_fmtp(&*ev(8000)));
}

#[test]
fn test_fmtp_defaults() {
    // pion `TestDefaults`.
    for (mime, clock_rate, channels) in [
        ("audio/opus", 48000, 2),
        ("audio/OPUS", 48000, 2),
        ("audio/pcmu", 8000, 1),
        ("audio/PCMA", 8000, 1),
        ("audio/multiopus", 90000, 1),
        ("video/vp8", 90000, 0),
    ] {
        assert_eq!(default_clock_rate(mime), clock_rate, "{mime}");
        assert_eq!(default_channels(mime), channels, "{mime}");
    }
}
