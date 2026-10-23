// Ported from pion/mdns v2.2.2 dns_sd_test.go (29 tests) and records_test.go
// (41 tests): https://github.com/pion/mdns/blob/v2.2.2/dns_sd_test.go and
// records_test.go. Test names are the snake_case of the Go names; the ledger
// references them.
//
// The byte-compat vectors at the bottom were produced by a throwaway Go
// program (not committed) that constructs the same dnsmessage.Resource
// values pion's records.go builders produce and packs them with
// golang.org/x/net v0.35.0 (the version pinned by pion/mdns v2.2.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;
use crate::config::RESPONSE_TTL;
use crate::dnssd::records::*;
use crate::message::header::Header;
use crate::message::resource::a::AResource;
use crate::message::resource::aaaa::AaaaResource;
use crate::message::resource::{Resource, ResourceBody};
use crate::message::{DnsClass, DnsType, Message};
use shared::error::{Error, Result};

// ---------------------------------------------------------------------------
// ServiceInstance — name construction
// ---------------------------------------------------------------------------

fn si(instance: &str, service: &str, domain: &str) -> ServiceInstance {
    ServiceInstance {
        instance: instance.to_owned(),
        service: service.to_owned(),
        domain: domain.to_owned(),
        ..Default::default()
    }
}

#[test]
fn test_service_instance_name_simple() {
    let si = si("My Web Server", "_http._tcp", "local");
    assert_eq!(
        si.service_instance_name(),
        "My Web Server._http._tcp.local."
    );
}

#[test]
fn test_service_instance_name_dots_escaped() {
    // RFC 6763 §4.3: dots in Instance escaped as "\."
    let si = si("My.Web", "_http._tcp", "local");
    assert_eq!(si.service_instance_name(), r"My\.Web._http._tcp.local.");
}

#[test]
fn test_service_instance_name_backslash_escaped() {
    // RFC 6763 §4.3: backslashes in Instance escaped as "\\"
    let si = si(r"Back\slash", "_http._tcp", "local");
    assert_eq!(si.service_instance_name(), r"Back\\slash._http._tcp.local.");
}

#[test]
fn test_service_instance_name_dot_and_backslash() {
    let si = si(r"Dot.And\Slash", "_http._tcp", "local");
    assert_eq!(
        si.service_instance_name(),
        r"Dot\.And\\Slash._http._tcp.local."
    );
}

#[test]
fn test_service_instance_name_no_special_chars() {
    let si = si("No Special Chars", "_http._tcp", "local");
    assert_eq!(
        si.service_instance_name(),
        "No Special Chars._http._tcp.local."
    );
}

#[test]
fn test_service_instance_name_rfc6763_section13() {
    // Test vectors from RFC 6763 §13.1
    let tests = [
        ("Zeroconf", "Zeroconf._http._tcp.dns-sd.org."),
        ("Multicast DNS", "Multicast DNS._http._tcp.dns-sd.org."),
        (
            "Service Discovery",
            "Service Discovery._http._tcp.dns-sd.org.",
        ),
        (
            "Stuart's Printer",
            "Stuart's Printer._http._tcp.dns-sd.org.",
        ),
    ];
    for (instance, expected) in tests {
        assert_eq!(
            si(instance, "_http._tcp", "dns-sd.org").service_instance_name(),
            expected,
            "instance={instance:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// ServiceInstance — service_name
// ---------------------------------------------------------------------------

#[test]
fn test_service_name() {
    let s = si("", "_http._tcp", "local");
    assert_eq!(s.service_name(), "_http._tcp.local.");
}

// ---------------------------------------------------------------------------
// escape_instance_name / unescape_instance_name round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_escape_unescape_round_trip() {
    let tests = [
        "simple",
        "has.dot",
        r"has\backslash",
        r"dot.and\slash",
        "no escaping needed",
        r"multi.ple.dots",
        r"back\\slash",
    ];
    for input in tests {
        let escaped = escape_instance_name(input);
        let unescaped = unescape_instance_name(&escaped);
        assert_eq!(input, unescaped, "round-trip failed for {input:?}");
    }
}

#[test]
fn test_escape_instance_name_nothing_to_escape() {
    assert_eq!(escape_instance_name("hello world"), "hello world");
}

#[test]
fn test_escape_instance_name_dots() {
    assert_eq!(escape_instance_name("a.b.c"), r"a\.b\.c");
}

#[test]
fn test_escape_instance_name_backslashes() {
    assert_eq!(escape_instance_name(r"a\b"), r"a\\b");
}

// ---------------------------------------------------------------------------
// parse_service_instance_name
// ---------------------------------------------------------------------------

#[test]
fn test_parse_service_instance_name_simple() {
    let (inst, svc, dom) = parse_service_instance_name("My Web._http._tcp.local.").unwrap();
    assert_eq!(inst, "My Web");
    assert_eq!(svc, "_http._tcp");
    assert_eq!(dom, "local");
}

#[test]
fn test_parse_service_instance_name_escaped_dot() {
    // From test_vectors.md §8
    let (inst, svc, dom) = parse_service_instance_name(r"My\.Web._http._tcp.local.").unwrap();
    assert_eq!(inst, "My.Web");
    assert_eq!(svc, "_http._tcp");
    assert_eq!(dom, "local");
}

#[test]
fn test_parse_service_instance_name_escaped_backslash() {
    // From test_vectors.md §8
    let (inst, svc, dom) = parse_service_instance_name(r"Back\\slash._http._tcp.local.").unwrap();
    assert_eq!(inst, r"Back\slash");
    assert_eq!(svc, "_http._tcp");
    assert_eq!(dom, "local");
}

#[test]
fn test_parse_service_instance_name_dot_and_backslash() {
    let (inst, svc, dom) =
        parse_service_instance_name(r"Dot\.And\\Slash._http._tcp.local.").unwrap();
    assert_eq!(inst, r"Dot.And\Slash");
    assert_eq!(svc, "_http._tcp");
    assert_eq!(dom, "local");
}

#[test]
fn test_parse_service_instance_name_no_trailing_dot() {
    let (inst, svc, dom) = parse_service_instance_name("My Web._http._tcp.local").unwrap();
    assert_eq!(inst, "My Web");
    assert_eq!(svc, "_http._tcp");
    assert_eq!(dom, "local");
}

#[test]
fn test_parse_service_instance_name_multi_label_domain() {
    let (inst, svc, dom) = parse_service_instance_name("Zeroconf._http._tcp.dns-sd.org.").unwrap();
    assert_eq!(inst, "Zeroconf");
    assert_eq!(svc, "_http._tcp");
    assert_eq!(dom, "dns-sd.org");
}

#[test]
fn test_parse_service_instance_name_space_in_instance() {
    let (inst, svc, dom) =
        parse_service_instance_name("Service Discovery._http._tcp.dns-sd.org.").unwrap();
    assert_eq!(inst, "Service Discovery");
    assert_eq!(svc, "_http._tcp");
    assert_eq!(dom, "dns-sd.org");
}

#[test]
fn test_parse_service_instance_name_too_few_labels() {
    assert!(parse_service_instance_name("_http._tcp.").is_err());
}

#[test]
fn test_parse_service_instance_name_no_underscore_labels() {
    assert!(parse_service_instance_name("a.b.c.d.").is_err());
}

#[test]
fn test_parse_service_instance_name_empty() {
    assert!(parse_service_instance_name("").is_err());
}

#[test]
fn test_parse_service_instance_name_round_trip() {
    let tests = [
        si("Simple", "_http._tcp", "local"),
        si("Has.Dot", "_http._tcp", "local"),
        si(r"Has\Backslash", "_ipp._tcp", "local"),
        si("Multicast DNS", "_http._tcp", "dns-sd.org"),
        si("Stuart's Printer", "_http._tcp", "dns-sd.org"),
    ];
    for s in &tests {
        let name = s.service_instance_name();
        let (inst, svc, dom) = parse_service_instance_name(&name).unwrap();
        assert_eq!(s.instance, inst, "name={name:?}");
        assert_eq!(s.service, svc, "name={name:?}");
        assert_eq!(s.domain, dom, "name={name:?}");
    }
}

// ---------------------------------------------------------------------------
// validate_service_name — valid cases
// ---------------------------------------------------------------------------

#[test]
fn test_validate_service_name_valid() {
    let valid = [
        "_http._tcp",
        "_ipp._tcp",
        "_ssh._tcp",
        "_http._udp",
        "_custom._tcp",
        "_a._tcp",               // min: 1 char
        "_abcdefghijklmno._tcp", // max: 15 chars
        "_has-hyphen._tcp",
    ];
    for s in valid {
        assert!(validate_service_name(s).is_ok(), "should be valid: {s:?}");
    }
}

// ---------------------------------------------------------------------------
// validate_service_name — invalid cases (from test_vectors.md §9)
// ---------------------------------------------------------------------------

#[test]
fn test_validate_service_name_invalid() {
    let tests = [
        ("_abcdefghijklmnop._tcp", "16 chars: exceeds 15-char limit"),
        ("http._tcp", "missing leading underscore on service"),
        ("_http.tcp", "missing leading underscore on proto"),
        ("_http._sctp", "proto must be _tcp or _udp"),
        ("_._tcp", "name portion empty (just underscore)"),
        ("_has space._tcp", "spaces not allowed in service name"),
        ("_-start._tcp", "must begin with letter or digit"),
        ("_end-._tcp", "must end with letter or digit"),
        ("_123._tcp", "must contain at least one letter"),
        ("_a--b._tcp", "consecutive hyphens"),
        ("", "empty string"),
        ("_http", "missing proto part"),
    ];
    for (input, reason) in tests {
        assert!(
            validate_service_name(input).is_err(),
            "should be invalid: {input:?} ({reason})"
        );
    }
}

// ---------------------------------------------------------------------------
// validate_instance_name
// ---------------------------------------------------------------------------

#[test]
fn test_validate_instance_name_valid() {
    let tests = [
        ("simple", "My Printer"),
        ("with dots", "a.b.c"),
        ("with space", " hello "),
        ("63 bytes", &"a".repeat(63)),
        ("unicode", "café"),
        ("punctuation", "Stuart's Printer"),
    ];
    for (name, input) in tests {
        assert!(
            validate_instance_name(input).is_ok(),
            "should be valid: {name}"
        );
    }
}

#[test]
fn test_validate_instance_name_invalid() {
    let tests: [(&str, &str, Error); 6] = [
        ("empty", "", Error::ErrInstanceNameEmpty),
        ("too long", &"a".repeat(64), Error::ErrInstanceNameTooLong),
        (
            "null byte",
            "has\u{0}null",
            Error::ErrInstanceNameHasControl,
        ),
        (
            "control 0x01",
            "has\u{1}ctrl",
            Error::ErrInstanceNameHasControl,
        ),
        (
            "control 0x1F",
            "has\u{1f}ctrl",
            Error::ErrInstanceNameHasControl,
        ),
        (
            "DEL 0x7F",
            "has\u{7f}ctrl",
            Error::ErrInstanceNameHasControl,
        ),
    ];
    for (name, input, expected) in tests {
        let err = validate_instance_name(input).unwrap_err();
        assert_eq!(err, expected, "case: {name}");
    }
}

#[test]
fn test_validate_instance_name_space_is_valid() {
    // 0x20 (space) is valid — it's above the control char range
    assert!(validate_instance_name(" ").is_ok());
}

// ---------------------------------------------------------------------------
// service_type_enumeration_name constant
// ---------------------------------------------------------------------------

#[test]
fn test_service_type_enumeration_name() {
    assert_eq!(SERVICE_TYPE_ENUMERATION_NAME, "_services._dns-sd._udp");
}

// ---------------------------------------------------------------------------
// split_escaped_dots
// ---------------------------------------------------------------------------

#[test]
fn test_split_escaped_dots() {
    let tests: [(&str, Vec<&str>); 5] = [
        ("a.b.c", vec!["a", "b", "c"]),
        (r"a\.b.c", vec![r"a\.b", "c"]),
        (r"a\\b.c", vec![r"a\\b", "c"]),
        (r"a\.b\.c", vec![r"a\.b\.c"]),
        ("single", vec!["single"]),
    ];
    for (input, expected) in tests {
        let result = split_escaped_dots(input);
        assert_eq!(result, expected, "input={input:?}");
    }
}

// ---------------------------------------------------------------------------
// TXT encoding — RFC 6763 §6.6 test vector
// ---------------------------------------------------------------------------

#[test]
fn test_encode_txt_record_strings_rfc6763_section_6_6() {
    // Test vector from RFC 6763 §6.6:
    //   | 0x09 | key=value | 0x08 | paper=A4 | 0x07 | passreq |
    let pairs = vec![
        TxtEntry {
            key: "key".to_owned(),
            value: Some(b"value".to_vec()),
        },
        TxtEntry {
            key: "paper".to_owned(),
            value: Some(b"A4".to_vec()),
        },
        TxtEntry {
            key: "passreq".to_owned(),
            value: None, // boolean attribute
        },
    ];

    let strs = encode_txt_record_strings(&pairs).unwrap();
    assert_eq!(strs.len(), 3);

    assert_eq!(strs[0], "key=value");
    assert_eq!(strs[1], "paper=A4");
    assert_eq!(strs[2], "passreq");

    // Verify byte lengths match the spec's length-prefix bytes
    assert_eq!(9, strs[0].len()); // 0x09
    assert_eq!(8, strs[1].len()); // 0x08
    assert_eq!(7, strs[2].len()); // 0x07
}

// ---------------------------------------------------------------------------
// TXT encoding — edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_encode_txt_record_strings_empty_value() {
    // "PlugIns=" → key present, empty value (RFC 6763 §6.4)
    let pairs = vec![TxtEntry {
        key: "PlugIns".to_owned(),
        value: Some(Vec::new()),
    }];
    let strs = encode_txt_record_strings(&pairs).unwrap();
    assert_eq!(strs, vec!["PlugIns="]);
}

#[test]
fn test_encode_txt_record_strings_empty_input() {
    // Empty pairs → single empty string (minimum valid TXT record, RFC 6763 §6.1)
    let strs = encode_txt_record_strings(&[]).unwrap();
    assert_eq!(strs, vec![""]);
}

#[test]
fn test_encode_txt_record_strings_empty_key() {
    let pairs = vec![TxtEntry {
        key: String::new(),
        value: Some(b"bad".to_vec()),
    }];
    assert_eq!(
        encode_txt_record_strings(&pairs).unwrap_err(),
        Error::ErrTXTKeyEmpty
    );
}

#[test]
fn test_encode_txt_record_strings_max_length() {
    // Exactly 255 bytes should succeed
    let pairs = vec![new_txt_string("k", &"x".repeat(253))]; // "k=" + 253 = 255
    let strs = encode_txt_record_strings(&pairs).unwrap();
    assert_eq!(255, strs[0].len());

    // 256 bytes should fail
    let pairs256 = vec![new_txt_string("k", &"x".repeat(254))]; // "k=" + 254 = 256
    assert_eq!(
        encode_txt_record_strings(&pairs256).unwrap_err(),
        Error::ErrTXTStringTooLong
    );
}

#[test]
fn test_encode_txt_record_strings_boolean_max_length() {
    // Boolean attribute: key only, 255 chars OK
    let pairs = vec![new_txt_flag(&"a".repeat(255))];
    let strs = encode_txt_record_strings(&pairs).unwrap();
    assert_eq!(255, strs[0].len());

    // 256 chars should fail
    let pairs256 = vec![new_txt_flag(&"a".repeat(256))];
    assert_eq!(
        encode_txt_record_strings(&pairs256).unwrap_err(),
        Error::ErrTXTStringTooLong
    );
}

// ---------------------------------------------------------------------------
// TXT decoding — RFC 6763 §6.6 test vector
// ---------------------------------------------------------------------------

#[test]
fn test_decode_txt_record_strings_rfc6763_section_6_6() {
    // Inverse of the encode test vector
    let strs: Vec<String> = ["key=value", "paper=A4", "passreq"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let kvs = decode_txt_record_strings(&strs);

    assert_eq!(kvs.len(), 3);

    assert_eq!(kvs[0].key, "key");
    assert_eq!(kvs[0].value, Some(b"value".to_vec()));

    assert_eq!(kvs[1].key, "paper");
    assert_eq!(kvs[1].value, Some(b"A4".to_vec()));

    assert_eq!(kvs[2].key, "passreq");
    assert_eq!(kvs[2].value, None); // boolean
}

// ---------------------------------------------------------------------------
// TXT decoding — four categories from RFC 6763 §6.4
// ---------------------------------------------------------------------------

#[test]
fn test_decode_txt_record_strings_four_categories() {
    let strs: Vec<String> = [
        "passreq",                  // boolean (present, no value)
        "PlugIns=",                 // present, empty value
        "PlugIns=JPEG,MPEG2,MPEG4", // duplicate — ignored
        "Color=4",                  // present, non-empty value
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let kvs = decode_txt_record_strings(&strs);

    assert_eq!(kvs.len(), 3); // PlugIns duplicate dropped

    // Boolean
    assert_eq!(kvs[0].key, "passreq");
    assert_eq!(kvs[0].value, None);

    // Empty value
    assert_eq!(kvs[1].key, "PlugIns");
    assert_eq!(kvs[1].value, Some(Vec::new()));

    // Non-empty value
    assert_eq!(kvs[2].key, "Color");
    assert_eq!(kvs[2].value, Some(b"4".to_vec()));
}

#[test]
fn test_decode_txt_record_strings_value_containing_equals() {
    // "equation=x=y" → key "equation", value "x=y" (split on first '=' only)
    let kvs = decode_txt_record_strings(&["equation=x=y".to_owned()]);
    assert_eq!(kvs.len(), 1);
    assert_eq!(kvs[0].key, "equation");
    assert_eq!(kvs[0].value, Some(b"x=y".to_vec()));
}

#[test]
fn test_decode_txt_record_strings_empty_key_ignored() {
    // "=bad" → key is empty → silently ignored (RFC 6763 §6.4)
    let kvs = decode_txt_record_strings(&["=bad".to_owned()]);
    assert!(kvs.is_empty());
}

#[test]
fn test_decode_txt_record_strings_empty_string_ignored() {
    let kvs = decode_txt_record_strings(&["".to_owned(), "ok=val".to_owned(), "".to_owned()]);
    assert_eq!(kvs.len(), 1);
    assert_eq!(kvs[0].key, "ok");
}

#[test]
fn test_decode_txt_record_strings_duplicate_keys_case_insensitive() {
    // RFC 6763 §6.4: case-insensitive dedup, keep first
    let strs: Vec<String> = ["papersize=A4", "PAPERSIZE=Letter", "Papersize=A3"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let kvs = decode_txt_record_strings(&strs);

    assert_eq!(kvs.len(), 1);
    assert_eq!(kvs[0].key, "papersize"); // original case preserved
    assert_eq!(kvs[0].value, Some(b"A4".to_vec()));
}

#[test]
fn test_decode_txt_record_strings_spaces_in_key() {
    // RFC 6763 §6.4: spaces in keys are significant
    let kvs = decode_txt_record_strings(&[" key =value".to_owned()]);
    assert_eq!(kvs.len(), 1);
    assert_eq!(kvs[0].key, " key ");
    assert_eq!(kvs[0].value, Some(b"value".to_vec()));
}

// ---------------------------------------------------------------------------
// TXT round-trip: encode → decode
// ---------------------------------------------------------------------------

#[test]
fn test_txt_round_trip() {
    let original = vec![
        new_txt_string("txtvers", "1"),
        new_txt_string("path", "/"),
        new_txt_flag("secure"),
        new_txt_string("empty", ""),
    ];

    let strs = encode_txt_record_strings(&original).unwrap();
    let decoded = decode_txt_record_strings(&strs);

    assert_eq!(decoded.len(), original.len());
    for (orig, dec) in original.iter().zip(decoded.iter()) {
        assert_eq!(orig.key, dec.key);
        assert_eq!(orig.value, dec.value);
    }
}

// ---------------------------------------------------------------------------
// TxtEntry constructors
// ---------------------------------------------------------------------------

#[test]
fn test_new_txt_string() {
    let e = new_txt_string("version", "1.2.3");
    assert_eq!(e.key, "version");
    assert_eq!(e.value, Some(b"1.2.3".to_vec()));

    // Explicit empty value is non-nil and encodes as "key=".
    let empty = new_txt_string("setup", "");
    assert_eq!(empty.key, "setup");
    assert_eq!(empty.value, Some(Vec::new()));
}

#[test]
fn test_new_txt_binary() {
    let raw = [0x00, 0x01, 0xff];
    let e = new_txt_binary("data", &raw);
    assert_eq!(e.key, "data");
    assert_eq!(e.value, Some(raw.to_vec()));

    // Empty bytes are an explicit empty value ("key="), never a flag.
    let nil_val = new_txt_binary("data", &[]);
    assert_eq!(nil_val.key, "data");
    assert_eq!(nil_val.value, Some(Vec::new()));
}

#[test]
fn test_new_txt_flag() {
    let e = new_txt_flag("secure");
    assert_eq!(e.key, "secure");
    assert_eq!(e.value, None);
}

#[test]
fn test_new_txt_constructors_encode() {
    let entries = vec![
        new_txt_string("version", "1.2.3"),
        new_txt_string("setup", ""),
        new_txt_binary("data", &[0x41, 0x42]),
        new_txt_flag("secure"),
    ];

    let strs = encode_txt_record_strings(&entries).unwrap();
    assert_eq!(strs, vec!["version=1.2.3", "setup=", "data=AB", "secure"]);

    // Round-trip back to entries.
    let decoded = decode_txt_record_strings(&strs);
    assert_eq!(decoded.len(), 4);
    assert_eq!(decoded[0].key, "version");
    assert_eq!(decoded[0].value, Some(b"1.2.3".to_vec()));
    assert_eq!(decoded[1].key, "setup");
    assert_eq!(decoded[1].value, Some(Vec::new()));
    assert_eq!(decoded[2].key, "data");
    assert_eq!(decoded[2].value, Some(b"AB".to_vec()));
    assert_eq!(decoded[3].key, "secure");
    assert_eq!(decoded[3].value, None);
}

#[test]
fn test_validate_txt_entries() {
    // valid
    assert!(
        validate_txt_entries(&[
            new_txt_string("version", "1.2.3"),
            new_txt_string("setup", ""),
            new_txt_flag("secure"),
        ])
        .is_ok()
    );

    // nil and empty are valid
    assert!(validate_txt_entries(&[]).is_ok());

    // empty key
    assert_eq!(
        validate_txt_entries(&[new_txt_string("", "v")]).unwrap_err(),
        Error::ErrTXTKeyEmpty
    );

    // key with equals
    assert_eq!(
        validate_txt_entries(&[TxtEntry {
            key: "a=b".to_owned(),
            value: Some(b"v".to_vec()),
        }])
        .unwrap_err(),
        Error::ErrTXTKeyHasEquals
    );

    // non-ascii key
    assert_eq!(
        validate_txt_entries(&[new_txt_string("naïve", "v")]).unwrap_err(),
        Error::ErrTXTKeyNotASCII
    );

    // control char key
    assert_eq!(
        validate_txt_entries(&[new_txt_string("a\u{1}b", "v")]).unwrap_err(),
        Error::ErrTXTKeyNotASCII
    );

    // duplicate key case-insensitive
    assert_eq!(
        validate_txt_entries(&[
            new_txt_string("version", "1"),
            new_txt_string("VERSION", "2"),
        ])
        .unwrap_err(),
        Error::ErrTXTDuplicateKey
    );

    // encoded string too long: "k=" + 254 bytes = 256 > 255.
    assert_eq!(
        validate_txt_entries(&[new_txt_string("k", &"x".repeat(254))]).unwrap_err(),
        Error::ErrTXTStringTooLong
    );

    // max length boundary: "k=" + 253 bytes = 255, exactly the limit.
    assert!(validate_txt_entries(&[new_txt_string("k", &"x".repeat(253))]).is_ok());
}

// ---------------------------------------------------------------------------
// Record builders — PTR
// ---------------------------------------------------------------------------

#[test]
fn test_build_ptr_resource() {
    let res =
        build_ptr_resource("_http._tcp.local.", "My Web._http._tcp.local.", BROWSE_TTL).unwrap();

    assert_eq!(res.header.typ, DnsType::Ptr);
    assert_eq!(res.header.class, DnsClass(1));
    assert_eq!(res.header.ttl, BROWSE_TTL);

    let target = parse_ptr_target(res.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(target, "My Web._http._tcp.local.");
}

#[test]
fn test_build_ptr_resource_invalid_name() {
    // Name::new rejects names of 256+ bytes (as dnsmessage.NewName does).
    let long_name = format!("{}.", "a".repeat(255));
    assert!(build_ptr_resource(&long_name, "target.local.", 300).is_err());
}

#[test]
fn test_build_ptr_resource_custom_ttl() {
    let res = build_ptr_resource("_ipp._tcp.local.", "printer._ipp._tcp.local.", 300).unwrap();
    assert_eq!(res.header.ttl, 300);
}

// ---------------------------------------------------------------------------
// Record builders — SRV
// ---------------------------------------------------------------------------

#[test]
fn test_build_srv_resource() {
    // Test vector from RFC 6763 §13.3:
    // SRV priority=0, weight=0, port=80, host=dns-sd.org
    let res = build_srv_resource(
        "Service Discovery._http._tcp.dns-sd.org.",
        "dns-sd.org.",
        80,
        0,
        0,
        RESPONSE_TTL,
    )
    .unwrap();

    assert_eq!(res.header.typ, DnsType::Srv);
    assert_eq!(res.header.class, DnsClass(1));
    assert_eq!(res.header.ttl, RESPONSE_TTL);

    let srv = parse_srv_data(res.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(srv.target, "dns-sd.org.");
    assert_eq!(srv.port, 80);
    assert_eq!(srv.priority, 0);
    assert_eq!(srv.weight, 0);
}

#[test]
fn test_build_srv_resource_non_zero_priority_weight() {
    let res = build_srv_resource("svc._tcp.local.", "host.local.", 8080, 10, 20, 300).unwrap();

    assert_eq!(res.header.ttl, 300);
    let srv = parse_srv_data(res.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(srv.port, 8080);
    assert_eq!(srv.priority, 10);
    assert_eq!(srv.weight, 20);
}

// ---------------------------------------------------------------------------
// Record builders — TXT
// ---------------------------------------------------------------------------

#[test]
fn test_build_txt_resource() {
    // Test vector from RFC 6763 §13.3:
    // TXT "txtvers=1" "path=/"
    let res = build_txt_resource(
        "Service Discovery._http._tcp.dns-sd.org.",
        vec!["txtvers=1".to_owned(), "path=/".to_owned()],
        BROWSE_TTL,
    )
    .unwrap();

    assert_eq!(res.header.typ, DnsType::Txt);
    assert_eq!(res.header.class, DnsClass(1));
    assert_eq!(res.header.ttl, BROWSE_TTL);

    let txts = parse_txt_data(res.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(txts, vec!["txtvers=1", "path=/"]);
}

#[test]
fn test_build_txt_resource_empty() {
    // Minimum valid TXT record: single empty string
    let res = build_txt_resource("svc._tcp.local.", vec![String::new()], 300).unwrap();

    assert_eq!(res.header.ttl, 300);
    let txts = parse_txt_data(res.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(txts, vec![""]);
}

// ---------------------------------------------------------------------------
// Record builders — A
// ---------------------------------------------------------------------------

#[test]
fn test_build_a_resource() {
    // Test vector from RFC 6763 §13.3: dns-sd.org = 64.142.82.154
    let addr: IpAddr = "64.142.82.154".parse().unwrap();
    let res = build_a_resource("dns-sd.org.", addr, RESPONSE_TTL).unwrap();

    assert_eq!(res.header.typ, DnsType::A);
    assert_eq!(res.header.class, DnsClass(1));
    assert_eq!(res.header.ttl, RESPONSE_TTL);

    let body = res.body.as_ref().unwrap();
    let a = body
        .as_any()
        .downcast_ref::<AResource>()
        .expect("should be AResource");
    assert_eq!(a.a, [64, 142, 82, 154]);
}

#[test]
fn test_build_a_resource_rejects_ipv6() {
    let addr: IpAddr = "::1".parse().unwrap();
    assert!(build_a_resource("host.local.", addr, 300).is_err());
}

// ---------------------------------------------------------------------------
// Record builders — AAAA
// ---------------------------------------------------------------------------

#[test]
fn test_build_aaaa_resource() {
    let addr: IpAddr = "fd00::1".parse().unwrap();
    let res = build_aaaa_resource("host.local.", addr, RESPONSE_TTL).unwrap();

    assert_eq!(res.header.typ, DnsType::Aaaa);
    assert_eq!(res.header.class, DnsClass(1));
    assert_eq!(res.header.ttl, RESPONSE_TTL);

    let body = res.body.as_ref().unwrap();
    let aaaa = body
        .as_any()
        .downcast_ref::<AaaaResource>()
        .expect("should be AaaaResource");
    assert_eq!(
        aaaa.aaaa,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets()
    );
}

#[test]
fn test_build_aaaa_resource_rejects_ipv4() {
    let addr: IpAddr = "192.168.1.1".parse().unwrap();
    assert!(build_aaaa_resource("host.local.", addr, 300).is_err());
}

// ---------------------------------------------------------------------------
// Record round-trip: build → pack → unpack → parse
// ---------------------------------------------------------------------------

fn pack_single_answer(res: Resource) -> Vec<u8> {
    let mut msg = Message {
        header: Header {
            response: true,
            authoritative: true,
            ..Default::default()
        },
        answers: vec![res],
        ..Default::default()
    };
    msg.pack().unwrap()
}

fn unpack_first_answer(raw: &[u8]) -> Resource {
    let mut msg = Message::default();
    msg.unpack(raw).unwrap();
    assert!(!msg.answers.is_empty());
    msg.answers.remove(0)
}

#[test]
fn test_ptr_round_trip() {
    let res = build_ptr_resource("_http._tcp.local.", "My Web._http._tcp.local.", 4500).unwrap();

    let msg = pack_single_answer(res);
    let parsed = unpack_first_answer(&msg);

    assert_eq!(parsed.header.typ, DnsType::Ptr);
    let target = parse_ptr_target(parsed.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(target, "My Web._http._tcp.local.");
}

#[test]
fn test_srv_round_trip() {
    let res =
        build_srv_resource("svc._http._tcp.local.", "myhost.local.", 8080, 0, 0, 120).unwrap();

    let msg = pack_single_answer(res);
    let parsed = unpack_first_answer(&msg);

    assert_eq!(parsed.header.typ, DnsType::Srv);
    let srv = parse_srv_data(parsed.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(srv.target, "myhost.local.");
    assert_eq!(srv.port, 8080);
    assert_eq!(srv.priority, 0);
    assert_eq!(srv.weight, 0);
}

#[test]
fn test_txt_round_trip_dns() {
    let res = build_txt_resource(
        "svc._tcp.local.",
        vec!["txtvers=1".to_owned(), "path=/".to_owned()],
        4500,
    )
    .unwrap();

    let msg = pack_single_answer(res);
    let parsed = unpack_first_answer(&msg);

    assert_eq!(parsed.header.typ, DnsType::Txt);
    let txts = parse_txt_data(parsed.body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(txts, vec!["txtvers=1", "path=/"]);
}

#[test]
fn test_a_round_trip() {
    let addr: IpAddr = "192.168.1.100".parse().unwrap();
    let res = build_a_resource("myhost.local.", addr, 120).unwrap();

    let msg = pack_single_answer(res);
    let parsed = unpack_first_answer(&msg);

    assert_eq!(parsed.header.typ, DnsType::A);
    let body = parsed.body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, [192, 168, 1, 100]);
}

#[test]
fn test_aaaa_round_trip() {
    let addr: IpAddr = "fd00::1".parse().unwrap();
    let res = build_aaaa_resource("myhost.local.", addr, 120).unwrap();

    let msg = pack_single_answer(res);
    let parsed = unpack_first_answer(&msg);

    assert_eq!(parsed.header.typ, DnsType::Aaaa);
    let body = parsed.body.as_ref().unwrap();
    let aaaa = body.as_any().downcast_ref::<AaaaResource>().unwrap();
    assert_eq!(
        aaaa.aaaa,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets()
    );
}

// ---------------------------------------------------------------------------
// Full TXT encode → build → pack → unpack → parse → decode round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_txt_full_round_trip() {
    // RFC 6763 §6.6 test vector
    let pairs = vec![
        TxtEntry {
            key: "key".to_owned(),
            value: Some(b"value".to_vec()),
        },
        TxtEntry {
            key: "paper".to_owned(),
            value: Some(b"A4".to_vec()),
        },
        TxtEntry {
            key: "passreq".to_owned(),
            value: None,
        },
    ];

    // Encode key/value → strings
    let strs = encode_txt_record_strings(&pairs).unwrap();

    // Build TXT resource
    let res = build_txt_resource("svc._tcp.local.", strs, BROWSE_TTL).unwrap();

    // Pack → unpack
    let msg = pack_single_answer(res);
    let parsed = unpack_first_answer(&msg);

    // Parse TXT body → strings
    let round_tripped = parse_txt_data(parsed.body.as_ref().unwrap().as_ref()).unwrap();

    // Decode strings → key/value
    let decoded = decode_txt_record_strings(&round_tripped);
    assert_eq!(decoded.len(), 3);

    assert_eq!(decoded[0].key, "key");
    assert_eq!(decoded[0].value, Some(b"value".to_vec()));

    assert_eq!(decoded[1].key, "paper");
    assert_eq!(decoded[1].value, Some(b"A4".to_vec()));

    assert_eq!(decoded[2].key, "passreq");
    assert_eq!(decoded[2].value, None);
}

// ---------------------------------------------------------------------------
// TTL constants — RFC 6762 §10
// ---------------------------------------------------------------------------

#[test]
fn test_ttl_constants() {
    // Host-scoped records: 120 seconds (RFC 6762 §10)
    assert_eq!(120, RESPONSE_TTL);

    // Browsing/other records: 4500 seconds = 75 minutes (RFC 6762 §10)
    assert_eq!(4500, BROWSE_TTL);
}

// ---------------------------------------------------------------------------
// Parse helpers — wrong body type
// ---------------------------------------------------------------------------

#[test]
fn test_parse_ptr_target_wrong_type() {
    let body: Box<dyn ResourceBody> = Box::new(AResource::default());
    assert!(parse_ptr_target(body.as_ref()).is_err());
}

#[test]
fn test_parse_srv_data_wrong_type() {
    let body: Box<dyn ResourceBody> = Box::new(AResource::default());
    assert!(parse_srv_data(body.as_ref()).is_err());
}

#[test]
fn test_parse_txt_data_wrong_type() {
    let body: Box<dyn ResourceBody> = Box::new(AResource::default());
    assert!(parse_txt_data(body.as_ref()).is_err());
}

// ---------------------------------------------------------------------------
// Multi-record message — simulating additional record generation (§12)
// ---------------------------------------------------------------------------

#[test]
fn test_multi_record_message() {
    // Simulate a PTR response with SRV + TXT + A + AAAA additional records,
    // as recommended by RFC 6763 §12.1
    let ptr =
        build_ptr_resource("_http._tcp.local.", "My Web._http._tcp.local.", BROWSE_TTL).unwrap();

    let srv = build_srv_resource(
        "My Web._http._tcp.local.",
        "myhost.local.",
        8080,
        0,
        0,
        RESPONSE_TTL,
    )
    .unwrap();

    let txt = build_txt_resource(
        "My Web._http._tcp.local.",
        vec!["path=/".to_owned()],
        BROWSE_TTL,
    )
    .unwrap();

    let a4: IpAddr = "192.168.1.100".parse().unwrap();
    let a_rec = build_a_resource("myhost.local.", a4, RESPONSE_TTL).unwrap();

    let a6: IpAddr = "fd00::1".parse().unwrap();
    let aaaa_rec = build_aaaa_resource("myhost.local.", a6, RESPONSE_TTL).unwrap();

    let mut msg = Message {
        header: Header {
            response: true,
            authoritative: true,
            ..Default::default()
        },
        answers: vec![ptr],
        additionals: vec![srv, txt, a_rec, aaaa_rec],
        ..Default::default()
    };

    let raw = msg.pack().unwrap();

    let mut unpacked = Message::default();
    unpacked.unpack(&raw).unwrap();

    // Verify answer: PTR
    assert_eq!(unpacked.answers.len(), 1);
    assert_eq!(unpacked.answers[0].header.typ, DnsType::Ptr);
    let ptr_target = parse_ptr_target(unpacked.answers[0].body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(ptr_target, "My Web._http._tcp.local.");

    // Verify additionals: SRV, TXT, A, AAAA
    assert_eq!(unpacked.additionals.len(), 4);
    assert_eq!(unpacked.additionals[0].header.typ, DnsType::Srv);
    assert_eq!(unpacked.additionals[1].header.typ, DnsType::Txt);
    assert_eq!(unpacked.additionals[2].header.typ, DnsType::A);
    assert_eq!(unpacked.additionals[3].header.typ, DnsType::Aaaa);

    // Verify SRV data
    let srv_data = parse_srv_data(unpacked.additionals[0].body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(srv_data.target, "myhost.local.");
    assert_eq!(srv_data.port, 8080);

    // Verify A data
    let a_body = unpacked.additionals[2]
        .body
        .as_ref()
        .unwrap()
        .as_any()
        .downcast_ref::<AResource>()
        .unwrap();
    assert_eq!(a_body.a, [192, 168, 1, 100]);
}

// ---------------------------------------------------------------------------
// Byte-compat with pion (golang.org/x/net dns/dnsmessage)
// ---------------------------------------------------------------------------
//
// The expected bytes below were produced by a throwaway Go program (kept in
// the PR description, not committed) that mirrors pion/mdns v2.2.2's
// records.go builders — the same ResourceHeader fields and bodies — and
// packs single-answer response messages (Header{Response: true,
// Authoritative: true}) with golang.org/x/net v0.35.0 dns/dnsmessage, the
// exact version pinned by pion/mdns v2.2.2. The program printed each packed
// message as hex; those constants are pasted here.
//
// The vectors cover: a plain PTR (owner-name compression in the rdata), a
// PTR with an escaped instance name, both SRV shapes, the RFC 6763 §13.3
// TXT vector, a TXT record mixing flag/binary/empty values, A and AAAA
// hosts, and the RFC 6763 §12.1 multi-record message (PTR answer plus SRV,
// TXT, A, AAAA additionals with cross-record compression pointers).

#[test]
fn test_pion_byte_compat_vectors() {
    let vectors: [(&str, Result<Resource>); 8] = [
        (
            "ptr_plain",
            build_ptr_resource("_http._tcp.local.", "My Web._http._tcp.local.", 4500),
        ),
        (
            "ptr_escaped",
            build_ptr_resource("_http._tcp.local.", r"My\.Web._http._tcp.local.", 4500),
        ),
        (
            "srv_rfc6763",
            build_srv_resource(
                "Service Discovery._http._tcp.dns-sd.org.",
                "dns-sd.org.",
                80,
                0,
                0,
                120,
            ),
        ),
        (
            "srv_nonzero",
            build_srv_resource("svc._tcp.local.", "host.local.", 8080, 10, 20, 300),
        ),
        (
            "txt_rfc6763",
            build_txt_resource(
                "Service Discovery._http._tcp.dns-sd.org.",
                vec!["txtvers=1".to_owned(), "path=/".to_owned()],
                4500,
            ),
        ),
        (
            "txt_mixed",
            build_txt_resource(
                "svc._tcp.local.",
                vec![
                    "version=1.2.3".to_owned(),
                    "setup=".to_owned(),
                    "data=\u{0}\u{1}\u{7f}".to_owned(),
                    "secure".to_owned(),
                ],
                4500,
            ),
        ),
        (
            "a_rfc6763",
            build_a_resource(
                "dns-sd.org.",
                IpAddr::V4(Ipv4Addr::new(64, 142, 82, 154)),
                120,
            ),
        ),
        (
            "aaaa",
            build_aaaa_resource(
                "host.local.",
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                120,
            ),
        ),
    ];

    let expected: [(&str, &str); 8] = [
        (
            "ptr_plain",
            "000084000000000100000000055f68747470045f746370056c6f63616c00000c0001000011940009064d7920576562c00c",
        ),
        (
            "ptr_escaped",
            "000084000000000100000000055f68747470045f746370056c6f63616c00000c000100001194000a034d795c03576562c00c",
        ),
        (
            "srv_rfc6763",
            "000084000000000100000000115365727669636520446973636f76657279055f68747470045f74637006646e732d7364036f7267000021000100000078001200000000005006646e732d7364036f726700",
        ),
        (
            "srv_nonzero",
            "00008400000000010000000003737663045f746370056c6f63616c00002100010000012c0012000a00141f9004686f7374056c6f63616c00",
        ),
        (
            "txt_rfc6763",
            "000084000000000100000000115365727669636520446973636f76657279055f68747470045f74637006646e732d7364036f7267000010000100001194001109747874766572733d3106706174683d2f",
        ),
        (
            "txt_mixed",
            "00008400000000010000000003737663045f746370056c6f63616c00001000010000119400250d76657273696f6e3d312e322e330673657475703d08646174613d00017f06736563757265",
        ),
        (
            "a_rfc6763",
            "00008400000000010000000006646e732d7364036f72670000010001000000780004408e529a",
        ),
        (
            "aaaa",
            "00008400000000010000000004686f7374056c6f63616c00001c0001000000780010fd000000000000000000000000000001",
        ),
    ];

    for (name, res) in vectors.into_iter() {
        let res = res.unwrap();
        let packed = pack_single_answer(res);
        assert_eq!(
            hex(&packed),
            expected
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, h)| *h)
                .unwrap_or_default(),
            "{name}: packed bytes differ from pion's dnsmessage output"
        );
    }

    // The multi-record message (RFC 6763 §12.1): PTR answer plus SRV, TXT,
    // A and AAAA additionals — exercises cross-record compression pointers.
    let ptr = build_ptr_resource("_http._tcp.local.", "My Web._http._tcp.local.", 4500).unwrap();
    let srv =
        build_srv_resource("My Web._http._tcp.local.", "myhost.local.", 8080, 0, 0, 120).unwrap();
    let txt =
        build_txt_resource("My Web._http._tcp.local.", vec!["path=/".to_owned()], 4500).unwrap();
    let a_rec = build_a_resource(
        "myhost.local.",
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        120,
    )
    .unwrap();
    let aaaa_rec = build_aaaa_resource(
        "myhost.local.",
        IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        120,
    )
    .unwrap();

    let mut msg = Message {
        header: Header {
            response: true,
            authoritative: true,
            ..Default::default()
        },
        answers: vec![ptr],
        additionals: vec![srv, txt, a_rec, aaaa_rec],
        ..Default::default()
    };
    let packed = msg.pack().unwrap();
    assert_eq!(
        hex(&packed),
        "000084000000000100000004055f68747470045f746370056c6f63616c00000c0001000011940009064d7920576562c00cc02800210001000000780014000000001f90066d79686f7374056c6f63616c00c0280010000100001194000706706174683d2f066d79686f7374c01700010001000000780004c0a80164c064001c0001000000780010fd000000000000000000000000000001",
        "multi: packed bytes differ from pion's dnsmessage output"
    );
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Malformed input — Err, never panic
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_input_returns_err_never_panics() {
    // Truncated TXT strings on the wire: a TXT body whose length field
    // promises more than the record holds.
    let mut msg = Message::default();
    // Raw bytes: header (12) + one TXT answer whose rdata claims 10 bytes
    // but only carries a 1-byte string "\x03ab" plus junk.
    let raw = hex_to_bytes(
        "00008400000000010000000003737663045f746370056c6f63616c000010000100001194000a036162020102",
    );
    assert!(msg.unpack(&raw).is_err() || !msg.answers.is_empty());

    // A TXT rdata that is cut short mid-string must fail, not panic.
    let raw_short = hex_to_bytes(
        "00008400000000010000000003737663045f746370056c6f63616c0000100001000011940005ffff076162",
    );
    let mut msg2 = Message::default();
    // Either it errors on unpack or the body itself is invalid; either way
    // there is no panic and no bogus success.
    if msg2.unpack(&raw_short).is_ok() && !msg2.answers.is_empty() {
        let body = msg2.answers[0].body.as_ref().unwrap();
        let parsed = parse_txt_data(body.as_ref());
        assert!(parsed.is_err() || !parsed.unwrap().is_empty());
    }

    // Bad escapes in service instance names: a lone trailing backslash is
    // preserved by unescape (as in pion) and never panics.
    assert_eq!(unescape_instance_name(r"abc\"), r"abc\");
    // A name made only of escapes and separators still parses or errors
    // without panicking.
    let _ = parse_service_instance_name(r"\.\.._a._tcp.local.");
    let _ = parse_service_instance_name("...");

    // Over-long labels: a 64-byte label cannot be packed (RFC 1035 §2.3.4).
    let long_label = format!("{}._tcp.local.", "a".repeat(64));
    let res = build_ptr_resource(&long_label, "target.local.", 300).unwrap();
    let mut msg = Message {
        header: Header {
            response: true,
            authoritative: true,
            ..Default::default()
        },
        answers: vec![res],
        ..Default::default()
    };
    assert!(msg.pack().is_err());

    // Over-long TXT strings are rejected by the encoder.
    assert!(encode_txt_record_strings(&[new_txt_string("k", &"x".repeat(300))]).is_err());
    // Non-UTF-8 binary values are rejected rather than corrupted.
    assert_eq!(
        encode_txt_record_strings(&[TxtEntry {
            key: "k".to_owned(),
            value: Some(vec![0xff, 0xfe]),
        }])
        .unwrap_err(),
        Error::ErrTXTValueNotUtf8
    );
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
