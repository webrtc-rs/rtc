//! Differential test against pion/stun (v4.0.1): each row of `tests/data/pion_stun_golden.jsonl` is a
//! datagram pion decoded, with what it found — message type, transaction id, raw attributes, the
//! result of checking FINGERPRINT and a short-term MESSAGE-INTEGRITY, the typed attribute values
//! and the bytes a re-encode produces. This crate must agree.
//!
//! `PION_STUN_GOLDEN=<file>` runs another file in exploration mode (report, don't fail);
//! `PION_STUN_REPORT=<file>` writes the divergences as JSONL.

use rtc_stun::addr::MappedAddress;
use rtc_stun::attributes::*;
use rtc_stun::error_code::ErrorCodeAttribute;
use rtc_stun::fingerprint::FINGERPRINT;
use rtc_stun::integrity::MessageIntegrity;
use rtc_stun::message::{Getter, Message};
use rtc_stun::textattrs::TextAttribute;
use rtc_stun::uattrs::UnknownAttributes;
use rtc_stun::xoraddr::XorMappedAddress;
use std::net::SocketAddr;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ok_err<T, E>(r: &Result<T, E>) -> &'static str {
    if r.is_ok() { "ok" } else { "err" }
}

fn analyze(raw: &[u8]) -> Result<serde_json::Value, String> {
    let mut m = Message {
        raw: raw.to_vec(),
        ..Default::default()
    };
    m.decode().map_err(|e| e.to_string())?;

    let attrs: Vec<[String; 2]> = m
        .attributes
        .0
        .iter()
        .map(|a| [format!("{:04x}", a.typ.0), hex(&a.value)])
        .collect();
    let fp = ok_err(&FINGERPRINT.check(&m));
    let provider = crypto::default_provider().expect("crypto provider");
    let mi = {
        let mut copy = m.clone();
        ok_err(&MessageIntegrity::check(
            &mut copy,
            b"pass",
            provider.crypto(),
        ))
    };

    let mut typed = serde_json::Map::new();
    if m.contains(ATTR_XORMAPPED_ADDRESS) {
        let mut a = XorMappedAddress::default();
        let v = match a.get_from(&m) {
            Ok(()) => SocketAddr::new(a.ip, a.port).to_string(),
            Err(_) => "err".into(),
        };
        typed.insert("xor-mapped".into(), v.into());
    }
    if m.contains(ATTR_MAPPED_ADDRESS) {
        let mut a = MappedAddress::default();
        let v = match a.get_from(&m) {
            Ok(()) => SocketAddr::new(a.ip, a.port).to_string(),
            Err(_) => "err".into(),
        };
        typed.insert("mapped".into(), v.into());
    }
    if m.contains(ATTR_ERROR_CODE) {
        let mut a = ErrorCodeAttribute::default();
        let v = match a.get_from(&m) {
            Ok(()) => format!("{} {}", a.code.0, hex(&a.reason)),
            Err(_) => "err".into(),
        };
        typed.insert("error".into(), v.into());
    }
    for (key, attr) in [
        ("username", ATTR_USERNAME),
        ("realm", ATTR_REALM),
        ("nonce", ATTR_NONCE),
        ("software", ATTR_SOFTWARE),
    ] {
        if m.contains(attr) {
            let v = match TextAttribute::get_from_as(&m, attr) {
                Ok(t) => format!("ok:{}", hex(t.text.as_bytes())),
                Err(_) => "err:".into(),
            };
            typed.insert(key.into(), v.into());
        }
    }
    if m.contains(ATTR_UNKNOWN_ATTRIBUTES) {
        let mut a = UnknownAttributes(vec![]);
        let v = match a.get_from(&m) {
            Ok(()) => {
                let mut s = "ok".to_string();
                for t in &a.0 {
                    s += &format!(",{:04x}", t.0);
                }
                s
            }
            Err(_) => "err".into(),
        };
        typed.insert("unknown".into(), v.into());
    }

    // Re-encode the decoded message.
    let mut m2 = Message::default();
    m2.typ = m.typ;
    m2.transaction_id = m.transaction_id;
    m2.write_header();
    for a in &m.attributes.0 {
        m2.add(a.typ, &a.value);
    }

    Ok(serde_json::json!({
        "typ": format!("{:04x}", m.typ.value()),
        "len": m.length,
        "tid": hex(&m.transaction_id.0),
        "attrs": attrs,
        "fp": fp,
        "mi": mi,
        "typed": typed,
        "reenc": hex(&m2.raw),
    }))
}

#[test]
fn matches_pion_stun() {
    let (path, explore) = match std::env::var("PION_STUN_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_stun_golden.jsonl",
                env!("CARGO_MANIFEST_DIR")
            ),
            false,
        ),
    };
    let data = std::fs::read_to_string(path).unwrap();
    let mut diverged: Vec<(String, String)> = vec![];
    let mut total = 0;
    for line in data.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let input = unhex(v["in"].as_str().unwrap());
        let pion_err = v.get("err").and_then(|e| e.as_str());
        total += 1;
        let shown = hex(&input);
        let got = std::panic::catch_unwind(|| analyze(&input));
        match (got, pion_err) {
            (Err(_), _) => diverged.push(("rust PANIC".into(), shown)),
            (Ok(Ok(_)), Some(e)) => {
                diverged.push((format!("rust accepts, pion rejects: {e}"), shown))
            }
            (Ok(Err(e)), None) => {
                diverged.push((format!("rust rejects ({e}), pion accepts"), shown))
            }
            (Ok(Err(_)), Some(_)) => {}
            (Ok(Ok(got)), None) => {
                for key in ["typ", "len", "tid", "attrs", "fp", "mi", "typed", "reenc"] {
                    let mut want = v.get(key).cloned().unwrap_or(serde_json::Value::Null);
                    if key == "typed" {
                        lossy_text(&mut want);
                    }
                    let have = got.get(key).cloned().unwrap_or(serde_json::Value::Null);
                    let empty = |x: &serde_json::Value| {
                        x.is_null()
                            || x.as_array().is_some_and(|a| a.is_empty())
                            || x.as_object().is_some_and(|o| o.is_empty())
                            || x == 0
                            || x == ""
                    };
                    if want != have && !(empty(&want) && empty(&have)) {
                        diverged.push((format!("{key}: want {want} got {have}"), shown.clone()));
                        break;
                    }
                }
            }
        }
    }
    eprintln!("{total} vectors, {} diverge from pion", diverged.len());
    if let Ok(report) = std::env::var("PION_STUN_REPORT") {
        let out: String = diverged
            .iter()
            .map(|(w, i)| serde_json::json!({"why": w, "input": i}).to_string() + "\n")
            .collect();
        std::fs::write(report, out).unwrap();
    }
    if explore {
        for (w, i) in diverged.iter().take(10) {
            eprintln!("--- {w}\n{i}");
        }
        return;
    }
    assert!(
        diverged.is_empty(),
        "diverges from pion:\n{}",
        diverged
            .iter()
            .take(5)
            .map(|(w, i)| format!("{w}\n{i}"))
            .collect::<Vec<_>>()
            .join("\n---\n")
    );
}

/// pion keeps USERNAME/REALM/NONCE/SOFTWARE as raw bytes; this crate converts a value that is not
/// UTF-8 lossily (see `TextAttribute::get_from_as`). Convert pion's expectation the same way.
fn lossy_text(typed: &mut serde_json::Value) {
    let Some(map) = typed.as_object_mut() else {
        return;
    };
    for key in ["username", "realm", "nonce", "software"] {
        if let Some(v) = map.get_mut(key) {
            if let Some(h) = v.as_str().and_then(|s| s.strip_prefix("ok:")) {
                let text = String::from_utf8_lossy(&unhex(h)).into_owned();
                *v = format!("ok:{}", hex(text.as_bytes())).into();
            }
        }
    }
}
