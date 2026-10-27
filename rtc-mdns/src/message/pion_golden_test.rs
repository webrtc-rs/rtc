//! Differential test against `golang.org/x/net/dns/dnsmessage`, the codec pion/mdns uses and this
//! one is a port of. Each row of `tests/data/pion_dnsmessage_golden.jsonl` is a message — a valid
//! one, or a mutation of one — with whether pion could unpack it, what it found, and the bytes it
//! packs back. This crate must agree. See `tests/oracle/README.md`.
//!
//! `PION_MDNS_GOLDEN=<file>` replays another file and reports instead of failing.

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn question(q: &question::Question) -> String {
    format!("{} {} {}", q.name.data, q.typ as u16, q.class.0)
}

fn resource(r: &resource::Resource) -> String {
    format!(
        "{} {} {} {}",
        r.header.name.data, r.header.typ as u16, r.header.class.0, r.header.ttl
    )
}

/// What this crate finds in `raw`, in the shape the oracle reports.
fn analyze(raw: &[u8]) -> serde_json::Value {
    let mut m = Message::default();
    if m.unpack(raw).is_err() {
        return serde_json::json!({ "err": "unpack" });
    }
    let list = |v: Vec<String>| serde_json::json!(v);
    let repack = match m.pack() {
        Ok(b) => hex(&b),
        Err(_) => "err".to_owned(),
    };
    serde_json::json!({
        "id": m.header.id,
        "bits": m.header.pack().1,
        "q": list(m.questions.iter().map(question).collect()),
        "an": list(m.answers.iter().map(resource).collect()),
        "ns": list(m.authorities.iter().map(resource).collect()),
        "ar": list(m.additionals.iter().map(resource).collect()),
        "repack": repack,
    })
}

fn field(v: &serde_json::Value, k: &str) -> serde_json::Value {
    // The oracle omits empty fields (`omitempty`).
    v.get(k).cloned().unwrap_or(serde_json::Value::Null)
}

fn same(want: &serde_json::Value, got: &serde_json::Value) -> std::result::Result<(), String> {
    for k in ["err", "id", "bits", "q", "an", "ns", "ar", "repack"] {
        let (w, g) = (field(want, k), field(got, k));
        let empty = |v: &serde_json::Value| {
            v.is_null() || v == &serde_json::json!(0) || v == &serde_json::json!([]) || v == ""
        };
        if w != g && !(empty(&w) && empty(&g)) {
            return Err(format!("{k}: pion {w}, this crate {g}"));
        }
    }
    Ok(())
}

/// The record types this crate models; pion also keeps any other as an `UnknownResource` and
/// understands SVCB/HTTPS, which an mDNS responder has no use for. A question may also ask for
/// ANY (255), which is not a record type.
const KNOWN_RECORD_TYPES: [u64; 10] = [1, 2, 5, 6, 12, 15, 16, 28, 33, 41];
const ANY: u64 = 255;

/// A difference that is intended, and why; `None` if the rows should agree.
///
/// * Names and TXT strings must be UTF-8 here (RFC 6762 §16); pion keeps their bytes.
/// * The header's AD and CD bits (DNSSEC) and an RCode above 5 are not modelled: RFC 6762 §18 has an
///   mDNS message leave them zero and the receiver ignore them. pion keeps them.
/// * A message with a record of a type outside [`KNOWN_TYPES`] is not unpacked whole, and a
///   question of such a type is reported with type 0. The responder never needs either: it
///   reads records one at a time and skips those it does not understand.
fn intended_difference(want: &serde_json::Value, raw: &[u8]) -> Option<&'static str> {
    // Names print as "name type class [ttl]"; the type is the third from the end for records
    // (name type class ttl) and second from the end for questions.
    let unknown = |k: &str, from_end: usize, any_ok: bool| {
        want[k]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str()?.rsplit(' ').nth(from_end)?.parse::<u64>().ok())
            .any(|t| !KNOWN_RECORD_TYPES.contains(&t) && !(any_ok && t == ANY))
    };
    if unknown("q", 1, true)
        || unknown("an", 2, false)
        || unknown("ns", 2, false)
        || unknown("ar", 2, false)
    {
        return Some("record type outside the modelled set");
    }
    if raw.len() >= 4 {
        let bits = u16::from_be_bytes([raw[2], raw[3]]);
        if bits & ((1 << 5) | (1 << 4)) != 0 || bits & 0xF > 5 {
            return Some("a header bit or RCode that is not modelled");
        }
    }
    let mut m = Message::default();
    match m.unpack(raw) {
        Err(shared::error::Error::Utf8(_) | shared::error::Error::ErrTXTValueNotUtf8)
            if want.get("err").is_none() =>
        {
            Some("a name or TXT string that is not UTF-8")
        }
        _ => None,
    }
}

fn replay(text: &str) -> (usize, usize, Vec<String>) {
    let (mut rows, mut intended) = (0, 0);
    let mut divergences = vec![];
    for line in text.lines().filter(|l| !l.is_empty()) {
        let want: serde_json::Value = serde_json::from_str(line).unwrap();
        let raw = unhex(want["in"].as_str().unwrap());
        rows += 1;
        if let Err(why) = same(&want, &analyze(&raw)) {
            if intended_difference(&want, &raw).is_some() {
                intended += 1;
            } else {
                divergences.push(format!("{}: {why}", hex(&raw)));
            }
        }
    }
    (rows, intended, divergences)
}

#[test]
fn matches_pion_dnsmessage() {
    if let Ok(path) = std::env::var("PION_MDNS_GOLDEN") {
        let (rows, intended, divergences) = replay(&std::fs::read_to_string(path).unwrap());
        for d in &divergences {
            eprintln!("DIVERGES {d}");
        }
        eprintln!(
            "{} of {rows} rows diverge ({intended} more differ as intended)",
            divergences.len()
        );
        return;
    }
    let (rows, intended, divergences) = replay(include_str!(
        "../../tests/data/pion_dnsmessage_golden.jsonl"
    ));
    eprintln!("{rows} rows, {intended} differ as intended");
    assert!(rows > 5000, "the golden file is missing rows: {rows}");
    assert!(
        divergences.is_empty(),
        "{} of {rows} rows diverge from pion; first: {:#?}",
        divergences.len(),
        &divergences[..divergences.len().min(10)]
    );
}
