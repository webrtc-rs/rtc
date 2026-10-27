//! Differential test against pion/ice (v4.4.8) `UnmarshalCandidate`: each row of
//! `tests/data/pion_candidate_golden.jsonl` is a candidate line — a seed, or a mutation of one — with
//! whether pion parsed it, the fields it found, and what `Marshal` writes back. This crate must
//! agree. See `tests/oracle/README.md`.
//!
//! `PION_ICE_GOLDEN=<file>` replays another file and lists the divergences instead of failing.

use rtc_ice::candidate::{Candidate, unmarshal_candidate};

fn analyze(line: &str) -> serde_json::Value {
    let c: Candidate = match unmarshal_candidate(line) {
        Ok(c) => c,
        Err(_) => return serde_json::json!({ "err": true }),
    };
    let tcp = match c.tcp_type().to_string().as_str() {
        "unspecified" => String::new(),
        other => other.to_owned(),
    };
    let related = c.related_address();
    serde_json::json!({
        "type": c.candidate_type().to_string(),
        "network": c.network_type().to_string(),
        "addr": c.address(),
        "port": c.port(),
        "prio": c.priority(),
        "comp": c.component(),
        "found": c.foundation(),
        "raddr": related.as_ref().map(|r| r.address.clone()).unwrap_or_default(),
        "rport": related.as_ref().map(|r| r.port).unwrap_or(0),
        "tcp": tcp,
        "marshal": c.marshal(),
    })
}

/// The oracle omits zero values (`omitempty`).
fn field(v: &serde_json::Value, k: &str) -> serde_json::Value {
    match v.get(k) {
        None => serde_json::Value::Null,
        Some(x) if x == &serde_json::json!(0) || x == "" => serde_json::Value::Null,
        Some(x) => x.clone(),
    }
}

fn differences(want: &serde_json::Value, got: &serde_json::Value) -> Vec<String> {
    let mut out = vec![];
    if want.get("err") != got.get("err") {
        out.push(format!(
            "pion {}, this crate {}",
            if want.get("err").is_some() {
                "rejects"
            } else {
                "accepts"
            },
            if got.get("err").is_some() {
                "rejects"
            } else {
                "accepts"
            }
        ));
        return out;
    }
    for k in [
        "type", "network", "addr", "port", "prio", "comp", "found", "raddr", "rport", "tcp",
        "marshal",
    ] {
        let (w, g) = (field(want, k), field(got, k));
        if w != g {
            out.push(format!("{k}: pion {w}, this crate {g}"));
        }
    }
    out
}

fn replay(text: &str) -> (usize, Vec<String>) {
    let (mut rows, mut divergences) = (0, vec![]);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let want: serde_json::Value = serde_json::from_str(line).unwrap();
        let input = want["in"].as_str().unwrap();
        rows += 1;
        let diff = differences(&want, &analyze(input));
        if !diff.is_empty() {
            divergences.push(format!("{input:?}: {}", diff.join("; ")));
        }
    }
    (rows, divergences)
}

#[test]
fn matches_pion_candidate_parsing() {
    if let Ok(path) = std::env::var("PION_ICE_GOLDEN") {
        let (rows, divergences) = replay(&std::fs::read_to_string(path).unwrap());
        for d in &divergences {
            eprintln!("DIVERGES {d}");
        }
        eprintln!("{} of {rows} rows diverge", divergences.len());
        return;
    }
    let (rows, divergences) = replay(include_str!("data/pion_candidate_golden.jsonl"));
    assert!(rows >= 4000, "the golden file is missing rows: {rows}");
    assert!(
        divergences.is_empty(),
        "{} of {rows} rows diverge from pion; first: {:#?}",
        divergences.len(),
        &divergences[..divergences.len().min(15)]
    );
}
