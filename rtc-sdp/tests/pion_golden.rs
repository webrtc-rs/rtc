//! Differential test against pion/sdp (v3.0.20): every vector in `tests/data/pion_sdp_golden.jsonl`
//! is an input pion was run on, with pion's verdict (accepted or rejected) and, when accepted,
//! the text pion marshals it back to. This crate must reach the same verdict and, on acceptance,
//! print the same text.
//!
//! Set `PION_SDP_GOLDEN=<file>` to run another vector file and report divergences instead of
//! failing (exploration mode).

use base64::Engine;
use rtc_sdp::SessionDescription;
use std::io::Cursor;

fn b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn matches_pion_sdp() {
    let (path, explore) = match std::env::var("PION_SDP_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_sdp_golden.jsonl",
                env!("CARGO_MANIFEST_DIR")
            ),
            false,
        ),
    };
    let data = std::fs::read_to_string(&path).unwrap();
    let mut verdict_mismatch: Vec<(String, String)> = vec![];
    let mut output_mismatch: Vec<(String, String)> = vec![];
    let mut total = 0;
    for line in data.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let input = b64(v["in"].as_str().unwrap());
        let pion_err = v.get("err").and_then(|e| e.as_str()).map(String::from);
        let pion_out = v.get("out").and_then(|e| e.as_str()).map(b64);
        total += 1;
        let res = std::panic::catch_unwind(|| {
            SessionDescription::unmarshal(&mut Cursor::new(input.clone()))
        });
        let shown = String::from_utf8_lossy(&input).replace("\r\n", "⏎\n");
        match (res, &pion_err) {
            (Err(_), _) => verdict_mismatch.push(("rust PANIC".into(), shown)),
            // Documented divergence: an unregistered `m=` protocol token is accepted (RFC 8866
            // §5.14 makes <proto> extensible); pion rejects it.
            (Ok(Ok(_)), Some(e))
                if e.contains("invalid numeric value") && has_unregistered_proto(&input) => {}
            (Ok(Ok(_)), Some(e)) => {
                verdict_mismatch.push((format!("rust accepts, pion rejects: {e}"), shown))
            }
            // Documented divergence: pion wraps `r=`/`z=` time values that overflow i64; a wrapped
            // time is wrong, so this crate rejects it.
            (Ok(Err(e)), None) if is_time_overflow(&e.to_string()) => {}
            (Ok(Err(e)), None) => {
                verdict_mismatch.push((format!("rust rejects ({e}), pion accepts"), shown))
            }
            (Ok(Err(_)), Some(_)) => {}
            (Ok(Ok(sd)), None) => {
                // pion prints `m=audio 9 RTP/AVP ` with a trailing space when a section lists no
                // formats; this crate does not. Compare with trailing spaces trimmed.
                let trim = |s: &str| {
                    s.split("\r\n")
                        .map(str::trim_end)
                        .collect::<Vec<_>>()
                        .join("\r\n")
                };
                let want_codecs: Vec<String> = v["codecs"]
                    .as_array()
                    .map(|a| a.iter().map(|c| c.as_str().unwrap().to_owned()).collect())
                    .unwrap_or_default();
                let mut got_codecs: Vec<_> = sd.codec_map().into_iter().collect();
                got_codecs.sort_by_key(|(pt, _)| *pt);
                let got_codecs: Vec<String> =
                    got_codecs.iter().map(|(_, c)| c.to_string()).collect();
                if got_codecs != want_codecs {
                    output_mismatch.push((
                        format!("codec map: want {want_codecs:?}\n   got {got_codecs:?}"),
                        shown.clone(),
                    ));
                }
                let want = trim(&String::from_utf8_lossy(&pion_out.unwrap()));
                let got = trim(&sd.marshal());
                if got != want {
                    output_mismatch.push((format!("want {want:?}\n   got {got:?}"), shown));
                }
            }
        }
    }
    eprintln!(
        "{total} vectors: {} verdict mismatches, {} output mismatches",
        verdict_mismatch.len(),
        output_mismatch.len()
    );
    if let Ok(report) = std::env::var("PION_SDP_REPORT") {
        let mut out = String::new();
        for (kind, list) in [("verdict", &verdict_mismatch), ("output", &output_mismatch)] {
            for (why, input) in list.iter() {
                out.push_str(
                    &serde_json::json!({"kind": kind, "why": why, "input": input}).to_string(),
                );
                out.push('\n');
            }
        }
        std::fs::write(report, out).unwrap();
    }
    if explore {
        for (why, input) in verdict_mismatch
            .iter()
            .chain(output_mismatch.iter())
            .take(25)
        {
            eprintln!("--- {why}\n{input}");
        }
        return;
    }
    assert!(
        verdict_mismatch.is_empty() && output_mismatch.is_empty(),
        "diverges from pion:\n{}",
        verdict_mismatch
            .iter()
            .chain(output_mismatch.iter())
            .take(5)
            .map(|(w, i)| format!("{w}\n{i}"))
            .collect::<Vec<_>>()
            .join("\n---\n")
    );
}

fn has_unregistered_proto(input: &[u8]) -> bool {
    const REGISTERED: &[&str] = &[
        "UDP", "RTP", "AVP", "SAVP", "SAVPF", "TLS", "DTLS", "SCTP", "AVPF", "TCP", "MSRP", "BFCP",
        "UDT", "IX", "MRCPv2", "FEC",
    ];
    String::from_utf8_lossy(input)
        .lines()
        .filter(|l| l.starts_with("m="))
        .filter_map(|l| l.split_whitespace().nth(2))
        .any(|proto| proto.split('/').any(|p| !REGISTERED.contains(&p)))
}

fn is_time_overflow(err: &str) -> bool {
    // `SdpInvalidValue: 106751991167301d`
    err.rsplit(' ').next().is_some_and(|v| {
        v.len() >= 14
            && v.ends_with(['d', 'h', 'm'])
            && v[..v.len() - 1].bytes().all(|b| b.is_ascii_digit())
    })
}
