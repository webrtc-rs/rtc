//! Differential test against pion/dtls (v3.1.15) record parsing: each row of
//! `tests/data/pion_dtls_golden.jsonl` is a DTLS record pion's `recordlayer.RecordLayer` parsed or
//! refused, with the bytes it re-marshals to. This crate must reach the same verdict, content type
//! and bytes.
//!
//! `PION_DTLS_GOLDEN=<file>` runs another file in exploration mode (report, don't fail);
//! `PION_DTLS_REPORT=<file>` writes the divergences as JSONL.

use rtc_dtls::content::Content;
use rtc_dtls::record_layer::RecordLayer;
use std::io::Cursor;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn run(input: &[u8]) -> Result<(i64, String), String> {
    let mut r = Cursor::new(input);
    let rl = RecordLayer::unmarshal(&mut r).map_err(|e| e.to_string())?;
    let typ = match &rl.content {
        Content::ChangeCipherSpec(_) => 20,
        Content::Alert(_) => 21,
        Content::Handshake(_) => 22,
        Content::ApplicationData(_) => 23,
        _ => -1,
    };
    let mut out = vec![];
    rl.marshal(&mut out).map_err(|e| e.to_string())?;
    Ok((typ, hex(&out)))
}

#[test]
fn matches_pion_dtls_records() {
    let (path, explore) = match std::env::var("PION_DTLS_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_dtls_golden.jsonl",
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
        // A datagram is split into records by their length field before any record is parsed, so
        // only records whose length field is true to their size reach the parsers. The key
        // exchange messages (12, 16) are skipped too: which wire form they take depends on the
        // negotiated cipher suite, which pion is told and this crate infers.
        if !well_framed(&input)
            || (input[0] == 22 && input.len() > 13 && matches!(input[13], 12 | 16))
        {
            continue;
        }
        total += 1;
        let shown = hex(&input);
        match (std::panic::catch_unwind(|| run(&input)), pion_err) {
            (Err(_), _) => diverged.push(("rust PANIC".into(), shown)),
            (Ok(Ok(_)), Some(e)) => {
                diverged.push((format!("rust accepts, pion rejects: {e}"), shown))
            }
            (Ok(Err(e)), None) => {
                diverged.push((format!("rust rejects ({e}), pion accepts"), shown))
            }
            (Ok(Err(_)), Some(_)) => {}
            (Ok(Ok((typ, out))), None) => {
                if typ != v["typ"].as_i64().unwrap_or(0) {
                    diverged.push((format!("type: want {} got {typ}", v["typ"]), shown));
                } else if v["out"].as_str() != Some(out.as_str()) {
                    diverged.push((format!("output: want {} got {out}", v["out"]), shown));
                }
            }
        }
    }
    eprintln!("{total} vectors, {} diverge from pion", diverged.len());
    if let Ok(report) = std::env::var("PION_DTLS_REPORT") {
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

fn well_framed(input: &[u8]) -> bool {
    input.len() >= 13 && input.len() == 13 + u16::from_be_bytes([input[11], input[12]]) as usize
}
