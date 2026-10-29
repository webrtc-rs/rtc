//! Differential test against pion/interceptor v0.1.49's NACK receive log and RTP send buffer.
//!
//! Each row of `tests/data/pion_nack_golden.jsonl` is a random packet-arrival sequence — in order,
//! lossy, reordered, duplicated, across the 16-bit wrap, with jumps of more than half the sequence
//! space — with every answer pion gave: what `get` found, and what `missingSeqNumbers` reported
//! (as a count, a hash and the first few, since one answer can run to thousands of numbers). This
//! crate must give the same. See `tests/oracle/README.md`.
//!
//! `PION_NACK_GOLDEN=<file>` replays another file and lists the divergences instead of failing.

use super::receive_log::ReceiveLog;
use super::send_buffer::SendBuffer;

/// The FNV-1a summary the oracle writes for a list of sequence numbers.
fn summary(ns: &[u16]) -> String {
    let mut h: u32 = 2166136261;
    for n in ns {
        for b in n.to_be_bytes() {
            h = (h ^ u32::from(b)).wrapping_mul(16777619);
        }
    }
    let first: Vec<String> = ns.iter().take(6).map(u16::to_string).collect();
    format!("n={} h={h:08x} first={}", ns.len(), first.join(","))
}

fn packet(seq: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            sequence_number: seq,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Runs one row's operations; the answer to each, in the oracle's format.
fn run(kind: &str, size: u16, ops: &[&str]) -> Vec<String> {
    let mut log = (kind == "recv").then(|| ReceiveLog::new(size).expect("a valid size"));
    let mut buf = (kind == "send").then(|| SendBuffer::new(size).expect("a valid size"));
    ops.iter()
        .map(|op| {
            let (name, arg) = op.split_once(':').unwrap();
            let arg: u32 = arg.parse().unwrap();
            match (name, log.as_mut(), buf.as_mut()) {
                ("a", Some(log), _) => {
                    log.add(arg as u16);
                    String::new()
                }
                ("a", _, Some(buf)) => {
                    buf.add(packet(arg as u16));
                    String::new()
                }
                ("g", Some(log), _) => u8::from(log.get(arg as u16)).to_string(),
                ("g", _, Some(buf)) => buf
                    .get(arg as u16)
                    .map_or(-1, |p| i32::from(p.header.sequence_number))
                    .to_string(),
                ("m", Some(log), _) => summary(&log.missing_seq_numbers(arg as u16)),
                _ => panic!("unexpected operation {op}"),
            }
        })
        .collect()
}

fn replay(text: &str) -> (usize, Vec<String>) {
    let (mut rows, mut divergences) = (0, vec![]);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        let ops: Vec<&str> = row["ops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        let want: Vec<&str> = row["out"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        let got = run(
            row["k"].as_str().unwrap(),
            row["size"].as_u64().unwrap() as u16,
            &ops,
        );
        rows += 1;
        if let Some(i) = want.iter().zip(&got).position(|(w, g)| w != g) {
            divergences.push(format!(
                "{} size {} after {} ops: {}: pion {:?}, this crate {:?}",
                row["k"].as_str().unwrap(),
                row["size"],
                i + 1,
                ops[i],
                want[i],
                got[i]
            ));
        }
    }
    (rows, divergences)
}

#[test]
fn matches_pion_nack_buffers() {
    if let Ok(path) = std::env::var("PION_NACK_GOLDEN") {
        let (rows, divergences) = replay(&std::fs::read_to_string(path).unwrap());
        for d in divergences.iter().take(40) {
            eprintln!("DIVERGES {d}");
        }
        eprintln!("{} of {rows} rows diverge", divergences.len());
        return;
    }
    let (rows, divergences) = replay(include_str!("../../tests/data/pion_nack_golden.jsonl"));
    assert!(rows >= 800, "the golden file is missing rows: {rows}");
    assert!(
        divergences.is_empty(),
        "{} of {rows} rows diverge from pion; first: {:#?}",
        divergences.len(),
        &divergences[..divergences.len().min(10)]
    );
}
