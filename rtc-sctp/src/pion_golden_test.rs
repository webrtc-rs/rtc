//! Differential test against pion/sctp (v1.12.0): each row of `tests/data/pion_sctp_golden.jsonl` is
//! a packet pion parsed (checksum verified) and marshalled back, with the chunk types it found and
//! the bytes it wrote. This crate must reach the same verdict, find the same chunks and write the
//! same bytes.
//!
//! `PION_SCTP_GOLDEN=<file>` runs another file in exploration mode (report, don't fail);
//! `PION_SCTP_REPORT=<file>` writes the divergences as JSONL.

use crate::chunk::Chunk;
use crate::chunk::chunk_type::*;
use crate::packet::Packet;
use bytes::{Bytes, BytesMut};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn chunk_name(c: &dyn Chunk, index: usize, first_is_init: bool) -> &'static str {
    let _ = (index, first_is_init);
    match c.header().typ {
        CT_INIT => "init",
        CT_INIT_ACK => "init-ack",
        CT_ABORT => "abort",
        CT_COOKIE_ECHO => "cookie-echo",
        CT_COOKIE_ACK => "cookie-ack",
        CT_HEARTBEAT => "heartbeat",
        CT_PAYLOAD_DATA => "data",
        CT_IDATA => "i-data",
        CT_SACK => "sack",
        CT_RECONFIG => "reconfig",
        CT_FORWARD_TSN => "forward-tsn",
        CT_IFORWARD_TSN => "i-forward-tsn",
        CT_ERROR => "error",
        CT_SHUTDOWN => "shutdown",
        CT_SHUTDOWN_ACK => "shutdown-ack",
        CT_SHUTDOWN_COMPLETE => "shutdown-complete",
        _ => "other",
    }
}

/// Reduces a packet to what must agree: the checksum (which covers everything else) is cleared;
/// the flags octet of chunks whose flags are reserved is cleared (pion keeps what it received,
/// this crate writes zero as RFC 4960 asks of a sender); and chunks that have no value (COOKIE
/// ACK, SHUTDOWN ACK, SHUTDOWN COMPLETE) lose any bytes a sender put after the header, which
/// pion echoes back and this crate drops.
fn normalize(packet: &[u8]) -> Vec<u8> {
    if packet.len() < 12 {
        return packet.to_vec();
    }
    let mut out = packet[..12].to_vec();
    out[8..12].fill(0);
    let mut i = 12;
    while i + 4 <= packet.len() {
        let len = u16::from_be_bytes([packet[i + 2], packet[i + 3]]) as usize;
        let typ = packet[i];
        let end = (i + len).min(packet.len());
        let mut chunk = packet[i..end].to_vec();
        // DATA (0) and I-DATA (64) carry flags; ABORT (6) and SHUTDOWN COMPLETE (14) the T bit.
        if !matches!(typ, 0 | 64 | 6 | 14) {
            chunk[1] = 0;
        }
        if matches!(typ, 8 | 11 | 14) {
            chunk.truncate(4);
            chunk[2..4].copy_from_slice(&4u16.to_be_bytes());
        }
        out.extend_from_slice(&chunk);
        out.resize(out.len() + (4 - out.len() % 4) % 4, 0);
        if len < 4 {
            break;
        }
        i += len + (4 - len % 4) % 4;
    }
    out
}

#[test]
fn matches_pion_sctp() {
    let (path, explore) = match std::env::var("PION_SCTP_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_sctp_golden.jsonl",
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
        let got = std::panic::catch_unwind(|| {
            let raw = Bytes::from(input.clone());
            Packet::unmarshal(&raw).and_then(|p| {
                let names: Vec<&str> = p
                    .chunks
                    .iter()
                    .enumerate()
                    .map(|(i, c)| chunk_name(&**c, i, false))
                    .collect();
                let mut buf = BytesMut::new();
                p.marshal_to(&mut buf)?;
                Ok((names.join(","), hex(&buf)))
            })
        });
        match (got, pion_err) {
            (Err(_), _) => diverged.push(("rust PANIC".into(), shown)),
            // pion refuses non-zero chunk padding; RFC 4960 §3.2 says the receiver MUST ignore it.
            (Ok(Ok(_)), Some(e))
                if e.contains("padding is non-zero")
                    || e.contains("non-zero trailing")
                    // An unrecognized parameter that says "skip me" is skipped here (RFC 4960
                    // §3.2.1); pion refuses a RECONFIG that carries one.
                    || e.contains("unhandled ParamType")
                    // A SACK with bytes after its gap/duplicate lists.
                    || e.contains("SACK Chunk size does not match") => {}
            (Ok(Ok(_)), Some(e)) => {
                diverged.push((format!("rust accepts, pion rejects: {e}"), shown))
            }
            // HEARTBEAT must carry a Heartbeat Info parameter (RFC 4960 §3.3.5); this crate refuses
            // one without, pion accepts it.
            (Ok(Err(e)), None) if e.to_string().contains("Heartbeat Info") => {}
            // An INIT parameter whose type says "stop processing" is refused while parsing here;
            // pion parses it and refuses it in the chunk's `check()`. Either way the INIT dies.
            (Ok(Err(e)), None)
                if e.to_string().contains("unhandled ParamType")
                    && has_chunk(&v, &["init", "init-ack"]) => {}
            (Ok(Err(e)), None) => {
                diverged.push((format!("rust rejects ({e}), pion accepts"), shown))
            }
            (Ok(Err(_)), Some(_)) => {}
            (Ok(Ok((names, out))), None) => {
                let want_names: Vec<&str> = v["chunks"]
                    .as_array()
                    .map(|a| a.iter().map(|x| x.as_str().unwrap()).collect())
                    .unwrap_or_default();
                if names != want_names.join(",") {
                    diverged.push((format!("chunks: want {want_names:?} got {names}"), shown));
                } else if has_chunk(&v, &["init", "init-ack"]) {
                    // pion drops unrecognized parameters when it re-marshals an INIT; this crate
                    // keeps them. The chunk types agreeing is what is compared.
                } else if v["out"].as_str().map(|s| hex(&normalize(&unhex(s))))
                    != Some(hex(&normalize(&unhex(&out))))
                {
                    diverged.push((format!("output: want {} got {out}", v["out"]), shown));
                }
            }
        }
    }
    eprintln!("{total} vectors, {} diverge from pion", diverged.len());
    if let Ok(report) = std::env::var("PION_SCTP_REPORT") {
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

fn has_chunk(v: &serde_json::Value, names: &[&str]) -> bool {
    v["chunks"]
        .as_array()
        .is_some_and(|c| c.iter().any(|n| names.iter().any(|x| n == x)))
}
