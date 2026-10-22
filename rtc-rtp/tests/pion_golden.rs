//! Differential test against pion/rtp (v1.10.6): each row of `tests/data/pion_rtp_golden.jsonl` is
//! an input pion was run on — an RTP packet, a codec payload to depacketize, or a frame to
//! packetize at some MTU — together with what pion produced. This crate must agree on the
//! verdict and the bytes.
//!
//! `PION_RTP_GOLDEN=<file>` runs another file in exploration mode (report, don't fail);
//! `PION_RTP_REPORT=<file>` writes the divergences as JSONL.

use bytes::Bytes;
use rtc_rtp::codec::av1::{Av1Depacketizer, Av1Payloader};
use rtc_rtp::codec::g7xx::G7xxPayloader;
use rtc_rtp::codec::h264::{H264Packet, H264Payloader};
use rtc_rtp::codec::h265::{H265Depacketizer, HevcPayloader};
use rtc_rtp::codec::h266::{H266Depacketizer, H266Payloader};
use rtc_rtp::codec::opus::{OpusPacket, OpusPayloader};
use rtc_rtp::codec::vp8::{Vp8Packet, Vp8Payloader};
use rtc_rtp::codec::vp9::{Vp9Packet, Vp9Payloader};
use rtc_rtp::packet::Packet;
use rtc_rtp::packetizer::{Depacketizer, Payloader};
use shared::marshal::{Marshal, Unmarshal};
use std::sync::Arc;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

enum Outcome {
    Err(String),
    Frames(Vec<String>, Option<bool>),
    Pkt(serde_json::Value),
    Skip,
}

fn depacketize<D: Depacketizer>(mut d: D, input: &Bytes, has_head: bool) -> Outcome {
    match d.depacketize(input) {
        Ok(out) => Outcome::Frames(
            vec![hex(&out)],
            has_head.then(|| d.is_partition_head(input)),
        ),
        Err(e) => Outcome::Err(e.to_string()),
    }
}

fn payload<P: Payloader>(mut p: P, mtu: usize, input: &Bytes) -> Outcome {
    match p.payload(mtu, input) {
        Ok(v) => Outcome::Frames(v.iter().map(|b| hex(b)).collect(), None),
        Err(e) => Outcome::Err(e.to_string()),
    }
}

fn run(kind: &str, op: &str, mtu: usize, input: Vec<u8>) -> Outcome {
    let bytes = Bytes::from(input);
    match (op, kind) {
        ("unmarshal", "Packet") => {
            let mut b = bytes.clone();
            match Packet::unmarshal(&mut b) {
                Err(e) => Outcome::Err(e.to_string()),
                Ok(p) => {
                    let h = &p.header;
                    let mut ids = h.get_extension_ids();
                    ids.sort_unstable();
                    let exts: serde_json::Map<String, serde_json::Value> = ids
                        .iter()
                        .map(|id| (id.to_string(), hex(&h.get_extension(*id).unwrap()).into()))
                        .collect();
                    // pion re-emits the minimal extension block; this crate keeps the padding it
                    // received. Compare the minimal form.
                    let mut q = p.clone();
                    q.header.extensions_padding = 0;
                    let marshaled = match q.marshal() {
                        Ok(m) => hex(&m),
                        Err(e) => format!("ERR:{e}"),
                    };
                    Outcome::Pkt(serde_json::json!({
                        "version": h.version, "padding": h.padding, "ext": h.extension, "marker": h.marker,
                        "pt": h.payload_type, "seq": h.sequence_number, "ts": h.timestamp, "ssrc": h.ssrc,
                        "csrc": h.csrc, "ext_profile": h.extension_profile, "exts": exts,
                        "payload": hex(&p.payload),
                        "pad_size": h.padding_size,
                        "marshaled": marshaled,
                    }))
                }
            }
        }
        ("unmarshal", "H264Packet") => depacketize(H264Packet::default(), &bytes, true),
        ("unmarshal", "VP8Packet") => depacketize(Vp8Packet::default(), &bytes, true),
        ("unmarshal", "VP9Packet") => depacketize(Vp9Packet::default(), &bytes, true),
        ("unmarshal", "OpusPacket") => depacketize(OpusPacket, &bytes, false),
        ("unmarshal", "H265Depacketizer") => {
            depacketize(H265Depacketizer::default(), &bytes, false)
        }
        ("unmarshal", "H266Depacketizer") => {
            depacketize(H266Depacketizer::default(), &bytes, false)
        }
        ("unmarshal", "AV1Depacketizer") => depacketize(Av1Depacketizer::default(), &bytes, false),
        ("payload", "H264Payloader") => payload(H264Payloader::default(), mtu, &bytes),
        ("payload", "VP8Payloader") => payload(
            {
                let mut p = Vp8Payloader::default();
                p.enable_picture_id = true;
                p
            },
            mtu,
            &bytes,
        ),
        ("payload", "VP9Payloader") => payload(
            {
                let mut p = Vp9Payloader::default();
                p.initial_picture_id_fn = Some(Arc::new(|| 0x1234));
                p
            },
            mtu,
            &bytes,
        ),
        ("payload", "OpusPayloader") => payload(OpusPayloader, mtu, &bytes),
        ("payload", "G711Payloader" | "G722Payloader") => payload(G7xxPayloader, mtu, &bytes),
        ("payload", "H265Payloader") => payload(HevcPayloader::default(), mtu, &bytes),
        ("payload", "H266Packetizer") => payload(H266Payloader::default(), mtu, &bytes),
        // The AV1 packetization strategy differs from pion's (this crate follows libwebrtc), so
        // payloads are not compared byte for byte: see `av1_semantic`.
        ("payload", "AV1Payloader") => Outcome::Skip,
        _ => Outcome::Skip,
    }
}

#[test]
fn matches_pion_rtp() {
    let (path, explore) = match std::env::var("PION_RTP_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_rtp_golden.jsonl",
                env!("CARGO_MANIFEST_DIR")
            ),
            false,
        ),
    };
    let data = std::fs::read_to_string(path).unwrap();
    let mut diverged: Vec<(String, String, String)> = vec![];
    let (mut total, mut skipped) = (0, 0);
    for line in data.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let (kind, op) = (v["k"].as_str().unwrap(), v["op"].as_str().unwrap());
        let mtu = v["mtu"].as_u64().unwrap() as usize;
        let input = unhex(v["in"].as_str().unwrap());
        let pion_err = v.get("err").and_then(|e| e.as_str());
        if pion_err.is_some_and(|e| e.starts_with("SKIP")) {
            continue;
        }
        // Go distinguishes a nil frame from an empty one (G.711 answers `[]` for nil, `[""]` for
        // empty); Rust has one empty value, and answers `[]`. Empty frames are not compared.
        if op == "payload" && input.is_empty() {
            continue;
        }
        let shown = format!("{kind} {op} mtu={mtu} {}", hex(&input));
        if kind == "AV1Payloader" {
            total += 1;
            if let Some(why) = av1_semantic(&v, mtu, &input) {
                diverged.push((kind.to_string(), why, shown));
            }
            continue;
        }
        let got = std::panic::catch_unwind(|| run(kind, op, mtu, input.clone()));
        total += 1;
        let tag = kind.to_string();
        match (got, pion_err) {
            (Err(_), _) => diverged.push((tag, "rust PANIC".into(), shown)),
            (Ok(Outcome::Skip), _) => {
                total -= 1;
                skipped += 1;
            }
            (Ok(Outcome::Err(_)), Some(_)) => {}
            // Documented strictness: an AV1 size field that runs past 8 bytes is not valid LEB128
            // ([AV1 spec] §4.10.5); pion reads it to the end and accepts the garbage.
            (Ok(Outcome::Err(_)), None)
                if kind == "AV1Depacketizer" && has_overlong_leb128(&input) => {}
            (Ok(Outcome::Err(e)), None) => {
                diverged.push((tag, format!("rust rejects ({e}), pion accepts"), shown))
            }
            // Documented leniency: a packet whose last element is a skipped temporal delimiter
            // is fine here; pion reports a count mismatch.
            (Ok(_), Some(e)) if kind == "AV1Depacketizer" && e.contains("OBU count") => {}
            (Ok(_), Some(e)) => {
                diverged.push((tag, format!("rust accepts, pion rejects: {e}"), shown))
            }
            (Ok(Outcome::Pkt(p)), None) => {
                let mut want = v["pkt"].clone();
                if want["csrc"].is_null() {
                    want["csrc"] = serde_json::json!([]);
                }
                if p != want {
                    diverged.push((tag, format!("packet: want {} got {p}", v["pkt"]), shown));
                }
            }
            (Ok(Outcome::Frames(out, head)), None) => {
                let out = if kind == "H265Depacketizer" {
                    mask_paci_f_bit(&input, out)
                } else {
                    out
                };
                let want: Vec<String> = v["out"]
                    .as_array()
                    .map(|a| a.iter().map(|x| x.as_str().unwrap().to_owned()).collect())
                    .unwrap_or_default();
                let want = if kind == "H265Depacketizer" {
                    mask_paci_f_bit(&input, want)
                } else {
                    want
                };
                if out != want {
                    diverged.push((tag, format!("output: want {want:?} got {out:?}"), shown));
                } else if let (Some(h), Some(w)) = (head, v["head"].as_bool()) {
                    if h != w {
                        diverged.push((tag, format!("is_partition_head: want {w} got {h}"), shown));
                    }
                }
            }
        }
    }
    eprintln!(
        "{total} vectors ({skipped} of kinds not implemented here), {} diverge from pion",
        diverged.len()
    );
    if let Ok(report) = std::env::var("PION_RTP_REPORT") {
        let out: String = diverged
            .iter()
            .map(|(k, w, i)| {
                serde_json::json!({"kind": k, "why": w, "input": i}).to_string() + "\n"
            })
            .collect();
        std::fs::write(report, out).unwrap();
    }
    if explore {
        let mut per: std::collections::BTreeMap<&str, usize> = Default::default();
        for (k, _, _) in &diverged {
            *per.entry(k.as_str()).or_default() += 1;
        }
        eprintln!("by kind: {per:?}");
        return;
    }
    assert!(
        diverged.is_empty(),
        "diverges from pion:\n{}",
        diverged
            .iter()
            .take(5)
            .map(|(_, w, i)| format!("{w}\n{i}"))
            .collect::<Vec<_>>()
            .join("\n---\n")
    );
}

/// AV1 payloads from this crate must fit the MTU and, depacketized in order, rebuild the same
/// OBU stream pion's depacketizer rebuilds from pion's own payloads. Pion's payloads must also
/// depacketize to that stream here. A panic or an oversize packet is a failure.
fn av1_semantic(v: &serde_json::Value, mtu: usize, input: &[u8]) -> Option<String> {
    let bytes = Bytes::from(input.to_vec());
    let mine = std::panic::catch_unwind(|| Av1Payloader::default().payload(mtu, &bytes));
    let mine = match mine {
        Err(_) => return Some("rust PANIC in AV1 payloader".into()),
        Ok(m) => m,
    };
    // Pion stops at the first OBU that does not parse and packetizes what came before; this crate
    // refuses the frame. Only "no panic" is required of a malformed frame.
    if v["malformed"].as_bool().unwrap_or(false) {
        return None;
    }
    if let Some(pion_stream) = v.get("stream").and_then(|s| s.as_str()) {
        // Pion's own payloads through this crate's depacketizer.
        let pion_out: Vec<Vec<u8>> = v["out"]
            .as_array()
            .map(|a| a.iter().map(|x| unhex(x.as_str().unwrap())).collect())
            .unwrap_or_default();
        let mut d = Av1Depacketizer::default();
        let mut stream = vec![];
        for p in &pion_out {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                d.depacketize(&Bytes::from(p.clone()))
            })) {
                Err(_) => return Some("rust PANIC in AV1 depacketizer".into()),
                Ok(Err(e)) => return Some(format!("rust rejects pion's AV1 payload: {e}")),
                Ok(Ok(b)) => stream.extend_from_slice(&b),
            }
        }
        if hex(&stream) != pion_stream {
            return Some(format!(
                "pion payloads depacketize differently: want {pion_stream} got {}",
                hex(&stream)
            ));
        }
        // This crate's payloads through this crate's depacketizer.
        let Ok(mine) = mine else {
            return Some("rust rejects an AV1 frame pion packetizes".into());
        };
        let mut d = Av1Depacketizer::default();
        let mut stream = vec![];
        for p in &mine {
            if p.len() > mtu {
                return Some(format!(
                    "rust AV1 packet of {} bytes exceeds mtu {mtu}",
                    p.len()
                ));
            }
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| d.depacketize(p))) {
                Err(_) => return Some("rust PANIC in AV1 depacketizer".into()),
                Ok(Err(e)) => {
                    return Some(format!("rust cannot depacketize its own AV1 payload: {e}"));
                }
                Ok(Ok(b)) => stream.extend_from_slice(&b),
            }
        }
        if hex(&stream) != pion_stream {
            return Some(format!(
                "own payloads rebuild a different stream: want {pion_stream} got {}",
                hex(&stream)
            ));
        }
    }
    None
}

fn has_overlong_leb128(input: &[u8]) -> bool {
    input.windows(8).any(|w| w.iter().all(|b| b & 0x80 != 0))
}

/// pion's PACI `A` accessor evaluates `(h & 1) << 15` (Go gives `&` and `<<` the same
/// precedence), so it copies bit 0 of the PACI fields into the F bit of the rebuilt NAL header.
/// This crate follows RFC 7798 and copies bit 15. Compare with that header bit cleared.
fn mask_paci_f_bit(input: &[u8], mut out: Vec<String>) -> Vec<String> {
    if input.len() >= 2 && (u16::from_be_bytes([input[0], input[1]]) >> 9) & 0x3f == 50 {
        for o in out.iter_mut() {
            // after the 4-byte start code, the high bit of the first header byte
            if let Some(b) = o.get(8..10).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                o.replace_range(8..10, &format!("{:02x}", b & 0x7f));
            }
        }
    }
    out
}
