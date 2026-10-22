//! Differential test against pion/rtcp (v1.2.20): each vector in `tests/data/pion_rtcp_golden.jsonl`
//! is a datagram pion was run on, with pion's verdict and, when it accepted, the bytes pion
//! marshals the parsed packets back to. This crate must reach the same verdict and output.
//!
//! `PION_RTCP_GOLDEN=<file>` runs another vector file in exploration mode (report, don't fail);
//! `PION_RTCP_REPORT=<file>` writes the divergences as JSONL.

use bytes::Bytes;
use rtc_rtcp::packet;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn matches_pion_rtcp() {
    let (path, explore) = match std::env::var("PION_RTCP_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_rtcp_golden.jsonl",
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
        let pion_out = v.get("out").and_then(|e| e.as_str());
        total += 1;
        let shown = hex(&input);
        let got = std::panic::catch_unwind(|| {
            let mut buf = Bytes::from(input.clone());
            packet::unmarshal(&mut buf).and_then(|pkts| packet::marshal(&pkts))
        });
        match (got, pion_err) {
            (Err(_), _) => diverged.push(("rust PANIC".into(), shown)),
            (Ok(Ok(_)), Some(e)) => {
                diverged.push((format!("rust accepts, pion rejects: {e}"), shown))
            }
            // Documented strictness: pion lets a CCFB report block overlap the trailing report
            // timestamp and an XR block run past the end of its packet; this crate rejects both.
            (Ok(Err(_)), None) if has_pkt(&v, &["ExtendedReport", "CCFeedbackReport"]) => {}
            (Ok(Err(e)), None) => {
                diverged.push((format!("rust rejects ({e}), pion accepts"), shown))
            }
            (Ok(Err(_)), Some(_)) => {}
            (Ok(Ok(_)), None) if v.get("tcc").is_some() => {
                if let Some(why) = tcc_mismatch(&input, &v["tcc"]) {
                    diverged.push((why, shown));
                }
            }
            // A TWCC packet later in a compound datagram: pion re-emits its received header (see
            // `tcc_mismatch`), so the bytes are not comparable; the verdict above is.
            (Ok(Ok(_)), None) if has_tcc(&v) => {}
            // XR: this crate keeps reserved fields it receives, pion zeroes them. The verdict above
            // is still compared.
            (Ok(Ok(_)), None) if has_pkt(&v, &["ExtendedReport"]) => {}
            (Ok(Ok(out)), None) => {
                // pion keeps a TWCC packet's P bit exactly as received; this crate sets it only
                // when padding is needed. Compare with the P bit and pad-count byte masked.
                let out = hex(&mask_twcc_padding(&out));
                let pion_out = pion_out.map(|s| hex(&mask_twcc_padding(&unhex(s))));
                if Some(out.as_str()) != pion_out.as_deref() {
                    diverged.push((format!("output: want {:?} got {out}", pion_out), shown));
                }
            }
        }
    }
    eprintln!("{total} vectors, {} diverge from pion", diverged.len());
    if let Ok(report) = std::env::var("PION_RTCP_REPORT") {
        let out: String = diverged
            .iter()
            .map(|(w, i)| serde_json::json!({"why": w, "input": i}).to_string() + "\n")
            .collect();
        std::fs::write(report, out).unwrap();
    }
    if explore {
        for (w, i) in diverged.iter().take(15) {
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

/// Clears the P bit and the pad-count byte of every transport-wide CC packet in a datagram.
fn mask_twcc_padding(datagram: &[u8]) -> Vec<u8> {
    let mut out = datagram.to_vec();
    let mut i = 0;
    while i + 4 <= out.len() {
        let size = (u16::from_be_bytes([out[i + 2], out[i + 3]]) as usize + 1) * 4;
        if out[i + 1] == 205 && out[i] & 0x1f == 15 && out[i] & 0x20 != 0 && i + size <= out.len() {
            out[i] &= !0x20;
            out[i + size - 1] = 0;
        }
        i += size;
    }
    out
}

/// Compares the first packet's parsed transport-wide CC content with what pion parsed. Byte
/// comparison is unusable here: pion re-emits the header length it received, so its output can
/// disagree with its own size.
fn tcc_mismatch(input: &[u8], pion: &serde_json::Value) -> Option<String> {
    use rtc_rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
    let mut buf = Bytes::from(input.to_vec());
    let pkts = packet::unmarshal(&mut buf).unwrap();
    let Some(tcc) = pkts[0].as_any().downcast_ref::<TransportLayerCc>() else {
        return Some("pion parsed a TWCC packet, this crate did not".into());
    };
    let rust = serde_json::json!({
        "sender": tcc.sender_ssrc, "media": tcc.media_ssrc, "base": tcc.base_sequence_number,
        "count": tcc.packet_status_count, "ref": tcc.reference_time, "fb": tcc.fb_pkt_count,
        "chunks": tcc.packet_chunks.iter().map(|c| {
            use shared::marshal::Marshal;
            hex(&c.marshal().unwrap())
        }).collect::<Vec<_>>(),
        "deltas": tcc.recv_deltas.iter().map(|d| [d.type_tcc_packet as i64, d.delta]).collect::<Vec<_>>(),
    });
    (rust != *pion).then(|| format!("tcc fields: want {pion} got {rust}"))
}

fn has_tcc(v: &serde_json::Value) -> bool {
    has_pkt(v, &["TransportLayerCC"])
}

fn has_pkt(v: &serde_json::Value, names: &[&str]) -> bool {
    v["pkts"]
        .as_array()
        .is_some_and(|p| p.iter().any(|n| names.iter().any(|x| n == x)))
}
