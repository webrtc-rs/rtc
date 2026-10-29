//! Differential test against pion/datachannel (v1.6.3): each row of `tests/data/pion_datachannel_golden.jsonl`
//! is a message pion's DCEP parser accepted or rejected. This crate must reach the same verdict.
//!
//! `PION_DC_GOLDEN=<file>` runs another file in exploration mode (report, don't fail).

use bytes::Bytes;
use rtc_datachannel::message::Message;
use shared::marshal::{Marshal, Unmarshal};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn matches_pion_datachannel() {
    let (path, explore) = match std::env::var("PION_DC_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_datachannel_golden.jsonl",
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
        let hex_in = v["in"].as_str().unwrap();
        let input = unhex(hex_in);
        let pion_rejects = v.get("err").is_some();
        total += 1;
        let got = std::panic::catch_unwind(|| {
            let mut b = Bytes::from(input.clone());
            Message::unmarshal(&mut b).and_then(|m| match m {
                // 0x00 and 0x01 are this crate's own control messages; DCEP defines only
                // ACK (0x02) and OPEN (0x03), and the receive path refuses the others.
                Message::DataChannelThreshold(_) | Message::DataChannelClose(_) => {
                    Err(shared::error::Error::InvalidMessageType(input[0]))
                }
                m => m.marshal().map(|_| ()),
            })
        });
        match (got, pion_rejects) {
            (Err(_), _) => diverged.push(("rust PANIC".into(), hex_in.into())),
            // Documented leniency: bytes after the label and protocol of an OPEN are ignored here;
            // pion insists the message is exactly as long as its header says.
            (Ok(Ok(())), true) if open_has_trailing_bytes(&input) => {}
            (Ok(Ok(())), true) => {
                diverged.push(("rust accepts, pion rejects".into(), hex_in.into()))
            }
            // Documented strictness: a DATA_CHANNEL_OPEN with a channel type RFC 8832 §5.1 does not
            // define is refused here; pion accepts it.
            (Ok(Err(_)), false)
                if input.len() > 1
                    && input[0] == 3
                    && ![0, 1, 2, 0x80, 0x81, 0x82].contains(&input[1]) => {}
            (Ok(Err(e)), false) => {
                diverged.push((format!("rust rejects ({e}), pion accepts"), hex_in.into()))
            }
            _ => {}
        }
    }
    eprintln!("{total} vectors, {} diverge from pion", diverged.len());
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

fn open_has_trailing_bytes(input: &[u8]) -> bool {
    if input.len() < 12 || input[0] != 3 {
        return false;
    }
    let label = u16::from_be_bytes([input[8], input[9]]) as usize;
    let protocol = u16::from_be_bytes([input[10], input[11]]) as usize;
    input.len() > 12 + label + protocol
}
