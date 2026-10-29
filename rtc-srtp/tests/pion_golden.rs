//! Differential test against pion/srtp (v3.1.3): each row of `tests/data/pion_srtp_golden.jsonl` is a
//! protect or unprotect operation on a fresh context with a fixed master key and salt (key byte i =
//! i, salt byte i = 0x10 + i), with pion's output or error. This crate must produce the same bytes
//! and accept and refuse the same packets.
//!
//! `PION_SRTP_GOLDEN=<file>` runs another file in exploration mode (report, don't fail).

use rtc_srtp::context::Context;
use rtc_srtp::protection_profile::ProtectionProfile;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn profile(p: i64) -> ProtectionProfile {
    match p {
        1 => ProtectionProfile::Aes128CmHmacSha1_80,
        2 => ProtectionProfile::Aes128CmHmacSha1_32,
        3 => ProtectionProfile::Aes256CmHmacSha1_80,
        4 => ProtectionProfile::Aes256CmHmacSha1_32,
        7 => ProtectionProfile::AeadAes128Gcm,
        8 => ProtectionProfile::AeadAes256Gcm,
        other => panic!("profile {other}"),
    }
}

fn run(p: ProtectionProfile, op: &str, input: &[u8]) -> Result<String, String> {
    let key: Vec<u8> = (0..p.key_len() as u8).collect();
    let salt: Vec<u8> = (0..p.salt_len() as u8).map(|i| 0x10 + i).collect();
    let provider = crypto::default_provider().expect("crypto provider");
    let mut ctx =
        Context::new(&key, &salt, p, None, None, provider.crypto()).map_err(|e| e.to_string())?;
    let out = match op {
        "enc_rtp" => ctx.encrypt_rtp(input),
        "dec_rtp" => ctx.decrypt_rtp(input),
        "enc_rtcp" => ctx.encrypt_rtcp(input),
        "dec_rtcp" => ctx.decrypt_rtcp(input),
        other => panic!("op {other}"),
    };
    out.map(|b| hex(&b)).map_err(|e| e.to_string())
}

#[test]
fn matches_pion_srtp() {
    let (path, explore) = match std::env::var("PION_SRTP_GOLDEN") {
        Ok(p) => (p, true),
        Err(_) => (
            format!(
                "{}/tests/data/pion_srtp_golden.jsonl",
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
        let (prof, op) = (v["profile"].as_i64().unwrap(), v["op"].as_str().unwrap());
        let input = unhex(v["in"].as_str().unwrap());
        let pion_err = v.get("err").and_then(|e| e.as_str());
        total += 1;
        let shown = format!("p{prof} {op} {}", hex(&input));
        match (
            std::panic::catch_unwind(|| run(profile(prof), op, &input)),
            pion_err,
        ) {
            (Err(_), _) => diverged.push(("rust PANIC".into(), shown)),
            (Ok(Ok(_)), Some(e)) => {
                diverged.push((format!("rust accepts, pion rejects: {e}"), shown))
            }
            (Ok(Err(e)), None) => {
                diverged.push((format!("rust rejects ({e}), pion accepts"), shown))
            }
            (Ok(Err(_)), Some(_)) => {}
            (Ok(Ok(out)), None) => {
                if v["out"].as_str() != Some(out.as_str()) {
                    diverged.push((format!("output: want {} got {out}", v["out"]), shown));
                }
            }
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
