//! Differential test against pion/turn v5.1.2's `internal/proto`: each row of
//! `tests/data/pion_turn_golden.jsonl` is a datagram — a seed or a mutation of one — classified as a
//! peer does (STUN message, ChannelData, or neither), with what pion's attribute getters and
//! ChannelData decoder found. This crate must agree. See `tests/oracle/README.md`.
//!
//! `PION_TURN_GOLDEN=<file>` replays another file and lists the divergences instead of failing.

use rtc_turn::proto::chandata::ChannelData;
use rtc_turn::proto::channum::ChannelNumber;
use rtc_turn::proto::connid::ConnectionId;
use rtc_turn::proto::data::Data;
use rtc_turn::proto::dontfrag::DontFragmentAttr;
use rtc_turn::proto::evenport::EvenPort;
use rtc_turn::proto::lifetime::Lifetime;
use rtc_turn::proto::peeraddr::PeerAddress;
use rtc_turn::proto::relayaddr::RelayedAddress;
use rtc_turn::proto::reqfamily::RequestedAddressFamily;
use rtc_turn::proto::reqtrans::RequestedTransport;
use rtc_turn::proto::rsrvtoken::ReservationToken;
use serde_json::{Map, Value, json};
use stun::attributes::*;
use stun::message::{Getter, Message, is_stun_message};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// "absent", "err", or "ok <value>".
fn attr<G: Getter>(
    m: &Message,
    typ: AttrType,
    mut getter: G,
    show: impl Fn(&G) -> String,
) -> String {
    if !m.contains(typ) {
        return "absent".to_owned();
    }
    match getter.get_from(m) {
        Ok(()) => format!("ok {}", show(&getter)),
        Err(_) => "err".to_owned(),
    }
}

fn attrs(m: &Message) -> Value {
    let mut out = Map::new();
    let mut put = |name: &str, v: String| {
        out.insert(name.to_owned(), json!(v));
    };
    put(
        "channel-number",
        attr(m, ATTR_CHANNEL_NUMBER, ChannelNumber::default(), |n| {
            n.0.to_string()
        }),
    );
    put(
        "lifetime",
        attr(m, ATTR_LIFETIME, Lifetime::default(), |l| {
            l.0.as_secs().to_string()
        }),
    );
    put("data", attr(m, ATTR_DATA, Data::default(), |d| hex(&d.0)));
    put(
        "even-port",
        attr(m, ATTR_EVEN_PORT, EvenPort::default(), |e| {
            e.reserve_port().to_string()
        }),
    );
    put(
        "requested-transport",
        attr(
            m,
            ATTR_REQUESTED_TRANSPORT,
            RequestedTransport::default(),
            |r| r.protocol.0.to_string(),
        ),
    );
    put(
        "requested-family",
        attr(
            m,
            ATTR_REQUESTED_ADDRESS_FAMILY,
            RequestedAddressFamily::default(),
            |f| f.0.to_string(),
        ),
    );
    put(
        "reservation-token",
        attr(
            m,
            ATTR_RESERVATION_TOKEN,
            ReservationToken::default(),
            |t| hex(&t.0),
        ),
    );
    put(
        "dont-fragment",
        attr(m, ATTR_DONT_FRAGMENT, DontFragmentAttr, |_| String::new()),
    );
    put(
        "peer-address",
        attr(m, ATTR_XOR_PEER_ADDRESS, PeerAddress::default(), |a| {
            format!("{}:{}", a.ip, a.port)
        }),
    );
    put(
        "relayed-address",
        attr(
            m,
            ATTR_XOR_RELAYED_ADDRESS,
            RelayedAddress::default(),
            |a| format!("{}:{}", a.ip, a.port),
        ),
    );
    put(
        "connection-id",
        attr(m, ATTR_CONNECTION_ID, ConnectionId::default(), |c| {
            c.0.to_string()
        }),
    );
    Value::Object(out)
}

fn analyze(raw: &[u8]) -> Value {
    if is_stun_message(raw) {
        let mut m = Message {
            raw: raw.to_vec(),
            ..Default::default()
        };
        if m.decode().is_err() {
            return json!({ "kind": "stun", "err": "decode" });
        }
        return json!({ "kind": "stun", "attrs": attrs(&m) });
    }
    if ChannelData::is_channel_data(raw) {
        let mut c = ChannelData {
            raw: raw.to_vec(),
            ..Default::default()
        };
        if c.decode().is_err() {
            return json!({ "kind": "chandata", "err": "decode" });
        }
        let (number, data) = (c.number.0, hex(&c.data));
        c.encode();
        return json!({ "kind": "chandata", "num": number, "data": data, "reenc": hex(&c.raw) });
    }
    json!({ "kind": "none" })
}

fn differences(want: &Value, got: &Value) -> Vec<String> {
    let mut out = vec![];
    // Attributes one by one, so a divergence names the attribute.
    if let (Some(w), Some(g)) = (want.get("attrs"), got.get("attrs")) {
        for (name, wv) in w.as_object().unwrap() {
            // pion's `firstBitSet` is `(1 << 8) - 1`, not `1 << 7`: it writes 0xFF and reads any
            // non-zero EVEN-PORT byte as "reserve the next port". RFC 5766 §14.6 gives the first bit
            // that meaning and has the other seven ignored, as this crate does.
            let pion_reads_reserved_bits =
                name == "even-port" && wv == "ok true" && g[name] == "ok false";
            if g.get(name) != Some(wv) && !pion_reads_reserved_bits {
                out.push(format!("{name}: pion {wv}, this crate {}", g[name]));
            }
        }
    }
    for k in ["kind", "err", "num", "data", "reenc"] {
        // The oracle omits empty fields (`omitempty`).
        let norm = |v: &Value| match v.get(k) {
            None => Value::Null,
            Some(x) if x == &json!(0) || x == "" => Value::Null,
            Some(x) => x.clone(),
        };
        let (w, g) = (norm(want), norm(got));
        if w != g {
            out.push(format!("{k}: pion {w}, this crate {g}"));
        }
    }
    out
}

fn replay(text: &str) -> (usize, Vec<String>) {
    let (mut rows, mut divergences) = (0, vec![]);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let want: Value = serde_json::from_str(line).unwrap();
        let input = want["in"].as_str().unwrap();
        rows += 1;
        let diff = differences(&want, &analyze(&unhex(input)));
        if !diff.is_empty() {
            divergences.push(format!("{input}: {}", diff.join("; ")));
        }
    }
    (rows, divergences)
}

#[test]
fn matches_pion_turn_proto() {
    if let Ok(path) = std::env::var("PION_TURN_GOLDEN") {
        let (rows, divergences) = replay(&std::fs::read_to_string(path).unwrap());
        for d in &divergences {
            eprintln!("DIVERGES {d}");
        }
        eprintln!("{} of {rows} rows diverge", divergences.len());
        return;
    }
    let (rows, divergences) = replay(include_str!("data/pion_turn_golden.jsonl"));
    assert!(rows >= 5000, "the golden file is missing rows: {rows}");
    assert!(
        divergences.is_empty(),
        "{} of {rows} rows diverge from pion; first: {:#?}",
        divergences.len(),
        &divergences[..divergences.len().min(12)]
    );
}
