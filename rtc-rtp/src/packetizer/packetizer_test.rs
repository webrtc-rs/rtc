use super::*;
use crate::codec::*;
use shared::error::Result;

use chrono::prelude::*;
use std::time::Duration;

#[test]
fn test_packetizer() -> Result<()> {
    let now = Instant::now();
    let multiple_payload = Bytes::from_static(&[0; 128]);
    let g722 = Box::new(g7xx::G722Payloader {});
    let seq = Box::new(new_random_sequencer());

    //use the G722 payloader here, because it's very simple and all 0s is valid G722 data.
    let mut packetizer = new_packetizer(now, 100, 98, 0x1234ABCD, g722, seq, 90000);
    let packets = packetizer.packetize(now, &multiple_payload, 2000)?;

    if packets.len() != 2 {
        let mut packet_lengths = String::new();
        #[allow(clippy::needless_range_loop)]
        for i in 0..packets.len() {
            packet_lengths +=
                format!("Packet {} length {}\n", i, packets[i].payload.len()).as_str();
        }
        panic!(
            "Generated {} packets instead of 2\n{}",
            packets.len(),
            packet_lengths,
        );
    }
    Ok(())
}

#[test]
fn test_packetizer_abs_send_time() -> Result<()> {
    let g722 = Box::new(g7xx::G722Payloader {});
    let sequencer = Box::new(new_fixed_sequencer(1234));
    let time_baseline = SystemInstant::now(Instant::now());

    // The instant to stamp the packet at, chosen so the NTP fraction is exactly 0x40000000.
    let loc = FixedOffset::west_opt(5 * 60 * 60).unwrap(); // UTC-5
    let t = loc.with_ymd_and_hms(2199, 6, 23, 4, 0, 0).unwrap();
    let duration_since_unix_epoch = Duration::from_nanos(t.timestamp_nanos_opt().unwrap() as u64);
    let send_at = time_baseline.instant(duration_since_unix_epoch);

    //use the G722 payloader here, because it's very simple and all 0s is valid G722 data.
    let mut pktizer = PacketizerImpl {
        mtu: 100,
        payload_type: 98,
        ssrc: 0x1234ABCD,
        payloader: g722,
        sequencer,
        timestamp: 45678,
        clock_rate: 90000,
        abs_send_time_ext_id: 0,
        abs_capture_time_ext_id: 0,
        ntp_64_ext_id: 0,
        time_baseline,
    };
    pktizer.enable_abs_send_time(1);

    let payload = Bytes::from_static(&[0x11, 0x12, 0x13, 0x14]);
    let packets = pktizer.packetize(send_at, &payload, 2000)?;

    let expected = Packet {
        header: Header {
            version: 2,
            padding: false,
            extension: true,
            marker: true,
            payload_type: 98,
            sequence_number: 1234,
            timestamp: 45678,
            ssrc: 0x1234ABCD,
            csrc: vec![],
            extension_profile: 0xBEDE,
            extensions: vec![Extension {
                id: 1,
                payload: Bytes::from_static(&[0x40, 0, 0]),
            }],
            extensions_padding: 0,
        },
        payload: Bytes::from_static(&[0x11, 0x12, 0x13, 0x14]),
    };

    if packets.len() != 1 {
        panic!("Generated {} packets instead of 1", packets.len())
    }

    assert_eq!(packets[0], expected);

    Ok(())
}

#[test]
fn test_packetizer_timestamp_rollover_does_not_panic() -> Result<()> {
    let now = Instant::now();
    let g722 = Box::new(g7xx::G722Payloader {});
    let seq = Box::new(new_random_sequencer());

    let payload = Bytes::from_static(&[0; 128]);
    let mut packetizer = new_packetizer(now, 100, 98, 0x1234ABCD, g722, seq, 90000);

    packetizer.packetize(now, &payload, 10)?;

    packetizer.packetize(now, &payload, u32::MAX)?;

    packetizer.skip_samples(u32::MAX);

    Ok(())
}

/// The absolute-send-time extension is derived from the instant the caller supplies, so two
/// frames stamped at the same instant carry the same extension and a later one carries a later
/// value — with no wall-clock time passing between them.
#[test]
fn test_packetizer_abs_send_time_comes_from_the_caller() -> Result<()> {
    let base = Instant::now();
    let t = |secs| base + Duration::from_secs(secs);

    let payload = Bytes::from_static(&[0x11, 0x12, 0x13, 0x14]);
    let mut packetizer = new_packetizer(
        t(0),
        100,
        98,
        0x1234ABCD,
        Box::new(g7xx::G722Payloader {}),
        Box::new(new_fixed_sequencer(1234)),
        90000,
    );
    packetizer.enable_abs_send_time(1);

    let abs_send_time = |packets: &[Packet]| packets[0].header.extensions[0].payload.clone();

    let first = abs_send_time(&packetizer.packetize(t(10), &payload, 2000)?);
    let same_instant = abs_send_time(&packetizer.packetize(t(10), &payload, 2000)?);
    let later = abs_send_time(&packetizer.packetize(t(20), &payload, 2000)?);

    assert_eq!(first, same_instant, "same instant, same absolute send time");
    assert_ne!(first, later, "a later instant must stamp a later time");

    Ok(())
}

/// The absolute-capture-time extension is derived from the `capture_time` passed to
/// `packetize_captured_at`, not from `now` (the send instant) — the two can differ by however
/// long the frame spent between capture and packetization.
#[test]
fn test_packetizer_abs_capture_time_comes_from_capture_time() -> Result<()> {
    let base = Instant::now();
    let t = |secs| base + Duration::from_secs(secs);

    let payload = Bytes::from_static(&[0x11, 0x12, 0x13, 0x14]);
    let mut packetizer = new_packetizer(
        t(0),
        100,
        98,
        0x1234ABCD,
        Box::new(g7xx::G722Payloader {}),
        Box::new(new_fixed_sequencer(1234)),
        90000,
    );
    packetizer.enable_abs_send_time(1);
    packetizer.enable_abs_capture_time(2);

    let ext = |packets: &[Packet], id: u8| {
        packets[0]
            .header
            .extensions
            .iter()
            .find(|e| e.id == id)
            .unwrap()
            .payload
            .clone()
    };

    // Sent "now" at t(10), but the frame was captured earlier, at t(5).
    let sent_at_10_captured_at_5 = packetizer.packetize_captured_at(t(10), t(5), &payload, 2000)?;
    // Same send instant, but captured later, at t(10): abs-send-time must be unchanged, while
    // abs-capture-time must differ.
    let sent_at_10_captured_at_10 =
        packetizer.packetize_captured_at(t(10), t(10), &payload, 2000)?;
    // Same capture instant as the first packet, t(5), but sent later, at t(20):
    // abs-capture-time must be unchanged, while abs-send-time must differ.
    let sent_at_20_captured_at_5 = packetizer.packetize_captured_at(t(20), t(5), &payload, 2000)?;

    assert_eq!(
        ext(&sent_at_10_captured_at_5, 1),
        ext(&sent_at_10_captured_at_10, 1),
        "same now, same abs-send-time, regardless of capture_time"
    );
    assert_ne!(
        ext(&sent_at_10_captured_at_5, 2),
        ext(&sent_at_10_captured_at_10, 2),
        "different capture_time must stamp a different abs-capture-time"
    );

    assert_eq!(
        ext(&sent_at_10_captured_at_5, 2),
        ext(&sent_at_20_captured_at_5, 2),
        "same capture_time, same abs-capture-time, regardless of now"
    );
    assert_ne!(
        ext(&sent_at_10_captured_at_5, 1),
        ext(&sent_at_20_captured_at_5, 1),
        "different now must stamp a different abs-send-time"
    );

    Ok(())
}
