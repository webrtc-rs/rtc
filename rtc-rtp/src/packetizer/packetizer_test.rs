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
