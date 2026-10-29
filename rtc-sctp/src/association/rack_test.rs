use super::*;
use crate::chunk::chunk_selective_ack::GapAckBlock;

fn rack_association() -> Association {
    let mut a = create_association(TransportConfig::default());
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.rwnd = 1 << 20;
    a.cwnd = 1 << 20;
    a.rto_mgr.set_rto(1000, true);
    a
}

fn send_chunks(a: &mut Association, count: usize, now: Instant) -> Vec<ChunkPayloadData> {
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi).unwrap();
    for _ in 0..count {
        a.stream(1)
            .unwrap()
            .write_sctp(now, &Bytes::from(vec![0xCD; 1000]), ppi)
            .unwrap();
    }
    transmitted_data(&a.gather_outbound(now).0)
}

fn sack(cumulative: u32, gaps: &[(u16, u16)]) -> ChunkSelectiveAck {
    ChunkSelectiveAck {
        cumulative_tsn_ack: cumulative,
        advertised_receiver_window_credit: 1 << 20,
        gap_ack_blocks: gaps
            .iter()
            .map(|&(start, end)| GapAckBlock { start, end })
            .collect(),
        duplicate_tsn: vec![],
    }
}

/// A lost tail leaves no later chunk to expose a gap, so classic loss detection waits a full
/// retransmission timeout. The probe fires after about two round trips instead and re-sends the
/// newest chunk, without treating that as loss.
#[test]
fn probe_timer_beats_the_retransmission_timeout_and_resends_the_newest_chunk() {
    let mut a = rack_association();
    let t0 = Instant::now();
    let sent = send_chunks(&mut a, 4, t0);
    assert_eq!(4, sent.len());

    // One acknowledged round trip of 5 ms gives the estimator something to work with.
    a.handle_sack(&sack(sent[0].tsn, &[]), t0 + Duration::from_millis(5))
        .unwrap();
    let cwnd_before = a.cwnd;
    let ssthresh_before = a.ssthresh;

    let pto = a
        .timers
        .get(Timer::Pto)
        .expect("data is outstanding: the probe timer runs");
    let t3 = a.timers.get(Timer::T3RTX).expect("and so does T3");
    assert!(
        pto < t3,
        "the probe must come well before the retransmission timeout"
    );
    assert!(
        pto - (t0 + Duration::from_millis(5)) < Duration::from_millis(100),
        "two RTTs plus slack, not a second"
    );

    a.handle_timeout(pto);
    let resent = transmitted_data(&a.gather_outbound(pto).0);
    assert_eq!(
        vec![sent[3].tsn],
        resent.iter().map(|c| c.tsn).collect::<Vec<_>>(),
        "the probe re-sends the newest outstanding chunk, and only that"
    );
    assert_eq!(2, a.inflight_queue.get(sent[3].tsn).unwrap().nsent);
    assert_eq!(
        cwnd_before, a.cwnd,
        "a probe is not a loss: cwnd is untouched"
    );
    assert_eq!(ssthresh_before, a.ssthresh);
    assert!(!a.in_fast_recovery);
    assert_eq!(1, a.stats.get_num_pto_probes());
    assert_eq!(0, a.stats.get_num_t3timeouts());
}

/// When chunks sent after a missing one are acknowledged and that is more than a round trip
/// ago, the missing one is lost: no third duplicate report needed, and one congestion response
/// however many chunks were lost.
#[test]
fn chunks_older_than_a_delivered_one_are_declared_lost_without_three_reports() {
    let mut a = rack_association();
    let t0 = Instant::now();
    let sent = send_chunks(&mut a, 10, t0);
    assert_eq!(10, sent.len());
    let first = sent[0].tsn;
    let cwnd_before = a.cwnd;

    // Chunks 4..9 arrive, 0..3 are missing.
    let report = sack(first - 1, &[(4 + 1, 9 + 1)]);
    a.handle_sack(&report, t0 + Duration::from_millis(10))
        .unwrap();

    for lost in &sent[..4] {
        assert!(
            a.inflight_queue.get(lost.tsn).unwrap().retransmit,
            "tsn {} should have been declared lost by RACK",
            lost.tsn
        );
    }
    for delivered in &sent[4..] {
        assert!(!a.inflight_queue.get(delivered.tsn).unwrap().retransmit);
    }
    assert_eq!(4, a.stats.get_num_rack_losses());
    assert!(a.in_fast_recovery);
    assert_eq!(cwnd_before / 2, a.cwnd, "exactly one halving");

    let resent = transmitted_data(&a.gather_outbound(t0 + Duration::from_millis(10)).0);
    assert_eq!(
        sent[..4].iter().map(|c| c.tsn).collect::<Vec<_>>(),
        resent.iter().map(|c| c.tsn).collect::<Vec<_>>()
    );
    // Retransmitted chunks are no longer RACK's business, and they are not RTT samples.
    assert!(
        a.rack
            .outstanding
            .iter()
            .all(|t| t.0 >= sent[4].tsn || t.0 > sent[3].tsn)
    );
}

/// Packets that arrive out of order are not loss. Once reordering has been seen, the window that
/// separates "late" from "lost" stays open for a fraction of the round-trip time and a timer
/// re-checks the suspects instead of condemning them on the spot.
#[test]
fn reordering_gets_a_window_before_anything_is_declared_lost() {
    let mut a = rack_association();
    let t0 = Instant::now();
    // The first send gives a round trip of 8 ms; then one more flight.
    let first = send_chunks(&mut a, 2, t0);
    a.handle_sack(&sack(first[1].tsn, &[]), t0 + Duration::from_millis(8))
        .unwrap();
    let t1 = t0 + Duration::from_millis(10);
    a.stream(1)
        .unwrap()
        .write_sctp(
            t1,
            &Bytes::from(vec![1; 1000]),
            PayloadProtocolIdentifier::Binary,
        )
        .unwrap();
    a.stream(1)
        .unwrap()
        .write_sctp(
            t1,
            &Bytes::from(vec![2; 1000]),
            PayloadProtocolIdentifier::Binary,
        )
        .unwrap();
    let flight = transmitted_data(&a.gather_outbound(t1).0);
    assert_eq!(2, flight.len());

    // The later chunk is acknowledged first (reordering) ...
    a.rack.reordering_seen = true;
    let at = t1 + Duration::from_millis(8);
    a.handle_sack(&sack(flight[0].tsn - 1, &[(2, 2)]), at)
        .unwrap();
    // ... but 8 ms after the earlier one was sent is exactly one round trip: not yet past
    // the reordering window, so it is a suspect and the reorder timer is armed.
    let suspect = a.inflight_queue.get(flight[0].tsn).unwrap();
    assert!(!suspect.retransmit, "late is not lost");
    let due = a
        .timers
        .get(Timer::Rack)
        .expect("a suspect arms the reorder timer");
    assert!(due > at);

    // If the missing chunk still hasn't turned up when the timer fires, it is lost.
    a.handle_timeout(due);
    assert!(a.inflight_queue.get(flight[0].tsn).unwrap().retransmit);
}

/// With RACK switched off no RACK timer is ever armed and nothing is declared lost early.
#[test]
fn rack_can_be_switched_off() {
    let mut a = create_association(TransportConfig::default().with_enable_rack(false));
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.rwnd = 1 << 20;
    a.cwnd = 1 << 20;
    let t0 = Instant::now();
    let sent = send_chunks(&mut a, 4, t0);
    a.handle_sack(
        &sack(sent[0].tsn - 1, &[(2, 4)]),
        t0 + Duration::from_millis(10),
    )
    .unwrap();
    assert!(a.timers.get(Timer::Pto).is_none());
    assert!(a.timers.get(Timer::Rack).is_none());
    assert_eq!(0, a.stats.get_num_rack_losses());
    assert!(!a.inflight_queue.get(sent[0].tsn).unwrap().retransmit);
}

#[test]
fn probe_timeout_without_a_round_trip_estimate_is_the_initial_rto() {
    let state = RackState::new(true);
    assert_eq!(Duration::from_secs(1), state.probe_timeout(3));
}

#[test]
fn probe_timeout_waits_for_a_delayed_ack_only_when_one_chunk_is_in_flight() {
    let mut state = RackState::new(true);
    let now = Instant::now();
    state.on_delivered(1, now, now + Duration::from_millis(10));
    assert_eq!(Duration::from_millis(2 * 10 + 200), state.probe_timeout(1));
    assert_eq!(Duration::from_millis(2 * 10 + 2), state.probe_timeout(5));
}

#[test]
fn delivery_out_of_send_order_is_recorded_as_reordering() {
    let mut state = RackState::new(true);
    let now = Instant::now();
    state.on_delivered(10, now, now + Duration::from_millis(5));
    assert!(!state.reordering_seen);
    state.on_delivered(8, now, now + Duration::from_millis(6));
    assert!(state.reordering_seen);
}

#[test]
fn tsns_order_across_the_32_bit_wrap() {
    let mut state = RackState::new(true);
    for tsn in [u32::MAX - 1, u32::MAX, 0, 1] {
        state.on_sent(tsn);
    }
    let order: Vec<u32> = state.outstanding.iter().map(|t| t.0).collect();
    assert_eq!(vec![u32::MAX - 1, u32::MAX, 0, 1], order);
}
