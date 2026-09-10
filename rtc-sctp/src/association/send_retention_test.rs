//! Sender payload ownership must remain independent of advisory ACK and recovery state.

use super::*;
use crate::chunk::chunk_selective_ack::GapAckBlock;
use std::sync::atomic::{AtomicUsize, Ordering};

const WINDOW: u32 = 65536;
const PAYLOAD_SIZE: usize = 64;

struct TrackedPayload {
    data: Vec<u8>,
    dropped: Arc<AtomicUsize>,
}

impl AsRef<[u8]> for TrackedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl Drop for TrackedPayload {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

fn sender(first_tsn: u32) -> Association {
    let mut a = timed_test_association();
    a.my_next_tsn = first_tsn;
    a.cumulative_tsn_ack_point = first_tsn.wrapping_sub(1);
    a.advanced_peer_tsn_ack_point = first_tsn.wrapping_sub(1);
    a.cwnd = WINDOW;
    a
}

fn write_reliable_hole(
    a: &mut Association,
    now: Instant,
    payload: &'static [u8],
) -> Result<ChunkPayloadData> {
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(2, ppi)?
        .write_sctp(now, &Bytes::from_static(payload), ppi)?;
    // Assign its TSN before an unordered message can take queue priority.
    let mut sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(sent.len(), 1);
    Ok(sent.remove(0))
}

fn write_tracked(
    a: &mut Association,
    now: Instant,
    sid: u16,
    ppi: PayloadProtocolIdentifier,
    size: usize,
) -> Result<Arc<AtomicUsize>> {
    let dropped = Arc::new(AtomicUsize::new(0));
    let payload = Bytes::from_owner(TrackedPayload {
        data: vec![0x5a; size],
        dropped: Arc::clone(&dropped),
    });
    a.stream(sid)?.write_chunk_with_ppi(now, &payload, ppi)?;
    Ok(dropped)
}

fn sack(cumulative_tsn_ack: u32, gaps: &[(u16, u16)]) -> ChunkSelectiveAck {
    ChunkSelectiveAck {
        cumulative_tsn_ack,
        advertised_receiver_window_credit: WINDOW,
        gap_ack_blocks: gaps
            .iter()
            .map(|&(start, end)| GapAckBlock { start, end })
            .collect(),
        ..Default::default()
    }
}

fn releases(a: &mut Association, sid: u16) -> (usize, usize) {
    let (mut bytes, mut low) = (0, 0);
    while let Some(event) = a.poll() {
        match event {
            Event::Stream(StreamEvent::BufferedAmountReleased { id, n_bytes }) if id == sid => {
                bytes += n_bytes;
            }
            Event::Stream(StreamEvent::BufferedAmountLow { id }) if id == sid => low += 1,
            _ => {}
        }
    }
    (bytes, low)
}

#[test]
fn gap_ack_frees_exhausted_rexmit_backing_without_abandoning() -> Result<()> {
    for first in [12345, u32::MAX] {
        for unordered in [false, true] {
            let mut a = sender(first);
            let now = Instant::now();
            let ppi = PayloadProtocolIdentifier::Binary;
            write_reliable_hole(&mut a, now, b"x")?;
            a.open_stream(1, ppi)?
                .set_reliability_params(unordered, ReliabilityType::Rexmit, 0)?;
            let dropped = write_tracked(&mut a, now, 1, ppi, 1024)?;
            // Decoding wire DATA creates separate backing, so it cannot keep the
            // application's tracked allocation alive.
            let sent = transmitted_data(&a.gather_outbound(now).0);
            assert_eq!(sent.len(), 1);
            let tsn = first.wrapping_add(1);
            let c = a.inflight_queue.get(tsn).unwrap();
            let identity = (
                c.message_id,
                c.stream_identifier,
                c.stream_generation,
                c.stream_sequence_number,
                c.since,
            );
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            let ack = sack(first.wrapping_sub(1), &[(2, 2)]);
            a.handle_sack(&ack, now + Duration::from_millis(10))?;

            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            let c = a.inflight_queue.get(tsn).unwrap();
            assert!(c.user_data.is_empty());
            assert!(c.acknowledged && c.buffer_released && c.delivery_credited);
            assert!(!c.abandoned && !c.retransmit);
            assert_eq!((c.nsent, c.miss_indicator), (1, 0));
            assert_eq!(c.unordered, unordered);
            assert!(c.beginning_fragment && c.ending_fragment);
            assert_eq!(
                (
                    c.message_id,
                    c.stream_identifier,
                    c.stream_generation,
                    c.stream_sequence_number,
                    c.since,
                ),
                identity
            );
            assert_eq!(a.inflight_queue.get_num_bytes(), 1);
            assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
            assert_eq!(a.inflight_queue.buffered_bytes(), 1);
            assert_eq!(a.stream(1)?.buffered_amount()?, 0);
            assert_eq!(releases(&mut a, 1), (1024, 1));
            assert_eq!(a.advanced_peer_tsn_ack_point, first.wrapping_sub(1));
            assert!(!a.will_send_forward_tsn);

            let deadline = a.poll_timeout();
            let cwnd = a.cwnd;
            for delay in [11, 12, 13] {
                a.handle_sack(&ack, now + Duration::from_millis(delay))?;
                assert_eq!(a.poll_timeout(), deadline);
                assert_eq!(a.cwnd, cwnd);
                assert_eq!(a.inflight_queue.get(first).unwrap().miss_indicator, 1);
                assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
                assert_eq!(a.inflight_queue.get_num_bytes(), 1);
                assert_eq!(releases(&mut a, 1), (0, 0));
                assert!(!a.inflight_queue.get(tsn).unwrap().abandoned);
            }
            assert!(
                transmitted_data(&a.gather_outbound(now + Duration::from_millis(14)).0).is_empty()
            );
            a.handle_sack(&sack(tsn, &[]), now + Duration::from_millis(20))?;
            assert!(a.inflight_queue.is_empty());
            assert_eq!(a.inflight_queue.get_num_bytes(), 0);
            assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
            assert_eq!(releases(&mut a, 1), (0, 0));
            assert!(a.poll_timeout().is_none());
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

#[test]
fn gap_ack_eviction_respects_captured_policy_and_pr_negotiation() -> Result<()> {
    let binary = PayloadProtocolIdentifier::Binary;
    for (policy, limit, ppi) in [
        (ReliabilityType::Reliable, 0, binary),
        (ReliabilityType::Rexmit, 0, binary),
        (ReliabilityType::Rexmit, 1, binary),
        (ReliabilityType::Timed, 10000, binary),
        (ReliabilityType::Timed, 0, binary),
        (ReliabilityType::Rexmit, 0, PayloadProtocolIdentifier::Dcep),
    ] {
        for negotiated in [false, true] {
            let first = 12345;
            let mut a = sender(first);
            a.use_forward_tsn = negotiated;
            let now = Instant::now();
            write_reliable_hole(&mut a, now, b"x")?;
            a.open_stream(1, ppi)?
                .set_reliability_params(true, policy, limit)?;
            let dropped = write_tracked(&mut a, now, 1, ppi, PAYLOAD_SIZE)?;
            assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 1);
            // A later stream setting must not alter already captured policy.
            a.stream(1)?
                .set_reliability_params(false, ReliabilityType::Reliable, 0)?;

            let evict = negotiated
                && ppi != PayloadProtocolIdentifier::Dcep
                && limit == 0
                && matches!(policy, ReliabilityType::Rexmit | ReliabilityType::Timed);
            a.handle_sack(&sack(first - 1, &[(2, 2)]), now + Duration::from_millis(10))?;
            let c = a.inflight_queue.get(first + 1).unwrap();
            assert_eq!(
                c.user_data.is_empty(),
                evict,
                "policy={policy:?}, limit={limit}, ppi={ppi:?}, negotiated={negotiated}"
            );
            assert_eq!(dropped.load(Ordering::SeqCst), usize::from(evict));
            assert!(c.acknowledged && !c.abandoned);
            assert_eq!(releases(&mut a, 1), (PAYLOAD_SIZE, 1));

            // Direct cumulative removal after revocation exercises pop's debt
            // accounting even when the queue no longer retains payload bytes.
            a.handle_sack(&sack(first - 1, &[]), now + Duration::from_millis(11))?;
            assert_eq!(a.inflight_queue.outstanding_bytes(), PAYLOAD_SIZE + 1);
            assert_eq!(a.rwnd, WINDOW - PAYLOAD_SIZE as u32 - 1);
            assert!(!a.inflight_queue.get(first + 1).unwrap().abandoned);
            a.handle_sack(&sack(first + 1, &[]), now + Duration::from_millis(12))?;
            assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
            assert_eq!(a.inflight_queue.get_num_bytes(), 0);
            assert_eq!(a.inflight_queue.buffered_bytes(), 0);
            assert_eq!(releases(&mut a, 1), (0, 0));
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}

#[test]
fn evicted_gap_ack_revoke_and_reack_restore_debt_without_repeating_credit() -> Result<()> {
    for first in [12345, u32::MAX - 1] {
        let mut a = sender(first);
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        write_reliable_hole(&mut a, now, b"x")?;
        a.open_stream(1, ppi)?
            .set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
        let dropped = write_tracked(&mut a, now, 1, ppi, PAYLOAD_SIZE)?;
        assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 1);
        a.stream(2)?
            .write_sctp(now, &Bytes::from(vec![7; PAYLOAD_SIZE]), ppi)?;
        assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 1);
        let tsn = first.wrapping_add(1);
        let ack = sack(first.wrapping_sub(1), &[(2, 2)]);
        a.handle_sack(&ack, now + Duration::from_millis(10))?;
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(releases(&mut a, 1), (PAYLOAD_SIZE, 1));
        assert_eq!(a.inflight_queue.get_num_bytes(), PAYLOAD_SIZE + 1);

        for delay in [11, 12] {
            a.handle_sack(
                &sack(first.wrapping_sub(1), &[]),
                now + Duration::from_millis(delay),
            )?;
            let c = a.inflight_queue.get(tsn).unwrap();
            assert!(c.user_data.is_empty() && !c.acknowledged && !c.abandoned);
            assert!(c.buffer_released && c.delivery_credited);
            assert_eq!(c.miss_indicator, 1, "duplicate revocation adds no report");
            assert_eq!(a.inflight_queue.outstanding_bytes(), 2 * PAYLOAD_SIZE + 1);
            assert_eq!(a.rwnd, WINDOW - (2 * PAYLOAD_SIZE + 1) as u32);
            assert_eq!(a.stream(1)?.buffered_amount()?, 0);
            assert_eq!(releases(&mut a, 1), (0, 0));
        }
        a.handle_sack(&ack, now + Duration::from_millis(13))?;
        assert_eq!(a.inflight_queue.outstanding_bytes(), PAYLOAD_SIZE + 1);
        assert_eq!(a.rwnd, WINDOW - (PAYLOAD_SIZE + 1) as u32);
        assert_eq!(releases(&mut a, 1), (0, 0));
        a.handle_sack(
            &sack(first.wrapping_sub(1), &[]),
            now + Duration::from_millis(14),
        )?;

        // Pending work makes slow-start credit visible. This SACK newly
        // acknowledges only the one-byte hole; re-ACKing the evicted DATA must
        // not add its 64 bytes a second time.
        a.stream(2)?
            .write_sctp(now, &Bytes::from_static(b"pending"), ppi)?;
        a.cwnd = 4096;
        a.ssthresh = WINDOW;
        a.handle_sack(&sack(first, &[(1, 1)]), now + Duration::from_millis(15))?;
        assert_eq!(a.cwnd, 4097);
        assert_eq!(a.inflight_queue.outstanding_bytes(), PAYLOAD_SIZE);
        assert_eq!(a.inflight_queue.get_num_bytes(), PAYLOAD_SIZE);
        assert_eq!(releases(&mut a, 1), (0, 0));
        a.handle_sack(
            &sack(first.wrapping_add(2), &[]),
            now + Duration::from_millis(16),
        )?;
        assert!(a.inflight_queue.is_empty());
        assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
        assert_eq!(a.inflight_queue.get_num_bytes(), 0);
        let last = transmitted_data(&a.gather_outbound(now + Duration::from_millis(16)).0);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].user_data.as_ref(), b"pending");
        a.handle_sack(&sack(last[0].tsn, &[]), now + Duration::from_millis(17))?;
        assert_eq!(a.stream(2)?.buffered_amount()?, 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(a.poll_timeout().is_none());
    }
    Ok(())
}

#[test]
fn retained_payload_retries_unchanged_and_exhausted_rexmit_one_can_then_evict() -> Result<()> {
    let binary = PayloadProtocolIdentifier::Binary;
    for (policy, limit, ppi, negotiated) in [
        (ReliabilityType::Reliable, 0, binary, true),
        (ReliabilityType::Rexmit, 1, binary, true),
        (ReliabilityType::Rexmit, 0, binary, false),
        (ReliabilityType::Timed, 10000, binary, true),
        (
            ReliabilityType::Rexmit,
            0,
            PayloadProtocolIdentifier::Dcep,
            true,
        ),
    ] {
        let first = 12345;
        let mut a = sender(first);
        a.use_forward_tsn = negotiated;
        let now = Instant::now();
        let mut sent = vec![write_reliable_hole(&mut a, now, b"x")?];
        a.open_stream(1, ppi)?
            .set_reliability_params(true, policy, limit)?;
        let dropped = write_tracked(&mut a, now, 1, ppi, PAYLOAD_SIZE)?;
        sent.extend(transmitted_data(&a.gather_outbound(now).0));
        assert_eq!(sent.len(), 2);
        let ack = sack(first - 1, &[(2, 2)]);
        a.handle_sack(&ack, now + Duration::from_millis(10))?;
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(releases(&mut a, 1), (PAYLOAD_SIZE, 1));
        a.handle_sack(&sack(first - 1, &[]), now + Duration::from_millis(11))?;
        let timeout = a.poll_timeout().unwrap();
        a.handle_timeout(timeout);
        let retry = transmitted_data(&a.gather_outbound(timeout).0);
        assert_eq!(retry.len(), 2);
        assert_eq!(
            retry
                .iter()
                .map(|c| (c.tsn, c.user_data.clone()))
                .collect::<Vec<_>>(),
            sent.iter()
                .map(|c| (c.tsn, c.user_data.clone()))
                .collect::<Vec<_>>(),
            "reneging must preserve the exact wire payload of allowed retries"
        );
        assert_eq!(a.inflight_queue.get(first + 1).unwrap().nsent, 2);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);

        let mut at = timeout + Duration::from_millis(10);
        a.handle_sack(&ack, at)?;
        let exhausted = policy == ReliabilityType::Rexmit && limit == 1;
        assert_eq!(dropped.load(Ordering::SeqCst), usize::from(exhausted));
        assert_eq!(releases(&mut a, 1), (0, 0));
        if exhausted {
            a.handle_sack(&sack(first - 1, &[]), at + Duration::from_millis(1))?;
            assert_eq!(a.inflight_queue.outstanding_bytes(), PAYLOAD_SIZE + 1);
            assert!(!a.inflight_queue.get(first + 1).unwrap().abandoned);
            at = a.poll_timeout().unwrap();
            a.handle_timeout(at);
            let later = transmitted_data(&a.gather_outbound(at).0);
            assert_eq!(later.len(), 1);
            assert_eq!(later[0].tsn, first);
            assert_eq!(later[0].user_data.as_ref(), b"x");
            assert!(a.inflight_queue.get(first + 1).unwrap().abandoned);
            assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
            assert_eq!(releases(&mut a, 1), (0, 0));
        }
        a.handle_sack(&sack(first + 1, &[]), at + Duration::from_millis(20))?;
        assert_eq!(a.inflight_queue.get_num_bytes(), 0);
        assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
        assert_eq!(a.stream(1)?.buffered_amount()?, 0);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn evicted_rexmit_zero_waits_for_fast_or_t3_candidate_after_revocation() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        for fast in [false, true] {
            let mut a = sender(first);
            let now = Instant::now();
            let ppi = PayloadProtocolIdentifier::Binary;
            write_reliable_hole(&mut a, now, b"received")?;
            a.open_stream(1, ppi)?
                .set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
            let dropped = write_tracked(&mut a, now, 1, ppi, PAYLOAD_SIZE)?;
            assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 1);
            for _ in 0..3 {
                a.stream(2)?
                    .write_sctp(now, &Bytes::from_static(b"reliable"), ppi)?;
            }
            assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 3);
            let tsn = first.wrapping_add(1);
            a.handle_sack(
                &sack(first.wrapping_sub(1), &[(2, 2)]),
                now + Duration::from_millis(10),
            )?;
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(releases(&mut a, 1), (PAYLOAD_SIZE, 1));
            for delay in [11, 12, 13] {
                a.handle_sack(&sack(first, &[]), now + Duration::from_millis(delay))?;
                let c = a.inflight_queue.get(tsn).unwrap();
                assert!(c.user_data.is_empty() && !c.acknowledged && !c.abandoned);
                assert_eq!(c.miss_indicator, 1);
                assert_eq!(a.inflight_queue.outstanding_bytes(), PAYLOAD_SIZE + 24);
                assert_eq!(a.advanced_peer_tsn_ack_point, first);
                assert!(!a.will_send_forward_tsn);
                assert_eq!(releases(&mut a, 1), (0, 0));
            }

            let at = if fast {
                a.handle_sack(&sack(first, &[(2, 2)]), now + Duration::from_millis(14))?;
                assert_eq!(a.inflight_queue.get(tsn).unwrap().miss_indicator, 2);
                assert!(!a.inflight_queue.get(tsn).unwrap().abandoned);
                assert!(
                    transmitted_data(&a.gather_outbound(now + Duration::from_millis(14)).0)
                        .is_empty()
                );
                let at = now + Duration::from_millis(15);
                let cwnd = a.cwnd;
                a.handle_sack(&sack(first, &[(2, 3)]), at)?;
                assert_eq!(a.inflight_queue.get(tsn).unwrap().miss_indicator, 3);
                assert!(!a.inflight_queue.get(tsn).unwrap().abandoned);
                assert!(a.in_fast_recovery && a.will_retransmit_fast);
                assert_eq!(a.cwnd, (cwnd / 2).max(4 * a.mtu));
                at
            } else {
                let at = a.poll_timeout().unwrap();
                a.handle_timeout(at);
                assert_eq!(a.cwnd, a.mtu);
                at
            };
            let data = transmitted_data(&a.gather_outbound(at).0);
            assert_eq!(data.len(), if fast { 0 } else { 3 });
            assert!(data.iter().all(|c| c.user_data.as_ref() == b"reliable"));
            let c = a.inflight_queue.get(tsn).unwrap();
            assert!(c.abandoned && !c.acknowledged && c.user_data.is_empty());
            assert!(!c.retransmit);
            assert_eq!(
                c.nsent, 1,
                "the evicted fragment must never be serialized again"
            );
            assert_eq!(
                a.inflight_queue.outstanding_bytes(),
                if fast { 8 } else { 24 }
            );
            assert_eq!(a.stream(1)?.buffered_amount()?, 0);
            assert_eq!(releases(&mut a, 1), (0, 0));
            a.handle_sack(
                &sack(first.wrapping_add(4), &[]),
                at + Duration::from_millis(10),
            )?;
            assert!(a.inflight_queue.is_empty());
            assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
            assert_eq!(a.inflight_queue.get_num_bytes(), 0);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert!(a.poll_timeout().is_none());
        }
    }
    Ok(())
}

#[test]
fn evicted_fragment_ack_preserves_pending_tail_until_whole_message_abandonment() -> Result<()> {
    for unordered in [false, true] {
        let first = u32::MAX - 2;
        let mut a = sender(first);
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        let fragment_size = a.max_payload_size as usize;
        let size = 4 * fragment_size + 37;
        a.cwnd = (2 * fragment_size + 1) as u32;
        write_reliable_hole(&mut a, now, b"x")?;
        a.open_stream(1, ppi)?
            .set_reliability_params(unordered, ReliabilityType::Rexmit, 0)?;
        let dropped = write_tracked(&mut a, now, 1, ppi, size)?;
        let sent = transmitted_data(&a.gather_outbound(now).0);
        assert_eq!(sent.len(), 2);
        let one = first.wrapping_add(1);
        let two = first.wrapping_add(2);
        let next = a.my_next_tsn;
        let id = a.inflight_queue.get(one).unwrap().message_id.unwrap();
        let pending_bytes = size - 2 * fragment_size;
        assert_eq!(a.pending_queue.get_num_bytes(), pending_bytes);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);

        let mut ack = sack(first.wrapping_sub(1), &[(2, 2)]);
        // Keep the remaining first transmissions pending while ACKs are handled.
        ack.advertised_receiver_window_credit = 0;
        a.handle_sack(&ack, now + Duration::from_millis(10))?;
        assert!(a.inflight_queue.get(one).unwrap().user_data.is_empty());
        assert_eq!(
            a.inflight_queue.get(two).unwrap().user_data.len(),
            fragment_size
        );
        assert_eq!(releases(&mut a, 1), (fragment_size, 0));
        ack.gap_ack_blocks = vec![GapAckBlock { start: 2, end: 3 }];
        a.handle_sack(&ack, now + Duration::from_millis(11))?;
        assert_eq!(releases(&mut a, 1), (fragment_size, 0));
        for tsn in [one, two] {
            let c = a.inflight_queue.get(tsn).unwrap();
            assert!(c.acknowledged && !c.abandoned && c.user_data.is_empty());
            assert_eq!(c.message_id, Some(id));
        }
        assert_eq!(a.inflight_queue.get_num_bytes(), 1);
        assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
        assert_eq!(a.pending_queue.get_num_bytes(), pending_bytes);
        assert_eq!(a.stream(1)?.buffered_amount()?, pending_bytes);
        assert_eq!(
            a.my_next_tsn, next,
            "eviction must not reserve a terminal TSN"
        );
        assert_eq!(a.advanced_peer_tsn_ack_point, first.wrapping_sub(1));
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            0,
            "the unsent tail still owns the backing"
        );
        assert!(transmitted_data(&a.gather_outbound(now + Duration::from_millis(12)).0).is_empty());

        // Revoke one evicted fragment while its sibling remains Gap-ACKed.
        // Only the next recovery event may abandon them and their unsent tail.
        ack.gap_ack_blocks = vec![GapAckBlock { start: 3, end: 3 }];
        a.handle_sack(&ack, now + Duration::from_millis(13))?;
        assert_eq!(a.inflight_queue.outstanding_bytes(), fragment_size + 1);
        assert_eq!(a.inflight_queue.get(one).unwrap().miss_indicator, 1);
        assert!(!a.inflight_queue.get(one).unwrap().abandoned);
        assert_eq!(a.pending_queue.get_num_bytes(), pending_bytes);
        assert_eq!(releases(&mut a, 1), (0, 0));
        let timeout = a.poll_timeout().unwrap();
        a.handle_timeout(timeout);
        let retry = transmitted_data(&a.gather_outbound(timeout).0);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].tsn, first);
        assert_eq!(retry[0].user_data.as_ref(), b"x");
        assert!(a.pending_queue.is_empty());
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(a.stream(1)?.buffered_amount()?, 0);
        assert_eq!(releases(&mut a, 1), (pending_bytes, 1));
        assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
        assert_eq!(a.inflight_queue.get_num_bytes(), 1);
        let terminal = next;
        for tsn in [one, two, terminal] {
            let c = a.inflight_queue.get(tsn).unwrap();
            assert_eq!(c.message_id, Some(id));
            assert!(c.abandoned && c.buffer_released && c.user_data.is_empty());
        }
        assert!(a.inflight_queue.get(terminal).unwrap().ending_fragment);
        assert_eq!(a.inflight_queue.get(terminal).unwrap().nsent, 0);

        a.handle_sack(&sack(first, &[]), timeout + Duration::from_millis(10))?;
        let forward = a.create_forward_tsn();
        assert_eq!(forward.new_cumulative_tsn, terminal);
        assert_eq!(forward.streams.len(), usize::from(!unordered));
        if !unordered {
            assert_eq!(forward.streams[0].identifier, 1);
            assert_eq!(forward.streams[0].sequence, sent[0].stream_sequence_number);
        }
        a.handle_sack(&sack(terminal, &[]), timeout + Duration::from_millis(20))?;
        assert!(a.inflight_queue.is_empty());
        assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
        assert_eq!(a.inflight_queue.get_num_bytes(), 0);
        assert_eq!(releases(&mut a, 1), (0, 0));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(a.poll_timeout().is_none());
    }
    Ok(())
}
