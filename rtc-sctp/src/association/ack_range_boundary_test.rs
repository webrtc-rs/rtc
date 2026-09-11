//! Boundary checks for advisory ACK range traversal, using per-TSN state as the oracle.

use super::*;
use crate::chunk::chunk_selective_ack::GapAckBlock;

const WINDOW: u32 = 1 << 20;

fn releases(a: &mut Association) -> (usize, usize) {
    let (mut bytes, mut low) = (0, 0);
    while let Some(event) = a.poll() {
        match event {
            Event::Stream(StreamEvent::BufferedAmountReleased { id: 1, n_bytes }) => {
                bytes += n_bytes
            }
            Event::Stream(StreamEvent::BufferedAmountLow { id: 1 }) => low += 1,
            _ => {}
        }
    }
    (bytes, low)
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

#[test]
fn maximum_gap_offset_matches_individual_receipts_through_wrap_and_reack() -> Result<()> {
    const COUNT: usize = u16::MAX as usize;
    let first = u32::MAX - 32767;
    let now = Instant::now();
    let mut a = timed_test_association();
    a.my_next_tsn = first;
    a.cumulative_tsn_ack_point = first.wrapping_sub(1);
    a.advanced_peer_tsn_ack_point = first.wrapping_sub(1);
    a.cwnd = WINDOW;
    a.rwnd = WINDOW;
    let ppi = PayloadProtocolIdentifier::Binary;
    let payload = Bytes::from_static(b"abc");
    let size = |index: usize| 1 + index % payload.len();
    {
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
        for index in 0..COUNT {
            stream.write_sctp(now, &payload.slice(..size(index)), ppi)?;
        }
    }
    // A single bounded flight makes offset 65535 a real assigned TSN. Wire
    // serialization is exercised, but no decoded copies are needed by the model.
    assert!(!a.gather_outbound(now).0.is_empty());
    assert!(a.pending_queue.is_empty());
    assert_eq!(a.inflight_queue.len(), COUNT);
    assert_eq!(a.my_next_tsn, first.wrapping_add(COUNT as u32));
    assert_eq!(releases(&mut a), (0, 0));

    // Each range names inclusive indices in the original flight. This oracle
    // tests membership for individual indices; it has no old/new range cursor,
    // serial-number ordering, or dependency on the production ACK cache.
    let phases: &[(usize, &[(usize, usize)])] = &[
        (0, &[(1, 16383), (32760, 65534)]),
        // Splitting contiguous evidence is entirely duplicate acknowledgment.
        (
            0,
            &[(1, 8191), (8192, 16383), (32760, 49151), (49152, 65534)],
        ),
        (0, &[(8192, 32768), (49152, 65534)]),
        (16384, &[(16385, 40000), (50000, 65534)]),
        // This cumulative ACK is u32::MAX; the remaining flight starts at zero.
        (32768, &[(32769, 45000), (50000, 65534)]),
        (32768, &[(32769, 38000), (38001, 40000), (45001, 65534)]),
        (32768, &[(32769, 65534)]),
        (COUNT, &[]),
    ];
    let mut credited = vec![false; COUNT];
    let mut total_released = 0;
    let total_size: usize = (0..COUNT).map(size).sum();
    for (phase, &(prefix, ranges)) in phases.iter().enumerate() {
        let before_buffered: usize = (0..COUNT).filter(|&index| !credited[index]).map(size).sum();
        let acknowledged: Vec<bool> = (0..COUNT)
            .map(|index| {
                index < prefix || ranges.iter().any(|&(lo, hi)| lo <= index && index <= hi)
            })
            .collect();
        let released: usize = (0..COUNT)
            .filter(|&index| acknowledged[index] && !credited[index])
            .map(size)
            .sum();
        for index in 0..COUNT {
            credited[index] |= acknowledged[index];
        }
        let buffered: usize = (0..COUNT).filter(|&index| !credited[index]).map(size).sum();
        let outstanding: usize = (prefix..COUNT)
            .filter(|&index| !acknowledged[index])
            .map(size)
            .sum();
        let gaps: Vec<_> = ranges
            .iter()
            .map(|&(lo, hi)| {
                assert!(prefix <= lo && lo <= hi && hi < COUNT);
                (
                    u16::try_from(lo + 1 - prefix).unwrap(),
                    u16::try_from(hi + 1 - prefix).unwrap(),
                )
            })
            .collect();
        if phase <= 2 {
            assert_eq!(gaps.last().unwrap().1, u16::MAX);
        }
        a.handle_sack(
            &sack(first.wrapping_add(prefix as u32).wrapping_sub(1), &gaps),
            now + Duration::from_millis(10 * (phase as u64 + 1)),
        )?;
        assert_eq!(
            releases(&mut a),
            (released, usize::from(before_buffered != 0 && buffered == 0)),
            "phase {phase}: application release"
        );
        total_released += released;
        assert_eq!(a.stream(1)?.buffered_amount()?, buffered, "phase {phase}");
        assert_eq!(a.inflight_queue.buffered_bytes(), buffered, "phase {phase}");
        assert_eq!(
            a.inflight_queue.outstanding_bytes(),
            outstanding,
            "phase {phase}"
        );
        assert_eq!(a.rwnd, WINDOW - outstanding as u32, "phase {phase}");
        assert_eq!(a.inflight_queue.len(), COUNT - prefix, "phase {phase}");
        assert_eq!(a.poll_timeout().is_none(), prefix == COUNT, "phase {phase}");
        for index in 0..COUNT {
            let chunk = a.inflight_queue.get(first.wrapping_add(index as u32));
            if index < prefix {
                assert!(chunk.is_none(), "phase {phase}: cumulative index {index}");
                continue;
            }
            let chunk = chunk.unwrap();
            assert_eq!(
                chunk.acknowledged, acknowledged[index],
                "phase {phase}, index {index}"
            );
            assert_eq!(
                (chunk.buffer_released, chunk.delivery_credited),
                (credited[index], credited[index]),
                "phase {phase}, index {index}: once-only credit"
            );
            assert_eq!(
                chunk.user_data.len(),
                if credited[index] { 0 } else { size(index) },
                "phase {phase}, index {index}: Rexmit(0) payload eviction"
            );
            assert!(
                !chunk.abandoned,
                "phase {phase}, index {index}: SACK alone is not a retry"
            );
            assert_eq!(chunk.nsent, 1, "phase {phase}, index {index}");
        }
    }
    assert_eq!(total_released, total_size);
    assert!(a.inflight_queue.is_empty());
    Ok(())
}

#[derive(Debug, PartialEq)]
struct SackState {
    cumulative: u32,
    advanced: u32,
    gaps: Vec<(u32, u32)>,
    // TSN, receipt, application credit, delivery credit, miss count, sends,
    // abandonment and retransmission status; original bytes are checked below.
    chunks: Vec<(u32, bool, bool, bool, u32, u32, bool, bool)>,
    outstanding: usize,
    retained: usize,
    buffered: usize,
    stream_buffered: usize,
    rwnd: u32,
    cwnd: u32,
    ssthresh: u32,
    partial_bytes_acked: u32,
    in_fast_recovery: bool,
    fast_recover_exit_point: u32,
    will_retransmit_fast: bool,
    deadline: Option<Instant>,
    rto: u64,
    srtt: u64,
    t3_errors: usize,
}

fn sack_state(a: &mut Association, now: Instant) -> Result<SackState> {
    let (expired, failed, t3_errors) = a.timers.is_expired(Timer::T3RTX, now);
    assert!(!expired && !failed, "snapshot must not expire T3");
    Ok(SackState {
        cumulative: a.cumulative_tsn_ack_point,
        advanced: a.advanced_peer_tsn_ack_point,
        gaps: a.peer_gap_ack_ranges.clone(),
        chunks: a
            .inflight_queue
            .tsns()
            .map(|tsn| {
                let c = a.inflight_queue.get(tsn).unwrap();
                assert_eq!(c.user_data, Bytes::from_static(b"retained"));
                (
                    tsn,
                    c.acknowledged,
                    c.buffer_released,
                    c.delivery_credited,
                    c.miss_indicator,
                    c.nsent,
                    c.abandoned,
                    c.retransmit,
                )
            })
            .collect(),
        outstanding: a.inflight_queue.outstanding_bytes(),
        retained: a.inflight_queue.get_num_bytes(),
        buffered: a.inflight_queue.buffered_bytes(),
        stream_buffered: a.stream(1)?.buffered_amount()?,
        rwnd: a.rwnd,
        cwnd: a.cwnd,
        ssthresh: a.ssthresh,
        partial_bytes_acked: a.partial_bytes_acked,
        in_fast_recovery: a.in_fast_recovery,
        fast_recover_exit_point: a.fast_recover_exit_point,
        will_retransmit_fast: a.will_retransmit_fast,
        deadline: a.poll_timeout(),
        rto: a.rto_mgr.get_rto(),
        srtt: a.rto_mgr.srtt,
        t3_errors,
    })
}

#[test]
fn invalid_and_stale_sacks_cannot_poison_cached_gap_evidence() -> Result<()> {
    const COUNT: usize = 24;
    const SIZE: usize = b"retained".len();
    for first in [12345, u32::MAX - 12] {
        let now = Instant::now();
        let mut a = timed_test_association();
        a.my_next_tsn = first;
        a.cumulative_tsn_ack_point = first.wrapping_sub(1);
        a.advanced_peer_tsn_ack_point = first.wrapping_sub(1);
        let ppi = PayloadProtocolIdentifier::Binary;
        let mut stream = a.open_stream(1, ppi)?;
        for _ in 0..COUNT {
            stream.write_sctp(now, &Bytes::from_static(b"retained"), ppi)?;
        }
        assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), COUNT);
        a.handle_sack(&sack(first.wrapping_sub(1), &[(3, 6), (10, 14)]), now)?;
        // Move the cumulative point before testing stale SACK rejection.
        let valid = sack(first, &[(2, 5), (9, 13)]);
        a.handle_sack(&valid, now + Duration::from_millis(10))?;
        assert_eq!(releases(&mut a), (10 * SIZE, 0));
        let timeout = a.poll_timeout().unwrap();
        a.handle_timeout(timeout);
        assert_eq!(transmitted_data(&a.gather_outbound(timeout).0).len(), 14);
        let before = sack_state(&mut a, timeout)?;
        assert_eq!(before.t3_errors, 1);

        let invalid = [
            sack(first, &[(0, 1)]),
            sack(first, &[(8, 7)]),
            sack(first, &[(2, 5), (5, 7)]),
            sack(first, &[(9, 12), (2, 5)]),
            // A valid new range preceding an unassigned TSN must not be applied.
            sack(first, &[(6, 7), (20, 24)]),
            sack(a.my_next_tsn, &[]),
            // Nor may an otherwise valid cumulative prefix be partially popped.
            sack(first.wrapping_add(3), &[(2, 3), (23, 24)]),
        ];
        for (case, mut invalid) in invalid.into_iter().enumerate() {
            invalid.advertised_receiver_window_credit = 7;
            let at = timeout + Duration::from_millis(case as u64 + 1);
            assert!(matches!(
                a.handle_sack(&invalid, at),
                Err(Error::ErrTsnRequestNotExist)
            ));
            assert_eq!(
                sack_state(&mut a, at)?,
                before,
                "first {first}, invalid case {case}"
            );
            assert_eq!(releases(&mut a), (0, 0));
        }
        let mut stale = sack(first.wrapping_sub(1), &[(1, COUNT as u16)]);
        stale.advertised_receiver_window_credit = 1;
        let at = timeout + Duration::from_millis(8);
        assert!(a.handle_sack(&stale, at)?.is_empty());
        assert_eq!(sack_state(&mut a, at)?, before, "first {first}: stale SACK");
        assert_eq!(releases(&mut a), (0, 0));

        // This valid omission must still revoke exactly four original TSNs.
        a.handle_sack(
            &sack(first, &[(9, 13)]),
            timeout + Duration::from_millis(10),
        )?;
        assert_eq!(a.inflight_queue.outstanding_bytes(), 18 * SIZE);
        assert_eq!(
            sack_state(&mut a, timeout + Duration::from_millis(10))?.t3_errors,
            1
        );
        assert_eq!(releases(&mut a), (0, 0));
        // Re-ACK is real peer progress, but both delivery/application credits
        // for these four TSNs were already consumed by the original SACK.
        a.handle_sack(&valid, timeout + Duration::from_millis(20))?;
        assert_eq!(a.inflight_queue.outstanding_bytes(), 14 * SIZE);
        assert_eq!(a.stream(1)?.buffered_amount()?, 14 * SIZE);
        assert_eq!(
            sack_state(&mut a, timeout + Duration::from_millis(20))?.t3_errors,
            0
        );
        assert_eq!(
            a.poll_timeout(),
            before.deadline,
            "the earliest TSN remains missing"
        );
        assert_eq!(releases(&mut a), (0, 0));
        a.handle_sack(
            &sack(first.wrapping_add(COUNT as u32 - 1), &[]),
            timeout + Duration::from_millis(30),
        )?;
        assert_eq!(releases(&mut a), (14 * SIZE, 1));
        assert!(a.inflight_queue.is_empty());
        assert!(a.poll_timeout().is_none());
    }
    Ok(())
}

#[test]
fn abandoned_gap_reappearance_is_duplicate_but_first_late_fragment_ack_is_progress() -> Result<()> {
    // Reading this tuple must not itself expire or reset T3. Keep credit and
    // congestion state separate from the error counter, which the late ACK is
    // expected to change even after all timed payload ownership is gone.
    let recovery = |a: &mut Association, at: Instant| {
        let (expired, failed, errors) = a.timers.is_expired(Timer::T3RTX, at);
        assert!(!expired && !failed);
        (
            (
                a.poll_timeout(),
                a.rto_mgr.get_rto(),
                a.rto_mgr.srtt,
                a.cwnd,
                a.partial_bytes_acked,
                a.in_fast_recovery,
            ),
            errors,
        )
    };
    for first in [12345, u32::MAX - 1] {
        let now = Instant::now();
        let mut a = timed_test_association();
        a.my_next_tsn = first;
        a.cumulative_tsn_ack_point = first.wrapping_sub(1);
        a.advanced_peer_tsn_ack_point = first.wrapping_sub(1);
        a.cwnd = WINDOW;
        a.rto_mgr.set_rto(1000, false);
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(2, ppi)?
            .write_sctp(now, &Bytes::from_static(b"x"), ppi)?;
        let hole = transmitted_data(&a.gather_outbound(now).0);
        assert_eq!(hole.len(), 1);
        assert_eq!(hole[0].tsn, first);

        let size = a.max_payload_size as usize + 17;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(true, ReliabilityType::Timed, 100)?;
        stream.write_sctp(now, &Bytes::from(vec![42; size]), ppi)?;
        let sent = transmitted_data(&a.gather_outbound(now).0);
        assert_eq!(sent.len(), 2);
        assert!(sent[0].beginning_fragment && !sent[0].ending_fragment);
        assert!(!sent[1].beginning_fragment && sent[1].ending_fragment);
        assert!(a.pending_queue.is_empty());
        let old_ack = sack(first.wrapping_sub(1), &[(2, 2)]);
        a.handle_sack(&old_ack, now + Duration::from_millis(50))?;
        assert_eq!(releases(&mut a), (sent[0].user_data.len(), 0));
        assert!(a.inflight_queue.get(sent[0].tsn).unwrap().acknowledged);
        assert!(!a.inflight_queue.get(sent[1].tsn).unwrap().acknowledged);

        let timeout = a.poll_timeout().unwrap();
        assert!(timeout >= now + Duration::from_millis(100));
        a.handle_timeout(timeout);
        let retried = transmitted_data(&a.gather_outbound(timeout).0);
        assert_eq!(retried.len(), 1, "only the reliable hole may be retried");
        assert_eq!((retried[0].tsn, retried[0].stream_identifier), (first, 2));
        assert_eq!(releases(&mut a), (sent[1].user_data.len(), 1));
        for (index, original) in sent.iter().enumerate() {
            let c = a.inflight_queue.get(original.tsn).unwrap();
            assert!(c.abandoned && c.buffer_released && c.user_data.is_empty());
            assert_eq!(c.nsent, 1, "both fragments were actually transmitted");
            assert_eq!(c.acknowledged, index == 0);
            assert_eq!(c.delivery_credited, index == 0);
        }
        assert_eq!(a.stream(1)?.buffered_amount()?, 0);
        assert_eq!(a.stream(2)?.buffered_amount()?, 1);
        assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
        let before = recovery(&mut a, timeout);
        assert_eq!(before.1, 1);
        let hole_misses = a.inflight_queue.get(first).unwrap().miss_indicator;

        // A3 abandonment is final. Omission removes the cached range without
        // unacknowledging the already received, now abandoned first fragment.
        a.handle_sack(
            &sack(first.wrapping_sub(1), &[]),
            timeout + Duration::from_millis(10),
        )?;
        assert!(a.peer_gap_ack_ranges.is_empty());
        assert!(a.inflight_queue.get(sent[0].tsn).unwrap().acknowledged);
        assert_eq!(
            recovery(&mut a, timeout + Duration::from_millis(10)),
            before
        );
        assert_eq!(releases(&mut a), (0, 0));

        // The first reappearance is outside the old range cache but remains a
        // duplicate according to the TSN's actual receipt state. Repeating it
        // once also exercises the ordinary cached-intersection skip.
        for delay in [20, 30] {
            let at = timeout + Duration::from_millis(delay);
            a.handle_sack(&old_ack, at)?;
            assert_eq!(
                recovery(&mut a, at),
                before,
                "first TSN {first}, delay {delay}"
            );
            assert_eq!(
                a.inflight_queue.get(first).unwrap().miss_indicator,
                hole_misses
            );
            assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
            assert_eq!(a.stream(1)?.buffered_amount()?, 0);
            assert_eq!(a.stream(2)?.buffered_amount()?, 1);
            assert_eq!(releases(&mut a), (0, 0));
            assert!(!a.inflight_queue.get(sent[1].tsn).unwrap().acknowledged);
            assert!(!a.inflight_queue.get(sent[1].tsn).unwrap().delivery_credited);
        }

        // In contrast, this is the first peer ACK for the other sent fragment.
        // It resets errors, but abandonment excludes RTT and delivery credit;
        // the reliable earliest TSN is still outstanding, so T3 stays scheduled.
        let late = timeout + Duration::from_millis(40);
        a.handle_sack(&sack(first.wrapping_sub(1), &[(2, 3)]), late)?;
        assert_eq!(recovery(&mut a, late), (before.0, 0));
        let c = a.inflight_queue.get(sent[1].tsn).unwrap();
        assert!(c.acknowledged && c.delivery_credited && c.abandoned && c.user_data.is_empty());
        assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
        assert_eq!(releases(&mut a), (0, 0));

        a.handle_sack(&sack(sent[1].tsn, &[]), late + Duration::from_millis(10))?;
        assert_eq!(releases(&mut a), (0, 0));
        assert_eq!(a.stream(2)?.buffered_amount()?, 0);
        assert!(a.inflight_queue.is_empty());
        assert!(a.poll_timeout().is_none());
    }
    Ok(())
}
