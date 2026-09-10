use super::*;
use crate::chunk::chunk_selective_ack::GapAckBlock;
use std::sync::atomic::{AtomicUsize, Ordering};

fn release_events(a: &mut Association, sid: u16) -> (usize, usize) {
    let (mut released, mut low) = (0, 0);
    while let Some(event) = a.poll() {
        match event {
            Event::Stream(StreamEvent::BufferedAmountReleased { id, n_bytes }) if id == sid => {
                released += n_bytes;
            }
            Event::Stream(StreamEvent::BufferedAmountLow { id }) if id == sid => low += 1,
            _ => {}
        }
    }
    (released, low)
}

fn t3_errors(a: &mut Association, before_expiry: Instant) -> usize {
    let (expired, failed, errors) = a.timers.is_expired(Timer::T3RTX, before_expiry);
    assert!(
        !expired && !failed,
        "reading the counter must not expire T3"
    );
    errors
}

#[test]
fn duplicate_gap_ack_preserves_t3_and_does_not_repeat_credit() -> Result<()> {
    let mut a = timed_test_association();
    a.rto_mgr.set_rto(1000, false);
    let now = Instant::now();
    let first = a.my_next_tsn;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"lost"), ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"received"), ppi)?;
    assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 2);
    let sack = ChunkSelectiveAck {
        cumulative_tsn_ack: first.wrapping_sub(1),
        advertised_receiver_window_credit: 65536,
        gap_ack_blocks: vec![GapAckBlock { start: 2, end: 2 }],
        ..Default::default()
    };
    a.handle_sack(&sack, now + Duration::from_millis(50))?;
    assert_eq!(release_events(&mut a, 1), (8, 0));

    let timeout = a.poll_timeout().unwrap();
    a.handle_timeout(timeout);
    let retried = transmitted_data(&a.gather_outbound(timeout).0);
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].tsn, first);
    assert_eq!(retried[0].user_data, Bytes::from_static(b"lost"));
    assert_eq!(t3_errors(&mut a, timeout), 1);
    let deadline = a.poll_timeout();
    let rto = a.rto_mgr.get_rto();
    let cwnd = a.cwnd;
    let srtt = a.rto_mgr.srtt;

    // RFC 9260 6.3.2 R3 and 8.1-8.2: repeated evidence for the second TSN
    // is neither acknowledgment of the earliest outstanding DATA nor progress.
    for delay in [10, 20, 30] {
        let at = timeout + Duration::from_millis(delay);
        a.handle_sack(&sack, at)?;
        assert_eq!(t3_errors(&mut a, at), 1);
        assert_eq!(a.poll_timeout(), deadline);
        assert_eq!(a.rto_mgr.get_rto(), rto);
        assert_eq!(a.rto_mgr.srtt, srtt);
        assert_eq!(a.cwnd, cwnd);
        assert_eq!(a.inflight_queue.outstanding_bytes(), 4);
        assert_eq!(a.stream(1)?.buffered_amount()?, 4);
        assert_eq!(release_events(&mut a, 1), (0, 0));
        assert!(transmitted_data(&a.gather_outbound(at).0).is_empty());
    }
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: first.wrapping_add(1),
            advertised_receiver_window_credit: 65536,
            ..Default::default()
        },
        timeout + Duration::from_millis(40),
    )?;
    assert_eq!(release_events(&mut a, 1), (4, 1));
    assert!(a.inflight_queue.is_empty());
    assert!(a.poll_timeout().is_none());
    Ok(())
}

#[test]
fn reack_after_gap_revocation_resets_t3_without_second_delivery_credit() -> Result<()> {
    let mut a = timed_test_association();
    a.rto_mgr.set_rto(1000, false);
    let now = Instant::now();
    let first = a.my_next_tsn;
    let ppi = PayloadProtocolIdentifier::Binary;
    let payload = Bytes::from(vec![42; 64]);
    let mut stream = a.open_stream(1, ppi)?;
    for _ in 0..3 {
        stream.write_sctp(now, &payload, ppi)?;
    }
    assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 3);
    let mut sack = ChunkSelectiveAck {
        cumulative_tsn_ack: first.wrapping_sub(1),
        advertised_receiver_window_credit: 65536,
        gap_ack_blocks: vec![GapAckBlock { start: 2, end: 2 }],
        ..Default::default()
    };
    a.handle_sack(&sack, now + Duration::from_millis(50))?;
    assert_eq!(release_events(&mut a, 1), (64, 0));
    sack.gap_ack_blocks.clear();
    a.handle_sack(&sack, now + Duration::from_millis(60))?;
    assert_eq!(a.inflight_queue.outstanding_bytes(), 192);

    // RFC 9260 6.2.1 D(iii): advisory ACK revocation restores recovery, while
    // the original application credit remains released.
    let timeout = a.poll_timeout().unwrap();
    a.handle_timeout(timeout);
    let retried = transmitted_data(&a.gather_outbound(timeout).0);
    assert_eq!(retried.len(), 3);
    assert!(retried.iter().all(|c| c.user_data == payload));
    assert_eq!(t3_errors(&mut a, timeout), 1);
    let deadline = a.poll_timeout();
    let rto = a.rto_mgr.get_rto();
    sack.gap_ack_blocks.push(GapAckBlock { start: 2, end: 2 });
    let reack = timeout + Duration::from_millis(10);
    a.handle_sack(&sack, reack)?;
    assert_eq!(t3_errors(&mut a, reack), 0);
    assert_eq!(
        a.poll_timeout(),
        deadline,
        "the earliest TSN is still missing"
    );
    assert_eq!(a.rto_mgr.get_rto(), rto, "Karn excludes retransmitted DATA");
    assert_eq!(release_events(&mut a, 1), (0, 0));
    assert_eq!(a.inflight_queue.outstanding_bytes(), 128);
    assert_eq!(a.stream(1)?.buffered_amount()?, 128);

    sack.gap_ack_blocks.clear();
    a.handle_sack(&sack, reack + Duration::from_millis(1))?;
    // Keep application DATA pending so congestion-window growth is observable.
    // The next SACK newly delivers only TSN 1; TSN 2's credit was already spent.
    a.stream(1)?.write_sctp(reack, &payload, ppi)?;
    let cwnd = a.cwnd;
    assert!(cwnd <= a.ssthresh);
    sack.cumulative_tsn_ack = first;
    sack.gap_ack_blocks.push(GapAckBlock { start: 1, end: 1 });
    let progressed = reack + Duration::from_millis(2);
    a.handle_sack(&sack, progressed)?;
    assert_eq!(a.cwnd, cwnd + 64, "reneged DATA must not grow cwnd twice");
    assert_eq!(release_events(&mut a, 1), (64, 0));
    assert_eq!(a.stream(1)?.buffered_amount()?, 128);
    assert_eq!(
        a.poll_timeout(),
        Some(progressed + Duration::from_millis(rto)),
        "acknowledgment of the earliest outstanding TSN restarts T3"
    );
    a.handle_sack(&sack, progressed + Duration::from_millis(1))?;
    assert_eq!(a.cwnd, cwnd + 64);
    assert_eq!(release_events(&mut a, 1), (0, 0));

    sack.cumulative_tsn_ack = first.wrapping_add(2);
    sack.gap_ack_blocks.clear();
    a.handle_sack(&sack, progressed + Duration::from_millis(2))?;
    assert_eq!(release_events(&mut a, 1), (64, 0));
    let final_data = transmitted_data(&a.gather_outbound(progressed + Duration::from_millis(2)).0);
    assert_eq!(final_data.len(), 1);
    assert_eq!(final_data[0].user_data, payload);
    sack.cumulative_tsn_ack = final_data[0].tsn;
    a.handle_sack(&sack, progressed + Duration::from_millis(3))?;
    assert_eq!(release_events(&mut a, 1), (64, 1));
    assert_eq!(a.stream(1)?.buffered_amount()?, 0);
    assert!(a.inflight_queue.is_empty());
    assert!(a.poll_timeout().is_none());
    Ok(())
}

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

#[test]
fn final_abandonment_drops_payload_owner_before_cumulative_ack() -> Result<()> {
    for unordered in [false, true] {
        for size in [64, 4000] {
            let mut a = timed_test_association();
            let now = Instant::now();
            let first = a.my_next_tsn;
            let ppi = PayloadProtocolIdentifier::Binary;
            a.cwnd = 2 * a.max_payload_size + 1;
            a.open_stream(2, ppi)?
                .write_sctp(now, &Bytes::from_static(b"x"), ppi)?;
            a.gather_outbound(now); // Keep a reliable hole before the timed DATA.
            let dropped = Arc::new(AtomicUsize::new(0));
            {
                let payload = Bytes::from_owner(TrackedPayload {
                    data: vec![42; size],
                    dropped: Arc::clone(&dropped),
                });
                let mut stream = a.open_stream(1, ppi)?;
                stream.set_reliability_params(unordered, ReliabilityType::Timed, 100)?;
                stream.write_chunk_with_ppi(now, &payload, ppi)?;
            }
            // Decoded wire DATA owns a serialized copy, never the tracked owner.
            let sent = transmitted_data(&a.gather_outbound(now).0);
            assert_eq!(sent.len(), if size == 64 { 1 } else { 2 });
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
            let mut sack = ChunkSelectiveAck {
                cumulative_tsn_ack: first.wrapping_sub(1),
                advertised_receiver_window_credit: 65536,
                ..Default::default()
            };
            let mut released = 0;
            if size == 4000 {
                assert!(!a.pending_queue.is_empty());
                sack.gap_ack_blocks.push(GapAckBlock { start: 2, end: 2 });
                a.handle_sack(&sack, now + Duration::from_millis(50))?;
                let events = release_events(&mut a, 1);
                released += events.0;
                assert_eq!(events, (sent[0].user_data.len(), 0));
                assert_eq!(dropped.load(Ordering::SeqCst), 0);
            }

            let timeout = a.poll_timeout().unwrap();
            a.handle_timeout(timeout);
            let retried = transmitted_data(&a.gather_outbound(timeout).0);
            assert_eq!(retried.len(), 1);
            assert_eq!(retried[0].stream_identifier, 2);
            assert_eq!(
                dropped.load(Ordering::SeqCst),
                1,
                "final abandonment must drop backing, including gap-ACKed and pending slices"
            );
            assert!(a.pending_queue.is_empty());
            assert!(a.inflight_queue.len() > 1, "TSNs still await peer progress");
            assert_eq!(a.stream(1)?.buffered_amount()?, 0);
            assert_eq!(release_events(&mut a, 1), (size - released, 1));
            assert_eq!(t3_errors(&mut a, timeout), 1);

            // The newly acknowledged fragment was actually sent before expiry.
            // It clears T3's error count even though its payload is already gone.
            sack.gap_ack_blocks = vec![GapAckBlock {
                start: 2,
                end: sent.len() as u16 + 1,
            }];
            let late = timeout + Duration::from_millis(10);
            a.handle_sack(&sack, late)?;
            assert_eq!(t3_errors(&mut a, late), 0);
            assert_eq!(release_events(&mut a, 1), (0, 0));
            sack.gap_ack_blocks.clear();
            a.handle_sack(&sack, late + Duration::from_millis(1))?;
            assert_eq!(a.inflight_queue.outstanding_bytes(), 1);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(release_events(&mut a, 1), (0, 0));

            sack.cumulative_tsn_ack = first;
            a.handle_sack(&sack, late + Duration::from_millis(2))?;
            let forwarded = a.create_forward_tsn().new_cumulative_tsn;
            assert_eq!(forwarded, a.my_next_tsn.wrapping_sub(1));
            assert!(
                transmitted_data(&a.gather_outbound(late + Duration::from_millis(2)).0).is_empty()
            );
            assert!(!a.inflight_queue.is_empty());
            sack.cumulative_tsn_ack = forwarded;
            a.handle_sack(&sack, late + Duration::from_millis(3))?;
            assert_eq!(release_events(&mut a, 1), (0, 0));
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert!(a.inflight_queue.is_empty());
            assert!(a.poll_timeout().is_none());
        }
    }
    Ok(())
}

#[test]
fn gap_range_overlap_matches_small_set_reference_across_cumulative_advance_and_wrap() -> Result<()>
{
    const COUNT: usize = 5;

    fn blocks(mask: u8, advanced: usize, split: bool) -> Vec<GapAckBlock> {
        let mut gaps: Vec<GapAckBlock> = Vec::new();
        for index in 0..COUNT {
            if mask & (1 << index) == 0 {
                continue;
            }
            let offset = (index - advanced + 1) as u16;
            if !split
                && let Some(last) = gaps.last_mut()
                && last.end + 1 == offset
            {
                last.end = offset;
            } else {
                gaps.push(GapAckBlock {
                    start: offset,
                    end: offset,
                });
            }
        }
        gaps
    }

    let all = (1u8 << COUNT) - 1;
    let ppi = PayloadProtocolIdentifier::Binary;
    for first in [12345, u32::MAX - 2] {
        for old in 0..=all {
            if old & 1 != 0 {
                continue; // Leave the first TSN missing before the initial gaps.
            }
            for advanced in 0..=COUNT {
                // A valid peer still has a hole immediately after its cumulative
                // ACK. Subsequent TSNs may appear in any combination of gaps.
                let allowed = all & !((1u8 << (advanced + 1)) - 1);
                for new in 0..=all {
                    if new & !allowed != 0 {
                        continue;
                    }
                    for (old_split, new_split) in
                        [(false, false), (false, true), (true, false), (true, true)]
                    {
                        let mut a = timed_test_association();
                        let now = Instant::now();
                        a.my_next_tsn = first;
                        a.cumulative_tsn_ack_point = first.wrapping_sub(1);
                        a.advanced_peer_tsn_ack_point = first.wrapping_sub(1);
                        let mut stream = a.open_stream(1, ppi)?;
                        for index in 0..COUNT {
                            stream.write_sctp(
                                now,
                                &Bytes::from(vec![index as u8; index + 1]),
                                ppi,
                            )?;
                        }
                        assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), COUNT);

                        // The model tracks individual relative TSNs, independently
                        // of the production range cursor and serial comparisons.
                        // Return to the old set after the second SACK so removed
                        // gaps must be re-ACKed using the replaced range cache.
                        let mut credited = 0u8;
                        let mut total_released = 0;
                        for (phase, (prefix, mask, split)) in [
                            (0, old, old_split),
                            (advanced, new, new_split),
                            (advanced, old & allowed, !old_split),
                            (COUNT, 0, false),
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            let context = format!(
                                "first={first} old={old:05b} new={new:05b} advanced={advanced} \
                                 old_split={old_split} new_split={new_split} phase={phase}"
                            );
                            let before = credited;
                            credited |= mask | ((1u8 << prefix) - 1);
                            let released: usize = (0..COUNT)
                                .filter(|&index| (credited & !before) & (1 << index) != 0)
                                .map(|index| index + 1)
                                .sum();
                            let buffered: usize = (0..COUNT)
                                .filter(|&index| credited & (1 << index) == 0)
                                .map(|index| index + 1)
                                .sum();
                            let outstanding: usize = (prefix..COUNT)
                                .filter(|&index| mask & (1 << index) == 0)
                                .map(|index| index + 1)
                                .sum();
                            a.handle_sack(
                                &ChunkSelectiveAck {
                                    cumulative_tsn_ack: first
                                        .wrapping_add(prefix as u32)
                                        .wrapping_sub(1),
                                    advertised_receiver_window_credit: 65536,
                                    gap_ack_blocks: blocks(mask, prefix, split),
                                    ..Default::default()
                                },
                                now + Duration::from_millis(10 * (phase as u64 + 1)),
                            )?;
                            assert_eq!(
                                release_events(&mut a, 1),
                                (released, usize::from(before != all && credited == all)),
                                "{context}"
                            );
                            total_released += released;
                            assert_eq!(a.stream(1)?.buffered_amount()?, buffered, "{context}");
                            assert_eq!(a.inflight_queue.buffered_bytes(), buffered, "{context}");
                            assert_eq!(
                                a.inflight_queue.outstanding_bytes(),
                                outstanding,
                                "{context}"
                            );
                            assert_eq!(a.poll_timeout().is_none(), prefix == COUNT, "{context}");
                            for index in 0..COUNT {
                                let chunk = a.inflight_queue.get(first.wrapping_add(index as u32));
                                if index < prefix {
                                    assert!(chunk.is_none(), "{context}: cumulative TSN {index}");
                                    continue;
                                }
                                let chunk = chunk.unwrap();
                                assert_eq!(
                                    chunk.acknowledged,
                                    mask & (1 << index) != 0,
                                    "{context}: receipt of TSN {index}"
                                );
                                assert_eq!(
                                    (chunk.buffer_released, chunk.delivery_credited),
                                    (credited & (1 << index) != 0, credited & (1 << index) != 0),
                                    "{context}: credit of TSN {index}"
                                );
                                assert_eq!(chunk.user_data.len(), index + 1, "{context}");
                            }
                        }
                        assert_eq!(total_released, COUNT * (COUNT + 1) / 2);
                        assert!(a.inflight_queue.is_empty());
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn closed_association_does_not_reuse_gap_ack_cache_after_cookie_echo() -> Result<()> {
    let mut a = timed_test_association();
    let cookie = ParamStateCookie::new();
    let echo = ChunkCookieEcho {
        cookie: cookie.cookie.clone(),
    };
    a.my_cookie = Some(cookie);
    let now = Instant::now();
    let first = a.my_next_tsn;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    for _ in 0..2 {
        stream.write_sctp(now, &Bytes::from_static(b"payload"), ppi)?;
    }
    assert_eq!(transmitted_data(&a.gather_outbound(now).0).len(), 2);
    let sack = ChunkSelectiveAck {
        cumulative_tsn_ack: first.wrapping_sub(1),
        advertised_receiver_window_credit: 65536,
        gap_ack_blocks: vec![GapAckBlock { start: 2, end: 2 }],
        ..Default::default()
    };
    a.handle_sack(&sack, now)?;
    assert!(!a.peer_gap_ack_ranges.is_empty());
    a.close(AssociationError::TransportError)?;
    assert_eq!(a.state(), AssociationState::Closed);
    assert!(a.inflight_queue.is_empty());

    // The existing handshake accepts a matching COOKIE ECHO in Closed. A
    // cached gap must not bypass validation of DATA removed during close().
    assert_eq!(a.handle_cookie_echo(&echo)?.len(), 1);
    assert_eq!(a.state(), AssociationState::Established);
    assert!(matches!(
        a.handle_sack(&sack, now + Duration::from_millis(1)),
        Err(Error::ErrTsnRequestNotExist)
    ));
    Ok(())
}
