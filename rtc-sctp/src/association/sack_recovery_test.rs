use super::*;
use crate::chunk::chunk_selective_ack::GapAckBlock;

fn recovery_sender(
    first_tsn: u32,
    count: usize,
) -> Result<(Association, Instant, Vec<ChunkPayloadData>)> {
    let now = Instant::now();
    let mut a = timed_test_association();
    a.my_next_tsn = first_tsn;
    a.cumulative_tsn_ack_point = first_tsn.wrapping_sub(1);
    a.advanced_peer_tsn_ack_point = first_tsn.wrapping_sub(1);
    a.cwnd = 65536;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    for index in 0..count {
        stream.write_sctp(now, &Bytes::from(vec![index as u8; 8]), ppi)?;
    }
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(sent.len(), count);
    Ok((a, now, sent))
}

fn report(
    a: &mut Association,
    now: Instant,
    cumulative_tsn_ack: u32,
    gaps: &[(u16, u16)],
) -> Result<Vec<ChunkPayloadData>> {
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack,
            advertised_receiver_window_credit: 65536,
            gap_ack_blocks: gaps
                .iter()
                .map(|&(start, end)| GapAckBlock { start, end })
                .collect(),
            ..Default::default()
        },
        now,
    )?;
    Ok(transmitted_data(&a.gather_outbound(now).0))
}

fn assert_retries(actual: &[ChunkPayloadData], original: &[ChunkPayloadData], indices: &[usize]) {
    assert_eq!(
        actual
            .iter()
            .map(|c| (c.tsn, c.user_data.clone()))
            .collect::<Vec<_>>(),
        indices
            .iter()
            .map(|&index| (original[index].tsn, original[index].user_data.clone()))
            .collect::<Vec<_>>(),
        "recovery must retransmit only the missing DATA, with its retained bytes"
    );
}

fn finish(a: &mut Association, now: Instant, sent: &[ChunkPayloadData]) -> Result<()> {
    assert!(report(a, now, sent.last().unwrap().tsn, &[])?.is_empty());
    assert!(a.inflight_queue.is_empty());
    assert_eq!(a.stream(1)?.buffered_amount()?, 0);
    assert!(a.poll_timeout().is_none());
    Ok(())
}

#[test]
fn repeated_gap_ack_does_not_count_as_new_missing_evidence() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        let (mut a, now, sent) = recovery_sender(first, 8)?;
        let cumulative = first.wrapping_sub(1);
        assert!(report(&mut a, now, cumulative, &[(2, 2)])?.is_empty());
        for _ in 0..4 {
            assert!(report(&mut a, now, cumulative, &[(2, 2)])?.is_empty());
        }
        assert!(report(&mut a, now, cumulative, &[(2, 3)])?.is_empty());
        let retried = report(&mut a, now, cumulative, &[(2, 4)])?;
        // RFC 9260 7.2.4: the first TSN has three reports, while the untouched
        // tail above HTNA has none. Repeated SACKs do not provide new evidence.
        assert_retries(&retried, &sent, &[0]);
        finish(&mut a, now, &sent)?;
    }
    Ok(())
}

#[test]
fn revoked_gap_above_htna_contributes_one_missing_report() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        let (mut a, now, sent) = recovery_sender(first, 4)?;
        let cumulative = first.wrapping_sub(1);
        assert!(report(&mut a, now, cumulative, &[(3, 3)])?.is_empty());
        // TSN 3 disappears while newly acknowledged TSN 2 determines HTNA.
        // D(iii)'s revocation report still applies to TSN 3 above that bound.
        assert!(report(&mut a, now, cumulative, &[(2, 2)])?.is_empty());
        for _ in 0..4 {
            assert!(report(&mut a, now, cumulative, &[(2, 2)])?.is_empty());
        }
        assert_retries(
            &report(&mut a, now, cumulative, &[(2, 2), (4, 4)])?,
            &sent,
            &[0],
        );
        // A cumulative advance in Fast Recovery supplies TSN 3's third
        // report. Without the earlier revocation report it would stall on T3.
        assert_retries(
            &report(&mut a, now, sent[0].tsn, &[(1, 1), (3, 3)])?,
            &sent,
            &[2],
        );
        finish(&mut a, now, &sent)?;
    }
    Ok(())
}

#[test]
fn revoked_gap_below_htna_is_not_counted_twice() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        let (mut a, now, sent) = recovery_sender(first, 5)?;
        assert!(report(&mut a, now, first.wrapping_sub(1), &[(2, 2)])?.is_empty());
        // The same SACK both revokes TSN 2 and puts it below HTNA=TSN 3.
        assert!(report(&mut a, now, sent[0].tsn, &[(2, 2)])?.is_empty());
        assert!(report(&mut a, now, sent[0].tsn, &[(2, 3)])?.is_empty());
        assert_retries(&report(&mut a, now, sent[0].tsn, &[(2, 4)])?, &sent, &[1]);
        finish(&mut a, now, &sent)?;
    }
    Ok(())
}

#[test]
fn fast_recovery_counts_revocation_and_cumulative_progress_separately() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        let (mut a, now, sent) = recovery_sender(first, 8)?;
        let cumulative = first.wrapping_sub(1);
        assert!(report(&mut a, now, cumulative, &[(2, 2)])?.is_empty());
        assert!(report(&mut a, now, cumulative, &[(2, 3)])?.is_empty());
        assert_retries(&report(&mut a, now, cumulative, &[(2, 4)])?, &sent, &[0]);
        assert!(a.in_fast_recovery);

        // In Fast Recovery with no cumulative progress, this newly ACKed TSN
        // 5 must not add a second report on top of the revocation of TSN 3.
        for _ in 0..4 {
            assert!(report(&mut a, now, cumulative, &[(2, 2), (4, 5)])?.is_empty());
        }
        // The remaining gap blocks are unchanged in absolute TSNs. HTNA is
        // now only the cumulative ACK, but the Fast Recovery rule still adds
        // reports to the missing TSN 3 on each cumulative advance.
        assert!(report(&mut a, now, sent[0].tsn, &[(1, 1), (3, 4)])?.is_empty());
        assert_retries(&report(&mut a, now, sent[1].tsn, &[(2, 3)])?, &sent, &[2]);
        finish(&mut a, now, &sent)?;
    }
    Ok(())
}

#[test]
fn sack_exiting_fast_recovery_does_not_report_the_newer_flight_missing() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        let (mut a, now, mut sent) = recovery_sender(first, 4)?;
        let cumulative = first.wrapping_sub(1);
        assert!(report(&mut a, now, cumulative, &[(2, 2)])?.is_empty());
        assert!(report(&mut a, now, cumulative, &[(2, 3)])?.is_empty());
        assert_retries(&report(&mut a, now, cumulative, &[(2, 4)])?, &sent, &[0]);

        // DATA sent after entry is beyond this recovery window. The SACK
        // leaving recovery provides no evidence of loss in that newer flight.
        let ppi = PayloadProtocolIdentifier::Binary;
        for index in 4..8 {
            a.stream(1)?
                .write_sctp(now, &Bytes::from(vec![index; 8]), ppi)?;
        }
        let newer = transmitted_data(&a.gather_outbound(now).0);
        assert_eq!(newer.len(), 4);
        sent.extend(newer);
        let exit = sent[3].tsn;
        for _ in 0..4 {
            assert!(report(&mut a, now, exit, &[])?.is_empty());
        }
        assert!(!a.in_fast_recovery);
        assert!(report(&mut a, now, exit, &[(2, 2)])?.is_empty());
        assert!(report(&mut a, now, exit, &[(2, 3)])?.is_empty());
        assert_retries(&report(&mut a, now, exit, &[(2, 4)])?, &sent, &[4]);
        finish(&mut a, now, &sent)?;
    }
    Ok(())
}

#[test]
fn cumulative_progress_prunes_old_gap_prefix_without_revoking_retained_gaps() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        let (mut a, now, sent) = recovery_sender(first, 5)?;
        let cumulative = first.wrapping_sub(1);
        assert!(report(&mut a, now, cumulative, &[(2, 5)])?.is_empty());
        // Equivalent split blocks must preserve the same advisory ACKs.
        assert!(report(&mut a, now, cumulative, &[(2, 3), (4, 5)])?.is_empty());
        assert!(report(&mut a, now, sent[1].tsn, &[(1, 1), (2, 3)])?.is_empty());
        assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
        assert_eq!(a.stream(1)?.buffered_amount()?, 0);

        // Only TSN 5 is revoked. Earlier cumulative DATA must never return,
        // while the remaining gap ACKs still exclude TSNs 3 and 4 from T3.
        assert!(report(&mut a, now, sent[1].tsn, &[(1, 2)])?.is_empty());
        assert_eq!(
            a.inflight_queue.outstanding_bytes(),
            sent[4].user_data.len()
        );
        let timeout = a.poll_timeout().expect("revoked DATA needs T3");
        a.handle_timeout(timeout);
        assert_retries(
            &transmitted_data(&a.gather_outbound(timeout).0),
            &sent,
            &[4],
        );
        finish(&mut a, timeout, &sent)?;
    }
    Ok(())
}

#[test]
fn older_cumulative_sack_cannot_replace_current_gap_evidence() -> Result<()> {
    for first in [12345, u32::MAX - 2] {
        let (mut a, now, sent) = recovery_sender(first, 6)?;
        let cumulative = first.wrapping_sub(1);
        assert!(report(&mut a, now, cumulative, &[(3, 4)])?.is_empty());
        assert!(report(&mut a, now, sent[0].tsn, &[(2, 3)])?.is_empty());
        for _ in 0..4 {
            assert!(report(&mut a, now, cumulative, &[])?.is_empty());
        }
        assert!(report(&mut a, now, sent[0].tsn, &[(2, 4)])?.is_empty());
        assert_retries(&report(&mut a, now, sent[0].tsn, &[(2, 5)])?, &sent, &[1]);
        finish(&mut a, now, &sent)?;
    }
    Ok(())
}

#[test]
fn abandoned_gap_acked_fragment_never_returns_to_outstanding() -> Result<()> {
    for first in [12345, u32::MAX] {
        let mut a = timed_test_association();
        let now = Instant::now();
        a.my_next_tsn = first;
        a.cumulative_tsn_ack_point = first.wrapping_sub(1);
        a.advanced_peer_tsn_ack_point = first.wrapping_sub(1);
        a.cwnd = 65536;
        let ppi = PayloadProtocolIdentifier::Binary;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(true, ReliabilityType::Timed, 100)?;
        stream.write_sctp(now, &Bytes::from(vec![42; 2000]), ppi)?;
        let sent = transmitted_data(&a.gather_outbound(now).0);
        assert_eq!(sent.len(), 2);
        assert!(report(&mut a, now, first.wrapping_sub(1), &[(2, 2)])?.is_empty());

        let timeout = a.poll_timeout().unwrap();
        assert!(timeout >= now + Duration::from_millis(100));
        a.handle_timeout(timeout);
        assert!(transmitted_data(&a.gather_outbound(timeout).0).is_empty());
        assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
        assert_eq!(a.inflight_queue.get_num_bytes(), 0);
        // RFC 3758's whole-message abandonment includes the previously
        // Gap-ACKed tail. A later missing gap cannot undo that decision.
        for _ in 0..3 {
            assert!(report(&mut a, timeout, first.wrapping_sub(1), &[])?.is_empty());
            assert_eq!(a.inflight_queue.outstanding_bytes(), 0);
            assert_eq!(a.stream(1)?.buffered_amount()?, 0);
        }
        finish(&mut a, timeout, &sent)?;
        let mut released = 0;
        while let Some(event) = a.poll() {
            if let Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) = event {
                released += n_bytes;
            }
        }
        assert_eq!(released, 2000, "payload credit is released exactly once");
    }
    Ok(())
}
