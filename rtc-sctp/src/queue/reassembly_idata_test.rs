//! Ports of pion/sctp's `TestReassemblyQueue` subtests that concern descriptor limits and I-DATA
//! (RFC 8260) message reassembly, plus `TestStreamHandleForwardTSNForMID`.

use super::reassembly_queue::*;
use crate::chunk::chunk_payload_data::{ChunkPayloadData, PayloadProtocolIdentifier};
use shared::error::Error;

use bytes::Bytes;

const PPI: PayloadProtocolIdentifier = PayloadProtocolIdentifier::Binary;

/// An I-DATA fragment, as pion's tests spell them out field by field.
fn idata(
    mid: u32,
    fsn: u32,
    tsn: u32,
    begin: bool,
    end: bool,
    data: &'static str,
) -> ChunkPayloadData {
    ChunkPayloadData {
        idata: true,
        message_identifier: mid,
        fragment_sequence_number: fsn,
        beginning_fragment: begin,
        ending_fragment: end,
        tsn,
        stream_identifier: 0,
        payload_type: PPI,
        user_data: Bytes::from_static(data.as_bytes()),
        ..Default::default()
    }
}

fn unordered(mut c: ChunkPayloadData) -> ChunkPayloadData {
    c.unordered = true;
    c
}

fn data_fragment(ssn: u16, tsn: u32, begin: bool, end: bool, unordered: bool) -> ChunkPayloadData {
    ChunkPayloadData {
        stream_sequence_number: ssn,
        beginning_fragment: begin,
        ending_fragment: end,
        unordered,
        tsn,
        stream_identifier: 0,
        payload_type: PPI,
        ..Default::default()
    }
}

fn read_all(rq: &mut ReassemblyQueue) -> (Vec<u8>, PayloadProtocolIdentifier) {
    let chunks = rq.read().expect("a readable message");
    let mut buf = vec![0u8; 64];
    let n = chunks.read(&mut buf).unwrap();
    buf.truncate(n);
    (buf, chunks.ppi)
}

#[test]
fn fragmented_and_unfragmented_chunks_with_the_same_ssn() {
    // pion: TestReassemblyQueue/"fragmented and unfragmented chunks with the same ssn"
    let mut rq = ReassemblyQueue::new(0);
    let ssn = 6;

    let mut c = data_fragment(ssn, 12, true, true, false);
    c.user_data = Bytes::from_static(b"DEF");
    assert!(rq.push(c), "chunk set should be complete");
    assert_eq!(3, rq.get_num_bytes(), "num bytes mismatch");

    let mut c = data_fragment(ssn, 11, true, false, false);
    c.user_data = Bytes::from_static(b"ABC");
    assert!(!rq.push(c), "chunk set should not be complete yet");
    assert_eq!(6, rq.get_num_bytes(), "num bytes mismatch");

    assert_eq!(2, rq.ordered.len(), "there should be two chunks");
    assert_eq!(6, rq.get_num_bytes(), "num bytes mismatch");
}

#[test]
fn data_has_no_descriptor_limit_by_default() {
    const OLD_LIMIT: u16 = 3;
    let mut rq = ReassemblyQueue::new(0);
    for i in 0..=OLD_LIMIT {
        let c = data_fragment(i, u32::from(i) + 1, true, false, false);
        assert_eq!(Ok(false), rq.push_checked(c).map_err(|e| e.to_string()));
    }
    assert_eq!(usize::from(OLD_LIMIT) + 1, rq.ordered.len());

    let mut rq = ReassemblyQueue::new(0);
    for i in 0..=OLD_LIMIT {
        let c = data_fragment(0, u32::from(i) + 1, true, false, true);
        assert!(
            !rq.push_checked(c).unwrap(),
            "unordered DATA should remain incomplete"
        );
    }
    assert_eq!(usize::from(OLD_LIMIT) + 1, rq.unordered_chunks.len());
    assert_eq!(0, rq.unordered.len());
}

#[test]
fn ordered_data_rejects_new_entries_after_descriptor_limit() {
    const LIMIT: u16 = 3;
    let mut rq = ReassemblyQueue::new(0).with_max_entries(u32::from(LIMIT));
    for i in 0..LIMIT {
        let c = data_fragment(i, u32::from(i) * 10 + 1, true, false, false);
        assert!(!rq.push_checked(c).unwrap(), "SSN should remain incomplete");
    }

    // A fragment that is already queued is a duplicate, not growth.
    let dup = data_fragment(0, 1, true, false, false);
    assert!(
        !rq.push_checked(dup).unwrap(),
        "duplicate fragments should not complete"
    );

    let err = rq.push_checked(data_fragment(0, 2, false, true, false));
    assert!(
        matches!(err, Err(Error::ErrReassemblyQueueLimitExceeded)),
        "new fragments for existing SSNs should be rejected at the limit: {err:?}"
    );

    let err = rq.push_checked(data_fragment(
        LIMIT,
        u32::from(LIMIT) * 10 + 1,
        true,
        false,
        false,
    ));
    assert!(
        matches!(err, Err(Error::ErrReassemblyQueueLimitExceeded)),
        "new SSN should be rejected"
    );
    assert_eq!(usize::from(LIMIT), rq.ordered.len());
}

#[test]
fn unordered_data_counts_queued_sets_and_fragments_against_the_descriptor_limit() {
    const LIMIT: u32 = 3;

    // New incomplete chunks.
    let mut rq = ReassemblyQueue::new(0).with_max_entries(LIMIT);
    for i in 0..LIMIT {
        assert!(
            !rq.push_checked(data_fragment(0, i + 1, true, false, true))
                .unwrap()
        );
    }
    let err = rq.push_checked(data_fragment(0, LIMIT + 1, true, false, true));
    assert!(matches!(err, Err(Error::ErrReassemblyQueueLimitExceeded)));
    assert_eq!(LIMIT as usize, rq.unordered_chunks.len());
    assert_eq!(0, rq.unordered.len());

    // Complete queued sets.
    let mut rq = ReassemblyQueue::new(0).with_max_entries(LIMIT);
    for i in 0..LIMIT {
        assert!(
            rq.push_checked(data_fragment(0, i + 1, true, true, true))
                .unwrap()
        );
    }
    let err = rq.push_checked(data_fragment(0, LIMIT + 1, true, true, true));
    assert!(matches!(err, Err(Error::ErrReassemblyQueueLimitExceeded)));
    assert_eq!(0, rq.unordered_chunks.len());
    assert_eq!(LIMIT as usize, rq.unordered.len());

    // The fragments of a complete queued set count one by one.
    let mut rq = ReassemblyQueue::new(0).with_max_entries(LIMIT);
    for i in 0..LIMIT {
        let complete = rq
            .push_checked(data_fragment(0, i + 1, i == 0, i == LIMIT - 1, true))
            .unwrap();
        assert_eq!(i == LIMIT - 1, complete);
    }
    let err = rq.push_checked(data_fragment(0, LIMIT + 1, true, true, true));
    assert!(matches!(err, Err(Error::ErrReassemblyQueueLimitExceeded)));
    assert_eq!(0, rq.unordered_chunks.len());
    assert_eq!(1, rq.unordered.len());
}

#[test]
fn idata_ordered_fragments_by_fsn() {
    let mut rq = ReassemblyQueue::new(0);
    assert!(
        !rq.push(idata(0, 1, 10, false, true, "B")),
        "chunk set should not be complete yet"
    );
    assert!(
        rq.push(idata(0, 0, 5, true, false, "A")),
        "chunk set should be complete"
    );
    let (data, ppi) = read_all(&mut rq);
    assert_eq!(b"AB", &data[..]);
    assert_eq!(PPI, ppi, "should have valid ppi");
}

#[test]
fn idata_ordered_ignores_duplicate_fsn_with_different_tsn() {
    let mut rq = ReassemblyQueue::new(0);
    assert!(!rq.push(idata(0, 0, 5, true, false, "A")));
    assert_eq!(1, rq.get_num_bytes());

    assert!(
        !rq.push(idata(0, 0, 10, false, false, "duplicate")),
        "duplicate FSN should be ignored"
    );
    assert_eq!(
        1,
        rq.get_num_bytes(),
        "duplicate FSN must not count toward queued bytes"
    );

    assert!(
        rq.push(idata(0, 1, 6, false, true, "B")),
        "chunk set should be complete"
    );
    assert_eq!(2, rq.get_num_bytes());

    let (data, ppi) = read_all(&mut rq);
    assert_eq!(b"AB", &data[..]);
    assert_eq!(PPI, ppi);
    assert_eq!(0, rq.get_num_bytes());
}

#[test]
fn idata_ordered_ignores_stale_incomplete_mid_after_read_advances_next_mid() {
    let mut rq = ReassemblyQueue::new(0);
    assert!(
        rq.push_checked(idata(0, 0, 1, true, true, "M0")).unwrap(),
        "MID 0 should be complete"
    );

    let (data, ppi) = read_all(&mut rq);
    assert_eq!((&b"M0"[..], PPI), (&data[..], ppi));
    assert_eq!(1, rq.next_mid, "next MID should advance");
    assert_eq!(0, rq.get_num_bytes(), "queue should be empty after read");

    assert!(
        !rq.push_checked(idata(0, 0, 2, true, false, "stale"))
            .unwrap(),
        "stale MID should be ignored"
    );
    assert_eq!(0, rq.ordered_mid_len(), "stale MID must not be queued");
    assert_eq!(
        0,
        rq.get_num_bytes(),
        "stale MID must not count toward queued bytes"
    );

    assert!(
        rq.push_checked(idata(1, 0, 3, true, true, "M1")).unwrap(),
        "MID 1 should be complete"
    );
    assert!(
        rq.is_readable(),
        "current MID should not be blocked by stale MID"
    );

    let (data, ppi) = read_all(&mut rq);
    assert_eq!((&b"M1"[..], PPI), (&data[..], ppi));
    assert_eq!(2, rq.next_mid, "next MID should advance");
    assert_eq!(0, rq.get_num_bytes(), "queue should be empty after read");
}

#[test]
fn idata_ordered_ignores_stale_complete_mid_after_read_advances_next_mid() {
    let mut rq = ReassemblyQueue::new(0);
    assert!(rq.push_checked(idata(0, 0, 1, true, true, "M0")).unwrap());
    let (data, _) = read_all(&mut rq);
    assert_eq!(b"M0", &data[..]);
    assert_eq!(1, rq.next_mid);
    assert_eq!(0, rq.get_num_bytes());

    assert!(
        !rq.push_checked(idata(0, 0, 2, true, true, "old")).unwrap(),
        "stale complete MID should be ignored"
    );
    assert!(
        !rq.is_readable(),
        "stale complete MID must not become readable"
    );
    assert_eq!(0, rq.ordered_mid_len(), "stale MID must not be queued");
    assert_eq!(
        0,
        rq.get_num_bytes(),
        "stale MID must not count toward queued bytes"
    );
}

#[test]
fn idata_unordered_ignores_duplicate_fsn_with_different_tsn() {
    let mut rq = ReassemblyQueue::new(0);
    assert!(!rq.push(unordered(idata(0, 0, 5, true, false, "A"))));
    assert_eq!(1, rq.get_num_bytes());

    assert!(
        !rq.push(unordered(idata(0, 0, 10, false, false, "duplicate"))),
        "duplicate FSN should be ignored"
    );
    assert_eq!(
        1,
        rq.get_num_bytes(),
        "duplicate FSN must not count toward queued bytes"
    );

    assert!(
        rq.push(unordered(idata(0, 1, 6, false, true, "B"))),
        "chunk set should be complete"
    );
    assert_eq!(2, rq.get_num_bytes());

    assert!(
        !rq.push(unordered(idata(0, 1, 11, false, true, "late-duplicate"))),
        "duplicate for queued complete MID should be ignored"
    );
    assert_eq!(
        2,
        rq.get_num_bytes(),
        "late duplicate must not count toward queued bytes"
    );

    let (data, ppi) = read_all(&mut rq);
    assert_eq!((&b"AB"[..], PPI), (&data[..], ppi));
    assert_eq!(0, rq.get_num_bytes());
}

#[test]
fn forward_tsn_for_ordered_idata_drops_incomplete_mids_and_advances_next_mid() {
    let mut rq = ReassemblyQueue::new(0);
    assert!(rq.push(idata(0, 0, 10, true, true, "OK")));
    assert!(
        !rq.push(idata(1, 0, 11, true, false, "DROP")),
        "MID 1 should remain incomplete"
    );
    assert_eq!(6, rq.get_num_bytes());

    rq.forward_tsn_for_ordered_mid(1);

    assert_eq!(2, rq.next_mid, "next MID should advance");
    assert_eq!(
        vec![0],
        rq.ordered_mids(),
        "only the complete MID should remain"
    );
    assert_eq!(
        2,
        rq.get_num_bytes(),
        "only the kept MID bytes should remain"
    );
    assert!(rq.is_readable(), "kept complete MID should be readable");

    let (data, ppi) = read_all(&mut rq);
    assert_eq!((&b"OK"[..], PPI), (&data[..], ppi));
    assert_eq!(
        0,
        rq.get_num_bytes(),
        "all bytes should be drained after read"
    );
    assert_eq!(2, rq.next_mid, "next MID should remain forwarded");
}

#[test]
fn ordered_idata_ignores_stale_mids_after_forward_tsn_advances_next_mid() {
    let mut rq = ReassemblyQueue::new(0);
    rq.forward_tsn_for_ordered_mid(1);
    assert_eq!(2, rq.next_mid, "next MID should advance");

    assert!(
        !rq.push_checked(idata(0, 0, 1, true, false, "old0"))
            .unwrap(),
        "stale MID 0 should be ignored"
    );
    assert_eq!(0, rq.ordered_mid_len());
    assert_eq!(0, rq.get_num_bytes());

    assert!(
        !rq.push_checked(idata(1, 0, 2, true, true, "old1")).unwrap(),
        "stale MID 1 should be ignored"
    );
    assert_eq!(0, rq.ordered_mid_len());
    assert_eq!(0, rq.get_num_bytes());

    assert!(
        rq.push_checked(idata(2, 0, 3, true, true, "M2")).unwrap(),
        "MID 2 should be complete"
    );
    assert!(
        rq.is_readable(),
        "current MID should not be blocked by stale MIDs"
    );

    let (data, ppi) = read_all(&mut rq);
    assert_eq!((&b"M2"[..], PPI), (&data[..], ppi));
    assert_eq!(3, rq.next_mid);
    assert_eq!(0, rq.get_num_bytes());
}

#[test]
fn forward_tsn_for_unordered_idata_keeps_complete_mids_and_drops_old_incomplete_mids() {
    let mut rq = ReassemblyQueue::new(0);
    assert!(
        rq.push(unordered(idata(1, 0, 10, true, true, "old"))),
        "MID 1 should be complete"
    );
    assert!(
        !rq.push(unordered(idata(2, 0, 11, true, false, "drop"))),
        "MID 2 should remain incomplete"
    );
    assert!(
        rq.push(unordered(idata(4, 0, 12, true, true, "keep"))),
        "MID 4 should be complete"
    );
    assert!(
        !rq.push(unordered(idata(5, 0, 13, true, false, "later"))),
        "MID 5 should remain incomplete"
    );
    assert_eq!(16, rq.get_num_bytes());

    rq.forward_tsn_for_unordered_mid(2);

    assert_eq!(
        vec![1, 4],
        rq.unordered_ready_mids(),
        "complete MIDs should remain queued"
    );
    assert_eq!(
        vec![5],
        rq.unordered_open_mids(),
        "only newer incomplete MIDs should remain"
    );
    assert_eq!(
        12,
        rq.get_num_bytes(),
        "only incomplete forwarded MID bytes should be removed"
    );
    assert!(
        rq.is_readable(),
        "complete unordered MID should still be readable"
    );

    let (data, ppi) = read_all(&mut rq);
    assert_eq!((&b"old"[..], PPI), (&data[..], ppi));
    assert_eq!(
        9,
        rq.get_num_bytes(),
        "newer complete and incomplete MID bytes should remain"
    );
    assert!(
        rq.is_readable(),
        "newer complete unordered MID should still be readable"
    );

    let (data, ppi) = read_all(&mut rq);
    assert_eq!((&b"keep"[..], PPI), (&data[..], ppi));
    assert_eq!(
        5,
        rq.get_num_bytes(),
        "only the remaining incomplete MID bytes should remain"
    );
    assert!(!rq.is_readable(), "only an incomplete MID should remain");
}

fn begin(mid: u32, tsn: u32, unordered: bool) -> ChunkPayloadData {
    ChunkPayloadData {
        unordered,
        ..idata(mid, 0, tsn, true, false, "")
    }
}

fn whole(mid: u32, tsn: u32, unordered: bool) -> ChunkPayloadData {
    ChunkPayloadData {
        unordered,
        ..idata(mid, 0, tsn, true, true, "")
    }
}

#[test]
fn idata_has_no_descriptor_limit_by_default() {
    const OLD_LIMIT: u32 = 3;
    for unordered in [false, true] {
        let mut rq = ReassemblyQueue::new(0);
        for i in 0..=OLD_LIMIT {
            assert!(
                !rq.push_checked(begin(i, i + 1, unordered)).unwrap(),
                "MID should remain incomplete"
            );
        }
        if unordered {
            assert_eq!(OLD_LIMIT as usize + 1, rq.unordered_open_mids().len());
            assert_eq!(0, rq.unordered_ready_mids().len());
        } else {
            assert_eq!(OLD_LIMIT as usize + 1, rq.ordered_mid_len());
        }
    }
}

#[test]
fn ordered_idata_rejects_new_mids_after_descriptor_limit() {
    const LIMIT: u32 = 3;
    let mut rq = ReassemblyQueue::new(0).with_max_entries(LIMIT);
    for i in 0..LIMIT {
        assert!(
            !rq.push_checked(begin(i, i + 1, false)).unwrap(),
            "MID should remain incomplete"
        );
    }

    let mut end = idata(0, 1, LIMIT + 1, false, true, "");
    end.payload_type = PPI;
    assert!(
        rq.push_checked(end).unwrap(),
        "existing MID should still accept fragments at the limit and complete"
    );

    let err = rq.push_checked(begin(LIMIT, LIMIT + 2, false));
    assert!(
        matches!(err, Err(Error::ErrReassemblyQueueMidLimitExceeded)),
        "new MID should be rejected"
    );
    assert_eq!(LIMIT as usize, rq.ordered_mid_len());
    assert_eq!(
        0,
        rq.get_num_bytes(),
        "zero-byte fragments must not hide descriptor growth"
    );
}

#[test]
fn ordered_idata_inserts_new_mids_in_order() {
    let mut rq = ReassemblyQueue::new(0);
    for (i, mid) in [3u32, 1, 2].into_iter().enumerate() {
        assert!(
            !rq.push_checked(begin(mid, i as u32 + 1, false)).unwrap(),
            "MID should remain incomplete"
        );
    }
    assert_eq!(vec![1, 2, 3], rq.ordered_mids());
}

#[test]
fn unordered_idata_rejects_new_incomplete_mids_after_descriptor_limit() {
    const LIMIT: u32 = 3;
    let mut rq = ReassemblyQueue::new(0).with_max_entries(LIMIT);
    for i in 0..LIMIT {
        assert!(!rq.push_checked(begin(i, i + 1, true)).unwrap());
    }
    let err = rq.push_checked(begin(LIMIT, LIMIT + 1, true));
    assert!(
        matches!(err, Err(Error::ErrReassemblyQueueMidLimitExceeded)),
        "new MID should be rejected"
    );
    assert_eq!(LIMIT as usize, rq.unordered_open_mids().len());
    assert_eq!(0, rq.unordered_ready_mids().len());
    assert_eq!(
        0,
        rq.get_num_bytes(),
        "zero-byte fragments must not hide descriptor growth"
    );
}

#[test]
fn unordered_idata_counts_complete_queued_mids_against_the_descriptor_limit() {
    const LIMIT: u32 = 3;
    let mut rq = ReassemblyQueue::new(0).with_max_entries(LIMIT);
    for i in 0..LIMIT {
        assert!(
            rq.push_checked(whole(i, i + 1, true)).unwrap(),
            "MID should complete"
        );
    }
    let err = rq.push_checked(whole(LIMIT, LIMIT + 1, true));
    assert!(
        matches!(err, Err(Error::ErrReassemblyQueueMidLimitExceeded)),
        "new MID should be rejected"
    );
    assert_eq!(0, rq.unordered_open_mids().len());
    assert_eq!(LIMIT as usize, rq.unordered_ready_mids().len());
    assert_eq!(
        0,
        rq.get_num_bytes(),
        "zero-byte messages must not hide descriptor growth"
    );
}
