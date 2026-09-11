use super::{ChunkPayloadData, GapAck, MessageReliability, PayloadQueue};
use bytes::Bytes;
use std::collections::{BTreeMap, BTreeSet};

// The oracle keys are unwrapped, signed positions chosen by the test. Ordering
// and membership use BTreeMap, independently of SCTP serial comparisons and
// the queue's checked-offset/binary-search lookup implementation.
fn wire(origin: u32, position: i64) -> u32 {
    (i64::from(origin) + position).rem_euclid(1_i64 << 32) as u32
}

#[derive(Clone)]
struct ExpectedData {
    len: usize,
    byte: u8,
    miss: u32,
    exhausted: bool,
}

impl ExpectedData {
    fn new(position: i64, exhausted: bool) -> Self {
        Self {
            len: 7 + position.rem_euclid(31) as usize,
            byte: position.rem_euclid(251) as u8,
            miss: 0,
            exhausted,
        }
    }

    fn chunk(&self, tsn: u32) -> ChunkPayloadData {
        ChunkPayloadData {
            tsn,
            beginning_fragment: true,
            ending_fragment: true,
            nsent: 1,
            user_data: Bytes::from(vec![self.byte; self.len]),
            reliability: if self.exhausted {
                MessageReliability::Rexmit { max_retransmits: 0 }
            } else {
                MessageReliability::Reliable
            },
            ..Default::default()
        }
    }
}

fn insert(
    queue: &mut PayloadQueue,
    expected: &mut BTreeMap<i64, ExpectedData>,
    origin: u32,
    position: i64,
    exhausted: bool,
) {
    let data = ExpectedData::new(position, exhausted);
    queue.push_no_check(data.chunk(wire(origin, position)));
    assert!(expected.insert(position, data).is_none());
}

fn assert_unacknowledged_model(
    queue: &PayloadQueue,
    expected: &BTreeMap<i64, ExpectedData>,
    origin: u32,
    last_probe: i64,
) {
    assert_eq!(
        queue.tsns().collect::<Vec<_>>(),
        expected
            .keys()
            .map(|&p| wire(origin, p))
            .collect::<Vec<_>>()
    );
    assert_eq!(queue.len(), expected.len());
    assert_eq!(queue.is_empty(), expected.is_empty());
    let bytes: usize = expected.values().map(|data| data.len).sum();
    assert_eq!(queue.get_num_bytes(), bytes);
    assert_eq!(queue.outstanding_bytes(), bytes);
    assert_eq!(queue.buffered_bytes(), bytes);
    for position in -3..=last_probe {
        let tsn = wire(origin, position);
        assert_eq!(
            queue.payload_len(tsn),
            expected.get(&position).map(|data| data.len),
            "original length at {origin}/{position}"
        );
        match (queue.get(tsn), expected.get(&position)) {
            (Some(actual), Some(data)) => {
                assert_eq!(actual.tsn, tsn);
                assert_eq!(actual.user_data.as_ref(), vec![data.byte; data.len]);
                assert_eq!(actual.miss_indicator, data.miss);
                assert!(actual.is_outstanding());
            }
            (None, None) => {}
            _ => panic!("membership differs at {origin}/{position}"),
        }
    }
}

fn pop_model_front(
    queue: &mut PayloadQueue,
    expected: &mut BTreeMap<i64, ExpectedData>,
    origin: u32,
) {
    let (position, data) = expected.pop_first().unwrap();
    let tsn = wire(origin, position);
    let popped = queue.pop(tsn).expect("model front must pop");
    assert_eq!(popped.tsn, tsn);
    assert_eq!(popped.user_data.as_ref(), vec![data.byte; data.len]);
    assert_eq!(popped.miss_indicator, data.miss);
    assert!(queue.get(tsn).is_none());
    assert!(queue.get_mut(tsn).is_none());
    assert_eq!(queue.payload_len(tsn), None);
}

#[test]
fn dense_and_sparse_inflight_match_serial_model_through_wrap_and_prefix_churn() {
    for origin in [4096, u32::MAX - 16] {
        let mut queue = PayloadQueue::default();
        let mut expected = BTreeMap::new();
        // At [0,4,9], querying 1 has an in-bounds direct candidate belonging to
        // TSN 4. It must miss, and querying 4 must find the sparse fallback.
        for position in [0, 4, 9, 1, 3, 8, 2, 7, 6, 5] {
            insert(&mut queue, &mut expected, origin, position, false);
            assert_unacknowledged_model(&queue, &expected, origin, 12);
            assert!(queue.get_mut(wire(origin, 11)).is_none());
        }
        for position in 10..512 {
            insert(&mut queue, &mut expected, origin, position, false);
        }
        for position in [1, 4, 127, 511] {
            let miss = 1000 + position as u32;
            queue
                .get_mut(wire(origin, position))
                .unwrap()
                .miss_indicator = miss;
            expected.get_mut(&position).unwrap().miss = miss;
        }
        assert_unacknowledged_model(&queue, &expected, origin, 514);
        for wrong in [-1, 7, 511, 512] {
            assert!(queue.pop(wire(origin, wrong)).is_none());
        }
        assert_unacknowledged_model(&queue, &expected, origin, 514);

        // Repeated front removal and tail appending exercises a wrapped deque
        // buffer as well as a wrapped wire TSN. No permanent insertion base is
        // a valid lookup base once the prefix starts moving.
        for position in 512..1536 {
            pop_model_front(&mut queue, &mut expected, origin);
            insert(&mut queue, &mut expected, origin, position, false);
            if position % 113 == 0 {
                assert_unacknowledged_model(&queue, &expected, origin, position + 2);
            }
        }
        assert_unacknowledged_model(&queue, &expected, origin, 1538);
        while !expected.is_empty() {
            pop_model_front(&mut queue, &mut expected, origin);
        }
        assert_unacknowledged_model(&queue, &expected, origin, 1538);

        // An empty queue accepts a fresh base independently of the last TSN it
        // held. This also represents acknowledged TSN-cycle elision in tests.
        let fresh_origin = origin.wrapping_add(1 << 31);
        for position in [0, 3, 1, 2] {
            insert(&mut queue, &mut expected, fresh_origin, position, false);
        }
        assert_unacknowledged_model(&queue, &expected, fresh_origin, 6);
        // Association close replaces the whole queue, even with live entries.
        queue = PayloadQueue::default();
        expected.clear();
        assert_unacknowledged_model(&queue, &expected, origin, 6);
        for position in [2, 0, 1] {
            insert(&mut queue, &mut expected, origin, position, false);
        }
        assert_unacknowledged_model(&queue, &expected, origin, 6);
        while !expected.is_empty() {
            pop_model_front(&mut queue, &mut expected, origin);
        }
        assert_unacknowledged_model(&queue, &expected, origin, 6);
    }
}

#[derive(Default)]
struct ReceiptModel {
    acknowledged: BTreeSet<i64>,
    buffer_released: BTreeSet<i64>,
    delivery_credited: BTreeSet<i64>,
    payload_freed: BTreeSet<i64>,
    abandoned: BTreeSet<i64>,
}

fn assert_receipt_model(
    queue: &PayloadQueue,
    expected: &BTreeMap<i64, ExpectedData>,
    origin: u32,
    receipts: &ReceiptModel,
) {
    assert_eq!(
        queue.tsns().collect::<Vec<_>>(),
        expected
            .keys()
            .map(|&p| wire(origin, p))
            .collect::<Vec<_>>()
    );
    assert_eq!(queue.len(), expected.len());
    assert_eq!(queue.is_empty(), expected.is_empty());
    let sum = |include: &dyn Fn(i64) -> bool| -> usize {
        expected
            .iter()
            .filter(|(position, _)| include(**position))
            .map(|(_, data)| data.len)
            .sum()
    };
    assert_eq!(
        queue.get_num_bytes(),
        sum(&|p| !receipts.payload_freed.contains(&p))
    );
    assert_eq!(
        queue.buffered_bytes(),
        sum(&|p| !receipts.buffer_released.contains(&p))
    );
    assert_eq!(
        queue.outstanding_bytes(),
        sum(&|p| !receipts.acknowledged.contains(&p) && !receipts.abandoned.contains(&p))
    );
    for (&position, data) in expected {
        let tsn = wire(origin, position);
        let chunk = queue.get(tsn).unwrap();
        assert_eq!(chunk.tsn, tsn);
        assert_eq!(queue.payload_len(tsn), Some(data.len));
        assert_eq!(
            chunk.acknowledged,
            receipts.acknowledged.contains(&position)
        );
        assert_eq!(
            chunk.buffer_released,
            receipts.buffer_released.contains(&position)
        );
        assert_eq!(
            chunk.delivery_credited,
            receipts.delivery_credited.contains(&position)
        );
        assert_eq!(chunk.abandoned, receipts.abandoned.contains(&position));
        if receipts.payload_freed.contains(&position) {
            assert!(chunk.user_data.is_empty());
        } else {
            assert_eq!(chunk.user_data.as_ref(), vec![data.byte; data.len]);
        }
    }
}

fn expect_new_ack(queue: &mut PayloadQueue, tsn: u32, released: usize, credited: usize) {
    match queue.acknowledge(tsn, true) {
        Some(GapAck::New {
            chunk,
            released_buffer,
            delivery_credit,
        }) => {
            assert_eq!(chunk.tsn, tsn);
            assert!(chunk.acknowledged);
            assert!(!chunk.retransmit);
            assert_eq!(chunk.miss_indicator, 0);
            assert_eq!(released_buffer, released);
            assert_eq!(delivery_credit, credited);
        }
        _ => panic!("expected a first receipt or reACK for {tsn}"),
    }
}

#[test]
fn sparse_lookup_preserves_original_debt_and_once_only_credit_after_reack() {
    for origin in [8192, u32::MAX - 5] {
        let mut queue = PayloadQueue::default();
        let mut expected = BTreeMap::new();
        let mut receipts = ReceiptModel::default();
        for position in [0, 6, 12, 1, 4, 10] {
            insert(&mut queue, &mut expected, origin, position, position == 4);
        }
        assert_receipt_model(&queue, &expected, origin, &receipts);
        queue.mark_all_to_retrasmit();
        for position in [4, 10] {
            let len = expected[&position].len;
            expect_new_ack(&mut queue, wire(origin, position), len, len);
            receipts.acknowledged.insert(position);
            receipts.buffer_released.insert(position);
            receipts.delivery_credited.insert(position);
        }
        receipts.payload_freed.insert(4); // Only exhausted Rexmit(0) can evict on gap ACK.
        assert_receipt_model(&queue, &expected, origin, &receipts);
        for position in [4, 10] {
            assert!(matches!(
                queue.acknowledge(wire(origin, position), true),
                Some(GapAck::Duplicate)
            ));
        }
        // In-bounds wrong candidates and missing fallbacks must not mutate a
        // neighboring DATA record through any indexed accounting operation.
        for position in [-1, 2, 5, 7, 11, 13] {
            let tsn = wire(origin, position);
            assert!(queue.get_mut(tsn).is_none());
            assert!(queue.acknowledge(tsn, true).is_none());
            assert!(!queue.revoke_gap_ack(tsn));
            assert_eq!(queue.abandon(tsn), (false, 0));
            assert!(queue.pop(tsn).is_none());
        }
        assert_receipt_model(&queue, &expected, origin, &receipts);

        assert!(queue.revoke_gap_ack(wire(origin, 4)));
        receipts.acknowledged.remove(&4);
        assert_receipt_model(&queue, &expected, origin, &receipts);
        assert!(!queue.revoke_gap_ack(wire(origin, 4)));
        queue.get_mut(wire(origin, 4)).unwrap().miss_indicator = 2;
        expect_new_ack(&mut queue, wire(origin, 4), 0, 0);
        receipts.acknowledged.insert(4);
        assert_receipt_model(&queue, &expected, origin, &receipts);

        assert_eq!(queue.abandon(wire(origin, 6)), (true, expected[&6].len));
        receipts.abandoned.insert(6);
        receipts.buffer_released.insert(6);
        receipts.payload_freed.insert(6);
        assert_eq!(queue.abandon(wire(origin, 6)), (false, 0));
        assert_receipt_model(&queue, &expected, origin, &receipts);

        assert!(queue.revoke_gap_ack(wire(origin, 10)));
        receipts.acknowledged.remove(&10);
        assert_receipt_model(&queue, &expected, origin, &receipts);
        expect_new_ack(&mut queue, wire(origin, 10), 0, 0);
        receipts.acknowledged.insert(10);
        assert_eq!(queue.abandon(wire(origin, 10)), (true, 0));
        receipts.abandoned.insert(10);
        receipts.payload_freed.insert(10);
        assert!(!queue.revoke_gap_ack(wire(origin, 10)));
        assert!(matches!(
            queue.acknowledge(wire(origin, 10), true),
            Some(GapAck::Duplicate)
        ));
        expect_new_ack(&mut queue, wire(origin, 6), 0, 0);
        receipts.acknowledged.insert(6);
        receipts.delivery_credited.insert(6);
        assert_receipt_model(&queue, &expected, origin, &receipts);

        assert!(queue.pop(wire(origin, 4)).is_none());
        assert_receipt_model(&queue, &expected, origin, &receipts);
        while let Some((position, data)) = expected.pop_first() {
            let tsn = wire(origin, position);
            let popped = queue.pop(tsn).unwrap();
            assert_eq!(popped.tsn, tsn);
            if receipts.payload_freed.contains(&position) {
                assert!(popped.user_data.is_empty());
            } else {
                assert_eq!(popped.user_data.as_ref(), vec![data.byte; data.len]);
            }
            assert!(queue.get(tsn).is_none());
            assert_eq!(queue.payload_len(tsn), None);
            assert_receipt_model(&queue, &expected, origin, &receipts);
        }
    }
}
