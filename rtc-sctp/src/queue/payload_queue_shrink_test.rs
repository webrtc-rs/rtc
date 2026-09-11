use super::{ChunkPayloadData, GapAck, MessageId, MessageReliability, PayloadQueue};
use bytes::Bytes;

fn whole(tsn: u32, size: usize) -> ChunkPayloadData {
    ChunkPayloadData {
        tsn,
        beginning_fragment: true,
        ending_fragment: true,
        nsent: 1,
        user_data: Bytes::from(vec![0x5a; size]),
        ..Default::default()
    }
}

#[test]
fn cumulative_shrink_keeps_busy_and_small_queues_and_leaves_headroom() {
    let mut queue = PayloadQueue::default();
    queue.inflight.reserve(8192);
    let original_capacity = queue.inflight.capacity();
    assert!(original_capacity > 4096);
    let quarter = original_capacity / 4;
    for tsn in 0..=quarter as u32 {
        queue.push_no_check(whole(tsn, 1));
    }

    queue.shrink_after_cumulative_ack();
    assert_eq!(queue.inflight.capacity(), original_capacity);
    assert!(queue.pop(0).is_some());
    // Individual pops must not resize the allocation.
    assert_eq!(queue.inflight.capacity(), original_capacity);
    queue.shrink_after_cumulative_ack();
    let smaller = queue.inflight.capacity();
    assert!(smaller < original_capacity);
    assert!(smaller >= 2 * queue.len());
    assert_eq!(queue.get_num_bytes(), quarter);
    assert_eq!(queue.outstanding_bytes(), quarter);
    assert_eq!(queue.buffered_bytes(), quarter);
    queue.shrink_after_cumulative_ack();
    assert_eq!(queue.inflight.capacity(), smaller);

    let mut empty = PayloadQueue::default();
    empty.inflight.reserve(8192);
    let empty_before = empty.inflight.capacity();
    empty.shrink_after_cumulative_ack();
    assert!(empty.inflight.capacity() < empty_before);
    assert!(empty.inflight.capacity() >= 1024);
    let floor_capacity = empty.inflight.capacity();
    empty.shrink_after_cumulative_ack();
    assert_eq!(empty.inflight.capacity(), floor_capacity);

    let mut small = PayloadQueue::default();
    small.inflight.reserve(4096);
    assert_eq!(small.inflight.capacity(), 4096);
    small.shrink_after_cumulative_ack();
    assert_eq!(small.inflight.capacity(), 4096);
}

#[test]
fn cumulative_shrink_preserves_wrapped_sparse_entries_and_original_byte_credit() {
    for wrap_tsn in [false, true] {
        let mut queue = PayloadQueue::default();
        queue.inflight.reserve(8192);
        let capacity = queue.inflight.capacity();
        let first_position = capacity as u32 - 4;
        let origin = if wrap_tsn {
            u32::MAX - (capacity as u32 - 2)
        } else {
            4096
        };
        let tsn = |position: u32| origin.wrapping_add(position);
        let size = |position: u32| 11 + (position % 7) as usize;
        let positions = [
            first_position,
            first_position + 1,
            first_position + 2,
            first_position + 3,
            first_position + 5,
            first_position + 6,
            first_position + 10,
        ];
        let id = MessageId::new(42);
        let make = |position: u32| {
            let mut chunk = whole(tsn(position), size(position));
            chunk.stream_identifier = 7;
            chunk.stream_generation = 11;
            chunk.stream_sequence_number = 8;
            chunk.miss_indicator = position % 3;
            if position == first_position || position == first_position + 2 {
                chunk.message_id = Some(id);
                chunk.beginning_fragment = position == first_position;
                chunk.ending_fragment = position == first_position + 2;
                chunk.reliability = MessageReliability::Rexmit { max_retransmits: 0 };
            }
            chunk
        };
        for position in 0..capacity as u32 {
            queue.push_no_check(make(position));
        }
        for position in 0..first_position {
            assert!(queue.pop(tsn(position)).is_some());
        }
        // Append across the physical ring boundary, then insert into its sparse tail.
        for position in [positions[5], positions[6], positions[4]] {
            queue.push_no_check(make(position));
        }
        assert!(!queue.inflight.as_slices().1.is_empty());
        let expected_tsns: Vec<_> = positions.iter().map(|&p| tsn(p)).collect();
        assert_eq!(queue.tsns().collect::<Vec<_>>(), expected_tsns);
        let missing = tsn(first_position + 4);
        assert!(queue.get(missing).is_none());
        assert!(queue.get_mut(missing).is_none());
        assert_eq!(queue.payload_len(missing), None);
        assert!(queue.pop(expected_tsns[1]).is_none());

        let evicted = expected_tsns[0];
        let reliable = expected_tsns[1];
        for (acked, expected_len) in [
            (evicted, size(positions[0])),
            (reliable, size(positions[1])),
        ] {
            let Some(GapAck::New {
                released_buffer,
                delivery_credit,
                ..
            }) = queue.acknowledge(acked, true)
            else {
                panic!("the first acknowledgment must grant its original credit");
            };
            assert_eq!(released_buffer, expected_len);
            assert_eq!(delivery_credit, expected_len);
        }
        let abandoned = expected_tsns[3];
        assert_eq!(queue.abandon(abandoned), (true, size(positions[3])));
        let original_bytes: usize = positions.iter().map(|&p| size(p)).sum();
        let outstanding =
            original_bytes - size(positions[0]) - size(positions[1]) - size(positions[3]);
        let retained = original_bytes - size(positions[0]) - size(positions[3]);
        assert_eq!(queue.get_num_bytes(), retained);
        assert_eq!(queue.outstanding_bytes(), outstanding);
        assert_eq!(queue.buffered_bytes(), outstanding);
        let describe = |queue: &PayloadQueue| {
            expected_tsns
                .iter()
                .map(|&tsn| {
                    let chunk = queue.get(tsn).unwrap();
                    (format!("{chunk:?}"), chunk.user_data.as_ptr() as usize)
                })
                .collect::<Vec<_>>()
        };
        let before_entries = describe(&queue);
        queue.shrink_after_cumulative_ack();
        let shrunk_capacity = queue.inflight.capacity();
        assert!(shrunk_capacity < capacity);
        assert!(shrunk_capacity >= 1024);
        assert_eq!(describe(&queue), before_entries);
        assert_eq!(queue.tsns().collect::<Vec<_>>(), expected_tsns);
        assert_eq!(
            queue.message_tsns(id),
            vec![expected_tsns[0], expected_tsns[2]]
        );
        assert_eq!(queue.get_num_bytes(), retained);
        assert_eq!(queue.outstanding_bytes(), outstanding);
        assert_eq!(queue.buffered_bytes(), outstanding);
        assert!(queue.get(missing).is_none());
        assert!(queue.get_mut(missing).is_none());
        assert_eq!(queue.payload_len(missing), None);
        for &position in &positions {
            assert_eq!(queue.payload_len(tsn(position)), Some(size(position)));
        }

        assert!(queue.revoke_gap_ack(evicted));
        assert_eq!(queue.outstanding_bytes(), outstanding + size(positions[0]));
        assert_eq!(queue.get_num_bytes(), retained);
        assert_eq!(queue.buffered_bytes(), outstanding);
        assert!(queue.get(evicted).unwrap().user_data.is_empty());
        assert!(queue.revoke_gap_ack(reliable));
        queue.mark_all_to_retrasmit();
        let retry = queue.get(reliable).unwrap();
        assert!(retry.retransmit);
        assert_eq!(retry.user_data.as_ref(), vec![0x5a; size(positions[1])]);
        for acked in [evicted, reliable] {
            let Some(GapAck::New {
                released_buffer,
                delivery_credit,
                ..
            }) = queue.acknowledge(acked, true)
            else {
                panic!("a revoked ACK must be accepted again");
            };
            assert_eq!((released_buffer, delivery_credit), (0, 0));
            assert!(matches!(
                queue.acknowledge(acked, true),
                Some(GapAck::Duplicate)
            ));
        }
        assert_eq!(queue.inflight.capacity(), shrunk_capacity);
        assert_eq!(queue.outstanding_bytes(), outstanding);
        assert_eq!(queue.buffered_bytes(), outstanding);
        assert_eq!(queue.get_num_bytes(), retained);
        for expected in expected_tsns {
            assert_eq!(queue.pop(expected).unwrap().tsn, expected);
        }
        assert!(queue.is_empty());
        assert!(queue.message_tsns(id).is_empty());
        assert_eq!(queue.get_num_bytes(), 0);
        assert_eq!(queue.outstanding_bytes(), 0);
        assert_eq!(queue.buffered_bytes(), 0);
    }
}
