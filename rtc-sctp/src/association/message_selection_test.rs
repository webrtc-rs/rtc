use super::*;

#[test]
fn pending_reset_waits_for_the_fragment_tail() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        let fragment_size = a.max_payload_size;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(unordered, ReliabilityType::Reliable, 0)?;
        stream.write_sctp(
            now,
            &Bytes::from(vec![7; fragment_size as usize * 2 + 1]),
            ppi,
        )?;
        a.send_reset_request(now, 1)?;
        a.cwnd = fragment_size;
        let (head, resets) = a.pop_pending_data_chunks_to_send(now);
        assert_eq!(1, head.len());
        assert!(resets.is_empty());
        assert!(head[0].beginning_fragment && !head[0].ending_fragment);
        assert_eq!(3, a.pending_queue.len()); // two fragments and the marker

        // Window pressure must leave the reset behind the remaining DATA.
        let (data, resets) = a.pop_pending_data_chunks_to_send(now);
        assert!(data.is_empty() && resets.is_empty());
        a.cwnd = u32::MAX;
        let (tail, resets) = a.pop_pending_data_chunks_to_send(now);
        assert_eq!(2, tail.len());
        assert_eq!(vec![1], resets);
        assert!(tail[1].ending_fragment);
        assert_eq!(head[0].tsn.wrapping_add(1), tail[0].tsn);
        assert_eq!(tail[0].tsn.wrapping_add(1), tail[1].tsn);
        assert!(a.pending_queue.is_empty());
        assert_eq!(0, a.pending_queue.get_num_bytes());
    }
    // A control-only reset consumes neither a TSN nor a DATA window slot.
    let mut a = timed_test_association();
    let now = Instant::now();
    let next_tsn = a.my_next_tsn;
    a.cwnd = 0;
    a.rwnd = 0;
    a.send_reset_request(now, 2)?;
    let (data, resets) = a.pop_pending_data_chunks_to_send(now);
    assert!(data.is_empty());
    assert_eq!(vec![2], resets);
    assert_eq!(next_tsn, a.my_next_tsn);
    assert!(a.pending_queue.is_empty());
    Ok(())
}

#[test]
fn invalid_pending_data_cannot_be_sent_or_reset_a_stream() {
    for id in [None, MessageId::new(0)] {
        for empty in [false, true] {
            for zero_window in [false, true] {
                let mut a = timed_test_association();
                let next_tsn = a.my_next_tsn;
                if zero_window {
                    a.cwnd = 0;
                    a.rwnd = 0;
                }
                let rwnd = a.rwnd;
                // Empty DATA is not a reset; a tail without B cannot start a
                // message, including through the zero-window probe path.
                a.pending_queue.push(ChunkPayloadData {
                    message_id: id,
                    stream_identifier: 1,
                    beginning_fragment: empty,
                    ending_fragment: true,
                    user_data: if empty {
                        Bytes::new()
                    } else {
                        Bytes::from_static(b"tail")
                    },
                    ..Default::default()
                });
                let (data, resets) = a.pop_pending_data_chunks_to_send(Instant::now());
                assert!(data.is_empty() && resets.is_empty());
                assert_eq!(AssociationState::Closed, a.state());
                assert_eq!(next_tsn, a.my_next_tsn);
                assert_eq!(rwnd, a.rwnd);
                assert!(a.poll_timeout().is_none());
            }
        }
    }
}

#[test]
fn message_id_exhaustion_preserves_write_state_and_input() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let queued = Bytes::from_static(b"already queued");
    a.next_message_id = u64::MAX - 1;
    a.open_stream(1, ppi)?.write_sctp(now, &queued, ppi)?;
    assert_eq!(u64::MAX, a.next_message_id);
    assert_eq!(
        MessageId::new(u64::MAX - 1),
        a.pending_queue.peek().unwrap().message_id
    );
    let sequence = a.streams.get(&1).unwrap().sequence_number;
    a.stream(1)?
        .set_buffered_amount_high_threshold(queued.len() + 1)?;
    while a.poll().is_some() {}

    let mut input = [Bytes::from_static(b"first"), Bytes::from_static(b"second")];
    let original = input.clone();
    for _ in 0..2 {
        assert!(matches!(
            a.stream(1)?.write_chunks(now, &mut input),
            Err(Error::OtherSctpErr(message)) if message == "message identity exhausted"
        ));
        assert_eq!(original, input, "a failed write must not consume input");
        assert_eq!(u64::MAX, a.next_message_id, "identities must not wrap");
        assert_eq!(sequence, a.streams.get(&1).unwrap().sequence_number);
        assert_eq!(queued.len(), a.stream(1)?.buffered_amount()?);
        assert_eq!(1, a.pending_queue.len());
        assert_eq!(queued.len(), a.pending_queue.get_num_bytes());
        assert_eq!(queued, a.pending_queue.peek().unwrap().user_data);
        assert!(a.inflight_queue.is_empty());
        assert!(
            a.poll().is_none(),
            "a failed write must not emit buffer events"
        );
    }
    // The last successfully allocated identity still carries a sendable message.
    let sent = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(1, sent.len());
    assert_eq!(queued, sent[0].user_data);
    Ok(())
}

#[test]
fn a_stale_whole_message_selection_cannot_abandon_a_reused_tsn() -> Result<()> {
    for (policy, value) in [(ReliabilityType::Timed, 100), (ReliabilityType::Rexmit, 0)] {
        let first_tsn: u32 = 12345;
        let now = Instant::now();
        let mut sender = timed_test_association();
        let mut receiver = timed_test_association();
        sender.my_next_tsn = first_tsn;
        sender.cumulative_tsn_ack_point = first_tsn.wrapping_sub(1);
        sender.advanced_peer_tsn_ack_point = first_tsn.wrapping_sub(1);
        receiver.peer_last_tsn = first_tsn.wrapping_sub(1);
        let ppi = PayloadProtocolIdentifier::Binary;
        let old = Bytes::from_static(b"delivered before the delayed SACK");
        let fresh = Bytes::from_static(b"a new message using the same wire TSN");
        let mut stream = sender.open_stream(1, ppi)?;
        stream.set_reliability_params(false, policy, value)?;
        stream.write_sctp(now, &old, ppi)?;
        let sent = transmitted_data(&sender.gather_outbound(now).0);
        assert_eq!(sent.len(), 1);
        receiver.handle_data(&sent[0])?;
        assert_eq!(
            receiver
                .stream(1)?
                .read_sctp()?
                .unwrap()
                .to_payload(1024)?
                .freeze(),
            old
        );
        let delayed_sack = receiver.create_selective_ack_chunk();

        // The message can be selected for recovery before its real peer
        // acknowledgment arrives, even though the peer already delivered it.
        let retry_at = now + Duration::from_millis(100);
        let candidates =
            sender.unretransmittable_messages(retry_at, ChunkPayloadData::is_outstanding)?;
        assert_eq!(candidates.len(), 1);
        let selected = candidates[0];
        assert!(sender.abandon_message(selected)?);
        assert!(!sender.abandon_message(selected)?);
        sender.handle_sack(&delayed_sack, retry_at)?;
        assert!(sender.inflight_queue.is_empty());
        assert_eq!(sender.stream(1)?.buffered_amount()?, 0);

        // Elide a complete cycle of acknowledged TSNs instead of sending
        // 2^32 packets. Message identity and stream sequence state are not
        // rewound: this is a new message, not the old transport obligation.
        sender.my_next_tsn = first_tsn;
        sender.cumulative_tsn_ack_point = first_tsn.wrapping_sub(1);
        sender.advanced_peer_tsn_ack_point = first_tsn.wrapping_sub(1);
        receiver.peer_last_tsn = first_tsn.wrapping_sub(1);
        sender.stream(1)?.write_sctp(retry_at, &fresh, ppi)?;
        let sent = transmitted_data(&sender.gather_outbound(retry_at).0);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].tsn, first_tsn);
        assert_ne!(
            sender.inflight_queue.get(first_tsn).unwrap().message_id,
            Some(selected.id)
        );

        assert!(
            !sender.abandon_message(selected)?,
            "a previously selected TSN must not identify the new message"
        );
        assert_eq!(sender.inflight_queue.get_num_bytes(), fresh.len());
        assert_eq!(sender.stream(1)?.buffered_amount()?, fresh.len());
        receiver.handle_data(&sent[0])?;
        assert_eq!(
            receiver
                .stream(1)?
                .read_sctp()?
                .unwrap()
                .to_payload(1024)?
                .freeze(),
            fresh
        );
        sender.handle_sack(&receiver.create_selective_ack_chunk(), retry_at)?;
        assert!(sender.inflight_queue.is_empty());
        assert_eq!(sender.stream(1)?.buffered_amount()?, 0);
        let mut released = 0;
        while let Some(event) = sender.poll() {
            if let Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) = event {
                released += n_bytes;
            }
        }
        assert_eq!(released, old.len() + fresh.len());
    }
    Ok(())
}
