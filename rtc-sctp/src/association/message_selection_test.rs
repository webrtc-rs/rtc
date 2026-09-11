use super::*;

#[test]
fn a_stale_whole_message_selection_cannot_abandon_a_reused_tsn() -> Result<()> {
    for (policy, value) in [(ReliabilityType::Timed, 100), (ReliabilityType::Rexmit, 0)] {
        for first_tsn in [12345, u32::MAX] {
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
                sender.unretransmittable_messages(retry_at, ChunkPayloadData::is_outstanding);
            assert_eq!(candidates.len(), 1);
            let selected = candidates[0];
            assert!(sender.abandon_message(selected));
            assert!(!sender.abandon_message(selected));
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
                !sender.abandon_message(selected),
                "a previously selected TSN must not identify the new message"
            );
            assert_eq!(sender.inflight_queue.outstanding_bytes(), fresh.len());
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
    }
    Ok(())
}
