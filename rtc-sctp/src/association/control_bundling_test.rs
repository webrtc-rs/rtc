use super::*;

#[test]
fn reconfig_response_bundles_the_complete_immediate_sack_within_mtu() -> Result<()> {
    for mtu in [52, 51] {
        let now = Instant::now();
        let mut association = timed_test_association();
        association.mtu = mtu;
        let cumulative = association.peer_last_tsn;
        let gap_tsn = cumulative.wrapping_add(2);
        let data = ChunkPayloadData {
            tsn: gap_tsn,
            ..Default::default()
        };
        assert!(association.payload_queue.push(data.clone(), cumulative));
        assert!(!association.payload_queue.push(data, cumulative));
        association.ack_state = AckState::Immediate;
        association
            .control_queue
            .push_back(association.reconfig_response_packet(17, ReconfigResult::SuccessPerformed));

        let (raw, keep_open) = association.gather_outbound(now);
        assert!(keep_open);
        assert_eq!(raw.len(), if mtu == 52 { 1 } else { 2 });
        assert!(raw.iter().all(|packet| packet.len() <= mtu as usize));
        let packets = raw
            .iter()
            .map(Packet::unmarshal)
            .collect::<Result<Vec<_>>>()?;
        assert!(packets[0].chunks[0].as_any().is::<ChunkReconfig>());
        let sacks: Vec<_> = packets
            .iter()
            .flat_map(|packet| &packet.chunks)
            .filter_map(|chunk| chunk.as_any().downcast_ref::<ChunkSelectiveAck>())
            .collect();
        assert_eq!(sacks.len(), 1);
        assert_eq!(sacks[0].cumulative_tsn_ack, cumulative);
        assert_eq!(sacks[0].gap_ack_blocks.len(), 1);
        assert_eq!(sacks[0].gap_ack_blocks[0].start, 2);
        assert_eq!(sacks[0].gap_ack_blocks[0].end, 2);
        assert_eq!(sacks[0].duplicate_tsn, [gap_tsn]);
        assert_eq!(association.ack_state, AckState::Idle);
        assert!(association.payload_queue.pop_duplicates().is_empty());
        assert!(association.gather_outbound(now).0.is_empty());
    }
    Ok(())
}

#[test]
fn reconfig_bundling_does_not_turn_a_delayed_ack_into_an_immediate_ack() -> Result<()> {
    let mut association = timed_test_association();
    let now = Instant::now();
    association.ack_state = AckState::Delay;
    association
        .control_queue
        .push_back(association.reconfig_response_packet(17, ReconfigResult::SuccessPerformed));
    let packets = association.gather_outbound(now).0;
    assert_eq!(packets.len(), 1);
    assert_eq!(Packet::unmarshal(&packets[0])?.chunks.len(), 1);
    assert_eq!(association.ack_state, AckState::Delay);
    Ok(())
}

#[test]
fn standalone_control_chunks_never_acquire_a_bundled_sack() -> Result<()> {
    let mut chunks: Vec<Box<dyn Chunk>> = [false, true]
        .into_iter()
        .map(|is_ack| {
            Box::new(ChunkInit {
                is_ack,
                initiate_tag: 1,
                num_outbound_streams: 1,
                num_inbound_streams: 1,
                ..Default::default()
            }) as Box<dyn Chunk>
        })
        .collect();
    chunks.push(Box::new(ChunkShutdownComplete {}));
    for chunk in chunks {
        let mut association = timed_test_association();
        association.ack_state = AckState::Immediate;
        association
            .control_queue
            .push_back(association.create_packet(vec![chunk]));
        let packets = association.gather_outbound(Instant::now()).0;
        assert_eq!(packets.len(), 2);
        for packet in packets {
            assert_eq!(Packet::unmarshal(&packet)?.chunks.len(), 1);
        }
    }
    Ok(())
}
