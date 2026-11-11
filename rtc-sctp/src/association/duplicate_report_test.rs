use super::*;

fn data(tsn: u32) -> ChunkPayloadData {
    ChunkPayloadData {
        unordered: true,
        beginning_fragment: true,
        ending_fragment: true,
        tsn,
        stream_identifier: 1,
        user_data: Bytes::from_static(b"x"),
        ..Default::default()
    }
}

fn receiver() -> Association {
    let mut a = timed_test_association();
    a.peer_last_tsn = 99;
    a
}

/// Hands `chunks` to the receiver as one inbound packet.
fn receive(a: &mut Association, chunks: &[ChunkPayloadData]) -> Result<()> {
    a.handle_chunk_start();
    for chunk in chunks {
        a.handle_data(chunk)?;
    }
    a.handle_chunk_end(Instant::now());
    Ok(())
}

#[test]
fn a_repeat_below_the_cumulative_tsn_is_reported_in_a_sack_sent_at_once() -> Result<()> {
    let mut a = receiver();
    receive(&mut a, &[data(100)])?;
    assert_eq!(
        AckState::Delay,
        a.ack_state,
        "one new chunk in order waits for the timer"
    );
    a.ack_state = AckState::Idle;
    assert!(a.create_selective_ack_chunk().duplicate_tsn.is_empty());

    receive(&mut a, &[data(100)])?;

    assert_eq!(
        AckState::Immediate,
        a.ack_state,
        "a repeats-only packet is acknowledged at once"
    );
    let sack = a.create_selective_ack_chunk();
    assert_eq!(100, sack.cumulative_tsn_ack);
    assert_eq!(vec![100], sack.duplicate_tsn);
    assert!(
        a.create_selective_ack_chunk().duplicate_tsn.is_empty(),
        "each SACK starts a fresh list"
    );
    Ok(())
}

#[test]
fn a_repeat_of_a_chunk_held_above_a_gap_is_reported() -> Result<()> {
    let mut a = receiver();
    receive(&mut a, &[data(102)])?;
    let _ = a.create_selective_ack_chunk();

    receive(&mut a, &[data(102)])?;

    assert_eq!(AckState::Immediate, a.ack_state);
    let sack = a.create_selective_ack_chunk();
    assert_eq!(99, sack.cumulative_tsn_ack);
    assert_eq!(vec![102], sack.duplicate_tsn);
    Ok(())
}

#[test]
fn a_tsn_received_three_times_is_listed_twice() -> Result<()> {
    let mut a = receiver();
    receive(&mut a, &[data(100), data(100), data(100)])?;

    assert_eq!(vec![100, 100], a.create_selective_ack_chunk().duplicate_tsn);
    Ok(())
}

#[test]
fn a_repeat_bundled_with_new_data_is_reported_and_the_new_data_kept() -> Result<()> {
    let mut a = receiver();
    receive(&mut a, &[data(100)])?;
    let _ = a.create_selective_ack_chunk();

    receive(&mut a, &[data(100), data(101)])?;

    let sack = a.create_selective_ack_chunk();
    assert_eq!(101, sack.cumulative_tsn_ack);
    assert_eq!(vec![100], sack.duplicate_tsn);
    Ok(())
}

#[test]
fn at_most_twenty_repeats_are_kept_between_sacks() -> Result<()> {
    let mut a = receiver();
    receive(&mut a, &[data(100)])?;
    let _ = a.create_selective_ack_chunk();

    receive(&mut a, &vec![data(100); 30])?;

    assert_eq!(vec![100; 20], a.create_selective_ack_chunk().duplicate_tsn);
    Ok(())
}

#[test]
fn a_sack_fits_one_packet_keeping_the_gaps_nearest_the_cumulative_tsn() -> Result<()> {
    let mut a = receiver();
    a.max_receive_buffer_size = 1024 * 1024;
    let every_other: Vec<_> = (0..2000).map(|i| data(101 + 2 * i)).collect();
    let repeat = data(101);
    receive(&mut a, &every_other)?;
    receive(&mut a, &[repeat])?;

    let sack = a.create_selective_ack_chunk();
    let packet = a.marshal_control_chunk(&sack)?;

    assert!(
        packet.len() <= a.mtu as usize,
        "{} bytes against an MTU of {}",
        packet.len(),
        a.mtu
    );
    assert_eq!(
        2, sack.gap_ack_blocks[0].start,
        "the first gap starts just past 99"
    );
    assert!(
        sack.duplicate_tsn.is_empty(),
        "the gaps fill the packet before the repeats"
    );
    Ok(())
}

#[test]
fn repeats_fill_the_room_the_gaps_leave() -> Result<()> {
    let mut a = receiver();
    receive(&mut a, &[data(102), data(104)])?;
    let _ = a.create_selective_ack_chunk();

    receive(&mut a, &[data(102), data(104)])?;

    let sack = a.create_selective_ack_chunk();
    assert_eq!(2, sack.gap_ack_blocks.len());
    assert_eq!(vec![102, 104], sack.duplicate_tsn);
    Ok(())
}
