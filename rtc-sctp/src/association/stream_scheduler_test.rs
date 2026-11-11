use super::*;
use crate::StreamScheduler;

fn sender(scheduler: StreamScheduler) -> Association {
    let mut a = create_association(TransportConfig::default().with_stream_scheduler(scheduler));
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.cwnd = 1024 * 1024;
    a.rwnd = 1024 * 1024;
    a
}

/// Writes four 16 KiB messages on stream 1, then four 4 KiB messages on stream 2, and returns
/// the stream of each DATA chunk in the order it left.
fn send_order(a: &mut Association) -> Result<Vec<(u16, usize)>> {
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?;
    a.open_stream(2, ppi)?;
    for _ in 0..4 {
        a.stream(1)?
            .write_sctp(now, &Bytes::from(vec![1; 16 * 1024]), ppi)?;
    }
    for _ in 0..4 {
        a.stream(2)?
            .write_sctp(now, &Bytes::from(vec![2; 4 * 1024]), ppi)?;
    }
    Ok(transmitted_data(&a.gather_outbound(now).0)
        .iter()
        .map(|c| (c.stream_identifier, c.user_data.len()))
        .collect())
}

fn stream_one_bytes_before_stream_two_finishes(order: &[(u16, usize)]) -> usize {
    let last_of_two = order.iter().rposition(|(s, _)| *s == 2).unwrap();
    order[..last_of_two]
        .iter()
        .filter(|(s, _)| *s == 1)
        .map(|(_, len)| len)
        .sum()
}

#[test]
fn weighted_fair_queueing_lets_a_small_stream_through_a_bulk_one() -> Result<()> {
    let mut a = sender(StreamScheduler::WeightedFairQueueing);
    let order = send_order(&mut a)?;

    assert_eq!(80 * 1024, order.iter().map(|(_, len)| len).sum::<usize>());
    assert!(
        stream_one_bytes_before_stream_two_finishes(&order) <= 16 * 1024,
        "stream 2's 16 KiB shares the line with stream 1's 64 KiB"
    );
    Ok(())
}

#[test]
fn first_come_first_served_sends_the_bulk_stream_first() -> Result<()> {
    let mut a = sender(StreamScheduler::FirstComeFirstServed);
    let order = send_order(&mut a)?;

    assert_eq!(
        64 * 1024,
        stream_one_bytes_before_stream_two_finishes(&order)
    );
    Ok(())
}

#[test]
fn a_higher_priority_stream_gets_the_larger_share() -> Result<()> {
    let mut a = sender(StreamScheduler::WeightedFairQueueing);
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.set_priority(1024)?;
    a.open_stream(2, ppi)?;
    for _ in 0..64 {
        a.stream(1)?
            .write_sctp(now, &Bytes::from(vec![1; 1024]), ppi)?;
        a.stream(2)?
            .write_sctp(now, &Bytes::from(vec![2; 1024]), ppi)?;
    }
    a.cwnd = 40 * 1024;

    let sent = transmitted_data(&a.gather_outbound(now).0);
    let from_one = sent.iter().filter(|c| c.stream_identifier == 1).count();
    let from_two = sent.iter().filter(|c| c.stream_identifier == 2).count();
    assert!(
        from_one.abs_diff(4 * from_two) <= 4,
        "1024 against 256: {from_one} and {from_two} messages"
    );
    Ok(())
}
