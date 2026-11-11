use super::*;

fn reset_requests(packets: &[Bytes]) -> Vec<ParamOutgoingResetRequest> {
    packets
        .iter()
        .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
        .filter_map(|c| {
            c.as_any()
                .downcast_ref::<ChunkReconfig>()
                .and_then(|c| c.param_a.as_ref())
                .and_then(|p| p.as_any().downcast_ref::<ParamOutgoingResetRequest>())
                .cloned()
        })
        .collect()
}

fn receive_reset_response(
    a: &mut Association,
    now: Instant,
    request: &ParamOutgoingResetRequest,
    result: ReconfigResult,
) -> Result<()> {
    a.handle_reconfig(
        now,
        &ChunkReconfig {
            param_a: Some(Box::new(ParamReconfigResponse {
                reconfig_response_sequence_number: request.reconfig_request_sequence_number,
                result,
            })),
            ..Default::default()
        },
    )?;
    Ok(())
}

fn reset_config(request: &ParamOutgoingResetRequest) -> ChunkReconfig {
    ChunkReconfig {
        param_a: Some(Box::new(request.clone())),
        ..Default::default()
    }
}

#[test]
fn test_unstarted_timed_message_expires_without_tsn_or_ssn_gap() -> Result<()> {
    for unordered in [false, true] {
        for size in [1, 4000] {
            for delta in [Duration::ZERO, Duration::from_nanos(1)] {
                let mut a = timed_test_association();
                let now = Instant::now();
                let ppi = PayloadProtocolIdentifier::Binary;
                let first_tsn = a.my_next_tsn;
                let mut stream = a.open_stream(1, ppi)?;
                stream.set_reliability_params(unordered, ReliabilityType::Timed, 100)?;
                stream.write_sctp(now, &Bytes::from(vec![1; size]), ppi)?;
                let deadline = now + Duration::from_millis(100) + delta;
                assert!(a.gather_outbound(deadline).0.is_empty());
                assert_eq!(first_tsn, a.my_next_tsn);
                assert!(a.pending_queue.is_empty());
                assert!(a.inflight_queue.is_empty());
                assert_eq!(0, a.stream(1)?.buffered_amount()?);
                let mut stream = a.stream(1)?;
                stream.set_reliability_params(false, ReliabilityType::Reliable, 0)?;
                stream.write_sctp(deadline, &Bytes::from_static(b"next"), ppi)?;
                let data = transmitted_data(&a.gather_outbound(deadline).0);
                assert_eq!(1, data.len());
                assert_eq!(first_tsn, data[0].tsn);
                assert_eq!(0, data[0].stream_sequence_number);
                let mut receiver = timed_test_association();
                receiver.peer_last_tsn = first_tsn.wrapping_sub(1);
                receiver.handle_data(&data[0])?;
                assert!(receiver.stream(1)?.read_sctp()?.is_some());
            }
        }
    }
    Ok(())
}

#[test]
fn test_timed_message_can_first_send_just_before_its_deadline() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
    stream.write_sctp(now, &Bytes::from_static(b"within lifetime"), ppi)?;
    let before = now + Duration::from_millis(100) - Duration::from_nanos(1);
    assert_eq!(1, transmitted_data(&a.gather_outbound(before).0).len());
    Ok(())
}

#[test]
fn test_reset_result_renumbers_only_released_messages() -> Result<()> {
    for result in [
        ReconfigResult::SuccessPerformed,
        ReconfigResult::SuccessNop,
        ReconfigResult::Denied,
    ] {
        for initial_ssn in [3u16, u16::MAX] {
            for queued in [false, true] {
                let mut a = timed_test_association();
                a.cwnd = 65536;
                let now = Instant::now();
                let ppi = PayloadProtocolIdentifier::Binary;
                a.open_stream(1, ppi)?;
                a.transmit_streams.entry(1).or_default().next_ssn = initial_ssn;
                a.stream(1)?
                    .write_sctp(now, &Bytes::from_static(b"old"), ppi)?;
                let old_tsn = transmitted_data(&a.gather_outbound(now).0)[0].tsn;
                a.stream(1)?.stop(now)?;
                if queued {
                    a.stream(1)?
                        .write_sctp(now, &Bytes::from(vec![7; 4000]), ppi)?;
                    a.stream(1)?
                        .write_sctp(now, &Bytes::from_static(b"next"), ppi)?;
                }
                let packets = a.gather_outbound(now).0;
                assert_eq!(0, data_chunks(&packets));
                let reset = reset_requests(&packets).remove(0);
                receive_reset_response(&mut a, now, &reset, ReconfigResult::InProgress)?;
                assert_eq!(0, data_chunks(&a.gather_outbound(now).0));
                receive_reset_response(&mut a, now, &reset, result)?;
                let first_ssn = if result == ReconfigResult::Denied {
                    initial_ssn.wrapping_add(1)
                } else {
                    0
                };
                let chunks = transmitted_data(&a.gather_outbound(now).0);
                if queued {
                    assert_eq!(4, chunks.len());
                    assert!(
                        chunks[..3]
                            .iter()
                            .all(|c| c.stream_sequence_number == first_ssn)
                    );
                    assert_eq!(first_ssn.wrapping_add(1), chunks[3].stream_sequence_number);
                } else {
                    assert!(chunks.is_empty());
                }
                let next_ssn = first_ssn.wrapping_add(if queued { 2 } else { 0 });
                a.stream(1)?
                    .write_sctp(now, &Bytes::from_static(b"later"), ppi)?;
                let chunks = transmitted_data(&a.gather_outbound(now).0);
                assert_eq!(1, chunks.len());
                assert_eq!(next_ssn, chunks[0].stream_sequence_number);
                // A duplicate result cannot restart the SSN counter a second time.
                receive_reset_response(&mut a, now, &reset, result)?;
                a.stream(1)?
                    .write_sctp(now, &Bytes::from_static(b"after duplicate"), ppi)?;
                let chunks = transmitted_data(&a.gather_outbound(now).0);
                assert_eq!(next_ssn.wrapping_add(1), chunks[0].stream_sequence_number);
                a.handle_sack(
                    &ChunkSelectiveAck {
                        cumulative_tsn_ack: old_tsn,
                        advertised_receiver_window_credit: 65536,
                        ..Default::default()
                    },
                    now,
                )?;
                assert!(a.confirmed_reset_tsns.is_empty());
                assert!(a.reset_tsn_ack_queue.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn test_denied_reset_preserves_pending_forward_ssn() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
    stream.write_sctp(now, &Bytes::from_static(b"lost"), ppi)?;
    a.gather_outbound(now);
    let at = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(at);
    a.gather_outbound(at);
    a.stream(1)?.stop(at)?;
    let reset = reset_requests(&a.gather_outbound(at).0).remove(0);
    let forward = a.create_forward_tsn();
    assert_eq!(1, forward.streams.len());
    receive_reset_response(&mut a, at, &reset, ReconfigResult::Denied)?;
    assert_eq!(
        a.marshal_control_chunk(&forward)?,
        a.marshal_control_chunk(&a.create_forward_tsn())?
    );
    assert!(a.confirmed_reset_tsns.is_empty());
    Ok(())
}

#[test]
fn test_serialized_resets_and_reused_sid_do_not_block_other_streams() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?.close(now)?;
        let first = reset_requests(&a.gather_outbound(now).0).remove(0);
        receive_reset_response(&mut a, now, &first, ReconfigResult::InProgress)?;
        a.open_stream(2, ppi)?;
        a.handle_reconfig(
            now,
            &ChunkReconfig {
                param_a: Some(Box::new(ParamOutgoingResetRequest {
                    reconfig_request_sequence_number: 1,
                    reconfig_response_sequence_number: first
                        .reconfig_request_sequence_number
                        .wrapping_sub(1),
                    sender_last_tsn: a.peer_last_tsn,
                    stream_identifiers: vec![2],
                })),
                ..Default::default()
            },
        )?;
        let mut reused = a.open_stream(2, ppi)?;
        reused.set_reliability_params(unordered, ReliabilityType::Reliable, 0)?;
        reused.write_sctp(now, &Bytes::from_static(b"new"), ppi)?;
        a.open_stream(3, ppi)?
            .write_sctp(now, &Bytes::from_static(b"other"), ppi)?;
        let packets = a.gather_outbound(now).0;
        assert!(reset_requests(&packets).is_empty());
        let data: Vec<_> = packets
            .iter()
            .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
            .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>().cloned())
            .collect();
        assert_eq!(1, data.len());
        assert_eq!(3, data[0].stream_identifier);
        assert_eq!(3, a.stream(2)?.buffered_amount()?);
        receive_reset_response(&mut a, now, &first, ReconfigResult::SuccessPerformed)?;
        let packets = a.gather_outbound(now).0;
        let next = reset_requests(&packets).remove(0);
        assert_eq!(vec![2], next.stream_identifiers);
        assert_eq!(data[0].tsn, next.sender_last_tsn);
        assert_eq!(0, data_chunks(&packets));
        assert_eq!(0, data_chunks(&a.gather_outbound(now).0));
        receive_reset_response(&mut a, now, &next, ReconfigResult::SuccessPerformed)?;
        let (data, _) = a.pop_pending_data_chunks_to_send(now);
        assert_eq!(1, data.len());
        assert_eq!(2, data[0].stream_identifier);
        assert!(sna32gt(data[0].tsn, next.sender_last_tsn));
    }
    Ok(())
}

#[test]
fn test_in_progress_reset_retries_without_exhausting_error_limit() -> Result<()> {
    let mut a = timed_test_association();
    let mut now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.close(now)?;
    let first = reset_requests(&a.gather_outbound(now).0).remove(0);
    a.open_stream(2, ppi)?.close(now)?;
    receive_reset_response(&mut a, now, &first, ReconfigResult::InProgress)?;
    for _ in 0..8 {
        now = a.timers.get(Timer::Reconfig).unwrap();
        a.handle_timeout(now);
        let requests = reset_requests(&a.gather_outbound(now).0);
        assert_eq!(vec![first.clone()], requests);
        assert_eq!(AssociationState::Established, a.state());
    }
    receive_reset_response(&mut a, now, &first, ReconfigResult::SuccessPerformed)?;
    let next = reset_requests(&a.gather_outbound(now).0).remove(0);
    assert_eq!(vec![2], next.stream_identifiers);
    // The next request has a fresh interval and its own error budget.
    assert_eq!(
        Some(now + Duration::from_secs(1)),
        a.timers.get(Timer::Reconfig)
    );
    Ok(())
}

#[test]
fn test_implicit_reset_ack_holds_next_request_until_result() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.close(now)?;
    let first = reset_requests(&a.gather_outbound(now).0).remove(0);
    a.open_stream(2, ppi)?.close(now)?;
    let implicit = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: first.reconfig_request_sequence_number,
        sender_last_tsn: a.peer_last_tsn.wrapping_add(1),
        stream_identifiers: vec![1],
    };
    a.handle_reconfig(now, &reset_config(&implicit))?;
    assert!(
        a.timers.get(Timer::Reconfig).is_none(),
        "E1 stops the timer"
    );
    assert!(a.streams.contains_key(&1), "receipt cannot finish RX reset");
    assert!(
        reset_requests(&a.gather_outbound(now).0).is_empty(),
        "N+1 waits for N's result"
    );
    receive_reset_response(&mut a, now, &first, ReconfigResult::SuccessPerformed)?;
    assert!(
        reset_requests(&a.gather_outbound(now).0).is_empty(),
        "H1 ignores result without timer"
    );
    let at = a.poll_timeout().unwrap();
    a.handle_timeout(at);
    assert_eq!(
        vec![first.clone()],
        reset_requests(&a.gather_outbound(at).0)
    );
    receive_reset_response(&mut a, at, &first, ReconfigResult::SuccessPerformed)?;
    let next = reset_requests(&a.gather_outbound(at).0).remove(0);
    assert_eq!(vec![2], next.stream_identifiers);
    let timer = a.timers.get(Timer::Reconfig);
    receive_reset_response(&mut a, at, &first, ReconfigResult::Denied)?;
    assert_eq!(timer, a.timers.get(Timer::Reconfig));
    assert_eq!(next, a.outgoing_reset.as_ref().unwrap().request);
    Ok(())
}

#[test]
fn test_same_reset_query_preserves_gates_timers_and_late_results() -> Result<()> {
    let mut a = timed_test_association();
    let mut now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.stop(now)?;
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"held until reset is known"), ppi)?;
    let original = reset_requests(&a.gather_outbound(now).0).remove(0);
    let implicit = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: original.reconfig_request_sequence_number,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![99],
    };
    a.handle_reconfig(now, &reset_config(&implicit))?;
    a.open_stream(2, ppi)?.close(now)?;
    a.open_stream(3, ppi)?
        .write_sctp(now, &Bytes::from_static(b"unaffected DATA"), ppi)?;
    let packets = a.gather_outbound(now).0;
    assert!(reset_requests(&packets).is_empty());
    let other = transmitted_data(&packets);
    assert_eq!(1, other.len());
    assert_eq!(3, other[0].stream_identifier);
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: other[0].tsn,
            advertised_receiver_window_credit: 65536,
            ..Default::default()
        },
        now,
    )?;
    for _ in 0..3 {
        now = a.poll_timeout().unwrap();
        a.handle_timeout(now);
        let packets = a.gather_outbound(now).0;
        assert_eq!(
            vec![original.clone()],
            reset_requests(&packets),
            "lost query repeats the identical request"
        );
        assert!(transmitted_data(&packets).is_empty());
    }
    receive_reset_response(&mut a, now, &original, ReconfigResult::SuccessPerformed)?;
    let mut packets = a.gather_outbound(now).0;
    packets.extend(a.gather_outbound(now).0);
    let released = transmitted_data(&packets);
    assert_eq!(1, released.len());
    assert_eq!(0, released[0].stream_sequence_number);
    let next = reset_requests(&packets).remove(0);
    assert_eq!(
        original.reconfig_request_sequence_number.wrapping_add(1),
        next.reconfig_request_sequence_number
    );
    let timer = a.timers.get(Timer::Reconfig);
    receive_reset_response(
        &mut a,
        now,
        &original,
        ReconfigResult::ErrorBadSequenceNumber,
    )?;
    assert_eq!(timer, a.timers.get(Timer::Reconfig));
    assert!(!a.is_closed());
    Ok(())
}

#[test]
fn test_reset_bounds_old_forward_tsn_even_with_other_stream_abandonment() -> Result<()> {
    for state in [
        AssociationState::Established,
        AssociationState::ShutdownPending,
        AssociationState::ShutdownSent,
        AssociationState::ShutdownReceived,
    ] {
        for implicit_ack in [false, true] {
            let mut a = timed_test_association();
            let now = Instant::now();
            let ppi = PayloadProtocolIdentifier::Binary;
            a.open_stream(1, ppi)?
                .set_reliability_params(false, ReliabilityType::Timed, 100)?;
            a.stream(1)?
                .write_sctp(now, &Bytes::from_static(b"old SID"), ppi)?;
            a.stream(1)?.close(now)?;
            let reset = reset_requests(&a.gather_outbound(now).0).remove(0);
            a.open_stream(2, ppi)?
                .set_reliability_params(false, ReliabilityType::Timed, 100)?;
            a.stream(2)?
                .write_sctp(now, &Bytes::from_static(b"later TSN on another SID"), ppi)?;
            a.gather_outbound(now);
            if implicit_ack {
                a.handle_reconfig(
                    now,
                    &reset_config(&ParamOutgoingResetRequest {
                        reconfig_request_sequence_number: 1,
                        reconfig_response_sequence_number: reset.reconfig_request_sequence_number,
                        sender_last_tsn: a.peer_last_tsn,
                        stream_identifiers: vec![99],
                    }),
                )?;
            }
            a.set_state(state);
            let at = a.timers.get(Timer::T3RTX).unwrap();
            a.handle_timeout(at);
            assert_eq!(
                vec![reset.clone()],
                reset_requests(&a.gather_outbound(at).0),
                "reset recovery must remain available: {state:?}, implicit_ack={implicit_ack}"
            );
            let old_forward = a.create_forward_tsn();
            assert_eq!(reset.sender_last_tsn, old_forward.new_cumulative_tsn);
            assert_eq!(
                vec![(1, 0)],
                old_forward
                    .streams
                    .iter()
                    .map(|s| (s.identifier, s.sequence))
                    .collect::<Vec<_>>()
            );
            receive_reset_response(&mut a, at, &reset, ReconfigResult::SuccessPerformed)?;
            let next_forward = a.create_forward_tsn();
            assert_eq!(
                reset.sender_last_tsn.wrapping_add(1),
                next_forward.new_cumulative_tsn
            );
            assert_eq!(
                vec![(2, 0)],
                next_forward
                    .streams
                    .iter()
                    .map(|s| (s.identifier, s.sequence))
                    .collect::<Vec<_>>()
            );
            // Any delayed old control is at/below the peer's performed-reset TSN and
            // therefore ignored even if new DATA of the reused SID was reordered first.
        }
    }
    Ok(())
}

#[test]
fn test_many_resets_respect_mtu_and_rsn_wrap() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    a.mtu = 96;
    a.my_next_rsn = u32::MAX;
    for sid in 0..100 {
        a.open_stream(sid, PayloadProtocolIdentifier::Binary)?
            .close(now)?;
    }
    let mut reset_sids = vec![];
    let mut next_sequence = u32::MAX;
    for _ in 0..4 {
        let packets = a.gather_outbound(now).0;
        assert!(packets.iter().all(|p| p.len() <= a.mtu as usize));
        let requests = reset_requests(&packets);
        assert_eq!(1, requests.len());
        assert_eq!(next_sequence, requests[0].reconfig_request_sequence_number);
        next_sequence = next_sequence.wrapping_add(1);
        reset_sids.extend(&requests[0].stream_identifiers);
        assert!(reset_requests(&a.gather_outbound(now).0).is_empty());
        receive_reset_response(&mut a, now, &requests[0], ReconfigResult::SuccessPerformed)?;
    }
    reset_sids.sort_unstable();
    assert_eq!((0..100u16).collect::<Vec<_>>(), reset_sids);
    assert!(a.pending_queue.is_empty());
    assert!(a.outgoing_reset.is_none());
    Ok(())
}

#[test]
fn test_reset_retry_exhaustion_closes_association_and_notifies_streams() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.close(now)?;
    a.gather_outbound(now);
    a.open_stream(2, ppi)?.close(now)?;
    for _ in 0..6 {
        let at = a.timers.get(Timer::Reconfig).unwrap();
        a.handle_timeout(at);
        a.gather_outbound(at);
    }
    assert!(a.is_closed());
    assert!(a.is_idle());
    assert!(a.outgoing_reset.is_none());
    let mut closed = vec![];
    while let Some(event) = a.poll() {
        if let Event::AssociationLost { id, reason } = event {
            assert_eq!(AssociationError::TimedOut, reason);
            closed.push(id);
        }
    }
    closed.sort_unstable();
    assert_eq!(vec![1, 2], closed);
    Ok(())
}

#[test]
fn test_unknown_reset_result_closes_instead_of_guessing_ssns() -> Result<()> {
    for result in [
        ReconfigResult::ErrorBadSequenceNumber,
        ReconfigResult::Unknown,
    ] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?.stop(now)?;
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"unknown SSN"), ppi)?;
        let first = reset_requests(&a.gather_outbound(now).0).remove(0);
        while a.poll().is_some() {}
        receive_reset_response(&mut a, now, &first, result)?;
        assert!(a.is_closed());
        assert!(a.poll_timeout().is_none());
        assert!(a.outgoing_reset.is_none());
        let packets = a.gather_outbound(now).0;
        assert!(transmitted_data(&packets).is_empty());
        assert!(packets.iter().any(|p| {
            Packet::unmarshal(p)
                .unwrap()
                .chunks
                .iter()
                .any(|c| c.as_any().is::<ChunkAbort>())
        }));
        assert!(matches!(
            a.poll(),
            Some(Event::AssociationLost {
                id: 1,
                reason: AssociationError::TransportError
            })
        ));
    }
    Ok(())
}

#[test]
fn test_write_after_stop_uses_reset_ssn() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = sender.my_next_tsn - 1;
    receiver.peer_last_rsn = sender.my_next_rsn.wrapping_sub(1);
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    sender
        .open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from_static(b"old"), ppi)?;
    for d in transmitted_data(&sender.gather_outbound(now).0) {
        receiver.handle_data(&d)?;
    }
    assert!(receiver.stream(1)?.read_sctp()?.is_some());
    sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
    sender.stream(1)?.stop(now)?;
    assert!(sender.stream(1)?.is_writable());
    sender
        .stream(1)?
        .write_sctp(now, &Bytes::from_static(b"new"), ppi)?;
    let mut payloads = Vec::new();
    for raw in sender.gather_outbound(now).0 {
        for c in Packet::unmarshal(&raw)?.chunks {
            if let Some(d) = c.as_any().downcast_ref::<ChunkPayloadData>() {
                receiver.handle_data(d)?;
                if let Some(msg) = receiver.stream(1)?.read_sctp()? {
                    payloads.push(msg);
                }
            } else if let Some(r) = c.as_any().downcast_ref::<ChunkReconfig>() {
                for response in receiver.handle_reconfig(now, r)? {
                    for c in response.chunks {
                        if let Some(r) = c.as_any().downcast_ref::<ChunkReconfig>() {
                            sender.handle_reconfig(now, r)?;
                        }
                    }
                }
            }
        }
    }
    for d in transmitted_data(&sender.gather_outbound(now).0) {
        receiver.handle_data(&d)?;
        if let Some(msg) = receiver.stream(1)?.read_sctp()? {
            payloads.push(msg);
        }
    }
    assert_eq!(
        1,
        payloads.len(),
        "queued writes resume with the old SSN after successful reset and remain unreadable"
    );
    Ok(())
}

#[test]
fn test_unsupported_reset_leaves_both_api_halves_usable() -> Result<()> {
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut a = timed_test_association();
    a.peer_supports_reconfig = false;
    let mut stream = a.open_stream(1, ppi)?;
    assert!(stream.close(now).is_err());
    assert!(stream.is_readable());
    assert!(stream.is_writable());
    stream.write_sctp(now, &Bytes::from_static(b"still usable"), ppi)?;
    let packets = a.gather_outbound(now).0;
    assert!(reset_requests(&packets).is_empty());
    assert_eq!(transmitted_data(&packets).len(), 1);
    assert!(a.timers.get(Timer::Reconfig).is_none());
    Ok(())
}

#[test]
fn test_incoming_reset_without_peer_advertisement_gets_response_only() -> Result<()> {
    let now = Instant::now();
    let mut a = timed_test_association();
    a.peer_supports_reconfig = false;
    a.open_stream(1, PayloadProtocolIdentifier::Binary)?;
    let request = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: a.my_next_rsn.wrapping_sub(1),
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1],
    };
    assert_eq!(
        reconfig_results(&a.handle_reconfig(now, &reset_config(&request))?),
        [ReconfigResult::SuccessPerformed],
    );
    assert!(reset_requests(&a.gather_outbound(now).0).is_empty());
    assert!(a.timers.get(Timer::Reconfig).is_none());
    assert!(a.stream(1).is_err());
    Ok(())
}

fn reconfig_results(packets: &[Packet]) -> Vec<ReconfigResult> {
    packets
        .iter()
        .flat_map(|p| &p.chunks)
        .filter_map(|c| c.as_any().downcast_ref::<ChunkReconfig>())
        .flat_map(|c| c.param_a.iter().chain(c.param_b.iter()))
        .filter_map(|p| {
            p.as_any()
                .downcast_ref::<ParamReconfigResponse>()
                .map(|p| p.result)
        })
        .collect()
}

#[test]
fn test_pending_reset_can_contain_two_stream_generations() -> Result<()> {
    for old_len in [32, 4000] {
        for old_unordered in [false, true] {
            for new_unordered in [false, true] {
                for queued_new in [false, true] {
                    let mut sender = timed_test_association();
                    sender.cwnd = 65536;
                    let now = Instant::now();
                    let ppi = PayloadProtocolIdentifier::Binary;
                    let mut old = sender.open_stream(1, ppi)?;
                    old.set_reliability_params(old_unordered, ReliabilityType::Reliable, 0)?;
                    old.stop(now)?;
                    old.write_sctp(now, &Bytes::from(vec![7; old_len]), ppi)?;
                    let reset = reset_requests(&sender.gather_outbound(now).0).remove(0);
                    // The simultaneous peer reset predates receipt of ours.
                    sender.handle_reconfig(
                        now,
                        &ChunkReconfig {
                            param_a: Some(Box::new(ParamOutgoingResetRequest {
                                reconfig_request_sequence_number: 1,
                                reconfig_response_sequence_number: reset
                                    .reconfig_request_sequence_number
                                    .wrapping_sub(1),
                                sender_last_tsn: sender.peer_last_tsn,
                                stream_identifiers: vec![1],
                            })),
                            ..Default::default()
                        },
                    )?;
                    let mut new = sender.open_stream(1, ppi)?;
                    new.set_reliability_params(new_unordered, ReliabilityType::Reliable, 0)?;
                    if queued_new {
                        new.write_sctp(now, &Bytes::from_static(b"new generation"), ppi)?;
                    }
                    receive_reset_response(
                        &mut sender,
                        now,
                        &reset,
                        ReconfigResult::SuccessPerformed,
                    )?;
                    let mut sent = transmitted_data(&sender.gather_outbound(now).0);
                    sender.stream(1)?.write_sctp(
                        now,
                        &Bytes::from_static(b"later new generation"),
                        ppi,
                    )?;
                    sent.extend(transmitted_data(&sender.gather_outbound(now).0));
                    let mut next_ssn = 0u16;
                    for chunk in &sent {
                        if !chunk.unordered {
                            assert_eq!(next_ssn, chunk.stream_sequence_number);
                            if chunk.ending_fragment {
                                next_ssn += 1;
                            }
                        }
                    }
                    assert_eq!(next_ssn, sender.transmit_streams[&1].next_ssn);
                    let mut receiver = timed_test_association();
                    receiver.peer_last_tsn = sent[0].tsn - 1;
                    for chunk in &sent {
                        receiver.handle_data(chunk)?;
                    }
                    let mut received = 0;
                    while receiver.stream(1)?.read_sctp()?.is_some() {
                        received += 1;
                    }
                    assert_eq!(if queued_new { 3 } else { 2 }, received);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_ready_reset_preserves_unrelated_fragmented_data_and_last_tsn() -> Result<()> {
    fn data(packets: &[Bytes]) -> Vec<ChunkPayloadData> {
        packets
            .iter()
            .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
            .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>().cloned())
            .collect()
    }
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.cwnd = a.mtu;
        a.open_stream(1, ppi)?;
        let payload = Bytes::from(vec![7; 4000]);
        let mut s = a.open_stream(2, ppi)?;
        s.set_reliability_params(unordered, ReliabilityType::Reliable, 0)?;
        s.write_sctp(now, &payload, ppi)?;
        let mut chunks = data(&a.gather_outbound(now).0);
        assert_eq!(1, chunks.len());
        let first_tsn = chunks[0].tsn;
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: first_tsn,
                advertised_receiver_window_credit: 0,
                ..Default::default()
            },
            now,
        )?;
        // Reset 2 must wait for its tail; the later reset 1 is already ready.
        for (index, id) in [2, 1].into_iter().enumerate() {
            a.handle_reconfig(
                now,
                &ChunkReconfig {
                    param_a: Some(Box::new(ParamOutgoingResetRequest {
                        reconfig_request_sequence_number: index as u32 + 1,
                        sender_last_tsn: a.peer_last_tsn,
                        stream_identifiers: vec![id],
                        ..Default::default()
                    })),
                    ..Default::default()
                },
            )?;
        }
        let packets = a.gather_outbound(now).0;
        assert_eq!(
            0,
            data_chunks(&packets),
            "ready reset must precede any new rwnd probe"
        );
        let resets = reset_requests(&packets);
        assert_eq!(1, resets.len());
        assert_eq!(vec![1], resets[0].stream_identifiers);
        assert_eq!(first_tsn, resets[0].sender_last_tsn);
        assert!(a.timers.get(Timer::Reconfig).is_some());
        a.handle_reconfig(
            now,
            &ChunkReconfig {
                param_a: Some(Box::new(ParamReconfigResponse {
                    reconfig_response_sequence_number: resets[0].reconfig_request_sequence_number,
                    result: ReconfigResult::SuccessPerformed,
                })),
                ..Default::default()
            },
        )?;
        // Restoring credit must continue the selected message with every byte intact.
        let mut reset_two = None;
        for _ in 0..10 {
            a.handle_sack(
                &ChunkSelectiveAck {
                    cumulative_tsn_ack: chunks.last().unwrap().tsn,
                    advertised_receiver_window_credit: 65536,
                    ..Default::default()
                },
                now,
            )?;
            let packets = a.gather_outbound(now).0;
            chunks.extend(data(&packets));
            if let Some(reset) = reset_requests(&packets).pop() {
                reset_two = Some(reset);
                break;
            }
        }
        let reset_two = reset_two.expect("reset 2 must follow its own DATA");
        assert_eq!(vec![2], reset_two.stream_identifiers);
        assert_eq!(chunks.last().unwrap().tsn, reset_two.sender_last_tsn);
        assert!(chunks[0].beginning_fragment);
        assert!(chunks.last().unwrap().ending_fragment);
        assert!(chunks.iter().all(|c| c.unordered == unordered));
        let received: Vec<u8> = chunks
            .iter()
            .flat_map(|c| c.user_data.iter().copied())
            .collect();
        assert_eq!(payload.as_ref(), received.as_slice());
        assert!(a.pending_queue.is_empty());
        assert_eq!(0, a.pending_queue.get_num_bytes());
    }
    Ok(())
}

#[test]
fn test_lost_result_after_implicit_ack_is_retried_without_resetting_reused_sid() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = sender.my_next_tsn - 1;
    receiver.peer_last_rsn = sender.my_next_rsn.wrapping_sub(1);
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    sender.open_stream(1, ppi)?.stop(now)?;
    sender
        .stream(1)?
        .write_sctp(now, &Bytes::from_static(b"after reset"), ppi)?;
    let request = reset_requests(&sender.gather_outbound(now).0).remove(0);
    let config = ChunkReconfig {
        param_a: Some(Box::new(request.clone())),
        ..Default::default()
    };
    // Lose the explicit result; the unrelated request acknowledges only receipt.
    receiver.handle_reconfig(now, &config)?;
    sender.handle_reconfig(
        now,
        &ChunkReconfig {
            param_a: Some(Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                reconfig_response_sequence_number: request.reconfig_request_sequence_number,
                sender_last_tsn: sender.peer_last_tsn,
                stream_identifiers: vec![2],
            })),
            ..Default::default()
        },
    )?;
    assert!(transmitted_data(&sender.gather_outbound(now).0).is_empty());
    assert!(sender.timers.get(Timer::Reconfig).is_none());
    // The peer may already have a new stream when we query the old result.
    receiver
        .open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from_static(b"new peer stream"), ppi)?;
    let at = sender
        .poll_timeout()
        .expect("a missing result needs recovery");
    sender.handle_timeout(at);
    let retried = reset_requests(&sender.gather_outbound(at).0);
    assert_eq!(vec![request], retried);
    assert!(sender.timers.get(Timer::Reconfig).is_some());
    for response in receiver.handle_reconfig(at, &config)? {
        for c in response.chunks {
            if let Some(config) = c.as_any().downcast_ref::<ChunkReconfig>() {
                sender.handle_reconfig(at, config)?;
            }
        }
    }
    assert!(
        receiver.stream(1).is_ok(),
        "a result query must not reset a reused stream"
    );
    let sent = transmitted_data(&sender.gather_outbound(at).0);
    assert_eq!(1, sent.len());
    assert_eq!(0, sent[0].stream_sequence_number);
    receiver.handle_data(&sent[0])?;
    assert!(receiver.stream(1)?.read_sctp()?.is_some());
    assert!(sender.outgoing_reset.is_none());
    Ok(())
}

#[test]
fn test_completed_reset_replays_do_not_modify_reused_streams() -> Result<()> {
    for initial_rsn in [10u32, u32::MAX - 1] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        let request = |sequence, streams| ChunkReconfig {
            param_a: Some(Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: sequence,
                sender_last_tsn: 0,
                stream_identifiers: streams,
                ..Default::default()
            })),
            ..Default::default()
        };
        a.peer_last_tsn = 0;
        a.peer_last_rsn = initial_rsn.wrapping_sub(1);
        a.open_stream(1, ppi)?;
        a.open_stream(2, ppi)?;
        let original = request(initial_rsn, vec![1, 2]);
        a.handle_reconfig(now, &original)?;
        a.open_stream(1, ppi)?;
        a.open_stream(2, ppi)?;
        a.handle_reconfig(now, &request(initial_rsn.wrapping_add(1), vec![2]))?;
        a.open_stream(2, ppi)?;
        for expected in [
            ReconfigResult::SuccessPerformed,
            ReconfigResult::ErrorBadSequenceNumber,
        ] {
            let generations = (a.streams[&1].generation, a.streams[&2].generation);
            let reply = a.handle_reconfig(now, &original)?;
            let results: Vec<_> = reply
                .into_iter()
                .flat_map(|p| p.chunks)
                .filter_map(|c| {
                    c.as_any()
                        .downcast_ref::<ChunkReconfig>()
                        .and_then(|r| r.param_a.as_ref())
                        .and_then(|p| p.as_any().downcast_ref::<ParamReconfigResponse>())
                        .map(|r| r.result)
                })
                .collect();
            assert_eq!(vec![expected], results);
            assert_eq!(
                generations,
                (a.streams[&1].generation, a.streams[&2].generation)
            );
            assert!(a.reconfig_requests.is_empty());
            if expected == ReconfigResult::SuccessPerformed {
                a.handle_reconfig(now, &request(initial_rsn.wrapping_add(2), vec![1]))?;
                a.open_stream(1, ppi)?;
            }
        }
        for offset in 3..90 {
            let sequence = initial_rsn.wrapping_add(offset);
            a.handle_reconfig(now, &request(sequence, vec![1]))?;
        }
        assert_eq!(
            2,
            a.completed_resets.len(),
            "history is bounded independently of SID count"
        );
    }
    Ok(())
}

#[test]
fn test_newer_partial_reset_must_not_cancel_deferred_stream() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?;
    a.open_stream(2, ppi)?;
    let before_reset = ChunkPayloadData {
        tsn: a.peer_last_tsn + 1,
        stream_identifier: 2,
        stream_sequence_number: 0,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: ppi,
        user_data: Bytes::from_static(b"application has not read this yet"),
        ..Default::default()
    };
    a.handle_data(&before_reset)?;
    let first = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1, 2],
        ..Default::default()
    };
    a.handle_reconfig(now, &reset_config(&first))?;
    assert!(a.stream(1).is_err());
    assert!(a.reconfig_requests.contains_key(&1));
    // Our reciprocal request for the already-drained SID 1 implicitly ACKs
    // receipt of the whole request, so the peer's request timer is stopped.
    let reciprocal = reset_requests(&a.gather_outbound(now).0).remove(0);
    assert_eq!(1, reciprocal.reconfig_response_sequence_number);
    // The peer may now send another request for SID 1 while SID 2 still
    // waits for the application to drain its previous incarnation.
    let newer = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 2,
        reconfig_response_sequence_number: reciprocal.reconfig_request_sequence_number,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1],
    };
    a.handle_reconfig(now, &reset_config(&newer))?;
    a.open_stream(1, ppi)?;
    let new_generation = a.streams[&1].generation;
    // Retransmitting N must keep its completed SID 1 out of the remaining work.
    let repeated = a.handle_reconfig(now, &reset_config(&first))?;
    assert_eq!(
        vec![ReconfigResult::InProgress],
        reconfig_results(&repeated)
    );
    assert_eq!(vec![2], a.reconfig_requests[&1].remaining);
    assert_eq!(new_generation, a.streams[&1].generation);
    assert!(a.stream(2)?.read_sctp()?.is_some());
    assert!(!a.reconfig_requests.contains_key(&1));
    let completed = a.handle_reconfig(now, &reset_config(&first))?;
    assert_eq!(
        vec![ReconfigResult::SuccessPerformed],
        reconfig_results(&completed)
    );
    assert_eq!(new_generation, a.streams[&1].generation);
    // The old request should now finish resetting SID 2. A completed result
    // for SID 1 must not turn the still-pending request into a stale replay.
    let after_reset = ChunkPayloadData {
        tsn: a.peer_last_tsn + 1,
        stream_identifier: 2,
        stream_sequence_number: 0,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: ppi,
        user_data: Bytes::from_static(b"message in the next SSN space"),
        ..Default::default()
    };
    a.handle_data(&after_reset)?;
    assert!(
        a.stream(2)?.read_sctp()?.is_some(),
        "a newer completed request for SID 1 cancelled SID 2's deferred reset; its first new message was discarded"
    );
    Ok(())
}

#[test]
fn test_duplicate_reset_with_changed_payload_never_reexecutes() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?;
    a.open_stream(2, ppi)?.stop(now)?;
    let outgoing = reset_requests(&a.gather_outbound(now).0).remove(0);
    let original = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: outgoing
            .reconfig_request_sequence_number
            .wrapping_sub(1),
        sender_last_tsn: a.peer_last_tsn.wrapping_add(1),
        stream_identifiers: vec![1],
    };
    a.handle_reconfig(now, &reset_config(&original))?;
    for completed in [false, true] {
        if completed {
            a.peer_last_tsn = original.sender_last_tsn;
            a.handle_reconfig(now, &reset_config(&original))?;
            a.open_stream(1, ppi)?;
        }
        let generation = a.streams[&1].generation;
        let timer = a.timers.get(Timer::Reconfig);
        for changed_field in 0..3 {
            let mut changed = original.clone();
            match changed_field {
                0 => changed.sender_last_tsn = changed.sender_last_tsn.wrapping_add(1),
                1 => changed.stream_identifiers = vec![2],
                _ => {
                    changed.reconfig_response_sequence_number =
                        outgoing.reconfig_request_sequence_number;
                }
            }
            assert_eq!(
                vec![ReconfigResult::ErrorBadSequenceNumber],
                reconfig_results(&a.handle_reconfig(now, &reset_config(&changed))?)
            );
            assert_eq!(generation, a.streams[&1].generation);
            assert_eq!(timer, a.timers.get(Timer::Reconfig));
        }
    }
    Ok(())
}
