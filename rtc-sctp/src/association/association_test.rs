use super::stream::ReliabilityType;
use super::*;

#[path = "reliability_reset_test.rs"]
mod reliability_reset;

#[path = "sack_recovery_test.rs"]
mod sack_recovery;

#[path = "message_selection_test.rs"]
mod message_selection;

#[path = "control_bundling_test.rs"]
mod control_bundling;

const ACCEPT_CH_SIZE: usize = 16;

fn create_association(config: TransportConfig) -> Association {
    Association::new(
        None,
        Arc::new(config),
        1400,
        0,
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        TransportProtocol::UDP,
        Instant::now(),
    )
}

fn timed_test_association() -> Association {
    let mut a = create_association(TransportConfig::default());
    a.control_queue.clear();
    a.timers.stop(Timer::T1Init);
    a.set_state(AssociationState::Established);
    a.use_forward_tsn = true;
    a.peer_supports_reconfig = true;
    a.incoming_resets = IncomingResetQueue::new(1);
    a.rwnd = 65536;
    a.rto_mgr.set_rto(1000, true);
    a
}

#[test]
fn test_two_rx_epochs_without_app_read_require_two_reciprocal_resets() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let first = ChunkPayloadData {
        tsn: a.peer_last_tsn.wrapping_add(1),
        stream_identifier: 1,
        stream_sequence_number: 0,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: ppi,
        user_data: Bytes::from_static(b"old receiver stays unread"),
        ..Default::default()
    };
    a.handle_data(&first)?;
    let first_reset = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: a.my_next_rsn.wrapping_sub(1),
        sender_last_tsn: first.tsn,
        stream_identifiers: vec![1],
    };
    assert_eq!(
        reconfig_results(&a.handle_reconfig(now, &reset_config(&first_reset))?),
        [ReconfigResult::SuccessPerformed],
    );
    let reciprocal = reset_requests(&a.gather_outbound(now).0).remove(0);
    assert_eq!(reciprocal.stream_identifiers, [1]);
    receive_reset_response(&mut a, now, &reciprocal, ReconfigResult::SuccessPerformed)?;
    assert!(a.outgoing_reset.is_none());
    // The peer has now reset both directions, and is permitted to reuse SID 1.
    // Receipt/delivery of the first generation by our application is separate.
    let second = ChunkPayloadData {
        tsn: first.tsn.wrapping_add(1),
        user_data: Bytes::from_static(b"new receiver also closes"),
        ..first.clone()
    };
    a.handle_data(&second)?;
    let second_reset = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 2,
        reconfig_response_sequence_number: reciprocal.reconfig_request_sequence_number,
        sender_last_tsn: second.tsn,
        stream_identifiers: vec![1],
    };
    assert_eq!(
        reconfig_results(&a.handle_reconfig(now, &reset_config(&second_reset))?),
        [ReconfigResult::SuccessPerformed],
    );
    let second_reciprocals = reset_requests(&a.gather_outbound(now).0);
    assert_eq!(
        second_reciprocals.len(),
        1,
        "each reused data channel needs its own reciprocal reset; old API delivery must not suppress it"
    );
    assert_eq!(second_reciprocals[0].stream_identifiers, [1]);
    assert_eq!(
        second_reciprocals[0].reconfig_request_sequence_number,
        reciprocal.reconfig_request_sequence_number.wrapping_add(1),
    );
    receive_reset_response(
        &mut a,
        now,
        &second_reciprocals[0],
        ReconfigResult::SuccessPerformed,
    )?;
    for expected in [&first.user_data, &second.user_data] {
        while a.poll().is_some() {}
        let received = a.stream(1)?.read_sctp()?.unwrap().to_payload(100)?;
        assert_eq!(&received[..], &expected[..]);
    }
    while a.poll().is_some() {}
    assert!(a.stream(1).is_err());
    assert_eq!(a.receive_streams[&1].get_num_bytes(), 0);
    Ok(())
}

#[test]
fn test_stopping_saved_receiver_does_not_close_current_wire_epoch() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let mut data = ChunkPayloadData {
            tsn: a.peer_last_tsn.wrapping_add(1),
            stream_identifier: 1,
            stream_sequence_number: 0,
            beginning_fragment: true,
            ending_fragment: true,
            unordered,
            payload_type: PayloadProtocolIdentifier::Binary,
            ..Default::default()
        };
        let mut last_reciprocal = a.my_next_rsn.wrapping_sub(1);
        for (sequence, payload) in [b"old".as_slice(), b"middle".as_slice()]
            .into_iter()
            .enumerate()
        {
            data.user_data = Bytes::copy_from_slice(payload);
            a.handle_data(&data)?;
            let request = ParamOutgoingResetRequest {
                reconfig_request_sequence_number: sequence as u32 + 1,
                reconfig_response_sequence_number: last_reciprocal,
                sender_last_tsn: data.tsn,
                stream_identifiers: vec![1],
            };
            assert_eq!(
                reconfig_results(&a.handle_reconfig(now, &reset_config(&request))?),
                [ReconfigResult::SuccessPerformed],
            );
            let reciprocals = reset_requests(&a.gather_outbound(now).0);
            assert_eq!(reciprocals.len(), 1);
            last_reciprocal = reciprocals[0].reconfig_request_sequence_number;
            receive_reset_response(
                &mut a,
                now,
                &reciprocals[0],
                ReconfigResult::SuccessPerformed,
            )?;
            data.tsn = data.tsn.wrapping_add(1);
        }

        data.user_data = Bytes::from_static(b"current");
        a.handle_data(&data)?;
        let old = a.stream(1)?.read_sctp()?.unwrap().to_payload(100)?;
        assert_eq!(&old[..], b"old");
        while a.poll().is_some() {}
        {
            let mut middle = a.stream(1)?;
            assert!(middle.is_readable());
            assert!(
                !middle.is_writable(),
                "saved delivery already completed its wire reset"
            );
            middle.stop(now)?;
        }
        assert!(reset_requests(&a.gather_outbound(now).0).is_empty());
        while a.poll().is_some() {}
        assert!(a.stream(1)?.is_writable());
        let current = a.stream(1)?.read_sctp()?.unwrap().to_payload(100)?;
        assert_eq!(&current[..], b"current");
        data.tsn = data.tsn.wrapping_add(1);
        data.stream_sequence_number = if unordered { 0 } else { 1 };
        data.user_data = Bytes::from_static(b"later in current");
        a.handle_data(&data)?;
        let later = a.stream(1)?.read_sctp()?.unwrap().to_payload(100)?;
        assert_eq!(&later[..], b"later in current");
        assert_eq!(a.receive_streams[&1].get_num_bytes(), 0);

        let request = ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 3,
            reconfig_response_sequence_number: last_reciprocal,
            sender_last_tsn: data.tsn,
            stream_identifiers: vec![1],
        };
        a.handle_reconfig(now, &reset_config(&request))?;
        let reciprocals = reset_requests(&a.gather_outbound(now).0);
        assert_eq!(
            reciprocals.len(),
            1,
            "the current wire epoch still needs its own reciprocal reset"
        );
        assert_eq!(reciprocals[0].stream_identifiers, [1]);
    }
    Ok(())
}

#[test]
fn test_reciprocal_reset_requires_new_wire_activity() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let mut last_reciprocal = a.my_next_rsn.wrapping_sub(1);
    // No DATA is necessary for a locally opened channel to need both resets.
    a.open_stream(1, PayloadProtocolIdentifier::Binary)?;
    for sequence in 1..=5 {
        if sequence == 3 {
            a.open_stream(1, PayloadProtocolIdentifier::Binary)?;
        } else if sequence == 5 {
            // A first message may expire before any of its DATA reaches us.
            a.handle_forward_tsn(&ChunkForwardTsn {
                new_cumulative_tsn: a.peer_last_tsn.wrapping_add(1),
                streams: vec![ChunkForwardTsnStream {
                    identifier: 1,
                    sequence: 0,
                }],
            })?;
        }
        let request = ParamOutgoingResetRequest {
            reconfig_request_sequence_number: sequence,
            reconfig_response_sequence_number: last_reciprocal,
            sender_last_tsn: a.peer_last_tsn,
            stream_identifiers: vec![1],
        };
        assert_eq!(
            reconfig_results(&a.handle_reconfig(now, &reset_config(&request))?),
            [ReconfigResult::SuccessPerformed],
        );
        let reciprocals = reset_requests(&a.gather_outbound(now).0);
        if sequence % 2 == 0 {
            assert!(
                reciprocals.is_empty(),
                "an unused reset stream must not start a reset loop"
            );
        } else {
            assert_eq!(reciprocals.len(), 1);
            last_reciprocal = reciprocals[0].reconfig_request_sequence_number;
            receive_reset_response(
                &mut a,
                now,
                &reciprocals[0],
                ReconfigResult::SuccessPerformed,
            )?;
        }
    }
    Ok(())
}

#[test]
fn test_timed_abandonment_preserves_t3_restart_for_outstanding_data() -> Result<()> {
    for gap_ack in [false, true] {
        let mut a = timed_test_association();
        a.rto_mgr.set_rto(1000, false);
        let now = Instant::now();
        let first_tsn = a.my_next_tsn;
        let ppi = PayloadProtocolIdentifier::Binary;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
        stream.write_sctp(now, &Bytes::from_static(b"lost"), ppi)?;
        let mut stream = a.open_stream(2, ppi)?;
        for _ in 0..2 {
            stream.write_sctp(now, &Bytes::from(vec![0; 1000]), ppi)?;
        }
        a.gather_outbound(now);
        let timeout = a.poll_timeout().unwrap();
        a.handle_timeout(timeout);
        assert_eq!(1, data_chunks(&a.gather_outbound(timeout).0));
        let at = timeout + Duration::from_millis(100);
        let sack = ChunkSelectiveAck {
            cumulative_tsn_ack: if gap_ack {
                first_tsn - 1
            } else {
                first_tsn + 1
            },
            advertised_receiver_window_credit: 65536,
            gap_ack_blocks: if gap_ack {
                vec![crate::chunk::chunk_selective_ack::GapAckBlock { start: 2, end: 2 }]
            } else {
                vec![]
            },
            ..Default::default()
        };
        a.handle_sack(&sack, at)?;
        assert_eq!(Some(at + Duration::from_secs(2)), a.poll_timeout());
        a.handle_sack(&sack, at + Duration::from_millis(100))?;
        assert_eq!(
            Some(at + Duration::from_secs(2)),
            a.poll_timeout(),
            "duplicate SACK must not restart T3"
        );
    }
    Ok(())
}

fn data_chunks(packets: &[Bytes]) -> usize {
    packets
        .iter()
        .map(|raw| {
            Packet::unmarshal(raw)
                .unwrap()
                .chunks
                .iter()
                .filter(|c| c.as_any().is::<ChunkPayloadData>())
                .count()
        })
        .sum()
}

#[test]
fn test_timed_retransmit_deadline_and_reliable_exemptions() -> Result<()> {
    let lifetime = Duration::from_millis(100);
    for (policy, ppi, forward_tsn, elapsed, retransmit) in [
        (
            ReliabilityType::Timed,
            PayloadProtocolIdentifier::Binary,
            true,
            lifetime - Duration::from_nanos(1),
            true,
        ),
        (
            ReliabilityType::Timed,
            PayloadProtocolIdentifier::Binary,
            true,
            lifetime,
            false,
        ),
        (
            ReliabilityType::Timed,
            PayloadProtocolIdentifier::Binary,
            true,
            Duration::from_millis(u32::MAX as u64 + 1),
            false,
        ),
        (
            ReliabilityType::Timed,
            PayloadProtocolIdentifier::Dcep,
            true,
            lifetime,
            true,
        ),
        (
            ReliabilityType::Timed,
            PayloadProtocolIdentifier::Binary,
            false,
            lifetime,
            true,
        ),
        (
            ReliabilityType::Reliable,
            PayloadProtocolIdentifier::Binary,
            true,
            lifetime,
            true,
        ),
    ] {
        let mut a = timed_test_association();
        a.use_forward_tsn = forward_tsn;
        let now = Instant::now();
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(true, policy, 100)?;
        stream.write_sctp(now, &Bytes::from_static(b"test"), ppi)?;
        assert_eq!(1, data_chunks(&a.gather_outbound(now).0));
        a.inflight_queue.mark_all_to_retrasmit();
        a.t3_retransmit_pending = true;
        assert_eq!(
            usize::from(retransmit),
            data_chunks(&a.gather_outbound(now + elapsed).0)
        );
        assert_eq!(if retransmit { 4 } else { 0 }, a.buffered_amount());
    }
    Ok(())
}

#[test]
fn test_timed_abandonment_covers_pending_tail_and_retries_forward_tsn() -> Result<()> {
    for unordered in [false, true] {
        for ack_prefix in [false, true] {
            let mut a = timed_test_association();
            a.cwnd = a.max_payload_size;
            let now = Instant::now();
            let first_tsn = a.my_next_tsn;
            let ppi = PayloadProtocolIdentifier::Binary;
            let mut stream = a.open_stream(1, ppi)?;
            stream.set_reliability_params(unordered, ReliabilityType::Timed, 100)?;
            stream.write_sctp(now, &Bytes::from(vec![0; 4000]), ppi)?;
            assert_eq!(1, data_chunks(&a.gather_outbound(now).0));
            assert!(!a.pending_queue.is_empty());
            if ack_prefix {
                a.handle_sack(
                    &ChunkSelectiveAck {
                        cumulative_tsn_ack: first_tsn,
                        advertised_receiver_window_credit: 65536,
                        ..Default::default()
                    },
                    now + Duration::from_millis(50),
                )?;
            }
            let packets = a.gather_outbound(now + Duration::from_millis(100)).0;
            assert_eq!(0, data_chunks(&packets));
            assert!(!packets.is_empty());
            assert!(a.pending_queue.is_empty());
            assert_eq!(0, a.stream(1)?.buffered_amount()?);
            assert_eq!(a.my_next_tsn - 1, a.advanced_peer_tsn_ack_point);
            let fwd = a.create_forward_tsn();
            assert_eq!(usize::from(!unordered), fwd.streams.len());
            let released: usize = std::iter::from_fn(|| a.poll())
                .filter_map(|event| {
                    if let Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) =
                        event
                    {
                        Some(n_bytes)
                    } else {
                        None
                    }
                })
                .sum();
            assert_eq!(4000, released);

            // Lose FORWARD TSN, including while waiting to shut down.
            a.set_state(AssociationState::ShutdownPending);
            let retry = a.poll_timeout().unwrap();
            a.handle_timeout(retry);
            assert_eq!(packets, a.gather_outbound(retry).0);
            assert!(
                a.poll().is_none(),
                "abandoned bytes must not be released twice"
            );
            let cwnd = a.cwnd;
            a.handle_sack(
                &ChunkSelectiveAck {
                    cumulative_tsn_ack: a.advanced_peer_tsn_ack_point,
                    advertised_receiver_window_credit: 65536,
                    ..Default::default()
                },
                retry,
            )?;
            assert!(a.inflight_queue.is_empty());
            assert_eq!(cwnd, a.cwnd, "abandoned bytes must not grow cwnd");
            assert!(a.poll().is_none());
        }
    }
    Ok(())
}

#[test]
fn test_timed_data_expires_between_retransmit_polls() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 1500)?;
    for _ in 0..2 {
        stream.write_sctp(now, &Bytes::from(vec![0; 1000]), ppi)?;
    }
    assert_eq!(2, data_chunks(&a.gather_outbound(now).0));
    let timeout = a.poll_timeout().unwrap();
    a.handle_timeout(timeout);
    assert_eq!(1, data_chunks(&a.gather_outbound(timeout).0));
    assert!(a.t3_retransmit_pending);
    assert_eq!(
        0,
        data_chunks(&a.gather_outbound(now + Duration::from_millis(1500)).0)
    );
    assert_eq!(0, a.buffered_amount());
    assert!(!a.t3_retransmit_pending);
    Ok(())
}

// `create_forward_tsn` no longer rescans the in-flight window; it emits the
// `fwd_tsn_stream_map` that the RFC 3758 C2 walk fills via
// `note_abandoned_for_forward_tsn` as each chunk is abandoned. These unit tests
// drive that same entry point directly (ascending TSN, as C2 would); the full
// window/SACK-driven path is exercised end-to-end by the `endpoint_test`
// `test_assoc_unreliable_rexmit_*` suite.
#[test]
fn test_create_forward_tsn_forward_one_abandoned() -> Result<()> {
    let mut a = Association::default();

    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 10;
    // tsn=10, ordered, si=1, ssn=2
    a.note_abandoned_for_forward_tsn(false, 1, 2);

    let fwdtsn = a.create_forward_tsn();

    assert_eq!(10, fwdtsn.new_cumulative_tsn, "should be able to serialize");
    assert_eq!(1, fwdtsn.streams.len(), "there should be one stream");
    assert_eq!(1, fwdtsn.streams[0].identifier, "si should be 1");
    assert_eq!(2, fwdtsn.streams[0].sequence, "ssn should be 2");

    Ok(())
}

#[test]
fn test_create_forward_tsn_forward_two_abandoned_with_the_same_si() -> Result<()> {
    let mut a = Association::default();

    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 12;
    a.note_abandoned_for_forward_tsn(false, 1, 2); // tsn=10
    a.note_abandoned_for_forward_tsn(false, 1, 3); // tsn=11 -> greatest SSN for si=1
    a.note_abandoned_for_forward_tsn(false, 2, 1); // tsn=12

    let fwdtsn = a.create_forward_tsn();

    assert_eq!(12, fwdtsn.new_cumulative_tsn, "should be able to serialize");
    assert_eq!(2, fwdtsn.streams.len(), "there should be two stream");

    let mut si1ok = false;
    let mut si2ok = false;
    for s in &fwdtsn.streams {
        match s.identifier {
            1 => {
                assert_eq!(3, s.sequence, "ssn should be 3");
                si1ok = true;
            }
            2 => {
                assert_eq!(1, s.sequence, "ssn should be 1");
                si2ok = true;
            }
            _ => assert!(false, "unexpected stream indentifier"),
        }
    }
    assert!(si1ok, "si=1 should be present");
    assert!(si2ok, "si=2 should be present");

    Ok(())
}

#[test]
fn test_create_forward_tsn_omits_unordered_streams() -> Result<()> {
    // Unordered chunks carry no meaningful stream-sequence-number: the receiver
    // advances unordered streams purely by `new_cumulative_tsn` and ignores the
    // per-stream list (see handle_forward_tsn), so create_forward_tsn must not
    // report them — only ordered streams contribute.
    let mut a = Association::default();

    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 11;
    a.note_abandoned_for_forward_tsn(true, 1, 5); // unordered -> omitted
    a.note_abandoned_for_forward_tsn(false, 2, 7); // ordered   -> reported

    let fwdtsn = a.create_forward_tsn();

    assert_eq!(11, fwdtsn.new_cumulative_tsn);
    assert_eq!(
        1,
        fwdtsn.streams.len(),
        "only the ordered stream is reported"
    );
    assert_eq!(2, fwdtsn.streams[0].identifier, "si should be 2");
    assert_eq!(7, fwdtsn.streams[0].sequence, "ssn should be 7");

    Ok(())
}

// The allocation-avoiding marshal_control_chunk() must produce byte-identical wire
// output to create_packet(vec![Box::new(chunk)]).marshal(). A 2-stream FORWARD-TSN
// also exercises ChunkForwardTsn::marshal_to's per-stream marshal_to loop, and a
// SACK and RE-CONFIG cover the remaining control call sites.
#[test]
fn test_marshal_control_chunk_byte_identical_to_create_packet() -> Result<()> {
    let mut a = Association::default();
    a.peer_verification_tag = 0x1234_5678;
    a.source_port = 5000;
    a.destination_port = 5001;

    let fwd_tsn = ChunkForwardTsn {
        new_cumulative_tsn: 42,
        streams: vec![
            ChunkForwardTsnStream {
                identifier: 1,
                sequence: 7,
            },
            ChunkForwardTsnStream {
                identifier: 3,
                sequence: 9,
            },
        ],
    };
    // Borrow for the helper, then move into create_packet (chunks are not Clone).
    let via_helper = a.marshal_control_chunk(&fwd_tsn)?;
    let via_packet = a.create_packet(vec![Box::new(fwd_tsn)]).marshal()?;
    assert_eq!(
        via_helper, via_packet,
        "FORWARD-TSN: marshal_control_chunk must match create_packet(..).marshal()"
    );

    let sack = a.create_selective_ack_chunk();
    let sack_via_helper = a.marshal_control_chunk(&sack)?;
    let sack_via_packet = a.create_packet(vec![Box::new(sack)]).marshal()?;
    assert_eq!(
        sack_via_helper, sack_via_packet,
        "SACK: marshal_control_chunk must match create_packet(..).marshal()"
    );

    // Odd/even SID counts exercise parameter and chunk padding, including the
    // empty list that denotes an all-stream reset.
    for stream_identifiers in [vec![], vec![1], vec![1, 2]] {
        let reconfig = ChunkReconfig {
            param_a: Some(Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 17,
                reconfig_response_sequence_number: 16,
                sender_last_tsn: 42,
                stream_identifiers,
            })),
            ..Default::default()
        };
        let via_helper = a.marshal_control_chunk(&reconfig)?;
        let via_packet = a.create_packet(vec![Box::new(reconfig)]).marshal()?;
        assert_eq!(via_helper, via_packet, "RE-CONFIG framing changed");
        Packet::unmarshal(&via_helper)?;
    }

    Ok(())
}

#[test]
fn test_handle_forward_tsn_forward_3unreceived_chunks() -> Result<()> {
    let mut a = Association::default();

    a.use_forward_tsn = true;
    let prev_tsn = a.peer_last_tsn;

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn + 3,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 0,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn)?;

    let delayed_ack_triggered = a.delayed_ack_triggered;
    let immediate_ack_triggered = a.immediate_ack_triggered;
    assert_eq!(
        a.peer_last_tsn,
        prev_tsn + 3,
        "peerLastTSN should advance by 3 "
    );
    assert!(delayed_ack_triggered, "delayed sack should be triggered");
    assert!(
        !immediate_ack_triggered,
        "immediate sack should NOT be triggered"
    );
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[test]
fn test_handle_forward_tsn_forward_1for1_missing() -> Result<()> {
    let mut a = Association::default();

    a.use_forward_tsn = true;
    let prev_tsn = a.peer_last_tsn;

    // this chunk is blocked by the missing chunk at tsn=1
    a.payload_queue.push(
        ChunkPayloadData {
            beginning_fragment: true,
            ending_fragment: true,
            tsn: a.peer_last_tsn + 2,
            stream_identifier: 0,
            stream_sequence_number: 1,
            user_data: Bytes::from_static(b"ABC"),
            ..Default::default()
        },
        a.peer_last_tsn,
    );

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn + 1,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 1,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn)?;

    let delayed_ack_triggered = a.delayed_ack_triggered;
    let immediate_ack_triggered = a.immediate_ack_triggered;
    assert_eq!(
        a.peer_last_tsn,
        prev_tsn + 2,
        "peerLastTSN should advance by 2"
    );
    assert!(delayed_ack_triggered, "delayed sack should be triggered");
    assert!(
        !immediate_ack_triggered,
        "immediate sack should NOT be triggered"
    );
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[test]
fn test_handle_forward_tsn_forward_1for2_missing() -> Result<()> {
    let mut a = Association::default();

    a.use_forward_tsn = true;
    let prev_tsn = a.peer_last_tsn;

    // this chunk is blocked by the missing chunk at tsn=1
    a.payload_queue.push(
        ChunkPayloadData {
            beginning_fragment: true,
            ending_fragment: true,
            tsn: a.peer_last_tsn + 3,
            stream_identifier: 0,
            stream_sequence_number: 1,
            user_data: Bytes::from_static(b"ABC"),
            ..Default::default()
        },
        a.peer_last_tsn,
    );

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn + 1,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 1,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn)?;

    let immediate_ack_triggered = a.immediate_ack_triggered;
    assert_eq!(
        a.peer_last_tsn,
        prev_tsn + 1,
        "peerLastTSN should advance by 1"
    );
    assert!(
        immediate_ack_triggered,
        "immediate sack should be triggered"
    );
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[test]
fn test_handle_forward_tsn_dup_forward_tsn_chunk_should_generate_sack() -> Result<()> {
    let mut a = Association::default();

    a.use_forward_tsn = true;
    let prev_tsn = a.peer_last_tsn;

    let fwdtsn = ChunkForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn,
        streams: vec![ChunkForwardTsnStream {
            identifier: 0,
            sequence: 1,
        }],
    };

    let p = a.handle_forward_tsn(&fwdtsn)?;

    let ack_state = a.ack_state;
    assert_eq!(a.peer_last_tsn, prev_tsn, "peerLastTSN should not advance");
    assert_eq!(AckState::Immediate, ack_state, "sack should be requested");
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

#[test]
fn test_assoc_create_new_stream() -> Result<()> {
    let mut a = Association {
        my_max_num_inbound_streams: ACCEPT_CH_SIZE as u16,
        ..Default::default()
    };

    for i in 0..ACCEPT_CH_SIZE {
        let stream_identifier =
            if let Some(s) = a.create_stream(i as u16, true, PayloadProtocolIdentifier::Unknown) {
                s.stream_identifier
            } else {
                assert!(false, "{} should success", i);
                0
            };
        let result = a.streams.get(&stream_identifier);
        assert!(result.is_some(), "should be in a.streams map");
    }

    let new_si = ACCEPT_CH_SIZE as u16;
    let result = a.streams.get(&new_si);
    assert!(result.is_none(), "should NOT be in a.streams map");

    let to_be_ignored = ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: a.peer_last_tsn + 1,
        stream_identifier: new_si,
        user_data: Bytes::from_static(b"ABC"),
        ..Default::default()
    };

    let p = a.handle_data(&to_be_ignored)?;
    assert!(p.is_empty(), "should return empty");

    Ok(())
}

fn handle_init_test(name: &str, initial_state: AssociationState, expect_err: bool) {
    let mut a = create_association(TransportConfig::default());
    a.set_state(initial_state);
    let pkt = Packet {
        common_header: CommonHeader {
            source_port: 5001,
            destination_port: 5002,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut init = ChunkInit {
        initial_tsn: 1234,
        num_outbound_streams: 1001,
        num_inbound_streams: 1002,
        initiate_tag: 5678,
        advertised_receiver_window_credit: 512 * 1024,
        ..Default::default()
    };
    init.set_supported_extensions();

    let result = a.handle_init(&pkt, &init);
    if expect_err {
        assert!(result.is_err(), "{} should fail", name);
        return;
    } else {
        assert!(result.is_ok(), "{} should be ok", name);
    }
    assert_eq!(
        if init.initial_tsn == 0 {
            u32::MAX
        } else {
            init.initial_tsn - 1
        },
        a.peer_last_tsn,
        "{} should match",
        name
    );
    assert_eq!(1002, a.my_max_num_outbound_streams, "{} should match", name);
    assert_eq!(1001, a.my_max_num_inbound_streams, "{} should match", name);
    assert_eq!(5678, a.peer_verification_tag, "{} should match", name);
    assert_eq!(
        pkt.common_header.source_port, a.destination_port,
        "{} should match",
        name
    );
    assert_eq!(
        pkt.common_header.destination_port, a.source_port,
        "{} should match",
        name
    );
    assert!(a.use_forward_tsn, "{} should be set to true", name);
}

// W3C `RTCSctpTransport.maxChannels` is the minimum of the negotiated inbound and outbound
// stream counts, and is null until the association is established. `handle_init` is where the
// negotiation happens: the peer's advertised counts narrow this endpoint's configured ones.
#[test]
fn test_assoc_negotiated_max_streams() -> Result<()> {
    let mut a = create_association(TransportConfig::default());

    // Before the handshake completes the two counts still hold the *configured* limits, which
    // were never agreed with anyone. Reporting them would overstate the association.
    assert!(a.is_handshaking());
    assert_eq!(
        None,
        a.negotiated_max_streams(),
        "a handshaking association has negotiated nothing yet"
    );

    a.set_state(AssociationState::Closed);
    let pkt = Packet {
        common_header: CommonHeader {
            source_port: 5001,
            destination_port: 5002,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut init = ChunkInit {
        initial_tsn: 1234,
        num_outbound_streams: 1001,
        num_inbound_streams: 1002,
        initiate_tag: 5678,
        advertised_receiver_window_credit: 512 * 1024,
        ..Default::default()
    };
    init.set_supported_extensions();
    a.handle_init(&pkt, &init)?;

    // `handle_init` narrowed the counts to 1001 outbound / 1002 inbound (see
    // `handle_init_test`), but the handshake is still in flight.
    assert_eq!(
        None,
        a.negotiated_max_streams(),
        "still handshaking after INIT, so still nothing to report"
    );

    a.handshake_completed = true;
    assert_eq!(
        Some(1001),
        a.negotiated_max_streams(),
        "the smaller of 1001 outbound and 1002 inbound"
    );

    Ok(())
}

#[test]
fn test_assoc_handle_init() -> Result<()> {
    handle_init_test("normal", AssociationState::Closed, false);

    handle_init_test(
        "unexpected state established",
        AssociationState::Established,
        true,
    );

    handle_init_test(
        "unexpected state shutdownAckSent",
        AssociationState::ShutdownAckSent,
        true,
    );

    handle_init_test(
        "unexpected state shutdownPending",
        AssociationState::ShutdownPending,
        true,
    );

    handle_init_test(
        "unexpected state shutdownReceived",
        AssociationState::ShutdownReceived,
        true,
    );

    handle_init_test(
        "unexpected state shutdownSent",
        AssociationState::ShutdownSent,
        true,
    );

    Ok(())
}

#[test]
fn test_assoc_max_message_size_default() -> Result<()> {
    let mut a = create_association(TransportConfig::default().with_max_message_size(65536));
    assert_eq!(65536, a.max_message_size, "should match");

    let ppi = PayloadProtocolIdentifier::Unknown;
    let stream = a.create_stream(1, false, ppi);
    assert!(stream.is_some(), "should succeed");

    if let Some(mut s) = stream {
        let p = Bytes::from(vec![0u8; 65537]);

        if let Err(err) = s.write_sctp(Instant::now(), &p.slice(..65536), ppi) {
            assert_ne!(
                Error::ErrOutboundPacketTooLarge,
                err,
                "should be not Error::ErrOutboundPacketTooLarge"
            );
        } else {
            assert!(false, "should be error");
        }

        if let Err(err) = s.write_sctp(Instant::now(), &p.slice(..65537), ppi) {
            assert_eq!(
                Error::ErrOutboundPacketTooLarge,
                err,
                "should be Error::ErrOutboundPacketTooLarge"
            );
        } else {
            assert!(false, "should be error");
        }
    }

    Ok(())
}

#[test]
fn test_assoc_max_message_size_explicit() -> Result<()> {
    let mut a = create_association(TransportConfig::default().with_max_message_size(30000));

    assert_eq!(30000, a.max_message_size, "should match");

    let ppi = PayloadProtocolIdentifier::Unknown;
    let stream = a.create_stream(1, false, ppi);
    assert!(stream.is_some(), "should succeed");

    if let Some(mut s) = stream {
        let p = Bytes::from(vec![0u8; 30001]);

        if let Err(err) = s.write_sctp(Instant::now(), &p.slice(..30000), ppi) {
            assert_ne!(
                Error::ErrOutboundPacketTooLarge,
                err,
                "should be not Error::ErrOutboundPacketTooLarge"
            );
        } else {
            assert!(false, "should be error");
        }

        if let Err(err) = s.write_sctp(Instant::now(), &p.slice(..30001), ppi) {
            assert_eq!(
                Error::ErrOutboundPacketTooLarge,
                err,
                "should be Error::ErrOutboundPacketTooLarge"
            );
        } else {
            assert!(false, "should be error");
        }
    }

    Ok(())
}

// The MTU-split rule in `bundle_data_chunks_into_packets` must bound every
// marshalled datagram: bundle decisions are made on padded wire sizes (the
// chunk header + payload, rounded up to the SCTP 4-byte boundary), never on
// raw payload sizes. These tests marshal real packets and measure the emitted
// bytes, so any accounting drift fails here rather than as silent on-path
// datagram loss.

use crate::EndpointConfig;
use crate::config::{INITIAL_MTU, max_payload_size_for_mtu};

fn create_association_with_mtu(mtu: u32) -> Association {
    Association::new(
        None,
        Arc::new(TransportConfig::default()),
        mtu - (COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE),
        0,
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        TransportProtocol::UDP,
        Instant::now(),
    )
}

fn payload_chunk(tsn: u32, len: usize) -> ChunkPayloadData {
    ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn,
        stream_identifier: 0,
        stream_sequence_number: 0,
        user_data: Bytes::from(vec![0u8; len]),
        ..Default::default()
    }
}

#[test]
fn bundle_split_decides_on_padded_wire_sizes() {
    // Payloads of 1147 + 16 bytes pass a payload-only boundary check at
    // exactly an MTU of 1191, but the two chunks marshal to
    // 12 + 1164 + 32 = 1208 bytes — past the MTU the association promised.
    let a = create_association_with_mtu(1191);
    let chunks = vec![payload_chunk(1, 1147), payload_chunk(2, 16)];
    let mut raw_packets = vec![];
    a.bundle_data_chunks_into_packets(chunks, &mut raw_packets);
    assert_eq!(
        raw_packets.len(),
        2,
        "a bundle that only fits unpadded must split"
    );
    for p in &raw_packets {
        assert!(
            p.len() as u32 <= a.mtu,
            "emitted packet is {} bytes, mtu is {}",
            p.len(),
            a.mtu
        );
    }
}

#[test]
fn single_maximum_size_chunk_marshals_within_initial_mtu() {
    let max_payload = EndpointConfig::default().get_max_payload_size();
    let a = create_association_with_mtu(max_payload + COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE);
    let chunks = vec![payload_chunk(1, max_payload as usize)];
    let mut raw_packets = vec![];
    a.bundle_data_chunks_into_packets(chunks, &mut raw_packets);
    assert_eq!(raw_packets.len(), 1);
    assert!(
        raw_packets[0].len() as u32 <= INITIAL_MTU,
        "a single maximum-size chunk is {} bytes, INITIAL_MTU is {}",
        raw_packets[0].len(),
        INITIAL_MTU
    );
}

#[test]
fn single_maximum_size_chunk_marshals_within_a_custom_mtu() {
    // `max_payload_size_for_mtu(N)` derives a payload budget for which a
    // single maximum-size DATA chunk marshals to at most N bytes, mirroring
    // the default derivation's guarantee for INITIAL_MTU. Prove it on
    // emitted bytes at the 32-byte floor (exactly the smallest
    // representable padded DATA packet), across
    // a 4-byte padding boundary (1201 emits 1200), and at a typical larger
    // path MTU (1500, fully used).
    for (mtu, expected) in [(32u32, 32usize), (1201, 1200), (1500, 1500)] {
        let max_payload = max_payload_size_for_mtu(mtu);
        let a =
            create_association_with_mtu(max_payload + COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE);
        let chunks = vec![payload_chunk(1, max_payload as usize)];
        let mut raw_packets = vec![];
        a.bundle_data_chunks_into_packets(chunks, &mut raw_packets);
        assert_eq!(raw_packets.len(), 1);
        assert_eq!(
            raw_packets[0].len(),
            expected,
            "a single maximum-size chunk under mtu({mtu})"
        );
    }
}

#[test]
fn initial_cwnd_is_computed_safely_for_non_default_mtus() {
    // Regression: the initial congestion window was computed as
    // `(2 * mtu).clamp(4380, 4 * mtu)`, which panicked for effective MTUs
    // below ~1095 (`Ord::clamp` with min > max) and overflowed near
    // `u32::MAX` — reachable through `EndpointConfig::max_payload_size`
    // and MTU-derived payload budgets. RFC 4960 §7.2.1:
    // cwnd = min(4*MTU, max(2*MTU, 4380)); for a small MTU that is 4*MTU.
    let a = create_association_with_mtu(100);
    assert_eq!(a.cwnd, 4 * a.mtu);

    // Directly via the low-level `max_payload_size` setter path: the
    // effective-MTU reconstruction (`max_payload_size + 28`) must saturate
    // rather than overflow when the payload budget itself is near
    // `u32::MAX` (the helper above subtracts the headers first, so it
    // never exercises this addition's edge).
    let a = Association::new(
        None,
        Arc::new(TransportConfig::default()),
        u32::MAX,
        0,
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        TransportProtocol::UDP,
        Instant::now(),
    );
    assert_eq!(a.mtu, u32::MAX);
    assert_eq!(a.cwnd, u32::MAX);
}

#[test]
fn many_small_chunks_bundle_within_mtu() {
    // Per-chunk padding (17-byte payloads: 33 raw, 36 padded) compounds; a
    // payload-only accounting packed bundles that marshalled well past the
    // MTU once dozens of small chunks rode one flight.
    let a = create_association_with_mtu(1191);
    let chunks: Vec<ChunkPayloadData> = (0..60).map(|i| payload_chunk(i, 17)).collect();
    let mut raw_packets = vec![];
    a.bundle_data_chunks_into_packets(chunks, &mut raw_packets);
    assert!(raw_packets.len() >= 2);
    let total: usize = raw_packets.iter().map(|p| p.len()).sum();
    for p in &raw_packets {
        assert!(
            p.len() as u32 <= a.mtu,
            "emitted packet is {} bytes, mtu is {}",
            p.len(),
            a.mtu
        );
    }
    // Nothing was dropped: at least every chunk's unpadded wire size plus one
    // common header per emitted packet.
    let min_expected = 60 * (DATA_CHUNK_HEADER_SIZE as usize + 17)
        + raw_packets.len() * COMMON_HEADER_SIZE as usize;
    assert!(total >= min_expected);
}

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

#[test]
fn test_expired_data_from_previous_sid_use_does_not_skip_new_messages() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
    for _ in 0..6 {
        stream.write_sctp(now, &Bytes::from_static(b"old"), ppi)?;
    }
    stream.close(now)?;
    let reset = reset_requests(&a.gather_outbound(now).0).remove(0);
    // The peer received our DATA and reset. Its DATA SACK was lost, but both
    // directions complete their reset, so SID 1 can be reused.
    a.handle_reconfig(
        now,
        &ChunkReconfig {
            param_b: Some(Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                reconfig_response_sequence_number: reset.reconfig_request_sequence_number,
                sender_last_tsn: a.peer_last_tsn,
                stream_identifiers: vec![1],
            })),
            param_a: Some(Box::new(ParamReconfigResponse {
                reconfig_response_sequence_number: reset.reconfig_request_sequence_number,
                result: ReconfigResult::SuccessPerformed,
            })),
        },
    )?;
    let mut stream = a.open_stream(2, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
    stream.write_sctp(now, &Bytes::from_static(b"also expires"), ppi)?;
    let new_message = Bytes::from_static(b"new reliable message");
    a.open_stream(1, ppi)?.write_sctp(now, &new_message, ppi)?;
    a.gather_outbound(now);
    let at = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(at);
    let packets = a.gather_outbound(at).0;
    let forward = packets
        .iter()
        .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
        .find_map(|c| c.as_any().downcast_ref::<ChunkForwardTsn>().cloned())
        .unwrap();
    assert!(sna32gt(forward.new_cumulative_tsn, reset.sender_last_tsn));
    assert!(
        forward.streams.iter().all(|s| s.identifier != 1),
        "old SSNs must not skip DATA on the reused stream"
    );
    assert_eq!(new_message.len(), a.stream(1)?.buffered_amount()?);
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: reset.sender_last_tsn,
            advertised_receiver_window_credit: 65536,
            ..Default::default()
        },
        at,
    )?;
    assert_eq!(new_message.len(), a.stream(1)?.buffered_amount()?);
    Ok(())
}

fn defer_reset(a: &mut Association) -> Result<()> {
    let now = Instant::now();
    a.peer_last_tsn = 10;
    a.handle_reconfig(
        now,
        &ChunkReconfig {
            param_a: Some(Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                sender_last_tsn: 12,
                stream_identifiers: vec![1],
                ..Default::default()
            })),
            ..Default::default()
        },
    )?;
    Ok(())
}

#[test]
fn test_reconfig_backoff_must_double_once() -> Result<()> {
    let mut a = timed_test_association();
    a.rto_mgr.set_rto(1000, false);
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"reliable data"), ppi)?;
    stream.close(now)?;
    a.gather_outbound(now);
    let timeout = a.timers.get(Timer::Reconfig).unwrap();
    assert_eq!(Some(timeout), a.timers.get(Timer::T3RTX));
    a.handle_timeout(timeout);
    a.gather_outbound(timeout);
    assert_eq!(
        Some(timeout + Duration::from_secs(2)),
        a.timers.get(Timer::Reconfig),
        "Reconfiguration timer must double its previous 1s interval, not back off twice"
    );
    Ok(())
}

#[test]
fn test_deferred_peer_reset_must_not_disable_timed_reliability() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
    stream.write_sctp(
        now,
        &Bytes::from_static(b"local timed message lost in flight"),
        ppi,
    )?;
    a.gather_outbound(now);
    defer_reset(&mut a)?;
    a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: 12,
        ..Default::default()
    })?;
    let timeout = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(timeout);
    for raw in a.gather_outbound(timeout).0 {
        for c in Packet::unmarshal(&raw)?.chunks {
            assert!(
                !c.as_any().is::<ChunkPayloadData>(),
                "deferred incoming reset erased reliability policy; expired timed DATA was retransmitted"
            );
        }
    }
    Ok(())
}

fn enqueue_pair(a: &mut Association, now: Instant) -> Result<u32> {
    let ppi = PayloadProtocolIdentifier::Binary;
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"timed"), ppi)?;
    a.stream(2)?
        .write_sctp(now, &Bytes::from_static(b"reliable"), ppi)?;
    a.gather_outbound(now);
    Ok(a.my_next_tsn - 1)
}

#[test]
fn test_t3_recovers_repeated_losses_when_peer_makes_progress() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?
        .set_reliability_params(false, ReliabilityType::Timed, 100)?;
    a.open_stream(2, ppi)?;
    let mut ack_through = enqueue_pair(&mut a, now)?;
    for round in 1..=8 {
        let timeout = a.poll_timeout().expect("outstanding DATA needs T3");
        a.handle_timeout(timeout);
        let packets = a.gather_outbound(timeout).0;
        let reliable_retransmitted = packets.iter().any(|raw| {
            Packet::unmarshal(raw).unwrap().chunks.iter().any(|chunk| {
                chunk
                    .as_any()
                    .downcast_ref::<ChunkPayloadData>()
                    .is_some_and(|data| data.stream_identifier == 2)
            })
        });
        assert!(
            reliable_retransmitted,
            "round {round}: reliable DATA never retransmitted, timer = {:?}",
            a.poll_timeout()
        );
        // Keep the send queue nonempty while successfully acknowledging every
        // TSN in the previous flight. Each round has actual receiver progress.
        let next_ack = enqueue_pair(&mut a, timeout)?;
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: ack_through,
                advertised_receiver_window_credit: 65536,
                ..Default::default()
            },
            timeout + Duration::from_millis(50),
        )?;
        ack_through = next_ack;
    }
    Ok(())
}

#[test]
fn test_forward_tsn_reset_waits_for_queued_data_and_starts_timer() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.cwnd = a.mtu;
    a.open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from(vec![1; 4000]), ppi)?;
    defer_reset(&mut a)?;
    let reply = a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: 12,
        ..Default::default()
    })?;
    let mut sent_bytes = 0;
    let mut last_data_tsn = 0;
    let mut packets: Vec<Bytes> = reply.iter().map(|p| p.marshal().unwrap()).collect();
    // A small send window forces the pending message to span several flights.
    for _ in 0..10 {
        packets.extend(a.gather_outbound(now).0);
        for raw in &packets {
            for c in Packet::unmarshal(raw)?.chunks {
                if let Some(c) = c.as_any().downcast_ref::<ChunkPayloadData>() {
                    sent_bytes += c.user_data.len();
                    last_data_tsn = c.tsn;
                }
            }
        }
        let resets = reset_requests(&packets);
        if let Some(reset) = resets.first() {
            assert_eq!(4000, sent_bytes, "reset overtook queued DATA");
            assert_eq!(last_data_tsn, reset.sender_last_tsn);
            assert_eq!(1, reset.reconfig_response_sequence_number);
            assert!(a.timers.get(Timer::Reconfig).is_some());
            return Ok(());
        }
        assert!(sent_bytes > 0);
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: last_data_tsn,
                advertised_receiver_window_credit: 65536,
                ..Default::default()
            },
            now,
        )?;
        packets.clear();
    }
    panic!("reciprocal reset was never sent");
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
#[ignore = "manual queue benchmark; run with --release --ignored --nocapture"]
fn benchmark_pending_data_before_reset() -> Result<()> {
    for count in [2048usize, 4096, 8192, 16384] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.cwnd = 1024 * 1024;
        a.rwnd = 1024 * 1024;
        let mut stream = a.open_stream(1, ppi)?;
        for _ in 0..count {
            stream.write_sctp(now, &Bytes::from_static(b"0123456789abcdef"), ppi)?;
        }
        a.handle_reconfig(
            now,
            &ChunkReconfig {
                param_a: Some(Box::new(ParamOutgoingResetRequest {
                    reconfig_request_sequence_number: 1,
                    sender_last_tsn: a.peer_last_tsn,
                    stream_identifiers: vec![1],
                    ..Default::default()
                })),
                ..Default::default()
            },
        )?;
        let started = Instant::now();
        let (chunks, resets) = std::hint::black_box(&mut a).pop_pending_data_chunks_to_send(now);
        let elapsed = started.elapsed();
        assert_eq!(count, chunks.len());
        assert_eq!(
            vec![1],
            resets
                .iter()
                .map(|reset| reset.stream_identifier)
                .collect::<Vec<_>>()
        );
        eprintln!(
            "queued_messages={count} payload_bytes={} send_queue_us={}",
            count * 16,
            elapsed.as_micros()
        );
    }
    Ok(())
}

#[test]
fn test_timed_zero_lifetime_sends_every_fragment_once() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        a.cwnd = 1300;
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(unordered, ReliabilityType::Timed, 0)?;
        stream.write_sctp(now, &Bytes::from(vec![0; 4000]), ppi)?;
        let mut sent = 0;
        for round in 0..3 {
            let at = now + Duration::from_millis(round * 10);
            let packets = a.gather_outbound(at).0;
            for raw in packets {
                for chunk in Packet::unmarshal(&raw)?.chunks {
                    if let Some(data) = chunk.as_any().downcast_ref::<ChunkPayloadData>() {
                        sent += data.user_data.len();
                        a.handle_sack(
                            &ChunkSelectiveAck {
                                cumulative_tsn_ack: data.tsn,
                                advertised_receiver_window_credit: 65536,
                                ..Default::default()
                            },
                            at,
                        )?;
                    }
                }
            }
        }
        assert_eq!(
            4000, sent,
            "zero lifetime must allow every fragment's first send"
        );
        assert!(a.pending_queue.is_empty());
        assert!(a.inflight_queue.is_empty());
        assert_eq!(0, a.stream(1)?.buffered_amount()?);
    }
    Ok(())
}

#[test]
fn test_timed_expiry_does_not_abandon_gap_acked_messages() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let first_tsn = a.my_next_tsn;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
    for _ in 0..2 {
        stream.write_sctp(now, &Bytes::from_static(b"test"), ppi)?;
    }
    a.gather_outbound(now);
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: first_tsn - 1,
            advertised_receiver_window_credit: 65536,
            gap_ack_blocks: vec![crate::chunk::chunk_selective_ack::GapAckBlock {
                start: 2,
                end: 2,
            }],
            ..Default::default()
        },
        now + Duration::from_millis(50),
    )?;
    let timeout = a.poll_timeout().unwrap();
    a.handle_timeout(timeout);
    a.gather_outbound(timeout);
    assert!(!a.inflight_queue.get(first_tsn + 1).unwrap().abandoned());
    assert!(sna32lt(a.advanced_peer_tsn_ack_point, first_tsn + 1));
    let streams = a.create_forward_tsn().streams;
    assert!(streams.iter().all(|s| s.sequence != 1));
    Ok(())
}

#[test]
fn test_reciprocal_reset_precedes_writes_on_reused_sid() -> Result<()> {
    for old_size in [0, 32, 4000] {
        for old_unordered in [false, true] {
            for new_unordered in [false, true] {
                let mut a = timed_test_association();
                a.cwnd = 65536;
                let now = Instant::now();
                let first_tsn = a.my_next_tsn;
                let ppi = PayloadProtocolIdentifier::Binary;
                let mut old = a.open_stream(5, ppi)?;
                old.set_reliability_params(old_unordered, ReliabilityType::Reliable, 0)?;
                if old_size > 0 {
                    old.write_sctp(now, &Bytes::from(vec![1; old_size]), ppi)?;
                }
                a.handle_reconfig(
                    now,
                    &ChunkReconfig {
                        param_a: Some(Box::new(ParamOutgoingResetRequest {
                            reconfig_request_sequence_number: 1,
                            sender_last_tsn: a.peer_last_tsn,
                            stream_identifiers: vec![5],
                            ..Default::default()
                        })),
                        ..Default::default()
                    },
                )?;
                let mut new = a.open_stream(5, ppi)?;
                new.set_reliability_params(new_unordered, ReliabilityType::Reliable, 0)?;
                let new_payload = Bytes::from_static(b"new stream data");
                new.write_sctp(now, &new_payload, ppi)?;

                let packets = a.gather_outbound(now).0;
                let reset = reset_requests(&packets).remove(0);
                assert_eq!(vec![5], reset.stream_identifiers);
                assert_eq!(1, reset.reconfig_response_sequence_number);
                let data: Vec<_> = packets
                    .iter()
                    .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
                    .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>().cloned())
                    .collect();
                let payload: Vec<u8> = data
                    .iter()
                    .flat_map(|c| c.user_data.iter().copied())
                    .collect();
                assert_eq!(
                    vec![1; old_size],
                    payload,
                    "new DATA crossed the reset: old_size={old_size}, old_unordered={old_unordered}, new_unordered={new_unordered}"
                );
                let last_tsn = reset.sender_last_tsn;
                assert_eq!(
                    first_tsn.wrapping_add(data.len() as u32).wrapping_sub(1),
                    last_tsn
                );
                assert_eq!(0, data_chunks(&a.gather_outbound(now).0));
                receive_reset_response(&mut a, now, &reset, ReconfigResult::SuccessPerformed)?;
                let (data, resets) = a.pop_pending_data_chunks_to_send(now);
                assert!(resets.is_empty());
                assert_eq!(1, data.len());
                assert_eq!(new_payload, data[0].user_data);
                assert!(sna32gt(data[0].tsn, last_tsn));
                assert!(a.pending_queue.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn test_timed_abandonment_discards_gap_acked_fragments() -> Result<()> {
    for unordered in [false, true] {
        for (size, lost_fragment) in [(2000, 0), (2000, 1), (4000, 0), (4000, 1), (4000, 2)] {
            let mut sender = timed_test_association();
            let mut receiver = timed_test_association();
            sender.cwnd = 65536;
            receiver.ack_mode = AckMode::NoDelay;
            receiver.peer_last_tsn = sender.my_next_tsn.wrapping_sub(1);
            receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
            let receive_window = receiver.get_my_receiver_window_credit();
            let now = Instant::now();
            let ppi = PayloadProtocolIdentifier::Binary;
            let mut stream = sender.open_stream(1, ppi)?;
            stream.set_reliability_params(unordered, ReliabilityType::Timed, 100)?;
            stream.write_sctp(now, &Bytes::from(vec![0x55; size]), ppi)?;
            // A fully received message must survive even with the same SID,
            // deadline and (for unordered DATA) SSN as the abandoned message.
            let delivered = Bytes::from(vec![0x66; size]);
            stream.write_sctp(now, &delivered, ppi)?;
            receiver.open_stream(1, ppi)?.set_reliability_params(
                unordered,
                ReliabilityType::Timed,
                100,
            )?;
            let data: Vec<ChunkPayloadData> = sender
                .gather_outbound(now)
                .0
                .iter()
                .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
                .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>().cloned())
                .collect();
            let fragments = size.div_ceil(sender.max_payload_size as usize);
            assert_eq!(2 * fragments, data.len());
            for (index, chunk) in data.iter().enumerate() {
                if index != lost_fragment {
                    receiver.handle_data(chunk)?;
                }
            }
            sender.handle_sack(
                &receiver.create_selective_ack_chunk(),
                now + Duration::from_millis(10),
            )?;
            let at = sender.poll_timeout().unwrap();
            sender.handle_timeout(at);
            let packets = sender.gather_outbound(at).0;
            assert_eq!(
                0,
                data_chunks(&packets),
                "expired DATA must not be retransmitted"
            );
            for chunk in &data[fragments..] {
                assert!(
                    !sender.inflight_queue.get(chunk.tsn).unwrap().abandoned(),
                    "a fully Gap-ACKed message must not be abandoned"
                );
            }
            let forwards: Vec<ChunkForwardTsn> = packets
                .iter()
                .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
                .filter_map(|c| c.as_any().downcast_ref::<ChunkForwardTsn>().cloned())
                .collect();
            assert_eq!(1, forwards.len());
            assert_eq!(data[fragments - 1].tsn, forwards[0].new_cumulative_tsn);
            receiver.handle_forward_tsn(&forwards[0])?;
            sender.handle_sack(&receiver.create_selective_ack_chunk(), at)?;
            assert!(sender.inflight_queue.is_empty());
            assert_eq!(0, sender.stream(1)?.buffered_amount()?);
            let released: usize = std::iter::from_fn(|| sender.poll())
                .filter_map(|event| {
                    if let Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) =
                        event
                    {
                        Some(n_bytes)
                    } else {
                        None
                    }
                })
                .sum();
            assert_eq!(
                2 * size,
                released,
                "Gap-ACKed bytes must not be released twice"
            );
            let queue = &receiver.receive_streams.get(&1).unwrap();
            assert_eq!(
                size,
                queue.get_num_bytes(),
                "abandoned fragments still occupy rwnd: unordered={unordered}, size={size}, lost_fragment={lost_fragment}"
            );
            let chunks = receiver
                .stream(1)?
                .read_sctp()?
                .expect("the complete message must remain readable");
            let mut received = vec![0; size];
            assert_eq!(size, chunks.read(&mut received)?);
            assert_eq!(delivered.as_ref(), received.as_slice());
            assert!(receiver.stream(1)?.read_sctp()?.is_none());
            assert_eq!(receive_window, receiver.get_my_receiver_window_credit());
        }
    }
    Ok(())
}

#[test]
fn test_t3_recovers_with_acked_timed_zero_data() -> Result<()> {
    for gap_ack in [false, true] {
        let mut a = timed_test_association();
        let mut receiver = timed_test_association();
        receiver.peer_last_tsn = a.my_next_tsn.wrapping_sub(1);
        receiver.incoming_resets = IncomingResetQueue::new(a.my_next_rsn);
        receiver.ack_mode = AckMode::NoDelay;
        a.rto_mgr.set_rto(1000, false);
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?
            .set_reliability_params(true, ReliabilityType::Timed, 100)?;
        a.open_stream(2, ppi)?
            .set_reliability_params(true, ReliabilityType::Timed, 0)?;
        receiver
            .open_stream(2, ppi)?
            .set_reliability_params(true, ReliabilityType::Timed, 0)?;
        let mut now = Instant::now();
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"lost timed message"), ppi)?;
        a.gather_outbound(now);
        for round in 1..=8 {
            now = a
                .poll_timeout()
                .expect("unacknowledged DATA needs a T3 timer");
            a.handle_timeout(now);
            let packets = a.gather_outbound(now).0;
            assert_eq!(
                0,
                data_chunks(&packets),
                "expired DATA must not be retransmitted"
            );
            let forwards: Vec<ChunkForwardTsn> = packets
                .iter()
                .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
                .filter_map(|c| c.as_any().downcast_ref::<ChunkForwardTsn>().cloned())
                .collect();
            assert!(
                !forwards.is_empty(),
                "round {round}, gap_ack={gap_ack}: T3 stopped producing FORWARD TSN despite peer progress"
            );
            if !gap_ack {
                for forward in &forwards {
                    receiver.handle_forward_tsn(forward)?;
                }
            }
            // Deliver fresh Timed(0) DATA. Drop FORWARD TSN in the gap-ACK case
            // so the actual DATA receipt must clear T3's error counter there too.
            a.stream(2)?.write_sctp(
                now,
                &Bytes::from_static(b"delivered timed zero message"),
                ppi,
            )?;
            for raw in a.gather_outbound(now).0 {
                for c in Packet::unmarshal(&raw)?.chunks {
                    if let Some(data) = c.as_any().downcast_ref::<ChunkPayloadData>() {
                        receiver.handle_data(data)?;
                    }
                }
            }
            assert!(
                receiver.stream(2)?.read_sctp()?.is_some(),
                "fresh Timed(0) DATA reached the peer"
            );
            let sack = receiver.create_selective_ack_chunk();
            if gap_ack {
                assert!(!sack.gap_ack_blocks.is_empty());
            } else {
                assert_eq!(a.my_next_tsn.wrapping_sub(1), sack.cumulative_tsn_ack);
            }
            // Keep new traffic in flight when the preceding DATA is ACKed.
            a.stream(1)?
                .write_sctp(now, &Bytes::from_static(b"lost timed message"), ppi)?;
            a.gather_outbound(now);
            a.handle_sack(&sack, now + Duration::from_millis(10))?;
        }
    }
    Ok(())
}

#[test]
fn test_timed_zero_fragment_loss_restores_receive_window() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    sender.cwnd = 1400;
    receiver.peer_last_tsn = sender.my_next_tsn - 1;
    receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    sender
        .open_stream(1, ppi)?
        .set_reliability_params(true, ReliabilityType::Timed, 0)?;
    receiver.open_stream(1, ppi)?;
    sender
        .stream(1)?
        .write_sctp(now, &Bytes::from(vec![0x55; 4000]), ppi)?;
    let lost = sender.gather_outbound(now).0;
    assert_eq!(1, lost.len());
    assert!(!sender.pending_queue.is_empty());
    let at = sender.poll_timeout().unwrap();
    sender.handle_timeout(at);
    for _ in 0..10 {
        let packets = sender.gather_outbound(at).0;
        for raw in packets {
            for c in Packet::unmarshal(&raw)?.chunks {
                if let Some(c) = c.as_any().downcast_ref::<ChunkPayloadData>() {
                    receiver.handle_data(c)?;
                } else if let Some(c) = c.as_any().downcast_ref::<ChunkForwardTsn>() {
                    receiver.handle_forward_tsn(c)?;
                }
            }
        }
        sender.handle_sack(&receiver.create_selective_ack_chunk(), at)?;
        while receiver.stream(1)?.read_sctp()?.is_some() {}
        if sender.pending_queue.is_empty() && sender.inflight_queue.is_empty() {
            break;
        }
    }
    assert!(sender.pending_queue.is_empty());
    assert!(sender.inflight_queue.is_empty());
    assert!(sender.poll_timeout().is_none());
    assert_eq!(
        0,
        receiver.receive_streams.get(&1).unwrap().get_num_bytes(),
        "abandoned Timed(0) message must not strand ACKed tail fragments in rwnd"
    );
    Ok(())
}

#[test]
fn test_late_real_data_acks_keep_t3_alive() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    sender.rto_mgr.set_rto(1000, false);
    receiver.peer_last_tsn = sender.my_next_tsn - 1;
    receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
    let ppi = PayloadProtocolIdentifier::Binary;
    sender
        .open_stream(1, ppi)?
        .set_reliability_params(true, ReliabilityType::Timed, 100)?;
    receiver.open_stream(1, ppi)?;
    let deliver_new_data =
        |sender: &mut Association, receiver: &mut Association, at: Instant| -> Result<()> {
            sender
                .stream(1)?
                .write_sctp(at, &Bytes::from_static(b"actually received"), ppi)?;
            let mut delivered = 0;
            for raw in sender.gather_outbound(at).0 {
                for c in Packet::unmarshal(&raw)?.chunks {
                    if let Some(c) = c.as_any().downcast_ref::<ChunkPayloadData>() {
                        receiver.handle_data(c)?;
                        delivered += 1;
                    }
                }
            }
            assert_eq!(1, delivered);
            assert!(receiver.stream(1)?.read_sctp()?.is_some());
            Ok(())
        };
    deliver_new_data(&mut sender, &mut receiver, Instant::now())?;
    for round in 1..=5 {
        let at = sender.poll_timeout().unwrap();
        let previous_ack = receiver.create_selective_ack_chunk();
        sender.handle_timeout(at);
        // Ignore the retransmission/FORWARD TSN: the peer already received this DATA.
        sender.gather_outbound(at);
        // A busy sender has the next message in flight when the old SACK arrives.
        if round < 5 {
            deliver_new_data(&mut sender, &mut receiver, at)?;
        } else {
            sender.open_stream(2, ppi)?.write_sctp(
                at,
                &Bytes::from_static(b"reliable, first send lost"),
                ppi,
            )?;
            assert!(!sender.gather_outbound(at).0.is_empty());
        }
        sender.handle_sack(&previous_ack, at + Duration::from_millis(10))?;
    }
    let at = sender.poll_timeout().unwrap();
    sender.handle_timeout(at);
    let retried_reliable = sender
        .gather_outbound(at)
        .0
        .iter()
        .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
        .filter(|c| {
            c.as_any()
                .downcast_ref::<ChunkPayloadData>()
                .is_some_and(|c| c.stream_identifier == 2)
        })
        .count();
    assert_eq!(
        1,
        retried_reliable,
        "T3 must retry the lost reliable DATA after five successful but late timed DATA ACKs; timer={:?}",
        sender.poll_timeout()
    );
    Ok(())
}

#[test]
fn test_message_abandonment_is_idempotent_after_partial_and_late_acks() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.cwnd = 2 * a.max_payload_size + 1;
        let cumulative_ack = a.my_next_tsn.wrapping_sub(1);
        a.open_stream(2, ppi)?
            .write_sctp(now, &Bytes::from_static(b"x"), ppi)?;
        a.gather_outbound(now); // Leave a gap before the fragmented message.
        let first = a.my_next_tsn;
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(unordered, ReliabilityType::Timed, 100)?;
        stream.write_sctp(now, &Bytes::from(vec![0; 4000]), ppi)?;
        stream.write_sctp(now, &Bytes::from_static(b"next"), ppi)?;
        assert_eq!(2, data_chunks(&a.gather_outbound(now).0));
        let mut sack = ChunkSelectiveAck {
            cumulative_tsn_ack: cumulative_ack,
            advertised_receiver_window_credit: 65536,
            gap_ack_blocks: vec![crate::chunk::chunk_selective_ack::GapAckBlock {
                start: 2,
                end: 2,
            }],
            ..Default::default()
        };
        a.handle_sack(&sack, now + Duration::from_millis(50))?;
        while a.poll().is_some() {}
        let at = now + Duration::from_millis(100);
        let messages = a.unretransmittable_messages(at, ChunkPayloadData::is_outstanding);
        assert_eq!(1, messages.len());
        let message = messages[0];
        assert!(a.abandon_message(message));
        let released: usize = std::iter::from_fn(|| a.poll())
            .filter_map(|event| {
                if let Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) = event {
                    Some(n_bytes)
                } else {
                    None
                }
            })
            .sum();
        assert_eq!(4000 - a.max_payload_size as usize, released);
        assert!(!a.abandon_message(message));
        assert!(
            a.poll().is_none(),
            "repeated abandonment must not release bytes twice"
        );
        assert_eq!(4, a.pending_queue.get_num_bytes());
        assert_eq!(4, a.stream(1)?.buffered_amount()?);
        assert_eq!(
            Bytes::from_static(b"next"),
            a.pending_queue.peek().unwrap().user_data
        );
        for offset in 0..3 {
            let c = a.inflight_queue.get(first.wrapping_add(offset)).unwrap();
            assert!(c.abandoned());
            assert!(!c.is_outstanding());
            assert!(c.user_data.is_empty());
        }
        assert!(!a.inflight_queue.get(first + 1).unwrap().acknowledged);
        // A late real ACK changes receipt state, without reclaiming payload again.
        sack.gap_ack_blocks[0].end = 3;
        a.handle_sack(&sack, at)?;
        a.handle_sack(&sack, at + Duration::from_millis(1))?;
        assert!(a.inflight_queue.get(first + 1).unwrap().acknowledged);
        assert!(!a.inflight_queue.get(first + 2).unwrap().acknowledged);
        assert!(a.poll().is_none());
        assert!(!a.abandon_message(message));
        assert_eq!(4, a.stream(1)?.buffered_amount()?);
    }
    Ok(())
}

#[test]
fn test_repeated_pending_abandonment_preserves_the_next_message() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let first_tsn = a.my_next_tsn;
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(true, ReliabilityType::Timed, 100)?;
    stream.write_sctp(now, &Bytes::from(vec![0; 4000]), ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"next"), ppi)?;
    let message = a.pending_message_to_abandon();
    assert!(a.abandon_message(message));
    assert!(!a.abandon_message(message));
    a.on_messages_abandoned(now + Duration::from_millis(100));
    assert_eq!(first_tsn, a.my_next_tsn);
    assert!(a.inflight_queue.is_empty());
    assert!(a.poll_timeout().is_none());
    assert_eq!(4, a.stream(1)?.buffered_amount()?);
    assert_eq!(
        Bytes::from_static(b"next"),
        a.pending_queue.peek().unwrap().user_data
    );
    Ok(())
}

#[test]
fn test_split_reciprocal_reset_waits_for_ack() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?;
    a.open_stream(2, ppi)?
        .write_sctp(now, &Bytes::from_static(b"queued"), ppi)?;
    let reply = a.handle_reconfig(
        now,
        &ChunkReconfig {
            param_a: Some(Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                sender_last_tsn: a.peer_last_tsn,
                stream_identifiers: vec![1, 2],
                ..Default::default()
            })),
            ..Default::default()
        },
    )?;
    let mut packets: Vec<_> = reply.iter().map(|p| p.marshal().unwrap()).collect();
    packets.extend(a.gather_outbound(now).0);
    packets.extend(a.gather_outbound(now).0);
    let requests = reset_requests(&packets);
    assert_eq!(
        1,
        requests.len(),
        "RFC 6525 5.1.1 permits only one request in flight"
    );
    assert_eq!(vec![1], requests[0].stream_identifiers);
    assert_eq!(
        1,
        data_chunks(&packets),
        "other streams' earlier DATA may still send"
    );
    receive_reset_response(&mut a, now, &requests[0], ReconfigResult::SuccessPerformed)?;
    let next = reset_requests(&a.gather_outbound(now).0).remove(0);
    assert_eq!(vec![2], next.stream_identifiers);
    assert_ne!(
        requests[0].reconfig_request_sequence_number,
        next.reconfig_request_sequence_number
    );
    assert_eq!(a.my_next_tsn - 1, next.sender_last_tsn);
    receive_reset_response(&mut a, now, &next, ReconfigResult::SuccessPerformed)?;
    assert!(a.outgoing_reset.is_none());
    assert!(a.timers.get(Timer::Reconfig).is_none());
    Ok(())
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
fn test_rexmit_zero_policy_survives_peer_reset() -> Result<()> {
    rexmit_after_peer_reset(false)
}

#[test]
fn test_rexmit_zero_policy_survives_sid_reuse() -> Result<()> {
    rexmit_after_peer_reset(true)
}

fn rexmit_after_peer_reset(reuse_sid: bool) -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(true, ReliabilityType::Rexmit, 0)?;
    stream.write_sctp(now, &Bytes::from_static(b"lost maxRetransmits=0 DATA"), ppi)?;
    assert_eq!(1, data_chunks(&a.gather_outbound(now).0));
    defer_reset(&mut a)?;
    a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: 12,
        ..Default::default()
    })?;
    assert!(!a.streams.contains_key(&1));
    if reuse_sid {
        a.open_stream(1, ppi)?;
    }
    let at = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(at);
    let packets = a.gather_outbound(at).0;
    assert_eq!(
        0,
        data_chunks(&packets),
        "peer reset erased maxRetransmits=0 policy; reuse_sid={reuse_sid}"
    );
    assert!(packets.iter().any(|raw| {
        Packet::unmarshal(raw)
            .unwrap()
            .chunks
            .iter()
            .any(|c| c.as_any().is::<ChunkForwardTsn>())
    }));
    Ok(())
}

#[test]
fn test_queued_message_keeps_its_original_reliability_policy() -> Result<()> {
    use ReliabilityType::{Reliable, Rexmit, Timed};
    for (original, value, replacement, ppi, forward_tsn, retransmit) in [
        (
            Reliable,
            0,
            Rexmit,
            PayloadProtocolIdentifier::Binary,
            true,
            true,
        ),
        (
            Rexmit,
            0,
            Reliable,
            PayloadProtocolIdentifier::Binary,
            true,
            false,
        ),
        (
            Rexmit,
            2,
            Rexmit,
            PayloadProtocolIdentifier::Binary,
            true,
            true,
        ),
        (
            Timed,
            100,
            Reliable,
            PayloadProtocolIdentifier::Binary,
            true,
            false,
        ),
        (
            Rexmit,
            0,
            Reliable,
            PayloadProtocolIdentifier::Dcep,
            true,
            true,
        ),
        (
            Rexmit,
            0,
            Reliable,
            PayloadProtocolIdentifier::Binary,
            false,
            true,
        ),
    ] {
        let mut a = timed_test_association();
        a.use_forward_tsn = forward_tsn;
        let now = Instant::now();
        let mut stream = a.open_stream(1, ppi)?;
        stream.set_reliability_params(false, original, value)?;
        stream.write_sctp(now, &Bytes::from_static(b"queued"), ppi)?;
        // Policy is captured at enqueue, before even the first transmission.
        stream.set_reliability_params(false, replacement, 0)?;
        assert_eq!(1, data_chunks(&a.gather_outbound(now).0));
        let at = a.timers.get(Timer::T3RTX).unwrap();
        a.handle_timeout(at);
        assert_eq!(
            usize::from(retransmit),
            data_chunks(&a.gather_outbound(at).0),
            "original={original:?} value={value} replacement={replacement:?} ppi={ppi:?} forward_tsn={forward_tsn}"
        );
        assert_eq!(
            if retransmit { 6 } else { 0 },
            a.stream(1)?.buffered_amount()?
        );
    }
    Ok(())
}

#[test]
fn test_rexmit_budget_counts_fast_and_timer_retransmissions_after_reset() -> Result<()> {
    for max_retransmits in [0, 1, 2] {
        for reset in [None, Some(false), Some(true)] {
            for fast_first in [false, true] {
                let mut a = timed_test_association();
                let now = Instant::now();
                let ppi = PayloadProtocolIdentifier::Binary;
                let first_tsn = a.my_next_tsn;
                let mut stream = a.open_stream(1, ppi)?;
                stream.set_reliability_params(true, ReliabilityType::Rexmit, max_retransmits)?;
                stream.write_sctp(now, &Bytes::from_static(b"lost"), ppi)?;
                assert_eq!(1, data_chunks(&a.gather_outbound(now).0));
                if let Some(reuse_sid) = reset {
                    defer_reset(&mut a)?;
                    a.handle_forward_tsn(&ChunkForwardTsn {
                        new_cumulative_tsn: 12,
                        ..Default::default()
                    })?;
                    assert!(!a.streams.contains_key(&1));
                    if reuse_sid {
                        a.open_stream(1, ppi)?;
                    }
                }
                for attempt in 0..=max_retransmits {
                    let at = if fast_first && attempt == 0 {
                        a.inflight_queue.get_mut(first_tsn).unwrap().miss_indicator = 3;
                        a.will_retransmit_fast = true;
                        now + Duration::from_millis(1)
                    } else {
                        let at = a.timers.get(Timer::T3RTX).unwrap();
                        a.handle_timeout(at);
                        at
                    };
                    let packets = a.gather_outbound(at).0;
                    let retransmit = attempt < max_retransmits;
                    assert_eq!(
                        usize::from(retransmit),
                        data_chunks(&packets),
                        "max_retransmits={max_retransmits} attempt={attempt} reset={reset:?} fast_first={fast_first}"
                    );
                    let chunk = a.inflight_queue.get(first_tsn).unwrap();
                    assert_eq!(!retransmit, chunk.abandoned());
                    assert_eq!(
                        if retransmit { 4 } else { 0 },
                        a.inflight_queue.get_num_bytes()
                    );
                    if !retransmit {
                        assert!(packets.iter().any(|raw| {
                            Packet::unmarshal(raw)
                                .unwrap()
                                .chunks
                                .iter()
                                .any(|c| c.as_any().is::<ChunkForwardTsn>())
                        }));
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_rexmit_zero_reset_abandons_acked_and_pending_fragments() -> Result<()> {
    for unordered in [false, true] {
        for ack_prefix in [false, true] {
            let mut a = timed_test_association();
            a.cwnd = 2 * a.max_payload_size;
            let now = Instant::now();
            let first_tsn = a.my_next_tsn;
            let ppi = PayloadProtocolIdentifier::Binary;
            let mut stream = a.open_stream(1, ppi)?;
            stream.set_reliability_params(unordered, ReliabilityType::Rexmit, 0)?;
            stream.write_sctp(now, &Bytes::from(vec![0; 4000]), ppi)?;
            assert_eq!(2, data_chunks(&a.gather_outbound(now).0));
            a.handle_sack(
                &ChunkSelectiveAck {
                    cumulative_tsn_ack: if ack_prefix { first_tsn } else { first_tsn - 1 },
                    advertised_receiver_window_credit: 65536,
                    gap_ack_blocks: if ack_prefix {
                        vec![]
                    } else {
                        vec![crate::chunk::chunk_selective_ack::GapAckBlock { start: 2, end: 2 }]
                    },
                    ..Default::default()
                },
                now + Duration::from_millis(1),
            )?;
            defer_reset(&mut a)?;
            a.handle_forward_tsn(&ChunkForwardTsn {
                new_cumulative_tsn: 12,
                ..Default::default()
            })?;
            a.open_stream(1, ppi)?
                .write_sctp(now, &Bytes::from_static(b"new"), ppi)?;
            let at = a.timers.get(Timer::T3RTX).unwrap();
            a.handle_timeout(at);
            let packets = a.gather_outbound(at).0;
            assert_eq!(0, data_chunks(&packets));
            assert_eq!(0, a.inflight_queue.get_num_bytes());
            assert_eq!(3, a.pending_queue.get_num_bytes());
            assert_eq!(3, a.stream(1)?.buffered_amount()?);
            let last_tsn = first_tsn + 2;
            for tsn in first_tsn..=last_tsn {
                if let Some(c) = a.inflight_queue.get(tsn) {
                    assert!(c.abandoned());
                    assert!(!c.retransmit);
                }
            }
            assert_eq!(last_tsn, a.advanced_peer_tsn_ack_point);
            let reset = reset_requests(&packets).remove(0);
            assert_eq!(last_tsn, reset.sender_last_tsn);
            receive_reset_response(&mut a, at, &reset, ReconfigResult::SuccessPerformed)?;
            assert_eq!(1, data_chunks(&a.gather_outbound(at).0));
            a.handle_sack(
                &ChunkSelectiveAck {
                    cumulative_tsn_ack: last_tsn,
                    advertised_receiver_window_credit: 65536,
                    ..Default::default()
                },
                at,
            )?;
            assert_eq!(
                3,
                a.stream(1)?.buffered_amount()?,
                "old ACK must not release new DATA"
            );
        }
    }
    Ok(())
}

fn transmitted_data(packets: &[Bytes]) -> Vec<ChunkPayloadData> {
    packets
        .iter()
        .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
        .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>().cloned())
        .collect()
}

#[test]
fn test_rexmit_one_waits_for_ack_of_first_retry() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut s = a.open_stream(1, ppi)?;
    s.set_reliability_params(false, ReliabilityType::Rexmit, 1)?;
    s.write_sctp(now, &Bytes::from(vec![0x55; 2000]), ppi)?;
    let initial = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(2, initial.len());
    let at = a.poll_timeout().unwrap();
    a.handle_timeout(at);
    let first_retry = transmitted_data(&a.gather_outbound(at).0);
    assert_eq!(1, first_retry.len());
    assert_eq!(initial[0].tsn, first_retry[0].tsn);
    // The normal driver drains poll_transmit until None at the same instant.
    let more = a.gather_outbound(at).0;
    assert!(
        a.inflight_queue
            .get(initial[0].tsn)
            .unwrap()
            .is_outstanding(),
        "a just-retried fragment must wait for ACK or a new loss indication; second drain emitted {more:?}"
    );
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: initial[0].tsn,
            advertised_receiver_window_credit: 65536,
            ..Default::default()
        },
        at + Duration::from_millis(10),
    )?;
    // The tail may be emitted by either drain. In both cases each fragment
    // gets its permitted retry and remains outstanding until the peer ACKs it.
    let mut tail_retry = transmitted_data(&more);
    tail_retry.extend(transmitted_data(
        &a.gather_outbound(at + Duration::from_millis(10)).0,
    ));
    assert_eq!(1, tail_retry.len());
    assert_eq!(initial[1].tsn, tail_retry[0].tsn);
    assert!(
        a.inflight_queue
            .get(initial[1].tsn)
            .unwrap()
            .is_outstanding()
    );
    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = initial[0].tsn - 1;
    for chunk in first_retry.iter().chain(tail_retry.iter()) {
        receiver.handle_data(chunk)?;
    }
    assert_eq!(2000, receiver.stream(1)?.read_sctp()?.unwrap().len());
    a.handle_sack(
        &receiver.create_selective_ack_chunk(),
        at + Duration::from_millis(20),
    )?;
    assert!(a.inflight_queue.is_empty());
    Ok(())
}

#[test]
fn test_fast_retry_does_not_abandon_unsent_fragment_tail_of_new_rexmit_zero() -> Result<()> {
    for policy in [ReliabilityType::Rexmit, ReliabilityType::Timed] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?
            .write_sctp(now, &Bytes::from_static(b"lost reliable"), ppi)?;
        let old = transmitted_data(&a.gather_outbound(now).0).remove(0);
        // Three real gap ACK reports request a fast retransmission for stream 1.
        for _ in 0..3 {
            a.stream(1)?
                .write_sctp(now, &Bytes::from_static(b"received"), ppi)?;
        }
        a.gather_outbound(now);
        for end in 2..=4 {
            a.handle_sack(
                &ChunkSelectiveAck {
                    cumulative_tsn_ack: old.tsn - 1,
                    advertised_receiver_window_credit: 65536,
                    gap_ack_blocks: vec![crate::chunk::chunk_selective_ack::GapAckBlock {
                        start: 2,
                        end,
                    }],
                    ..Default::default()
                },
                now,
            )?;
        }
        assert!(a.will_retransmit_fast);
        let mut fresh = a.open_stream(2, ppi)?;
        fresh.set_reliability_params(false, policy, 0)?;
        fresh.write_sctp(now, &Bytes::from(vec![0x33; 16000]), ppi)?;
        let sent = a.gather_outbound(now).0;
        assert!(
            transmitted_data(&sent)
                .iter()
                .any(|c| c.stream_identifier == 1)
        );
        assert!(
            transmitted_data(&sent)
                .iter()
                .any(|c| c.stream_identifier == 2)
        );
        assert!(
            !a.pending_queue.is_empty(),
            "an unrelated fast retry discarded never-sent fragments of fresh DATA"
        );
        assert_eq!(16000, a.stream(2)?.buffered_amount()?);
    }
    Ok(())
}

#[test]
fn test_write_after_stop_uses_reset_ssn() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = sender.my_next_tsn - 1;
    receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
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
fn test_old_forward_ssn_needed_until_reciprocal_reset_is_acknowledged() -> Result<()> {
    for reopen in [false, true] {
        for abandon_before_reopen in [false, true] {
            let mut sender = timed_test_association();
            let mut receiver = timed_test_association();
            receiver.peer_last_tsn = sender.my_next_tsn - 1;
            receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
            let now = Instant::now();
            let ppi = PayloadProtocolIdentifier::Binary;
            let mut stream = sender.open_stream(1, ppi)?;
            stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
            stream.write_sctp(now, &Bytes::from_static(b"lost ssn zero"), ppi)?;
            stream.write_sctp(now, &Bytes::from_static(b"received ssn one"), ppi)?;
            let sent = transmitted_data(&sender.gather_outbound(now).0);
            assert_eq!(2, sent.len());
            // Peer has ACKed the second message, but cannot deliver it until SSN 0 is skipped.
            receiver.handle_data(&sent[1])?;
            assert!(receiver.stream(1)?.read_sctp()?.is_none());
            sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
            // Let the sender abandon SSN 0 and build its forward map; lose these packets.
            // A second timeout also puts the unpatched base on the FORWARD TSN path.
            let mut at = now;
            if abandon_before_reopen {
                for _ in 0..2 {
                    at = sender.timers.get(Timer::T3RTX).unwrap();
                    sender.handle_timeout(at);
                    sender.gather_outbound(at);
                }
            }
            // Peer closes its own outgoing direction while it still expects our queued sends.
            let peer_request = ChunkReconfig {
                param_a: Some(Box::new(ParamOutgoingResetRequest {
                    reconfig_request_sequence_number: 1,
                    sender_last_tsn: sender.peer_last_tsn,
                    stream_identifiers: vec![1],
                    ..Default::default()
                })),
                ..Default::default()
            };
            let mut packets = sender.handle_reconfig(at, &peer_request)?;
            assert!(sender.stream(1).is_err());
            if reopen {
                sender.open_stream(1, ppi)?;
            }
            if !abandon_before_reopen {
                at = sender.timers.get(Timer::T3RTX).unwrap();
                sender.handle_timeout(at);
            }
            // Repeat the gap ACK so the outstanding FORWARD TSN is generated again.
            sender.handle_sack(&receiver.create_selective_ack_chunk(), at)?;
            packets.extend(
                sender
                    .gather_outbound(at)
                    .0
                    .iter()
                    .map(|raw| Packet::unmarshal(raw).unwrap()),
            );
            // Our reciprocal reset reaches the peer before FORWARD TSN; the peer defers it.
            for packet in &packets {
                for c in &packet.chunks {
                    if let Some(r) = c.as_any().downcast_ref::<ChunkReconfig>() {
                        receiver.handle_reconfig(at, r)?;
                    }
                }
            }
            for packet in &packets {
                for c in &packet.chunks {
                    if let Some(f) = c.as_any().downcast_ref::<ChunkForwardTsn>() {
                        receiver.handle_forward_tsn(f)?;
                    }
                }
            }
            assert!(
                receiver
                    .stream(1)
                    .is_ok_and(|mut s| s.read_sctp().is_ok_and(|m| m.is_some())),
                "already acknowledged message was discarded by reset because FORWARD TSN omitted old SSN; reopen={reopen}"
            );
        }
    }
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
fn test_implicit_ack_does_not_confirm_deferred_reset() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = sender.my_next_tsn - 1;
    receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = sender.open_stream(1, ppi)?;
    stream.set_reliability_params(false, ReliabilityType::Timed, 100)?;
    stream.write_sctp(now, &Bytes::from_static(b"lost ssn zero"), ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"received ssn one"), ppi)?;
    let sent = transmitted_data(&sender.gather_outbound(now).0);
    receiver.handle_data(&sent[1])?;
    sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
    sender.stream(1)?.close(now)?;
    let mut our_rsn = None;
    for raw in sender.gather_outbound(now).0 {
        for c in Packet::unmarshal(&raw)?.chunks {
            if let Some(config) = c.as_any().downcast_ref::<ChunkReconfig>() {
                let request = config
                    .param_a
                    .as_ref()
                    .unwrap()
                    .as_any()
                    .downcast_ref::<ParamOutgoingResetRequest>()
                    .unwrap();
                our_rsn = Some(request.reconfig_request_sequence_number);
                for response in receiver.handle_reconfig(now, config)? {
                    for c in response.chunks {
                        if let Some(config) = c.as_any().downcast_ref::<ChunkReconfig>() {
                            let response = config
                                .param_a
                                .as_ref()
                                .unwrap()
                                .as_any()
                                .downcast_ref::<ParamReconfigResponse>()
                                .unwrap();
                            assert_eq!(ReconfigResult::InProgress, response.result);
                            sender.handle_reconfig(now, config)?;
                        }
                    }
                }
            }
        }
    }
    let our_rsn = our_rsn.unwrap();
    // A compliant peer sends an unrelated outgoing reset. RFC 6525 A4 puts
    // its most recently received request number in the response-sequence field,
    // even though that earlier request is still deferred for missing DATA.
    sender.open_stream(2, ppi)?;
    sender.handle_reconfig(
        now,
        &ChunkReconfig {
            param_a: Some(Box::new(ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                reconfig_response_sequence_number: our_rsn,
                sender_last_tsn: sender.peer_last_tsn,
                stream_identifiers: vec![2],
            })),
            ..Default::default()
        },
    )?;
    let at = sender.timers.get(Timer::T3RTX).unwrap();
    sender.handle_timeout(at);
    let forwards: Vec<_> = sender
        .gather_outbound(at)
        .0
        .iter()
        .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
        .filter_map(|c| c.as_any().downcast_ref::<ChunkForwardTsn>().cloned())
        .collect();
    assert!(!forwards.is_empty());
    for forward in forwards {
        receiver.handle_forward_tsn(&forward)?;
    }
    assert!(
        receiver
            .stream(1)
            .is_ok_and(|mut s| s.read_sctp().is_ok_and(|v| v.is_some())),
        "an implicit request ACK was treated as reset success; it removed the SSN needed to deliver acknowledged DATA"
    );
    Ok(())
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
fn test_implicit_ack_keeps_data_queued_until_result_without_changing_newer_timer() -> Result<()> {
    for result in [ReconfigResult::SuccessPerformed, ReconfigResult::Denied] {
        let mut a = timed_test_association();
        let mut now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?
            .write_sctp(now, &Bytes::from_static(b"old"), ppi)?;
        a.stream(1)?.stop(now)?;
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"after reset"), ppi)?;
        let first = reset_requests(&a.gather_outbound(now).0).remove(0);
        a.handle_sack(
            &ChunkSelectiveAck {
                cumulative_tsn_ack: first.sender_last_tsn,
                advertised_receiver_window_credit: 65536,
                ..Default::default()
            },
            now,
        )?;
        let implicit = ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 1,
            reconfig_response_sequence_number: first.reconfig_request_sequence_number,
            sender_last_tsn: a.peer_last_tsn,
            stream_identifiers: vec![99],
        };
        a.handle_reconfig(now, &reset_config(&implicit))?;
        a.open_stream(2, ppi)?.close(now)?;
        for late in [
            ReconfigResult::InProgress,
            result,
            ReconfigResult::ErrorBadSequenceNumber,
        ] {
            receive_reset_response(&mut a, now, &first, late)?;
            assert!(a.gather_outbound(now).0.is_empty());
            assert!(a.timers.get(Timer::Reconfig).is_none());
        }
        now = a.poll_timeout().unwrap();
        a.handle_timeout(now);
        assert_eq!(
            vec![first.clone()],
            reset_requests(&a.gather_outbound(now).0)
        );
        receive_reset_response(&mut a, now, &first, result)?;
        let mut packets = a.gather_outbound(now).0;
        packets.extend(a.gather_outbound(now).0);
        let second = reset_requests(&packets).remove(0);
        assert_eq!(vec![2], second.stream_identifiers);
        let resumed = transmitted_data(&packets);
        assert_eq!(1, resumed.len());
        assert_eq!(
            if result == ReconfigResult::Denied {
                1
            } else {
                0
            },
            resumed[0].stream_sequence_number
        );
        let timer = a.timers.get(Timer::Reconfig);
        for late in [
            ReconfigResult::SuccessPerformed,
            ReconfigResult::Denied,
            ReconfigResult::ErrorBadSequenceNumber,
        ] {
            receive_reset_response(&mut a, now, &first, late)?;
            assert_eq!(timer, a.timers.get(Timer::Reconfig));
        }
        a.stream(1)?
            .write_sctp(now, &Bytes::from_static(b"later"), ppi)?;
        assert_eq!(
            resumed[0].stream_sequence_number + 1,
            transmitted_data(&a.gather_outbound(now).0)[0].stream_sequence_number
        );
    }
    Ok(())
}

#[test]
fn test_lost_result_after_implicit_ack_is_retried_without_resetting_reused_sid() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = sender.my_next_tsn - 1;
    receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
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
    assert!(sender.outgoing_reset.is_none());
    Ok(())
}

#[test]
fn test_result_queries_are_serialized_and_keep_in_progress_status() -> Result<()> {
    for progress_before_implicit in [false, true] {
        let mut a = timed_test_association();
        let mut now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(1, ppi)?.close(now)?;
        let first = reset_requests(&a.gather_outbound(now).0).remove(0);
        if progress_before_implicit {
            receive_reset_response(&mut a, now, &first, ReconfigResult::InProgress)?;
        }
        a.handle_reconfig(
            now,
            &reset_config(&ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                reconfig_response_sequence_number: first.reconfig_request_sequence_number,
                sender_last_tsn: a.peer_last_tsn,
                stream_identifiers: vec![99],
            }),
        )?;
        a.open_stream(2, ppi)?.close(now)?;
        assert!(reset_requests(&a.gather_outbound(now).0).is_empty());
        now = a.poll_timeout().unwrap();
        a.handle_timeout(now);
        assert_eq!(
            vec![first.clone()],
            reset_requests(&a.gather_outbound(now).0)
        );
        if !progress_before_implicit {
            receive_reset_response(&mut a, now, &first, ReconfigResult::InProgress)?;
        }
        for _ in 0..8 {
            now = a.poll_timeout().unwrap();
            a.handle_timeout(now);
            assert_eq!(
                vec![first.clone()],
                reset_requests(&a.gather_outbound(now).0)
            );
            assert_eq!(AssociationState::Established, a.state());
        }
        receive_reset_response(&mut a, now, &first, ReconfigResult::SuccessPerformed)?;
        let second = reset_requests(&a.gather_outbound(now).0).remove(0);
        assert_eq!(vec![2], second.stream_identifiers);
        receive_reset_response(&mut a, now, &second, ReconfigResult::SuccessPerformed)?;
        assert!(a.poll_timeout().is_none());
    }
    Ok(())
}

#[test]
fn test_completed_reset_replays_do_not_modify_reused_streams() -> Result<()> {
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
    a.incoming_resets = IncomingResetQueue::new(10);
    a.open_stream(1, ppi)?;
    a.open_stream(2, ppi)?;
    let original = request(10, vec![1, 2]);
    a.handle_reconfig(now, &original)?;
    a.open_stream(1, ppi)?;
    a.open_stream(2, ppi)?;
    a.handle_reconfig(now, &request(11, vec![2]))?;
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
        assert!(a.incoming_resets.is_empty());
        if expected == ReconfigResult::SuccessPerformed {
            a.handle_reconfig(now, &request(12, vec![1]))?;
            a.open_stream(1, ppi)?;
        }
    }
    for sequence in 13..100 {
        a.handle_reconfig(now, &request(sequence, vec![1]))?;
    }
    assert_eq!(
        2,
        a.incoming_resets.history_len(),
        "history is bounded independently of SID count"
    );
    Ok(())
}

fn reset_config(request: &ParamOutgoingResetRequest) -> ChunkReconfig {
    ChunkReconfig {
        param_a: Some(Box::new(request.clone())),
        ..Default::default()
    }
}

#[test]
fn test_old_result_query_must_not_resume_with_stale_ssn() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    receiver.peer_last_tsn = sender.my_next_tsn.wrapping_sub(1);
    receiver.incoming_resets = IncomingResetQueue::new(sender.my_next_rsn);
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    sender
        .open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from_static(b"before reset"), ppi)?;
    for data in transmitted_data(&sender.gather_outbound(now).0) {
        receiver.handle_data(&data)?;
    }
    assert!(receiver.stream(1)?.read_sctp()?.is_some());
    sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
    sender.stream(1)?.stop(now)?;
    sender
        .stream(1)?
        .write_sctp(now, &Bytes::from_static(b"after reset"), ppi)?;
    let first = reset_requests(&sender.gather_outbound(now).0).remove(0);
    receiver.handle_reconfig(now, &reset_config(&first))?; // lose Success
    sender.handle_reconfig(
        now,
        &reset_config(&ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 1,
            reconfig_response_sequence_number: first.reconfig_request_sequence_number,
            sender_last_tsn: sender.peer_last_tsn,
            stream_identifiers: vec![99],
        }),
    )?;
    for sid in [2, 3] {
        sender.open_stream(sid, ppi)?.close(now)?;
        assert!(
            reset_requests(&sender.gather_outbound(now).0).is_empty(),
            "retain N even in a peer cache of only one completed result"
        );
    }
    let at = sender.poll_timeout().unwrap();
    sender.handle_timeout(at);
    assert_eq!(
        vec![first.clone()],
        reset_requests(&sender.gather_outbound(at).0)
    );
    for packet in receiver.handle_reconfig(at, &reset_config(&first))? {
        for chunk in packet.chunks {
            if let Some(config) = chunk.as_any().downcast_ref::<ChunkReconfig>() {
                sender.handle_reconfig(at, config)?;
            }
        }
    }
    let mut packets = sender.gather_outbound(at).0;
    packets.extend(sender.gather_outbound(at).0);
    let data = transmitted_data(&packets);
    assert_eq!(1, data.len());
    assert_eq!(0, data[0].stream_sequence_number);
    receiver.handle_data(&data[0])?;
    assert_eq!(
        Bytes::from_static(b"after reset"),
        receiver
            .stream(1)?
            .read_sctp()?
            .unwrap()
            .to_payload(usize::MAX)?
            .freeze()
    );
    assert!(
        !reset_requests(&packets).is_empty(),
        "later requests eventually resume"
    );
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
    assert!(a.incoming_resets.get(1).is_none());
    // Network reset completes independently of application delivery.
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
        vec![ReconfigResult::SuccessPerformed],
        reconfig_results(&repeated)
    );
    assert!(a.incoming_resets.get(1).is_none());
    assert_eq!(new_generation, a.streams[&1].generation);
    assert!(a.incoming_resets.get(1).is_none());

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
    let credit_before = a.get_my_receiver_window_credit();
    a.handle_data(&after_reset)?;
    assert_eq!(
        credit_before - after_reset.user_data.len() as u32,
        a.get_my_receiver_window_credit()
    );
    assert_eq!(
        before_reset.user_data,
        a.stream(2)?
            .read_sctp()?
            .unwrap()
            .to_payload(usize::MAX)?
            .freeze()
    );
    assert!(
        !a.streams.contains_key(&2),
        "old receiver is retired before the next accessor publishes its successor"
    );
    // Poll and public accessors publish the next receiver after the old close.
    while a.poll().is_some() {}
    assert_eq!(
        after_reset.user_data,
        a.stream(2)?
            .read_sctp()?
            .unwrap()
            .to_payload(usize::MAX)?
            .freeze()
    );
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
fn test_revoked_gap_ack_retains_payload_and_releases_buffer_once() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let initial = a.my_next_tsn;
    let mut stream = a.open_stream(1, ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"first"), ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"second"), ppi)?;
    let original = transmitted_data(&a.gather_outbound(now).0);
    assert_eq!(2, original.len());
    while a.poll().is_some() {}
    let mut sack = ChunkSelectiveAck {
        cumulative_tsn_ack: initial.wrapping_sub(1),
        advertised_receiver_window_credit: 65536,
        gap_ack_blocks: vec![crate::chunk::chunk_selective_ack::GapAckBlock { start: 2, end: 2 }],
        ..Default::default()
    };
    a.handle_sack(&sack, now)?;
    assert_eq!(
        11,
        a.inflight_queue.get_num_bytes(),
        "gap ACK is not final ownership release"
    );
    assert_eq!(5, a.inflight_queue.outstanding_bytes());
    assert_eq!(5, a.stream(1)?.buffered_amount()?);
    let mut released = 0;
    while let Some(event) = a.poll() {
        if let Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) = event {
            released += n_bytes;
        }
    }
    assert_eq!(6, released);
    sack.gap_ack_blocks.clear();
    a.handle_sack(&sack, now)?;
    assert_eq!(11, a.inflight_queue.outstanding_bytes());
    assert_eq!(5, a.stream(1)?.buffered_amount()?);
    assert_eq!(
        1,
        a.inflight_queue
            .get(initial.wrapping_add(1))
            .unwrap()
            .miss_indicator
    );
    let at = a.poll_timeout().expect("revoked DATA needs recovery");
    a.handle_timeout(at);
    let retried = transmitted_data(&a.gather_outbound(at).0);
    assert_eq!(2, retried.len());
    for (original, retried) in original.iter().zip(&retried) {
        assert_eq!(original.tsn, retried.tsn);
        assert_eq!(
            original.user_data, retried.user_data,
            "must retransmit retained bytes"
        );
    }
    sack.gap_ack_blocks
        .push(crate::chunk::chunk_selective_ack::GapAckBlock { start: 2, end: 2 });
    a.handle_sack(&sack, at)?;
    a.handle_sack(&sack, at)?;
    sack.cumulative_tsn_ack = initial.wrapping_add(1);
    sack.gap_ack_blocks.clear();
    a.handle_sack(&sack, at)?;
    while let Some(event) = a.poll() {
        if let Event::Stream(StreamEvent::BufferedAmountReleased { n_bytes, .. }) = event {
            released += n_bytes;
        }
    }
    assert_eq!(11, released);
    assert_eq!(0, a.stream(1)?.buffered_amount()?);
    assert_eq!(0, a.inflight_queue.get_num_bytes());
    assert!(a.poll_timeout().is_none());
    Ok(())
}

#[test]
fn test_revoked_gap_ack_timed_message_is_abandoned_before_retry() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let initial = a.my_next_tsn;
    a.open_stream(2, ppi)?
        .write_sctp(now, &Bytes::from_static(b"reliable gap"), ppi)?;
    a.gather_outbound(now);
    let mut stream = a.open_stream(1, ppi)?;
    stream.set_reliability_params(true, ReliabilityType::Timed, 100)?;
    stream.write_sctp(now, &Bytes::from_static(b"timed"), ppi)?;
    a.gather_outbound(now);
    let mut sack = ChunkSelectiveAck {
        cumulative_tsn_ack: initial.wrapping_sub(1),
        advertised_receiver_window_credit: 65536,
        gap_ack_blocks: vec![crate::chunk::chunk_selective_ack::GapAckBlock { start: 2, end: 2 }],
        ..Default::default()
    };
    a.handle_sack(&sack, now)?;
    sack.gap_ack_blocks.clear();
    let expired = now + Duration::from_millis(100);
    a.handle_sack(&sack, expired)?;
    let at = a.poll_timeout().unwrap();
    a.handle_timeout(at);
    let packets = a.gather_outbound(at).0;
    assert!(
        transmitted_data(&packets)
            .iter()
            .all(|c| c.stream_identifier == 2)
    );
    assert!(
        a.inflight_queue
            .get(initial.wrapping_add(1))
            .unwrap()
            .abandoned()
    );
    assert_eq!(0, a.stream(1)?.buffered_amount()?);
    Ok(())
}

#[test]
fn test_abandoned_tail_uses_one_terminal_tsn_after_cumulative_prefix_ack() -> Result<()> {
    for unordered in [false, true] {
        let mut sender = timed_test_association();
        let mut receiver = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        let first_tsn = sender.my_next_tsn;
        receiver.peer_last_tsn = first_tsn.wrapping_sub(1);
        sender.cwnd = sender.max_payload_size;
        let mut stream = sender.open_stream(1, ppi)?;
        stream.set_reliability_params(unordered, ReliabilityType::Timed, 100)?;
        stream.write_sctp(now, &Bytes::from(vec![7; 12000]), ppi)?;
        let first = transmitted_data(&sender.gather_outbound(now).0);
        assert_eq!(1, first.len());
        receiver.handle_data(&first[0])?;
        receiver
            .stream(1)?
            .set_reliability_params(unordered, ReliabilityType::Reliable, 0)?;
        sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
        assert!(sender.inflight_queue.is_empty());
        let expired = now + Duration::from_millis(100);
        let packets = sender.gather_outbound(expired).0;
        assert!(
            transmitted_data(&packets).is_empty(),
            "terminal TSN is never an empty DATA packet"
        );
        assert_eq!(first_tsn.wrapping_add(2), sender.my_next_tsn);
        let forwards: Vec<_> = packets
            .iter()
            .flat_map(|p| Packet::unmarshal(p).unwrap().chunks)
            .filter_map(|c| c.as_any().downcast_ref::<ChunkForwardTsn>().cloned())
            .collect();
        assert_eq!(1, forwards.len());
        receiver.handle_forward_tsn(&forwards[0])?;
        assert_eq!(0, receiver.receive_streams[&1].get_num_bytes());
        assert_eq!(0, sender.stream(1)?.buffered_amount()?);
        assert!(sender.pending_queue.is_empty());
        sender.handle_sack(&receiver.create_selective_ack_chunk(), expired)?;
        assert!(sender.inflight_queue.is_empty());
        assert!(sender.poll_timeout().is_none());
    }
    Ok(())
}

#[test]
fn test_forward_tsn_crossing_reset_boundary_preserves_old_ready_message() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.peer_last_tsn = 0;
    a.handle_data(&ChunkPayloadData {
        tsn: 2,
        stream_identifier: 1,
        stream_sequence_number: 1,
        beginning_fragment: true,
        ending_fragment: true,
        payload_type: ppi,
        user_data: Bytes::from_static(b"complete after missing SSN zero"),
        ..Default::default()
    })?;
    let reset = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        sender_last_tsn: 2,
        stream_identifiers: vec![1],
        ..Default::default()
    };
    assert_eq!(
        vec![ReconfigResult::InProgress],
        reconfig_results(&a.handle_reconfig(now, &reset_config(&reset))?)
    );
    // TSN 3 belongs to another abandoned stream. NewCum crosses the boundary,
    // but SID 1's SSN still describes its OLD direction (A1/H4 and RFC 3758 C4).
    let reply = a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: 3,
        streams: vec![ChunkForwardTsnStream {
            identifier: 1,
            sequence: 0,
        }],
    })?;
    assert_eq!(
        vec![ReconfigResult::SuccessPerformed],
        reconfig_results(&reply)
    );
    assert_eq!(
        Bytes::from_static(b"complete after missing SSN zero"),
        a.stream(1)?
            .read_sctp()?
            .unwrap()
            .to_payload(usize::MAX)?
            .freeze()
    );
    assert!(a.stream(1).is_err());
    Ok(())
}

#[test]
fn test_future_data_waits_for_receive_reset_and_keeps_window_charge() -> Result<()> {
    for unordered in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.peer_last_tsn = 0;
        let data = |tsn, sid, ssn, unordered| ChunkPayloadData {
            tsn,
            stream_identifier: sid,
            stream_sequence_number: ssn,
            unordered,
            beginning_fragment: true,
            ending_fragment: true,
            payload_type: ppi,
            user_data: Bytes::from_static(b"saved"),
            ..Default::default()
        };
        a.handle_data(&data(1, 1, 0, unordered))?;
        assert!(a.stream(1)?.read_sctp()?.is_some());
        a.handle_reconfig(
            now,
            &reset_config(&ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                sender_last_tsn: 3,
                stream_identifiers: vec![1],
                ..Default::default()
            }),
        )?;
        let credit = a.get_my_receiver_window_credit();
        a.handle_data(&data(4, 1, 0, unordered))?;
        assert!(
            a.stream(1)?.read_sctp()?.is_none(),
            "E2 holds DATA above the boundary"
        );
        assert_eq!(credit - 5, a.get_my_receiver_window_credit());
        a.handle_data(&data(2, 2, 0, false))?;
        let reply = a.handle_data(&data(3, 2, 1, false))?;
        assert_eq!(
            vec![ReconfigResult::SuccessPerformed],
            reconfig_results(&reply)
        );
        while a.poll().is_some() {}
        assert_eq!(
            Bytes::from_static(b"saved"),
            a.stream(1)?
                .read_sctp()?
                .unwrap()
                .to_payload(usize::MAX)?
                .freeze()
        );
    }
    Ok(())
}

#[test]
fn test_fragmented_data_and_gap_sack_cross_tsn_wrap() -> Result<()> {
    for unordered in [false, true] {
        let now = Instant::now();
        let mut sender = timed_test_association();
        let mut receiver = timed_test_association();
        sender.my_next_tsn = u32::MAX - 1;
        sender.cumulative_tsn_ack_point = u32::MAX - 2;
        sender.advanced_peer_tsn_ack_point = u32::MAX - 2;
        receiver.peer_last_tsn = u32::MAX - 2;
        sender.cwnd = 65536;
        let payload = Bytes::from(vec![42; 4000]);
        let mut stream = sender.open_stream(1, PayloadProtocolIdentifier::Binary)?;
        stream.set_reliability_params(unordered, ReliabilityType::Reliable, 0)?;
        stream.write_sctp(now, &payload, PayloadProtocolIdentifier::Binary)?;
        let sent = transmitted_data(&sender.gather_outbound(now).0);
        assert_eq!(
            vec![u32::MAX - 1, u32::MAX, 0],
            sent.iter().map(|d| d.tsn).collect::<Vec<_>>()
        );
        receiver.handle_data(&sent[2])?;
        let sack = receiver.create_selective_ack_chunk();
        assert_eq!(
            vec![(3, 3)],
            sack.gap_ack_blocks
                .iter()
                .map(|g| (g.start, g.end))
                .collect::<Vec<_>>()
        );
        sender.handle_sack(&sack, now)?;
        receiver.handle_data(&sent[0])?;
        receiver.handle_data(&sent[1])?;
        assert_eq!(
            payload,
            receiver
                .stream(1)?
                .read_sctp()?
                .unwrap()
                .to_payload(usize::MAX)?
                .freeze()
        );
        sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
        assert!(sender.inflight_queue.is_empty());
    }
    Ok(())
}

#[test]
fn test_responsive_zero_window_probe_does_not_exhaust_t3() -> Result<()> {
    let mut sender = timed_test_association();
    let mut receiver = timed_test_association();
    let mut now = Instant::now();
    receiver.peer_last_tsn = sender.my_next_tsn.wrapping_sub(1);
    receiver.max_receive_buffer_size = 4;
    let ppi = PayloadProtocolIdentifier::Binary;
    sender
        .open_stream(1, ppi)?
        .write_sctp(now, &Bytes::from_static(b"full"), ppi)?;
    for data in transmitted_data(&sender.gather_outbound(now).0) {
        receiver.handle_data(&data)?;
    }
    sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
    sender
        .stream(1)?
        .write_sctp(now, &Bytes::from_static(b"next"), ppi)?;
    for _ in 0..9 {
        for data in transmitted_data(&sender.gather_outbound(now).0) {
            receiver.handle_data(&data)?;
        }
        let sack = receiver.create_selective_ack_chunk();
        assert_eq!(0, sack.advertised_receiver_window_credit);
        sender.handle_sack(&sack, now)?;
        now = sender.timers.get(Timer::T3RTX).unwrap();
        sender.handle_timeout(now);
        assert!(
            !sender.is_closed(),
            "a slow reader is not a failed association"
        );
    }
    assert_eq!(
        Bytes::from_static(b"full"),
        receiver
            .stream(1)?
            .read_sctp()?
            .unwrap()
            .to_payload(16)?
            .freeze()
    );
    sender.handle_sack(&receiver.create_selective_ack_chunk(), now)?;
    for data in transmitted_data(&sender.gather_outbound(now).0) {
        receiver.handle_data(&data)?;
    }
    assert_eq!(
        Bytes::from_static(b"next"),
        receiver
            .stream(1)?
            .read_sctp()?
            .unwrap()
            .to_payload(16)?
            .freeze()
    );
    Ok(())
}

#[test]
fn test_reset_bounds_old_forward_tsn_even_with_other_stream_abandonment() -> Result<()> {
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
    let at = a.timers.get(Timer::T3RTX).unwrap();
    a.handle_timeout(at);
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
fn test_invalid_reconfig_combination_has_no_partial_effects() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?;
    a.open_stream(2, ppi)?.close(now)?;
    let outgoing = reset_requests(&a.gather_outbound(now).0).remove(0);
    let timer = a.timers.get(Timer::Reconfig);
    let request = |sequence| ParamOutgoingResetRequest {
        reconfig_request_sequence_number: sequence,
        reconfig_response_sequence_number: outgoing.reconfig_request_sequence_number,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1],
    };
    let invalid = ChunkReconfig {
        param_a: Some(Box::new(request(1))),
        param_b: Some(Box::new(request(2))),
    };
    assert!(a.handle_reconfig(now, &invalid)?.is_empty());
    assert_eq!(1, a.expected_reset_sequence());
    assert!(a.stream(1).is_ok());
    assert_eq!(
        timer,
        a.timers.get(Timer::Reconfig),
        "invalid combination cannot apply E1"
    );
    Ok(())
}

#[test]
fn test_denied_local_reset_does_not_suppress_later_reciprocal() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    let mut stream = a.open_stream(1, ppi)?;
    stream.write_sctp(now, &Bytes::from_static(b"old TX epoch"), ppi)?;
    a.gather_outbound(now);
    a.handle_sack(
        &ChunkSelectiveAck {
            cumulative_tsn_ack: a.my_next_tsn.wrapping_sub(1),
            advertised_receiver_window_credit: 65536,
            ..Default::default()
        },
        now,
    )?;
    a.stream(1)?.stop(now)?;
    let outgoing = reset_requests(&a.gather_outbound(now).0).remove(0);
    receive_reset_response(&mut a, now, &outgoing, ReconfigResult::Denied)?;
    assert!(a.outgoing_reset.is_none());
    let incoming = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: outgoing.reconfig_request_sequence_number,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1],
    };
    assert_eq!(
        reconfig_results(&a.handle_reconfig(now, &reset_config(&incoming))?),
        [ReconfigResult::SuccessPerformed]
    );
    assert_eq!(
        reset_requests(&a.gather_outbound(now).0).len(),
        1,
        "a denied outgoing reset did not close TX; incoming close still needs its reciprocal"
    );
    Ok(())
}

#[test]
fn test_success_of_required_reset_does_not_bind_next_local_reset() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.stop(now)?;
    let old = reset_requests(&a.gather_outbound(now).0).remove(0);
    let incoming = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: old.reconfig_request_sequence_number,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1],
    };
    a.handle_reconfig(now, &reset_config(&incoming))?;
    assert!(matches!(
        a.outgoing_reset.as_ref().unwrap().phase,
        reset::RequestPhase::ReceiptOnly { .. }
    ));
    a.open_stream(1, ppi)?.stop(now)?;
    let retry_at = a.next_reconfig_result_retry().unwrap().1;
    a.handle_timeout(retry_at);
    let query = reset_requests(&a.gather_outbound(retry_at).0).remove(0);
    assert_eq!(
        query.reconfig_request_sequence_number,
        old.reconfig_request_sequence_number
    );
    receive_reset_response(&mut a, retry_at, &query, ReconfigResult::SuccessPerformed)?;
    let next = reset_requests(&a.gather_outbound(retry_at).0).remove(0);
    assert_eq!(
        next.reconfig_request_sequence_number,
        old.reconfig_request_sequence_number.wrapping_add(1)
    );
    receive_reset_response(&mut a, retry_at, &next, ReconfigResult::Denied)?;
    assert_eq!(
        a.state(),
        AssociationState::Established,
        "the successful M already met incoming N's reciprocal obligation; unrelated local M2 denial must not abort"
    );
    Ok(())
}

#[test]
fn test_denied_reset_after_peer_close_has_explicit_failure() -> Result<()> {
    for implicit_ack in [false, true] {
        let mut a = timed_test_association();
        let now = Instant::now();
        let ppi = PayloadProtocolIdentifier::Binary;
        a.open_stream(2, ppi)?;
        a.open_stream(1, ppi)?.stop(now)?;
        let request = reset_requests(&a.gather_outbound(now).0).remove(0);
        a.handle_reconfig(
            now,
            &reset_config(&ParamOutgoingResetRequest {
                reconfig_request_sequence_number: 1,
                reconfig_response_sequence_number: request
                    .reconfig_request_sequence_number
                    .wrapping_sub(u32::from(!implicit_ack)),
                sender_last_tsn: a.peer_last_tsn,
                stream_identifiers: vec![1],
            }),
        )?;
        let at = if implicit_ack {
            receive_reset_response(&mut a, now, &request, ReconfigResult::Denied)?;
            assert_eq!(
                a.state(),
                AssociationState::Established,
                "H1 ignores a result without its timer"
            );
            assert!(a.outgoing_reset.is_some());
            let at = a.next_reconfig_result_retry().unwrap().1;
            a.handle_timeout(at);
            assert_eq!(reset_requests(&a.gather_outbound(at).0), [request.clone()]);
            at
        } else {
            now
        };
        receive_reset_response(&mut a, at, &request, ReconfigResult::Denied)?;
        assert_eq!(a.state(), AssociationState::Closed);
        assert!(a.pending_queue.is_empty());
        assert!(a.outgoing_reset.is_none());
        assert!(a.poll_timeout().is_none());
        let packets = a.gather_outbound(at).0;
        assert!(a.is_closed());
        assert!(
            packets
                .iter()
                .flat_map(|raw| Packet::unmarshal(raw).unwrap().chunks)
                .any(|chunk| chunk.as_any().is::<ChunkAbort>())
        );
        let mut notified = false;
        while let Some(event) = a.poll() {
            notified |= matches!(
                event,
                Event::AssociationLost {
                    id: 2,
                    reason: AssociationError::TransportError
                }
            );
        }
        assert!(
            notified,
            "failure must be visible through the existing event API"
        );
    }
    Ok(())
}

#[test]
fn test_reset_result_coverage_follows_each_rx_epoch() -> Result<()> {
    for newer_peer_reset in [false, true] {
        for first_result in [ReconfigResult::SuccessPerformed, ReconfigResult::Denied] {
            for next_result in [ReconfigResult::SuccessPerformed, ReconfigResult::Denied] {
                for pending_size in [0, 4000] {
                    let mut a = timed_test_association();
                    a.cwnd = 65536;
                    let now = Instant::now();
                    let ppi = PayloadProtocolIdentifier::Binary;
                    a.open_stream(1, ppi)?
                        .write_sctp(now, &Bytes::from_static(b"old"), ppi)?;
                    a.gather_outbound(now);
                    a.handle_sack(
                        &ChunkSelectiveAck {
                            cumulative_tsn_ack: a.my_next_tsn.wrapping_sub(1),
                            advertised_receiver_window_credit: 65536,
                            ..Default::default()
                        },
                        now,
                    )?;
                    a.stream(1)?.stop(now)?;
                    let first = reset_requests(&a.gather_outbound(now).0).remove(0);
                    let incoming = ParamOutgoingResetRequest {
                        reconfig_request_sequence_number: 1,
                        reconfig_response_sequence_number: first.reconfig_request_sequence_number,
                        sender_last_tsn: a.peer_last_tsn,
                        stream_identifiers: vec![1],
                    };
                    a.handle_reconfig(now, &reset_config(&incoming))?;
                    let mut next = a.open_stream(1, ppi)?;
                    if pending_size != 0 {
                        next.write_sctp(now, &Bytes::from(vec![7; pending_size]), ppi)?;
                    }
                    next.stop(now)?;
                    if newer_peer_reset {
                        a.handle_reconfig(
                            now,
                            &reset_config(&ParamOutgoingResetRequest {
                                reconfig_request_sequence_number: 2,
                                ..incoming
                            }),
                        )?;
                    }
                    receive_reset_response(&mut a, now, &first, ReconfigResult::Denied)?;
                    assert!(a.timers.get(Timer::Reconfig).is_none());
                    let at = a.next_reconfig_result_retry().unwrap().1;
                    a.handle_timeout(at);
                    assert_eq!(reset_requests(&a.gather_outbound(at).0), [first.clone()]);
                    receive_reset_response(&mut a, at, &first, first_result)?;
                    assert_eq!(
                        a.state(),
                        AssociationState::Established,
                        "a queued later reset can still finish the close"
                    );
                    let packets = a.gather_outbound(at).0;
                    let resets = reset_requests(&packets);
                    assert_eq!(resets.len(), 1);
                    let next = &resets[0];
                    assert_eq!(
                        next.reconfig_request_sequence_number,
                        first.reconfig_request_sequence_number.wrapping_add(1)
                    );
                    let data = transmitted_data(&packets);
                    assert_eq!(
                        data.iter().map(|data| data.user_data.len()).sum::<usize>(),
                        pending_size
                    );
                    assert!(data.iter().all(|data| data.stream_sequence_number
                        == u16::from(first_result == ReconfigResult::Denied)));
                    // A result of the older request must not stop the next timer.
                    let next_timer = a.timers.get(Timer::Reconfig);
                    receive_reset_response(&mut a, at, &first, ReconfigResult::Denied)?;
                    assert_eq!(a.timers.get(Timer::Reconfig), next_timer);
                    receive_reset_response(&mut a, at, next, next_result)?;
                    let refused_required = next_result == ReconfigResult::Denied
                        && (newer_peer_reset || first_result == ReconfigResult::Denied);
                    assert_eq!(
                        a.state(),
                        if refused_required {
                            AssociationState::Closed
                        } else {
                            AssociationState::Established
                        },
                        "first={first_result:?}, next={next_result:?}, newer_peer_reset={newer_peer_reset}, bytes={pending_size}"
                    );
                    assert!(
                        reset_requests(&a.gather_outbound(at).0).is_empty(),
                        "completion must not manufacture a third reset"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_denied_old_reset_preserves_new_epoch_request() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.stop(now)?;
    let first = reset_requests(&a.gather_outbound(now).0).remove(0);
    let incoming = ParamOutgoingResetRequest {
        reconfig_request_sequence_number: 1,
        reconfig_response_sequence_number: first.reconfig_request_sequence_number,
        sender_last_tsn: a.peer_last_tsn,
        stream_identifiers: vec![1],
    };
    a.handle_reconfig(now, &reset_config(&incoming))?;
    a.open_stream(1, ppi)?.stop(now)?;
    let at = a.next_reconfig_result_retry().unwrap().1;
    a.handle_timeout(at);
    assert_eq!(reset_requests(&a.gather_outbound(at).0), [first.clone()]);
    receive_reset_response(&mut a, at, &first, ReconfigResult::Denied)?;
    let next = reset_requests(&a.gather_outbound(at).0).remove(0);
    a.handle_reconfig(
        at,
        &reset_config(&ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 2,
            ..incoming
        }),
    )?;
    receive_reset_response(&mut a, at, &next, ReconfigResult::SuccessPerformed)?;
    assert!(
        reset_requests(&a.gather_outbound(at).0).is_empty(),
        "the old refusal cannot erase the new RX epoch's already queued reset"
    );
    assert_eq!(a.state(), AssociationState::Established);
    a.open_stream(1, ppi)?.stop(at)?;
    let subsequent = reset_requests(&a.gather_outbound(at).0).remove(0);
    assert_eq!(
        subsequent.reconfig_request_sequence_number,
        first.reconfig_request_sequence_number.wrapping_add(2)
    );
    Ok(())
}

#[test]
fn test_success_before_peer_reset_does_not_bind_next_local_reset() -> Result<()> {
    let mut a = timed_test_association();
    let now = Instant::now();
    let ppi = PayloadProtocolIdentifier::Binary;
    a.open_stream(1, ppi)?.stop(now)?;
    let first = reset_requests(&a.gather_outbound(now).0).remove(0);
    receive_reset_response(&mut a, now, &first, ReconfigResult::SuccessPerformed)?;
    a.handle_reconfig(
        now,
        &reset_config(&ParamOutgoingResetRequest {
            reconfig_request_sequence_number: 1,
            reconfig_response_sequence_number: first.reconfig_request_sequence_number,
            sender_last_tsn: a.peer_last_tsn,
            stream_identifiers: vec![1],
        }),
    )?;
    assert!(reset_requests(&a.gather_outbound(now).0).is_empty());
    a.open_stream(1, ppi)?.stop(now)?;
    let next = reset_requests(&a.gather_outbound(now).0).remove(0);
    receive_reset_response(&mut a, now, &next, ReconfigResult::Denied)?;
    assert_eq!(a.state(), AssociationState::Established);
    a.stream(1)?
        .write_sctp(now, &Bytes::from_static(b"still writable"), ppi)?;
    assert_eq!(
        transmitted_data(&a.gather_outbound(now).0)[0].stream_sequence_number,
        0
    );
    Ok(())
}
