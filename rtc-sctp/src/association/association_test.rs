use super::*;

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

#[test]
fn test_create_forward_tsn_forward_one_abandoned() -> Result<()> {
    let mut a = Association::default();

    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 10;
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 10,
        stream_identifier: 1,
        stream_sequence_number: 2,
        user_data: Bytes::from_static(b"ABC"),
        nsent: 1,
        abandoned: true,
        ..Default::default()
    });

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
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 10,
        stream_identifier: 1,
        stream_sequence_number: 2,
        user_data: Bytes::from_static(b"ABC"),
        nsent: 1,
        abandoned: true,
        ..Default::default()
    });
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 11,
        stream_identifier: 1,
        stream_sequence_number: 3,
        user_data: Bytes::from_static(b"DEF"),
        nsent: 1,
        abandoned: true,
        ..Default::default()
    });
    a.inflight_queue.push_no_check(ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        tsn: 12,
        stream_identifier: 2,
        stream_sequence_number: 1,
        user_data: Bytes::from_static(b"123"),
        nsent: 1,
        abandoned: true,
        ..Default::default()
    });

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
    let mut a = Association::default();

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
    assert_eq!(1001, a.my_max_num_outbound_streams, "{} should match", name);
    assert_eq!(1002, a.my_max_num_inbound_streams, "{} should match", name);
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

        if let Err(err) = s.write_sctp(&p.slice(..65536), ppi) {
            assert_ne!(
                Error::ErrOutboundPacketTooLarge,
                err,
                "should be not Error::ErrOutboundPacketTooLarge"
            );
        } else {
            assert!(false, "should be error");
        }

        if let Err(err) = s.write_sctp(&p.slice(..65537), ppi) {
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

        if let Err(err) = s.write_sctp(&p.slice(..30000), ppi) {
            assert_ne!(
                Error::ErrOutboundPacketTooLarge,
                err,
                "should be not Error::ErrOutboundPacketTooLarge"
            );
        } else {
            assert!(false, "should be error");
        }

        if let Err(err) = s.write_sctp(&p.slice(..30001), ppi) {
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

/// Regression test for the PR-SCTP `max_retransmits` off-by-one fix.
///
/// In production code, `nsent` is set to 1 on the initial send and incremented
/// before each retransmission, so it always represents the total number of
/// transmissions (initial + retransmissions).  `reliability_value` equals
/// `max_retransmits`, which is a *retransmission* cap (not a total-send cap).
///
/// The correct comparison is `nsent > reliability_value`:
///   - `max_retransmits=0` (fire-and-forget): abandon when nsent > 0,
///     i.e. immediately after the initial send (nsent=1).  No retransmissions.
///   - `max_retransmits=1`: abandon when nsent > 1, i.e. after the initial
///     send plus one retransmission (nsent=2).
///
/// The old `>=` comparison abandoned one send too early: with
/// `max_retransmits=1`, the chunk was abandoned at nsent=1 (the initial send),
/// preventing the one permitted retransmission.
///
/// All `nsent` values used here mirror real call-site values (nsent >= 1).
#[test]
fn test_check_partial_reliability_rexmit_boundary() {
    let now = Instant::now();
    let side = Side::Client;

    // Build a streams map with a single stream using Rexmit reliability.
    let make_streams = |reliability_value: u32| -> HashMap<u16, StreamState> {
        let mut streams = HashMap::new();
        let mut ss = StreamState::new(side, 0, 1400, PayloadProtocolIdentifier::Binary);
        ss.reliability_type = ReliabilityType::Rexmit;
        ss.reliability_value = reliability_value;
        streams.insert(0, ss);
        streams
    };

    // Helper: create a chunk with the given nsent value (mirrors production
    // where nsent is always >= 1 when check_partial_reliability_status is
    // called).
    let make_chunk = |nsent: u32| -> ChunkPayloadData {
        ChunkPayloadData {
            stream_identifier: 0,
            nsent,
            ..Default::default()
        }
    };

    // --- max_retransmits = 0 (fire-and-forget) ---
    // Abandon when nsent > 0.  The initial send (nsent=1) already exceeds the
    // limit, so the chunk is abandoned immediately -- no retransmissions.
    let streams = make_streams(0);

    // nsent=1: initial send.  1 > 0 is true → abandoned.
    let mut c = make_chunk(1);
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(
        c.abandoned,
        "max_retransmits=0, nsent=1: must abandon (fire-and-forget, no retransmissions)"
    );

    // --- max_retransmits = 1 ---
    // Abandon when nsent > 1.  The initial send is allowed, plus one
    // retransmission, so abandonment happens at nsent=2.
    let streams = make_streams(1);

    // nsent=1: initial send only.  1 > 1 is false → NOT abandoned.
    // KEY REGRESSION ASSERTION: with `>=`, this would be 1 >= 1 → true,
    // incorrectly abandoning before the permitted retransmission.
    let mut c = make_chunk(1);
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(
        !c.abandoned,
        "max_retransmits=1, nsent=1: must NOT abandon (initial send, retransmission still allowed)"
    );

    // nsent=2: initial + 1 retransmission.  2 > 1 is true → abandoned.
    let mut c = make_chunk(2);
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(
        c.abandoned,
        "max_retransmits=1, nsent=2: must abandon (retransmission limit reached)"
    );

    // --- max_retransmits = 2 ---
    // Abandon when nsent > 2.  Verify the boundary at nsent=2 and nsent=3.
    let streams = make_streams(2);

    // nsent=1: initial send.  1 > 2 is false → NOT abandoned.
    let mut c = make_chunk(1);
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(
        !c.abandoned,
        "max_retransmits=2, nsent=1: must NOT abandon (initial send)"
    );

    // nsent=2: initial + 1 retransmission.  2 > 2 is false → NOT abandoned.
    // With `>=` this would incorrectly abandon (2 >= 2).
    let mut c = make_chunk(2);
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(
        !c.abandoned,
        "max_retransmits=2, nsent=2: must NOT abandon (one more retransmission allowed)"
    );

    // nsent=3: initial + 2 retransmissions.  3 > 2 is true → abandoned.
    let mut c = make_chunk(3);
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(
        c.abandoned,
        "max_retransmits=2, nsent=3: must abandon (retransmission limit reached)"
    );
}

/// Verify that non-Rexmit reliability types and edge cases (missing stream,
/// DCEP payload) do not trigger abandonment via the Rexmit path.
#[test]
fn test_check_partial_reliability_rexmit_no_false_abandon() {
    let now = Instant::now();
    let side = Side::Client;

    // Stream with Rexmit reliability, max_retransmits = 0.
    let mut streams = HashMap::new();
    let mut ss = StreamState::new(side, 0, 1400, PayloadProtocolIdentifier::Binary);
    ss.reliability_type = ReliabilityType::Rexmit;
    ss.reliability_value = 0;
    streams.insert(0, ss);

    // DCEP chunks are never abandoned regardless of nsent.
    let mut c = ChunkPayloadData {
        stream_identifier: 0,
        nsent: 100,
        payload_type: PayloadProtocolIdentifier::Dcep,
        ..Default::default()
    };
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(
        !c.abandoned,
        "DCEP payload must never be abandoned by partial reliability"
    );

    // use_forward_tsn=false disables PR-SCTP entirely.
    let mut c = ChunkPayloadData {
        stream_identifier: 0,
        nsent: 100,
        ..Default::default()
    };
    Association::check_partial_reliability_status(&mut c, now, false, side, &streams);
    assert!(
        !c.abandoned,
        "use_forward_tsn=false: partial reliability is disabled"
    );

    // Chunk referencing a non-existent stream should not panic or abandon.
    let mut c = ChunkPayloadData {
        stream_identifier: 999,
        nsent: 100,
        ..Default::default()
    };
    Association::check_partial_reliability_status(&mut c, now, true, side, &streams);
    assert!(!c.abandoned, "missing stream must not cause abandonment");
}
