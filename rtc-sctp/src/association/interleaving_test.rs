//! RFC 8260 user message interleaving at the association level: ports of pion/sctp v1.12.0's
//! unit tests for negotiation, the I-FORWARD-TSN chunk handling, protocol violations and the
//! per-stream message identifiers.

use super::stream::{RecvSendState, ReliabilityType, StreamState};
use super::*;
use crate::chunk::chunk_i_forward_tsn::MAX_I_FORWARD_TSN_STREAMS;
use crate::config::INITIAL_MTU;
use crate::param::param_state_cookie::ParamStateCookie;

fn association_with_mtu(config: TransportConfig, mtu: u32) -> Association {
    Association::new(
        None,
        Arc::new(config),
        crate::config::max_payload_size_for_mtu(mtu),
        0,
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        SocketAddr::from_str("0.0.0.0:0").unwrap(),
        TransportProtocol::UDP,
        Instant::now(),
    )
}

fn interleaving() -> TransportConfig {
    TransportConfig::default().with_enable_interleaving(true)
}

/// The reason in the first protocol-violation ABORT queued for the peer.
fn protocol_violation_reason(a: &Association) -> Option<String> {
    for packet in &a.control_queue {
        for chunk in &packet.chunks {
            if let Some(abort) = chunk.as_any().downcast_ref::<ChunkAbort>() {
                for cause in &abort.error_causes {
                    if cause.code == PROTOCOL_VIOLATION {
                        return Some(String::from_utf8_lossy(&cause.raw).into_owned());
                    }
                }
            }
        }
    }
    None
}

fn established(mut a: Association) -> Association {
    a.set_state(AssociationState::Established);
    a
}

fn idata_chunk(mid: u32, tsn: u32, si: u16) -> ChunkPayloadData {
    ChunkPayloadData {
        idata: true,
        message_identifier: mid,
        fragment_sequence_number: 0,
        beginning_fragment: true,
        tsn,
        stream_identifier: si,
        payload_type: PayloadProtocolIdentifier::Binary,
        ..Default::default()
    }
}

#[test]
fn test_association_interleaving_updates_max_payload_size() {
    // pion: TestAssociationInterleavingUpdatesMaxPayloadSize
    let mut a = association_with_mtu(interleaving(), INITIAL_MTU);
    let plain = crate::config::max_payload_size_for_mtu(INITIAL_MTU);
    assert_eq!(1160, plain, "the default MTU leaves 1160 bytes for DATA");

    assert!(!a.use_interleaving);
    assert_eq!(plain, a.max_payload_size);

    a.peer_interleaving = true;
    a.update_interleaving_state().unwrap();
    assert!(a.use_interleaving);
    assert_eq!(
        1156, a.max_payload_size,
        "I-DATA's header is four bytes larger"
    );

    a.peer_interleaving = false;
    a.update_interleaving_state().unwrap();
    assert!(!a.use_interleaving);
    assert_eq!(plain, a.max_payload_size);
}

#[test]
fn test_association_interleaving_finalized_on_established_transition() {
    // pion: TestAssociationInterleavingFinalizedOnEstablishedTransition
    // cookie ack
    {
        let mut a = association_with_mtu(interleaving(), INITIAL_MTU);
        a.peer_interleaving = true;
        a.peer_iforward_tsn = true;
        a.set_state(AssociationState::CookieEchoed);

        a.handle_cookie_ack().unwrap();

        assert_eq!(AssociationState::Established, a.state());
        assert!(a.use_interleaving);
        assert!(a.use_iforward_tsn);
        assert!(!a.use_forward_tsn);
        assert!(matches!(a.poll(), Some(Event::Connected)));
    }
    // cookie echo
    {
        let mut a = association_with_mtu(interleaving(), INITIAL_MTU);
        a.my_cookie = Some(ParamStateCookie {
            cookie: Bytes::from_static(b"cookie"),
        });
        a.peer_interleaving = true;
        a.peer_iforward_tsn = true;
        a.set_state(AssociationState::CookieEchoed);

        let packets = a
            .handle_cookie_echo(&ChunkCookieEcho {
                cookie: Bytes::from_static(b"cookie"),
            })
            .unwrap();

        assert!(!packets.is_empty());
        assert_eq!(AssociationState::Established, a.state());
        assert!(a.use_interleaving);
        assert!(a.use_iforward_tsn);
        assert!(!a.use_forward_tsn);
        assert!(matches!(a.poll(), Some(Event::Connected)));
    }
}

#[test]
fn test_association_data_ignored_outside_receive_states_is_not_a_protocol_violation() {
    // pion: TestAssociationDataIgnoredOutsideReceiveStates concerns whether the chunk kind is
    // checked before the state; the state gate itself is covered by
    // `data_is_ignored_outside_the_receive_states`.
    let mut a = association_with_mtu(interleaving(), INITIAL_MTU);
    a.local_interleaving = true;
    a.peer_interleaving = true;
    a.use_interleaving = false;
    a.set_state(AssociationState::CookieEchoed);
    let mut d = idata_chunk(1, 1, 1);
    d.ending_fragment = true;
    d.user_data = Bytes::from_static(b"ignored");
    let packets = a.handle_data(&d).unwrap();
    assert!(packets.is_empty());
    assert!(protocol_violation_reason(&a).is_none());
}

#[test]
fn test_association_interleaving_protocol_violation_wrong_payload_chunk_type() {
    // pion: TestAssociationInterleavingProtocolViolationWrongPayloadChunkType (the unit-level
    // half; the over-the-wire half is in the endpoint tests)
    for (negotiated, idata, reason) in [
        (true, false, "received DATA with interleaving negotiated"),
        (
            false,
            true,
            "received I-DATA without interleaving negotiated",
        ),
    ] {
        let mut a = established(association_with_mtu(interleaving(), INITIAL_MTU));
        a.use_interleaving = negotiated;
        let d = ChunkPayloadData {
            idata,
            beginning_fragment: true,
            ending_fragment: true,
            tsn: 1,
            stream_identifier: 1,
            user_data: Bytes::from_static(b"bad"),
            ..Default::default()
        };
        a.handle_data(&d).unwrap();
        assert_eq!(Some(reason.to_string()), protocol_violation_reason(&a));
        assert_eq!(
            AssociationState::Closed,
            a.state(),
            "the association is torn down"
        );
    }
}

#[test]
fn test_association_interleaving_protocol_violation_wrong_forward_tsn_chunk_type() {
    // pion: TestAssociationInterleavingProtocolViolationWrongForwardTSNChunkType (unit half)
    let mut a = established(association_with_mtu(interleaving(), INITIAL_MTU));
    a.use_interleaving = true;
    a.use_iforward_tsn = true;
    a.handle_forward_tsn(&ChunkForwardTsn {
        new_cumulative_tsn: 1,
        streams: vec![ChunkForwardTsnStream {
            identifier: 1,
            sequence: 0,
        }],
    })
    .unwrap();
    assert_eq!(
        Some("received FORWARD-TSN with interleaving enabled".to_string()),
        protocol_violation_reason(&a)
    );

    let mut a = established(association_with_mtu(
        TransportConfig::default(),
        INITIAL_MTU,
    ));
    a.handle_i_forward_tsn(&ChunkIForwardTsn {
        new_cumulative_tsn: 1,
        streams: vec![ChunkIForwardTsnStream {
            identifier: 1,
            unordered: false,
            message_identifier: 0,
        }],
    })
    .unwrap();
    assert_eq!(
        Some("received I-FORWARD-TSN without support".to_string()),
        protocol_violation_reason(&a)
    );
}

#[test]
fn test_association_i_forward_tsn_validation_abort() {
    // pion: TestAssociationIForwardTSNValidationAbort
    let mut a = established(association_with_mtu(
        TransportConfig::default(),
        INITIAL_MTU,
    ));
    a.use_iforward_tsn = true;

    let streams = (0..=MAX_I_FORWARD_TSN_STREAMS)
        .map(|i| ChunkIForwardTsnStream {
            identifier: i as u16,
            unordered: false,
            message_identifier: i as u32,
        })
        .collect();
    let chunk: Box<dyn Chunk> = Box::new(ChunkIForwardTsn {
        new_cumulative_tsn: 1,
        streams,
    });
    let packet = Packet::default();
    a.handle_chunk(&packet, &chunk, Instant::now()).unwrap();

    let reason = protocol_violation_reason(&a)
        .expect("association should send an abort on invalid I-FORWARD-TSN");
    assert!(
        reason.contains("i-forward-tsn chunk contains too many streams"),
        "{reason}"
    );
}

#[test]
fn test_association_i_forward_tsn_duplicate_entries_use_largest_mid() {
    // pion: TestAssociationIForwardTSNDuplicateEntriesUseLargestMID
    let mut a = established(association_with_mtu(
        TransportConfig::default(),
        INITIAL_MTU,
    ));
    a.use_iforward_tsn = true;

    let si = 1;
    assert!(
        a.create_stream(si, false, PayloadProtocolIdentifier::Unknown)
            .is_some()
    );
    for (mid, tsn, data) in [(2, 10, "MID2"), (3, 11, "MID3")] {
        let mut c = idata_chunk(mid, tsn, si);
        c.user_data = Bytes::copy_from_slice(data.as_bytes());
        let queue = &mut a.streams.get_mut(&si).unwrap().reassembly_queue;
        assert!(!queue.push(c));
    }

    let chunk = ChunkIForwardTsn {
        new_cumulative_tsn: a.peer_last_tsn.wrapping_add(1),
        streams: vec![
            ChunkIForwardTsnStream {
                identifier: si,
                unordered: false,
                message_identifier: 2,
            },
            ChunkIForwardTsnStream {
                identifier: si,
                unordered: false,
                message_identifier: 3,
            },
        ],
    };
    a.handle_i_forward_tsn(&chunk).unwrap();

    assert!(
        protocol_violation_reason(&a).is_none(),
        "duplicate I-FORWARD-TSN entries should not abort"
    );
    assert_eq!(
        vec![ChunkIForwardTsnStream {
            identifier: si,
            unordered: false,
            message_identifier: 3,
        }],
        normalize_i_forward_tsn_streams(&chunk.streams).into_owned()
    );
    let queue = &a.streams[&si].reassembly_queue;
    assert_eq!(4, queue.next_mid, "largest duplicate MID should be applied");
    assert!(
        queue.ordered_mids().is_empty(),
        "forwarded incomplete MIDs should be removed"
    );
    assert_eq!(
        0,
        queue.get_num_bytes(),
        "forwarded bytes should be removed"
    );
}

fn reassembly_limit_association(limit: Option<u32>, interleaved: bool) -> Association {
    let config = match limit {
        Some(limit) => TransportConfig::default().with_max_reassembly_queue_entries(limit),
        None => TransportConfig::default(),
    };
    let mut a = established(association_with_mtu(config, INITIAL_MTU));
    a.use_interleaving = interleaved;
    a.peer_last_tsn = 0;
    a
}

#[test]
fn test_association_interleaving_protocol_violation_mid_limit() {
    // pion: TestAssociationInterleavingProtocolViolationMIDLimit
    const LIMIT: u32 = 3;
    let mut a = reassembly_limit_association(Some(LIMIT), true);

    for i in 0..LIMIT {
        let packets = a.handle_data(&idata_chunk(i, i + 1, 1)).unwrap();
        assert!(packets.is_empty());
        assert!(
            protocol_violation_reason(&a).is_none(),
            "association should remain open below the MID limit"
        );
    }

    let packets = a.handle_data(&idata_chunk(LIMIT, LIMIT + 1, 1)).unwrap();
    assert!(packets.is_empty());
    assert_eq!(
        Some("reassembly queue i-data message identifier limit exceeded".to_string()),
        protocol_violation_reason(&a),
        "association should abort on a new MID over the limit"
    );
}

#[test]
fn test_association_interleaving_mid_limit_disabled_by_default() {
    // pion: TestAssociationInterleavingMIDLimitDisabledByDefault
    const OLD_LIMIT: u32 = 3;
    let mut a = reassembly_limit_association(None, true);
    for i in 0..=OLD_LIMIT {
        let packets = a.handle_data(&idata_chunk(i, i + 1, 1)).unwrap();
        assert!(packets.is_empty());
        assert!(
            protocol_violation_reason(&a).is_none(),
            "association should not abort when the MID limit is disabled"
        );
    }
}

#[test]
fn test_association_data_reassembly_limit_protocol_violation() {
    // pion: TestAssociationDataReassemblyLimitProtocolViolation
    const LIMIT: u32 = 3;
    let mut a = reassembly_limit_association(Some(LIMIT), false);
    let data = |ssn: u16, tsn: u32| ChunkPayloadData {
        stream_sequence_number: ssn,
        beginning_fragment: true,
        tsn,
        stream_identifier: 1,
        payload_type: PayloadProtocolIdentifier::Binary,
        ..Default::default()
    };

    for i in 0..LIMIT {
        let packets = a.handle_data(&data(i as u16, i + 1)).unwrap();
        assert!(packets.is_empty());
        assert!(
            protocol_violation_reason(&a).is_none(),
            "association should remain open below the DATA limit"
        );
    }
    let packets = a.handle_data(&data(LIMIT as u16, LIMIT + 1)).unwrap();
    assert!(packets.is_empty());
    assert_eq!(
        Some("reassembly queue data limit exceeded".to_string()),
        protocol_violation_reason(&a),
        "association should abort on a new DATA entry over the limit"
    );
}

#[test]
fn test_create_i_forward_tsn() {
    // pion: TestCreateIForwardTSN. The sender keeps the greatest abandoned MID per (stream,
    // ordered/unordered) as chunks are abandoned (`note_abandoned_for_i_forward_tsn`, the
    // I-DATA counterpart of the RFC 3758 C2 loops) rather than rescanning the in-flight
    // window, so the tests drive that same entry point.
    let mut a = Association::default();
    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 10;
    a.note_abandoned_for_i_forward_tsn(false, 1, 2); // tsn=10
    let fwdtsn = a.create_i_forward_tsn();
    assert_eq!(
        10, fwdtsn.new_cumulative_tsn,
        "should set new cumulative TSN"
    );
    assert_eq!(
        vec![ChunkIForwardTsnStream {
            identifier: 1,
            unordered: false,
            message_identifier: 2,
        }],
        fwdtsn.streams,
        "should report the abandoned ordered MID"
    );

    let mut a = Association::default();
    a.cumulative_tsn_ack_point = 9;
    a.advanced_peer_tsn_ack_point = 14;
    a.note_abandoned_for_i_forward_tsn(false, 1, 2); // tsn=10
    a.note_abandoned_for_i_forward_tsn(false, 1, 4); // tsn=11
    a.note_abandoned_for_i_forward_tsn(true, 1, 3); // tsn=12
    a.note_abandoned_for_i_forward_tsn(true, 1, 5); // tsn=13
    a.note_abandoned_for_i_forward_tsn(false, 2, 1); // tsn=14
    let fwdtsn = a.create_i_forward_tsn();
    assert_eq!(
        14, fwdtsn.new_cumulative_tsn,
        "should set new cumulative TSN"
    );
    // RFC 8260 gives I-FORWARD TSN entries an ordered flag, so the FORWARD TSN exclusion of
    // unordered streams does not apply.
    let mut streams = fwdtsn.streams.clone();
    streams.sort_by_key(|s| (s.identifier, s.unordered));
    assert_eq!(
        vec![
            ChunkIForwardTsnStream {
                identifier: 1,
                unordered: false,
                message_identifier: 4,
            },
            ChunkIForwardTsnStream {
                identifier: 1,
                unordered: true,
                message_identifier: 5,
            },
            ChunkIForwardTsnStream {
                identifier: 2,
                unordered: false,
                message_identifier: 1,
            },
        ],
        streams,
        "should report the highest MID per stream and ordering"
    );
}

#[test]
fn test_handle_i_forward_tsn() {
    // pion: TestHandleIForwardTSN
    // forward ordered and unordered mids for named streams
    {
        let mut a = Association::default();
        a.use_iforward_tsn = true;
        let prev_tsn = a.peer_last_tsn;

        for si in 0..3 {
            assert!(
                a.create_stream(si, false, PayloadProtocolIdentifier::Unknown)
                    .is_some()
            );
        }
        let frag = |si: u16, unordered: bool, mid: u32, tsn: u32, end: bool, data: &'static str| {
            let mut c = idata_chunk(mid, tsn, si);
            c.unordered = unordered;
            c.ending_fragment = end;
            c.user_data = Bytes::from_static(data.as_bytes());
            c
        };
        let push = |a: &mut Association, c: ChunkPayloadData, complete: bool| {
            let si = c.stream_identifier;
            let q = &mut a.streams.get_mut(&si).unwrap().reassembly_queue;
            assert_eq!(complete, q.push(c));
        };
        push(&mut a, frag(0, false, 0, 10, true, "OK"), true);
        push(&mut a, frag(0, false, 1, 11, false, "DROP"), false);
        push(&mut a, frag(1, true, 1, 20, true, "old"), true);
        push(&mut a, frag(1, true, 2, 21, false, "drop"), false);
        push(&mut a, frag(1, true, 4, 22, true, "keep"), true);
        push(&mut a, frag(1, true, 5, 23, false, "later"), false);
        push(&mut a, frag(2, false, 1, 30, false, "stay"), false);

        let pack = a
            .handle_i_forward_tsn(&ChunkIForwardTsn {
                new_cumulative_tsn: prev_tsn + 1,
                streams: vec![
                    ChunkIForwardTsnStream {
                        identifier: 0,
                        unordered: false,
                        message_identifier: 1,
                    },
                    ChunkIForwardTsnStream {
                        identifier: 1,
                        unordered: true,
                        message_identifier: 2,
                    },
                ],
            })
            .unwrap();

        assert_eq!(
            prev_tsn + 1,
            a.peer_last_tsn,
            "peer_last_tsn should advance by 1"
        );
        assert!(a.delayed_ack_triggered, "delayed sack should be triggered");
        assert!(
            !a.immediate_ack_triggered,
            "immediate sack should NOT be triggered"
        );
        assert!(pack.is_empty(), "should return empty");

        let ordered = &a.streams[&0].reassembly_queue;
        assert_eq!(2, ordered.next_mid, "next MID should advance");
        assert_eq!(
            vec![0],
            ordered.ordered_mids(),
            "only the complete ordered MID should remain"
        );
        assert_eq!(
            2,
            ordered.get_num_bytes(),
            "only the kept ordered MID bytes should remain"
        );
        assert!(
            ordered.is_readable(),
            "kept ordered MID should remain readable"
        );

        let unordered = &a.streams[&1].reassembly_queue;
        assert_eq!(
            vec![1, 4],
            unordered.unordered_ready_mids(),
            "should keep complete unordered MIDs"
        );
        assert_eq!(
            vec![5],
            unordered.unordered_open_mids(),
            "should only keep newer incomplete unordered MID"
        );
        assert_eq!(
            12,
            unordered.get_num_bytes(),
            "only incomplete forwarded unordered MID bytes should be removed"
        );
        assert!(
            unordered.is_readable(),
            "complete unordered MID should remain readable"
        );

        let untouched = &a.streams[&2].reassembly_queue;
        assert_eq!(
            vec![1],
            untouched.ordered_mids(),
            "unmentioned stream should not be touched"
        );
        assert_eq!(
            0, untouched.next_mid,
            "unmentioned stream next_mid should not advance"
        );
        assert_eq!(
            4,
            untouched.get_num_bytes(),
            "unmentioned stream bytes should be unchanged"
        );
    }

    // dup i-forward tsn chunk should generate sack
    {
        let mut a = Association::default();
        a.use_iforward_tsn = true;
        let prev_tsn = a.peer_last_tsn;
        let pack = a
            .handle_i_forward_tsn(&ChunkIForwardTsn {
                new_cumulative_tsn: prev_tsn,
                streams: vec![ChunkIForwardTsnStream {
                    identifier: 0,
                    unordered: false,
                    message_identifier: 1,
                }],
            })
            .unwrap();
        assert_eq!(
            prev_tsn, a.peer_last_tsn,
            "peer_last_tsn should not advance"
        );
        assert_eq!(AckState::Immediate, a.ack_state, "sack should be requested");
        assert!(pack.is_empty(), "should return empty");
    }

    // far i-forward tsn advances in bounded time
    {
        let mut a = Association::default();
        a.use_iforward_tsn = true;
        let prev_tsn = a.peer_last_tsn;
        let new_cumulative_tsn = prev_tsn.wrapping_add((1 << 31) - 1);
        a.payload_queue.push(
            ChunkPayloadData {
                tsn: prev_tsn + 2,
                ..Default::default()
            },
            prev_tsn,
        );

        let started = std::time::Instant::now();
        let pack = a
            .handle_i_forward_tsn(&ChunkIForwardTsn {
                new_cumulative_tsn,
                streams: vec![ChunkIForwardTsnStream {
                    identifier: 0,
                    unordered: false,
                    message_identifier: 1,
                }],
            })
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the cumulative TSN must jump, not walk"
        );
        assert_eq!(
            new_cumulative_tsn, a.peer_last_tsn,
            "peer_last_tsn should advance"
        );
        assert!(
            a.payload_queue.is_empty(),
            "payload queue should be cleared"
        );
        assert!(pack.is_empty(), "should return empty");
    }
}

#[test]
fn test_handle_forward_tsn_far_forward_advances_in_bounded_time() {
    // pion: TestHandleForwardTSN/"far forward tsn advances in bounded time"
    let mut a = Association::default();
    a.use_forward_tsn = true;
    let prev_tsn = a.peer_last_tsn;
    let new_cumulative_tsn = prev_tsn.wrapping_add((1 << 31) - 1);
    a.payload_queue.push(
        ChunkPayloadData {
            tsn: prev_tsn + 2,
            ..Default::default()
        },
        prev_tsn,
    );

    let started = std::time::Instant::now();
    let pack = a
        .handle_forward_tsn(&ChunkForwardTsn {
            new_cumulative_tsn,
            streams: vec![ChunkForwardTsnStream {
                identifier: 0,
                sequence: 1,
            }],
        })
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        new_cumulative_tsn, a.peer_last_tsn,
        "peer_last_tsn should advance"
    );
    assert!(
        a.payload_queue.is_empty(),
        "payload queue should be cleared"
    );
    assert!(pack.is_empty(), "should return empty");
}

#[test]
fn test_stream_packetize_interleaving_mid_allocation() {
    // pion: TestStreamPacketizeInterleavingMIDAllocation
    let mut s = StreamState::new(Side::Client, 0, 3, PayloadProtocolIdentifier::Unknown);
    s.use_idata = true;
    s.unordered = true;
    let now = Instant::now();

    let (_, chunks) = s.packetize(
        now,
        &Bytes::from_static(b"abcdef"),
        PayloadProtocolIdentifier::Binary,
    );
    assert_eq!(2, chunks.len());
    assert!(chunks[0].beginning_fragment && !chunks[0].ending_fragment);
    assert!(!chunks[1].beginning_fragment && chunks[1].ending_fragment);
    for (i, c) in chunks.iter().enumerate() {
        assert!(c.idata);
        assert!(c.unordered);
        assert_eq!(0, c.message_identifier);
        assert_eq!(i as u32, c.fragment_sequence_number);
        assert_eq!(0, c.stream_sequence_number);
    }

    let (_, chunks) = s.packetize(
        now,
        &Bytes::from_static(b"xy"),
        PayloadProtocolIdentifier::Binary,
    );
    assert_eq!(1, chunks.len());
    assert!(chunks[0].idata && chunks[0].unordered);
    assert_eq!(1, chunks[0].message_identifier);
    assert_eq!(1, chunks[0].stream_sequence_number);

    // DCEP is always ordered, whatever the stream says.
    let (_, chunks) = s.packetize(
        now,
        &Bytes::from_static(b"hi"),
        PayloadProtocolIdentifier::Dcep,
    );
    assert_eq!(1, chunks.len());
    assert!(chunks[0].idata && !chunks[0].unordered);
    assert_eq!(0, chunks[0].message_identifier);
    assert_eq!(0, chunks[0].stream_sequence_number);

    let (_, chunks) = s.packetize(
        now,
        &Bytes::from_static(b"ok"),
        PayloadProtocolIdentifier::Dcep,
    );
    assert_eq!(1, chunks.len());
    assert!(chunks[0].idata && !chunks[0].unordered);
    assert_eq!(1, chunks[0].message_identifier);
    assert_eq!(1, chunks[0].stream_sequence_number);

    assert_eq!(0, s.sequence_number, "interleaving should not advance SSN");
    assert_eq!(2, s.next_ordered_mid, "ordered MID counter mismatch");
    assert_eq!(2, s.next_unordered_mid, "unordered MID counter mismatch");
}

#[test]
fn test_stream_write_leaves_interleaving_mids_untouched_on_send_error() {
    // pion: TestStreamWriteSCTPRollsBackInterleavingMIDsOnSendError. A write on an association
    // that cannot send fails before any identifier is taken, so there is nothing to roll back.
    for (ppi, unordered) in [
        (PayloadProtocolIdentifier::Dcep, false),
        (PayloadProtocolIdentifier::Binary, true),
    ] {
        let mut a = association_with_mtu(interleaving(), INITIAL_MTU);
        a.peer_interleaving = true;
        a.update_interleaving_state().unwrap();
        a.set_state(AssociationState::ShutdownPending);
        let mut stream = a
            .create_stream(0, false, PayloadProtocolIdentifier::Binary)
            .unwrap();
        stream
            .set_reliability_params(unordered, ReliabilityType::Reliable, 0)
            .unwrap();
        let err = stream
            .write_sctp(Instant::now(), &Bytes::from_static(b"test"), ppi)
            .unwrap_err();
        assert_eq!(Error::ErrStreamClosed, err);
        let s = &a.streams[&0];
        assert_eq!(0, s.sequence_number);
        assert_eq!(0, s.next_ordered_mid);
        assert_eq!(0, s.next_unordered_mid);
        assert_eq!(0, s.buffered_amount);
        assert_eq!(RecvSendState::ReadWritable, s.state);
    }

    // And the same before the association is established at all.
    let mut a = association_with_mtu(interleaving(), INITIAL_MTU);
    a.peer_interleaving = true;
    a.update_interleaving_state().unwrap();
    let mut stream = a
        .create_stream(0, false, PayloadProtocolIdentifier::Binary)
        .unwrap();
    let err = stream
        .write_sctp(
            Instant::now(),
            &Bytes::from_static(b"test"),
            PayloadProtocolIdentifier::Dcep,
        )
        .unwrap_err();
    assert_eq!(Error::ErrPayloadDataStateNotExist, err);
    let s = &a.streams[&0];
    assert_eq!(
        (0, 0, 0, 0),
        (
            s.sequence_number,
            s.next_ordered_mid,
            s.next_unordered_mid,
            s.buffered_amount
        )
    );
}

#[test]
fn test_stream_handle_forward_tsn_for_mid() {
    // pion: TestStreamHandleForwardTSNForMID
    let ppi = PayloadProtocolIdentifier::Binary;
    let chunk = |mid, tsn, unordered, end, data: &'static str| ChunkPayloadData {
        idata: true,
        unordered,
        message_identifier: mid,
        beginning_fragment: true,
        ending_fragment: end,
        tsn,
        stream_identifier: 0,
        payload_type: ppi,
        user_data: Bytes::from_static(data.as_bytes()),
        ..Default::default()
    };

    // ordered MID forward makes next complete message readable
    {
        let mut a = Association::default();
        a.create_stream(0, false, ppi).unwrap();
        let s = a.streams.get_mut(&0).unwrap();
        assert!(
            !s.handle_data(&chunk(0, 10, false, false, "DROP")).unwrap(),
            "MID 0 should remain incomplete"
        );
        assert!(
            s.handle_data(&chunk(1, 11, false, true, "OK")).unwrap(),
            "MID 1 should be complete"
        );
        assert!(
            !s.reassembly_queue.is_readable(),
            "MID 1 should be blocked by missing MID 0"
        );

        s.handle_forward_tsn_for_ordered_mid(0);
        assert!(
            s.reassembly_queue.is_readable(),
            "forwarded MID should expose the next complete message"
        );

        let mut stream = a.stream(0).unwrap();
        let chunks = stream.read_sctp().unwrap().unwrap();
        let mut buf = vec![0u8; 4];
        let n = chunks.read(&mut buf).unwrap();
        assert_eq!(b"OK", &buf[..n]);
        assert_eq!(ppi, chunks.ppi, "should preserve payload type");
        let s = &a.streams[&0];
        assert_eq!(
            2, s.reassembly_queue.next_mid,
            "next MID should stay advanced after read"
        );
        assert_eq!(
            0,
            s.get_num_bytes_in_reassembly_queue(),
            "queue should be empty after read"
        );
    }

    // unordered MID forward keeps complete data and drops old incomplete message
    {
        let mut a = Association::default();
        a.create_stream(0, false, ppi).unwrap();
        let s = a.streams.get_mut(&0).unwrap();
        assert!(s.handle_data(&chunk(1, 10, true, true, "old")).unwrap());
        assert!(!s.handle_data(&chunk(2, 11, true, false, "drop")).unwrap());
        assert!(s.handle_data(&chunk(4, 12, true, true, "keep")).unwrap());
        assert!(!s.handle_data(&chunk(5, 13, true, false, "later")).unwrap());

        s.handle_forward_tsn_for_unordered_mid(2);
        assert_eq!(
            vec![1, 4],
            s.reassembly_queue.unordered_ready_mids(),
            "complete MIDs should remain queued"
        );
        assert_eq!(
            vec![5],
            s.reassembly_queue.unordered_open_mids(),
            "only newer incomplete MID should remain"
        );
        assert_eq!(12, s.get_num_bytes_in_reassembly_queue());
        assert!(
            s.reassembly_queue.is_readable(),
            "complete MID should stay readable"
        );

        let mut buf = vec![0u8; 8];
        let mut stream = a.stream(0).unwrap();
        let chunks = stream.read_sctp().unwrap().unwrap();
        let n = chunks.read(&mut buf).unwrap();
        assert_eq!(b"old", &buf[..n]);
        assert_eq!(9, a.streams[&0].get_num_bytes_in_reassembly_queue());
        assert!(a.streams[&0].reassembly_queue.is_readable());

        let mut stream = a.stream(0).unwrap();
        let chunks = stream.read_sctp().unwrap().unwrap();
        let n = chunks.read(&mut buf).unwrap();
        assert_eq!(b"keep", &buf[..n]);
        assert_eq!(5, a.streams[&0].get_num_bytes_in_reassembly_queue());
        assert!(!a.streams[&0].reassembly_queue.is_readable());
    }
}
