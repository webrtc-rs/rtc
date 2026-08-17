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

// `create_forward_tsn` no longer rescans the in-flight window; it emits the
// `fwd_tsn_stream_map` that the RFC 3758 C2 loops fill via
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
// SACK covers the other call site.
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

// The MTU-split rule in `bundle_data_chunks_into_packets` must bound every
// marshalled datagram: bundle decisions are made on padded wire sizes (the
// chunk header + payload, rounded up to the SCTP 4-byte boundary), never on
// raw payload sizes. These tests marshal real packets and measure the emitted
// bytes, so any accounting drift fails here rather than as silent on-path
// datagram loss.

use crate::EndpointConfig;
use crate::config::INITIAL_MTU;

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
    // `EndpointConfig::mtu(N)` promises that a single maximum-size DATA
    // chunk marshals to at most N bytes, mirroring the default derivation's
    // guarantee for INITIAL_MTU. Prove it on emitted bytes at the 32-byte
    // floor (exactly the smallest representable padded DATA packet), across
    // a 4-byte padding boundary (1201 emits 1200), and at a typical larger
    // path MTU (1500, fully used).
    for (mtu, expected) in [(32u32, 32usize), (1201, 1200), (1500, 1500)] {
        let mut config = EndpointConfig::new();
        config.mtu(mtu);
        let max_payload = config.get_max_payload_size();
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
    // `u32::MAX` — both reachable via `EndpointConfig::max_payload_size`/
    // `mtu`. RFC 4960 §7.2.1: cwnd = min(4*MTU, max(2*MTU, 4380)); for a
    // small MTU that is 4*MTU.
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
