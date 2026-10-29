//! User message interleaving (RFC 8260) between two real associations: negotiation, I-DATA on
//! the wire, interleaved large messages, loss recovery and partial reliability over
//! I-FORWARD-TSN.

use super::*;
use crate::chunk::Chunk;
use crate::chunk::chunk_i_forward_tsn::ChunkIForwardTsn;
use crate::chunk::chunk_type::*;
use crate::param::param_supported_extensions::ParamSupportedExtensions;
use crate::util::{sna32gt, sna32lt};
use crate::{PartialReliabilityMode, StreamScheduler};
use std::num::NonZeroU16;

fn interleaving_config(enabled: bool) -> TransportConfig {
    TransportConfig::default().with_enable_interleaving(enabled)
}

fn pair_with(
    client: TransportConfig,
    server: TransportConfig,
) -> (Pair, AssociationHandle, AssociationHandle) {
    let mut pair = Pair::new(
        EndpointConfig::default(),
        ServerConfig {
            transport: Arc::new(server),
            ..Default::default()
        },
    );
    let (client_ch, server_ch) = pair.connect_with(ClientConfig {
        transport: Arc::new(client),
    });
    pair.client_conn_mut(client_ch).ack_mode = AckMode::NoDelay;
    pair.server_conn_mut(server_ch).ack_mode = AckMode::NoDelay;
    (pair, client_ch, server_ch)
}

fn chunks_of(wire: &[Bytes]) -> Vec<Box<dyn Chunk>> {
    let mut chunks = vec![];
    for raw in wire {
        let packet = Packet::unmarshal(raw).expect("every datagram on the wire parses");
        chunks.extend(packet.chunks);
    }
    chunks
}

fn data_chunks_of(wire: &[Bytes]) -> Vec<ChunkPayloadData> {
    chunks_of(wire)
        .iter()
        .filter_map(|c| c.as_any().downcast_ref::<ChunkPayloadData>().cloned())
        .collect()
}

fn chunk_type_counts(wire: &[Bytes]) -> HashMap<u8, usize> {
    let mut counts = HashMap::new();
    for c in chunks_of(wire) {
        *counts.entry(c.header().typ.0).or_default() += 1;
    }
    counts
}

/// Open stream `si` from the client and complete the DCEP-less open handshake.
fn open_stream(
    pair: &mut Pair,
    client_ch: AssociationHandle,
    server_ch: AssociationHandle,
    si: u16,
) {
    establish_session_pair(pair, client_ch, server_ch, si).unwrap();
}

fn write(pair: &mut Pair, ch: AssociationHandle, si: u16, data: &Bytes) {
    let now = pair.time;
    let n = pair
        .client_stream(ch, si)
        .unwrap()
        .write_sctp(now, data, PayloadProtocolIdentifier::Binary)
        .unwrap();
    assert_eq!(data.len(), n);
}

fn pattern(len: usize, seed: u8) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect::<Vec<u8>>(),
    )
}

fn read_message(pair: &mut Pair, ch: AssociationHandle, si: u16) -> Option<Bytes> {
    let chunks = pair.server_stream(ch, si).unwrap().read_sctp().unwrap()?;
    Some(chunks.to_payload(usize::MAX).unwrap().freeze())
}

#[test]
fn interleaving_is_negotiated_only_when_both_sides_offer_it() {
    // pion: TestAssociationInterleavingNegotiationPayloadChunkType
    for (client, server) in [(true, true), (true, false), (false, true), (false, false)] {
        let (mut pair, client_ch, server_ch) =
            pair_with(interleaving_config(client), interleaving_config(server));
        let expect = client && server;

        let metadata = pair.client_conn_mut(client_ch).metadata().unwrap();
        assert_eq!(expect, metadata.message_interleaving_enabled);
        assert_eq!(
            if expect {
                PartialReliabilityMode::IForwardTsn
            } else {
                PartialReliabilityMode::ForwardTsn
            },
            metadata.partial_reliability_mode
        );
        assert_eq!(Some(metadata), pair.server_conn_mut(server_ch).metadata());
        let assoc = pair.client_conn_mut(client_ch);
        assert_eq!(
            expect, assoc.use_interleaving,
            "client={client} server={server}"
        );
        assert_eq!(expect, assoc.use_iforward_tsn, "i-forward-tsn");
        assert_eq!(!expect, assoc.use_forward_tsn, "forward-tsn");
        let server_assoc = pair.server_conn_mut(server_ch);
        assert_eq!(expect, server_assoc.use_interleaving);
        assert_eq!(expect, server_assoc.use_iforward_tsn);
        assert_eq!(!expect, server_assoc.use_forward_tsn);

        let si = 1;
        open_stream(&mut pair, client_ch, server_ch, si);
        pair.client_wire.clear();
        write(&mut pair, client_ch, si, &Bytes::from_static(b"ABC"));
        pair.drive();

        let data = data_chunks_of(&pair.client_wire);
        assert_eq!(1, data.len());
        assert_eq!(expect, data[0].idata, "client={client} server={server}");
        let counts = chunk_type_counts(&pair.client_wire);
        let (i, plain) = (
            counts.get(&CT_IDATA.0).copied().unwrap_or(0),
            counts.get(&CT_PAYLOAD_DATA.0).copied().unwrap_or(0),
        );
        assert_eq!((expect as usize, !expect as usize), (i, plain));

        assert_eq!(
            Some(Bytes::from_static(b"ABC")),
            read_message(&mut pair, server_ch, si)
        );
    }
}

#[test]
fn interleaving_is_off_by_default_and_the_init_does_not_offer_it() {
    // A default configuration must look exactly as it did before I-DATA existed: browsers see
    // no new chunk types in the supported-extensions list.
    let (pair, _, _) = pair_with(TransportConfig::default(), TransportConfig::default());
    for wire in [&pair.client_wire, &pair.server_wire] {
        for c in chunks_of(wire) {
            if let Some(init) = c.as_any().downcast_ref::<ChunkInit>() {
                for p in &init.params {
                    if let Some(ext) = p.as_any().downcast_ref::<ParamSupportedExtensions>() {
                        assert!(!ext.chunk_types.contains(&CT_IDATA));
                        assert!(!ext.chunk_types.contains(&CT_IFORWARD_TSN));
                    }
                }
            }
        }
    }
}

#[test]
fn interleaving_offer_lists_i_data_and_i_forward_tsn() {
    let (pair, _, _) = pair_with(interleaving_config(true), interleaving_config(true));
    let mut offers = 0;
    for wire in [&pair.client_wire, &pair.server_wire] {
        for c in chunks_of(wire) {
            if let Some(init) = c.as_any().downcast_ref::<ChunkInit>() {
                for p in &init.params {
                    if let Some(ext) = p.as_any().downcast_ref::<ParamSupportedExtensions>() {
                        assert!(ext.chunk_types.contains(&CT_IDATA));
                        assert!(ext.chunk_types.contains(&CT_IFORWARD_TSN));
                        assert!(ext.chunk_types.contains(&CT_FORWARD_TSN));
                        assert!(ext.chunk_types.contains(&CT_RECONFIG));
                        offers += 1;
                    }
                }
            }
        }
    }
    assert_eq!(2, offers, "one INIT and one INIT ACK");
}

#[test]
fn interleaving_shrinks_the_payload_budget_by_the_larger_header() {
    // pion: TestAssociationInterleavingUpdatesMaxPayloadSize
    let (mut pair, client_ch, _) = pair_with(interleaving_config(true), interleaving_config(true));
    let on = pair.client_conn_mut(client_ch).max_payload_size;
    let (mut pair, client_ch, _) =
        pair_with(TransportConfig::default(), TransportConfig::default());
    let off = pair.client_conn_mut(client_ch).max_payload_size;
    assert_eq!(off - 4, on);
    // The wire size of a full chunk is the same either way, so the MTU bound still holds.
    let data = |idata: bool, len: usize| ChunkPayloadData {
        beginning_fragment: true,
        ending_fragment: true,
        idata,
        user_data: Bytes::from(vec![0; len]),
        ..Default::default()
    };
    assert_eq!(
        data(false, off as usize).wire_size(),
        data(true, on as usize).wire_size()
    );
}

#[test]
fn large_messages_interleave_across_streams() {
    for scheduler in [
        StreamScheduler::RoundRobin,
        StreamScheduler::WeightedFairQueueing,
    ] {
        let config = || interleaving_config(true).with_stream_scheduler(scheduler);
        let (mut pair, client_ch, server_ch) = pair_with(config(), config());
        for si in [1, 2, 3] {
            open_stream(&mut pair, client_ch, server_ch, si);
        }
        pair.client_wire.clear();

        let big = pattern(200_000, 1);
        let small_a = pattern(300, 2);
        let small_b = pattern(5_000, 3);
        let other_big = pattern(80_000, 4);
        write(&mut pair, client_ch, 1, &big);
        write(&mut pair, client_ch, 2, &small_a);
        write(&mut pair, client_ch, 2, &small_b);
        write(&mut pair, client_ch, 3, &other_big);
        pair.drive();

        assert_eq!(Some(big.clone()), read_message(&mut pair, server_ch, 1));
        assert_eq!(Some(small_a.clone()), read_message(&mut pair, server_ch, 2));
        assert_eq!(Some(small_b.clone()), read_message(&mut pair, server_ch, 2));
        assert_eq!(
            Some(other_big.clone()),
            read_message(&mut pair, server_ch, 3)
        );

        let data = data_chunks_of(&pair.client_wire);
        assert!(data.iter().all(|c| c.idata));
        let mut tsns: Vec<u32> = data.iter().map(|c| c.tsn).collect();
        tsns.dedup();
        let last_of_big = data
            .iter()
            .filter(|c| c.stream_identifier == 1 && c.ending_fragment)
            .map(|c| c.tsn)
            .next()
            .unwrap();
        let first_small = data
            .iter()
            .filter(|c| c.stream_identifier == 2)
            .map(|c| c.tsn)
            .min()
            .unwrap();
        assert!(
            sna32lt(first_small, last_of_big),
            "{scheduler:?}: the small message must not wait for the whole large one \
             (small tsn {first_small}, large message ends at {last_of_big})"
        );

        // Identifiers and fragment numbers: per stream, per message, counted from zero.
        for si in [1u16, 2, 3] {
            let mut mids: Vec<u32> = data
                .iter()
                .filter(|c| c.stream_identifier == si && c.beginning_fragment)
                .map(|c| c.message_identifier)
                .collect();
            mids.sort_unstable();
            // The open handshake wrote message 0 (before the capture started).
            assert_eq!(
                (1..=mids.len() as u32).collect::<Vec<_>>(),
                mids,
                "stream {si}"
            );
            for mid in mids {
                let mut fsns: Vec<u32> = data
                    .iter()
                    .filter(|c| c.stream_identifier == si && c.message_identifier == mid)
                    .map(|c| c.fragment_sequence_number)
                    .collect();
                fsns.sort_unstable();
                assert_eq!((0..fsns.len() as u32).collect::<Vec<_>>(), fsns);
            }
        }
    }
}

#[test]
fn without_interleaving_a_large_message_holds_up_the_small_one() {
    // The behaviour interleaving exists to fix, pinned so the test above means something.
    let (mut pair, client_ch, server_ch) =
        pair_with(TransportConfig::default(), TransportConfig::default());
    for si in [1, 2] {
        open_stream(&mut pair, client_ch, server_ch, si);
    }
    pair.client_wire.clear();
    write(&mut pair, client_ch, 1, &pattern(200_000, 1));
    write(&mut pair, client_ch, 2, &pattern(300, 2));
    pair.drive();
    let data = data_chunks_of(&pair.client_wire);
    let last_of_big = data
        .iter()
        .filter(|c| c.stream_identifier == 1 && c.ending_fragment)
        .map(|c| c.tsn)
        .next()
        .unwrap();
    let first_small = data
        .iter()
        .filter(|c| c.stream_identifier == 2)
        .map(|c| c.tsn)
        .min()
        .unwrap();
    assert!(sna32gt(first_small, last_of_big));
}

#[test]
fn weighted_fair_queueing_gives_heavier_streams_more_of_the_wire() {
    let config = || {
        interleaving_config(true)
            .with_stream_scheduler_weight(1, NonZeroU16::new(3).unwrap())
            .with_stream_scheduler_weight(2, NonZeroU16::new(1).unwrap())
    };
    let (mut pair, client_ch, server_ch) = pair_with(config(), config());
    for si in [1, 2] {
        open_stream(&mut pair, client_ch, server_ch, si);
    }
    pair.client_wire.clear();
    let (a, b) = (pattern(120_000, 1), pattern(120_000, 2));
    write(&mut pair, client_ch, 1, &a);
    write(&mut pair, client_ch, 2, &b);
    pair.drive();
    assert_eq!(Some(a), read_message(&mut pair, server_ch, 1));
    assert_eq!(Some(b), read_message(&mut pair, server_ch, 2));

    // While both are backlogged, stream 1 sends about three fragments for each of stream 2's.
    let data = data_chunks_of(&pair.client_wire);
    let window: Vec<_> = data.iter().take(80).collect();
    let (s1, s2) = (
        window.iter().filter(|c| c.stream_identifier == 1).count(),
        window.iter().filter(|c| c.stream_identifier == 2).count(),
    );
    assert!(
        s1 >= 2 * s2 && s2 > 0,
        "weights 3:1 should show in the first 80 fragments, got {s1}:{s2}"
    );
}

#[test]
fn interleaved_transfer_survives_packet_loss() {
    for period in [3usize, 5, 11] {
        let (mut pair, client_ch, server_ch) =
            pair_with(interleaving_config(true), interleaving_config(true));
        for si in [1, 2, 3] {
            open_stream(&mut pair, client_ch, server_ch, si);
        }
        pair.client_wire.clear();
        let base = pair.client_datagrams;
        pair.client_loss = Some(Box::new(move |i| (i - base) % period == period - 1));

        let messages: Vec<(u16, Bytes)> = vec![
            (1, pattern(60_000, 1)),
            (2, pattern(3_000, 2)),
            (3, pattern(40_000, 3)),
            (2, pattern(10, 4)),
            (1, pattern(20_000, 5)),
            (3, pattern(1_500, 6)),
        ];
        for (si, m) in &messages {
            write(&mut pair, client_ch, *si, m);
        }
        pair.drive();

        for si in [1u16, 2, 3] {
            for (_, expected) in messages.iter().filter(|(s, _)| *s == si) {
                assert_eq!(
                    Some(expected.clone()),
                    read_message(&mut pair, server_ch, si),
                    "loss period {period}, stream {si}"
                );
            }
            assert_eq!(None, read_message(&mut pair, server_ch, si));
        }
        let mut seen = std::collections::HashSet::new();
        let retransmitted = data_chunks_of(&pair.client_wire)
            .iter()
            .filter(|c| !seen.insert(c.tsn))
            .count();
        assert!(
            retransmitted > 0,
            "the loss must have forced retransmissions"
        );
    }
}

#[test]
fn unordered_messages_interleave_and_arrive_whole() {
    let (mut pair, client_ch, server_ch) =
        pair_with(interleaving_config(true), interleaving_config(true));
    for si in [1, 2] {
        open_stream(&mut pair, client_ch, server_ch, si);
    }
    pair.client_wire.clear();
    pair.client_stream(client_ch, 1)
        .unwrap()
        .set_reliability_params(true, ReliabilityType::Reliable, 0)
        .unwrap();
    pair.client_stream(client_ch, 2)
        .unwrap()
        .set_reliability_params(true, ReliabilityType::Reliable, 0)
        .unwrap();
    let messages = [
        (1u16, pattern(50_000, 1)),
        (2, pattern(50_000, 2)),
        (1, pattern(7_000, 3)),
        (2, pattern(7_000, 4)),
    ];
    for (si, m) in &messages {
        write(&mut pair, client_ch, *si, m);
    }
    pair.drive();
    for si in [1u16, 2] {
        let mut got = vec![];
        while let Some(m) = read_message(&mut pair, server_ch, si) {
            got.push(m);
        }
        let mut want: Vec<Bytes> = messages
            .iter()
            .filter(|(s, _)| *s == si)
            .map(|(_, m)| m.clone())
            .collect();
        got.sort();
        want.sort();
        assert_eq!(want, got, "stream {si}");
    }
    let data = data_chunks_of(&pair.client_wire);
    assert!(!data.is_empty());
    assert!(data.iter().all(|c| c.idata && c.unordered));
}

#[test]
fn partial_reliability_is_carried_by_the_forward_tsn_chunk_matching_the_negotiation() {
    // pion: TestAssociationPRForwardTSNChunkTypeMatchesInterleaving
    for interleaving in [false, true] {
        let (mut pair, client_ch, server_ch) = pair_with(
            interleaving_config(interleaving),
            interleaving_config(interleaving),
        );
        let si = 1;
        open_stream(&mut pair, client_ch, server_ch, si);
        pair.client_stream(client_ch, si)
            .unwrap()
            .set_reliability_params(false, ReliabilityType::Rexmit, 0)
            .unwrap();
        pair.client_wire.clear();

        // Drop the first datagram: its message is abandoned, not retransmitted.
        let base = pair.client_datagrams;
        pair.client_loss = Some(Box::new(move |i| i == base));
        let first = pattern(1000, 1);
        let second = pattern(1000, 2);
        write(&mut pair, client_ch, si, &first);
        pair.drive_client();
        write(&mut pair, client_ch, si, &second);
        pair.drive();

        let counts = chunk_type_counts(&pair.client_wire);
        let (fwd, ifwd) = (
            counts.get(&CT_FORWARD_TSN.0).copied().unwrap_or(0),
            counts.get(&CT_IFORWARD_TSN.0).copied().unwrap_or(0),
        );
        if interleaving {
            assert!(
                ifwd > 0 && fwd == 0,
                "I-DATA must be forwarded by I-FORWARD-TSN"
            );
        } else {
            assert!(
                fwd > 0 && ifwd == 0,
                "DATA must be forwarded by FORWARD-TSN"
            );
        }
        assert_eq!(Some(second), read_message(&mut pair, server_ch, si));
    }
}

#[test]
fn i_forward_tsn_reports_the_abandoned_message_identifiers() {
    let (mut pair, client_ch, server_ch) =
        pair_with(interleaving_config(true), interleaving_config(true));
    let si = 1;
    open_stream(&mut pair, client_ch, server_ch, si);
    pair.client_stream(client_ch, si)
        .unwrap()
        .set_reliability_params(false, ReliabilityType::Rexmit, 0)
        .unwrap();
    pair.client_wire.clear();
    let base = pair.client_datagrams;
    pair.client_loss = Some(Box::new(move |i| i == base));
    write(&mut pair, client_ch, si, &pattern(1000, 1));
    pair.drive_client();
    write(&mut pair, client_ch, si, &pattern(1000, 2));
    pair.drive();

    let forwards: Vec<ChunkIForwardTsn> = chunks_of(&pair.client_wire)
        .iter()
        .filter_map(|c| c.as_any().downcast_ref::<ChunkIForwardTsn>().cloned())
        .collect();
    assert!(!forwards.is_empty());
    let first = &forwards[0];
    let lost = data_chunks_of(&pair.client_wire)[0].clone();
    assert_eq!(lost.tsn, first.new_cumulative_tsn);
    assert_eq!(1, first.streams.len());
    assert_eq!(si, first.streams[0].identifier);
    assert!(!first.streams[0].unordered);
    assert_eq!(lost.message_identifier, first.streams[0].message_identifier);
}

#[test]
fn a_reset_stream_restarts_its_message_identifiers() {
    // pion: TestAssocResetResetsInterleavingCounters
    let (mut pair, client_ch, server_ch) =
        pair_with(interleaving_config(true), interleaving_config(true));
    let si = 7;
    open_stream(&mut pair, client_ch, server_ch, si);
    write(&mut pair, client_ch, si, &pattern(100, 1));
    write(&mut pair, client_ch, si, &pattern(100, 2));
    pair.drive();
    // A stream with unread data is not reset yet, so drain it first.
    while read_message(&mut pair, server_ch, si).is_some() {}
    // The open handshake's DCEP message was the first.
    assert_eq!(
        3,
        pair.client_conn_mut(client_ch).streams[&si].next_ordered_mid
    );

    let now = pair.time;
    pair.client_stream(client_ch, si)
        .unwrap()
        .close(now)
        .unwrap();
    pair.drive();
    // Both sides have dropped the stream; opening it again starts from zero.
    assert!(!pair.client_conn_mut(client_ch).streams.contains_key(&si));

    pair.client_wire.clear();
    open_stream(&mut pair, client_ch, server_ch, si);
    let data = data_chunks_of(&pair.client_wire);
    assert!(!data.is_empty());
    assert!(data.iter().all(|c| c.idata && c.message_identifier == 0));
    assert_eq!(
        1,
        pair.client_conn_mut(client_ch).streams[&si].next_ordered_mid
    );
}

/// Hands `chunk`, built by `from`'s association, to `to` as if it had come over the wire.
fn inject(pair: &mut Pair, from_client: bool, handle: AssociationHandle, chunk: Box<dyn Chunk>) {
    let raw = if from_client {
        pair.client_conn_mut(handle)
            .create_packet(vec![chunk])
            .marshal()
            .unwrap()
    } else {
        pair.server_conn_mut(handle)
            .create_packet(vec![chunk])
            .marshal()
            .unwrap()
    };
    let at = pair.time;
    if from_client {
        pair.server.inbound.push_back((at, None, raw));
    } else {
        pair.client.inbound.push_back((at, None, raw));
    }
}

/// Reasons of the protocol-violation ABORTs `wire` carries.
fn abort_reasons(wire: &[Bytes]) -> Vec<String> {
    let mut reasons = vec![];
    for c in chunks_of(wire) {
        if let Some(abort) = c.as_any().downcast_ref::<ChunkAbort>() {
            for cause in &abort.error_causes {
                if cause.code == PROTOCOL_VIOLATION {
                    reasons.push(String::from_utf8_lossy(&cause.raw).into_owned());
                }
            }
        }
    }
    reasons
}

#[test]
fn a_chunk_that_contradicts_the_negotiation_aborts_with_a_protocol_violation() {
    // pion: TestAssociationInterleavingProtocolViolationWrongPayloadChunkType and
    // ...WrongForwardTSNChunkType, over the wire.
    let payload = |idata: bool| -> Box<dyn Chunk> {
        Box::new(ChunkPayloadData {
            idata,
            tsn: 1,
            stream_identifier: 1,
            payload_type: PayloadProtocolIdentifier::Binary,
            user_data: Bytes::from_static(b"bad"),
            beginning_fragment: true,
            ending_fragment: true,
            ..Default::default()
        })
    };
    let forward: Box<dyn Fn() -> Box<dyn Chunk>> = Box::new(|| {
        Box::new(ChunkForwardTsn {
            new_cumulative_tsn: 1,
            streams: vec![crate::chunk::chunk_forward_tsn::ChunkForwardTsnStream {
                identifier: 1,
                sequence: 0,
            }],
        })
    });
    let i_forward: Box<dyn Fn() -> Box<dyn Chunk>> = Box::new(|| {
        Box::new(ChunkIForwardTsn {
            new_cumulative_tsn: 1,
            streams: vec![crate::chunk::chunk_i_forward_tsn::ChunkIForwardTsnStream {
                identifier: 1,
                unordered: false,
                message_identifier: 0,
            }],
        })
    });
    type Make<'a> = &'a dyn Fn() -> Box<dyn Chunk>;
    let data_plain: Make<'_> = &|| payload(false);
    let data_idata: Make<'_> = &|| payload(true);
    let cases: Vec<(&str, bool, bool, Make<'_>, &str)> = vec![
        (
            "DATA after interleaving negotiated",
            true,
            true,
            data_plain,
            "received DATA with interleaving negotiated",
        ),
        (
            "I-DATA without interleaving negotiated",
            true,
            false,
            data_idata,
            "received I-DATA without interleaving negotiated",
        ),
        (
            "FORWARD-TSN after interleaving negotiated",
            true,
            true,
            &*forward,
            "received FORWARD-TSN with interleaving enabled",
        ),
        (
            "I-FORWARD-TSN without interleaving negotiated",
            false,
            false,
            &*i_forward,
            "received I-FORWARD-TSN without support",
        ),
    ];
    for (name, client, server, make, reason) in cases {
        let (mut pair, client_ch, server_ch) =
            pair_with(interleaving_config(client), interleaving_config(server));
        pair.server_wire.clear();
        inject(&mut pair, true, client_ch, make());
        pair.drive();
        // Let the client read what the server sent last.
        pair.drive_client();
        assert_eq!(
            vec![reason.to_string()],
            abort_reasons(&pair.server_wire),
            "{name}"
        );
        assert!(
            pair.server_conn_mut(server_ch).is_closed(),
            "{name}: the offender is cut off"
        );
        assert!(
            pair.client_conn_mut(client_ch).is_closed(),
            "{name}: and the peer learns of it"
        );
    }
}
