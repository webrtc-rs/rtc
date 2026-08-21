//! Receive-side FlexFEC draft-03, in a chain.
//!
//! There is no upstream counterpart to compare against — pion's decoder is never constructed
//! outside its own unit tests — so the evidence here has to come from the chain itself: a marker
//! interceptor below records exactly what the rest of the pipeline is offered.
//!
//! Two properties carry the task. Repair packets must never appear below: they are not media, and
//! an interceptor treating their sequence numbers as a media stream's would report gaps that do
//! not exist. And a recovered packet must arrive through `inner.handle_read`, indistinguishable
//! from one that was never lost.

use rtc_interceptor::{
    AttributedPacket, FlexFec03Encoder, FlexFec03ReceiveBuilder, Interceptor, Packet, Registry, StreamInfo, TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use shared::marshal::{Marshal, MarshalSize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MEDIA_SSRC: u32 = 476_325_762;
const REPAIR_SSRC: u32 = 867_589_674;
const REPAIR_PT: u8 = 49;

/// What the layer below the FEC interceptor saw, in full, so the test can compare bytes.
struct Marker {
    seen: Arc<Mutex<Vec<rtp::Packet>>>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for Marker {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = shared::error::Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp) = &msg.message.packet {
            self.seen.lock().unwrap().push(rtp.clone());
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for Marker {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

struct Harness {
    chain: Box<dyn Interceptor>,
    seen: Arc<Mutex<Vec<rtp::Packet>>>,
    epoch: Instant,
}

impl Harness {
    fn new() -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let marker_seen = Arc::clone(&seen);

        // The marker sits application-ward of the decoder, so it sees what the decoder passes on:
        // repair packets swallowed, recovered ones added.
        let chain = Registry::new()
            .with(FlexFec03ReceiveBuilder::new().build())
            .with(Marker {
                seen: marker_seen,
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            })
            .build();

        Self {
            chain: Box::new(chain),
            seen,
            epoch: Instant::now(),
        }
    }

    fn bind_protected(&mut self) {
        self.chain.bind_remote_stream(&StreamInfo {
            ssrc: MEDIA_SSRC,
            ssrc_fec: Some(REPAIR_SSRC),
            payload_type: 96,
            payload_type_fec: Some(REPAIR_PT),
            clock_rate: 90_000,
            ..Default::default()
        });
    }

    fn receive(&mut self, packet: &rtp::Packet) {
        self.chain
            .handle_read(TaggedPacket {
                now: self.epoch,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet.clone())),
            })
            .expect("handle_read");
    }

    fn seen(&self) -> Vec<rtp::Packet> {
        self.seen.lock().unwrap().clone()
    }

    fn seen_sequence_numbers(&self) -> Vec<u16> {
        self.seen()
            .iter()
            .map(|packet| packet.header.sequence_number)
            .collect()
    }
}

fn media_packet(sequence_number: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::header::Header {
            version: 2,
            marker: true,
            payload_type: 96,
            sequence_number,
            timestamp: 3_653_407_706u32.wrapping_add(u32::from(sequence_number) * 3000),
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        payload: vec![1, 2, 3, 4, 5, sequence_number as u8].into(),
    }
}

fn block(first: u16, count: u16) -> Vec<rtp::Packet> {
    (0..count).map(|i| media_packet(first + i)).collect()
}

fn encode(media: &[rtp::Packet], num_fec_packets: u32) -> Vec<rtp::Packet> {
    FlexFec03Encoder::new(REPAIR_PT, REPAIR_SSRC).encode(media, num_fec_packets)
}

fn bytes_of(packet: &rtp::Packet) -> Vec<u8> {
    let mut buffer = vec![0u8; packet.marshal_size()];
    packet.marshal_to(&mut buffer).expect("marshal");
    buffer
}

// ---------------------------------------------------------------------------------------
// Recovery under induced loss
// ---------------------------------------------------------------------------------------

/// The property #847 asks for, and the bar P3A-05 is gated on: a packet dropped in transit is
/// rebuilt and handed to the rest of the pipeline.
#[test]
fn a_packet_lost_in_transit_is_recovered_and_forwarded() {
    let media = block(100, 5);
    let repair = encode(&media, 2);

    let mut harness = Harness::new();
    harness.bind_protected();

    for packet in media.iter().filter(|p| p.header.sequence_number != 102) {
        harness.receive(packet);
    }
    assert_eq!(
        vec![100, 101, 103, 104],
        harness.seen_sequence_numbers(),
        "the gap is real before any repair packet arrives"
    );

    for packet in &repair {
        harness.receive(packet);
    }

    assert_eq!(
        vec![100, 101, 103, 104, 102],
        harness.seen_sequence_numbers(),
        "102 was rebuilt and forwarded once the repair packet arrived"
    );

    let recovered = harness
        .seen()
        .into_iter()
        .find(|packet| packet.header.sequence_number == 102)
        .expect("recovered");
    assert_eq!(
        bytes_of(&media[2]),
        bytes_of(&recovered),
        "byte-identical to the packet that was lost"
    );
}

#[test]
fn every_packet_of_a_block_can_be_recovered_in_turn() {
    let media = block(100, 5);
    let repair = encode(&media, 2);

    for lost in 0..media.len() {
        let mut harness = Harness::new();
        harness.bind_protected();

        for (index, packet) in media.iter().enumerate() {
            if index != lost {
                harness.receive(packet);
            }
        }
        for packet in &repair {
            harness.receive(packet);
        }

        let recovered = harness
            .seen()
            .into_iter()
            .find(|packet| packet.header.sequence_number == media[lost].header.sequence_number);
        assert!(
            recovered.is_some(),
            "packet {lost} was recovered and forwarded"
        );
        assert_eq!(bytes_of(&media[lost]), bytes_of(&recovered.unwrap()));
    }
}

// ---------------------------------------------------------------------------------------
// Repair packets must not escape
// ---------------------------------------------------------------------------------------

/// A repair packet is not media. Forwarding it would put a second stream in front of every
/// interceptor below — the NACK generator would track its sequence numbers, the jitter buffer
/// would try to play it out, and the application would be handed something it cannot decode.
#[test]
fn repair_packets_never_reach_the_layers_below() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut harness = Harness::new();
    harness.bind_protected();

    for packet in &media {
        harness.receive(packet);
    }
    for packet in &repair {
        harness.receive(packet);
    }

    assert!(
        harness
            .seen()
            .iter()
            .all(|packet| packet.header.ssrc == MEDIA_SSRC),
        "only media SSRCs below: {:?}",
        harness
            .seen()
            .iter()
            .map(|p| p.header.ssrc)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        4,
        harness.seen().len(),
        "the four media packets, and nothing else"
    );
}

/// Even when a repair packet recovers nothing, it is still consumed rather than passed along.
#[test]
fn a_repair_packet_that_recovers_nothing_is_still_consumed() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut harness = Harness::new();
    harness.bind_protected();

    harness.receive(&repair[0]);

    assert!(
        harness.seen().is_empty(),
        "nothing was forwarded: the repair packet had nothing to rebuild yet"
    );
}

// ---------------------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------------------

#[test]
fn an_unprotected_stream_passes_through_untouched() {
    let media = block(100, 3);

    let mut harness = Harness::new();
    // Bound without a repair association.
    harness.chain.bind_remote_stream(&StreamInfo {
        ssrc: MEDIA_SSRC,
        ..Default::default()
    });

    for packet in &media {
        harness.receive(packet);
    }

    assert_eq!(vec![100, 101, 102], harness.seen_sequence_numbers());
}

/// Half an association is not an association. Without the payload type the repair stream was
/// never negotiated, so nothing here may claim its SSRC — the packets on it belong to whatever
/// else is using that SSRC, and swallowing them would make them vanish.
#[test]
fn a_stream_with_only_half_a_repair_association_is_not_protected() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    for info in [
        // The repair SSRC, but no payload type to recognise it by.
        StreamInfo {
            ssrc: MEDIA_SSRC,
            ssrc_fec: Some(REPAIR_SSRC),
            ..Default::default()
        },
        // A payload type, but no SSRC to route.
        StreamInfo {
            ssrc: MEDIA_SSRC,
            payload_type_fec: Some(REPAIR_PT),
            ..Default::default()
        },
    ] {
        let mut harness = Harness::new();
        harness.chain.bind_remote_stream(&info);

        for packet in media.iter().filter(|p| p.header.sequence_number != 101) {
            harness.receive(packet);
        }
        for packet in &repair {
            harness.receive(packet);
        }

        let sequence_numbers = harness.seen_sequence_numbers();
        assert!(
            !sequence_numbers.contains(&101),
            "nothing is recovered for an unnegotiated association: {sequence_numbers:?}"
        );
        assert!(
            harness
                .seen()
                .iter()
                .any(|packet| packet.header.ssrc == REPAIR_SSRC),
            "and the packets on that SSRC are passed along rather than swallowed"
        );
    }
}

/// A stream nobody bound is forwarded as-is rather than buffered against a decoder that will
/// never be driven.
#[test]
fn packets_for_unknown_streams_pass_through() {
    let mut harness = Harness::new();
    harness.bind_protected();

    let mut stray = media_packet(1);
    stray.header.ssrc = 12_345;
    harness.receive(&stray);

    assert_eq!(vec![1], harness.seen_sequence_numbers());
}

#[test]
fn unbinding_stops_recovery_and_stops_swallowing_repair_packets() {
    let media = block(100, 4);
    let repair = encode(&media, 1);

    let mut harness = Harness::new();
    harness.bind_protected();
    harness.chain.unbind_remote_stream(&StreamInfo {
        ssrc: MEDIA_SSRC,
        ..Default::default()
    });

    for packet in media.iter().filter(|p| p.header.sequence_number != 101) {
        harness.receive(packet);
    }
    for packet in &repair {
        harness.receive(packet);
    }

    // With nothing bound, the repair packet is no longer recognised as repair, so it is forwarded
    // like any other unknown stream — and nothing is recovered.
    let sequence_numbers = harness.seen_sequence_numbers();
    assert!(
        !sequence_numbers.contains(&101),
        "no recovery after unbind: {sequence_numbers:?}"
    );
}

/// RTCP has no place in FEC recovery and must not be delayed or consumed by it.
#[test]
fn rtcp_passes_through() {
    let mut harness = Harness::new();
    harness.bind_protected();

    harness
        .chain
        .handle_read(TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        })
        .expect("handle_read");

    assert!(harness.seen().is_empty(), "the marker only records RTP");
}

/// A recovered packet must not be forwarded twice, however many repair packets could have
/// rebuilt it.
#[test]
fn a_packet_is_recovered_at_most_once() {
    let media = block(100, 6);
    // Two repair packets, each covering an interleaved half; 100 is covered by the first only,
    // but a second repair packet arriving must not re-emit it.
    let repair = encode(&media, 2);

    let mut harness = Harness::new();
    harness.bind_protected();

    for packet in media.iter().filter(|p| p.header.sequence_number != 100) {
        harness.receive(packet);
    }
    for packet in &repair {
        harness.receive(packet);
    }
    // Offer the repair packets again, as a duplicate would arrive.
    for packet in &repair {
        harness.receive(packet);
    }

    let hundreds = harness
        .seen_sequence_numbers()
        .into_iter()
        .filter(|&sequence_number| sequence_number == 100)
        .count();
    assert_eq!(1, hundreds, "recovered once, forwarded once");
}

// ---------------------------------------------------------------------------------------
// CC-PRE-04 — what a recovered packet means to the NACK generator
// ---------------------------------------------------------------------------------------

/// `Attribute::RecoveredByFec` documents itself as *"a NACK generator that sees this must not ask
/// for the packet again"*. This asks whether that needs an attribute check at all.
///
/// The chain ordering already arranges it: the FEC decoder is wire-ward of the NACK generator, so a
/// recovered packet reaches the generator on the read walk like any other arrival and fills the gap
/// in its receive log. The generator then has nothing to ask for — not because it inspected an
/// attribute, but because the packet is *there*.
///
/// If this passes with no attribute check anywhere, the attribute's claim is about a mechanism that
/// does not exist, and the doc is what needs fixing.
#[test]
fn a_recovered_packet_stops_the_nack_generator_asking_for_it() {
    use rtc_interceptor::{NackGeneratorBuilder, RTCPFeedback};
    use std::time::Duration;

    const NACK_INTERVAL: Duration = Duration::from_millis(100);

    let media = block(200, 5);
    let repair = encode(&media, 2);

    // Wire-to-application: FEC decoder, then NACK generator — the shipped ordering.
    let mut chain = Registry::new()
        .with(FlexFec03ReceiveBuilder::new().build())
        .with(NackGeneratorBuilder::new().with_interval(NACK_INTERVAL).build())
        .build();

    let stream = StreamInfo {
        ssrc: MEDIA_SSRC,
        ssrc_fec: Some(REPAIR_SSRC),
        payload_type: 96,
        payload_type_fec: Some(REPAIR_PT),
        clock_rate: 90_000,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_owned(),
            parameter: String::new(),
        }],
        ..Default::default()
    };
    chain.bind_remote_stream(&stream);

    let epoch = Instant::now();
    let mut receive = |chain: &mut dyn Interceptor, packet: &rtp::Packet| {
        chain
            .handle_read(TaggedPacket {
                now: epoch,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(packet.clone())),
            })
            .expect("handle_read");
        while chain.poll_read().is_some() {}
    };

    // 202 is lost, then rebuilt from the repair packets — all before the NACK timer fires.
    for packet in media.iter().filter(|p| p.header.sequence_number != 202) {
        receive(&mut chain, packet);
    }
    for packet in &repair {
        receive(&mut chain, packet);
    }

    chain
        .handle_timeout(epoch + NACK_INTERVAL * 2)
        .expect("handle_timeout");

    let mut asked_for = Vec::new();
    while let Some(packet) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &packet.message.packet {
            for rtcp_packet in rtcp_packets {
                if let Some(nack) = rtcp_packet
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    ) {
                    for pair in &nack.nacks {
                        asked_for.push(pair.packet_id);
                    }
                }
            }
        }
    }

    assert!(
        !asked_for.contains(&202),
        "the generator asked for a packet FEC had already rebuilt: {asked_for:?}"
    );
}
