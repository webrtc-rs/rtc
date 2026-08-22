//! Send-side FlexFEC draft-03: which streams get protected, and what reaches the network.
//!
//! A marker interceptor sits below the FEC layer and records everything that passes. That
//! placement is the point: repair packets must arrive there through `inner.handle_write`, because
//! a repair packet is a real outgoing RTP packet that still needs the layers below it — a
//! transport-wide sequence number, and a place in the send history congestion control reads. A
//! repair packet returned from a local queue would skip all of that.

use rtc_interceptor::{
    AttributedPacket, FlexFec03SendBuilder, Interceptor, Packet, Registry, Slot, StreamInfo,
    TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MEDIA_SSRC: u32 = 1000;
const REPAIR_SSRC: u32 = 2000;
const MEDIA_PT: u8 = 96;
const REPAIR_PT: u8 = 98;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sent {
    ssrc: u32,
    payload_type: u8,
    sequence_number: u16,
}

struct Marker {
    sent: Arc<Mutex<Vec<Sent>>>,
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
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp) = &msg.message.packet {
            self.sent.lock().unwrap().push(Sent {
                ssrc: rtp.header.ssrc,
                payload_type: rtp.header.payload_type,
                sequence_number: rtp.header.sequence_number,
            });
        }
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
    sent: Arc<Mutex<Vec<Sent>>>,
    epoch: Instant,
}

impl Harness {
    fn new(num_media_packets: u32, num_fec_packets: u32) -> Self {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let marker_sent = Arc::clone(&sent);

        let chain = Registry::new()
            .with(
                // Wire-ward of the FEC encoder at 5_000, so it sees the repair packets it emits.
                Slot::from(4_500),
                Marker {
                    sent: marker_sent,
                    read_queue: VecDeque::new(),
                    write_queue: VecDeque::new(),
                },
            )
            .with(
                Slot::FecEncoder,
                FlexFec03SendBuilder::new()
                    .with_num_media_packets(num_media_packets)
                    .with_num_fec_packets(num_fec_packets)
                    .build(),
            )
            .build();

        Self {
            chain: Box::new(chain),
            sent,
            epoch: Instant::now(),
        }
    }

    fn bind_protected(&mut self) {
        self.chain.bind_local_stream(&StreamInfo {
            ssrc: MEDIA_SSRC,
            ssrc_fec: Some(REPAIR_SSRC),
            payload_type: MEDIA_PT,
            payload_type_fec: Some(REPAIR_PT),
            clock_rate: 90_000,
            ..Default::default()
        });
    }

    fn send(&mut self, sequence_number: u16) {
        self.send_on(MEDIA_SSRC, sequence_number);
    }

    fn send_on(&mut self, ssrc: u32, sequence_number: u16) {
        self.chain
            .handle_write(TaggedPacket {
                now: self.epoch,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        payload_type: MEDIA_PT,
                        sequence_number,
                        ssrc,
                        ..Default::default()
                    },
                    payload: vec![1, 2, 3, 4].into(),
                })),
            })
            .expect("handle_write");
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }

    fn repair_packets(&self) -> Vec<Sent> {
        self.sent()
            .into_iter()
            .filter(|packet| packet.ssrc == REPAIR_SSRC)
            .collect()
    }

    fn media_packets(&self) -> Vec<Sent> {
        self.sent()
            .into_iter()
            .filter(|packet| packet.ssrc == MEDIA_SSRC)
            .collect()
    }
}

// ---------------------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------------------

/// The gate FEC-PRE-01 exists to open: without both halves of the repair association, there is no
/// SSRC to send repair packets on and no payload type to mark them with.
#[test]
fn a_stream_without_a_repair_association_is_not_protected() {
    for info in [
        // Neither half.
        StreamInfo {
            ssrc: MEDIA_SSRC,
            ..Default::default()
        },
        // SSRC but no payload type.
        StreamInfo {
            ssrc: MEDIA_SSRC,
            ssrc_fec: Some(REPAIR_SSRC),
            ..Default::default()
        },
        // Payload type but no SSRC.
        StreamInfo {
            ssrc: MEDIA_SSRC,
            payload_type_fec: Some(REPAIR_PT),
            ..Default::default()
        },
    ] {
        let mut harness = Harness::new(2, 1);
        harness.chain.bind_local_stream(&info);

        harness.send(1);
        harness.send(2);

        assert!(
            harness.repair_packets().is_empty(),
            "no repair packets for {info:?}"
        );
        assert_eq!(2, harness.media_packets().len(), "media still goes out");
    }
}

#[test]
fn a_stream_with_both_halves_is_protected() {
    let mut harness = Harness::new(2, 1);
    harness.bind_protected();

    harness.send(1);
    harness.send(2);

    assert_eq!(1, harness.repair_packets().len());
}

#[test]
fn unbinding_stops_protection() {
    let mut harness = Harness::new(2, 1);
    harness.bind_protected();

    harness.send(1);
    harness.send(2);
    assert_eq!(1, harness.repair_packets().len());

    harness.chain.unbind_local_stream(&StreamInfo {
        ssrc: MEDIA_SSRC,
        ..Default::default()
    });

    harness.send(3);
    harness.send(4);
    assert_eq!(
        1,
        harness.repair_packets().len(),
        "no further repair packets after unbind"
    );
    assert_eq!(4, harness.media_packets().len(), "media is unaffected");
}

/// Only the stream that negotiated FEC is protected; another stream sharing the chain is not.
#[test]
fn an_unprotected_stream_passes_through_untouched() {
    let mut harness = Harness::new(2, 1);
    harness.bind_protected();

    harness.send_on(9999, 1);
    harness.send_on(9999, 2);

    assert!(harness.repair_packets().is_empty());
    assert_eq!(
        2,
        harness.sent().len(),
        "both packets went out as they were"
    );
}

// ---------------------------------------------------------------------------------------
// Block shape
// ---------------------------------------------------------------------------------------

/// Repair packets are produced once a block is full, not per packet — that is what makes the
/// overhead a fraction of the media rather than a multiple of it.
#[test]
fn repair_packets_appear_only_when_a_block_completes() {
    let mut harness = Harness::new(5, 2);
    harness.bind_protected();

    for sequence_number in 1..=4 {
        harness.send(sequence_number);
        assert!(
            harness.repair_packets().is_empty(),
            "block of 5 is not full after {sequence_number}"
        );
    }

    harness.send(5);
    assert_eq!(2, harness.repair_packets().len(), "the block completed");
}

#[test]
fn each_block_produces_its_own_repair_packets() {
    let mut harness = Harness::new(3, 1);
    harness.bind_protected();

    for sequence_number in 1..=9 {
        harness.send(sequence_number);
    }

    assert_eq!(3, harness.repair_packets().len(), "three full blocks");
    assert_eq!(9, harness.media_packets().len());
}

#[test]
fn the_repair_stream_has_its_own_identity_and_sequence_numbers() {
    let mut harness = Harness::new(2, 1);
    harness.bind_protected();

    for sequence_number in 1..=6 {
        harness.send(sequence_number);
    }

    let repair = harness.repair_packets();
    assert_eq!(3, repair.len());
    for packet in &repair {
        assert_eq!(REPAIR_SSRC, packet.ssrc);
        assert_eq!(REPAIR_PT, packet.payload_type);
    }
    assert_eq!(
        vec![0, 1, 2],
        repair
            .iter()
            .map(|packet| packet.sequence_number)
            .collect::<Vec<_>>(),
        "the repair stream numbers its own packets consecutively"
    );
}

/// The media packet goes out before the repair packets that protect it — a receiver cannot use a
/// repair packet for media it has not been offered yet.
#[test]
fn media_precedes_the_repair_packets_that_protect_it() {
    let mut harness = Harness::new(2, 1);
    harness.bind_protected();

    harness.send(1);
    harness.send(2);

    let sent = harness.sent();
    assert_eq!(
        vec![MEDIA_SSRC, MEDIA_SSRC, REPAIR_SSRC],
        sent.iter().map(|packet| packet.ssrc).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------------------
// Blocks the encoder cannot describe
// ---------------------------------------------------------------------------------------

/// A packet mask describes positions relative to one base sequence number, so a block with a gap
/// would protect the wrong packets. The block is dropped and the next one starts clean, rather
/// than the gap being retried as more packets arrive.
#[test]
fn a_block_with_a_gap_produces_no_repair_packets_and_does_not_stall() {
    let mut harness = Harness::new(3, 1);
    harness.bind_protected();

    harness.send(1);
    harness.send(2);
    harness.send(10); // gap

    assert!(
        harness.repair_packets().is_empty(),
        "the encoder refused a block it cannot describe"
    );
    assert_eq!(3, harness.media_packets().len(), "media still went out");

    // The next full block is clean and must be protected normally.
    harness.send(11);
    harness.send(12);
    harness.send(13);

    assert_eq!(
        1,
        harness.repair_packets().len(),
        "the buffer was cleared, so the next block works"
    );
}

/// The repair packets are re-injected through `inner`, so a downstream layer sees them exactly as
/// it sees media. If they were returned from a local queue instead, they would reach the network
/// without a transport-wide sequence number or an entry in the send history.
#[test]
fn repair_packets_traverse_the_layers_below() {
    let mut harness = Harness::new(2, 2);
    harness.bind_protected();

    harness.send(1);
    harness.send(2);

    assert_eq!(
        2,
        harness.repair_packets().len(),
        "both repair packets reached the layer below the FEC interceptor"
    );
}

#[test]
fn asking_for_no_repair_packets_produces_none() {
    let mut harness = Harness::new(2, 0);
    harness.bind_protected();

    harness.send(1);
    harness.send(2);

    assert!(harness.repair_packets().is_empty());
    assert_eq!(2, harness.media_packets().len());
}

/// RTCP is not media and carries no sequence number to protect; it passes through.
#[test]
fn rtcp_is_not_protected() {
    let mut harness = Harness::new(2, 1);
    harness.bind_protected();

    harness
        .chain
        .handle_write(TaggedPacket {
            now: harness.epoch,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![])),
        })
        .expect("handle_write");

    assert!(harness.repair_packets().is_empty());
}
