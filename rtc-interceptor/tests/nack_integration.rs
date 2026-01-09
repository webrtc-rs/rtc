//! Integration tests for NACK (Negative Acknowledgement) interceptors.
//!
//! These tests verify that the interceptor chain correctly:
//! - Generates NACK requests for missing packets
//! - Retransmits packets when NACK requests are received
//! - Supports RFC4588 RTX retransmission
//! - Properly tracks stream binding/unbinding

use rtc_interceptor::{
    Interceptor, NackGeneratorBuilder, NackResponderBuilder, Packet, RTCPFeedback, Registry,
    StreamInfo, TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

// =============================================================================
// Helper Functions
// =============================================================================

/// Helper to create a tagged RTP packet with specific parameters.
fn create_rtp_packet(ssrc: u32, seq: u16, timestamp: u32, payload_len: usize) -> TaggedPacket {
    let mut payload = vec![0u8; payload_len];
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    TaggedPacket {
        now: Instant::now(),
        transport: TransportContext::default(),
        message: Packet::Rtp(rtp::Packet {
            header: rtp::header::Header {
                ssrc,
                sequence_number: seq,
                timestamp,
                payload_type: 96,
                ..Default::default()
            },
            payload: payload.into(),
        }),
    }
}

/// Helper to create a tagged RTP packet with custom timestamp.
fn create_rtp_packet_with_time(
    now: Instant,
    ssrc: u32,
    seq: u16,
    timestamp: u32,
    payload_len: usize,
) -> TaggedPacket {
    let mut pkt = create_rtp_packet(ssrc, seq, timestamp, payload_len);
    pkt.now = now;
    pkt
}

/// Stream info with NACK support.
fn nack_stream_info(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

/// Stream info with NACK and RTX support.
fn nack_rtx_stream_info(ssrc: u32, rtx_ssrc: u32, rtx_pt: u8) -> StreamInfo {
    StreamInfo {
        ssrc,
        ssrc_rtx: Some(rtx_ssrc),
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        payload_type_rtx: Some(rtx_pt),
        rtcp_feedback: vec![RTCPFeedback {
            typ: "nack".to_string(),
            parameter: String::new(),
        }],
        ..Default::default()
    }
}

/// Stream info without NACK support.
fn no_nack_stream_info(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90000,
        mime_type: "video/VP8".to_string(),
        payload_type: 96,
        rtcp_feedback: vec![],
        ..Default::default()
    }
}

/// Create a NACK RTCP packet.
fn create_nack_packet(
    now: Instant,
    sender_ssrc: u32,
    media_ssrc: u32,
    nacks: Vec<rtcp::transport_feedbacks::transport_layer_nack::NackPair>,
) -> TaggedPacket {
    let nack = rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack {
        sender_ssrc,
        media_ssrc,
        nacks,
    };

    TaggedPacket {
        now,
        transport: TransportContext::default(),
        message: Packet::Rtcp(vec![Box::new(nack)]),
    }
}

// =============================================================================
// NACK Generator Tests
// =============================================================================

#[test]
fn test_nack_generator_detects_packet_loss() {
    let mut chain = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let ssrc = 0x12345678;
    chain.bind_remote_stream(&nack_stream_info(ssrc));

    let base_time = Instant::now();

    // Receive packets with a gap: 0, 1, 2, skip 3-5, 6, 7
    for seq in [0u16, 1, 2, 6, 7] {
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Drain RTP packets
    while chain.poll_read().is_some() {}

    // Trigger timeout to generate NACK
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Check for NACK in output
    let mut nack_found = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(nack) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                {
                    assert_eq!(nack.media_ssrc, ssrc);
                    nack_found = true;
                }
            }
        }
    }

    assert!(nack_found, "NACK should be generated for missing packets");
}

#[test]
fn test_nack_generator_no_nack_for_sequential_packets() {
    let mut chain = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let ssrc = 0x12345678;
    chain.bind_remote_stream(&nack_stream_info(ssrc));

    let base_time = Instant::now();

    // Receive sequential packets without gaps
    for seq in 0..10u16 {
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Drain RTP packets
    while chain.poll_read().is_some() {}

    // Trigger timeout
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Should not have any NACK
    let mut nack_found = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                    .is_some()
                {
                    nack_found = true;
                }
            }
        }
    }

    assert!(
        !nack_found,
        "No NACK should be generated for sequential packets"
    );
}

#[test]
fn test_nack_generator_ignores_streams_without_nack_support() {
    let mut chain = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let ssrc = 0x12345678;
    // Bind stream WITHOUT NACK support
    chain.bind_remote_stream(&no_nack_stream_info(ssrc));

    let base_time = Instant::now();

    // Receive packets with a gap
    for seq in [0u16, 1, 2, 10, 11] {
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Drain and trigger timeout
    while chain.poll_read().is_some() {}
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Should not generate NACK for unsupported stream
    let mut nack_found = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                    .is_some()
                {
                    nack_found = true;
                }
            }
        }
    }

    assert!(
        !nack_found,
        "No NACK should be generated for streams without NACK support"
    );
}

// =============================================================================
// NACK Responder Tests
// =============================================================================

#[test]
fn test_nack_responder_retransmits_packet() {
    let mut chain = Registry::new()
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();

    let ssrc = 0xABCDEF00;
    chain.bind_local_stream(&nack_stream_info(ssrc));

    let base_time = Instant::now();

    // Send some RTP packets
    for seq in 0..10u16 {
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_write(pkt).unwrap();
    }

    // Drain written RTP packets
    let mut sent_packets = Vec::new();
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtp(rtp) = &pkt.message {
            sent_packets.push(rtp.header.sequence_number);
        }
    }
    assert_eq!(sent_packets.len(), 10);

    // Receive a NACK requesting retransmission of packets 3 and 5
    // RFC 4585: lost_packets bit i means packet_id + i + 1 is also lost
    // So for packet 5: bit 1 (5 = 3 + 1 + 1)
    let nack = create_nack_packet(
        base_time,
        0x11111111,
        ssrc,
        vec![rtcp::transport_feedbacks::transport_layer_nack::NackPair {
            packet_id: 3,
            lost_packets: 0b0000_0000_0000_0010, // bit 1 = packet 5 (3 + 1 + 1)
        }],
    );
    chain.handle_read(nack).unwrap();

    // Drain read output
    while chain.poll_read().is_some() {}

    // Check for retransmitted packets
    let mut retransmitted = Vec::new();
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtp(rtp) = &pkt.message {
            retransmitted.push(rtp.header.sequence_number);
        }
    }

    assert!(
        retransmitted.contains(&3),
        "Packet 3 should be retransmitted, got {:?}",
        retransmitted
    );
    assert!(
        retransmitted.contains(&5),
        "Packet 5 should be retransmitted, got {:?}",
        retransmitted
    );
}

#[test]
fn test_nack_responder_rtx_retransmission() {
    let mut chain = Registry::new()
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();

    let ssrc = 0xABCDEF00;
    let rtx_ssrc = 0xABCDEF01;
    let rtx_pt = 97;
    chain.bind_local_stream(&nack_rtx_stream_info(ssrc, rtx_ssrc, rtx_pt));

    let base_time = Instant::now();

    // Send some RTP packets
    for seq in 0..5u16 {
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_write(pkt).unwrap();
    }

    // Drain written RTP packets
    while chain.poll_write().is_some() {}

    // Receive a NACK requesting retransmission of packet 2
    let nack = create_nack_packet(
        base_time,
        0x11111111,
        ssrc,
        vec![rtcp::transport_feedbacks::transport_layer_nack::NackPair {
            packet_id: 2,
            lost_packets: 0,
        }],
    );
    chain.handle_read(nack).unwrap();

    // Drain read output
    while chain.poll_read().is_some() {}

    // Check for RTX retransmission
    let mut rtx_found = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtp(rtp) = &pkt.message
            && rtp.header.ssrc == rtx_ssrc
            && rtp.header.payload_type == rtx_pt
        {
            rtx_found = true;
            // RTX payload should contain original sequence number
            assert!(rtp.payload.len() >= 2);
            let original_seq = u16::from_be_bytes([rtp.payload[0], rtp.payload[1]]);
            assert_eq!(original_seq, 2, "RTX payload should contain original seq");
        }
    }

    assert!(rtx_found, "RTX retransmission should be sent");
}

#[test]
fn test_nack_responder_ignores_expired_packets() {
    let mut chain = Registry::new()
        .with(NackResponderBuilder::new().with_size(4).build()) // Small buffer
        .build();

    let ssrc = 0xABCDEF00;
    chain.bind_local_stream(&nack_stream_info(ssrc));

    let base_time = Instant::now();

    // Send packets 0-9 (only 4 will be buffered)
    for seq in 0..10u16 {
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_write(pkt).unwrap();
    }

    // Drain written packets
    while chain.poll_write().is_some() {}

    // Request retransmission of packet 0 (should be expired)
    let nack = create_nack_packet(
        base_time,
        0x11111111,
        ssrc,
        vec![rtcp::transport_feedbacks::transport_layer_nack::NackPair {
            packet_id: 0,
            lost_packets: 0,
        }],
    );
    chain.handle_read(nack).unwrap();
    while chain.poll_read().is_some() {}

    // Should not retransmit expired packet
    let mut retransmit_count = 0;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtp(rtp) = &pkt.message
            && rtp.header.sequence_number == 0
        {
            retransmit_count += 1;
        }
    }

    assert_eq!(
        retransmit_count, 0,
        "Expired packets should not be retransmitted"
    );
}

// =============================================================================
// Combined Generator + Responder Tests
// =============================================================================

#[test]
fn test_combined_nack_generator_and_responder() {
    // Build chain with both generator (for receiving) and responder (for sending)
    let mut chain = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();

    let local_ssrc = 0x11111111;
    let remote_ssrc = 0x22222222;

    // Bind local stream (for responder)
    chain.bind_local_stream(&nack_stream_info(local_ssrc));
    // Bind remote stream (for generator)
    chain.bind_remote_stream(&nack_stream_info(remote_ssrc));

    let base_time = Instant::now();

    // Send local RTP packets
    for seq in 0..5u16 {
        let pkt = create_rtp_packet_with_time(base_time, local_ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_write(pkt).unwrap();
    }

    // Receive remote RTP packets with gap
    for seq in [0u16, 1, 2, 5, 6] {
        let pkt = create_rtp_packet_with_time(base_time, remote_ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Drain packets
    while chain.poll_write().is_some() {}
    while chain.poll_read().is_some() {}

    // Trigger timeout to generate NACK for remote stream
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Should generate NACK for missing packets 3, 4 from remote
    let mut nack_generated = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(nack) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                    && nack.media_ssrc == remote_ssrc
                {
                    nack_generated = true;
                }
            }
        }
    }

    assert!(
        nack_generated,
        "NACK should be generated for remote stream packet loss"
    );

    // Now simulate receiving a NACK for local stream
    let nack = create_nack_packet(
        base_time,
        remote_ssrc,
        local_ssrc,
        vec![rtcp::transport_feedbacks::transport_layer_nack::NackPair {
            packet_id: 2,
            lost_packets: 0,
        }],
    );
    chain.handle_read(nack).unwrap();
    while chain.poll_read().is_some() {}

    // Should retransmit local packet 2
    let mut retransmitted = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtp(rtp) = &pkt.message
            && rtp.header.ssrc == local_ssrc
            && rtp.header.sequence_number == 2
        {
            retransmitted = true;
        }
    }

    assert!(
        retransmitted,
        "Local packet should be retransmitted on NACK"
    );
}

#[test]
fn test_nack_unbind_stops_processing() {
    let mut chain = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();

    let local_ssrc = 0x11111111;
    let remote_ssrc = 0x22222222;

    let local_info = nack_stream_info(local_ssrc);
    let remote_info = nack_stream_info(remote_ssrc);

    chain.bind_local_stream(&local_info);
    chain.bind_remote_stream(&remote_info);

    let base_time = Instant::now();

    // Send and receive some packets
    let pkt = create_rtp_packet_with_time(base_time, local_ssrc, 0, 0, 500);
    chain.handle_write(pkt).unwrap();

    let pkt = create_rtp_packet_with_time(base_time, remote_ssrc, 0, 0, 500);
    chain.handle_read(pkt).unwrap();

    // Unbind streams
    chain.unbind_local_stream(&local_info);
    chain.unbind_remote_stream(&remote_info);

    // Drain packets
    while chain.poll_write().is_some() {}
    while chain.poll_read().is_some() {}

    // Packets should no longer be processed for NACK
    // Send packet with gap after unbind
    let pkt = create_rtp_packet_with_time(base_time, remote_ssrc, 10, 30000, 500);
    chain.handle_read(pkt).unwrap();
    while chain.poll_read().is_some() {}

    // Trigger timeout
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // No NACK should be generated for unbound stream
    let mut nack_found = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                    .is_some()
                {
                    nack_found = true;
                }
            }
        }
    }

    assert!(
        !nack_found,
        "No NACK should be generated for unbound streams"
    );
}

#[test]
fn test_nack_multiple_streams() {
    let mut chain = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let video_ssrc = 0x11111111;
    let audio_ssrc = 0x22222222;

    chain.bind_remote_stream(&nack_stream_info(video_ssrc));
    chain.bind_remote_stream(&nack_stream_info(audio_ssrc));

    let base_time = Instant::now();

    // Receive video packets with gap
    for seq in [0u16, 1, 5, 6] {
        let pkt = create_rtp_packet_with_time(base_time, video_ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Receive audio packets with gap
    for seq in [0u16, 1, 10, 11] {
        let pkt = create_rtp_packet_with_time(base_time, audio_ssrc, seq, seq as u32 * 960, 160);
        chain.handle_read(pkt).unwrap();
    }

    // Drain
    while chain.poll_read().is_some() {}

    // Trigger timeout
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Check for NACKs for both streams
    let mut video_nack = false;
    let mut audio_nack = false;

    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(nack) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                {
                    if nack.media_ssrc == video_ssrc {
                        video_nack = true;
                    }
                    if nack.media_ssrc == audio_ssrc {
                        audio_nack = true;
                    }
                }
            }
        }
    }

    assert!(video_nack, "NACK should be generated for video stream");
    assert!(audio_nack, "NACK should be generated for audio stream");
}

// =============================================================================
// End-to-End NACK Simulation Tests (ported from pion/interceptor/examples/nack)
// =============================================================================
//
// These tests simulate the complete NACK workflow as demonstrated in the pion
// NACK example, but using the sans-I/O pattern instead of actual UDP sockets.
//
// The pion example has:
// - Sender: NACK Responder that buffers packets and retransmits on NACK
// - Receiver: NACK Generator that detects missing packets and sends NACKs
//
// We simulate this by:
// 1. Creating separate sender and receiver interceptor chains
// 2. Simulating packet flow between them (with packet loss)
// 3. Verifying the complete NACK/retransmit cycle

/// Simulates the end-to-end NACK workflow from pion's example.
/// This test creates two separate interceptor chains (sender and receiver)
/// and simulates packet loss, NACK generation, and retransmission.
#[test]
fn test_nack_example_simulation() {
    const SSRC: u32 = 5000;

    // === SENDER SETUP ===
    // Sender uses NACK Responder to buffer packets and respond to NACKs
    let mut sender = Registry::new()
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();

    sender.bind_local_stream(&nack_stream_info(SSRC));

    // === RECEIVER SETUP ===
    // Receiver uses NACK Generator to detect packet loss and generate NACKs
    let mut receiver = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    receiver.bind_remote_stream(&nack_stream_info(SSRC));

    let base_time = Instant::now();

    // === SENDER SENDS RTP PACKETS ===
    // Send packets 0-9, simulating the sendRoutine() in pion example
    let mut sent_seqs = Vec::new();
    for seq in 0..10u16 {
        let pkt = create_rtp_packet_with_time(base_time, SSRC, seq, seq as u32 * 3000, 3);
        sender.handle_write(pkt).unwrap();

        // Collect sent packet sequence numbers
        while let Some(out_pkt) = sender.poll_write() {
            if let Packet::Rtp(rtp) = &out_pkt.message {
                sent_seqs.push(rtp.header.sequence_number);
            }
        }
    }

    assert_eq!(sent_seqs.len(), 10, "Sender should have sent 10 packets");

    // === SIMULATE NETWORK: SOME PACKETS ARE LOST ===
    // Packets 3, 5, 7 are "lost" (not delivered to receiver)
    let lost_packets: Vec<u16> = vec![3, 5, 7];

    for seq in 0..10u16 {
        if !lost_packets.contains(&seq) {
            // Deliver to receiver (recreate the packet)
            let recv_pkt = create_rtp_packet_with_time(base_time, SSRC, seq, seq as u32 * 3000, 3);
            receiver.handle_read(recv_pkt).unwrap();
        }
    }

    // Drain received packets
    while receiver.poll_read().is_some() {}

    // === RECEIVER DETECTS LOSS AND GENERATES NACK ===
    // Trigger timeout to generate NACK (simulating the NACK interval)
    receiver
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Collect NACK packets from receiver
    let mut nack_packets = Vec::new();
    while let Some(pkt) = receiver.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(nack) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                {
                    nack_packets.push(nack.clone());
                }
            }
        }
    }

    assert!(
        !nack_packets.is_empty(),
        "Receiver should generate NACK for lost packets"
    );

    // Verify NACK contains lost sequence numbers
    let mut nacked_seqs = Vec::new();
    for nack in &nack_packets {
        assert_eq!(nack.media_ssrc, SSRC);
        for nack_pair in &nack.nacks {
            nacked_seqs.push(nack_pair.packet_id);
            for i in 0..16 {
                if nack_pair.lost_packets & (1 << i) != 0 {
                    nacked_seqs.push(nack_pair.packet_id.wrapping_add(i + 1));
                }
            }
        }
    }

    for lost_seq in &lost_packets {
        assert!(
            nacked_seqs.contains(lost_seq),
            "NACK should request retransmission of seq {}",
            lost_seq
        );
    }

    // === SENDER RECEIVES NACK AND RETRANSMITS ===
    // Pass NACK to sender (simulating RTCP being sent back)
    for nack in &nack_packets {
        let nack_pkt = TaggedPacket {
            now: base_time,
            transport: TransportContext::default(),
            message: Packet::Rtcp(vec![Box::new(nack.clone())]),
        };
        sender.handle_read(nack_pkt).unwrap();
    }

    // Drain sender's read output
    while sender.poll_read().is_some() {}

    // Collect retransmitted packets from sender
    let mut retransmitted_seqs = Vec::new();
    while let Some(pkt) = sender.poll_write() {
        if let Packet::Rtp(rtp) = &pkt.message {
            retransmitted_seqs.push(rtp.header.sequence_number);
        }
    }

    // Verify all lost packets were retransmitted
    for lost_seq in &lost_packets {
        assert!(
            retransmitted_seqs.contains(lost_seq),
            "Sender should retransmit seq {}",
            lost_seq
        );
    }

    println!(
        "NACK simulation successful: lost {:?}, retransmitted {:?}",
        lost_packets, retransmitted_seqs
    );
}

/// Tests the complete NACK cycle with RTX (RFC 4588) retransmission.
/// This extends the basic simulation to use RTX format for retransmissions.
#[test]
fn test_nack_example_with_rtx() {
    const SSRC: u32 = 5000;
    const RTX_SSRC: u32 = 5001;
    const RTX_PT: u8 = 97;

    // === SENDER SETUP WITH RTX ===
    let mut sender = Registry::new()
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();

    sender.bind_local_stream(&nack_rtx_stream_info(SSRC, RTX_SSRC, RTX_PT));

    // === RECEIVER SETUP ===
    let mut receiver = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    receiver.bind_remote_stream(&nack_stream_info(SSRC));

    let base_time = Instant::now();

    // === SENDER SENDS RTP PACKETS ===
    for seq in 0..10u16 {
        let pkt = create_rtp_packet_with_time(base_time, SSRC, seq, seq as u32 * 3000, 100);
        sender.handle_write(pkt).unwrap();
        while sender.poll_write().is_some() {}
    }

    // === SIMULATE PACKET LOSS ===
    let lost_packets: Vec<u16> = vec![2, 6];

    for seq in 0..10u16 {
        if !lost_packets.contains(&seq) {
            let recv_pkt =
                create_rtp_packet_with_time(base_time, SSRC, seq, seq as u32 * 3000, 100);
            receiver.handle_read(recv_pkt).unwrap();
        }
    }

    while receiver.poll_read().is_some() {}

    // === RECEIVER GENERATES NACK ===
    receiver
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    let mut nack_packets = Vec::new();
    while let Some(pkt) = receiver.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(nack) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                {
                    nack_packets.push(nack.clone());
                }
            }
        }
    }

    // === SENDER RECEIVES NACK AND RETRANSMITS VIA RTX ===
    for nack in &nack_packets {
        let nack_pkt = TaggedPacket {
            now: base_time,
            transport: TransportContext::default(),
            message: Packet::Rtcp(vec![Box::new(nack.clone())]),
        };
        sender.handle_read(nack_pkt).unwrap();
    }

    while sender.poll_read().is_some() {}

    // Collect RTX retransmissions
    let mut rtx_packets = Vec::new();
    while let Some(pkt) = sender.poll_write() {
        if let Packet::Rtp(rtp) = pkt.message {
            rtx_packets.push(rtp);
        }
    }

    // Verify RTX format
    assert_eq!(
        rtx_packets.len(),
        lost_packets.len(),
        "Should retransmit all lost packets"
    );

    for rtx in &rtx_packets {
        // RTX packets should use RTX SSRC and payload type
        assert_eq!(rtx.header.ssrc, RTX_SSRC, "RTX should use RTX SSRC");
        assert_eq!(
            rtx.header.payload_type, RTX_PT,
            "RTX should use RTX payload type"
        );

        // RTX payload format: first 2 bytes are original sequence number (big-endian)
        assert!(rtx.payload.len() >= 2, "RTX payload should have seq header");
        let original_seq = u16::from_be_bytes([rtx.payload[0], rtx.payload[1]]);
        assert!(
            lost_packets.contains(&original_seq),
            "RTX should contain original seq {} in payload",
            original_seq
        );
    }

    println!(
        "RTX NACK simulation successful: lost {:?}, retransmitted {} RTX packets",
        lost_packets,
        rtx_packets.len()
    );
}

/// Tests continuous packet flow with periodic NACK generation,
/// simulating a realistic streaming scenario.
#[test]
fn test_continuous_stream_with_nack_recovery() {
    const SSRC: u32 = 5000;
    const TOTAL_PACKETS: u16 = 100;

    let mut sender = Registry::new()
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();
    sender.bind_local_stream(&nack_stream_info(SSRC));

    let mut receiver = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(20))
                .build(),
        )
        .build();
    receiver.bind_remote_stream(&nack_stream_info(SSRC));

    let base_time = Instant::now();
    let packet_interval = Duration::from_millis(20); // 50 packets/second

    let mut received_seqs: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut lost_seqs: Vec<u16> = Vec::new();

    // Determine which packets will be "lost" (deterministic for reproducibility)
    for seq in 0..TOTAL_PACKETS {
        // Simple deterministic "loss" pattern: every 10th packet starting from 5
        if seq % 10 == 5 {
            lost_seqs.push(seq);
        }
    }

    // === SIMULATE STREAMING WITH PACKET LOSS ===
    for seq in 0..TOTAL_PACKETS {
        let pkt_time = base_time + packet_interval * seq as u32;

        // Sender sends packet
        let pkt = create_rtp_packet_with_time(pkt_time, SSRC, seq, seq as u32 * 3000, 100);
        sender.handle_write(pkt).unwrap();

        // Drain sent packet
        while sender.poll_write().is_some() {}

        // Deliver to receiver (unless "lost")
        if !lost_seqs.contains(&seq) {
            let recv_pkt = create_rtp_packet_with_time(pkt_time, SSRC, seq, seq as u32 * 3000, 100);
            receiver.handle_read(recv_pkt).unwrap();
            while receiver.poll_read().is_some() {}
            received_seqs.insert(seq);
        }

        // Periodically trigger NACK generation and handle retransmissions
        if seq % 10 == 9 {
            // Trigger receiver timeout to generate NACKs
            receiver.handle_timeout(pkt_time).unwrap();

            // Collect NACKs from receiver and forward to sender
            while let Some(nack_pkt) = receiver.poll_write() {
                if let Packet::Rtcp(rtcp_packets) = nack_pkt.message {
                    // Forward NACK to sender
                    let sender_nack = TaggedPacket {
                        now: pkt_time,
                        transport: TransportContext::default(),
                        message: Packet::Rtcp(rtcp_packets),
                    };
                    sender.handle_read(sender_nack).unwrap();
                    while sender.poll_read().is_some() {}

                    // Collect retransmissions from sender
                    while let Some(retrans_pkt) = sender.poll_write() {
                        if let Packet::Rtp(rtp) = &retrans_pkt.message {
                            // Mark as received via retransmission
                            received_seqs.insert(rtp.header.sequence_number);
                        }
                    }
                }
            }
        }
    }

    // Final NACK cycle
    let final_time = base_time + packet_interval * TOTAL_PACKETS as u32;
    receiver.handle_timeout(final_time).unwrap();

    while let Some(nack_pkt) = receiver.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = nack_pkt.message {
            let sender_nack = TaggedPacket {
                now: final_time,
                transport: TransportContext::default(),
                message: Packet::Rtcp(rtcp_packets),
            };
            sender.handle_read(sender_nack).unwrap();
            while sender.poll_read().is_some() {}

            while let Some(retrans_pkt) = sender.poll_write() {
                if let Packet::Rtp(rtp) = &retrans_pkt.message {
                    received_seqs.insert(rtp.header.sequence_number);
                }
            }
        }
    }

    // === VERIFY RECOVERY ===
    let recovery_count = lost_seqs
        .iter()
        .filter(|seq| received_seqs.contains(seq))
        .count();

    println!(
        "Continuous stream test: {} packets sent, {} initially lost, {} recovered via NACK",
        TOTAL_PACKETS,
        lost_seqs.len(),
        recovery_count
    );

    // All lost packets should have been recovered
    assert_eq!(
        recovery_count,
        lost_seqs.len(),
        "All lost packets should be recovered via NACK"
    );

    // All packets should have been received
    assert_eq!(
        received_seqs.len(),
        TOTAL_PACKETS as usize,
        "All packets should be received (original + retransmitted)"
    );
}

/// Tests NACK behavior with sequence number wraparound.
#[test]
fn test_nack_sequence_wraparound() {
    const SSRC: u32 = 5000;

    let mut sender = Registry::new()
        .with(NackResponderBuilder::new().with_size(512).build())
        .build();
    sender.bind_local_stream(&nack_stream_info(SSRC));

    let mut receiver = Registry::new()
        .with(
            NackGeneratorBuilder::new()
                .with_size(512)
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();
    receiver.bind_remote_stream(&nack_stream_info(SSRC));

    let base_time = Instant::now();

    // Send packets around the u16 wraparound point
    // Sequence: 65530, 65531, 65532, 65533, 65534, 65535, 0, 1, 2, 3
    let sequences: Vec<u16> = (65530..=65535).chain(0..=3).map(|s| s as u16).collect();
    let lost_seqs: Vec<u16> = vec![65533, 0, 2]; // Lost around wraparound

    // Send all packets through sender
    for &seq in &sequences {
        let pkt = create_rtp_packet_with_time(base_time, SSRC, seq, seq as u32 * 3000, 100);
        sender.handle_write(pkt).unwrap();
        while sender.poll_write().is_some() {}
    }

    // Deliver non-lost packets to receiver
    for &seq in &sequences {
        if !lost_seqs.contains(&seq) {
            let recv_pkt =
                create_rtp_packet_with_time(base_time, SSRC, seq, seq as u32 * 3000, 100);
            receiver.handle_read(recv_pkt).unwrap();
        }
    }

    while receiver.poll_read().is_some() {}

    // Generate NACKs
    receiver
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    let mut nacked_seqs = Vec::new();
    while let Some(pkt) = receiver.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = pkt.message {
            for rtcp_pkt in &rtcp_packets {
                if let Some(nack) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::transport_feedbacks::transport_layer_nack::TransportLayerNack>(
                    )
                {
                    // Extract nacked sequences
                    for nack_pair in &nack.nacks {
                        nacked_seqs.push(nack_pair.packet_id);
                        for i in 0..16 {
                            if nack_pair.lost_packets & (1 << i) != 0 {
                                nacked_seqs.push(nack_pair.packet_id.wrapping_add(i + 1));
                            }
                        }
                    }
                }
            }

            // Forward to sender
            let nack_pkt = TaggedPacket {
                now: base_time,
                transport: TransportContext::default(),
                message: Packet::Rtcp(rtcp_packets),
            };
            sender.handle_read(nack_pkt).unwrap();
        }
    }

    while sender.poll_read().is_some() {}

    // Collect retransmissions
    let mut retransmitted = Vec::new();
    while let Some(pkt) = sender.poll_write() {
        if let Packet::Rtp(rtp) = &pkt.message {
            retransmitted.push(rtp.header.sequence_number);
        }
    }

    // Verify all lost packets (including wraparound) were handled
    for &lost_seq in &lost_seqs {
        assert!(
            nacked_seqs.contains(&lost_seq),
            "NACK should request seq {} (wraparound)",
            lost_seq
        );
        assert!(
            retransmitted.contains(&lost_seq),
            "Should retransmit seq {} (wraparound)",
            lost_seq
        );
    }

    println!(
        "Wraparound test successful: lost {:?}, nacked {:?}, retransmitted {:?}",
        lost_seqs, nacked_seqs, retransmitted
    );
}
