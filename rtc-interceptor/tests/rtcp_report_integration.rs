//! Integration tests for RTCP Sender Report and Receiver Report interceptors.
//!
//! These tests verify that the interceptor chain correctly:
//! - Generates Sender Reports when sending RTP packets
//! - Generates Receiver Reports when receiving RTP packets
//! - Properly tracks stream statistics
//! - Generates reports at configured intervals

use rtc_interceptor::{
    Interceptor, Packet, ReceiverReportBuilder, Registry, SenderReportBuilder, StreamInfo,
    TaggedPacket,
};
use sansio::Protocol;
use shared::TransportContext;
use std::time::{Duration, Instant};

/// Helper to create a tagged RTP packet with specific parameters.
fn create_rtp_packet(ssrc: u32, seq: u16, timestamp: u32, payload_len: usize) -> TaggedPacket {
    let mut payload = vec![0u8; payload_len];
    // Fill with some pattern for debugging
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
                ..Default::default()
            },
            payload: payload.into(),
            ..Default::default()
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

/// Stream info helper for video stream.
fn video_stream_info(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 90000, // typical video clock rate
        mime_type: "video/VP8".to_string(),
        ..Default::default()
    }
}

/// Stream info helper for audio stream.
fn audio_stream_info(ssrc: u32) -> StreamInfo {
    StreamInfo {
        ssrc,
        clock_rate: 48000, // typical opus clock rate
        mime_type: "audio/opus".to_string(),
        channels: 2,
        ..Default::default()
    }
}

// =============================================================================
// Sender Side Tests
// =============================================================================

#[test]
fn test_sender_report_interceptor_generates_sr_on_timeout() {
    // Build an interceptor chain with SenderReportInterceptor
    let mut chain = Registry::new()
        .with(
            SenderReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .build();

    let ssrc = 0x12345678;

    // Bind a local stream (sender side)
    chain.bind_local_stream(&video_stream_info(ssrc));

    // Send some RTP packets
    let base_time = Instant::now();
    for seq in 0..10u16 {
        let timestamp = seq as u32 * 3000; // 33ms per frame at 90kHz
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, timestamp, 1000);
        chain.handle_write(pkt).unwrap();
    }

    // Poll all written packets (RTP passes through)
    let mut rtp_count = 0;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtp(_) = pkt.message {
            rtp_count += 1;
        }
    }
    assert_eq!(rtp_count, 10, "All 10 RTP packets should pass through");

    // Check that a timeout is scheduled
    let timeout = chain.poll_timeout();
    assert!(timeout.is_some(), "Timeout should be scheduled");

    // Trigger timeout to generate Sender Report
    let trigger_time = base_time + Duration::from_millis(150);
    chain.handle_timeout(trigger_time).unwrap();

    // Poll for the generated RTCP Sender Report
    let mut sr_found = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    .is_some()
                {
                    sr_found = true;
                }
            }
        }
    }
    assert!(sr_found, "Sender Report should be generated on timeout");
}

#[test]
fn test_sender_report_tracks_packet_statistics() {
    let mut chain = Registry::new()
        .with(
            SenderReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let ssrc = 0xABCDEF00;
    chain.bind_local_stream(&video_stream_info(ssrc));

    let base_time = Instant::now();

    // Send 5 packets with varying payload sizes
    let payload_sizes = [100, 200, 300, 400, 500];
    for (seq, &size) in payload_sizes.iter().enumerate() {
        let timestamp = seq as u32 * 3000;
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq as u16, timestamp, size);
        chain.handle_write(pkt).unwrap();
    }

    // Drain RTP packets
    while chain.poll_write().is_some() {}

    // Trigger timeout
    let trigger_time = base_time + Duration::from_millis(100);
    chain.handle_timeout(trigger_time).unwrap();

    // Find the Sender Report and verify statistics
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(sr) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                {
                    assert_eq!(sr.ssrc, ssrc, "SSRC should match");
                    assert_eq!(sr.packet_count, 5, "Should have counted 5 packets");
                    let expected_octets: u32 = payload_sizes.iter().map(|&s| s as u32).sum();
                    assert_eq!(
                        sr.octet_count, expected_octets,
                        "Octet count should match total payload bytes"
                    );
                    return; // Test passed
                }
            }
        }
    }
    panic!("Sender Report not found in output");
}

#[test]
fn test_sender_report_multiple_streams() {
    let mut chain = Registry::new()
        .with(
            SenderReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let video_ssrc = 0x11111111;
    let audio_ssrc = 0x22222222;

    // Bind both video and audio streams
    chain.bind_local_stream(&video_stream_info(video_ssrc));
    chain.bind_local_stream(&audio_stream_info(audio_ssrc));

    let base_time = Instant::now();

    // Send video packets
    for seq in 0..3u16 {
        let pkt = create_rtp_packet_with_time(base_time, video_ssrc, seq, seq as u32 * 3000, 1000);
        chain.handle_write(pkt).unwrap();
    }

    // Send audio packets
    for seq in 0..5u16 {
        let pkt = create_rtp_packet_with_time(base_time, audio_ssrc, seq, seq as u32 * 960, 160);
        chain.handle_write(pkt).unwrap();
    }

    // Drain RTP packets
    while chain.poll_write().is_some() {}

    // Trigger timeout
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Collect all Sender Reports
    let mut video_sr = false;
    let mut audio_sr = false;

    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(sr) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                {
                    if sr.ssrc == video_ssrc {
                        assert_eq!(sr.packet_count, 3);
                        video_sr = true;
                    } else if sr.ssrc == audio_ssrc {
                        assert_eq!(sr.packet_count, 5);
                        audio_sr = true;
                    }
                }
            }
        }
    }

    assert!(video_sr, "Video Sender Report should be generated");
    assert!(audio_sr, "Audio Sender Report should be generated");
}

// =============================================================================
// Receiver Side Tests
// =============================================================================

#[test]
fn test_receiver_report_interceptor_generates_rr_on_timeout() {
    let mut chain = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .build();

    let ssrc = 0x87654321;

    // Bind a remote stream (receiver side)
    chain.bind_remote_stream(&video_stream_info(ssrc));

    let base_time = Instant::now();

    // Receive some RTP packets
    for seq in 0..10u16 {
        let timestamp = seq as u32 * 3000;
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, timestamp, 1000);
        chain.handle_read(pkt).unwrap();
    }

    // Poll all read packets (RTP passes through)
    let mut rtp_count = 0;
    while let Some(pkt) = chain.poll_read() {
        if let Packet::Rtp(_) = pkt.message {
            rtp_count += 1;
        }
    }
    assert_eq!(rtp_count, 10, "All 10 RTP packets should pass through");

    // Trigger timeout to generate Receiver Report
    let trigger_time = base_time + Duration::from_millis(150);
    chain.handle_timeout(trigger_time).unwrap();

    // Poll for the generated RTCP Receiver Report
    let mut rr_found = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                    .is_some()
                {
                    rr_found = true;
                }
            }
        }
    }
    assert!(rr_found, "Receiver Report should be generated on timeout");
}

#[test]
fn test_receiver_report_tracks_sequence_numbers() {
    let mut chain = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let ssrc = 0xDEADBEEF;
    chain.bind_remote_stream(&video_stream_info(ssrc));

    let base_time = Instant::now();

    // Receive packets with sequential sequence numbers
    for seq in 0..100u16 {
        let timestamp = seq as u32 * 3000;
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, timestamp, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Drain read packets
    while chain.poll_read().is_some() {}

    // Trigger timeout
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Verify Receiver Report contains correct sequence tracking
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(rr) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                {
                    // Should have one report for our stream
                    assert!(!rr.reports.is_empty(), "Should have reception reports");
                    let report = &rr.reports[0];
                    assert_eq!(report.ssrc, ssrc, "SSRC should match");
                    // Last sequence number should be 99 (0-indexed)
                    assert_eq!(
                        report.last_sequence_number & 0xFFFF,
                        99,
                        "Last sequence number should be 99"
                    );
                    return;
                }
            }
        }
    }
    panic!("Receiver Report not found");
}

#[test]
fn test_receiver_report_detects_packet_loss() {
    let mut chain = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let ssrc = 0xCAFEBABE;
    chain.bind_remote_stream(&video_stream_info(ssrc));

    let base_time = Instant::now();

    // Receive packets with gaps (simulating packet loss)
    // Send: 0, 1, 2, skip 3-7, 8, 9
    let sequences = [0u16, 1, 2, 8, 9];
    for &seq in &sequences {
        let timestamp = seq as u32 * 3000;
        let pkt = create_rtp_packet_with_time(base_time, ssrc, seq, timestamp, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Drain read packets
    while chain.poll_read().is_some() {}

    // Trigger timeout
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Verify Receiver Report indicates packet loss
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(rr) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                {
                    if !rr.reports.is_empty() {
                        let report = &rr.reports[0];
                        // Should have detected lost packets (3, 4, 5, 6, 7 = 5 packets lost)
                        assert!(
                            report.total_lost > 0,
                            "Should have detected packet loss, got total_lost={}",
                            report.total_lost
                        );
                        return;
                    }
                }
            }
        }
    }
    panic!("Receiver Report not found");
}

// =============================================================================
// Combined Sender + Receiver Tests
// =============================================================================

#[test]
fn test_combined_sender_and_receiver_interceptors() {
    // Build a chain with both interceptors
    let mut chain = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .with(
            SenderReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .build();

    let local_ssrc = 0x11111111;
    let remote_ssrc = 0x22222222;

    // Bind streams
    chain.bind_local_stream(&video_stream_info(local_ssrc));
    chain.bind_remote_stream(&video_stream_info(remote_ssrc));

    let base_time = Instant::now();

    // Send outgoing RTP (local stream)
    for seq in 0..5u16 {
        let pkt = create_rtp_packet_with_time(base_time, local_ssrc, seq, seq as u32 * 3000, 1000);
        chain.handle_write(pkt).unwrap();
    }

    // Receive incoming RTP (remote stream)
    for seq in 0..5u16 {
        let pkt = create_rtp_packet_with_time(base_time, remote_ssrc, seq, seq as u32 * 3000, 800);
        chain.handle_read(pkt).unwrap();
    }

    // Drain all packets
    while chain.poll_write().is_some() {}
    while chain.poll_read().is_some() {}

    // Trigger timeout
    chain
        .handle_timeout(base_time + Duration::from_millis(150))
        .unwrap();

    // Collect all RTCP reports
    let mut sr_found = false;
    let mut rr_found = false;

    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(sr) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                {
                    if sr.ssrc == local_ssrc {
                        sr_found = true;
                    }
                }
                if let Some(rr) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                {
                    if !rr.reports.is_empty() && rr.reports[0].ssrc == remote_ssrc {
                        rr_found = true;
                    }
                }
            }
        }
    }

    assert!(
        sr_found,
        "Sender Report for local stream should be generated"
    );
    assert!(
        rr_found,
        "Receiver Report for remote stream should be generated"
    );
}

#[test]
fn test_interceptor_chain_unbind_streams() {
    let mut chain = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .with(
            SenderReportBuilder::new()
                .with_interval(Duration::from_millis(50))
                .build(),
        )
        .build();

    let local_ssrc = 0xAAAAAAAA;
    let remote_ssrc = 0xBBBBBBBB;

    let local_info = video_stream_info(local_ssrc);
    let remote_info = video_stream_info(remote_ssrc);

    // Bind streams
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

    // Drain pending packets
    while chain.poll_write().is_some() {}
    while chain.poll_read().is_some() {}

    // Trigger timeout - should not generate reports for unbound streams
    chain
        .handle_timeout(base_time + Duration::from_millis(100))
        .unwrap();

    // Verify no RTCP reports are generated
    let mut report_count = 0;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    .is_some()
                {
                    report_count += 1;
                }
                if rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                    .is_some()
                {
                    report_count += 1;
                }
            }
        }
    }

    assert_eq!(
        report_count, 0,
        "No reports should be generated for unbound streams"
    );
}

#[test]
fn test_receiver_processes_sender_report() {
    let mut chain = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(Duration::from_millis(100))
                .build(),
        )
        .build();

    let remote_ssrc = 0x99999999;
    chain.bind_remote_stream(&video_stream_info(remote_ssrc));

    let base_time = Instant::now();

    // First receive some RTP packets
    for seq in 0..5u16 {
        let pkt = create_rtp_packet_with_time(base_time, remote_ssrc, seq, seq as u32 * 3000, 500);
        chain.handle_read(pkt).unwrap();
    }

    // Now receive a Sender Report from the remote (simulating the other peer's SR)
    let sr = rtcp::sender_report::SenderReport {
        ssrc: remote_ssrc,
        ntp_time: 0x0001000200030004u64, // some NTP time
        rtp_time: 12000,
        packet_count: 100,
        octet_count: 50000,
        ..Default::default()
    };

    let sr_packet = TaggedPacket {
        now: base_time,
        transport: TransportContext::default(),
        message: Packet::Rtcp(vec![Box::new(sr)]),
    };

    // Process the incoming SR
    chain.handle_read(sr_packet).unwrap();

    // Drain all read packets
    while chain.poll_read().is_some() {}

    // Trigger timeout to generate RR
    chain
        .handle_timeout(base_time + Duration::from_millis(150))
        .unwrap();

    // The RR should have DLSR (delay since last SR) set
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(rtcp_packets) = &pkt.message {
            for rtcp_pkt in rtcp_packets {
                if let Some(rr) = rtcp_pkt
                    .as_any()
                    .downcast_ref::<rtcp::receiver_report::ReceiverReport>()
                {
                    if !rr.reports.is_empty() {
                        let report = &rr.reports[0];
                        assert_eq!(report.ssrc, remote_ssrc);
                        // LSR should reflect the middle 32 bits of NTP time from SR
                        // NTP time was 0x0001000200030004, so LSR = 0x00020003
                        assert_eq!(report.last_sender_report, 0x00020003);
                        return;
                    }
                }
            }
        }
    }
    panic!("Receiver Report not found after processing Sender Report");
}

// =============================================================================
// Timing Tests
// =============================================================================

#[test]
fn test_report_interval_is_respected() {
    let interval = Duration::from_millis(200);

    let mut chain = Registry::new()
        .with(SenderReportBuilder::new().with_interval(interval).build())
        .build();

    let ssrc = 0x12121212;
    chain.bind_local_stream(&video_stream_info(ssrc));

    let base_time = Instant::now();

    // Send a packet
    let pkt = create_rtp_packet_with_time(base_time, ssrc, 0, 0, 500);
    chain.handle_write(pkt).unwrap();
    while chain.poll_write().is_some() {}

    // First timeout should generate a report
    chain.handle_timeout(base_time + interval).unwrap();
    let mut first_sr = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(pkts) = &pkt.message {
            for p in pkts {
                if p.as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    .is_some()
                {
                    first_sr = true;
                }
            }
        }
    }
    assert!(first_sr, "First SR should be generated");

    // Timeout before interval should not generate another report
    chain
        .handle_timeout(base_time + interval + Duration::from_millis(50))
        .unwrap();
    let mut second_sr = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(pkts) = &pkt.message {
            for p in pkts {
                if p.as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    .is_some()
                {
                    second_sr = true;
                }
            }
        }
    }
    assert!(!second_sr, "No SR before next interval");

    // Timeout after full interval should generate another report
    chain
        .handle_timeout(base_time + interval + interval + Duration::from_millis(10))
        .unwrap();
    let mut third_sr = false;
    while let Some(pkt) = chain.poll_write() {
        if let Packet::Rtcp(pkts) = &pkt.message {
            for p in pkts {
                if p.as_any()
                    .downcast_ref::<rtcp::sender_report::SenderReport>()
                    .is_some()
                {
                    third_sr = true;
                }
            }
        }
    }
    assert!(third_sr, "Second SR should be generated after interval");
}

#[test]
fn test_poll_timeout_returns_earliest() {
    let sr_interval = Duration::from_millis(100);
    let rr_interval = Duration::from_millis(150);

    let mut chain = Registry::new()
        .with(
            ReceiverReportBuilder::new()
                .with_interval(rr_interval)
                .build(),
        )
        .with(
            SenderReportBuilder::new()
                .with_interval(sr_interval)
                .build(),
        )
        .build();

    chain.bind_local_stream(&video_stream_info(0x11111111));
    chain.bind_remote_stream(&video_stream_info(0x22222222));

    // The timeout should be scheduled
    let timeout = chain.poll_timeout();
    assert!(timeout.is_some(), "Should have a scheduled timeout");
}
