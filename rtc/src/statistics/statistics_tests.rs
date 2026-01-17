//! Integration tests for statistics collection pipeline.
//!
//! These tests simulate realistic WebRTC scenarios and verify that
//! statistics are correctly collected, accumulated, and serialized.

use crate::data_channel::RTCDataChannelState;
use crate::peer_connection::transport::{
    RTCDtlsRole, RTCDtlsTransportState, RTCIceRole, RTCIceTransportState,
};
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::statistics::accumulator::{
    DataChannelStatsAccumulator, IceCandidatePairAccumulator, InboundRtpStreamAccumulator,
    OutboundRtpStreamAccumulator, PeerConnectionStatsAccumulator, RTCStatsAccumulator,
    TransportStatsAccumulator,
};
use crate::statistics::report::{RTCStatsReport, RTCStatsReportEntry};
use crate::statistics::stats::RTCStatsType;
use crate::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;
use serde_json::Value;
use std::time::{Duration, Instant};

/// Helper to normalize JSON by replacing timestamps with a constant value.
fn normalize_json(json_str: &str) -> Value {
    let mut value: Value = serde_json::from_str(json_str).expect("valid JSON");

    fn normalize_timestamps(v: &mut Value) {
        match v {
            Value::Object(map) => {
                // Normalize timestamp fields
                if map.contains_key("timestamp") {
                    map.insert(
                        "timestamp".to_string(),
                        Value::String("NORMALIZED".to_string()),
                    );
                }
                if map.contains_key("lastPacketReceivedTimestamp") {
                    map.insert(
                        "lastPacketReceivedTimestamp".to_string(),
                        Value::String("NORMALIZED".to_string()),
                    );
                }
                if map.contains_key("lastPacketSentTimestamp") {
                    map.insert(
                        "lastPacketSentTimestamp".to_string(),
                        Value::String("NORMALIZED".to_string()),
                    );
                }
                if map.contains_key("estimatedPlayoutTimestamp") {
                    map.insert(
                        "estimatedPlayoutTimestamp".to_string(),
                        Value::String("NORMALIZED".to_string()),
                    );
                }
                if map.contains_key("remoteTimestamp") {
                    map.insert(
                        "remoteTimestamp".to_string(),
                        Value::String("NORMALIZED".to_string()),
                    );
                }
                for (_, value) in map.iter_mut() {
                    normalize_timestamps(value);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    normalize_timestamps(item);
                }
            }
            _ => {}
        }
    }

    normalize_timestamps(&mut value);
    value
}

/// Test a complete video call scenario with statistics collection.
#[test]
fn test_video_call_statistics_flow() {
    let now = Instant::now();

    // Create accumulators for a video call
    let pc_acc = PeerConnectionStatsAccumulator::default();
    let mut transport_acc = TransportStatsAccumulator {
        transport_id: "RTCTransport_0".to_string(),
        ice_role: RTCIceRole::Controlling,
        ice_local_username_fragment: "abcd1234".to_string(),
        ..Default::default()
    };
    let mut pair_acc = IceCandidatePairAccumulator {
        transport_id: "RTCTransport_0".to_string(),
        local_candidate_id: "RTCIceCandidate_host_udp_192.168.1.100_50000".to_string(),
        remote_candidate_id: "RTCIceCandidate_srflx_udp_203.0.113.50_60000".to_string(),
        ..Default::default()
    };
    let mut inbound_acc = InboundRtpStreamAccumulator {
        ssrc: 12345678,
        kind: RtpCodecKind::Video,
        transport_id: "RTCTransport_0".to_string(),
        codec_id: "RTCCodec_video_96".to_string(),
        track_identifier: "remote-video".to_string(),
        mid: "0".to_string(),
        rtx_ssrc: Some(12345679),
        ..Default::default()
    };
    let mut outbound_acc = OutboundRtpStreamAccumulator {
        ssrc: 87654321,
        kind: RtpCodecKind::Video,
        transport_id: "RTCTransport_0".to_string(),
        codec_id: "RTCCodec_video_96".to_string(),
        mid: "0".to_string(),
        rtx_ssrc: Some(87654322),
        active: true,
        ..Default::default()
    };

    // Simulate ICE connectivity check
    pair_acc.on_stun_request_sent();
    pair_acc.on_stun_response_received();
    pair_acc.on_rtt_measured(0.025);
    pair_acc.state = RTCStatsIceCandidatePairState::Succeeded;
    pair_acc.nominated = true;

    // Simulate transport state transitions
    transport_acc.on_ice_state_changed(RTCIceTransportState::Connected);
    transport_acc.on_dtls_state_changed(RTCDtlsTransportState::Connected);
    transport_acc.on_dtls_handshake_complete(
        "DTLS 1.2".to_string(),
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        "SRTP_AES128_CM_HMAC_SHA1_80".to_string(),
        RTCDtlsRole::Client,
    );
    transport_acc.on_selected_candidate_pair_changed("RTCIceCandidatePair_0".to_string());

    // Simulate 30fps video for 1 second (30 frames)
    for i in 0..30 {
        let t = now + Duration::from_millis(i * 33);

        // Sending video
        outbound_acc.on_rtp_sent(12, 10000, t); // ~10KB per frame
        outbound_acc.on_frame_sent(i == 0); // First frame is huge (keyframe)
        transport_acc.on_packet_sent(10012);
        pair_acc.on_packet_sent(10012, t);

        // Receiving video
        inbound_acc.on_rtp_received(12, 8000, t);
        inbound_acc.on_frame_received();
        transport_acc.on_packet_received(8012);
        pair_acc.on_packet_received(8012, t);
    }

    // Simulate packet loss and retransmission
    inbound_acc.on_rtcp_rr_generated(2, 0.003);
    inbound_acc.on_nack_sent();
    inbound_acc.on_rtx_received(8000);

    outbound_acc.on_nack_received();
    outbound_acc.on_rtx_sent(10000);

    // Simulate RTCP reports
    inbound_acc.on_rtcp_sr_received(30, 300000, now);
    outbound_acc.on_rtcp_rr_received(28, 2, 0.003, 0.067, 0.025);

    // Generate stats report
    let stats = vec![
        RTCStatsReportEntry::PeerConnection(pc_acc.snapshot(now)),
        RTCStatsReportEntry::Transport(transport_acc.snapshot(now)),
        RTCStatsReportEntry::IceCandidatePair(pair_acc.snapshot(now, "RTCIceCandidatePair_0")),
        RTCStatsReportEntry::InboundRtp(
            inbound_acc.snapshot(now, "RTCInboundRTPStream_video_12345678"),
        ),
        RTCStatsReportEntry::OutboundRtp(
            outbound_acc.snapshot(now, "RTCOutboundRTPStream_video_87654321"),
        ),
        RTCStatsReportEntry::RemoteInboundRtp(outbound_acc.snapshot_remote(now)),
        RTCStatsReportEntry::RemoteOutboundRtp(inbound_acc.snapshot_remote(now)),
    ];

    let report = RTCStatsReport::new(stats);

    // Verify report structure
    assert_eq!(report.len(), 7);
    assert!(report.peer_connection().is_some());
    assert!(report.transport().is_some());
    assert_eq!(report.inbound_rtp_streams().count(), 1);
    assert_eq!(report.outbound_rtp_streams().count(), 1);
    assert_eq!(report.candidate_pairs().count(), 1);

    // Verify transport stats
    let transport = report.transport().unwrap();
    assert_eq!(transport.packets_sent, 30);
    assert_eq!(transport.packets_received, 30);
    assert_eq!(transport.ice_state, RTCIceTransportState::Connected);
    assert_eq!(transport.dtls_state, RTCDtlsTransportState::Connected);
    assert_eq!(transport.tls_version, "DTLS 1.2");

    // Verify candidate pair stats
    let pair = report.candidate_pairs().next().unwrap();
    assert_eq!(pair.packets_sent, 30);
    assert_eq!(pair.packets_received, 30);
    assert!(pair.nominated);
    assert_eq!(pair.state, RTCStatsIceCandidatePairState::Succeeded);
    assert_eq!(pair.current_round_trip_time, 0.025);

    // Verify inbound RTP stats
    let inbound = report.inbound_rtp_streams().next().unwrap();
    assert_eq!(inbound.received_rtp_stream_stats.packets_received, 30);
    assert_eq!(inbound.bytes_received, 240000); // 30 * 8000
    assert_eq!(inbound.frames_received, 30);
    assert_eq!(inbound.nack_count, 1);
    assert_eq!(inbound.retransmitted_packets_received, 1);
    assert_eq!(inbound.received_rtp_stream_stats.packets_lost, 2);

    // Verify outbound RTP stats
    let outbound = report.outbound_rtp_streams().next().unwrap();
    assert_eq!(outbound.sent_rtp_stream_stats.packets_sent, 30);
    assert_eq!(outbound.sent_rtp_stream_stats.bytes_sent, 300000); // 30 * 10000
    assert_eq!(outbound.frames_sent, 30);
    assert_eq!(outbound.huge_frames_sent, 1);
    assert_eq!(outbound.nack_count, 1);
    assert_eq!(outbound.retransmitted_packets_sent, 1);
}

/// Test data channel statistics collection.
#[test]
fn test_data_channel_statistics_flow() {
    let now = Instant::now();

    let mut pc_acc = PeerConnectionStatsAccumulator::default();
    let mut dc_acc = DataChannelStatsAccumulator {
        data_channel_identifier: 1,
        label: "chat".to_string(),
        protocol: "".to_string(),
        state: RTCDataChannelState::Connecting,
        ..Default::default()
    };

    // Data channel opens
    dc_acc.on_state_changed(RTCDataChannelState::Open);
    pc_acc.on_data_channel_opened();

    // Send and receive messages
    for _ in 0..10 {
        dc_acc.on_message_sent(100);
    }
    for _ in 0..8 {
        dc_acc.on_message_received(120);
    }

    // Generate stats
    let dc_stats = dc_acc.snapshot(now, "RTCDataChannel_1".to_string());
    let pc_stats = pc_acc.snapshot(now);

    // Verify data channel stats
    assert_eq!(dc_stats.data_channel_identifier, 1);
    assert_eq!(dc_stats.label, "chat");
    assert_eq!(dc_stats.state, RTCDataChannelState::Open);
    assert_eq!(dc_stats.messages_sent, 10);
    assert_eq!(dc_stats.bytes_sent, 1000);
    assert_eq!(dc_stats.messages_received, 8);
    assert_eq!(dc_stats.bytes_received, 960);

    // Verify peer connection stats
    assert_eq!(pc_stats.data_channels_opened, 1);
    assert_eq!(pc_stats.data_channels_closed, 0);

    // Verify JSON serialization
    let json = serde_json::to_string(&dc_stats).expect("should serialize");
    let normalized = normalize_json(&json);

    assert_eq!(normalized["dataChannelIdentifier"], 1);
    assert_eq!(normalized["label"], "chat");
    assert_eq!(normalized["state"], "open");
    assert_eq!(normalized["messagesSent"], 10);
    assert_eq!(normalized["bytesSent"], 1000);
    assert_eq!(normalized["type"], "data-channel");
}

/// Test audio stream statistics collection.
#[test]
fn test_audio_stream_statistics_flow() {
    let now = Instant::now();

    let mut inbound_acc = InboundRtpStreamAccumulator {
        ssrc: 11111111,
        kind: RtpCodecKind::Audio,
        transport_id: "RTCTransport_0".to_string(),
        codec_id: "RTCCodec_audio_111".to_string(),
        track_identifier: "remote-audio".to_string(),
        mid: "1".to_string(),
        ..Default::default()
    };

    let mut outbound_acc = OutboundRtpStreamAccumulator {
        ssrc: 22222222,
        kind: RtpCodecKind::Audio,
        transport_id: "RTCTransport_0".to_string(),
        codec_id: "RTCCodec_audio_111".to_string(),
        mid: "1".to_string(),
        active: true,
        ..Default::default()
    };

    // Simulate 1 second of audio at 50 packets/sec (20ms packets)
    for i in 0..50 {
        let t = now + Duration::from_millis(i * 20);
        outbound_acc.on_rtp_sent(12, 160, t); // 160 bytes = 20ms of audio
        inbound_acc.on_rtp_received(12, 160, t);
    }

    // No packet loss for audio
    inbound_acc.on_rtcp_rr_generated(0, 0.001);
    outbound_acc.on_rtcp_rr_received(50, 0, 0.001, 0.0, 0.020);

    // Generate stats
    let inbound_stats = inbound_acc.snapshot(now, "RTCInboundRTPStream_audio_11111111");
    let outbound_stats = outbound_acc.snapshot(now, "RTCOutboundRTPStream_audio_22222222");

    // Verify inbound audio stats
    assert_eq!(inbound_stats.received_rtp_stream_stats.packets_received, 50);
    assert_eq!(inbound_stats.bytes_received, 8000); // 50 * 160
    assert_eq!(inbound_stats.received_rtp_stream_stats.packets_lost, 0);
    assert_eq!(inbound_stats.received_rtp_stream_stats.jitter, 0.001);
    assert_eq!(
        inbound_stats
            .received_rtp_stream_stats
            .rtp_stream_stats
            .kind,
        RtpCodecKind::Audio
    );

    // Verify outbound audio stats
    assert_eq!(outbound_stats.sent_rtp_stream_stats.packets_sent, 50);
    assert_eq!(outbound_stats.sent_rtp_stream_stats.bytes_sent, 8000);
    assert!(outbound_stats.active);

    // Verify JSON serialization
    let inbound_json = serde_json::to_string(&inbound_stats).expect("should serialize");
    assert!(inbound_json.contains("\"kind\":\"audio\""));
    assert!(inbound_json.contains("\"type\":\"inbound-rtp\""));

    let outbound_json = serde_json::to_string(&outbound_stats).expect("should serialize");
    assert!(outbound_json.contains("\"kind\":\"audio\""));
    assert!(outbound_json.contains("\"type\":\"outbound-rtp\""));
}

/// Test that JSON output matches expected W3C format.
#[test]
fn test_json_format_compliance() {
    let now = Instant::now();

    // Create peer connection stats
    let mut pc_acc = PeerConnectionStatsAccumulator::default();
    pc_acc.on_data_channel_opened();
    let pc_stats = pc_acc.snapshot(now);

    // Verify camelCase field names (W3C spec)
    let json = serde_json::to_string(&pc_stats).expect("should serialize");
    let normalized = normalize_json(&json);

    // Check expected structure
    assert!(normalized.get("timestamp").is_some());
    assert!(normalized.get("type").is_some());
    assert!(normalized.get("id").is_some());
    assert!(normalized.get("dataChannelsOpened").is_some());
    assert!(normalized.get("dataChannelsClosed").is_some());

    // Type should be hyphenated per W3C spec
    assert_eq!(normalized["type"], "peer-connection");
}

/// Test RTCStatsReport iteration and filtering.
#[test]
fn test_stats_report_iteration() {
    let now = Instant::now();

    let pc_acc = PeerConnectionStatsAccumulator::default();
    let transport_acc = TransportStatsAccumulator::default();
    let mut dc_acc1 = DataChannelStatsAccumulator {
        data_channel_identifier: 1,
        label: "channel1".to_string(),
        state: RTCDataChannelState::Open,
        ..Default::default()
    };
    let mut dc_acc2 = DataChannelStatsAccumulator {
        data_channel_identifier: 2,
        label: "channel2".to_string(),
        state: RTCDataChannelState::Open,
        ..Default::default()
    };

    dc_acc1.on_message_sent(100);
    dc_acc2.on_message_sent(200);

    let stats = vec![
        RTCStatsReportEntry::PeerConnection(pc_acc.snapshot(now)),
        RTCStatsReportEntry::Transport(transport_acc.snapshot(now)),
        RTCStatsReportEntry::DataChannel(dc_acc1.snapshot(now, "RTCDataChannel_1".to_string())),
        RTCStatsReportEntry::DataChannel(dc_acc2.snapshot(now, "RTCDataChannel_2".to_string())),
    ];

    let report = RTCStatsReport::new(stats);

    // Test len and is_empty
    assert_eq!(report.len(), 4);
    assert!(!report.is_empty());

    // Test get by ID
    assert!(report.get("RTCPeerConnection").is_some());
    assert!(report.get("RTCDataChannel_1").is_some());
    assert!(report.get("RTCDataChannel_2").is_some());
    assert!(report.get("nonexistent").is_none());

    // Test contains
    assert!(report.contains("RTCPeerConnection"));
    assert!(!report.contains("nonexistent"));

    // Test iter_by_type
    let data_channels: Vec<_> = report.iter_by_type(RTCStatsType::DataChannel).collect();
    assert_eq!(data_channels.len(), 2);

    let peer_connections: Vec<_> = report.iter_by_type(RTCStatsType::PeerConnection).collect();
    assert_eq!(peer_connections.len(), 1);

    // Test convenience accessors
    assert!(report.peer_connection().is_some());
    assert!(report.transport().is_some());
    assert_eq!(report.data_channels().count(), 2);
}

/// Test candidate pair state transitions.
#[test]
fn test_ice_candidate_pair_state_transitions() {
    let now = Instant::now();

    let mut pair_acc = IceCandidatePairAccumulator {
        transport_id: "RTCTransport_0".to_string(),
        local_candidate_id: "local_1".to_string(),
        remote_candidate_id: "remote_1".to_string(),
        state: RTCStatsIceCandidatePairState::Waiting,
        ..Default::default()
    };

    // Initial state
    let stats1 = pair_acc.snapshot(now, "pair_1");
    assert_eq!(stats1.state, RTCStatsIceCandidatePairState::Waiting);
    assert!(!stats1.nominated);

    // Start checking
    pair_acc.state = RTCStatsIceCandidatePairState::InProgress;
    pair_acc.on_stun_request_sent();

    let stats2 = pair_acc.snapshot(now, "pair_1");
    assert_eq!(stats2.state, RTCStatsIceCandidatePairState::InProgress);
    assert_eq!(stats2.requests_sent, 1);

    // Succeed and nominate
    pair_acc.state = RTCStatsIceCandidatePairState::Succeeded;
    pair_acc.nominated = true;
    pair_acc.on_stun_response_received();
    pair_acc.on_rtt_measured(0.020);

    let stats3 = pair_acc.snapshot(now, "pair_1");
    assert_eq!(stats3.state, RTCStatsIceCandidatePairState::Succeeded);
    assert!(stats3.nominated);
    assert_eq!(stats3.responses_received, 1);
    assert_eq!(stats3.current_round_trip_time, 0.020);

    // Verify JSON serialization
    let json = serde_json::to_string(&stats3).expect("should serialize");
    assert!(json.contains("\"state\":\"succeeded\""));
    assert!(json.contains("\"nominated\":true"));
}

/// Test accumulator isolation (stats don't leak between accumulators).
#[test]
fn test_accumulator_isolation() {
    let now = Instant::now();

    let mut acc1 = InboundRtpStreamAccumulator {
        ssrc: 1111,
        kind: RtpCodecKind::Video,
        ..Default::default()
    };

    let acc2 = InboundRtpStreamAccumulator {
        ssrc: 2222,
        kind: RtpCodecKind::Audio,
        ..Default::default()
    };

    // Update acc1 only
    acc1.on_rtp_received(12, 1000, now);
    acc1.on_frame_received();
    acc1.on_nack_sent();

    // acc2 should be unchanged
    let stats1 = acc1.snapshot(now, "stream_1");
    let stats2 = acc2.snapshot(now, "stream_2");

    assert_eq!(stats1.received_rtp_stream_stats.packets_received, 1);
    assert_eq!(stats1.frames_received, 1);
    assert_eq!(stats1.nack_count, 1);

    assert_eq!(stats2.received_rtp_stream_stats.packets_received, 0);
    assert_eq!(stats2.frames_received, 0);
    assert_eq!(stats2.nack_count, 0);
}

/// Test large-scale statistics accumulation.
#[test]
fn test_high_volume_accumulation() {
    let now = Instant::now();

    let mut outbound_acc = OutboundRtpStreamAccumulator {
        ssrc: 99999999,
        kind: RtpCodecKind::Video,
        active: true,
        ..Default::default()
    };

    // Simulate 1 hour of 30fps video (108,000 frames)
    let packet_count = 108_000u64;
    let bytes_per_packet = 1200usize;

    for i in 0..packet_count {
        let t = now + Duration::from_millis(i * 33);
        outbound_acc.on_rtp_sent(12, bytes_per_packet, t);
        outbound_acc.on_frame_sent(i % 30 == 0); // Keyframe every 30 frames
    }

    let stats = outbound_acc.snapshot(now, "test");

    assert_eq!(stats.sent_rtp_stream_stats.packets_sent, packet_count);
    assert_eq!(
        stats.sent_rtp_stream_stats.bytes_sent,
        packet_count * bytes_per_packet as u64
    );
    assert_eq!(stats.frames_sent, packet_count as u32);
    assert_eq!(stats.huge_frames_sent, 3600); // 108000 / 30

    // Verify JSON serialization works with large numbers
    let json = serde_json::to_string(&stats).expect("should serialize");
    assert!(json.contains(&format!("\"packetsSent\":{}", packet_count)));
}

/// Test RTCStatsAccumulator master accumulator snapshot.
#[test]
fn test_master_accumulator_snapshot() {
    let now = Instant::now();

    let mut master = RTCStatsAccumulator::new();

    // Set up transport
    master.transport.transport_id = "RTCTransport_0".to_string();
    master
        .transport
        .on_ice_state_changed(RTCIceTransportState::Connected);
    master
        .transport
        .on_dtls_state_changed(RTCDtlsTransportState::Connected);

    // Create inbound stream
    let inbound = master.get_or_create_inbound_rtp_streams(
        12345678,
        RtpCodecKind::Video,
        "video-track",
        "0",
        Some(12345679),
        None,
    );
    inbound.on_rtp_received(12, 1000, now);
    inbound.on_frame_received();

    // Create outbound stream
    let outbound = master.get_or_create_outbound_rtp_streams(
        87654321,
        RtpCodecKind::Video,
        "0",
        "",
        0,
        Some(87654322),
    );
    outbound.on_rtp_sent(12, 1200, now);
    outbound.on_frame_sent(true);

    // Create data channel
    let dc = master.get_or_create_data_channel(1, "test-channel", "");
    dc.on_message_sent(100);
    master.peer_connection.on_data_channel_opened();

    // Generate snapshot
    let report = master.snapshot(now);

    // Verify report contents
    assert!(report.peer_connection().is_some());
    assert!(report.transport().is_some());
    assert_eq!(report.inbound_rtp_streams().count(), 1);
    assert_eq!(report.outbound_rtp_streams().count(), 1);
    assert_eq!(report.data_channels().count(), 1);

    // Verify stats values
    let pc = report.peer_connection().unwrap();
    assert_eq!(pc.data_channels_opened, 1);

    let transport = report.transport().unwrap();
    assert_eq!(transport.ice_state, RTCIceTransportState::Connected);

    let inbound_stats = report.inbound_rtp_streams().next().unwrap();
    assert_eq!(inbound_stats.received_rtp_stream_stats.packets_received, 1);
    assert_eq!(inbound_stats.frames_received, 1);

    let outbound_stats = report.outbound_rtp_streams().next().unwrap();
    assert_eq!(outbound_stats.sent_rtp_stream_stats.packets_sent, 1);
    assert_eq!(outbound_stats.frames_sent, 1);
}

/// Test RTX/FEC packet tracking via master accumulator.
#[test]
fn test_rtx_fec_tracking() {
    let now = Instant::now();

    let mut master = RTCStatsAccumulator::new();

    // Create inbound stream with RTX and FEC SSRCs
    let primary_ssrc = 12345678u32;
    let rtx_ssrc = 12345679u32;
    let fec_ssrc = 12345680u32;

    master.get_or_create_inbound_rtp_streams(
        primary_ssrc,
        RtpCodecKind::Video,
        "video-track",
        "0",
        Some(rtx_ssrc),
        Some(fec_ssrc),
    );

    // Receive primary packets
    if let Some(stream) = master.inbound_rtp_streams.get_mut(&primary_ssrc) {
        stream.on_rtp_received(12, 1000, now);
        stream.on_rtp_received(12, 1000, now);
    }

    // Track RTX packet (should update retransmitted counters)
    let rtx_tracked = master.on_rtx_packet_received_if_rtx(rtx_ssrc, 1000);
    assert!(rtx_tracked);

    // Track FEC packet
    let fec_tracked = master.on_fec_packet_received_if_fec(fec_ssrc, 500);
    assert!(fec_tracked);

    // Unknown SSRC should not be tracked
    let unknown_tracked = master.on_rtx_packet_received_if_rtx(99999999, 1000);
    assert!(!unknown_tracked);

    // Verify stats
    let report = master.snapshot(now);
    let inbound = report.inbound_rtp_streams().next().unwrap();

    assert_eq!(inbound.received_rtp_stream_stats.packets_received, 2);
    assert_eq!(inbound.retransmitted_packets_received, 1);
    assert_eq!(inbound.retransmitted_bytes_received, 1000);
    assert_eq!(inbound.fec_packets_received, 1);
    assert_eq!(inbound.fec_bytes_received, 500);
}

/// Test JSON snapshot comparison for peer connection stats.
#[test]
fn test_peer_connection_json_snapshot() {
    let now = Instant::now();

    let mut pc_acc = PeerConnectionStatsAccumulator::default();
    pc_acc.on_data_channel_opened();
    pc_acc.on_data_channel_opened();
    pc_acc.on_data_channel_closed();

    let stats = pc_acc.snapshot(now);
    let json = serde_json::to_string_pretty(&stats).expect("should serialize");
    let normalized = normalize_json(&json);

    // Verify structure matches W3C spec
    assert_eq!(normalized["type"], "peer-connection");
    assert_eq!(normalized["id"], "RTCPeerConnection");
    assert_eq!(normalized["dataChannelsOpened"], 2);
    assert_eq!(normalized["dataChannelsClosed"], 1);
}

/// Test JSON snapshot comparison for transport stats.
#[test]
fn test_transport_json_snapshot() {
    let now = Instant::now();

    let mut transport_acc = TransportStatsAccumulator {
        transport_id: "RTCTransport_0".to_string(),
        ice_role: RTCIceRole::Controlling,
        ..Default::default()
    };

    transport_acc.on_packet_sent(1000);
    transport_acc.on_packet_received(800);
    transport_acc.on_ice_state_changed(RTCIceTransportState::Connected);
    transport_acc.on_dtls_state_changed(RTCDtlsTransportState::Connected);
    transport_acc.on_dtls_handshake_complete(
        "DTLS 1.2".to_string(),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        "SRTP_AES128_CM_HMAC_SHA1_80".to_string(),
        RTCDtlsRole::Server,
    );

    let stats = transport_acc.snapshot(now);
    let json = serde_json::to_string_pretty(&stats).expect("should serialize");
    let normalized = normalize_json(&json);

    // Verify structure
    assert_eq!(normalized["type"], "transport");
    assert_eq!(normalized["packetsSent"], 1);
    assert_eq!(normalized["bytesSent"], 1000);
    assert_eq!(normalized["packetsReceived"], 1);
    assert_eq!(normalized["bytesReceived"], 800);
    assert_eq!(normalized["iceState"], "connected");
    assert_eq!(normalized["dtlsState"], "connected");
    assert_eq!(normalized["tlsVersion"], "DTLS 1.2");
    assert_eq!(normalized["dtlsRole"], "server");
}
