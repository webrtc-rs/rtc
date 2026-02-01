//! Integration test to verify ICE candidate events are emitted correctly
//!
//! This test verifies that when local candidates (host and srflx) are added
//! via add_local_candidate(), the OnIceCandidateEvent is properly emitted
//! and can be retrieved via poll_event().

use rtc::peer_connection::RTCPeerConnection;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::sansio::Protocol;

#[test]
fn test_host_candidate_event_emission() {
    // Create a basic RTCPeerConnection
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnection::new(config).expect("Failed to create peer connection");

    // Create a host candidate
    let host_candidate = RTCIceCandidateInit {
        candidate: "candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: Some("test".to_string()),
        url: None,
    };

    println!("🔍 Adding host candidate: {}", host_candidate.candidate);

    // Add the host candidate
    pc.add_local_candidate(host_candidate)
        .expect("Failed to add host candidate");

    // Poll for events
    let mut found_event = false;
    let mut event_count = 0;
    while let Some(event) = pc.poll_event() {
        event_count += 1;
        println!(
            "📨 Polled event #{}: {:?}",
            event_count,
            std::mem::discriminant(&event)
        );

        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) = event {
            println!("✅ Received OnIceCandidateEvent for host candidate");
            println!(
                "   Address: {}:{}",
                ice_event.candidate.address, ice_event.candidate.port
            );
            println!("   Type: {:?}", ice_event.candidate.typ);
            println!("   Foundation: {}", ice_event.candidate.foundation);
            assert_eq!(
                ice_event.candidate.typ,
                rtc::peer_connection::transport::RTCIceCandidateType::Host
            );
            found_event = true;
        }
    }

    println!("📊 Total events polled: {}", event_count);
    assert!(
        found_event,
        "OnIceCandidateEvent was not emitted for host candidate"
    );
}

#[test]
fn test_srflx_candidate_event_emission() {
    // Create a basic RTCPeerConnection
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnection::new(config).expect("Failed to create peer connection");

    // Create an srflx candidate (server reflexive)
    let srflx_candidate = RTCIceCandidateInit {
        candidate: "candidate:2 1 udp 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport 54321".to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: Some("test".to_string()),
        url: Some("stun:stun.example.com:3478".to_string()),
    };

    println!("🔍 Adding srflx candidate: {}", srflx_candidate.candidate);

    // Add the srflx candidate
    pc.add_local_candidate(srflx_candidate)
        .expect("Failed to add srflx candidate");

    // Poll for events
    let mut found_event = false;
    let mut event_count = 0;
    while let Some(event) = pc.poll_event() {
        event_count += 1;
        println!(
            "📨 Polled event #{}: {:?}",
            event_count,
            std::mem::discriminant(&event)
        );

        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) = event {
            println!("✅ Received OnIceCandidateEvent for srflx candidate");
            println!(
                "   Address: {}:{}",
                ice_event.candidate.address, ice_event.candidate.port
            );
            println!("   Type: {:?}", ice_event.candidate.typ);
            println!("   Foundation: {}", ice_event.candidate.foundation);
            println!("   URL: {}", ice_event.url);
            assert_eq!(
                ice_event.candidate.typ,
                rtc::peer_connection::transport::RTCIceCandidateType::Srflx
            );
            assert_eq!(ice_event.url, "stun:stun.example.com:3478");
            found_event = true;
        }
    }

    println!("📊 Total events polled: {}", event_count);
    assert!(
        found_event,
        "OnIceCandidateEvent was not emitted for srflx candidate"
    );
}

#[test]
fn test_multiple_candidates_events() {
    // Create a basic RTCPeerConnection
    let config = RTCConfigurationBuilder::new().build();
    let mut pc = RTCPeerConnection::new(config).expect("Failed to create peer connection");

    // Add multiple candidates
    let candidates = vec![
        RTCIceCandidateInit {
            candidate: "candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
            username_fragment: Some("test".to_string()),
            url: None,
        },
        RTCIceCandidateInit {
            candidate: "candidate:2 1 udp 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport 54321".to_string(),
            sdp_mid: Some("0".to_string()),
            sdp_mline_index: Some(0),
            username_fragment: Some("test".to_string()),
            url: Some("stun:stun.example.com:3478".to_string()),
        },
    ];

    println!("🔍 Adding {} candidates", candidates.len());
    for (i, candidate) in candidates.iter().enumerate() {
        println!("  [{}] {}", i, candidate.candidate);
        pc.add_local_candidate(candidate.clone())
            .expect("Failed to add candidate");
    }

    // Poll for all events
    let mut total_events = 0;
    let mut ice_events = 0;
    let mut host_found = false;
    let mut srflx_found = false;

    while let Some(event) = pc.poll_event() {
        total_events += 1;
        println!(
            "📨 Event #{}: {:?}",
            total_events,
            std::mem::discriminant(&event)
        );

        if let RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) = event {
            ice_events += 1;
            println!(
                "✅ ICE Event {}: {:?} candidate at {}:{}",
                ice_events,
                ice_event.candidate.typ,
                ice_event.candidate.address,
                ice_event.candidate.port
            );

            match ice_event.candidate.typ {
                rtc::peer_connection::transport::RTCIceCandidateType::Host => host_found = true,
                rtc::peer_connection::transport::RTCIceCandidateType::Srflx => srflx_found = true,
                _ => {}
            }
        }
    }

    println!(
        "📊 Total events: {}, ICE candidate events: {}",
        total_events, ice_events
    );
    assert_eq!(
        ice_events, 2,
        "Expected 2 OnIceCandidateEvents, got {}",
        ice_events
    );
    assert!(host_found, "Host candidate event not found");
    assert!(srflx_found, "Srflx candidate event not found");
}
