//! Integration tests for rtc-mdns
//!
//! These tests verify the interaction between mDNS server and client
//! using the sans-I/O pattern without actual network I/O.

use bytes::BytesMut;
use rtc_mdns::{MDNS_DEST_ADDR, Mdns, MdnsConfig, MdnsEvent};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Helper to create a transport context for a message
fn create_transport_context(local: SocketAddr, peer: SocketAddr) -> TransportContext {
    TransportContext {
        local_addr: local,
        peer_addr: peer,
        transport_protocol: TransportProtocol::UDP,
        ecn: None,
    }
}

/// Helper to create a TaggedBytesMut from a packet
fn create_message(
    now: Instant,
    local: SocketAddr,
    peer: SocketAddr,
    data: &[u8],
) -> TaggedBytesMut {
    TaggedBytesMut {
        now,
        transport: create_transport_context(local, peer),
        message: BytesMut::from(data),
    }
}

/// Simulates packet delivery between two mDNS connections.
/// Returns the number of packets delivered.
fn deliver_packets(
    from: &mut Mdns,
    to: &mut Mdns,
    from_addr: SocketAddr,
    to_addr: SocketAddr,
    now: Instant,
) -> usize {
    let mut count = 0;
    while let Some(packet) = from.poll_write() {
        // Only deliver packets destined for multicast (both listen on it)
        if packet.transport.peer_addr == MDNS_DEST_ADDR {
            let msg = create_message(now, to_addr, from_addr, &packet.message);
            let _ = to.handle_read(msg);
            count += 1;
        }
    }
    count
}

/// Simulates bidirectional packet delivery between two connections.
/// Returns (packets_a_to_b, packets_b_to_a).
fn exchange_packets(
    conn_a: &mut Mdns,
    conn_b: &mut Mdns,
    addr_a: SocketAddr,
    addr_b: SocketAddr,
    now: Instant,
) -> (usize, usize) {
    // Collect packets from both before delivering to avoid borrow issues
    let mut packets_a: Vec<TaggedBytesMut> = Vec::new();
    let mut packets_b: Vec<TaggedBytesMut> = Vec::new();

    while let Some(packet) = conn_a.poll_write() {
        packets_a.push(packet);
    }
    while let Some(packet) = conn_b.poll_write() {
        packets_b.push(packet);
    }

    // Deliver A's packets to B
    let count_a_to_b = packets_a.len();
    for packet in packets_a {
        if packet.transport.peer_addr == MDNS_DEST_ADDR {
            let msg = create_message(now, addr_b, addr_a, &packet.message);
            let _ = conn_b.handle_read(msg);
        }
    }

    // Deliver B's packets to A
    let count_b_to_a = packets_b.len();
    for packet in packets_b {
        if packet.transport.peer_addr == MDNS_DEST_ADDR {
            let msg = create_message(now, addr_a, addr_b, &packet.message);
            let _ = conn_a.handle_read(msg);
        }
    }

    (count_a_to_b, count_b_to_a)
}

#[test]
fn test_server_responds_to_query() {
    // Server configuration
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5353);
    let config_server = MdnsConfig::default()
        .with_local_names(vec!["test-server.local".to_string()])
        .with_local_addr(server_addr);
    let mut server = Mdns::new(config_server);

    // Client configuration
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 5353);
    let config_client = MdnsConfig::default().with_query_interval(Duration::from_secs(1));
    let mut client = Mdns::new(config_client);

    let now = Instant::now();

    // Client starts a query
    let query_id = client.query("test-server.local");
    assert!(client.is_query_pending(query_id));

    // Exchange packets: client query -> server, server response -> client
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Client should have received an answer
    let event = client.poll_event();
    assert!(event.is_some(), "Expected QueryAnswered event");

    match event.unwrap() {
        MdnsEvent::QueryAnswered(id, addr) => {
            assert_eq!(id, query_id);
            assert_eq!(addr, server_addr.ip());
        }
        MdnsEvent::QueryTimeout(_) => panic!("Unexpected QueryTimeout"),
    }

    // Query should no longer be pending
    assert!(!client.is_query_pending(query_id));
}

#[test]
fn test_multiple_local_names() {
    // Server with multiple local names
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 5353);
    let config_server = MdnsConfig::default()
        .with_local_names(vec![
            "name1.local".to_string(),
            "name2.local".to_string(),
            "name3.local".to_string(),
        ])
        .with_local_addr(server_addr);
    let mut server = Mdns::new(config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5353);
    let config_client = MdnsConfig::default();
    let mut client = Mdns::new(config_client);

    let now = Instant::now();

    // Query for each name
    let query1 = client.query("name1.local");
    let query2 = client.query("name2.local");
    let query3 = client.query("name3.local");

    assert_eq!(client.pending_query_count(), 3);

    // Exchange packets
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Collect all answers
    let mut answered_ids = Vec::new();
    while let Some(event) = client.poll_event() {
        if let MdnsEvent::QueryAnswered(id, addr) = event {
            answered_ids.push(id);
            assert_eq!(addr, server_addr.ip());
        }
    }

    // All queries should be answered
    assert_eq!(answered_ids.len(), 3);
    assert!(answered_ids.contains(&query1));
    assert!(answered_ids.contains(&query2));
    assert!(answered_ids.contains(&query3));
    assert_eq!(client.pending_query_count(), 0);
}

#[test]
fn test_query_for_unknown_name_remains_pending() {
    // Server only knows about "known.local"
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5353);
    let config_server = MdnsConfig::default()
        .with_local_names(vec!["known.local".to_string()])
        .with_local_addr(server_addr);
    let mut server = Mdns::new(config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 5353);
    let config_client = MdnsConfig::default();
    let mut client = Mdns::new(config_client);

    let now = Instant::now();

    // Query for unknown name
    let query_id = client.query("unknown.local");

    // Exchange packets
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // No answer should be received
    assert!(client.poll_event().is_none());

    // Query should still be pending
    assert!(client.is_query_pending(query_id));
}

#[test]
fn test_query_timeout() {
    let config = MdnsConfig::default()
        .with_query_interval(Duration::from_millis(100))
        .with_query_timeout(Duration::from_millis(300));
    let mut client = Mdns::new(config);

    // Capture time before starting query (query uses Instant::now() internally)
    let start_time = Instant::now();
    let query_id = client.query("nonexistent.local");

    // Drain initial packet
    while client.poll_write().is_some() {}

    // Simulate time passing - not yet timed out
    let time_200ms = start_time + Duration::from_millis(200);
    client.handle_timeout(time_200ms).unwrap();

    // Query should still be pending
    assert!(client.is_query_pending(query_id));
    assert!(client.poll_event().is_none());

    // Simulate time passing - past timeout (add extra margin for timing)
    let time_400ms = start_time + Duration::from_millis(400);
    client.handle_timeout(time_400ms).unwrap();

    // Query should be timed out
    assert!(!client.is_query_pending(query_id));

    let event = client.poll_event();
    assert!(event.is_some());
    match event.unwrap() {
        MdnsEvent::QueryTimeout(id) => assert_eq!(id, query_id),
        _ => panic!("Expected QueryTimeout event"),
    }
}

#[test]
fn test_query_retry() {
    let config = MdnsConfig::default().with_query_interval(Duration::from_millis(100));
    let mut client = Mdns::new(config);

    // Capture time before starting query
    let start_time = Instant::now();
    let _query_id = client.query("retry-test.local");

    // Drain initial packet
    let initial_packet = client.poll_write();
    assert!(initial_packet.is_some());
    assert!(client.poll_write().is_none());

    // Not enough time for retry
    let time_50ms = start_time + Duration::from_millis(50);
    client.handle_timeout(time_50ms).unwrap();
    assert!(client.poll_write().is_none());

    // Enough time for retry (add margin for timing)
    let time_150ms = start_time + Duration::from_millis(150);
    client.handle_timeout(time_150ms).unwrap();

    // Should have a retry packet
    let retry_packet = client.poll_write();
    assert!(retry_packet.is_some());
}

#[test]
fn test_cancel_query() {
    let config = MdnsConfig::default();
    let mut client = Mdns::new(config);

    let query1 = client.query("host1.local");
    let query2 = client.query("host2.local");
    let query3 = client.query("host3.local");

    assert_eq!(client.pending_query_count(), 3);

    // Cancel middle query
    client.cancel_query(query2);

    assert_eq!(client.pending_query_count(), 2);
    assert!(client.is_query_pending(query1));
    assert!(!client.is_query_pending(query2));
    assert!(client.is_query_pending(query3));

    // Cancel remaining queries
    client.cancel_query(query1);
    client.cancel_query(query3);

    assert_eq!(client.pending_query_count(), 0);
}

#[test]
fn test_server_without_local_addr_logs_warning() {
    // Server with local names but no local_addr - should not crash
    let config_server = MdnsConfig::default().with_local_names(vec!["test.local".to_string()]);
    // Note: local_addr is not set
    let mut server = Mdns::new(config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 5353);
    let config_client = MdnsConfig::default();
    let mut client = Mdns::new(config_client);

    let now = Instant::now();

    let _query_id = client.query("test.local");

    // Exchange packets - should not panic
    let (client_sent, _) = exchange_packets(
        &mut client,
        &mut server,
        client_addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353),
        now,
    );

    // Client should have sent the query
    assert_eq!(client_sent, 1);

    // Server should NOT have queued a response (no local_addr)
    assert!(server.poll_write().is_none());
}

#[test]
fn test_close_clears_all_state() {
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5353);
    let config = MdnsConfig::default()
        .with_local_names(vec!["host.local".to_string()])
        .with_local_addr(server_addr)
        .with_query_interval(Duration::from_secs(1));
    let mut conn = Mdns::new(config);

    // Start some queries
    conn.query("q1.local");
    conn.query("q2.local");

    assert_eq!(conn.pending_query_count(), 2);
    assert!(conn.poll_timeout().is_some());

    // Packets should be queued
    assert!(conn.poll_write().is_some());

    // Close
    conn.close().unwrap();

    // All state should be cleared
    assert_eq!(conn.pending_query_count(), 0);
    assert!(conn.poll_timeout().is_none());
    assert!(conn.poll_write().is_none());
    assert!(conn.poll_event().is_none());
}

#[test]
fn test_closed_connection_rejects_operations() {
    let mut conn = Mdns::new(MdnsConfig::default());

    conn.close().unwrap();

    // handle_read should fail
    let msg = create_message(
        Instant::now(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353),
        MDNS_DEST_ADDR,
        &[],
    );
    let result = conn.handle_read(msg);
    assert!(result.is_err());

    // handle_timeout should fail
    let result = conn.handle_timeout(Instant::now());
    assert!(result.is_err());
}

#[test]
fn test_sequential_queries() {
    // Similar to mdns_server_query.rs example: query1, wait for answer, then query2
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 5353);
    let config_server = MdnsConfig::default()
        .with_local_names(vec!["first.local".to_string(), "second.local".to_string()])
        .with_local_addr(server_addr);
    let mut server = Mdns::new(config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 5353);
    let config_client = MdnsConfig::default();
    let mut client = Mdns::new(config_client);

    let now = Instant::now();

    // First query
    let query1 = client.query("first.local");

    // Exchange packets for first query
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Verify first answer
    let event = client.poll_event().expect("Expected first answer");
    match event {
        MdnsEvent::QueryAnswered(id, _addr) => {
            assert_eq!(id, query1);
        }
        _ => panic!("Expected QueryAnswered"),
    }

    // Second query (sequential)
    let query2 = client.query("second.local");

    // Exchange packets for second query
    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Verify second answer
    let event = client.poll_event().expect("Expected second answer");
    match event {
        MdnsEvent::QueryAnswered(id, _addr) => {
            assert_eq!(id, query2);
        }
        _ => panic!("Expected QueryAnswered"),
    }

    assert_eq!(client.pending_query_count(), 0);
}

#[test]
fn test_name_normalization() {
    // Names with and without trailing dots should work the same
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 5353);

    // Server configured with name without trailing dot
    let config_server = MdnsConfig::default()
        .with_local_names(vec!["nodot.local".to_string()])
        .with_local_addr(server_addr);
    let mut server = Mdns::new(config_server);

    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 5353);
    let config_client = MdnsConfig::default();
    let mut client = Mdns::new(config_client);

    let now = Instant::now();

    // Query with trailing dot
    let query_id = client.query("nodot.local.");

    exchange_packets(&mut client, &mut server, client_addr, server_addr, now);
    exchange_packets(&mut server, &mut client, server_addr, client_addr, now);

    // Should still get an answer
    let event = client.poll_event();
    assert!(event.is_some());
    match event.unwrap() {
        MdnsEvent::QueryAnswered(id, _addr) => {
            assert_eq!(id, query_id);
        }
        _ => panic!("Expected QueryAnswered"),
    }
}

#[test]
fn test_multiple_clients_single_server() {
    // One server, multiple clients querying
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 5353);
    let config_server = MdnsConfig::default()
        .with_local_names(vec!["shared-server.local".to_string()])
        .with_local_addr(server_addr);
    let mut server = Mdns::new(config_server);

    let client1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10)), 5353);
    let client2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 20)), 5353);

    let mut client1 = Mdns::new(MdnsConfig::default());
    let mut client2 = Mdns::new(MdnsConfig::default());

    let now = Instant::now();

    // Both clients query
    let query1 = client1.query("shared-server.local");
    let query2 = client2.query("shared-server.local");

    // Client1 sends query to server
    deliver_packets(&mut client1, &mut server, client1_addr, server_addr, now);

    // Client2 sends query to server
    deliver_packets(&mut client2, &mut server, client2_addr, server_addr, now);

    // Server responds (may have multiple response packets queued)
    // Collect all server responses
    let mut responses: Vec<TaggedBytesMut> = Vec::new();
    while let Some(packet) = server.poll_write() {
        responses.push(packet);
    }

    // Deliver responses to both clients (multicast behavior)
    for response in &responses {
        let msg1 = create_message(now, client1_addr, server_addr, &response.message);
        let msg2 = create_message(now, client2_addr, server_addr, &response.message);
        let _ = client1.handle_read(msg1);
        let _ = client2.handle_read(msg2);
    }

    // Both clients should have answers
    let event1 = client1.poll_event().expect("Client1 should have answer");
    let event2 = client2.poll_event().expect("Client2 should have answer");

    match event1 {
        MdnsEvent::QueryAnswered(id, _addr) => assert_eq!(id, query1),
        _ => panic!("Expected QueryAnswered for client1"),
    }

    match event2 {
        MdnsEvent::QueryAnswered(id, _addr) => assert_eq!(id, query2),
        _ => panic!("Expected QueryAnswered for client2"),
    }
}

#[test]
fn test_bidirectional_server_client() {
    // Two connections that are both server and client (like mdns_server_query.rs)
    let addr_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 5353);
    let addr_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)), 5353);

    // Connection A: serves "hostA.local", queries for "hostB.local"
    let config_a = MdnsConfig::default()
        .with_local_names(vec!["hostA.local".to_string()])
        .with_local_addr(addr_a);
    let mut conn_a = Mdns::new(config_a);

    // Connection B: serves "hostB.local", queries for "hostA.local"
    let config_b = MdnsConfig::default()
        .with_local_names(vec!["hostB.local".to_string()])
        .with_local_addr(addr_b);
    let mut conn_b = Mdns::new(config_b);

    let now = Instant::now();

    // Both start queries
    let query_a = conn_a.query("hostB.local");
    let query_b = conn_b.query("hostA.local");

    // Exchange packets multiple times to ensure full communication
    for _ in 0..3 {
        exchange_packets(&mut conn_a, &mut conn_b, addr_a, addr_b, now);
    }

    // Both should have answers
    let mut a_answered = false;
    let mut b_answered = false;

    while let Some(event) = conn_a.poll_event() {
        if let MdnsEvent::QueryAnswered(id, addr) = event {
            assert_eq!(id, query_a);
            assert_eq!(addr, addr_b.ip());
            a_answered = true;
        }
    }

    while let Some(event) = conn_b.poll_event() {
        if let MdnsEvent::QueryAnswered(id, addr) = event {
            assert_eq!(id, query_b);
            assert_eq!(addr, addr_a.ip());
            b_answered = true;
        }
    }

    assert!(a_answered, "Connection A should have received answer");
    assert!(b_answered, "Connection B should have received answer");
}

#[test]
fn test_poll_timeout_scheduling() {
    let config = MdnsConfig::default().with_query_interval(Duration::from_secs(2));
    let mut conn = Mdns::new(config);

    // No queries, no timeout
    assert!(conn.poll_timeout().is_none());

    // Start a query
    let _query = conn.query("test.local");

    // Should have a timeout scheduled
    let timeout = conn.poll_timeout();
    assert!(timeout.is_some());

    // Cancel query
    conn.cancel_query(_query);

    // No more timeout needed
    // Note: The timeout might still be set until next handle_timeout call
    // but since query is cancelled, it shouldn't affect anything
    assert_eq!(conn.pending_query_count(), 0);
}
