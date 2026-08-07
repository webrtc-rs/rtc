use super::*;
use sansio::Protocol;
use shared::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

#[test]
fn test_mdns_query() {
    let now = Instant::now();
    let config = MdnsConfig::default();
    let mut conn = Mdns::new(now, config);

    // Start a query
    let query_id = conn.query_now(now, "test.local");
    assert!(conn.is_query_pending(query_id));
    assert_eq!(conn.pending_query_count(), 1);

    // Should have a packet queued to send
    let packet = conn.poll_write();
    assert!(packet.is_some());

    // Verify destination
    let packet = packet.unwrap();
    assert_eq!(packet.transport.peer_addr, MDNS_DEST_ADDR);
}

#[test]
fn test_mdns_cancel_query() {
    let now = Instant::now();
    let config = MdnsConfig::default();
    let mut conn = Mdns::new(now, config);

    let query_id = conn.query_now(now, "test.local");
    assert!(conn.is_query_pending(query_id));

    conn.cancel_query(query_id);
    assert!(!conn.is_query_pending(query_id));
    assert_eq!(conn.pending_query_count(), 0);
}

#[test]
fn test_mdns_local_names() {
    let now = Instant::now();
    let config = MdnsConfig::default()
        .with_local_names(vec!["myhost.local".to_string()])
        .with_local_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

    let conn = Mdns::new(now, config);
    assert_eq!(conn.local_names, vec!["myhost.local."]);
}

// Tests converted from async mDNS conn_test.rs

#[test]
fn test_multiple_close() {
    let now = Instant::now();
    let config = MdnsConfig::default();
    let mut conn = Mdns::new(now, config);

    // First close should succeed
    let result = conn.close();
    assert!(result.is_ok());

    // After close, handle_read should return ErrConnectionClosed
    let msg = TaggedBytesMut {
        now: now,
        transport: TransportContext {
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5353),
            peer_addr: MDNS_DEST_ADDR,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::new(),
    };

    let result = conn.handle_read(msg);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::ErrConnectionClosed);

    // handle_timeout should also return ErrConnectionClosed
    let result = conn.handle_timeout(now);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Error::ErrConnectionClosed);
}

#[test]
fn test_query_timeout_behavior() {
    let now = Instant::now();
    // In sansio, timeout behavior is caller-controlled.
    // This test verifies that queries remain pending until explicitly
    // answered or cancelled, and that handle_timeout triggers retries.
    let config = MdnsConfig::default().with_query_interval(Duration::from_millis(100));
    let mut conn = Mdns::new(now, config);

    // Start a query
    let query_id = conn.query_now(now, "invalid-host.local");
    assert!(conn.is_query_pending(query_id));

    // Consume the initial query packet
    let packet = conn.poll_write();
    assert!(packet.is_some());

    // No more packets yet
    assert!(conn.poll_write().is_none());

    // Query should still be pending
    assert!(conn.is_query_pending(query_id));

    // Simulate time passing and trigger timeout
    let retry_at = now + Duration::from_millis(150);
    let result = conn.handle_timeout(retry_at);
    assert!(result.is_ok());

    // Should have a retry packet queued
    let packet = conn.poll_write();
    assert!(packet.is_some());
    assert_eq!(packet.unwrap().transport.peer_addr, MDNS_DEST_ADDR);

    // Query still pending (no answer received)
    assert!(conn.is_query_pending(query_id));

    // Cancel the query
    conn.cancel_query(query_id);
    assert!(!conn.is_query_pending(query_id));
}

#[test]
fn test_poll_timeout() {
    let now = Instant::now();
    let config = MdnsConfig::default().with_query_interval(Duration::from_secs(1));
    let mut conn = Mdns::new(now, config);

    // No queries, no timeout
    assert!(conn.poll_timeout().is_none());

    // Start a query
    let _query_id = conn.query_now(now, "test.local");

    // Should have a timeout scheduled
    let timeout = conn.poll_timeout();
    assert!(timeout.is_some());
}

#[test]
fn test_multiple_queries() {
    let now = Instant::now();
    let config = MdnsConfig::default();
    let mut conn = Mdns::new(now, config);

    // Start multiple queries
    let query1 = conn.query_now(now, "host1.local");
    let query2 = conn.query_now(now, "host2.local");
    let query3 = conn.query_now(now, "host3.local");

    assert_eq!(conn.pending_query_count(), 3);
    assert!(conn.is_query_pending(query1));
    assert!(conn.is_query_pending(query2));
    assert!(conn.is_query_pending(query3));

    // Should have 3 packets queued
    assert!(conn.poll_write().is_some());
    assert!(conn.poll_write().is_some());
    assert!(conn.poll_write().is_some());
    assert!(conn.poll_write().is_none());

    // Cancel one query
    conn.cancel_query(query2);
    assert_eq!(conn.pending_query_count(), 2);
    assert!(conn.is_query_pending(query1));
    assert!(!conn.is_query_pending(query2));
    assert!(conn.is_query_pending(query3));
}

#[test]
fn test_local_names_normalization() {
    let now = Instant::now();
    // Names without trailing dots should get them added
    let config = MdnsConfig::default().with_local_names(vec![
        "host1.local".to_string(),
        "host2.local.".to_string(), // Already has dot
    ]);

    let conn = Mdns::new(now, config);
    assert_eq!(conn.local_names.len(), 2);
    assert_eq!(conn.local_names[0], "host1.local.");
    assert_eq!(conn.local_names[1], "host2.local.");
}

#[test]
fn test_query_interval_default() {
    let now = Instant::now();
    // Zero interval should use default
    let config = MdnsConfig::default().with_query_interval(Duration::ZERO);
    let conn = Mdns::new(now, config);
    assert_eq!(conn.query_interval, DEFAULT_QUERY_INTERVAL);

    // Non-zero interval should be used
    let config = MdnsConfig::default().with_query_interval(Duration::from_millis(500));
    let conn = Mdns::new(now, config);
    assert_eq!(conn.query_interval, Duration::from_millis(500));
}

#[test]
fn test_close_clears_state() {
    let now = Instant::now();
    let config = MdnsConfig::default().with_local_names(vec!["host.local".to_string()]);
    let mut conn = Mdns::new(now, config);

    // Start some queries
    conn.query_now(now, "query1.local");
    conn.query_now(now, "query2.local");
    assert_eq!(conn.pending_query_count(), 2);
    assert!(conn.poll_timeout().is_some());

    // Close
    conn.close().unwrap();

    // State should be cleared
    assert_eq!(conn.pending_query_count(), 0);
    assert!(conn.poll_timeout().is_none());
    assert!(conn.poll_write().is_none());
    assert!(conn.poll_event().is_none());
}

#[test]
fn test_query_timeout_emits_event() {
    let now = Instant::now();
    // MdnsConfigure with a short timeout
    let config = MdnsConfig::default()
        .with_query_interval(Duration::from_millis(100))
        .with_query_timeout(Duration::from_millis(250));
    let mut conn = Mdns::new(now, config);

    // Start a query
    let query_id = conn.query_now(now, "timeout-test.local");
    assert!(conn.is_query_pending(query_id));

    // Consume the initial query packet
    conn.poll_write();

    // Simulate time passing but not enough to timeout
    let not_yet = now + Duration::from_millis(150);
    conn.handle_timeout(not_yet).unwrap();

    // Query should still be pending, no timeout event
    assert!(conn.is_query_pending(query_id));
    assert!(conn.poll_event().is_none());

    // Simulate time passing past the timeout
    let past_timeout = now + Duration::from_millis(300);
    conn.handle_timeout(past_timeout).unwrap();

    // Query should no longer be pending
    assert!(!conn.is_query_pending(query_id));

    // Should have a timeout event
    let event = conn.poll_event();
    assert!(event.is_some());
    match event.unwrap() {
        MdnsEvent::QueryTimeout(id) => {
            assert_eq!(id, query_id);
        }
        _ => panic!("Expected QueryTimeout event"),
    }

    // No more events
    assert!(conn.poll_event().is_none());
}

#[test]
fn test_query_timeout_multiple_queries() {
    let now = Instant::now();
    // MdnsConfigure with a timeout
    let config = MdnsConfig::default()
        .with_query_interval(Duration::from_millis(100))
        .with_query_timeout(Duration::from_millis(200));
    let mut conn = Mdns::new(now, config);

    // Start both queries at the same time
    let query1 = conn.query_now(now, "query1.local");
    let query2 = conn.query_now(now, "query2.local");

    // Drain write queue
    while conn.poll_write().is_some() {}

    // Both queries pending
    assert!(conn.is_query_pending(query1));
    assert!(conn.is_query_pending(query2));
    assert_eq!(conn.pending_query_count(), 2);

    // Simulate time passing but not enough to timeout (150ms)
    let time_150ms = now + Duration::from_millis(150);
    conn.handle_timeout(time_150ms).unwrap();

    // Both queries should still be pending
    assert!(conn.is_query_pending(query1));
    assert!(conn.is_query_pending(query2));
    assert_eq!(conn.pending_query_count(), 2);

    // No timeout events yet
    assert!(conn.poll_event().is_none());

    // Simulate time passing past the timeout (250ms)
    let time_250ms = now + Duration::from_millis(250);
    conn.handle_timeout(time_250ms).unwrap();

    // Both queries should be timed out
    assert!(!conn.is_query_pending(query1));
    assert!(!conn.is_query_pending(query2));
    assert_eq!(conn.pending_query_count(), 0);

    // Should have two timeout events
    let mut timeout_ids = Vec::new();
    while let Some(event) = conn.poll_event() {
        match event {
            MdnsEvent::QueryTimeout(id) => timeout_ids.push(id),
            _ => panic!("Expected QueryTimeout event"),
        }
    }
    assert_eq!(timeout_ids.len(), 2);
    assert!(timeout_ids.contains(&query1));
    assert!(timeout_ids.contains(&query2));
}

#[test]
fn test_no_timeout_without_config() {
    let now = Instant::now();
    // Default config has no timeout
    let config = MdnsConfig::default().with_query_interval(Duration::from_millis(100));
    let mut conn = Mdns::new(now, config);

    let query_id = conn.query_now(now, "no-timeout.local");
    conn.poll_write();

    // Simulate a very long time passing
    let future = now + Duration::from_secs(3600); // 1 hour later
    conn.handle_timeout(future).unwrap();

    // Query should still be pending (no timeout configured)
    assert!(conn.is_query_pending(query_id));

    // No timeout events
    assert!(conn.poll_event().is_none());
}

#[test]
fn test_query_timeout_config() {
    let now = Instant::now();
    // Test that query_timeout is properly stored
    let config = MdnsConfig::default().with_query_timeout(Duration::from_secs(10));
    let conn = Mdns::new(now, config);
    assert_eq!(conn.query_timeout, Some(Duration::from_secs(10)));

    // Default should be None
    let config = MdnsConfig::default();
    let conn = Mdns::new(now, config);
    assert_eq!(conn.query_timeout, None);
}
