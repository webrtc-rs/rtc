use super::*;
use sansio::Protocol;
use std::collections::HashSet;
use std::net::UdpSocket;

/// Tests may resolve the built-in provider; library code never does.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn create_listening_test_client(rto_in_ms: u64) -> Result<(UdpSocket, Client)> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;

    let client = Client::new(
        ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: String::new(),
            local_addr: udp_socket.local_addr()?,
            transport_protocol: TransportProtocol::UDP,
            username: String::new(),
            password: String::new(),
            realm: String::new(),
            software: "TEST SOFTWARE".to_owned(),
            rto_in_ms,
        },
        test_crypto_provider(),
    )?;

    Ok((udp_socket, client))
}

fn create_listening_test_client_with_stun_serv() -> Result<(UdpSocket, Client)> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;

    let client = Client::new(
        ClientConfig {
            stun_serv_addr: "stun1.l.google.com:19302".to_owned(),
            turn_serv_addr: String::new(),
            local_addr: udp_socket.local_addr()?,
            transport_protocol: TransportProtocol::UDP,
            username: String::new(),
            password: String::new(),
            realm: String::new(),
            software: "TEST SOFTWARE".to_owned(),
            rto_in_ms: 0,
        },
        test_crypto_provider(),
    )?;

    Ok((udp_socket, client))
}

#[test]
fn test_client_with_stun_send_binding_request() -> Result<()> {
    //env_logger::init();

    let (conn, mut client) = create_listening_test_client_with_stun_serv()?;
    let local_addr = conn.local_addr()?;

    let tid = client.send_binding_request(Instant::now())?;

    while let Some(transmit) = client.poll_write() {
        conn.send_to(&transmit.message, transmit.transport.peer_addr)?;
    }

    let mut buffer = vec![0u8; 2048];
    let (n, peer_addr) = conn.recv_from(&mut buffer)?;
    client.handle_read(TransportMessage {
        now: Instant::now(),
        transport: TransportContext {
            local_addr,
            peer_addr,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        },
        message: BytesMut::from(&buffer[..n]),
    })?;

    if let Some(event) = client.poll_event() {
        match event {
            Event::BindingResponse(id, refl_addr) => {
                assert_eq!(tid, id);
                debug!("mapped-addr: {}", refl_addr);
            }
            _ => assert!(false),
        }
    } else {
        assert!(false);
    }

    assert_eq!(0, client.tr_map.size(), "should be no transaction left");

    client.close()
}

#[test]
fn test_client_with_stun_send_binding_request_to_parallel() -> Result<()> {
    //env_logger::init();

    let (conn, mut client) = create_listening_test_client(0)?;
    let local_addr = conn.local_addr()?;

    let to = lookup_host(true, "stun1.l.google.com:19302")?;

    let tid1 = client.send_binding_request_to(Instant::now(), to)?;
    let tid2 = client.send_binding_request_to(Instant::now(), to)?;
    while let Some(transmit) = client.poll_write() {
        conn.send_to(&transmit.message, transmit.transport.peer_addr)?;
    }

    let mut buffer = vec![0u8; 2048];
    for _ in 0..2 {
        let (n, peer_addr) = conn.recv_from(&mut buffer)?;
        client.handle_read(TransportMessage {
            now: Instant::now(),
            transport: TransportContext {
                local_addr,
                peer_addr,
                transport_protocol: TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&buffer[..n]),
        })?;
    }

    let mut tids = HashSet::new();
    while let Some(event) = client.poll_event() {
        match event {
            Event::BindingResponse(tid, refl_addr) => {
                tids.insert(tid);
                debug!("mapped-addr: {}", refl_addr);
            }
            _ => {}
        }
    }

    assert_eq!(2, tids.len());
    assert!(tids.contains(&tid1));
    assert!(tids.contains(&tid2));

    client.close()
}

#[test]
fn test_client_with_stun_send_binding_request_to_timeout() -> Result<()> {
    //env_logger::init();

    let (conn, mut client) = create_listening_test_client(10)?;

    let to = lookup_host(true, "127.0.0.1:9")?;

    let tid = client.send_binding_request_to(Instant::now(), to)?;
    while let Some(transmit) = client.poll_write() {
        conn.send_to(&transmit.message, transmit.transport.peer_addr)?;
    }

    while let Some(to) = client.poll_timeout() {
        client.handle_timeout(to)?;
    }

    if let Some(event) = client.poll_event() {
        match event {
            Event::TransactionTimeout(id) => {
                assert_eq!(tid, id);
            }
            _ => assert!(false),
        }
    } else {
        assert!(false);
    }

    client.close()
}

/// The allocation-refresh timer is seeded from the instant passed to `RelayState::new` and
/// compared against the instant passed to `handle_timeout`, so a refresh can be observed by
/// arithmetic on a base instant with no wall-clock time passing and no sleeping.
#[test]
fn test_relay_refresh_timers_run_on_injected_time() -> Result<()> {
    let base = Instant::now();
    let t = |secs| base + Duration::from_secs(secs);

    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut client = Client::new(
        ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: "127.0.0.1:3478".to_owned(),
            local_addr: udp_socket.local_addr()?,
            transport_protocol: TransportProtocol::UDP,
            username: "user".to_owned(),
            password: "pass".to_owned(),
            realm: "realm".to_owned(),
            software: "TEST SOFTWARE".to_owned(),
            rto_in_ms: 0,
        },
        test_crypto_provider(),
    )?;

    // Stand in for a granted allocation, seeded at t(0) with a 10-minute lifetime.
    let lifetime = Duration::from_secs(600);
    let relayed_addr: RelayedAddr = "127.0.0.1:50000".parse().unwrap();
    client.relays.insert(
        relayed_addr,
        RelayState::new(
            t(0),
            relayed_addr,
            vec![0u8; 16],
            Nonce::new(ATTR_NONCE, "nonce".to_owned()),
            lifetime,
        ),
    );

    // The allocation is refreshed at half its lifetime; permissions sooner, at 120s.
    assert_eq!(client.relay(relayed_addr)?.poll_timeout(), Some(t(120)));

    // One second before the allocation deadline nothing is sent for it. (The permission
    // refresh at t(120) has already fired by then, so drain whatever it queued first.)
    client.relay(relayed_addr)?.handle_timeout(t(120));
    while client.poll_write().is_some() {}
    client.relay(relayed_addr)?.handle_timeout(t(299));
    assert!(
        client.poll_write().is_none(),
        "no refresh is due one second before the deadline"
    );

    // At the deadline the Refresh request goes out, stamped with the caller's instant.
    client.relay(relayed_addr)?.handle_timeout(t(300));
    let transmit = client
        .poll_write()
        .expect("the allocation must be refreshed at half its lifetime");
    assert_eq!(
        transmit.now,
        t(300),
        "the request carries the instant the caller supplied, not an ambient reading"
    );

    let mut msg = Message::new();
    msg.raw = transmit.message.to_vec();
    msg.decode()?;
    assert_eq!(msg.typ.method, METHOD_REFRESH);

    // Both timers advance by a fixed step from where they were, rather than being recomputed
    // against the wall clock: permissions are next again at 360s, the allocation at 600s.
    assert_eq!(client.relay(relayed_addr)?.poll_timeout(), Some(t(360)));

    client.relay(relayed_addr)?.handle_timeout(t(600));
    let transmit = client
        .poll_write()
        .expect("the allocation must be refreshed again a half-lifetime later");
    assert_eq!(transmit.now, t(600));

    client.close()
}
