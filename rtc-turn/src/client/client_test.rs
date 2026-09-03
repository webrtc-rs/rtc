use super::*;
use sansio::Protocol;
use std::collections::HashSet;
use std::net::UdpSocket;

fn create_listening_test_client(rto_in_ms: u64) -> Result<(UdpSocket, Client)> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;

    let client = Client::new(ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: String::new(),
        local_addr: udp_socket.local_addr()?,
        transport_protocol: TransportProtocol::UDP,
        username: String::new(),
        password: String::new(),
        realm: String::new(),
        software: "TEST SOFTWARE".to_owned(),
        rto_in_ms,
    })?;

    Ok((udp_socket, client))
}

fn create_listening_test_client_with_stun_serv() -> Result<(UdpSocket, Client)> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;

    let client = Client::new(ClientConfig {
        stun_serv_addr: "stun1.l.google.com:19302".to_owned(),
        turn_serv_addr: String::new(),
        local_addr: udp_socket.local_addr()?,
        transport_protocol: TransportProtocol::UDP,
        username: String::new(),
        password: String::new(),
        realm: String::new(),
        software: "TEST SOFTWARE".to_owned(),
        rto_in_ms: 0,
    })?;

    Ok((udp_socket, client))
}

/// A host demultiplexing STUN on a socket it shares — a STUN gatherer and this client pointed at
/// one server address — routes a response by transaction id, because nothing else identifies its
/// owner. See webrtc-rs/webrtc#890.
#[test]
fn test_has_transaction_reports_outstanding_requests() -> Result<()> {
    let (_conn, mut client) = create_listening_test_client(0)?;
    let server = "127.0.0.1:3478".parse::<std::net::SocketAddr>().unwrap();

    let unknown = TransactionId::new();
    assert!(
        !client.has_transaction(&unknown),
        "a fresh client is waiting on nothing"
    );

    let tid = client.send_binding_request_to(server)?;
    assert!(
        client.has_transaction(&tid),
        "the transaction just started is outstanding"
    );
    assert!(
        !client.has_transaction(&unknown),
        "an id this client never sent is not its own"
    );

    Ok(())
}

#[test]
fn test_client_with_stun_send_binding_request() -> Result<()> {
    //env_logger::init();

    let (conn, mut client) = create_listening_test_client_with_stun_serv()?;
    let local_addr = conn.local_addr()?;

    let tid = client.send_binding_request()?;

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

    let tid1 = client.send_binding_request_to(to)?;
    let tid2 = client.send_binding_request_to(to)?;
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

    let tid = client.send_binding_request_to(to)?;
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

/// Handling an overdue relay timer once must put every refreshed deadline back in the future.
/// A runtime may be suspended for longer than several refresh intervals on a mobile platform;
/// replaying each missed interval makes a Sans-I/O driver spin through historical deadlines.
#[test]
fn test_overdue_relay_refreshes_are_rescheduled_from_now() -> Result<()> {
    let base = Instant::now();
    let t = |secs| base + Duration::from_secs(secs);

    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut client = Client::new(ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: "127.0.0.1:3478".to_owned(),
        local_addr: udp_socket.local_addr()?,
        transport_protocol: TransportProtocol::UDP,
        username: "user".to_owned(),
        password: "pass".to_owned(),
        realm: "realm".to_owned(),
        software: "TEST SOFTWARE".to_owned(),
        rto_in_ms: 0,
    })?;

    let relayed_addr: RelayedAddr = "127.0.0.1:50000".parse().unwrap();
    client.relays.insert(
        relayed_addr,
        RelayState::new(
            relayed_addr,
            MessageIntegrity::new_short_term_integrity("password".to_owned()),
            Nonce::new(ATTR_NONCE, "nonce".to_owned()),
            Duration::from_secs(600),
        ),
    );

    let resumed_at = t(1000);
    client.relay(relayed_addr)?.handle_timeout(resumed_at);

    assert_eq!(
        client.relay(relayed_addr)?.poll_timeout(),
        Some(t(1120)),
        "one timeout pass must move the permission and allocation deadlines past now"
    );

    client.close()
}
