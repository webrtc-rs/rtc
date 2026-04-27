use super::*;
use sansio::Protocol;
use std::collections::HashSet;
use std::net::UdpSocket;

fn create_test_client_with_turn_server() -> Result<(UdpSocket, Client)> {
    let udp_socket = UdpSocket::bind("127.0.0.1:0")?;

    let client = Client::new(ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: format!("127.0.0.1:{}", udp_socket.local_addr()?.port()),
        local_addr: udp_socket.local_addr()?,
        transport_protocol: TransportProtocol::UDP,
        username: "user".to_string(),
        password: "pass".to_string(),
        realm: "test".to_string(),
        software: "TEST SOFTWARE".to_owned(),
        rto_in_ms: 0,
    })?;

    Ok((udp_socket, client))
}

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

#[test]
fn test_turn_server_addr_returns_some_when_configured() -> Result<()> {
    let (_conn, mut client) = create_test_client_with_turn_server()?;
    let addr = client.turn_server_addr();
    assert!(
        addr.is_some(),
        "turn_server_addr should return Some when configured"
    );
    assert_eq!(addr.unwrap().ip(), std::net::IpAddr::from([127, 0, 0, 1]));
    client.close()
}

#[test]
fn test_turn_server_addr_returns_none_when_not_configured() -> Result<()> {
    let (_conn, mut client) = create_listening_test_client(0)?;
    let addr = client.turn_server_addr();
    assert!(
        addr.is_none(),
        "turn_server_addr should return None when not configured"
    );
    client.close()
}

#[test]
fn test_turn_server_addr_or_err_returns_ok_when_configured() -> Result<()> {
    let (_conn, mut client) = create_test_client_with_turn_server()?;
    let result = client.turn_server_addr_or_err();
    assert!(
        result.is_ok(),
        "turn_server_addr_or_err should return Ok when configured"
    );
    client.close()
}

#[test]
fn test_turn_server_addr_or_err_returns_err_when_not_configured() -> Result<()> {
    let (_conn, mut client) = create_listening_test_client(0)?;
    let result = client.turn_server_addr_or_err();
    assert!(
        result.is_err(),
        "turn_server_addr_or_err should return Err when not configured"
    );
    assert_eq!(result.unwrap_err(), Error::ErrNilTurnSocket);
    client.close()
}

#[test]
fn test_local_addr_returns_bound_address() -> Result<()> {
    let (conn, mut client) = create_test_client_with_turn_server()?;
    let expected = conn.local_addr()?;
    assert_eq!(
        client.local_addr(),
        expected,
        "local_addr should match the configured address"
    );
    client.close()
}
