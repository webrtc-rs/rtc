use super::*;
use std::collections::HashSet;
use std::net::UdpSocket;

fn create_listening_test_client(rto_in_ms: u64) -> Result<(UdpSocket, Client)> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0")?;

    let client = Client::new(ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: String::new(),
        local_addr: udp_socket.local_addr()?,
        protocol: Protocol::UDP,
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
        protocol: Protocol::UDP,
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

    while let Some(transmit) = client.poll_transmit() {
        conn.send_to(&transmit.message, transmit.transport.peer_addr)?;
    }

    let mut buffer = vec![0u8; 2048];
    let (n, peer_addr) = conn.recv_from(&mut buffer)?;
    client.handle_transmit(Transmit {
        now: Instant::now(),
        transport: TransportContext {
            local_addr,
            peer_addr,
            protocol: Protocol::UDP,
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

    client.close();

    Ok(())
}

#[test]
fn test_client_with_stun_send_binding_request_to_parallel() -> Result<()> {
    //env_logger::init();

    let (conn, mut client) = create_listening_test_client(0)?;
    let local_addr = conn.local_addr()?;

    let to = lookup_host(true, "stun1.l.google.com:19302")?;

    let tid1 = client.send_binding_request_to(to)?;
    let tid2 = client.send_binding_request_to(to)?;
    while let Some(transmit) = client.poll_transmit() {
        conn.send_to(&transmit.message, transmit.transport.peer_addr)?;
    }

    let mut buffer = vec![0u8; 2048];
    for _ in 0..2 {
        let (n, peer_addr) = conn.recv_from(&mut buffer)?;
        client.handle_transmit(Transmit {
            now: Instant::now(),
            transport: TransportContext {
                local_addr,
                peer_addr,
                protocol: Protocol::UDP,
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

    client.close();

    Ok(())
}

#[test]
fn test_client_with_stun_send_binding_request_to_timeout() -> Result<()> {
    //env_logger::init();

    let (conn, mut client) = create_listening_test_client(10)?;

    let to = lookup_host(true, "127.0.0.1:9")?;

    let tid = client.send_binding_request_to(to)?;
    while let Some(transmit) = client.poll_transmit() {
        conn.send_to(&transmit.message, transmit.transport.peer_addr)?;
    }

    while let Some(to) = client.poll_timout() {
        client.handle_timeout(to);
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

    client.close();

    Ok(())
}
