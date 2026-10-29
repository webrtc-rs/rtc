use crypto::default_provider;
use rtc_dtls::{
    config::{ClientAuthType, ConfigBuilder},
    crypto::Certificate,
    endpoint::{Endpoint, EndpointEvent},
};
use shared::TransportProtocol;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Association {
    client: Endpoint,
    server: Endpoint,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
    start: Instant,
}

impl Association {
    /// Starts a mutually authenticated handshake; the ClientHello is queued.
    fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let provider = default_provider()?;
        let certificate =
            Certificate::generate_self_signed(vec!["localhost".into()], provider.crypto())?;
        let configuration = ConfigBuilder::default()
            .with_crypto_provider(provider)
            .with_certificates(vec![certificate])
            // Self-signed peers keep this packet-loss regression independent of a CA.
            .with_insecure_skip_verify(true)
            .with_client_auth(ClientAuthType::RequireAnyClientCert);
        let client_addr: SocketAddr = "127.0.0.1:44001".parse()?;
        let server_addr: SocketAddr = "127.0.0.1:44002".parse()?;
        let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
        let server = Endpoint::new(
            server_addr,
            TransportProtocol::UDP,
            Some(Arc::new(configuration.clone().build(false, None)?)),
        );
        let start = Instant::now();

        client.connect(
            start,
            server_addr,
            Arc::new(configuration.build(true, None)?),
            None,
        )?;

        Ok(Self {
            client,
            server,
            client_addr,
            server_addr,
            start,
        })
    }
}

fn transfer(
    source: &mut Endpoint,
    destination: &mut Endpoint,
    source_addr: SocketAddr,
    now: Instant,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut completed = false;

    while let Some(packet) = source.poll_transmit() {
        completed |= destination
            .read(now, source_addr, packet.transport.ecn, packet.message)?
            .iter()
            .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
    }

    Ok(completed)
}

const HANDSHAKE_CONTENT_TYPE: u8 = 22;
const SERVER_HELLO_DONE: u8 = 14;

/// Fresh epoch-0 record sequence numbers, above any used by the handshake.
const INJECTED_SEQUENCE_START: u64 = 1_000;

/// A 25-byte epoch-0 ServerHelloDone record: never valid once DTLS is established.
fn unexpected_handshake_record(message_sequence: u16, record_sequence: u64) -> Vec<u8> {
    let mut record = vec![HANDSHAKE_CONTENT_TYPE, 0xfe, 0xfd, 0, 0];

    record.extend_from_slice(&record_sequence.to_be_bytes()[2..]);
    record.extend_from_slice(&12u16.to_be_bytes());
    record.extend_from_slice(&[SERVER_HELLO_DONE, 0, 0, 0]);
    record.extend_from_slice(&message_sequence.to_be_bytes());
    record.extend_from_slice(&[0; 6]);
    record
}

#[test]
fn completed_endpoints_ignore_unexpected_plaintext_handshake_records() -> TestResult {
    let mut association = Association::connect()?;
    let mut client_completed = false;
    let mut server_completed = false;
    for _ in 0..4 {
        server_completed |= transfer(
            &mut association.client,
            &mut association.server,
            association.client_addr,
            association.start,
        )?;
        client_completed |= transfer(
            &mut association.server,
            &mut association.client,
            association.server_addr,
            association.start,
        )?;
    }
    assert!(client_completed && server_completed);

    for (endpoint, peer_addr) in [
        (&mut association.client, association.server_addr),
        (&mut association.server, association.client_addr),
    ] {
        let now = association.start + Duration::from_millis(500);
        for sequence in 0..32 {
            let record = unexpected_handshake_record(
                sequence,
                INJECTED_SEQUENCE_START + u64::from(sequence),
            );
            let events = endpoint.read(now, peer_addr, None, record.as_slice().into())?;
            assert!(
                events.is_empty(),
                "a stray record does not complete the handshake again"
            );
            assert!(
                endpoint.poll_transmit().is_none(),
                "a stray plaintext handshake must not retransmit a completed flight"
            );
        }
    }

    association.client.write(
        association.start,
        association.server_addr,
        b"still connected",
    )?;
    let packet = association
        .client
        .poll_transmit()
        .expect("application data is queued");
    let events = association.server.read(
        association.start,
        association.client_addr,
        None,
        packet.message,
    )?;
    assert!(events.iter().any(|event| matches!(event, EndpointEvent::ApplicationData(data) if data.as_ref() == b"still connected")));
    Ok(())
}

#[test]
fn stray_handshake_records_do_not_spend_the_final_flight_retry_budget() -> TestResult {
    let Association {
        mut client,
        mut server,
        client_addr,
        server_addr,
        start,
    } = Association::connect()?;
    // Stop once the server completes, with its final flight still queued.
    transfer(&mut client, &mut server, client_addr, start)?;
    transfer(&mut server, &mut client, server_addr, start)?;
    transfer(&mut client, &mut server, client_addr, start)?;
    transfer(&mut server, &mut client, server_addr, start)?;
    assert!(transfer(&mut client, &mut server, client_addr, start)?);
    let mut dropped = 0;
    while server.poll_transmit().is_some() {
        dropped += 1;
    }
    assert!(dropped > 0, "the final server flight was actually lost");

    // These records carry no MAC and require no knowledge of the session keys.
    // Drain replies so the recovery assertion sees only the legitimate repeat.
    for sequence in 0..32 {
        let record =
            unexpected_handshake_record(sequence, INJECTED_SEQUENCE_START + u64::from(sequence));
        server.read(
            start + Duration::from_millis(500),
            client_addr,
            None,
            record.as_slice().into(),
        )?;
        while server.poll_transmit().is_some() {}
    }

    let deadline = client
        .poll_timeout(&server_addr)
        .expect("the client is waiting for the server Finished");
    client.handle_timeout(server_addr, deadline)?;
    let mut repeated = Vec::new();
    while let Some(packet) = client.poll_transmit() {
        repeated.push(packet.message);
    }
    assert!(!repeated.is_empty(), "the client repeated its final flight");
    for packet in &repeated {
        server.read(deadline, client_addr, None, packet.clone())?;
    }

    assert!(
        transfer(&mut server, &mut client, server_addr, deadline)?,
        "the authenticated repeated Finished must still recover the lost final server flight after stray plaintext records"
    );
    // The same encrypted records cannot trigger another response.
    for packet in repeated {
        server.read(deadline, client_addr, None, packet)?;
    }
    assert!(
        server.poll_transmit().is_none(),
        "record replay protection is preserved"
    );
    Ok(())
}
