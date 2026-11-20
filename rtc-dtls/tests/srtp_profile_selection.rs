//! Server-side SRTP protection profile selection: whose offer order wins
//! when the client's `use_srtp` list and the server's configured profiles
//! intersect. RFC 5764 §4.1.1 mandates only that the server select a
//! profile the client offered; [`SrtpProfileSelection::ServerPreference`]
//! makes the server rank the intersection by its own order.

use crypto::default_provider;
use rtc_dtls::{
    config::{ClientAuthType, ConfigBuilder, SrtpProfileSelection},
    crypto::Certificate,
    endpoint::{Endpoint, EndpointEvent},
    extension::extension_use_srtp::SrtpProtectionProfile,
};
use shared::TransportProtocol;
use std::{net::SocketAddr, sync::Arc, time::Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type HandshakeResult = Result<ProfilePair, Box<dyn std::error::Error>>;

type ProfilePair = (SrtpProtectionProfile, SrtpProtectionProfile);

const SHA1_80: SrtpProtectionProfile = SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80;
const SHA1_32: SrtpProtectionProfile = SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32;

/// Run a full handshake; return the profile selected on each side.
fn handshake(selection: SrtpProfileSelection) -> HandshakeResult {
    let provider = default_provider()?;
    let client_cert = Certificate::generate_self_signed(vec!["client".into()], provider.crypto())?;
    let server_cert =
        Certificate::generate_self_signed(vec!["localhost".into()], provider.crypto())?;

    // The client prefers HMAC-SHA1; the server prefers AEAD-capable order
    // here SHA1_32-first: the two orders disagree on the intersection, so
    // the test pins whose order actually wins.
    let client_profiles = vec![SHA1_80, SHA1_32];
    let server_profiles = vec![SHA1_32, SHA1_80];

    let client_config = ConfigBuilder::default()
        .with_crypto_provider(provider.clone().into())
        .with_certificates(vec![client_cert])
        .with_insecure_skip_verify(true)
        .with_client_auth(ClientAuthType::RequireAnyClientCert)
        .with_srtp_protection_profiles(client_profiles);
    let server_config = ConfigBuilder::default()
        .with_crypto_provider(provider.into())
        .with_certificates(vec![server_cert])
        .with_insecure_skip_verify(true)
        .with_client_auth(ClientAuthType::RequireAnyClientCert)
        .with_srtp_protection_profiles(server_profiles)
        .with_srtp_profile_selection(selection);

    let client_addr: SocketAddr = "127.0.0.1:44003".parse()?;
    let server_addr: SocketAddr = "127.0.0.1:44004".parse()?;
    let start = Instant::now();
    let mut client = Endpoint::new(client_addr, TransportProtocol::UDP, None);
    let mut server = Endpoint::new(
        server_addr,
        TransportProtocol::UDP,
        Some(Arc::new(server_config.build(false, None)?)),
    );
    client.connect(
        start,
        server_addr,
        Arc::new(client_config.build(true, None)?),
        None,
    )?;

    // Pump the flights between the endpoints until both sides complete.
    let mut client_completed = false;
    let mut server_completed = false;
    for _ in 0..6 {
        while let Some(packet) = client.poll_transmit() {
            server_completed |= server
                .read(start, client_addr, packet.transport.ecn, packet.message)?
                .iter()
                .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        }
        while let Some(packet) = server.poll_transmit() {
            client_completed |= client
                .read(start, server_addr, packet.transport.ecn, packet.message)?
                .iter()
                .any(|event| matches!(event, EndpointEvent::HandshakeComplete));
        }
        if client_completed && server_completed {
            break;
        }
    }
    assert!(
        client_completed && server_completed,
        "the handshake must complete with {selection:?}"
    );

    Ok((
        client
            .connection(server_addr)
            .expect("client connection")
            .selected_srtp_protection_profile(),
        server
            .connection(client_addr)
            .expect("server connection")
            .selected_srtp_protection_profile(),
    ))
}

#[test]
fn client_preference_selects_by_the_client_order() -> TestResult {
    let (client, server) = handshake(SrtpProfileSelection::ClientPreference)?;
    // Client order: SHA1_80 first.
    assert_eq!(client, SHA1_80);
    assert_eq!(server, SHA1_80);
    Ok(())
}

#[test]
fn server_preference_selects_by_the_server_order() -> TestResult {
    let (client, server) = handshake(SrtpProfileSelection::ServerPreference)?;
    // Server order: SHA1_32 first.
    assert_eq!(client, SHA1_32);
    assert_eq!(server, SHA1_32);
    Ok(())
}
