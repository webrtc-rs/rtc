//! Integration coverage for RSA certificates over DTLS.
//!
//! `ConfigBuilder::validate` used to reject every private key that was not Ed25519 or ECDSA
//! P-256. This restriction has been removed with this test validating expected behavior with
//! RSA keys.
//!
//! The keys are fixtures rather than freshly generated because rcgen cannot generate RSA keys
//! under the `ring` backend.

use anyhow::Result;
use rtc::crypto::{self, SignatureScheme};
use rtc::peer_connection::certificate::{CertificateParams, RTCCertificate};
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;

use crate::dtls_common::TestPeer;

mod dtls_common;

const RSA_OFFERER_KEY: &str = include_str!("testdata/rsa_2048_offerer_key.pem");
const RSA_ANSWERER_KEY: &str = include_str!("testdata/rsa_2048_answerer_key.pem");

/// The key type a peer authenticates with.
#[derive(Copy, Clone, Debug)]
enum KeyType {
    Rsa2048(&'static str),
    EcdsaP256,
}

impl KeyType {
    fn certificate(self) -> Result<RTCCertificate> {
        let provider = crypto::default_provider()?;
        let params = CertificateParams::new(vec!["webrtc.rs".to_owned()])?;

        Ok(match self {
            // The RSA key is a fixture, so it is imported rather than generated and then
            // wrapped in a fresh self-signed certificate.
            KeyType::Rsa2048(pem) => {
                let der = pem::parse(pem)?.into_contents();
                let signing_key = provider
                    .crypto()
                    .import_signing_key(SignatureScheme::RsaPkcs1Sha256, &der)?;
                RTCCertificate::generate_from_signing_key(
                    params,
                    SignatureScheme::RsaPkcs1Sha256,
                    signing_key,
                )?
            }
            KeyType::EcdsaP256 => RTCCertificate::generate(
                provider.crypto(),
                SignatureScheme::EcdsaP256Sha256,
                params,
            )?,
        })
    }
}

struct Peer {
    pc: RTCPeerConnection,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl TestPeer for Peer {
    fn pc(&mut self) -> &mut RTCPeerConnection {
        &mut self.pc
    }

    fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Peer {
    async fn new(key_type: KeyType) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = socket.local_addr()?;

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_certificates(vec![key_type.certificate()?])
                    .build(),
            )
            .build(Instant::now())?;

        // Host candidate only: the peers talk over loopback, so no STUN is needed.
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: local_addr.ip().to_string(),
                port: local_addr.port(),
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()?;
        pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

        Ok(Self {
            pc,
            socket: Arc::new(socket),
            local_addr,
        })
    }
}

/// Negotiates a connection between two peers with the given certificate key types.
async fn handshake_between(offer_key: KeyType, answer_key: KeyType) -> Result<bool> {
    let mut offer = Peer::new(offer_key).await?;
    let mut answer = Peer::new(answer_key).await?;

    // A data channel is needed for the m-line that carries the DTLS parameters.
    offer.pc.create_data_channel("test", None)?;

    let local_offer = offer.pc.create_offer(None)?;
    offer
        .pc
        .set_local_description(Instant::now(), local_offer.clone())?;
    answer
        .pc
        .set_remote_description(Instant::now(), local_offer)?;

    let local_answer = answer.pc.create_answer(None)?;
    offer
        .pc
        .set_remote_description(Instant::now(), local_answer.clone())?;
    answer
        .pc
        .set_local_description(Instant::now(), local_answer)?;

    let connected = offer.connect(&mut answer).await?;

    offer.pc.close().ok();
    answer.pc.close().ok();

    Ok(connected)
}

/// An RSA certificate on both ends must complete the handshake.
#[tokio::test]
async fn rsa_certificates_complete_dtls_handshake() -> Result<()> {
    assert!(
        handshake_between(
            KeyType::Rsa2048(RSA_OFFERER_KEY),
            KeyType::Rsa2048(RSA_ANSWERER_KEY)
        )
        .await?,
        "DTLS should complete when both peers authenticate with an RSA certificate"
    );
    Ok(())
}

/// Mixed private key case must complete the handshake.
#[tokio::test]
async fn rsa_certificate_interoperates_with_ecdsa_peer() -> Result<()> {
    assert!(
        handshake_between(KeyType::Rsa2048(RSA_OFFERER_KEY), KeyType::EcdsaP256).await?,
        "DTLS should complete with an RSA offerer and an ECDSA answerer"
    );
    assert!(
        handshake_between(KeyType::EcdsaP256, KeyType::Rsa2048(RSA_ANSWERER_KEY)).await?,
        "DTLS should complete with an ECDSA offerer and an RSA answerer"
    );
    Ok(())
}
