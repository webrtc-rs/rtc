//! Regression test for `SettingEngineBuilder::disable_certificate_fingerprint_verification`.
//!
//! The setter existed but the flag was never plumbed into `RTCDtlsTransport`, so the
//! DTLS handshake always installed the fingerprint-matching `verify_peer_certificate`
//! callback and enabling the option had no effect at all.
//!
//! This matters for protocols where the answerer *cannot* know the offerer's
//! fingerprint ahead of time. libp2p's WebRTC-Direct is the canonical example: the
//! server never receives a real offer — it synthesizes one locally from the incoming
//! STUN binding request, filling the `a=fingerprint` line with a placeholder, and
//! authenticates the peer afterwards with a Noise handshake over the data channel.
//! With the flag ignored, that handshake fails with `ErrNoMatchingCertificateFingerprint`.
//!
//! The two tests below pin both directions: with the option enabled a mismatched
//! fingerprint connects, and with it left at the default the same setup still fails.

use anyhow::Result;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::{SettingEngine, SettingEngineBuilder};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate,
};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::sansio::Protocol;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;

use crate::dtls_common::TestPeer;

mod dtls_common;

/// A fingerprint that matches no certificate, standing in for the placeholder a
/// WebRTC-Direct server puts in the offer it synthesizes for the client.
const PLACEHOLDER_FINGERPRINT: &str = "a=fingerprint:sha-256 \
FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:\
FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF";

struct Peer {
    pc: RTCPeerConnection,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
}

impl Peer {
    async fn new(setting_engine: SettingEngine) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = socket.local_addr()?;

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(RTCConfigurationBuilder::new().build())
            .with_setting_engine(setting_engine)
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

/// Replaces the `a=fingerprint` line so the answerer is told to expect a
/// certificate the offerer will never present.
fn with_placeholder_fingerprint(sdp: &str) -> String {
    sdp.lines()
        .map(|line| {
            if line.starts_with("a=fingerprint:") {
                PLACEHOLDER_FINGERPRINT
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n"
}

/// Runs the handshake with the answerer given a fingerprint that cannot match.
///
/// `disable_verification` selects whether the answerer opts out of fingerprint
/// checking; everything else is identical between the two tests.
async fn handshake_with_mismatched_fingerprint(disable_verification: bool) -> Result<bool> {
    let offer_setting_engine = SettingEngineBuilder::new()
        .with_answering_dtls_role(RTCDtlsRole::Client)
        .build();
    let mut offer = Peer::new(offer_setting_engine).await?;

    // The answerer takes the DTLS server role, mirroring a WebRTC-Direct listener.
    let answer_setting_engine = SettingEngineBuilder::new()
        .with_answering_dtls_role(RTCDtlsRole::Server)
        .with_disable_certificate_fingerprint_verification(disable_verification)
        .build();
    let mut answer = Peer::new(answer_setting_engine).await?;

    // A data channel is needed for the m-line that carries the DTLS parameters.
    offer.pc.create_data_channel("test", None)?;

    let local_offer = offer.pc.create_offer(None)?;
    offer
        .pc
        .set_local_description(Instant::now(), local_offer.clone())?;

    // The answerer is handed an offer whose fingerprint the offerer cannot satisfy.
    let mut tampered = local_offer;
    tampered.sdp = with_placeholder_fingerprint(&tampered.sdp);
    answer.pc.set_remote_description(Instant::now(), tampered)?;

    let local_answer = answer.pc.create_answer(None)?;
    answer
        .pc
        .set_local_description(Instant::now(), local_answer.clone())?;
    offer
        .pc
        .set_remote_description(Instant::now(), local_answer)?;

    let connected = offer.connect(&mut answer).await?;

    offer.pc.close().ok();
    answer.pc.close().ok();

    Ok(connected)
}

/// With verification disabled, a mismatched fingerprint must not block the handshake.
#[tokio::test]
async fn disabled_verification_accepts_mismatched_fingerprint() -> Result<()> {
    assert!(
        handshake_with_mismatched_fingerprint(true).await?,
        "DTLS should complete when disable_certificate_fingerprint_verification is set"
    );
    Ok(())
}

/// The same setup must still fail by default — otherwise the test above would pass
/// even if the option were ignored again.
#[tokio::test]
async fn default_verification_rejects_mismatched_fingerprint() -> Result<()> {
    assert!(
        !handshake_with_mismatched_fingerprint(false).await?,
        "DTLS must reject a certificate that does not match the signaled fingerprint"
    );
    Ok(())
}
