//! Shared helpers for the interop tests.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::Result;
use bytes::BytesMut;
use rtc::peer_connection::{
    RTCPeerConnection, event::RTCPeerConnectionEvent, state::RTCPeerConnectionState,
};
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;

/// Installs a process-wide rustls `CryptoProvider` if one is not already installed.
///
/// The interop tests drive the published `webrtc` crate alongside this one, and its `dtls 0.13`
/// dependency asks rustls to infer the provider from crate features. That inference only works
/// when exactly one of rustls' `ring`/`aws-lc-rs` features is enabled — but in a test build both
/// are: `dtls 0.13` turns on `rustls/ring` while `rtc` turns on whichever its own feature selects.
/// Cargo unifies the two, rustls finds an ambiguity, and the old crate panics.
///
/// Naming a provider here resolves it for that crate. `rtc` itself no longer consults this
/// default — it passes its provider explicitly (see `rtc_dtls::config`) — so which one we install
/// only has to satisfy the old code. `ring` is always available in a test build: either `rtc`
/// selected it, or `dtls 0.13` pulled it in.
///
/// Idempotent, and safe to call from every test: `install_default` returns `Err` once a provider
/// is set, which is ignored here, so the first caller wins and an application that installed its
/// own is unaffected.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Connection timeout used during [`TestPeer::connect`], long enough for a DTLS handshake over
/// loopback, short enough to keep the negative test from dominating the suite.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub trait TestPeer {
    /// Mutable reference to the underlying [`RTCPeerConnection`].
    fn pc(&mut self) -> &mut RTCPeerConnection;
    /// Reference to the underlying UDP socket.
    fn socket(&self) -> &UdpSocket;
    /// The local socket address.
    fn local_addr(&self) -> SocketAddr;

    /// Drives both peers until each reports `Connected`, or the timeout expires.
    ///
    /// Returns whether the DTLS handshake completed on both ends.
    async fn connect(&mut self, answer: &mut impl TestPeer) -> Result<bool> {
        let (mut offer_connected, mut answer_connected) = (false, false);
        let mut offer_buf = vec![0u8; 2000];
        let mut answer_buf = vec![0u8; 2000];
        let start = Instant::now();

        while start.elapsed() < CONNECT_TIMEOUT && !(offer_connected && answer_connected) {
            while let Some(msg) = self.pc().poll_write() {
                self.socket()
                    .send_to(&msg.message, msg.transport.peer_addr)
                    .await?;
            }
            while let Some(event) = self.pc().poll_event() {
                if matches!(
                    event,
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Connected
                    )
                ) {
                    offer_connected = true;
                }
            }

            while let Some(msg) = answer.pc().poll_write() {
                answer
                    .socket()
                    .send_to(&msg.message, msg.transport.peer_addr)
                    .await?;
            }
            while let Some(event) = answer.pc().poll_event() {
                if matches!(
                    event,
                    RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                        RTCPeerConnectionState::Connected
                    )
                ) {
                    answer_connected = true;
                }
            }

            let next_timeout = self
                .pc()
                .poll_timeout()
                .unwrap_or_else(|| Instant::now() + CONNECT_TIMEOUT)
                .min(
                    answer
                        .pc()
                        .poll_timeout()
                        .unwrap_or_else(|| Instant::now() + CONNECT_TIMEOUT),
                );
            let delay = next_timeout
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10));

            if delay.is_zero() {
                self.pc().handle_timeout(Instant::now()).ok();
                answer.pc().handle_timeout(Instant::now()).ok();
                continue;
            }

            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            tokio::select! {
                _ = sleep => {
                    self.pc().handle_timeout(Instant::now()).ok();
                    answer.pc().handle_timeout(Instant::now()).ok();
                }
                Ok((n, peer_addr)) = self.socket().recv_from(&mut offer_buf) => {
                    let local_addr = self.local_addr();
                    self.pc().handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&offer_buf[..n]),
                    }).ok();
                }

                Ok((n, peer_addr)) = answer.socket().recv_from(&mut answer_buf) => {
                    let local_addr = answer.local_addr();
                    answer.pc().handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&answer_buf[..n]),
                    }).ok();
                }
            }
        }

        Ok(offer_connected && answer_connected)
    }
}
