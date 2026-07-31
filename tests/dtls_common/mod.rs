//! Shared helpers for DTLS related integration tests.

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
