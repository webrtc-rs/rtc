#![cfg(all(feature = "ring", feature = "aws-lc-rs"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use bytes::{Bytes, BytesMut};
use rtc::crypto::providers::{AwsLcRsProvider, RingProvider};
use rtc::crypto::{
    ActiveKeyExchange, AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher,
    CryptoAlgorithm, CryptoError, HashAlgorithm, HmacAlgorithm, KeyExchangeAlgorithm, PublicKey,
    RTCCrypto, RTCCryptoProvider, RTCRandom, SignatureScheme, SigningKey, StreamCipher,
    StreamCipherAlgorithm,
};
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtc::rtp;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;

const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const MEDIA_SSRC: u32 = 0x1122_3344;

#[derive(Default)]
struct Calls {
    random: AtomicUsize,
    hash: AtomicUsize,
    hmac: AtomicUsize,
    aead: AtomicUsize,
    aead_seal: AtomicUsize,
    aead_open: AtomicUsize,
    key_exchange: AtomicUsize,
    signing: AtomicUsize,
    verification: AtomicUsize,
}

struct RecordingProvider {
    inner: Arc<dyn RTCCryptoProvider>,
    calls: Arc<Calls>,
}

impl RecordingProvider {
    fn wrap(inner: impl RTCCryptoProvider + 'static) -> (Arc<dyn RTCCryptoProvider>, Arc<Calls>) {
        let calls = Arc::new(Calls::default());
        let provider: Arc<dyn RTCCryptoProvider> = Arc::new(Self {
            inner: Arc::new(inner),
            calls: calls.clone(),
        });
        (provider, calls)
    }
}

impl RTCCryptoProvider for RecordingProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        self
    }

    fn random(&self) -> &dyn RTCRandom {
        self
    }
}

impl RTCRandom for RecordingProvider {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        self.calls.random.fetch_add(1, Ordering::Relaxed);
        self.inner.random().fill(output)
    }
}

/// Counts every tag computation, so the test can assert the provider is actually used. The count
/// now happens per `sign`/`verify` rather than per one-shot `hmac` call, since keyed MACs are
/// created once per context.
struct CountingMac {
    inner: Box<dyn rtc::crypto::Mac>,
    calls: Arc<Calls>,
}

impl rtc::crypto::Mac for CountingMac {
    fn output_len(&self) -> usize {
        self.inner.output_len()
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        self.calls.hmac.fetch_add(1, Ordering::Relaxed);
        self.inner.sign(input, output)
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        self.calls.hmac.fetch_add(1, Ordering::Relaxed);
        self.inner.verify(input, expected)
    }
}

impl RTCCrypto for RecordingProvider {
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        self.inner.crypto().supports(algorithm)
    }

    fn hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.calls.hash.fetch_add(1, Ordering::Relaxed);
        self.inner.crypto().hash(algorithm, data)
    }

    fn new_hmac(
        &self,
        algorithm: HmacAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn rtc::crypto::Mac>, CryptoError> {
        Ok(Box::new(CountingMac {
            inner: self.inner.crypto().new_hmac(algorithm, key)?,
            calls: Arc::clone(&self.calls),
        }))
    }

    fn block_encrypt(
        &self,
        algorithm: BlockCipherAlgorithm,
        key: &[u8],
        block: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.inner.crypto().block_encrypt(algorithm, key, block)
    }

    fn new_stream_cipher(
        &self,
        algorithm: StreamCipherAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher>, CryptoError> {
        self.inner.crypto().new_stream_cipher(algorithm, key)
    }

    fn new_aead(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher>, CryptoError> {
        self.calls.aead.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(RecordingAead {
            inner: self.inner.crypto().new_aead(algorithm, key)?,
            calls: self.calls.clone(),
        }))
    }

    fn new_cbc(
        &self,
        algorithm: CbcAlgorithm,
        key: &[u8],
    ) -> Result<Box<dyn CbcCipher>, CryptoError> {
        self.inner.crypto().new_cbc(algorithm, key)
    }

    fn start_key_exchange(
        &self,
        algorithm: KeyExchangeAlgorithm,
    ) -> Result<Box<dyn ActiveKeyExchange>, CryptoError> {
        self.calls.key_exchange.fetch_add(1, Ordering::Relaxed);
        self.inner.crypto().start_key_exchange(algorithm)
    }

    fn generate_signing_key(
        &self,
        scheme: SignatureScheme,
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        self.calls.signing.fetch_add(1, Ordering::Relaxed);
        self.inner.crypto().generate_signing_key(scheme)
    }

    fn import_signing_key(
        &self,
        scheme: SignatureScheme,
        pkcs8_der: &[u8],
    ) -> Result<Arc<dyn SigningKey>, CryptoError> {
        self.calls.signing.fetch_add(1, Ordering::Relaxed);
        self.inner.crypto().import_signing_key(scheme, pkcs8_der)
    }

    fn verify_signature(
        &self,
        scheme: SignatureScheme,
        public_key: PublicKey<'_>,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.calls.verification.fetch_add(1, Ordering::Relaxed);
        self.inner
            .crypto()
            .verify_signature(scheme, public_key, message, signature)
    }
}

struct RecordingAead {
    inner: Box<dyn AeadCipher>,
    calls: Arc<Calls>,
}

impl AeadCipher for RecordingAead {
    fn tag_len(&self) -> usize {
        self.inner.tag_len()
    }

    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.calls.aead_seal.fetch_add(1, Ordering::Relaxed);
        self.inner
            .seal_in_place(nonce, aad, plaintext_and_ciphertext, tag_out)
    }

    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        self.calls.aead_open.fetch_add(1, Ordering::Relaxed);
        self.inner
            .open_in_place(nonce, aad, ciphertext_and_plaintext, tag)
    }
}

struct Peer {
    pc: RTCPeerConnection,
    socket: UdpSocket,
    local_addr: SocketAddr,
}

impl Peer {
    async fn new(
        provider: Arc<dyn RTCCryptoProvider>,
        send_media: bool,
    ) -> Result<(Self, Option<RTCRtpSenderId>)> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = socket.local_addr()?;
        let codec = RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90_000,
                ..Default::default()
            },
            payload_type: 96,
        };
        let mut media_engine = MediaEngine::default();
        media_engine.register_codec(codec.clone(), RtpCodecKind::Video)?;
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_crypto_provider(provider);
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_setting_engine(setting_engine)
            .with_media_engine(media_engine)
            .build()?;

        let sender_id = if send_media {
            Some(pc.add_track(MediaStreamTrack::new(
                "provider-test-stream".to_owned(),
                "provider-test-video".to_owned(),
                "provider test video".to_owned(),
                RtpCodecKind::Video,
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(MEDIA_SSRC),
                        ..Default::default()
                    },
                    codec: codec.rtp_codec,
                    ..Default::default()
                }],
            ))?)
        } else {
            None
        };

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
        Ok((
            Self {
                pc,
                socket,
                local_addr,
            },
            sender_id,
        ))
    }

    async fn send_pending(&mut self) -> Result<()> {
        while let Some(message) = self.pc.poll_write() {
            self.socket
                .send_to(&message.message, message.transport.peer_addr)
                .await?;
        }
        Ok(())
    }

    fn receive(&mut self, data: &[u8], peer_addr: SocketAddr) -> Result<()> {
        Ok(self.pc.handle_read(TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(data),
        })?)
    }
}

async fn exercise_pair(
    offer_provider: Arc<dyn RTCCryptoProvider>,
    offer_calls: Arc<Calls>,
    answer_provider: Arc<dyn RTCCryptoProvider>,
    answer_calls: Arc<Calls>,
) -> Result<()> {
    let (mut offer, sender_id) = Peer::new(offer_provider, true).await?;
    let sender_id = sender_id.expect("offer peer has a media sender");
    let (mut answer, _) = Peer::new(answer_provider, false).await?;

    let description = offer.pc.create_offer(None)?;
    offer.pc.set_local_description(description.clone())?;
    answer.pc.set_remote_description(description)?;
    let description = answer.pc.create_answer(None)?;
    answer.pc.set_local_description(description.clone())?;
    offer.pc.set_remote_description(description)?;

    let mut offer_connected = false;
    let mut answer_connected = false;
    let mut receiver_id: Option<RTCRtpReceiverId> = None;
    let mut sent_rtp = 0_u16;
    let mut received_rtp = false;
    let mut sent_rtcp = false;
    let mut received_rtcp = false;
    let mut rtcp_aead_baseline = None;
    let mut sequence_number = 0;
    let mut offer_buffer = vec![0; 2048];
    let mut answer_buffer = vec![0; 2048];
    let started = Instant::now();

    while started.elapsed() < SESSION_TIMEOUT && !received_rtcp {
        offer.send_pending().await?;
        answer.send_pending().await?;

        while let Some(event) = offer.pc.poll_event() {
            if matches!(
                event,
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected
                )
            ) {
                offer_connected = true;
            }
        }
        while let Some(event) = answer.pc.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Connected,
                ) => answer_connected = true,
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
                    receiver_id = Some(init.receiver_id)
                }
                _ => {}
            }
        }

        while let Some(message) = answer.pc.poll_read() {
            if matches!(message, RTCMessage::RtpPacket(_, _)) {
                received_rtp = true;
            }
        }
        while let Some(message) = offer.pc.poll_read() {
            if matches!(message, RTCMessage::RtcpPacket(_, _)) {
                received_rtcp = true;
            }
        }
        if let Some((offer_open, answer_seal)) = rtcp_aead_baseline {
            received_rtcp = offer_calls.aead_open.load(Ordering::Relaxed) > offer_open
                && answer_calls.aead_seal.load(Ordering::Relaxed) > answer_seal;
        }

        if offer_connected && answer_connected && !received_rtp && sent_rtp < 30 {
            sequence_number += 1;
            let payload_type = offer
                .pc
                .rtp_sender(sender_id)
                .and_then(|mut sender| {
                    sender
                        .get_parameters()
                        .rtp_parameters
                        .codecs
                        .first()
                        .map(|codec| codec.payload_type)
                })
                .unwrap_or(96);
            offer
                .pc
                .rtp_sender(sender_id)
                .expect("media sender exists")
                .write_rtp(rtp::packet::Packet {
                    header: rtp::header::Header {
                        version: 2,
                        marker: true,
                        payload_type,
                        sequence_number,
                        timestamp: 90_000,
                        ssrc: MEDIA_SSRC,
                        ..Default::default()
                    },
                    payload: Bytes::from_static(b"provider-isolation"),
                })?;
            sent_rtp += 1;
        }
        if received_rtp && !sent_rtcp {
            rtcp_aead_baseline = Some((
                offer_calls.aead_open.load(Ordering::Relaxed),
                answer_calls.aead_seal.load(Ordering::Relaxed),
            ));
            answer
                .pc
                .rtp_receiver(receiver_id.expect("receiver opened before RTP arrived"))
                .expect("media receiver exists")
                .write_rtcp(vec![Box::new(PictureLossIndication {
                    sender_ssrc: 0,
                    media_ssrc: MEDIA_SSRC,
                })])?;
            sent_rtcp = true;
        }

        let next_timeout = offer
            .pc
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + SESSION_TIMEOUT)
            .min(
                answer
                    .pc
                    .poll_timeout()
                    .unwrap_or_else(|| Instant::now() + SESSION_TIMEOUT),
            );
        let delay = next_timeout
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(10));
        if delay.is_zero() {
            offer.pc.handle_timeout(Instant::now())?;
            answer.pc.handle_timeout(Instant::now())?;
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(delay) => {
                offer.pc.handle_timeout(Instant::now())?;
                answer.pc.handle_timeout(Instant::now())?;
            }
            result = offer.socket.recv_from(&mut offer_buffer) => {
                let (length, peer_addr) = result?;
                offer.receive(&offer_buffer[..length], peer_addr)?;
            }
            result = answer.socket.recv_from(&mut answer_buffer) => {
                let (length, peer_addr) = result?;
                answer.receive(&answer_buffer[..length], peer_addr)?;
            }
        }
    }

    ensure!(
        offer_connected && answer_connected,
        "peer connection did not reach Connected"
    );
    ensure!(
        received_rtp,
        "answerer did not receive provider-encrypted SRTP"
    );
    ensure!(
        received_rtcp,
        "offerer did not receive provider-encrypted SRTCP"
    );
    offer.pc.close()?;
    answer.pc.close()?;
    Ok(())
}

fn assert_calls(calls: &Calls) {
    assert!(
        calls.random.load(Ordering::Relaxed) > 0,
        "provider randomness was bypassed"
    );
    assert!(
        calls.hash.load(Ordering::Relaxed) > 0,
        "provider fingerprint hashing was bypassed"
    );
    assert!(
        calls.hmac.load(Ordering::Relaxed) > 0,
        "provider STUN HMAC was bypassed"
    );
    assert!(
        calls.aead.load(Ordering::Relaxed) > 0,
        "provider DTLS/SRTP AEAD was bypassed"
    );
    assert!(
        calls.key_exchange.load(Ordering::Relaxed) > 0,
        "provider key exchange was bypassed"
    );
    assert!(
        calls.signing.load(Ordering::Relaxed) > 0,
        "provider signing-key generation was bypassed"
    );
    assert!(
        calls.verification.load(Ordering::Relaxed) > 0,
        "provider signature verification was bypassed"
    );
}

#[tokio::test]
async fn isolates_crypto_providers_across_simultaneous_peer_connections() -> Result<()> {
    env_logger::builder().is_test(true).try_init().ok();
    let (ring_a, ring_a_calls) = RecordingProvider::wrap(RingProvider::new());
    let (ring_b, ring_b_calls) = RecordingProvider::wrap(RingProvider::new());
    let (aws_a, aws_a_calls) = RecordingProvider::wrap(AwsLcRsProvider::new());
    let (aws_b, aws_b_calls) = RecordingProvider::wrap(AwsLcRsProvider::new());
    exercise_pair(ring_a, ring_a_calls.clone(), ring_b, ring_b_calls.clone()).await?;
    exercise_pair(aws_a, aws_a_calls.clone(), aws_b, aws_b_calls.clone()).await?;

    let (ring_offer, ring_offer_calls) = RecordingProvider::wrap(RingProvider::new());
    let (aws_answer, aws_answer_calls) = RecordingProvider::wrap(AwsLcRsProvider::new());
    let (aws_offer, aws_offer_calls) = RecordingProvider::wrap(AwsLcRsProvider::new());
    let (ring_answer, ring_answer_calls) = RecordingProvider::wrap(RingProvider::new());
    let (ring_to_aws, aws_to_ring) = tokio::join!(
        exercise_pair(
            ring_offer,
            ring_offer_calls.clone(),
            aws_answer,
            aws_answer_calls.clone(),
        ),
        exercise_pair(
            aws_offer,
            aws_offer_calls.clone(),
            ring_answer,
            ring_answer_calls.clone(),
        ),
    );
    ring_to_aws?;
    aws_to_ring?;

    for calls in [
        ring_a_calls,
        ring_b_calls,
        aws_a_calls,
        aws_b_calls,
        ring_offer_calls,
        aws_answer_calls,
        aws_offer_calls,
        ring_answer_calls,
    ] {
        assert_calls(&calls);
    }
    Ok(())
}
