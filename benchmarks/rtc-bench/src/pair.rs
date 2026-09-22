//! Two peer connections joined by an in-memory wire and driven by a virtual clock.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rtc::crypto::RTCCryptoProvider;
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::interceptor::Registry;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::certificate::RTCCertificate;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
use rtc::peer_connection::configuration::media_engine::MediaEngine;
use rtc::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent, RTCTrackEvent};
use rtc::peer_connection::message::{RTCMessage, TaggedRTCMessage};
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};
use rtc::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtc::rtp;
use rtc::rtp_transceiver::RTCRtpSenderId;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodingParameters, RTCRtpEncodingParameters};
use rtc::sansio::Protocol;
use rtc::shared::error::{Error, Result};
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};

use crate::allocations::{self, Allocations};
use crate::fixtures::{self, Interceptors, MediaKind};

/// How much virtual time a drive may consume before it is declared stalled.
///
/// Generous: a handshake needs a few round trips at zero latency, and a transfer only waits on
/// timers when SCTP is holding a delayed SACK. Reaching this means the harness or the stack is
/// stuck, and a benchmark that reports a number for a stuck path is worse than one that fails.
const VIRTUAL_TIME_BUDGET: Duration = Duration::from_secs(120);

/// Pump rounds [`PeerPair::flush`] allows before declaring that the peers never go quiet.
const FLUSH_ROUND_LIMIT: usize = 100_000;

/// Unacknowledged data-channel bytes [`PeerPair::transfer`] allows before it stops queueing and
/// lets the wire drain. The same cap `rtc-sctp`'s `sctp_e2e` harness uses, so the SCTP pending
/// queue stays realistic instead of absorbing the whole workload up front.
const SEND_BUFFER_LIMIT: usize = 1 << 20;

const OFFERER_ADDR: &str = "127.0.0.1:40000";
const ANSWERER_ADDR: &str = "127.0.0.1:40001";

/// First SSRC handed to an offerer track; later tracks count up from it.
const FIRST_SSRC: u32 = 0x5EED_0000;

/// What the application side of a peer has taken out of `poll_read`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// RTP packets delivered to the application.
    pub rtp_packets: u64,
    /// RTP payload bytes delivered to the application.
    pub rtp_payload_bytes: u64,
    /// RTCP packets delivered to the application.
    pub rtcp_packets: u64,
    /// Data-channel messages delivered to the application.
    pub data_channel_messages: u64,
    /// Data-channel payload bytes delivered to the application.
    pub data_channel_bytes: u64,
}

/// Traffic that crossed the wire in one direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Direction {
    /// Datagrams sent.
    pub datagrams: u64,
    /// Bytes sent, counting everything `poll_write` produced — headers, SRTP tags, DTLS records.
    pub bytes: u64,
}

/// Traffic on the in-memory wire since the pair was built.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WireStats {
    /// Offerer to answerer.
    pub to_answerer: Direction,
    /// Answerer to offerer.
    pub to_offerer: Direction,
}

/// One side of a [`PeerPair`].
pub struct Peer {
    /// The peer connection. Public so a benchmark can call anything the harness does not wrap.
    pub pc: RTCPeerConnection,
    addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound: VecDeque<BytesMut>,
    connected: bool,
    failed: bool,
    open_channels: Vec<RTCDataChannelId>,
    tracks_opened: usize,
    received: Received,
    busy: Duration,
    allocations: Allocations,
}

/// Wall time and allocations since a call into a peer began, charged to it by [`Peer::charge`].
struct Meter {
    started: Instant,
    allocations: Allocations,
}

impl Meter {
    fn start() -> Self {
        Self {
            started: Instant::now(),
            allocations: allocations::snapshot(),
        }
    }
}

impl Peer {
    fn new(pc: RTCPeerConnection, addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            pc,
            addr,
            remote_addr,
            inbound: VecDeque::new(),
            connected: false,
            failed: false,
            open_channels: Vec::new(),
            tracks_opened: 0,
            received: Received::default(),
            busy: Duration::ZERO,
            allocations: Allocations::default(),
        }
    }

    fn charge(&mut self, meter: Meter) {
        self.busy += meter.started.elapsed();
        self.allocations += allocations::snapshot() - meter.allocations;
    }

    /// Runs `f` against the peer connection and charges the wall time and allocations it took to
    /// this peer.
    ///
    /// Every call the harness makes into a peer is charged the same way, so [`Self::busy`] and
    /// [`Self::allocations`] are the cost of that side of the connection. Use this for work a
    /// benchmark does directly, such as `write_rtp`, so that it is charged to the right side too.
    pub fn timed<R>(&mut self, f: impl FnOnce(&mut RTCPeerConnection) -> R) -> R {
        let meter = Meter::start();
        let result = f(&mut self.pc);
        self.charge(meter);
        result
    }

    /// Wall time spent inside this peer's connection since the last [`Self::reset_accounting`].
    ///
    /// Covers every call the harness makes — `handle_read`, `handle_timeout`, and draining
    /// `poll_write`, `poll_event` and `poll_read` — plus whatever a benchmark ran through
    /// [`Self::timed`]. Polls that find nothing are included: an application pays for those too.
    pub fn busy(&self) -> Duration {
        self.busy
    }

    /// Heap allocations made inside this peer's connection since the last
    /// [`Self::reset_accounting`], over the same calls as [`Self::busy`].
    ///
    /// Always zero unless the bench binary installs
    /// [`CountingAllocator`](crate::allocations::CountingAllocator).
    pub fn allocations(&self) -> Allocations {
        self.allocations
    }

    /// Zeroes [`Self::busy`] and [`Self::allocations`].
    pub fn reset_accounting(&mut self) {
        self.busy = Duration::ZERO;
        self.allocations = Allocations::default();
    }

    /// Whether the connection has reached `connected`.
    pub fn connected(&self) -> bool {
        self.connected
    }

    /// Data channels that have announced `open`, in the order they did.
    pub fn open_channels(&self) -> &[RTCDataChannelId] {
        &self.open_channels
    }

    /// Remote tracks that have announced `open`.
    pub fn tracks_opened(&self) -> usize {
        self.tracks_opened
    }

    /// What the application side has read so far.
    pub fn received(&self) -> Received {
        self.received
    }

    /// Delivers queued inbound datagrams, fires a due timer, and drains events and reads.
    ///
    /// Returns whether anything happened. A timer firing does not count: a timer can stay due
    /// across a `handle_timeout` that had nothing to do, and counting it would spin forever.
    fn step(&mut self, now: Instant) -> Result<bool> {
        let meter = Meter::start();
        let mut worked = false;

        while let Some(message) = self.inbound.pop_front() {
            worked = true;
            self.pc.handle_read(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: self.addr,
                    peer_addr: self.remote_addr,
                    ecn: None,
                    transport_protocol: TransportProtocol::UDP,
                },
                message,
            })?;
        }

        if self
            .pc
            .poll_timeout()
            .is_some_and(|deadline| deadline <= now)
        {
            self.pc.handle_timeout(now)?;
        }

        while let Some(event) = self.pc.poll_event() {
            worked = true;
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => match state {
                    RTCPeerConnectionState::Connected => self.connected = true,
                    RTCPeerConnectionState::Failed => self.failed = true,
                    _ => {}
                },
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    self.open_channels.push(id);
                }
                RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(_)) => {
                    self.tracks_opened += 1;
                }
                _ => {}
            }
        }

        while let Some(TaggedRTCMessage { message, .. }) = self.pc.poll_read() {
            worked = true;
            match message {
                RTCMessage::RtpPacket(_, packet) => {
                    self.received.rtp_packets += 1;
                    self.received.rtp_payload_bytes += packet.payload.len() as u64;
                }
                RTCMessage::RtcpPacket(_, _) => self.received.rtcp_packets += 1,
                RTCMessage::DataChannelMessage(_, message) => {
                    self.received.data_channel_messages += 1;
                    self.received.data_channel_bytes += message.data.len() as u64;
                }
                _ => {}
            }
        }

        self.charge(meter);
        Ok(worked)
    }
}

/// Moves everything `from` wants to send onto `to`'s inbound queue.
fn transmit(from: &mut Peer, to: &mut Peer, stats: &mut Direction) -> bool {
    let meter = Meter::start();
    let mut worked = false;
    while let Some(datagram) = from.pc.poll_write() {
        debug_assert_eq!(datagram.transport.peer_addr, to.addr, "misrouted datagram");
        stats.datagrams += 1;
        stats.bytes += datagram.message.len() as u64;
        to.inbound.push_back(datagram.message);
        worked = true;
    }
    from.charge(meter);
    worked
}

/// A track the offerer sends, with the RTP state needed to keep producing valid packets.
#[derive(Debug, Clone)]
pub struct LocalTrack {
    /// The sender carrying this track.
    pub sender_id: RTCRtpSenderId,
    /// What the track carries.
    pub kind: MediaKind,
    /// The SSRC its encoding was given.
    pub ssrc: u32,
    /// Negotiated payload type. Resolved after negotiation; until then, the registered one.
    pub payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    payload: Bytes,
}

/// Performs a complete offer/answer exchange between two peer connections at `now`.
///
/// Exposed on its own so signaling cost can be benchmarked without anything else a
/// [`PeerPair`] does.
///
/// # Errors
///
/// Whatever the first failing negotiation step returns.
pub fn negotiate(
    offerer: &mut RTCPeerConnection,
    answerer: &mut RTCPeerConnection,
    now: Instant,
) -> Result<()> {
    let offer = offerer.create_offer(None)?;
    offerer.set_local_description(now, offer.clone())?;
    answerer.set_remote_description(now, offer)?;
    let answer = answerer.create_answer(None)?;
    answerer.set_local_description(now, answer.clone())?;
    offerer.set_remote_description(now, answer)?;
    Ok(())
}

/// Configures a [`PeerPair`]. Created by [`PeerPair::builder`].
pub struct PairBuilder {
    provider: Arc<dyn RTCCryptoProvider>,
    certificates: Option<(RTCCertificate, RTCCertificate)>,
    interceptors: Interceptors,
    tracks: Vec<MediaKind>,
    data_channel: Option<RTCDataChannelInit>,
}

impl PairBuilder {
    /// Uses these certificates instead of letting each peer generate one at construction.
    ///
    /// Almost always wanted: otherwise building the pair includes two key generations.
    pub fn certificates(mut self, offerer: RTCCertificate, answerer: RTCCertificate) -> Self {
        self.certificates = Some((offerer, answerer));
        self
    }

    /// Builds both peers with this interceptor chain. Defaults to [`Interceptors::None`].
    pub fn interceptors(mut self, interceptors: Interceptors) -> Self {
        self.interceptors = interceptors;
        self
    }

    /// Adds a track the offerer sends. May be called repeatedly.
    pub fn track(mut self, kind: MediaKind) -> Self {
        self.tracks.push(kind);
        self
    }

    /// Has the offerer create a data channel, negotiated in-band with DCEP as browsers do.
    pub fn data_channel(mut self, init: RTCDataChannelInit) -> Self {
        self.data_channel = Some(init);
        self
    }

    /// Builds both peers and adds their candidates, tracks and data channel. Does not negotiate.
    ///
    /// # Errors
    ///
    /// If either peer connection cannot be built or configured.
    pub fn build(self) -> Result<PeerPair> {
        let now = Instant::now();
        let offerer_addr: SocketAddr = OFFERER_ADDR.parse().expect("valid address");
        let answerer_addr: SocketAddr = ANSWERER_ADDR.parse().expect("valid address");
        let (offerer_certificate, answerer_certificate) = match self.certificates {
            Some((offerer, answerer)) => (Some(offerer), Some(answerer)),
            None => (None, None),
        };

        let mut offerer = build_peer(
            &self.provider,
            offerer_certificate,
            self.interceptors,
            offerer_addr,
            now,
        )?;
        let answerer = build_peer(
            &self.provider,
            answerer_certificate,
            self.interceptors,
            answerer_addr,
            now,
        )?;

        let mut tracks = Vec::with_capacity(self.tracks.len());
        for (index, kind) in self.tracks.into_iter().enumerate() {
            let ssrc = FIRST_SSRC + index as u32;
            let codec = kind.codec();
            let track = MediaStreamTrack::new(
                format!("rtc-bench-stream-{index}"),
                format!("rtc-bench-track-{index}"),
                format!("{}-{index}", kind.label()),
                kind.codec_kind(),
                vec![RTCRtpEncodingParameters {
                    rtp_coding_parameters: RTCRtpCodingParameters {
                        ssrc: Some(ssrc),
                        ..Default::default()
                    },
                    codec: codec.rtp_codec,
                    ..Default::default()
                }],
            );
            let sender_id = offerer.add_track(track)?;
            tracks.push(LocalTrack {
                sender_id,
                kind,
                ssrc,
                payload_type: codec.payload_type,
                sequence_number: 0,
                timestamp: 0,
                payload: fixtures::payload(kind.payload_len()),
            });
        }

        let data_channel = match self.data_channel {
            Some(init) => Some(offerer.create_data_channel("rtc-bench", Some(init))?.id()),
            None => None,
        };

        Ok(PeerPair {
            offerer: Peer::new(offerer, offerer_addr, answerer_addr),
            answerer: Peer::new(answerer, answerer_addr, offerer_addr),
            now,
            wire: WireStats::default(),
            tracks,
            next_track: 0,
            data_channel,
        })
    }

    /// [`build`](Self::build), negotiate, and drive until connected — and, if a data channel was
    /// requested, until it is open on both sides.
    ///
    /// # Errors
    ///
    /// If building or negotiating fails, or the connection fails or stalls.
    pub fn connect(self) -> Result<PeerPair> {
        let mut pair = self.build()?;
        pair.negotiate()?;
        pair.connect()?;
        Ok(pair)
    }
}

fn build_peer(
    provider: &Arc<dyn RTCCryptoProvider>,
    certificate: Option<RTCCertificate>,
    interceptors: Interceptors,
    addr: SocketAddr,
    now: Instant,
) -> Result<RTCPeerConnection> {
    // Both kinds are registered on both sides regardless of which tracks exist, so every pair
    // negotiates from the same codec set. Codecs must be registered before the interceptors,
    // which attach their RTCP feedback to the registered video codecs.
    let mut media_engine = MediaEngine::default();
    for kind in [MediaKind::Audio, MediaKind::Video] {
        media_engine.register_codec(kind.codec(), kind.codec_kind())?;
    }

    let mut builder = RTCPeerConnectionBuilder::new();
    if interceptors == Interceptors::Default {
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
        builder = builder.with_interceptor_registry(registry);
    }

    let mut configuration = RTCConfigurationBuilder::new();
    if let Some(certificate) = certificate {
        configuration = configuration.with_certificates(vec![certificate]);
    }

    let mut pc = builder
        .with_configuration(configuration.build())
        .with_media_engine(media_engine)
        .with_setting_engine(
            SettingEngineBuilder::new()
                .with_crypto_provider(Arc::clone(provider))
                .build(),
        )
        .build(now)?;

    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()?;
    pc.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;

    Ok(pc)
}

/// Two peer connections, an offerer and an answerer, joined by a lossless zero-latency wire.
///
/// Nothing happens on its own. [`Self::pump`] moves datagrams and fires due timers once;
/// [`Self::flush`] pumps until both sides go quiet; [`Self::advance`] moves the virtual clock.
/// The higher-level drivers — [`Self::connect`], [`Self::transfer`] — combine those and advance
/// the clock to the next deadline whenever the peers are idle.
///
/// Every `poll_read` result is drained and counted into [`Peer::received`] as part of pumping,
/// so the application side never applies back-pressure. That is the right default for measuring
/// throughput; a benchmark about back-pressure would need its own driver.
pub struct PeerPair {
    /// The side that created the offer, the data channel and the tracks.
    pub offerer: Peer,
    /// The side that answered.
    pub answerer: Peer,
    now: Instant,
    wire: WireStats,
    tracks: Vec<LocalTrack>,
    next_track: usize,
    data_channel: Option<RTCDataChannelId>,
}

impl PeerPair {
    /// Starts configuring a pair whose peers both use `provider`.
    pub fn builder(provider: Arc<dyn RTCCryptoProvider>) -> PairBuilder {
        PairBuilder {
            provider,
            certificates: None,
            interceptors: Interceptors::None,
            tracks: Vec::new(),
            data_channel: None,
        }
    }

    /// The virtual instant both peers are currently being driven at.
    pub fn now(&self) -> Instant {
        self.now
    }

    /// Moves the virtual clock forward. Due timers fire on the next [`Self::pump`].
    pub fn advance(&mut self, by: Duration) {
        self.now += by;
    }

    /// Traffic on the wire so far.
    pub fn wire(&self) -> WireStats {
        self.wire
    }

    /// The offerer's tracks, in the order they were added.
    pub fn tracks(&self) -> &[LocalTrack] {
        &self.tracks
    }

    /// Offer/answer between the two peers. See [`negotiate`].
    ///
    /// # Errors
    ///
    /// Whatever the first failing negotiation step returns.
    pub fn negotiate(&mut self) -> Result<()> {
        negotiate(&mut self.offerer.pc, &mut self.answerer.pc, self.now)?;
        self.resolve_payload_types();
        Ok(())
    }

    /// Drives until both sides are connected, and until the data channel — if any — is open on
    /// both.
    ///
    /// # Errors
    ///
    /// If either side fails, or the connection stalls.
    pub fn connect(&mut self) -> Result<()> {
        let wants_channel = self.data_channel.is_some();
        self.drive_until("connected", |pair| {
            pair.offerer.connected
                && pair.answerer.connected
                && (!wants_channel
                    || (!pair.offerer.open_channels.is_empty()
                        && !pair.answerer.open_channels.is_empty()))
        })
    }

    /// One round: move every pending datagram in both directions, then let each side process
    /// its inbound queue, fire a due timer, and drain events and reads.
    ///
    /// Returns whether any datagram, event or read was produced.
    ///
    /// # Errors
    ///
    /// Whatever a peer connection returns from `handle_read` or `handle_timeout`. On a lossless
    /// in-memory wire neither should fail, so an error here is surfaced rather than skipped.
    pub fn pump(&mut self) -> Result<bool> {
        let mut worked = transmit(
            &mut self.offerer,
            &mut self.answerer,
            &mut self.wire.to_answerer,
        );
        worked |= transmit(
            &mut self.answerer,
            &mut self.offerer,
            &mut self.wire.to_offerer,
        );
        worked |= self.offerer.step(self.now)?;
        worked |= self.answerer.step(self.now)?;
        Ok(worked)
    }

    /// Pumps until a round produces nothing, without moving the clock.
    ///
    /// # Errors
    ///
    /// If pumping fails, or the peers never go quiet.
    pub fn flush(&mut self) -> Result<()> {
        for _ in 0..FLUSH_ROUND_LIMIT {
            if !self.pump()? {
                return Ok(());
            }
        }
        Err(Error::Other(format!(
            "peers still exchanging traffic after {FLUSH_ROUND_LIMIT} rounds"
        )))
    }

    /// Pumps until `done` holds, jumping the clock to the next deadline whenever both sides are
    /// idle.
    ///
    /// # Errors
    ///
    /// If pumping fails, either side reaches `failed`, or `done` does not hold within the
    /// virtual-time budget.
    pub fn drive_until(&mut self, what: &str, mut done: impl FnMut(&Self) -> bool) -> Result<()> {
        let deadline = self.now + VIRTUAL_TIME_BUDGET;
        loop {
            let worked = self.pump()?;
            if done(self) {
                return Ok(());
            }
            if self.offerer.failed || self.answerer.failed {
                return Err(Error::Other(format!(
                    "peer connection failed before {what}"
                )));
            }
            if !worked {
                self.advance_to_next_deadline();
                if self.now > deadline {
                    return Err(self.stalled(what));
                }
            }
        }
    }

    /// Queues RTP on offerer track `index` and charges the `write_rtp` call to the offerer.
    ///
    /// Sequence number and timestamp advance per call, so the receiver sees a well-formed stream
    /// and SRTP replay protection never trips. Nothing is transmitted until the next pump.
    ///
    /// # Errors
    ///
    /// Whatever `write_rtp` returns.
    ///
    /// # Panics
    ///
    /// If there is no track `index`.
    pub fn send_rtp(&mut self, index: usize) -> Result<()> {
        let now = self.now;
        let track = &mut self.tracks[index];
        let packet = rtp::packet::Packet {
            header: rtp::header::Header {
                version: 2,
                payload_type: track.payload_type,
                sequence_number: track.sequence_number,
                timestamp: track.timestamp,
                ssrc: track.ssrc,
                ..Default::default()
            },
            payload: track.payload.clone(),
        };
        track.sequence_number = track.sequence_number.wrapping_add(1);
        track.timestamp = track.timestamp.wrapping_add(track.kind.timestamp_step());
        let sender_id = track.sender_id;

        self.offerer.timed(|pc| {
            pc.rtp_sender(sender_id)
                .ok_or(Error::ErrRTPSenderNotExisted)?
                .write_rtp(now, packet)
        })
    }

    /// Sends `packets` RTP packets round-robin across the offerer's tracks, pumping after every
    /// `burst`, and checks that the answerer's application received every one.
    ///
    /// Virtual time advances by a track's packet interval divided by the number of tracks, so each
    /// track keeps its own real-world rate however many there are. Round-robin position carries
    /// over between calls.
    ///
    /// # Errors
    ///
    /// If a send or pump fails, or fewer packets arrived than were sent. The wire is lossless, so
    /// a shortfall means the path under measurement dropped them — and a timing of that path
    /// would be a timing of the wrong thing.
    ///
    /// # Panics
    ///
    /// If the pair has no tracks, or `burst` is zero.
    pub fn stream_rtp(&mut self, packets: u64, burst: u64) -> Result<()> {
        assert!(
            !self.tracks.is_empty(),
            "stream_rtp needs at least one track"
        );
        assert!(burst > 0, "burst must be at least one packet");
        let before = self.answerer.received.rtp_packets;
        let tracks = self.tracks.len() as u32;

        for sent in 1..=packets {
            let index = self.next_track;
            self.next_track = (index + 1) % self.tracks.len();
            let interval = self.tracks[index].kind.packet_interval() / tracks;
            self.send_rtp(index)?;
            self.advance(interval);
            if sent % burst == 0 || sent == packets {
                self.flush()?;
            }
        }

        let delivered = self.answerer.received.rtp_packets - before;
        if delivered != packets {
            return Err(Error::Other(format!(
                "sent {packets} RTP packets over a lossless wire, but the answerer's application \
                 received {delivered}"
            )));
        }
        Ok(())
    }

    /// Sends every message over the offerer's data channel and drives until the answerer's
    /// application has read all of it.
    ///
    /// Queues while fewer than 1 MiB are unacknowledged, then pumps to let the wire drain. When
    /// neither side has anything to do — SCTP holding a delayed SACK, say — the clock jumps to
    /// the next deadline.
    ///
    /// # Errors
    ///
    /// If the pair has no open data channel, a send or pump fails, or delivery stalls.
    pub fn transfer(&mut self, messages: impl IntoIterator<Item = BytesMut>) -> Result<()> {
        let channel = self
            .data_channel
            .filter(|_| !self.offerer.open_channels.is_empty())
            .ok_or_else(|| Error::Other("no open data channel to transfer over".to_owned()))?;

        let mut messages = messages.into_iter().peekable();
        let mut expected = self.answerer.received.data_channel_bytes;
        let deadline = self.now + VIRTUAL_TIME_BUDGET;

        loop {
            let mut sent = false;
            while messages.peek().is_some() {
                let now = self.now;
                let queued = self.offerer.timed(|pc| -> Result<bool> {
                    let mut dc = pc
                        .data_channel(channel)
                        .ok_or(Error::ErrDataChannelClosed)?;
                    if dc.outstanding_bytes() >= SEND_BUFFER_LIMIT {
                        return Ok(false);
                    }
                    let message = messages.next().expect("peeked");
                    let len = message.len() as u64;
                    dc.send(now, message)?;
                    expected += len;
                    Ok(true)
                })?;
                if !queued {
                    break;
                }
                sent = true;
            }

            let worked = self.pump()?;
            if messages.peek().is_none() && self.answerer.received.data_channel_bytes >= expected {
                return Ok(());
            }
            if !(worked || sent) {
                self.advance_to_next_deadline();
                if self.now > deadline {
                    return Err(self.stalled("data-channel transfer complete"));
                }
            }
        }
    }

    /// Sets each track's payload type to what negotiation settled on for its codec.
    fn resolve_payload_types(&mut self) {
        for track in &mut self.tracks {
            let Some(mut sender) = self.offerer.pc.rtp_sender(track.sender_id) else {
                continue;
            };
            let mime_type = track.kind.codec().rtp_codec.mime_type;
            if let Some(codec) = sender
                .get_parameters()
                .rtp_parameters
                .codecs
                .iter()
                .find(|codec| codec.rtp_codec.mime_type.eq_ignore_ascii_case(&mime_type))
            {
                track.payload_type = codec.payload_type;
            }
        }
    }

    /// Jumps to the earlier of the two peers' deadlines, or 1 ms on if neither is ahead of now.
    fn advance_to_next_deadline(&mut self) {
        let next = [
            self.offerer.pc.poll_timeout(),
            self.answerer.pc.poll_timeout(),
        ]
        .into_iter()
        .flatten()
        .filter(|deadline| *deadline > self.now)
        .min();
        self.now = next.unwrap_or(self.now + Duration::from_millis(1));
    }

    fn stalled(&self, what: &str) -> Error {
        Error::Other(format!(
            "stalled: {what} not reached within {VIRTUAL_TIME_BUDGET:?} of virtual time \
             (offerer connected={}, answerer connected={}, wire={:?})",
            self.offerer.connected, self.answerer.connected, self.wire,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers;

    fn pair_builder() -> PairBuilder {
        let (_, provider) = providers().into_iter().next().expect("a provider");
        let certificates = (
            fixtures::certificate(provider.as_ref()).unwrap(),
            fixtures::certificate(provider.as_ref()).unwrap(),
        );
        PeerPair::builder(provider).certificates(certificates.0, certificates.1)
    }

    /// The harness must deliver what the benchmarks think it delivers. A driver that silently
    /// drops traffic would still produce timings — of the wrong thing.
    #[test]
    fn data_channel_transfer_delivers_every_byte() {
        let mut pair = pair_builder()
            .data_channel(RTCDataChannelInit {
                ordered: true,
                ..Default::default()
            })
            .connect()
            .unwrap();

        let messages: Vec<BytesMut> = (0..64)
            .map(|_| BytesMut::from(&fixtures::payload(4096)[..]))
            .collect();
        pair.transfer(messages).unwrap();

        let received = pair.answerer.received();
        assert_eq!(received.data_channel_messages, 64);
        assert_eq!(received.data_channel_bytes, 64 * 4096);
    }

    #[test]
    fn rtp_reaches_the_receiving_application() {
        for interceptors in [Interceptors::None, Interceptors::Default] {
            let mut pair = pair_builder()
                .interceptors(interceptors)
                .track(MediaKind::Video)
                .connect()
                .unwrap();

            pair.stream_rtp(50, 16).unwrap();

            let received = pair.answerer.received();
            assert_eq!(received.rtp_packets, 50, "{interceptors:?}");
            assert_eq!(received.rtp_payload_bytes, 50 * 1200, "{interceptors:?}");
            assert!(pair.offerer.busy() > Duration::ZERO);
            assert!(pair.answerer.busy() > Duration::ZERO);
        }
    }

    /// Every track must open and carry its share, or a many-track benchmark would quietly be a
    /// one-track benchmark.
    #[test]
    fn rtp_flows_on_every_track() {
        let mut pair = (0..4)
            .fold(pair_builder(), |builder, _| builder.track(MediaKind::Video))
            .track(MediaKind::Audio)
            .interceptors(Interceptors::Default)
            .connect()
            .unwrap();

        pair.stream_rtp(100, 16).unwrap();

        assert_eq!(pair.answerer.tracks_opened(), 5);
        assert_eq!(pair.answerer.received().rtp_packets, 100);
        assert_eq!(
            pair.answerer.received().rtp_payload_bytes,
            80 * 1200 + 20 * 160
        );
    }
}
