//! Interceptor Registry - Configuration helpers for RTP/RTCP interceptor chains.
//!
//! This module provides convenience functions for configuring common interceptor
//! combinations used in WebRTC applications. Interceptors process RTP/RTCP packets
//! as they flow through the media pipeline, enabling features like:
//!
//! - **NACK** - Negative acknowledgement for packet loss recovery (RFC 4585)
//! - **RTCP Reports** - Sender/Receiver reports for quality monitoring (RFC 3550)
//! - **TWCC** - Transport-wide congestion control for bandwidth estimation
//! - **Simulcast** - Multi-resolution video streaming support
//!
//! # Interceptor Chain Architecture
//!
//! A chain is a flat list of interceptors ordered by **distance from the wire**: the first added
//! is closest to the network, the last closest to the application. Direction is a property of the
//! walk rather than of the list:
//!
//! ```text
//! read   (network → application)   forward:  first → … → last
//! write  (application → network)   reverse:  last  → … → first
//! ```
//!
//! One list serves both directions, so "closest to the wire" means one thing rather than opposite
//! things per direction.
//!
//! [`register_default_interceptors`] composes this chain, listed wire-to-application:
//!
//! ```text
//!   wire-most   [NACK Responder]    buffers sent RTP, retransmits on NACK
//!               [NACK Generator]    detects gaps in inbound RTP, emits NACK
//!               [TWCC Receiver]     records arrivals, emits TransportLayerCC
//!               [Receiver Report]   emits RR from inbound RTP statistics
//!    app-most   [Sender Report]     emits SR, filters hop-by-hop RTCP
//!                     ↓
//!               [Noop]              ends the inbound RTCP path
//! ```
//!
//! The NACK responder is wire-most because its retransmissions must still pass everything between
//! it and the network; the generator is above it because loss has to be detected from arrivals.
//! The arrival recorders come before the report generators, and before anything that delays or
//! re-stamps a packet.
//!
//! When adding an interceptor that **delays** a packet (jitter buffer, pacer) or **generates**
//! one (FEC repair, a recovered packet), its position stops being a preference and becomes a
//! correctness property. The rules that govern it are documented on
//! [`Registry`](crate::interceptor::Registry) and on the interceptor trait itself.
//!
//! # Quick Start
//!
//! For most applications, use [`register_default_interceptors`] to enable
//! standard WebRTC functionality:
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let builder = RegistryBuilder::new();
//!
//! // Register NACK, RTCP reports, simulcast headers, and TWCC receiver.
//! // Note this takes `&mut media_engine`: it registers the RTCP feedback types and
//! // header extensions the interceptors need, so pass that same engine to the builder.
//! let registry = register_default_interceptors(builder, &mut media_engine)?.build();
//!
//! let pc = RTCPeerConnectionBuilder::new()
//!     .with_media_engine(media_engine)
//!     .with_interceptor_registry(registry)
//!     .build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Custom Configuration
//!
//! For fine-grained control, configure individual interceptors:
//!
//! ```no_run
//! # use std::time::Instant;
//! use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::interceptor_registry::{configure_nack, configure_twcc};
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let builder = RegistryBuilder::new();
//!
//! // Only enable NACK (no TWCC, no reports)
//! let builder = configure_nack(builder, &mut media_engine);
//!
//! // Or enable full TWCC for bandwidth estimation
//! let builder = configure_twcc(builder, &mut media_engine)?;
//!
//! // `build` sorts by slot, so the order the helpers ran in does not matter.
//! let registry = builder.build();
//!
//! let pc = RTCPeerConnectionBuilder::new()
//!     .with_media_engine(media_engine)
//!     .with_interceptor_registry(registry)
//!     .build(Instant::now())?;
//! # Ok(())
//! # }
//! ```
//!
//! # Available Configurations
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`register_default_interceptors`] | Standard WebRTC setup (NACK + Reports + TWCC Receiver) |
//! | [`configure_nack`] | NACK generator and responder for loss recovery |
//! | [`configure_rtcp_reports`] | Sender and Receiver Reports |
//! | [`configure_twcc`] | Full TWCC (sender + receiver) |
//! | [`configure_twcc_sender_only`] | TWCC sender only (remote generates feedback) |
//! | [`configure_twcc_receiver_only`] | TWCC receiver only (generates feedback for remote) |
//! | [`configure_simulcast_extension_headers`] | RTP extensions for simulcast |
//!
//! # References
//!
//! - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - RTP/AVPF (NACK)
//! - [RFC 3550](https://datatracker.ietf.org/doc/html/rfc3550) - RTP (SR/RR)
//! - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01) - TWCC

use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::rtp_sender::rtcp_parameters::{
    TYPE_RTCP_FB_NACK, TYPE_RTCP_FB_TRANSPORT_CC,
};
use crate::rtp_transceiver::rtp_sender::{
    RTCPFeedback, RTCRtpCodec, RTCRtpHeaderExtensionCapability, RTCRtpHeaderExtensionParameters,
    RtpCodecKind,
};
use crate::rtp_transceiver::{PayloadType, SSRC};
use interceptor::{
    BandwidthEstimator, BoxedInterceptor, CongestionControlBuilder, Interceptor,
    NackGeneratorBuilder, NackResponderBuilder, PacerBuilder, ReceiverReportBuilder, Registry,
    SenderReportBuilder, TwccReceiverBuilder, TwccSenderBuilder,
};
use shared::error::Result;

/// Where an interceptor belongs in the chain, measured by **distance from the wire**.
///
/// This is the chain contract's ordering table expressed as data, so that one place decides it and
/// a test can check a builder against it. The doc comments carry that table's indices; the gaps are
/// slots nothing fills yet.
///
/// Read walks the list forwards and write walks it in reverse, so a smaller slot is closer to the
/// network in both directions.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[non_exhaustive]
#[repr(usize)]
pub enum InterceptorSlot {
    /// Congestion control: send history and feedback ingest.
    ///
    /// The only position that sees every byte that leaves, because nothing exits the chain except
    /// through the interceptors ahead of it. Filled by P7; named here so an estimator of your own
    /// has a landmark.
    CongestionControl = 100,
    /// `TwccSenderInterceptor` — assigns the transport-wide sequence number the send history keys on.
    TwccSender = 200,
    /// `PacerInterceptor` — gates departures. Everything that generates a packet sits above it, so
    /// retransmissions, FEC repair and generated RTCP are all metered.
    Pacer = 300,
    /// `NackResponderInterceptor` — buffers sent RTP; its retransmissions still reach 300, 200, 100.
    NackResponder = 400,
    /// `FlexFec03SendInterceptor` — its repair packets still reach everything below.
    FecEncoder = 500,
    /// `FlexFec03ReceiveInterceptor` — recovery before anything inspects sequence numbers.
    FecDecoder = 600,
    /// `NackGeneratorInterceptor` — loss detected from arrivals, not from released packets.
    NackGenerator = 700,
    /// `TwccReceiverInterceptor` — records arrivals and reports them to the remote sender's
    /// congestion controller. An arrival recorder, so it precedes the jitter buffer.
    TwccReceiver = 800,
    /// `Rfc8888Interceptor` — the same job as [`InterceptorSlot::TwccReceiver`] in a different format, and
    /// registering both double-counts, so a chain carries one or the other.
    Rfc8888 = 900,
    /// `ReceiverReportInterceptor` — RFC 3550 reception quality, not congestion-control feedback.
    /// Still an arrival recorder, so it precedes the jitter buffer.
    ReceiverReport = 1000,
    /// `SenderReportInterceptor` — a generator with no read-side ordering constraint.
    SenderReport = 1100,
    /// `IntervalPliInterceptor` — a generator with no read-side ordering constraint.
    IntervalPli = 1200,
    /// `JitterBufferInterceptor` — delays and re-stamps, so every arrival recorder precedes it.
    ///
    /// A recorder below this would report local playout instants to the remote as arrival times,
    /// and the remote's congestion controller would read this endpoint's buffering depth as network
    /// delay variation.
    JitterBuffer = 1300,
}

impl From<InterceptorSlot> for usize {
    fn from(slot: InterceptorSlot) -> Self {
        slot as usize
    }
}

/// Collects interceptors with the slot each belongs in, then assembles a [`Registry`].
///
/// # Why this exists rather than adding to a [`Registry`] directly
///
/// `Registry` is positional: the first interceptor added is closest to the wire. That is the right
/// model for the chain itself, but it makes *composition* hazardous, because a helper that appends
/// can only ever occupy contiguous positions. The helpers here do not:
///
/// | Helper | Slots |
/// |---|---|
/// | [`configure_nack`] | [`InterceptorSlot::NackResponder`], [`InterceptorSlot::NackGenerator`] |
/// | [`configure_twcc`] | **[`InterceptorSlot::TwccSender`]**, [`InterceptorSlot::TwccReceiver`] |
/// | [`configure_rtcp_reports`] | [`InterceptorSlot::ReceiverReport`], [`InterceptorSlot::SenderReport`] |
///
/// TWCC spans NACK, so with append-only helpers **no call order produces the documented ordering** —
/// `nack` then `twcc` gives responder, generator, sender, receiver, and the reverse is no better.
/// Neither reports an error. A chain that records a packet in the send history *before* the TWCC
/// sender has numbered it yields a bandwidth estimate computed from packets the estimator cannot
/// match against feedback.
///
/// Here every interceptor carries the slot it belongs in, and [`build`](Self::build) sorts. Call
/// order stops being load-bearing, and the ordering lives in one place — the [`InterceptorSlot`] values.
///
/// Calling a helper twice adds its interceptors twice, exactly as `Registry::with` always did.
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::{
///     RegistryBuilder, configure_nack, configure_twcc,
/// };
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
///
/// // Either order; the chain is the same.
/// let builder = configure_nack(RegistryBuilder::new(), &mut media_engine);
/// let builder = configure_twcc(builder, &mut media_engine)?;
///
/// let registry = builder.build();
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct RegistryBuilder {
    /// Each interceptor with the position it asked for, in the order they were added.
    slots: Vec<(usize, BoxedInterceptor)>,
    rtcp_readable: bool,
}

impl RegistryBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an interceptor at `position`.
    ///
    /// [`InterceptorSlot`] names the positions this crate knows about, spaced a hundred apart so anything else
    /// fits **between** them — pass a `Slot` to sit at one, or a bare number to sit in a gap:
    ///
    /// ```text
    /// Slot::TwccSender (200) ── yours at 250 ── Slot::Pacer (300)
    /// ```
    ///
    /// At the same position, interceptors keep the order they were added in, so an application's
    /// own sits application-ward of a built-in it shares a slot with.
    ///
    /// ```
    /// # use rtc::peer_connection::configuration::interceptor_registry::{RegistryBuilder, InterceptorSlot};
    /// # fn example(mine: impl rtc::interceptor::Interceptor + 'static) {
    /// let registry = RegistryBuilder::new().at(InterceptorSlot::Pacer, mine).build();
    /// # }
    /// ```
    pub fn at(
        mut self,
        position: impl Into<usize>,
        interceptor: impl Interceptor + 'static,
    ) -> Self {
        self.slots.push((position.into(), Box::new(interceptor)));
        self
    }

    /// [`at`](Self::at) for an interceptor that is already boxed, so it is not boxed twice.
    pub fn at_boxed(mut self, position: impl Into<usize>, interceptor: BoxedInterceptor) -> Self {
        self.slots.push((position.into(), interceptor));
        self
    }

    /// Make inbound RTCP readable by the application — it arrives from
    /// [`poll_read`](sansio::Protocol::poll_read) like media does — as well as acted on by the
    /// interceptors.
    ///
    /// Off by default. RTCP is control traffic the interceptors act on: a receiver report feeds
    /// the sender statistics, a NACK is answered by the responder, transport-wide feedback drives
    /// the bandwidth estimate. An application that did not ask for it would find a stream of
    /// packets it cannot use interleaved with its media. Turn it on for an SFU relaying feedback,
    /// or a tool inspecting a session.
    ///
    /// Outbound RTCP is unaffected; this is only about what arrives.
    ///
    /// It has to be asked for here rather than arranged by an interceptor of your own. One that
    /// captured an RTCP packet and re-emitted it from `poll_read` would put the copy back on the
    /// belt *behind* itself, where [`NoopInterceptor`] is still ahead of it and drops it — the
    /// original and the copy both. The nested chain allowed that trick because a local `poll_read`
    /// queue was terminal and bypassed everything below it, which is precisely the bypass this
    /// design removes.
    pub fn with_rtcp_readable(mut self) -> Self {
        self.rtcp_readable = true;
        self
    }

    /// Assemble the [`Registry`], wire-to-application.
    ///
    /// The sort is **stable**, so interceptors sharing a position keep the order they were added
    /// in. Flags that are not positional — [`Registry::with_rtcp_readable`] — apply to the result:
    ///
    /// ```
    /// # use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
    /// let registry = RegistryBuilder::new().with_rtcp_readable().build();
    /// ```
    ///
    /// An interceptor added with [`Registry::with`] after this lands application-most, which is
    /// where something that merely observes the chain wants to be. One whose depth matters should
    /// use [`at`](Self::at) instead.
    pub fn build(mut self) -> Registry {
        self.slots.sort_by_key(|(position, _)| *position);

        let mut registry = Registry::new();
        for (_position, interceptor) in self.slots {
            registry = registry.with_boxed(interceptor);
        }
        if self.rtcp_readable {
            registry = registry.with_rtcp_readable();
        }
        registry
    }
}

/// Registers a standard set of interceptors for typical WebRTC usage.
///
/// This function configures the following interceptors:
/// - **NACK**: Detects packet loss and requests retransmissions (video only)
/// - **RTCP Reports**: Generates Sender Reports (SR) and Receiver Reports (RR)
/// - **Simulcast Headers**: Enables RTP extensions for multi-resolution streaming
/// - **TWCC Receiver**: Generates transport-wide congestion control feedback
///
/// # Arguments
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register RTCP feedback and header extensions
///
/// # Returns
///
/// A new registry with the configured interceptor chain.
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
/// use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let builder = RegistryBuilder::new();
/// let builder = register_default_interceptors(builder, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// If you need to customize which interceptors are loaded, copy the code from
/// this function and remove or modify the unwanted interceptors.
pub fn register_default_interceptors(
    builder: RegistryBuilder,
    media_engine: &mut MediaEngine,
) -> Result<RegistryBuilder> {
    // Order is not decided here — `RegistryBuilder::planned` decides it. These may be called in
    // any sequence.
    let builder = configure_nack(builder, media_engine);

    configure_simulcast_extension_headers(media_engine)?;

    let builder = configure_twcc_receiver_only(builder, media_engine)?;

    let builder = configure_rtcp_reports(builder);

    Ok(builder)
}

/// Configures NACK (Negative Acknowledgement) interceptors for packet loss recovery.
///
/// This function registers the following:
/// - **NACK Generator**: Monitors incoming RTP packets and generates NACK requests for missing packets
/// - **NACK Responder**: Buffers outgoing RTP packets and retransmits them when NACK requests arrive
/// - **RTCP Feedback**: Registers "nack" and "nack pli" feedback types for video codecs
///
/// # How NACK Works
///
/// 1. Receiver detects missing packets by tracking sequence numbers
/// 2. Receiver sends RTCP NACK listing missing sequence numbers
/// 3. Sender retransmits the requested packets from its buffer
///
/// # Arguments
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register NACK feedback capability
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_nack;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let builder = RegistryBuilder::new();
/// let builder = configure_nack(builder, &mut media_engine);
/// ```
///
/// # References
///
/// - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - Extended RTP Profile for RTCP-Based Feedback
pub fn configure_nack(builder: RegistryBuilder, media_engine: &mut MediaEngine) -> RegistryBuilder {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_NACK.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_NACK.to_owned(),
            parameter: "pli".to_owned(),
        },
        RtpCodecKind::Video,
    );

    builder
        .at(
            InterceptorSlot::NackResponder,
            NackResponderBuilder::new().build(),
        )
        .at(
            InterceptorSlot::NackGenerator,
            NackGeneratorBuilder::new().build(),
        )
}

/// Configures RTCP Sender and Receiver Report interceptors.
///
/// This function registers:
/// - **Receiver Report Interceptor**: Generates RR packets with reception statistics
/// - **Sender Report Interceptor**: Generates SR packets with transmission statistics
///
/// # Sender Reports (SR)
///
/// Sent by active senders, containing:
/// - NTP timestamp (wall-clock time for synchronization)
/// - RTP timestamp (media time)
/// - Packet and octet counts
///
/// # Receiver Reports (RR)
///
/// Sent by receivers, containing per-source:
/// - Fraction of packets lost since last report
/// - Cumulative packets lost
/// - Extended highest sequence number received
/// - Interarrival jitter estimate
/// - Last SR timestamp and delay since last SR
///
/// # Arguments
///
/// * `registry` - The interceptor registry to configure
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_rtcp_reports;
///
/// let builder = RegistryBuilder::new();
/// let builder = configure_rtcp_reports(builder);
/// ```
///
/// # References
///
/// - [RFC 3550 Section 6](https://datatracker.ietf.org/doc/html/rfc3550#section-6) - RTCP Sender and Receiver Reports
pub fn configure_rtcp_reports(builder: RegistryBuilder) -> RegistryBuilder {
    builder
        .at(
            InterceptorSlot::ReceiverReport,
            ReceiverReportBuilder::new().build(),
        )
        .at(
            InterceptorSlot::SenderReport,
            SenderReportBuilder::new().build(),
        )
}

/// Registers RTP header extensions required for simulcast streaming.
///
/// Simulcast allows sending multiple resolutions/qualities of the same video
/// simultaneously. This function registers the following header extensions:
///
/// - **SDES MID** (`urn:ietf:params:rtp-hdrext:sdes:mid`): Media identification
/// - **SDES RtpStreamId** (`urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id`): Stream identification
/// - **SDES RepairedRtpStreamId** (`urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id`): Repair stream identification
///
/// # Arguments
///
/// * `media_engine` - The media engine to register header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::configure_simulcast_extension_headers;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// configure_simulcast_extension_headers(&mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [RFC 8852](https://datatracker.ietf.org/doc/html/rfc8852) - RTP Stream Identifier Source Description Extensions
pub fn configure_simulcast_extension_headers(media_engine: &mut MediaEngine) -> Result<()> {
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_MID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_RTP_STREAM_ID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: ::sdp::extmap::SDES_REPAIR_RTP_STREAM_ID_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    Ok(())
}

/// Configures full TWCC (Transport-Wide Congestion Control) for bandwidth estimation.
///
/// This function enables both sending and receiving TWCC feedback:
/// - **TWCC Sender**: Adds transport-wide sequence numbers to outgoing RTP packets
/// - **TWCC Receiver**: Generates TransportLayerCC RTCP feedback for incoming packets
///
/// # How TWCC Works
///
/// 1. Sender adds a transport-wide sequence number to each RTP packet
/// 2. Receiver records arrival time of each packet by sequence number
/// 3. Receiver periodically sends TransportLayerCC RTCP packets with timing info
/// 4. Sender uses feedback to estimate available bandwidth
///
/// # When to Use
///
/// Use full TWCC when you need bandwidth estimation in both directions,
/// such as in a two-way video call where both peers send media.
///
/// # Arguments
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let builder = RegistryBuilder::new();
/// let builder = configure_twcc(builder, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
pub fn configure_twcc(
    builder: RegistryBuilder,
    media_engine: &mut MediaEngine,
) -> Result<RegistryBuilder> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(builder
        .at(
            InterceptorSlot::TwccSender,
            TwccSenderBuilder::new().build(),
        )
        .at(
            InterceptorSlot::TwccReceiver,
            TwccReceiverBuilder::new().build(),
        ))
}

/// Configures TWCC sender only (the remote peer generates feedback).
///
/// This function enables only the TWCC sender interceptor, which adds
/// transport-wide sequence numbers to outgoing RTP packets. The remote
/// peer is expected to generate and send TransportLayerCC feedback.
///
/// # When to Use
///
/// Use sender-only TWCC when:
/// - You are sending media but not receiving (e.g., streaming/broadcasting)
/// - The remote peer handles feedback generation
/// - You want to minimize local processing overhead
///
/// # Arguments
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_sender_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let builder = RegistryBuilder::new();
/// let builder = configure_twcc_sender_only(builder, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_sender_only(
    builder: RegistryBuilder,
    media_engine: &mut MediaEngine,
) -> Result<RegistryBuilder> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Video,
    );

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            parameter: "".to_owned(),
        },
        RtpCodecKind::Audio,
    );

    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(builder.at(
        InterceptorSlot::TwccSender,
        TwccSenderBuilder::new().build(),
    ))
}

/// Configures TWCC receiver only (generates feedback for the remote sender).
///
/// This function enables only the TWCC receiver interceptor, which:
/// - Tracks arrival times of incoming RTP packets with TWCC sequence numbers
/// - Generates TransportLayerCC RTCP feedback packets periodically
/// - Sends feedback to the remote sender for bandwidth estimation
///
/// This is the default TWCC configuration used by [`register_default_interceptors`].
///
/// # When to Use
///
/// Use receiver-only TWCC when:
/// - You are receiving media but not sending (e.g., viewer in a broadcast)
/// - The remote peer adds TWCC sequence numbers and needs feedback
/// - You want to help the sender estimate available bandwidth
///
/// # Arguments
///
/// * `registry` - The interceptor registry to configure
/// * `media_engine` - The media engine to register feedback and header extensions
///
/// # Errors
///
/// Returns an error if header extension registration fails.
///
/// # Example
///
/// ```
/// use rtc::peer_connection::configuration::interceptor_registry::RegistryBuilder;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_receiver_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let builder = RegistryBuilder::new();
/// let builder = configure_twcc_receiver_only(builder, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_receiver_only(
    builder: RegistryBuilder,
    media_engine: &mut MediaEngine,
) -> Result<RegistryBuilder> {
    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Video,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Video,
        None,
    )?;

    media_engine.register_feedback(
        RTCPFeedback {
            typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
            ..Default::default()
        },
        RtpCodecKind::Audio,
    );
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
        },
        RtpCodecKind::Audio,
        None,
    )?;

    Ok(builder.at(
        InterceptorSlot::TwccReceiver,
        TwccReceiverBuilder::new().build(),
    ))
}

/// Which feedback format the remote should report arrivals with.
///
/// **One or the other, never both** (D7). Both resolve into the same `PacketReport`s and the
/// estimator cannot tell them apart, so a chain carrying both senders counts every packet twice and
/// the estimate is wrong by a factor of two in the direction that causes congestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CongestionFeedback {
    /// Transport-wide congestion control. The default: browsers support it.
    #[default]
    Twcc,
    /// RFC 8888 congestion control feedback. Carries ECN, which TWCC cannot.
    Rfc8888,
}

/// Configure send-side congestion control around `estimator`.
///
/// Places three interceptors, at the slots the chain contract reserves for them:
///
/// | Slot | Interceptor | Why there |
/// |---|---|---|
/// | [`InterceptorSlot::CongestionControl`] | send history and feedback ingest | the only position that sees every byte that leaves |
/// | [`InterceptorSlot::TwccSender`] | transport-wide sequence numbers | so the history keys on a number that already exists |
/// | [`InterceptorSlot::Pacer`] | paces departures | above the two, so `packet.now` is the release instant |
///
/// The order is declared, not implied by the order these are added, so this composes with
/// [`configure_nack`] and the rest in any sequence.
///
/// # Not a default (D6)
///
/// Congestion control implies pacing, pacing implies queueing delay, and that is not something an
/// application should acquire without asking. [`register_default_interceptors`] does not call this.
///
/// # Example
///
/// ```
/// use rtc::interceptor::Gcc;
/// use rtc::peer_connection::configuration::interceptor_registry::{
///     CongestionFeedback, RegistryBuilder, configure_congestion_control,
/// };
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let builder = configure_congestion_control(
///     RegistryBuilder::new(),
///     Gcc::default(),
///     CongestionFeedback::Twcc,
///     &mut media_engine,
/// )?;
/// let registry = builder.build();
/// # Ok(())
/// # }
/// ```
pub fn configure_congestion_control<E: BandwidthEstimator + 'static>(
    builder: RegistryBuilder,
    estimator: E,
    feedback: CongestionFeedback,
    media_engine: &mut MediaEngine,
) -> Result<RegistryBuilder> {
    // The remote needs to know how to report. RFC 8888 needs no header extension — it reports
    // against the RTP sequence number — so only TWCC registers one.
    if feedback == CongestionFeedback::Twcc {
        for kind in [RtpCodecKind::Video, RtpCodecKind::Audio] {
            media_engine.register_feedback(
                RTCPFeedback {
                    typ: TYPE_RTCP_FB_TRANSPORT_CC.to_owned(),
                    parameter: "".to_owned(),
                },
                kind,
            );
            media_engine.register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: sdp::extmap::TRANSPORT_CC_URI.to_owned(),
                },
                kind,
                None,
            )?;
        }
    }

    let builder = builder
        .at(
            InterceptorSlot::CongestionControl,
            CongestionControlBuilder::new(estimator).build(),
        )
        .at(InterceptorSlot::Pacer, PacerBuilder::new().build());

    // The sequence numbers the history keys on. RFC 8888 needs none.
    Ok(match feedback {
        CongestionFeedback::Twcc => builder.at(
            InterceptorSlot::TwccSender,
            TwccSenderBuilder::new().build(),
        ),
        CongestionFeedback::Rfc8888 => builder,
    })
}

/// Creates a [`StreamInfo`](interceptor::StreamInfo) from RTC types for interceptor binding.
///
/// This helper converts RTC codec and header extension information into the format
/// expected by the interceptor layer when binding local or remote streams.
#[allow(clippy::too_many_arguments)]
pub(crate) fn create_stream_info(
    ssrc: SSRC,
    ssrc_rtx: Option<SSRC>,
    ssrc_fec: Option<SSRC>,
    payload_type: PayloadType,
    payload_type_rtx: Option<PayloadType>,
    payload_type_fec: Option<PayloadType>,
    codec: &RTCRtpCodec,
    header_extensions: &[RTCRtpHeaderExtensionParameters],
) -> interceptor::StreamInfo {
    let rtp_header_extensions: Vec<interceptor::RTPHeaderExtension> = header_extensions
        .iter()
        .map(|h| interceptor::RTPHeaderExtension {
            id: h.id,
            uri: h.uri.clone(),
        })
        .collect();

    let feedbacks: Vec<_> = codec
        .rtcp_feedback
        .iter()
        .map(|f| interceptor::RTCPFeedback {
            typ: f.typ.clone(),
            parameter: f.parameter.clone(),
        })
        .collect();

    interceptor::StreamInfo {
        ssrc,
        ssrc_rtx,
        ssrc_fec,
        payload_type,
        payload_type_rtx,
        payload_type_fec,
        rtp_header_extensions,
        mime_type: codec.mime_type.clone(),
        clock_rate: codec.clock_rate,
        channels: codec.channels,
        sdp_fmtp_line: codec.sdp_fmtp_line.clone(),
        rtcp_feedback: feedbacks,
    }
}

#[cfg(test)]
mod slot_order_tests {
    use super::*;

    /// Positions of everything a builder holds, after `build`'s sort.
    fn positions(mut builder: RegistryBuilder) -> Vec<usize> {
        builder.slots.sort_by_key(|(position, _)| *position);
        builder
            .slots
            .iter()
            .map(|(position, _)| *position)
            .collect()
    }

    /// The hazard this type exists for: with append-only helpers, TWCC spans NACK and no call
    /// order produces the documented ordering. Here the two orders must be indistinguishable.
    #[test]
    fn helper_call_order_does_not_affect_the_chain() {
        let mut media_engine = MediaEngine::default();

        let nack_first = configure_twcc(
            configure_nack(RegistryBuilder::new(), &mut media_engine),
            &mut media_engine,
        )
        .expect("twcc");

        let mut media_engine = MediaEngine::default();
        let twcc_first = configure_nack(
            configure_twcc(RegistryBuilder::new(), &mut media_engine).expect("twcc"),
            &mut media_engine,
        );

        assert_eq!(positions(nack_first), positions(twcc_first));
    }

    /// Whatever a builder is asked for, it emits wire-to-application.
    #[test]
    fn the_default_chain_is_emitted_in_slot_order() {
        let mut media_engine = MediaEngine::default();
        let builder = register_default_interceptors(RegistryBuilder::new(), &mut media_engine)
            .expect("default interceptors");

        let positions = positions(builder);
        assert!(
            positions.windows(2).all(|pair| pair[0] <= pair[1]),
            "default chain is not wire-to-application: {positions:?}"
        );
        assert_eq!(
            vec![
                InterceptorSlot::NackResponder as usize,
                InterceptorSlot::NackGenerator as usize,
                InterceptorSlot::TwccReceiver as usize,
                InterceptorSlot::ReceiverReport as usize,
                InterceptorSlot::SenderReport as usize,
            ],
            positions
        );
    }

    /// The three slots congestion control occupies land wire-to-application, whatever order the
    /// helpers ran in. Getting this wrong means the send history records a packet *before* the
    /// TWCC sender has numbered it, and the estimator cannot match feedback to what it sent.
    #[test]
    fn congestion_control_occupies_its_three_slots_in_order() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        // Deliberately after another helper, to show the order does not matter.
        let builder = configure_nack(RegistryBuilder::new(), &mut media_engine);
        let builder = configure_congestion_control(
            builder,
            Gcc::default(),
            CongestionFeedback::Twcc,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![
                InterceptorSlot::CongestionControl as usize,
                InterceptorSlot::TwccSender as usize,
                InterceptorSlot::Pacer as usize,
                InterceptorSlot::NackResponder as usize,
                InterceptorSlot::NackGenerator as usize,
            ],
            positions(builder)
        );
    }

    /// **D7.** RFC 8888 reports against the RTP sequence number, so it needs no TWCC sender — and
    /// must not get one. Two senders would number every packet twice and the estimator, which
    /// cannot tell the formats apart, would count every packet twice with it.
    #[test]
    fn rfc8888_does_not_also_install_the_twcc_sender() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let builder = configure_congestion_control(
            RegistryBuilder::new(),
            Gcc::default(),
            CongestionFeedback::Rfc8888,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![
                InterceptorSlot::CongestionControl as usize,
                InterceptorSlot::Pacer as usize,
            ],
            positions(builder),
            "RFC 8888 needs no transport-wide sequence numbers"
        );
    }

    /// **D6.** Congestion control implies pacing, pacing implies queueing delay, and that is not
    /// something an application should acquire without asking.
    #[test]
    fn the_default_chain_has_no_congestion_control() {
        let mut media_engine = MediaEngine::default();
        let builder = register_default_interceptors(RegistryBuilder::new(), &mut media_engine)
            .expect("default interceptors");

        let slots = positions(builder);
        assert!(
            !slots.contains(&(InterceptorSlot::CongestionControl as usize)),
            "no estimator by default: {slots:?}"
        );
        assert!(
            !slots.contains(&(InterceptorSlot::Pacer as usize)),
            "and no pacer by default: {slots:?}"
        );
    }

    /// A bare number puts an interceptor between two named slots — the reason they are spaced.
    #[test]
    fn a_custom_interceptor_fits_between_named_slots() {
        let mut media_engine = MediaEngine::default();
        let builder = configure_twcc(RegistryBuilder::new(), &mut media_engine)
            .expect("twcc")
            .at(250usize, interceptor::NoopInterceptor::new(false));

        assert_eq!(
            vec![
                InterceptorSlot::TwccSender as usize,
                250,
                InterceptorSlot::TwccReceiver as usize
            ],
            positions(builder)
        );
    }

    /// Sharing a slot is allowed, and the sort is stable, so the one added later sits
    /// application-ward of the one added first.
    #[test]
    fn interceptors_sharing_a_slot_keep_the_order_they_were_added() {
        let builder = RegistryBuilder::new()
            .at(
                InterceptorSlot::Pacer,
                interceptor::NoopInterceptor::new(false),
            )
            .at(
                InterceptorSlot::Pacer,
                interceptor::NoopInterceptor::new(true),
            );

        assert_eq!(
            vec![
                InterceptorSlot::Pacer as usize,
                InterceptorSlot::Pacer as usize
            ],
            positions(builder)
        );
    }
}
