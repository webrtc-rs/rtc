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
//! use rtc::interceptor::Registry;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Register NACK, RTCP reports, simulcast headers, and TWCC receiver.
//! // Note this takes `&mut media_engine`: it registers the RTCP feedback types and
//! // header extensions the interceptors need, so pass that same engine to the registry.
//! let registry = register_default_interceptors(registry, &mut media_engine)?;
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
//! use rtc::interceptor::Registry;
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::interceptor_registry::{configure_nack, configure_twcc};
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Only enable NACK (no TWCC, no reports)
//! let registry = configure_nack(registry, &mut media_engine);
//!
//! // Or enable full TWCC for bandwidth estimation
//! let registry = configure_twcc(registry, &mut media_engine)?;
//!
//! // Handed over unbuilt: the peer connection builds the chain, and `build` composes by slot
//! // rather than by the order the helpers ran in.
//! let registry = registry;
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
    BandwidthEstimator, CongestionControlBuilder, NackGeneratorBuilder, NackResponderBuilder,
    PacerBuilder, ReceiverReportBuilder, SenderReportBuilder, TwccReceiverBuilder,
    TwccSenderBuilder,
};

/// The chain registry these helpers take and return, and the positions they place interceptors at.
///
/// Re-exported so the helpers and the type they operate on can be named from one path — every
/// example here reaches for both, and the definitions live in `rtc-interceptor` because the chain
/// does.
pub use interceptor::{Registry, Slot};
use shared::error::Result;

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
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # Customization
///
/// If you need to customize which interceptors are loaded, copy the code from
/// this function and remove or modify the unwanted interceptors.
pub fn register_default_interceptors(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
    // Order is not decided here — `Registry::build` decides it. These may be called in
    // any sequence.
    let registry = configure_nack(registry, media_engine);

    configure_simulcast_extension_headers(media_engine)?;

    let registry = configure_twcc_receiver_only(registry, media_engine)?;

    let registry = configure_rtcp_reports(registry);

    Ok(registry)
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
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_nack;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_nack(registry, &mut media_engine);
/// ```
///
/// # References
///
/// - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - Extended RTP Profile for RTCP-Based Feedback
pub fn configure_nack(registry: Registry, media_engine: &mut MediaEngine) -> Registry {
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

    registry
        .with(Slot::NackResponder, NackResponderBuilder::new().build())
        .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())
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
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_rtcp_reports;
///
/// let registry = Registry::new();
/// let registry = configure_rtcp_reports(registry);
/// ```
///
/// # References
///
/// - [RFC 3550 Section 6](https://datatracker.ietf.org/doc/html/rfc3550#section-6) - RTCP Sender and Receiver Reports
pub fn configure_rtcp_reports(registry: Registry) -> Registry {
    registry
        .with(Slot::ReceiverReport, ReceiverReportBuilder::new().build())
        .with(Slot::SenderReport, SenderReportBuilder::new().build())
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
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
///
/// # References
///
/// - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
pub fn configure_twcc(registry: Registry, media_engine: &mut MediaEngine) -> Result<Registry> {
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

    Ok(registry
        .with(Slot::TwccSender, TwccSenderBuilder::new().build())
        .with(Slot::TwccReceiver, TwccReceiverBuilder::new().build()))
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
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_sender_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_sender_only(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_sender_only(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
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

    Ok(registry.with(Slot::TwccSender, TwccSenderBuilder::new().build()))
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
/// use rtc::interceptor::Registry;
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_receiver_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_receiver_only(registry, &mut media_engine)?;
/// # Ok(())
/// # }
/// ```
pub fn configure_twcc_receiver_only(
    registry: Registry,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
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

    Ok(registry.with(Slot::TwccReceiver, TwccReceiverBuilder::new().build()))
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
/// | [`Slot::CongestionControl`] | send history and feedback ingest | the only position that sees every byte that leaves |
/// | [`Slot::TwccSender`] | transport-wide sequence numbers | so the history keys on a number that already exists |
/// | [`Slot::Pacer`] | paces departures | above the two, so `packet.now` is the release instant |
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
///     CongestionFeedback, Registry, configure_congestion_control,
/// };
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// let registry = configure_congestion_control(
///     Registry::new(),
///     Gcc::default(),
///     CongestionFeedback::Twcc,
///     &mut media_engine,
/// )?;
/// let registry = registry.build();
/// # Ok(())
/// # }
/// ```
pub fn configure_congestion_control<E: BandwidthEstimator + 'static>(
    registry: Registry,
    estimator: E,
    feedback: CongestionFeedback,
    media_engine: &mut MediaEngine,
) -> Result<Registry> {
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

    let registry = registry
        .with(
            Slot::CongestionControl,
            CongestionControlBuilder::new(estimator).build(),
        )
        .with(Slot::Pacer, PacerBuilder::new().build());

    // The sequence numbers the history keys on. RFC 8888 needs none.
    Ok(match feedback {
        CongestionFeedback::Twcc => {
            registry.with(Slot::TwccSender, TwccSenderBuilder::new().build())
        }
        CongestionFeedback::Rfc8888 => registry,
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

    /// Just the positions, for the tests that are about ordering rather than identity.
    fn slots(registry: &Registry) -> Vec<Slot> {
        registry.slots().into_iter().map(|(slot, _)| slot).collect()
    }

    /// The hazard this type exists for: with append-only helpers, TWCC spans NACK and no call
    /// order produces the documented ordering. Here the two orders must be indistinguishable.
    #[test]
    fn helper_call_order_does_not_affect_the_chain() {
        let mut media_engine = MediaEngine::default();

        let nack_first = configure_twcc(
            configure_nack(Registry::new(), &mut media_engine),
            &mut media_engine,
        )
        .expect("twcc");

        let mut media_engine = MediaEngine::default();
        let twcc_first = configure_nack(
            configure_twcc(Registry::new(), &mut media_engine).expect("twcc"),
            &mut media_engine,
        );

        assert_eq!(slots(&nack_first), slots(&twcc_first));
    }

    /// Whatever a registry is asked for, it emits wire-to-application.
    #[test]
    fn the_default_chain_is_emitted_in_slot_order() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let slots = slots(&registry);
        assert!(
            slots.windows(2).all(|pair| pair[0] <= pair[1]),
            "default chain is not wire-to-application: {slots:?}"
        );
        assert_eq!(
            vec![
                Slot::NackResponder,
                Slot::NackGenerator,
                Slot::TwccReceiver,
                Slot::ReceiverReport,
                Slot::SenderReport,
            ],
            slots
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
        let registry = configure_nack(Registry::new(), &mut media_engine);
        let registry = configure_congestion_control(
            registry,
            Gcc::default(),
            CongestionFeedback::Twcc,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![
                Slot::CongestionControl,
                Slot::TwccSender,
                Slot::Pacer,
                Slot::NackResponder,
                Slot::NackGenerator,
            ],
            slots(&registry)
        );
    }

    /// **D7.** RFC 8888 reports against the RTP sequence number, so it needs no TWCC sender — and
    /// must not get one. Two senders would number every packet twice and the estimator, which
    /// cannot tell the formats apart, would count every packet twice with it.
    #[test]
    fn rfc8888_does_not_also_install_the_twcc_sender() {
        use interceptor::Gcc;

        let mut media_engine = MediaEngine::default();
        let registry = configure_congestion_control(
            Registry::new(),
            Gcc::default(),
            CongestionFeedback::Rfc8888,
            &mut media_engine,
        )
        .expect("congestion control");

        assert_eq!(
            vec![Slot::CongestionControl, Slot::Pacer,],
            slots(&registry),
            "RFC 8888 needs no transport-wide sequence numbers"
        );
    }

    /// **D6.** Congestion control implies pacing, pacing implies queueing delay, and that is not
    /// something an application should acquire without asking.
    #[test]
    fn the_default_chain_has_no_congestion_control() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        let slots = slots(&registry);
        assert!(
            !slots.contains(&(Slot::CongestionControl)),
            "no estimator by default: {slots:?}"
        );
        assert!(
            !slots.contains(&(Slot::Pacer)),
            "and no pacer by default: {slots:?}"
        );
    }

    /// A bare number puts an interceptor between two named slots — the reason they are spaced.
    #[test]
    fn a_custom_interceptor_fits_between_named_slots() {
        let mut media_engine = MediaEngine::default();
        let registry = configure_twcc(Registry::new(), &mut media_engine)
            .expect("twcc")
            .with(Slot::from(2_500), interceptor::NoopInterceptor::new());

        assert_eq!(
            vec![Slot::TwccSender, Slot::from(2_500), Slot::TwccReceiver],
            slots(&registry)
        );
    }

    /// A slot holds one interceptor, so a helper cannot quietly end up with two of anything by
    /// being called twice — the position is the identity.
    #[test]
    fn a_slot_holds_one_interceptor() {
        let registry = Registry::new()
            .with(Slot::Pacer, interceptor::NoopInterceptor::new())
            .with(Slot::Pacer, interceptor::NoopInterceptor::new());

        assert_eq!(vec![Slot::Pacer], slots(&registry));
    }

    /// What the default chain is actually made of, by name. The ordering tests above prove the
    /// positions are right; this proves the right interceptors are in them — a chain assembled from
    /// several helpers has no other single view of what it ended up containing.
    #[test]
    fn the_default_chain_names_what_it_registered() {
        let mut media_engine = MediaEngine::default();
        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .expect("default interceptors");

        assert_eq!(
            vec![
                (Slot::NackResponder, "NackResponderInterceptor".to_owned()),
                (Slot::NackGenerator, "NackGeneratorInterceptor".to_owned()),
                (Slot::TwccReceiver, "TwccReceiverInterceptor".to_owned()),
                (Slot::ReceiverReport, "ReceiverReportInterceptor".to_owned()),
                (Slot::SenderReport, "SenderReportInterceptor".to_owned()),
            ],
            registry.slots()
        );
    }
}
