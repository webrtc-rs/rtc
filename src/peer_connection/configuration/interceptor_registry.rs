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
//! Interceptors form a processing chain where each interceptor wraps the next:
//!
//! ```text
//! Application
//!     ↓ write (outgoing RTP)
//! [TWCC Receiver] → [Sender Report] → [NACK Responder] → [NACK Generator] → Network
//!     ↑ read (incoming RTP)
//! ```
//!
//! The order matters: interceptors added later wrap those added earlier,
//! meaning they process outgoing packets first and incoming packets last.
//!
//! # Quick Start
//!
//! For most applications, use [`register_default_interceptors`] to enable
//! standard WebRTC functionality:
//!
//! ```ignore
//! use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//! use interceptor::Registry;
//!
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Register NACK, RTCP reports, simulcast headers, and TWCC receiver
//! let registry = register_default_interceptors(registry, &mut media_engine)?;
//!
//! // Use with RTCConfigurationBuilder
//! let config = RTCConfigurationBuilder::new()
//!     .with_media_engine(media_engine)
//!     .with_interceptor_registry(registry)
//!     .build();
//! ```
//!
//! # Custom Configuration
//!
//! For fine-grained control, configure individual interceptors:
//!
//! ```ignore
//! use rtc::peer_connection::configuration::interceptor_registry::*;
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//! use interceptor::Registry;
//!
//! let mut media_engine = MediaEngine::default();
//! let registry = Registry::new();
//!
//! // Only enable NACK (no TWCC, no reports)
//! let registry = configure_nack(registry, &mut media_engine);
//!
//! // Or enable full TWCC for bandwidth estimation
//! let registry = configure_twcc(registry, &mut media_engine)?;
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
    Interceptor, NackGeneratorBuilder, NackResponderBuilder, ReceiverReportBuilder, Registry,
    SenderReportBuilder, TwccReceiverBuilder, TwccSenderBuilder,
};
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
/// ```ignore
/// use rtc::peer_connection::configuration::interceptor_registry::register_default_interceptors;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use interceptor::Registry;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = register_default_interceptors(registry, &mut media_engine)?;
/// ```
///
/// # Customization
///
/// If you need to customize which interceptors are loaded, copy the code from
/// this function and remove or modify the unwanted interceptors.
pub fn register_default_interceptors<P>(
    registry: Registry<P>,
    media_engine: &mut MediaEngine,
) -> Result<Registry<impl Interceptor + use<P>>>
where
    P: Interceptor,
{
    let registry = configure_nack(registry, media_engine);

    let registry = configure_rtcp_reports(registry);

    configure_simulcast_extension_headers(media_engine)?;

    let registry = configure_twcc_receiver_only(registry, media_engine)?;

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
/// ```ignore
/// use rtc::peer_connection::configuration::interceptor_registry::configure_nack;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use interceptor::Registry;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_nack(registry, &mut media_engine);
/// ```
///
/// # References
///
/// - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - Extended RTP Profile for RTCP-Based Feedback
pub fn configure_nack<P>(
    registry: Registry<P>,
    media_engine: &mut MediaEngine,
) -> Registry<impl Interceptor + use<P>>
where
    P: Interceptor,
{
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
        .with(NackGeneratorBuilder::new().build())
        .with(NackResponderBuilder::new().build())
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
/// ```ignore
/// use rtc::peer_connection::configuration::interceptor_registry::configure_rtcp_reports;
/// use interceptor::Registry;
///
/// let registry = Registry::new();
/// let registry = configure_rtcp_reports(registry);
/// ```
///
/// # References
///
/// - [RFC 3550 Section 6](https://datatracker.ietf.org/doc/html/rfc3550#section-6) - RTCP Sender and Receiver Reports
pub fn configure_rtcp_reports<P>(registry: Registry<P>) -> Registry<impl Interceptor + use<P>>
where
    P: Interceptor,
{
    registry
        .with(ReceiverReportBuilder::new().build())
        .with(SenderReportBuilder::new().build())
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
/// ```ignore
/// use rtc::peer_connection::configuration::interceptor_registry::configure_simulcast_extension_headers;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
///
/// let mut media_engine = MediaEngine::default();
/// configure_simulcast_extension_headers(&mut media_engine)?;
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
/// ```ignore
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use interceptor::Registry;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc(registry, &mut media_engine)?;
/// ```
///
/// # References
///
/// - [draft-holmer-rmcat-transport-wide-cc](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
pub fn configure_twcc<P>(
    registry: Registry<P>,
    media_engine: &mut MediaEngine,
) -> Result<Registry<impl Interceptor + use<P>>>
where
    P: Interceptor,
{
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
        .with(TwccSenderBuilder::new().build())
        .with(TwccReceiverBuilder::new().build()))
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
/// ```ignore
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_sender_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use interceptor::Registry;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_sender_only(registry, &mut media_engine)?;
/// ```
pub fn configure_twcc_sender_only<P>(
    registry: Registry<P>,
    media_engine: &mut MediaEngine,
) -> Result<Registry<impl Interceptor + use<P>>>
where
    P: Interceptor,
{
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

    Ok(registry.with(TwccSenderBuilder::new().build()))
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
/// ```ignore
/// use rtc::peer_connection::configuration::interceptor_registry::configure_twcc_receiver_only;
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use interceptor::Registry;
///
/// let mut media_engine = MediaEngine::default();
/// let registry = Registry::new();
/// let registry = configure_twcc_receiver_only(registry, &mut media_engine)?;
/// ```
pub fn configure_twcc_receiver_only<P>(
    registry: Registry<P>,
    media_engine: &mut MediaEngine,
) -> Result<Registry<impl Interceptor + use<P>>>
where
    P: Interceptor,
{
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

    Ok(registry.with(TwccReceiverBuilder::new().build()))
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
