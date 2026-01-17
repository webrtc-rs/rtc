//! Media engine configuration for codecs and RTP extensions.
//!
//! The media engine manages codec registration, RTP header extensions, and media
//! capabilities negotiation for peer connections. It defines what codecs and features
//! are available for encoding/decoding media streams.
//!
//! # Overview
//!
//! - **Codec Registration** - Define supported audio/video codecs
//! - **Header Extensions** - Configure RTP header extensions
//! - **Feedback Mechanisms** - Register RTCP feedback types
//! - **Negotiation** - Codec and extension negotiation with remote peers
//!
//! # Examples
//!
//! ## Using Default Codecs
//!
//! ```
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//!
//! // Register standard WebRTC codecs
//! media_engine.register_default_codecs()?;
//! // Now supports: Opus, G722, PCMU, PCMA, VP8, VP9, H264, AV1
//! # Ok(())
//! # }
//! ```
//!
//! ## Registering Custom Codec
//!
//! ```
//! use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS};
//! use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind, RTCRtpCodecParameters};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//!
//! // Register Opus with custom parameters
//! let opus_codec = RTCRtpCodecParameters {
//!     rtp_codec: RTCRtpCodec {
//!         mime_type: MIME_TYPE_OPUS.to_owned(),
//!         clock_rate: 48000,
//!         channels: 2,
//!         sdp_fmtp_line: "minptime=10;useinbandfec=1;stereo=1".to_owned(),
//!         rtcp_feedback: vec![],
//!     },
//!     payload_type: 111,
//!     ..Default::default()
//! };
//!
//! media_engine.register_codec(opus_codec, RtpCodecKind::Audio)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Registering RTP Header Extension
//!
//! ```
//! use rtc::peer_connection::configuration::media_engine::MediaEngine;
//! use rtc::rtp_transceiver::rtp_sender::{RtpCodecKind, RTCRtpHeaderExtensionCapability};
//! use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut media_engine = MediaEngine::default();
//!
//! // Register audio level extension
//! media_engine.register_header_extension(
//!     RTCRtpHeaderExtensionCapability {
//!         uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
//!     },
//!     RtpCodecKind::Audio,
//!     Some(RTCRtpTransceiverDirection::Sendrecv),
//! )?;
//! # Ok(())
//! # }
//! ```

//TODO:#[cfg(test)]
//mod media_engine_test;

use crate::peer_connection::sdp::{
    codecs_from_media_description, rtp_extensions_from_media_description,
};
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::fmtp;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RTCRtpCodec, RtpCodecKind, codec_parameters_fuzzy_search,
    rtcp_feedback_intersection,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;
use crate::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;
use crate::rtp_transceiver::{PayloadType, rtp_sender::rtcp_parameters::RTCPFeedback};
use sdp::MediaDescription;
use sdp::description::session::SessionDescription;
use shared::error::{Error, Result};
use std::collections::HashMap;
use std::ops::Range;
use unicase::UniCase;

/// H.264 video codec MIME type.
///
/// Used for baseline, main, and high profile H.264 video encoding.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_H264: &str = "video/H264";

/// H.265/HEVC video codec MIME type.
///
/// Used for High Efficiency Video Coding (HEVC/H.265) video encoding.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_HEVC: &str = "video/H265";

/// Opus audio codec MIME type.
///
/// Modern, versatile audio codec with excellent quality and low latency.
/// Recommended for most WebRTC applications.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_OPUS: &str = "audio/opus";

/// VP8 video codec MIME type.
///
/// Open-source video codec, widely supported across all browsers.
/// Good fallback option for video conferencing.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_VP8: &str = "video/VP8";

/// VP9 video codec MIME type.
///
/// Successor to VP8 with better compression efficiency.
/// Supported by modern browsers.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_VP9: &str = "video/VP9";

/// AV1 video codec MIME type.
///
/// Next-generation open video codec with excellent compression.
/// Increasing browser support.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_AV1: &str = "video/AV1";

/// G.722 audio codec MIME type.
///
/// Wideband audio codec (50-7000 Hz).
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_G722: &str = "audio/G722";

/// PCMU (G.711 μ-law) audio codec MIME type.
///
/// Standard telephony codec, primarily used in North America.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_PCMU: &str = "audio/PCMU";

/// PCMA (G.711 A-law) audio codec MIME type.
///
/// Standard telephony codec, primarily used in Europe.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_PCMA: &str = "audio/PCMA";

/// RTX (Retransmission) MIME type.
///
/// Used for RTP retransmission to improve reliability.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_RTX: &str = "video/rtx";

/// FlexFEC forward error correction MIME type.
///
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_FLEX_FEC: &str = "video/flexfec";

/// FlexFEC-03 forward error correction MIME type.
///
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_FLEX_FEC03: &str = "video/flexfec-03";

/// ULP FEC (Uneven Level Protection Forward Error Correction) MIME type.
///
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_ULP_FEC: &str = "video/ulpfec";

/// Telephone-event MIME type for DTMF tones.
///
/// Used for transmitting DTMF (touch-tone) signals.
/// Note: MIME type matching is case-insensitive.
pub const MIME_TYPE_TELEPHONE_EVENT: &str = "audio/telephone-event";

const VALID_EXT_IDS: Range<u16> = 1..15;

#[derive(Default, Clone)]
pub(crate) struct MediaEngineHeaderExtension {
    pub(crate) uri: String,
    pub(crate) is_audio: bool,
    pub(crate) is_video: bool,
    pub(crate) allowed_direction: Option<RTCRtpTransceiverDirection>,
}

impl MediaEngineHeaderExtension {
    pub fn is_matching_direction(&self, dir: RTCRtpTransceiverDirection) -> bool {
        if let Some(allowed_direction) = self.allowed_direction {
            use RTCRtpTransceiverDirection::*;
            allowed_direction == Inactive && dir == Inactive
                || allowed_direction.has_send() && dir.has_send()
                || allowed_direction.has_recv() && dir.has_recv()
        } else {
            // None means all directions matches.
            true
        }
    }
}

/// Media engine managing codecs and RTP capabilities for peer connections.
///
/// MediaEngine defines which audio/video codecs are supported and how they're
/// configured. Each peer connection should have its own MediaEngine instance
/// as codec negotiation state is tracked per-connection.
///
/// # Thread Safety
///
/// ⚠️ MediaEngine is **not** safe for concurrent use during configuration.
/// Configure it completely before using in a peer connection.
///
/// # Examples
///
/// ## Default Configuration
///
/// ```
/// use rtc::peer_connection::configuration::media_engine::MediaEngine;
/// use rtc::peer_connection::configuration::RTCConfigurationBuilder;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
/// media_engine.register_default_codecs()?;
///
/// let config = RTCConfigurationBuilder::new()
///     .with_media_engine(media_engine)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Custom Codec Configuration
///
/// ```
/// use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS, MIME_TYPE_VP8};
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind, RTCRtpCodecParameters};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut media_engine = MediaEngine::default();
///
/// // Register only specific codecs for minimal overhead
/// media_engine.register_codec(
///     RTCRtpCodecParameters {
///         rtp_codec: RTCRtpCodec {
///             mime_type: MIME_TYPE_OPUS.to_owned(),
///             clock_rate: 48000,
///             channels: 2,
///             sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
///             rtcp_feedback: vec![],
///         },
///         payload_type: 111,
///         ..Default::default()
///     },
///     RtpCodecKind::Audio,
/// )?;
///
/// media_engine.register_codec(
///     RTCRtpCodecParameters {
///         rtp_codec: RTCRtpCodec {
///             mime_type: MIME_TYPE_VP8.to_owned(),
///             clock_rate: 90000,
///             channels: 0,
///             sdp_fmtp_line: "".to_owned(),
///             rtcp_feedback: vec![],
///         },
///         payload_type: 96,
///         ..Default::default()
///     },
///     RtpCodecKind::Video,
/// )?;
/// # Ok(())
/// # }
/// ```
#[derive(Default, Clone)]
pub struct MediaEngine {
    // If we have attempted to negotiate a codec type yet.
    pub(crate) negotiated_video: bool,
    pub(crate) negotiated_audio: bool,
    pub(crate) negotiate_multi_codecs: bool,

    pub(crate) video_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) audio_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) negotiated_video_codecs: Vec<RTCRtpCodecParameters>,
    pub(crate) negotiated_audio_codecs: Vec<RTCRtpCodecParameters>,

    pub(crate) header_extensions: Vec<MediaEngineHeaderExtension>,
    pub(crate) negotiated_header_extensions: HashMap<u16, MediaEngineHeaderExtension>,
}

impl MediaEngine {
    /// Registers standard WebRTC codecs for audio and video.
    ///
    /// This convenience method registers all codecs commonly supported by WebRTC implementations:
    ///
    /// **Audio Codecs:**
    /// - Opus (48kHz, stereo, with FEC)
    /// - G.722 (8kHz wideband)
    /// - PCMU/G.711 μ-law (8kHz)
    /// - PCMA/G.711 A-law (8kHz)
    ///
    /// **Video Codecs:**
    /// - VP8 with RTCP feedback
    /// - VP9 (multiple profiles) with RTCP feedback
    /// - H.264 (multiple profiles/packetization modes) with RTCP feedback
    /// - AV1 with RTCP feedback  
    /// - H.265/HEVC with RTCP feedback
    /// - ULP FEC (forward error correction)
    ///
    /// # Thread Safety
    ///
    /// ⚠️ Not safe for concurrent use. Call before using MediaEngine in a peer connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::media_engine::MediaEngine;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    /// media_engine.register_default_codecs()?;
    /// // Media engine now supports all standard WebRTC codecs
    /// # Ok(())
    /// # }
    /// ```
    pub fn register_default_codecs(&mut self) -> Result<()> {
        // Default Audio Codecs
        for codec in [
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_OPUS.to_owned(),
                    clock_rate: 48000,
                    channels: 2,
                    sdp_fmtp_line: "minptime=10;useinbandfec=1".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 111,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_G722.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 9,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_PCMU.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 0,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_PCMA.to_owned(),
                    clock_rate: 8000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 8,
            },
        ] {
            self.register_codec(codec, RtpCodecKind::Audio)?;
        }

        let video_rtcp_feedback = vec![
            RTCPFeedback {
                typ: "goog-remb".to_owned(),
                parameter: "".to_owned(),
            },
            RTCPFeedback {
                typ: "ccm".to_owned(),
                parameter: "fir".to_owned(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "".to_owned(),
            },
            RTCPFeedback {
                typ: "nack".to_owned(),
                parameter: "pli".to_owned(),
            },
        ];
        for codec in vec![
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 96,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP9.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "profile-id=0".to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 98,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP9.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "profile-id=1".to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 100,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 102,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 127,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 125,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 108,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 127,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_H264.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line:
                        "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032"
                            .to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 123,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_AV1.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "profile-id=0".to_owned(),
                    rtcp_feedback: video_rtcp_feedback.clone(),
                },
                payload_type: 41,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_HEVC.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: video_rtcp_feedback,
                },
                payload_type: 126,
            },
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: "video/ulpfec".to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: "".to_owned(),
                    rtcp_feedback: vec![],
                },
                payload_type: 116,
            },
        ] {
            self.register_codec(codec, RtpCodecKind::Video)?;
        }

        Ok(())
    }

    /// add_codec will append codec if it not exists
    fn add_codec(codecs: &mut Vec<RTCRtpCodecParameters>, codec: RTCRtpCodecParameters) {
        for c in codecs.iter() {
            if c.rtp_codec.mime_type == codec.rtp_codec.mime_type
                && c.payload_type == codec.payload_type
            {
                return;
            }
        }
        codecs.push(codec);
    }

    /// Registers a custom codec for use in this peer connection.
    ///
    /// Adds a codec to the list of supported codecs. During SDP negotiation, only
    /// codecs registered here will be offered/accepted.
    ///
    /// # Parameters
    ///
    /// * `codec` - The codec parameters including MIME type, clock rate, and payload type
    /// * `typ` - Whether this is an audio or video codec
    ///
    /// # Thread Safety
    ///
    /// ⚠️ Not safe for concurrent use. Register all codecs before using in a peer connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_OPUS};
    /// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind, RTCRtpCodecParameters};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut media_engine = MediaEngine::default();
    ///
    /// // Register Opus with custom fmtp parameters
    /// media_engine.register_codec(
    ///     RTCRtpCodecParameters {
    ///         rtp_codec: RTCRtpCodec {
    ///             mime_type: MIME_TYPE_OPUS.to_owned(),
    ///             clock_rate: 48000,
    ///             channels: 2,
    ///             sdp_fmtp_line: "minptime=10;useinbandfec=1;stereo=1".to_owned(),
    ///             rtcp_feedback: vec![],
    ///         },
    ///         payload_type: 111,
    ///         ..Default::default()
    ///     },
    ///     RtpCodecKind::Audio,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn register_codec(
        &mut self,
        codec: RTCRtpCodecParameters,
        typ: RtpCodecKind,
    ) -> Result<()> {
        match typ {
            RtpCodecKind::Audio => {
                MediaEngine::add_codec(&mut self.audio_codecs, codec);
                Ok(())
            }
            RtpCodecKind::Video => {
                MediaEngine::add_codec(&mut self.video_codecs, codec);
                Ok(())
            }
            _ => Err(Error::ErrUnknownType),
        }
    }

    /// Adds a header extension to the MediaEngine
    /// To determine the negotiated value use [`MediaEngine::get_header_extension_id`] after signaling is complete.
    ///
    /// The `allowed_direction` controls for which transceiver directions the extension matches. If
    /// set to `None` it matches all directions. The `SendRecv` direction would match all transceiver
    /// directions apart from `Inactive`. Inactive only matches inactive.
    pub fn register_header_extension(
        &mut self,
        extension: RTCRtpHeaderExtensionCapability,
        typ: RtpCodecKind,
        allowed_direction: Option<RTCRtpTransceiverDirection>,
    ) -> Result<()> {
        if let Some(direction) = &allowed_direction
            && (direction == &RTCRtpTransceiverDirection::Unspecified
                || direction == &RTCRtpTransceiverDirection::Inactive)
        {
            return Err(Error::ErrRegisterHeaderExtensionInvalidDirection);
        }

        let ext = {
            match self
                .header_extensions
                .iter_mut()
                .find(|ext| ext.uri == extension.uri)
            {
                Some(ext) => ext,
                None => {
                    // We have registered too many extensions
                    if self.header_extensions.len() > VALID_EXT_IDS.end as usize {
                        return Err(Error::ErrRegisterHeaderExtensionNoFreeID);
                    }
                    self.header_extensions
                        .push(MediaEngineHeaderExtension::default());

                    // Unwrap is fine because we just pushed
                    self.header_extensions.last_mut().unwrap()
                }
            }
        };

        if typ == RtpCodecKind::Audio {
            ext.is_audio = true;
        } else if typ == RtpCodecKind::Video {
            ext.is_video = true;
        }

        ext.uri = extension.uri;
        ext.allowed_direction = allowed_direction;

        Ok(())
    }

    /// register_feedback adds feedback mechanism to already registered codecs.
    pub fn register_feedback(&mut self, feedback: RTCPFeedback, typ: RtpCodecKind) {
        match typ {
            RtpCodecKind::Video => {
                for v in &mut self.video_codecs {
                    v.rtp_codec.rtcp_feedback.push(feedback.clone());
                }
            }
            RtpCodecKind::Audio => {
                for a in &mut self.audio_codecs {
                    a.rtp_codec.rtcp_feedback.push(feedback.clone());
                }
            }
            _ => {}
        }
    }

    /// get_header_extension_id returns the negotiated ID for a header extension.
    /// If the Header Extension isn't enabled ok will be false
    pub fn get_header_extension_id(
        &self,
        extension: RTCRtpHeaderExtensionCapability,
    ) -> (u16, bool, bool) {
        if self.negotiated_header_extensions.is_empty() {
            return (0, false, false);
        }

        for (id, h) in &self.negotiated_header_extensions {
            if extension.uri == h.uri {
                return (*id, h.is_audio, h.is_video);
            }
        }

        (0, false, false)
    }

    /// clone_to copies any user modifiable state of the MediaEngine
    /// all internal state is reset
    pub(crate) fn clone_to(&self) -> Self {
        MediaEngine {
            video_codecs: self.video_codecs.clone(),
            audio_codecs: self.audio_codecs.clone(),
            header_extensions: self.header_extensions.clone(),
            ..Default::default()
        }
    }

    /// set_multi_codec_negotiation enables or disables the negotiation of multiple codecs.
    pub(crate) fn set_multi_codec_negotiation(&mut self, negotiate_multi_codecs: bool) {
        self.negotiate_multi_codecs = negotiate_multi_codecs;
    }

    /// multi_codec_negotiation returns the current state of the negotiation of multiple codecs.
    pub(crate) fn multi_codec_negotiation(&self) -> bool {
        self.negotiate_multi_codecs
    }

    pub(crate) fn get_codec_by_payload(
        &self,
        payload_type: PayloadType,
    ) -> Result<(RTCRtpCodecParameters, RtpCodecKind)> {
        if self.negotiated_video {
            for codec in &self.negotiated_video_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Video));
                }
            }
        }
        if self.negotiated_audio {
            for codec in &self.negotiated_audio_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Audio));
                }
            }
        }
        if !self.negotiated_video {
            for codec in &self.video_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Video));
                }
            }
        }
        if !self.negotiated_audio {
            for codec in &self.audio_codecs {
                if codec.payload_type == payload_type {
                    return Ok((codec.clone(), RtpCodecKind::Audio));
                }
            }
        }

        Err(Error::ErrCodecNotFound)
    }

    /// Look up a codec and enable if it exists
    pub(crate) fn match_remote_codec(
        &self,
        remote_codec: &RTCRtpCodecParameters,
        typ: RtpCodecKind,
        exact_matches: &[RTCRtpCodecParameters],
        partial_matches: &[RTCRtpCodecParameters],
    ) -> Result<(RTCRtpCodecParameters, CodecMatch)> {
        let codecs = if typ == RtpCodecKind::Audio {
            &self.audio_codecs
        } else {
            &self.video_codecs
        };

        let remote_fmtp = fmtp::parse(
            &remote_codec.rtp_codec.mime_type,
            remote_codec.rtp_codec.sdp_fmtp_line.as_str(),
        );
        if let Some(apt) = remote_fmtp.parameter("apt") {
            let payload_type = apt.parse::<u8>()?;

            let mut apt_match = CodecMatch::None;
            let mut apt_codec = None;
            for codec in exact_matches {
                if codec.payload_type == payload_type {
                    apt_match = CodecMatch::Exact;
                    apt_codec = Some(codec);
                    break;
                }
            }

            if apt_match == CodecMatch::None {
                for codec in partial_matches {
                    if codec.payload_type == payload_type {
                        apt_match = CodecMatch::Partial;
                        apt_codec = Some(codec);
                        break;
                    }
                }
            }

            if apt_match == CodecMatch::None {
                return Ok((RTCRtpCodecParameters::default(), CodecMatch::None));
                // not an error, we just ignore this codec we don't support
            }

            // replace the apt value with the original codec's payload type
            let mut to_match_codec = remote_codec.clone();
            if let Some(apt_codec) = apt_codec {
                let (apt_matched, mt) = codec_parameters_fuzzy_search(&apt_codec.rtp_codec, codecs);
                if mt == apt_match {
                    to_match_codec.rtp_codec.sdp_fmtp_line =
                        to_match_codec.rtp_codec.sdp_fmtp_line.replacen(
                            &format!("apt={payload_type}"),
                            &format!("apt={}", apt_matched.payload_type),
                            1,
                        );
                }
            }

            // if apt's media codec is partial match, then apt codec must be partial match too
            let (local_codec, mut match_type) =
                codec_parameters_fuzzy_search(&to_match_codec.rtp_codec, codecs);
            if match_type == CodecMatch::Exact && apt_match == CodecMatch::Partial {
                match_type = CodecMatch::Partial;
            }
            return Ok((local_codec, match_type));
        }

        let (local_codec, match_type) =
            codec_parameters_fuzzy_search(&remote_codec.rtp_codec, codecs);
        Ok((local_codec, match_type))
    }

    // Update header extensions from a remote media section.
    fn update_header_extension_from_media_section(
        &mut self,
        media: &MediaDescription,
    ) -> Result<()> {
        let typ = if media.media_name.media.to_lowercase() == "audio" {
            RtpCodecKind::Audio
        } else if media.media_name.media.to_lowercase() == "video" {
            RtpCodecKind::Video
        } else {
            return Ok(());
        };

        let extensions = rtp_extensions_from_media_description(media)?;

        for (extension, id) in extensions {
            self.update_header_extension(id, extension.as_str(), typ)?;
        }

        Ok(())
    }

    /// Look up a header extension and enable if it exists
    pub(crate) fn update_header_extension(
        &mut self,
        id: u16,
        extension: &str,
        typ: RtpCodecKind,
    ) -> Result<()> {
        for local_extension in &self.header_extensions {
            if local_extension.uri == extension {
                if let Some(existing_extension) = self.negotiated_header_extensions.get_mut(&id) {
                    if local_extension.is_audio && typ == RtpCodecKind::Audio {
                        existing_extension.is_audio = true;
                    }
                    if local_extension.is_video && typ == RtpCodecKind::Video {
                        existing_extension.is_video = true;
                    }
                } else {
                    self.negotiated_header_extensions.insert(
                        id,
                        MediaEngineHeaderExtension {
                            uri: extension.to_owned(),
                            is_audio: local_extension.is_audio && typ == RtpCodecKind::Audio,
                            is_video: local_extension.is_video && typ == RtpCodecKind::Video,
                            allowed_direction: local_extension.allowed_direction,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn push_codecs(&mut self, codecs: Vec<RTCRtpCodecParameters>, typ: RtpCodecKind) {
        for codec in codecs {
            if typ == RtpCodecKind::Audio {
                MediaEngine::add_codec(&mut self.negotiated_audio_codecs, codec);
            } else if typ == RtpCodecKind::Video {
                MediaEngine::add_codec(&mut self.negotiated_video_codecs, codec);
            }
        }
    }

    /// Update the MediaEngine from a remote description
    pub(crate) fn update_from_remote_description(
        &mut self,
        desc: &SessionDescription,
    ) -> Result<()> {
        for media in &desc.media_descriptions {
            let typ = if media.media_name.media.to_lowercase() == "audio" {
                RtpCodecKind::Audio
            } else if media.media_name.media.to_lowercase() == "video" {
                RtpCodecKind::Video
            } else {
                RtpCodecKind::Unspecified
            };

            if !self.negotiated_audio && typ == RtpCodecKind::Audio {
                self.negotiated_audio = true;
            } else if !self.negotiated_video && typ == RtpCodecKind::Video {
                self.negotiated_video = true;
            } else {
                // update header extesions from remote sdp if codec is negotiated, Firefox
                // would send updated header extension in renegotiation.
                // e.g. publish first track without simucalst ->negotiated-> publish second track with simucalst
                // then the two media secontions have different rtp header extensions in offer
                self.update_header_extension_from_media_section(media)?;

                if !self.negotiate_multi_codecs
                    || (typ != RtpCodecKind::Audio && typ != RtpCodecKind::Video)
                {
                    continue;
                }
            }

            let mut codecs = codecs_from_media_description(media)?;

            let add_if_new = |existing_codecs: &mut Vec<RTCRtpCodecParameters>,
                              codec: &RTCRtpCodecParameters| {
                let mut found = false;
                for existing_codec in existing_codecs.iter() {
                    if existing_codec.payload_type == codec.payload_type {
                        found = true;
                        break;
                    }
                }

                if !found {
                    existing_codecs.push(codec.clone());
                }
            };

            let mut exact_matches = vec![];
            let mut partial_matches = vec![];

            for remote_codec in &mut codecs {
                let (local_codec, match_type) =
                    self.match_remote_codec(remote_codec, typ, &exact_matches, &partial_matches)?;

                remote_codec.rtp_codec.rtcp_feedback = rtcp_feedback_intersection(
                    &local_codec.rtp_codec.rtcp_feedback,
                    &remote_codec.rtp_codec.rtcp_feedback,
                );

                if match_type == CodecMatch::Exact {
                    add_if_new(&mut exact_matches, remote_codec);
                } else if match_type == CodecMatch::Partial {
                    add_if_new(&mut partial_matches, remote_codec);
                }
            }
            // second pass in case there were missed RTX codecs
            for remote_codec in &mut codecs {
                let (local_codec, match_type) =
                    self.match_remote_codec(remote_codec, typ, &exact_matches, &partial_matches)?;

                remote_codec.rtp_codec.rtcp_feedback = rtcp_feedback_intersection(
                    &local_codec.rtp_codec.rtcp_feedback,
                    &remote_codec.rtp_codec.rtcp_feedback,
                );

                if match_type == CodecMatch::Exact {
                    add_if_new(&mut exact_matches, remote_codec);
                } else if match_type == CodecMatch::Partial {
                    add_if_new(&mut partial_matches, remote_codec);
                }
            }

            // use exact matches when they exist, otherwise fall back to partial
            if !exact_matches.is_empty() {
                self.push_codecs(exact_matches, typ);
            } else if !partial_matches.is_empty() {
                self.push_codecs(partial_matches, typ);
            } else {
                // no match, not negotiated
                continue;
            }

            self.update_header_extension_from_media_section(media)?;
        }

        Ok(())
    }

    pub(crate) fn get_codecs_by_kind(&self, typ: RtpCodecKind) -> Vec<RTCRtpCodecParameters> {
        if typ == RtpCodecKind::Video {
            if self.negotiated_video {
                self.negotiated_video_codecs.clone()
            } else {
                self.video_codecs.clone()
            }
        } else if typ == RtpCodecKind::Audio {
            if self.negotiated_audio {
                self.negotiated_audio_codecs.clone()
            } else {
                self.audio_codecs.clone()
            }
        } else {
            vec![]
        }
    }

    pub(crate) fn get_rtp_parameters_by_kind(
        &self,
        typ: RtpCodecKind,
        direction: RTCRtpTransceiverDirection,
    ) -> RTCRtpParameters {
        let mut header_extensions = vec![];

        let found_codecs = self.get_codecs_by_kind(typ);

        if self.negotiated_video && typ == RtpCodecKind::Video
            || self.negotiated_audio && typ == RtpCodecKind::Audio
        {
            for (id, e) in &self.negotiated_header_extensions {
                if e.is_matching_direction(direction)
                    && (e.is_audio && typ == RtpCodecKind::Audio
                        || e.is_video && typ == RtpCodecKind::Video)
                {
                    header_extensions.push(RTCRtpHeaderExtensionParameters {
                        id: *id,
                        uri: e.uri.clone(),
                        ..Default::default()
                    });
                }
            }
        } else {
            let mut media_header_extensions = HashMap::new();

            for ext in &self.header_extensions {
                let mut using_negotiated_id = false;
                for (id, negotiated_extension) in &self.negotiated_header_extensions {
                    if negotiated_extension.uri == ext.uri {
                        using_negotiated_id = true;
                        media_header_extensions.insert(*id, ext);
                        break;
                    }
                }
                if !using_negotiated_id {
                    for id in 1..15 {
                        let mut id_available = true;
                        if media_header_extensions.contains_key(&id) {
                            id_available = false
                        }
                        if id_available && !self.negotiated_header_extensions.contains_key(&id) {
                            media_header_extensions.insert(id, ext);
                            break;
                        }
                    }
                }
            }

            for (id, e) in media_header_extensions {
                if e.is_matching_direction(direction)
                    && (e.is_audio && typ == RtpCodecKind::Audio
                        || e.is_video && typ == RtpCodecKind::Video)
                {
                    header_extensions.push(RTCRtpHeaderExtensionParameters {
                        id,
                        uri: e.uri.clone(),
                        ..Default::default()
                    })
                }
            }
        }

        RTCRtpParameters {
            header_extensions,
            codecs: found_codecs,
            ..Default::default()
        }
    }

    pub(crate) fn get_rtp_parameters_by_payload_type(
        &self,
        payload_type: PayloadType,
    ) -> Result<RTCRtpParameters> {
        let (codec, typ) = self.get_codec_by_payload(payload_type)?;

        let mut header_extensions = vec![];
        for (id, e) in &self.negotiated_header_extensions {
            if e.is_audio && typ == RtpCodecKind::Audio || e.is_video && typ == RtpCodecKind::Video
            {
                header_extensions.push(RTCRtpHeaderExtensionParameters {
                    uri: e.uri.clone(),
                    id: *id,
                    ..Default::default()
                });
            }
        }

        Ok(RTCRtpParameters {
            header_extensions,
            codecs: vec![codec],
            ..Default::default()
        })
    }

    pub(crate) fn is_rtx_enabled(
        &self,
        kind: RtpCodecKind,
        direction: RTCRtpTransceiverDirection,
    ) -> bool {
        for codec in &self.get_rtp_parameters_by_kind(kind, direction).codecs {
            if UniCase::new(codec.rtp_codec.mime_type.as_str()) == UniCase::new(MIME_TYPE_RTX) {
                return true;
            }
        }

        false
    }

    pub(crate) fn is_fec_enabled(
        &self,
        kind: RtpCodecKind,
        direction: RTCRtpTransceiverDirection,
    ) -> bool {
        for codec in &self.get_rtp_parameters_by_kind(kind, direction).codecs {
            if UniCase::new(codec.rtp_codec.mime_type.as_str())
                .contains(*UniCase::new(MIME_TYPE_FLEX_FEC))
            {
                return true;
            }
        }

        false
    }
}
