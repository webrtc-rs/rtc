use std::fmt;

use crate::peer_connection::configuration::UNSPECIFIED_STR;
use crate::peer_connection::configuration::media_engine::*;
use crate::rtp_transceiver::rtp_sender::rtcp_parameters::RTCPFeedback;
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::{PayloadType, fmtp};
use shared::error::{Error, Result};

/// Codec kind identifying the media type.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum RtpCodecKind {
    /// Unspecified or unknown codec type
    #[default]
    Unspecified = 0,

    /// Audio codec
    Audio = 1,

    /// Video codec
    Video = 2,
}

impl From<&str> for RtpCodecKind {
    fn from(raw: &str) -> Self {
        match raw {
            "audio" => RtpCodecKind::Audio,
            "video" => RtpCodecKind::Video,
            _ => RtpCodecKind::Unspecified,
        }
    }
}

impl From<u8> for RtpCodecKind {
    fn from(v: u8) -> Self {
        match v {
            1 => RtpCodecKind::Audio,
            2 => RtpCodecKind::Video,
            _ => RtpCodecKind::Unspecified,
        }
    }
}

impl fmt::Display for RtpCodecKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RtpCodecKind::Audio => "audio",
            RtpCodecKind::Video => "video",
            RtpCodecKind::Unspecified => UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}

/// RTP codec capability providing information about supported codecs.
///
/// ## Specifications
///
/// * [W3C](https://w3c.github.io/webrtc-pc/#dictionary-rtcrtpcodeccapability-members)
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RTCRtpCodec {
    /// MIME type of the codec (e.g., "video/VP8", "audio/opus")
    pub mime_type: String,
    /// Codec clock rate in Hz
    pub clock_rate: u32,
    /// Number of audio channels (0 for video codecs)
    pub channels: u16,
    /// Format-specific parameters as SDP fmtp line
    pub sdp_fmtp_line: String,
    /// RTCP feedback mechanisms supported by this codec (deprecated, will be removed)
    pub rtcp_feedback: Vec<RTCPFeedback>, //TODO: to be removed
}

impl RTCRtpCodec {
    /// Creates an RTP payloader for this codec.
    ///
    /// Returns a boxed trait object implementing the Payloader interface
    /// for packetizing media frames into RTP packets.
    ///
    /// # Errors
    ///
    /// Returns `Error::ErrNoPayloaderForCodec` if the codec is not supported.
    pub fn payloader(&self) -> Result<Box<dyn rtp::packetizer::Payloader>> {
        let mime_type = self.mime_type.to_lowercase();
        if mime_type == MIME_TYPE_H264.to_lowercase() {
            Ok(Box::<rtp::codec::h264::H264Payloader>::default())
        } else if mime_type == MIME_TYPE_HEVC.to_lowercase() {
            Ok(Box::<rtp::codec::h265::HevcPayloader>::default())
        } else if mime_type == MIME_TYPE_VP8.to_lowercase() {
            let mut vp8_payloader = rtp::codec::vp8::Vp8Payloader::default();
            vp8_payloader.enable_picture_id = true;
            Ok(Box::new(vp8_payloader))
        } else if mime_type == MIME_TYPE_VP9.to_lowercase() {
            Ok(Box::<rtp::codec::vp9::Vp9Payloader>::default())
        } else if mime_type == MIME_TYPE_OPUS.to_lowercase() {
            Ok(Box::<rtp::codec::opus::OpusPayloader>::default())
        } else if mime_type == MIME_TYPE_G722.to_lowercase()
            || mime_type == MIME_TYPE_PCMU.to_lowercase()
            || mime_type == MIME_TYPE_PCMA.to_lowercase()
            || mime_type == MIME_TYPE_TELEPHONE_EVENT.to_lowercase()
        {
            Ok(Box::<rtp::codec::g7xx::G7xxPayloader>::default())
        } else if mime_type == MIME_TYPE_AV1.to_lowercase() {
            Ok(Box::<rtp::codec::av1::Av1Payloader>::default())
        } else {
            Err(Error::ErrNoPayloaderForCodec)
        }
    }
}

/// Codec match quality result from fuzzy search.
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum CodecMatch {
    /// No match found
    #[default]
    None = 0,
    /// Partial match (MIME type matches)
    Partial = 1,
    /// Exact match (MIME type and format parameters match)
    Exact = 2,
}

/// Performs fuzzy search for a codec in a list of available codecs.
///
/// First attempts an exact match on both MIME type and format parameters,
/// then falls back to matching only the MIME type.
///
/// # Parameters
///
/// * `needle_rtp_codec` - The codec to search for
/// * `haystack` - List of available codecs to search in
///
/// # Returns
///
/// A tuple of (matched codec parameters, match quality)
pub(crate) fn codec_parameters_fuzzy_search(
    needle_rtp_codec: &RTCRtpCodec,
    haystack: &[RTCRtpCodecParameters],
) -> (RTCRtpCodecParameters, CodecMatch) {
    let needle_fmtp = fmtp::parse(&needle_rtp_codec.mime_type, &needle_rtp_codec.sdp_fmtp_line);

    //TODO: add unicode case-folding equal support

    // First attempt to match on mime_type + sdpfmtp_line
    for c in haystack {
        let cfmpt = fmtp::parse(&c.rtp_codec.mime_type, &c.rtp_codec.sdp_fmtp_line);
        if needle_fmtp.match_fmtp(&*cfmpt) {
            return (c.clone(), CodecMatch::Exact);
        }
    }

    // Fallback to just mime_type
    for c in haystack {
        if c.rtp_codec.mime_type.to_uppercase() == needle_rtp_codec.mime_type.to_uppercase() {
            return (c.clone(), CodecMatch::Partial);
        }
    }

    (RTCRtpCodecParameters::default(), CodecMatch::None)
}

/// Searches for a matching encoding in available codecs.
///
/// Iterates through encodings looking for the best codec match, preferring exact matches.
///
/// # Parameters
///
/// * `encodings` - List of encoding parameters to search through
/// * `haystack` - List of available codec parameters
///
/// # Returns
///
/// A tuple of (matched encoding, match quality)
pub(crate) fn encoding_parameters_fuzzy_search(
    encodings: &[RTCRtpEncodingParameters],
    haystack: &[RTCRtpCodecParameters],
) -> (RTCRtpEncodingParameters, CodecMatch) {
    let mut result = None;
    for encoding in encodings {
        let (_, codec_match_type) = codec_parameters_fuzzy_search(&encoding.codec, haystack);
        if codec_match_type == CodecMatch::Exact {
            return (encoding.clone(), codec_match_type);
        } else if result.is_none() {
            result = Some((encoding.clone(), CodecMatch::Partial));
        }
    }

    if let Some((encoding, code_match_type)) = result {
        (encoding, code_match_type)
    } else {
        (RTCRtpEncodingParameters::default(), CodecMatch::None)
    }
}

/// Finds the RTX payload type associated with a given payload type.
///
/// Searches for an RTX codec with the matching APT (Associated Payload Type) parameter.
///
/// # Parameters
///
/// * `needle` - The primary payload type to find RTX for
/// * `haystack` - List of codec parameters to search
///
/// # Returns
///
/// The RTX payload type if found, None otherwise
pub(crate) fn find_rtx_payload_type(
    needle: PayloadType,
    haystack: &[RTCRtpCodecParameters],
) -> Option<PayloadType> {
    let apt_str = format!("apt={}", needle);
    for c in haystack {
        if apt_str == c.rtp_codec.sdp_fmtp_line {
            return Some(c.payload_type);
        }
    }

    None
}

// For now, only FlexFEC is supported.
pub(crate) fn find_fec_payload_type(haystack: &[RTCRtpCodecParameters]) -> Option<PayloadType> {
    for c in haystack {
        if c.rtp_codec
            .mime_type
            .to_lowercase()
            .contains(MIME_TYPE_FLEX_FEC)
        {
            return Some(c.payload_type);
        }
    }

    None
}

/// Computes the intersection of two RTCP feedback lists.
///
/// Returns feedback mechanisms that are supported by both lists,
/// matching on both type and parameter fields.
///
/// # Parameters
///
/// * `a` - First feedback list
/// * `b` - Second feedback list
///
/// # Returns
///
/// Vector of common feedback mechanisms
pub(crate) fn rtcp_feedback_intersection(
    a: &[RTCPFeedback],
    b: &[RTCPFeedback],
) -> Vec<RTCPFeedback> {
    let mut out = vec![];
    for a_feedback in a {
        for b_feeback in b {
            if a_feedback.typ == b_feeback.typ && a_feedback.parameter == b_feeback.parameter {
                out.push(a_feedback.clone());
                break;
            }
        }
    }

    out
}
