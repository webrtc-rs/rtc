//TODO:#[cfg(test)]
//mod media_engine_test;

use std::collections::HashMap;
use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};

use sdp::description::session::SessionDescription;

use crate::peer_connection::sdp::{
    codecs_from_media_description, rtp_extensions_from_media_description,
};
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::fmtp;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    codec_parameters_fuzzy_search, CodecMatch, RTCRtpCodec, RtpCodecKind,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;
use crate::rtp_transceiver::rtp_sender::rtp_parameters::RTCRtpParameters;
use crate::rtp_transceiver::{rtp_sender::rtcp_parameters::RTCPFeedback, PayloadType};
use shared::error::{Error, Result};

/// MIME_TYPE_H264 H264 MIME type.
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_H264: &str = "video/H264";
/// MIME_TYPE_HEVC HEVC/H265 MIME type.
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_HEVC: &str = "video/H265";
/// MIME_TYPE_OPUS Opus MIME type
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_OPUS: &str = "audio/opus";
/// MIME_TYPE_VP8 VP8 MIME type
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_VP8: &str = "video/VP8";
/// MIME_TYPE_VP9 VP9 MIME type
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_VP9: &str = "video/VP9";
/// MIME_TYPE_AV1 AV1 MIME type
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_AV1: &str = "video/AV1";
/// MIME_TYPE_G722 G722 MIME type
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_G722: &str = "audio/G722";
/// MIME_TYPE_PCMU PCMU MIME type
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_PCMU: &str = "audio/PCMU";
/// MIME_TYPE_PCMA PCMA MIME type
/// Note: Matching should be case insensitive.
pub const MIME_TYPE_PCMA: &str = "audio/PCMA";
/// MIME_TYPE_TELEPHONE_EVENT telephone-event MIME type
/// Note: Matching should be case insensitive.
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

/// A MediaEngine defines the codecs supported by a PeerConnection, and the
/// configuration of those codecs. A MediaEngine must not be shared between
/// PeerConnections.
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

    header_extensions: Vec<MediaEngineHeaderExtension>,
    proposed_header_extensions: HashMap<u16, MediaEngineHeaderExtension>,
    pub(crate) negotiated_header_extensions: HashMap<u16, MediaEngineHeaderExtension>,
}

impl MediaEngine {
    /// register_default_codecs registers the default codecs supported by Pion WebRTC.
    /// register_default_codecs is not safe for concurrent use.
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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

    /// register_codec adds codec to the MediaEngine
    /// These are the list of codecs supported by this PeerConnection.
    /// register_codec is not safe for concurrent use.
    pub fn register_codec(
        &mut self,
        mut codec: RTCRtpCodecParameters,
        typ: RtpCodecKind,
    ) -> Result<()> {
        codec.stats_id = format!(
            "RTPCodec-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
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
                    self.header_extensions.push(MediaEngineHeaderExtension {
                        allowed_direction,
                        ..Default::default()
                    });

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

        if ext.allowed_direction != allowed_direction {
            return Err(Error::ErrRegisterHeaderExtensionInvalidDirection);
        }

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

    /*TODO:
    pub(crate) fn collect_stats(&self, collector: &StatsCollector) {
        let mut reports = HashMap::new();

        for codec in &self.video_codecs {
            reports.insert(codec.stats_id.clone(), Codec(CodecStats::from(codec)));
        }

        for codec in &self.audio_codecs {
            reports.insert(codec.stats_id.clone(), Codec(CodecStats::from(codec)));
        }

        collector.merge(reports);
    }*/

    /// Look up a codec and enable if it exists
    pub(crate) fn match_remote_codec(
        &self,
        remote_codec: &RTCRtpCodecParameters,
        typ: RtpCodecKind,
        exact_matches: &[RTCRtpCodecParameters],
        partial_matches: &[RTCRtpCodecParameters],
    ) -> Result<CodecMatch> {
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
                return Ok(CodecMatch::None); // not an error, we just ignore this codec we don't support
            }

            // replace the apt value with the original codec's payload type
            let mut to_match_codec = remote_codec.clone();
            if let Some(apt_codec) = apt_codec {
                let (apt_matched, mt) = codec_parameters_fuzzy_search(apt_codec, codecs);
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
            let (_, mut match_type) = codec_parameters_fuzzy_search(&to_match_codec, codecs);
            if match_type == CodecMatch::Exact && apt_match == CodecMatch::Partial {
                match_type = CodecMatch::Partial;
            }
            return Ok(match_type);
        }

        let (_, match_type) = codec_parameters_fuzzy_search(remote_codec, codecs);
        Ok(match_type)
    }

    /// Look up a header extension and enable if it exists
    pub(crate) fn update_header_extension(
        &mut self,
        id: u16,
        extension: &str,
        typ: RtpCodecKind,
    ) -> Result<()> {
        let (negotiated_header_extensions, proposed_header_extensions) = (
            &mut self.negotiated_header_extensions,
            &mut self.proposed_header_extensions,
        );

        for local_extension in &self.header_extensions {
            if local_extension.uri != extension {
                continue;
            }

            let negotiated_ext = negotiated_header_extensions
                .iter_mut()
                .find(|(_, ext)| ext.uri == extension);

            if let Some(n_ext) = negotiated_ext {
                if *n_ext.0 == id {
                    n_ext.1.is_video |= typ == RtpCodecKind::Video;
                    n_ext.1.is_audio |= typ == RtpCodecKind::Audio;
                } else {
                    let nid = n_ext.0;
                    log::warn!("Invalid ext id mapping in update_header_extension. {extension} was negotiated as {nid}, but was {id} in call");
                }
            } else {
                // We either only have a proposal or we have neither proposal nor a negotiated id
                // Accept whatevers the peer suggests

                if let Some(prev_ext) = negotiated_header_extensions.get(&id) {
                    let prev_uri = &prev_ext.uri;
                    log::warn!("Assigning {id} to {extension} would override previous assignment to {prev_uri}, no action taken");
                } else {
                    let h = MediaEngineHeaderExtension {
                        uri: extension.to_owned(),
                        is_audio: local_extension.is_audio && typ == RtpCodecKind::Audio,
                        is_video: local_extension.is_video && typ == RtpCodecKind::Video,
                        allowed_direction: local_extension.allowed_direction,
                    };
                    negotiated_header_extensions.insert(id, h);
                }
            }

            // Clear any proposals we had for this id
            proposed_header_extensions.remove(&id);
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
            let typ = if (!self.negotiated_audio || self.negotiate_multi_codecs)
                && media.media_name.media.to_lowercase() == "audio"
            {
                self.negotiated_audio = true;
                RtpCodecKind::Audio
            } else if (!self.negotiated_video || self.negotiate_multi_codecs)
                && media.media_name.media.to_lowercase() == "video"
            {
                self.negotiated_video = true;
                RtpCodecKind::Video
            } else {
                continue;
            };

            let codecs = codecs_from_media_description(media)?;

            let mut exact_matches = vec![]; //make([]RTPCodecParameters, 0, len(codecs))
            let mut partial_matches = vec![]; //make([]RTPCodecParameters, 0, len(codecs))

            for codec in codecs {
                let match_type =
                    self.match_remote_codec(&codec, typ, &exact_matches, &partial_matches)?;

                if match_type == CodecMatch::Exact {
                    exact_matches.push(codec);
                } else if match_type == CodecMatch::Partial {
                    partial_matches.push(codec);
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

            let extensions = rtp_extensions_from_media_description(media)?;

            for (extension, id) in extensions {
                self.update_header_extension(id, &extension, typ)?;
            }
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
        &mut self,
        typ: RtpCodecKind,
        direction: RTCRtpTransceiverDirection,
    ) -> RTCRtpParameters {
        let mut header_extensions = vec![];

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
            let (proposed_header_extensions, negotiated_header_extensions) = (
                &mut self.proposed_header_extensions,
                &mut self.negotiated_header_extensions,
            );

            for local_extension in &self.header_extensions {
                let relevant = local_extension.is_matching_direction(direction)
                    && (local_extension.is_audio && typ == RtpCodecKind::Audio
                        || local_extension.is_video && typ == RtpCodecKind::Video);

                if !relevant {
                    continue;
                }

                if let Some((id, negotiated_extension)) = negotiated_header_extensions
                    .iter_mut()
                    .find(|(_, e)| e.uri == local_extension.uri)
                {
                    // We have previously negotiated this extension, make sure to record it as
                    // active for the current type
                    negotiated_extension.is_audio |= typ == RtpCodecKind::Audio;
                    negotiated_extension.is_video |= typ == RtpCodecKind::Video;

                    header_extensions.push(RTCRtpHeaderExtensionParameters {
                        id: *id,
                        uri: negotiated_extension.uri.clone(),
                        ..Default::default()
                    });

                    continue;
                }

                if let Some((id, negotiated_extension)) = proposed_header_extensions
                    .iter_mut()
                    .find(|(_, e)| e.uri == local_extension.uri)
                {
                    // We have previously proposed this extension, re-use it
                    header_extensions.push(RTCRtpHeaderExtensionParameters {
                        id: *id,
                        uri: negotiated_extension.uri.clone(),
                        ..Default::default()
                    });

                    continue;
                }

                // Figure out which (unused id) to propose.
                let id = VALID_EXT_IDS.clone().find(|id| {
                    !negotiated_header_extensions.keys().any(|nid| nid == id)
                        && !proposed_header_extensions.keys().any(|pid| pid == id)
                });

                if let Some(id) = id {
                    proposed_header_extensions.insert(
                        id,
                        MediaEngineHeaderExtension {
                            uri: local_extension.uri.clone(),
                            is_audio: local_extension.is_audio,
                            is_video: local_extension.is_video,
                            allowed_direction: local_extension.allowed_direction,
                        },
                    );

                    header_extensions.push(RTCRtpHeaderExtensionParameters {
                        id,
                        uri: local_extension.uri.clone(),
                        ..Default::default()
                    });
                } else {
                    log::warn!("No available RTP extension ID for {}", local_extension.uri);
                }
            }
        }

        RTCRtpParameters {
            header_extensions,
            codecs: self.get_codecs_by_kind(typ),
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
}
