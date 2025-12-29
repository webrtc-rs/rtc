//TODO: #[cfg(test)]
//mod rtp_receiver_test;

mod rtp_contributing_source;

use crate::media_stream::track::MediaStreamTrack;
use crate::media_stream::MediaStreamId;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::rtp_contributing_source::{
    RTCRtpContributingSource, RTCRtpSynchronizationSource,
};
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    codec_parameters_fuzzy_search, CodecMatch, RtpCodecKind,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use shared::util::math_rand_alpha;
use std::time::Duration;

/// RTPReceiver allows an application to inspect the receipt of a TrackRemote
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpReceiver
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtcrtpreceiver-interface
#[derive(Default, Debug, Clone)]
pub struct RTCRtpReceiver {
    receiver_track: MediaStreamTrack,
    contributing_sources: Vec<RTCRtpContributingSource>,
    synchronization_sources: Vec<RTCRtpSynchronizationSource>,
    jitter_buffer_target: Duration,

    associated_remote_media_stream_ids: Vec<MediaStreamId>,
    last_stable_state_associated_remote_media_stream_ids: Vec<MediaStreamId>,
    receive_codecs: Vec<RTCRtpCodecParameters>,
    last_stable_state_receive_codecs: Vec<RTCRtpCodecParameters>,
}

impl RTCRtpReceiver {
    pub fn new(kind: RtpCodecKind) -> Self {
        Self {
            receiver_track: MediaStreamTrack::new(
                math_rand_alpha(36),
                kind,
                format!("remote {}", kind),
                true,
            ),
            ..Default::default()
        }
    }

    pub fn track(&self) -> &MediaStreamTrack {
        &self.receiver_track
    }

    pub fn get_capabilities(
        &self,
        kind: RtpCodecKind,
        media_engine: &mut MediaEngine,
    ) -> Option<RTCRtpCapabilities> {
        if kind == RtpCodecKind::Unspecified {
            return None;
        }

        let rtp_parameters = media_engine
            .get_rtp_parameters_by_kind(self.track().kind(), RTCRtpTransceiverDirection::Recvonly);

        Some(RTCRtpCapabilities {
            codecs: self
                .receive_codecs
                .iter()
                .filter(|codec| {
                    codec
                        .rtp_codec
                        .mime_type
                        .contains(kind.to_string().as_str())
                })
                .map(|codec| codec.rtp_codec.clone())
                .collect(),
            header_extensions: rtp_parameters
                .header_extensions
                .into_iter()
                .map(|h| RTCRtpHeaderExtensionCapability { uri: h.uri })
                .collect(),
        })
    }

    pub fn get_parameters(&self, media_engine: &mut MediaEngine) -> RTCRtpReceiveParameters {
        let mut rtp_parameters = media_engine
            .get_rtp_parameters_by_kind(self.track().kind(), RTCRtpTransceiverDirection::Recvonly);

        rtp_parameters.codecs =
            RTCRtpReceiver::get_codecs(&self.receive_codecs, self.kind(), media_engine);

        RTCRtpReceiveParameters { rtp_parameters }
    }

    pub fn get_contributing_sources(&self) -> impl Iterator<Item = &RTCRtpContributingSource> {
        self.contributing_sources.iter()
    }

    pub fn get_synchronization_sources(
        &self,
    ) -> impl Iterator<Item = &RTCRtpSynchronizationSource> {
        self.synchronization_sources.iter()
    }

    pub(super) fn kind(&self) -> RtpCodecKind {
        self.receiver_track.kind()
    }

    pub(super) fn get_codecs(
        codecs: &[RTCRtpCodecParameters],
        kind: RtpCodecKind,
        media_engine: &MediaEngine,
    ) -> Vec<RTCRtpCodecParameters> {
        let media_engine_codecs = media_engine.get_codecs_by_kind(kind);
        if codecs.is_empty() {
            return media_engine_codecs;
        }
        let mut filtered_codecs = vec![];
        for codec in codecs {
            let (c, match_type) = codec_parameters_fuzzy_search(codec, &media_engine_codecs);
            if match_type != CodecMatch::None {
                filtered_codecs.push(c);
            }
        }

        filtered_codecs
    }
}
