use crate::media_stream::track::MediaStreamTrack;
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
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use shared::error::Result;
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
pub(crate) struct RTCRtpReceiverInternal {
    kind: RtpCodecKind,
    receiver_track: MediaStreamTrack,
    contributing_sources: Vec<RTCRtpContributingSource>,
    synchronization_sources: Vec<RTCRtpSynchronizationSource>,
    jitter_buffer_target: Duration,

    receive_codings: Vec<RTCRtpCodingParameters>,
    receive_codecs: Vec<RTCRtpCodecParameters>,

    last_returned_parameters: Option<RTCRtpReceiveParameters>,
}

impl RTCRtpReceiverInternal {
    pub(crate) fn new(
        kind: RtpCodecKind,
        track: MediaStreamTrack,
        receive_codings: Vec<RTCRtpCodingParameters>,
    ) -> Self {
        Self {
            kind,
            receiver_track: track,
            receive_codings,
            ..Default::default()
        }
    }

    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    pub(crate) fn track(&self) -> &MediaStreamTrack {
        &self.receiver_track
    }

    pub(crate) fn get_capabilities(
        &self,
        kind: RtpCodecKind,
        media_engine: &mut MediaEngine,
    ) -> Option<RTCRtpCapabilities> {
        if kind == RtpCodecKind::Unspecified {
            return None;
        }

        let rtp_parameters = media_engine
            .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Recvonly);

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

    pub(crate) fn get_parameters(
        &mut self,
        media_engine: &mut MediaEngine,
    ) -> &RTCRtpReceiveParameters {
        if self.last_returned_parameters.is_none() {
            let mut rtp_parameters = media_engine
                .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Recvonly);

            rtp_parameters.codecs =
                RTCRtpReceiverInternal::get_codecs(&self.receive_codecs, self.kind(), media_engine);

            self.last_returned_parameters = Some(RTCRtpReceiveParameters { rtp_parameters });
        }

        self.last_returned_parameters.as_ref().unwrap()
    }

    pub(crate) fn get_contributing_sources(
        &self,
    ) -> impl Iterator<Item = &RTCRtpContributingSource> {
        self.contributing_sources.iter()
    }

    pub(crate) fn get_synchronization_sources(
        &self,
    ) -> impl Iterator<Item = &RTCRtpSynchronizationSource> {
        self.synchronization_sources.iter()
    }

    pub(crate) fn get_codecs(
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

    pub(crate) fn get_coding_parameters(&self) -> &[RTCRtpCodingParameters] {
        &self.receive_codings
    }

    pub(crate) fn set_coding_parameters(&mut self, receive_codings: Vec<RTCRtpCodingParameters>) {
        self.receive_codings = receive_codings;
    }

    pub(crate) fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) {
        self.receive_codecs = codecs;
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        //TODO:
        Ok(())
    }
}
