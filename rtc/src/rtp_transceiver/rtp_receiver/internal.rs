use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::rtp_contributing_source::{
    RTCRtpContributingSource, RTCRtpSynchronizationSource,
};
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RtpCodecKind, codec_parameters_fuzzy_search, find_fec_payload_type,
    find_rtx_payload_type,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpHeaderExtensionParameters};
use crate::rtp_transceiver::{PayloadType, SSRC, create_stream_info};
use interceptor::Interceptor;
use shared::error::Result;
use std::marker::PhantomData;
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
pub(crate) struct RTCRtpReceiverInternal<I>
where
    I: Interceptor,
{
    kind: RtpCodecKind,
    track: MediaStreamTrack,
    contributing_sources: Vec<RTCRtpContributingSource>,
    synchronization_sources: Vec<RTCRtpSynchronizationSource>,
    jitter_buffer_target: Duration,

    receive_codings: Vec<RTCRtpCodingParameters>,
    receive_codecs: Vec<RTCRtpCodecParameters>,

    last_returned_parameters: Option<RTCRtpReceiveParameters>,

    _phantom: PhantomData<I>,
}

impl<I> RTCRtpReceiverInternal<I>
where
    I: Interceptor,
{
    pub(crate) fn new(kind: RtpCodecKind, receive_codings: Vec<RTCRtpCodingParameters>) -> Self {
        Self {
            kind,
            track: Default::default(),
            contributing_sources: vec![],
            synchronization_sources: vec![],
            jitter_buffer_target: Default::default(),
            receive_codings,

            receive_codecs: vec![],
            last_returned_parameters: None,
            _phantom: PhantomData,
        }
    }

    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    pub(crate) fn track(&self) -> &MediaStreamTrack {
        &self.track
    }

    pub(crate) fn track_mut(&mut self) -> &mut MediaStreamTrack {
        &mut self.track
    }

    pub(crate) fn get_capabilities(
        &self,
        kind: RtpCodecKind,
        media_engine: &MediaEngine,
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
        media_engine: &MediaEngine,
    ) -> &RTCRtpReceiveParameters {
        if self.last_returned_parameters.is_none() {
            let mut rtp_parameters = media_engine
                .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Recvonly);

            rtp_parameters.codecs = RTCRtpReceiverInternal::<I>::get_codecs(
                &self.receive_codecs,
                self.kind(),
                media_engine,
            );

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
            let (c, match_type) =
                codec_parameters_fuzzy_search(&codec.rtp_codec, &media_engine_codecs);
            if match_type != CodecMatch::None {
                filtered_codecs.push(c);
            }
        }

        filtered_codecs
    }

    pub(crate) fn get_coding_parameters(&self) -> &[RTCRtpCodingParameters] {
        &self.receive_codings
    }

    pub(crate) fn get_coding_parameter_mut_by_rid(
        &mut self,
        rid: &str,
    ) -> Option<&mut RTCRtpCodingParameters> {
        self.receive_codings
            .iter_mut()
            .find(|coding| coding.rid.as_str() == rid)
    }

    pub(crate) fn set_coding_parameters(&mut self, receive_codings: Vec<RTCRtpCodingParameters>) {
        self.receive_codings = receive_codings;
        //TODO: if get_parameters is changed to use receive_codings to return it in RTCRtpReceiveParameters
        // self.last_returned_parameters = None;
    }

    pub(crate) fn get_codec_preferences(&self) -> &[RTCRtpCodecParameters] {
        &self.receive_codecs
    }

    pub(crate) fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) {
        self.receive_codecs = codecs;
        self.last_returned_parameters = None;
    }

    pub(crate) fn set_track(&mut self, track: MediaStreamTrack) {
        self.track = track;
    }

    pub(crate) fn stop(&mut self, media_engine: &MediaEngine, interceptor: &mut I) -> Result<()> {
        self.interceptor_remote_streams_op(media_engine, interceptor, false);

        Ok(())
    }

    pub(crate) fn interceptor_remote_stream_op(
        interceptor: &mut I,
        is_binding: bool,
        ssrc: SSRC,
        payload_type: PayloadType,
        rtp_codec: &RTCRtpCodec,
        header_extensions: &[RTCRtpHeaderExtensionParameters],
    ) {
        let stream_info = create_stream_info(
            ssrc,
            None,
            None,
            payload_type,
            None,
            None,
            rtp_codec,
            header_extensions,
        );

        if is_binding {
            interceptor.bind_remote_stream(&stream_info);
        } else {
            interceptor.unbind_remote_stream(&stream_info);
        }
    }

    pub(crate) fn interceptor_remote_streams_op(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut I,
        is_binding: bool,
    ) {
        let parameters = self.get_parameters(media_engine).clone();

        for coding in self.track().codings() {
            let (codec, match_type) =
                codec_parameters_fuzzy_search(&coding.codec, &parameters.rtp_parameters.codecs);
            if let Some(&ssrc) = coding.rtp_coding_parameters.ssrc.as_ref()
                && match_type != CodecMatch::None
            {
                RTCRtpReceiverInternal::interceptor_remote_stream_op(
                    interceptor,
                    is_binding,
                    ssrc,
                    codec.payload_type,
                    &codec.rtp_codec,
                    &parameters.rtp_parameters.header_extensions,
                );

                if let Some(rtx) = coding.rtp_coding_parameters.rtx.as_ref() {
                    RTCRtpReceiverInternal::interceptor_remote_stream_op(
                        interceptor,
                        is_binding,
                        rtx.ssrc,
                        find_rtx_payload_type(
                            codec.payload_type,
                            &parameters.rtp_parameters.codecs,
                        )
                        .unwrap_or_default(),
                        &codec.rtp_codec,
                        &parameters.rtp_parameters.header_extensions,
                    );
                }

                if let Some(fec) = coding.rtp_coding_parameters.fec.as_ref() {
                    RTCRtpReceiverInternal::interceptor_remote_stream_op(
                        interceptor,
                        is_binding,
                        fec.ssrc,
                        find_fec_payload_type(&parameters.rtp_parameters.codecs)
                            .unwrap_or_default(),
                        &codec.rtp_codec,
                        &parameters.rtp_parameters.header_extensions,
                    );
                }
            }
        }
    }
}
