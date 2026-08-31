use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::interceptor_registry::create_stream_info;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::rtp_contributing_source::{
    RTCRtpContributingSource, RTCRtpSynchronizationSource,
};
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RtpCodecKind, codec_parameters_fuzzy_search, find_fec_payload_type,
    find_rtx_payload_type, is_repair_codec, parse_rtx_apt,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpHeaderExtensionParameters};
use crate::rtp_transceiver::{PayloadType, SSRC};
use interceptor::Interceptor;
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
/// [W3C]: https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface
#[derive(Default, Debug, Clone)]
pub(crate) struct RTCRtpReceiverInternal {
    kind: RtpCodecKind,
    track: MediaStreamTrack,
    contributing_sources: Vec<RTCRtpContributingSource>,
    synchronization_sources: Vec<RTCRtpSynchronizationSource>,
    jitter_buffer_target: Duration,

    receive_codings: Vec<RTCRtpCodingParameters>,
    receive_codecs: Vec<RTCRtpCodecParameters>,

    last_returned_parameters: Option<RTCRtpReceiveParameters>,
}

impl RTCRtpReceiverInternal {
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
            let (c, match_type) =
                codec_parameters_fuzzy_search(&codec.rtp_codec, &media_engine_codecs);
            if match_type != CodecMatch::None {
                filtered_codecs.push(c);
            }
        }

        // Repair codecs survive the filter. They are not alternative media formats to choose
        // between — they accompany whichever primary was chosen — so W3C `setCodecPreferences`
        // leaves them in place, and dropping them here would produce an offer no peer can act on:
        // an `a=ssrc-group:FEC-FR` naming a repair SSRC with no `a=rtpmap:<pt> flexfec-03/90000`
        // to give it a format, and likewise `a=ssrc-group:FID` with no `rtx` codec.
        for codec in &media_engine_codecs {
            if !is_repair_codec(&codec.rtp_codec)
                || filtered_codecs
                    .iter()
                    .any(|filtered| filtered.payload_type == codec.payload_type)
            {
                continue;
            }

            // An RTX codec repairs one specific primary (RFC 4588 `apt`), so it belongs here only
            // when that primary survived. FEC and RED are not bound to a payload type and always do.
            if let Some(apt) = parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)
                && !filtered_codecs
                    .iter()
                    .any(|filtered| filtered.payload_type == apt)
            {
                continue;
            }

            filtered_codecs.push(codec.clone());
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

    pub(crate) fn stop(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<()> {
        self.interceptor_remote_streams_op(media_engine, interceptor, false);

        Ok(())
    }

    /// Binds or unbinds one remote stream, optionally carrying its repair-flow associations.
    ///
    /// RTX ([RFC 4588]) and FEC ([RFC 8888]/FlexFEC) both repair a media stream from a *separate*
    /// SSRC, so both are described the same way: the association travels on the media stream's
    /// `StreamInfo`, telling an interceptor which SSRC carries repair for it. This mirrors what
    /// the sender side already does in `interceptor_local_streams_op`.
    ///
    /// [RFC 4588]: https://datatracker.ietf.org/doc/html/rfc4588
    /// [RFC 8888]: https://datatracker.ietf.org/doc/html/rfc8888
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn interceptor_remote_stream_op(
        interceptor: &mut dyn Interceptor,
        is_binding: bool,
        ssrc: SSRC,
        ssrc_rtx: Option<SSRC>,
        ssrc_fec: Option<SSRC>,
        payload_type: PayloadType,
        payload_type_rtx: Option<PayloadType>,
        payload_type_fec: Option<PayloadType>,
        rtp_codec: &RTCRtpCodec,
        header_extensions: &[RTCRtpHeaderExtensionParameters],
    ) {
        let stream_info = create_stream_info(
            ssrc,
            ssrc_rtx,
            ssrc_fec,
            payload_type,
            payload_type_rtx,
            payload_type_fec,
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
        interceptor: &mut dyn Interceptor,
        is_binding: bool,
    ) {
        let parameters = self.get_parameters(media_engine).clone();

        for coding in self.track().codings() {
            let (codec, match_type) =
                codec_parameters_fuzzy_search(&coding.codec, &parameters.rtp_parameters.codecs);
            if let Some(&ssrc) = coding.rtp_coding_parameters.ssrc.as_ref()
                && match_type != CodecMatch::None
            {
                // Both halves or neither, for each repair flow: a repair SSRC whose payload type
                // was never negotiated is not a usable association, and a half-filled one would
                // open an interceptor's bind gate on a flow it cannot actually demultiplex.
                let rtx = coding.rtp_coding_parameters.rtx.as_ref().and_then(|rtx| {
                    find_rtx_payload_type(codec.payload_type, &parameters.rtp_parameters.codecs)
                        .map(|payload_type| (rtx.ssrc, payload_type))
                });
                let fec = coding.rtp_coding_parameters.fec.as_ref().and_then(|fec| {
                    find_fec_payload_type(&parameters.rtp_parameters.codecs)
                        .map(|payload_type| (fec.ssrc, payload_type))
                });

                RTCRtpReceiverInternal::interceptor_remote_stream_op(
                    interceptor,
                    is_binding,
                    ssrc,
                    rtx.map(|(ssrc_rtx, _)| ssrc_rtx),
                    fec.map(|(ssrc_fec, _)| ssrc_fec),
                    codec.payload_type,
                    rtx.map(|(_, payload_type_rtx)| payload_type_rtx),
                    fec.map(|(_, payload_type_fec)| payload_type_fec),
                    &codec.rtp_codec,
                    &parameters.rtp_parameters.header_extensions,
                );

                // Each repair flow is also bound in its own right, as it has been: it is a real
                // RTP stream with its own SSRC and sequence-number space, and an interceptor that
                // tracks arrival needs to know it exists. RTX and FEC are treated identically
                // here — they are the same shape of thing.
                if let Some((ssrc_rtx, payload_type_rtx)) = rtx {
                    RTCRtpReceiverInternal::interceptor_remote_stream_op(
                        interceptor,
                        is_binding,
                        ssrc_rtx,
                        None,
                        None,
                        payload_type_rtx,
                        None,
                        None,
                        &codec.rtp_codec,
                        &parameters.rtp_parameters.header_extensions,
                    );
                }

                if let Some((ssrc_fec, payload_type_fec)) = fec {
                    RTCRtpReceiverInternal::interceptor_remote_stream_op(
                        interceptor,
                        is_binding,
                        ssrc_fec,
                        None,
                        None,
                        payload_type_fec,
                        None,
                        None,
                        &codec.rtp_codec,
                        &parameters.rtp_parameters.header_extensions,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod repair_association_test {
    //! Repair-flow associations on remote streams (FEC-PRE-01).
    //!
    //! RTX ([RFC 4588]) and FEC (FlexFEC) both repair a media stream from a **separate SSRC**, so
    //! both are described the same way: the association travels on the media stream's
    //! `StreamInfo`. A receive-side FEC interceptor binds on the media stream and gates on the
    //! FEC SSRC and payload type both being present — so an association that never arrives means
    //! the interceptor silently never binds, which is invisible until recovery quietly does not
    //! happen.
    //!
    //! [RFC 4588]: https://datatracker.ietf.org/doc/html/rfc4588

    // Imported explicitly rather than with `use super::*`: the parent module has
    // `shared::error::Result` in scope, and the interceptor macros generate `Result<_, _>`.
    use super::{RTCRtpReceiverInternal, RtpCodecKind};
    use crate::media_stream::track::MediaStreamTrack;
    use crate::peer_connection::configuration::media_engine::{
        MIME_TYPE_FLEX_FEC03, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
    };
    use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
    use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
    use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
    use crate::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpFecParameters, RTCRtpRtxParameters,
    };
    use crate::rtp_transceiver::{PayloadType, SSRC};
    use interceptor::{Interceptor, StreamInfo, TaggedPacket};
    use sansio::Protocol;
    use shared::error::Error;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// Records every remote stream bound and unbound, so a test can assert what the chain was
    /// told rather than what the caller intended.
    #[derive(Default)]
    struct Recorder {
        bound: Arc<Mutex<Vec<StreamInfo>>>,
        unbound: Arc<Mutex<Vec<StreamInfo>>>,
        read_queue: VecDeque<TaggedPacket>,
        write_queue: VecDeque<TaggedPacket>,
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for Recorder {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.read_queue.push_back(msg);
            Ok(())
        }

        fn poll_read(&mut self) -> Option<Self::Rout> {
            self.read_queue.pop_front()
        }

        fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.write_queue.push_back(msg);
            Ok(())
        }

        fn poll_write(&mut self) -> Option<Self::Wout> {
            self.write_queue.pop_front()
        }
    }

    impl Interceptor for Recorder {
        fn bind_local_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _info: &StreamInfo) {}

        fn bind_remote_stream(&mut self, info: &StreamInfo) {
            self.bound.lock().unwrap().push(info.clone());
        }

        fn unbind_remote_stream(&mut self, info: &StreamInfo) {
            self.unbound.lock().unwrap().push(info.clone());
        }
    }

    fn codec(payload_type: PayloadType, mime_type: &str, fmtp: &str) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    /// A media engine offering VP8, its RTX form, and FlexFEC-03.
    ///
    /// FlexFEC is registered explicitly rather than relying on defaults: `register_default_codecs`
    /// does not offer it yet (that is P3A-05, gated on recovery actually working), so a test that
    /// assumed the default would be asserting on a codec the engine never had.
    fn media_engine() -> MediaEngine {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(codec(96, MIME_TYPE_VP8, ""), RtpCodecKind::Video)
            .expect("vp8");
        media_engine
            .register_codec(codec(97, MIME_TYPE_RTX, "apt=96"), RtpCodecKind::Video)
            .expect("rtx");
        media_engine
            .register_codec(codec(98, MIME_TYPE_FLEX_FEC03, ""), RtpCodecKind::Video)
            .expect("flexfec");
        media_engine
    }

    /// A media engine that never negotiated FlexFEC.
    fn media_engine_without_fec() -> MediaEngine {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(codec(96, MIME_TYPE_VP8, ""), RtpCodecKind::Video)
            .expect("vp8");
        media_engine
    }

    fn encoding(
        rid: &str,
        ssrc: SSRC,
        rtx_ssrc: Option<SSRC>,
        fec_ssrc: Option<SSRC>,
    ) -> RTCRtpEncodingParameters {
        RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_owned(),
                ssrc: Some(ssrc),
                rtx: rtx_ssrc.map(|ssrc| RTCRtpRtxParameters { ssrc }),
                fec: fec_ssrc.map(|ssrc| RTCRtpFecParameters { ssrc }),
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }
    }

    /// Runs the bind (or unbind) pass and returns what the chain was told.
    fn run(
        media_engine: &MediaEngine,
        encodings: Vec<RTCRtpEncodingParameters>,
        is_binding: bool,
    ) -> Vec<StreamInfo> {
        let bound = Arc::new(Mutex::new(Vec::new()));
        let unbound = Arc::new(Mutex::new(Vec::new()));
        let mut interceptor = Recorder {
            bound: Arc::clone(&bound),
            unbound: Arc::clone(&unbound),
            ..Default::default()
        };

        let codings = encodings
            .iter()
            .map(|e| e.rtp_coding_parameters.clone())
            .collect();
        let mut receiver = RTCRtpReceiverInternal::new(RtpCodecKind::Video, codings);
        receiver.set_track(MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Video,
            encodings,
        ));

        receiver.interceptor_remote_streams_op(media_engine, &mut interceptor, is_binding);

        let recorded = if is_binding { bound } else { unbound };
        let recorded = recorded.lock().unwrap().clone();
        recorded
    }

    fn primary(streams: &[StreamInfo], ssrc: SSRC) -> &StreamInfo {
        streams
            .iter()
            .find(|info| info.ssrc == ssrc)
            .unwrap_or_else(|| panic!("no stream bound for ssrc {ssrc}; bound: {streams:?}"))
    }

    /// The gap FEC-PRE-01 closes: without this the FEC fields are `None` and a receive-side FEC
    /// interceptor never binds.
    #[test]
    fn the_media_stream_carries_its_fec_association() {
        let streams = run(
            &media_engine(),
            vec![encoding("", 1000, None, Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(
            Some(3000),
            media.ssrc_fec,
            "the media stream must name the SSRC carrying its repair packets"
        );
        assert_eq!(
            Some(98),
            media.payload_type_fec,
            "and the FlexFEC payload type, which is the other half of the interceptor's gate"
        );
    }

    /// RTX and FEC are the same shape of thing — a repair flow on its own SSRC — and are reported
    /// identically. This is the property that keeps the two paths from drifting apart.
    #[test]
    fn rtx_and_fec_associations_are_reported_the_same_way() {
        let streams = run(
            &media_engine(),
            vec![encoding("", 1000, Some(2000), Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(
            (Some(2000), Some(97)),
            (media.ssrc_rtx, media.payload_type_rtx)
        );
        assert_eq!(
            (Some(3000), Some(98)),
            (media.ssrc_fec, media.payload_type_fec)
        );

        // Each repair flow is also bound in its own right, as a real RTP stream with its own
        // sequence-number space — again, both the same way.
        assert!(
            streams.iter().any(|info| info.ssrc == 2000),
            "the RTX flow is bound: {streams:?}"
        );
        assert!(
            streams.iter().any(|info| info.ssrc == 3000),
            "the FEC flow is bound: {streams:?}"
        );
    }

    /// Both halves or neither. A repair SSRC whose payload type was never negotiated is not a
    /// usable association: reporting the SSRC alone would open an interceptor's bind gate on a
    /// flow it cannot demultiplex.
    #[test]
    fn a_repair_ssrc_without_a_negotiated_payload_type_is_not_reported() {
        let streams = run(
            &media_engine_without_fec(),
            vec![encoding("", 1000, None, Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(None, media.ssrc_fec, "no FlexFEC codec was negotiated");
        assert_eq!(None, media.payload_type_fec);
        assert!(
            !streams.iter().any(|info| info.ssrc == 3000),
            "and the unusable repair flow is not bound either: {streams:?}"
        );
    }

    /// Simulcast: every layer has its own repair flow, so the association must be resolved per
    /// coding. Sharing one would point recovery at another layer's packets.
    #[test]
    fn each_simulcast_layer_carries_its_own_repair_flow() {
        let streams = run(
            &media_engine(),
            vec![
                encoding("hi", 1000, Some(2000), Some(3000)),
                encoding("lo", 1001, Some(2001), Some(3001)),
            ],
            true,
        );

        assert_eq!(Some(3000), primary(&streams, 1000).ssrc_fec);
        assert_eq!(Some(3001), primary(&streams, 1001).ssrc_fec);
        assert_eq!(Some(2000), primary(&streams, 1000).ssrc_rtx);
        assert_eq!(Some(2001), primary(&streams, 1001).ssrc_rtx);
    }

    /// Unbinding must describe the same streams binding did, or an interceptor keyed on the
    /// association cannot clean up what it created.
    #[test]
    fn unbinding_reports_the_same_associations() {
        let encodings = vec![encoding("", 1000, Some(2000), Some(3000))];
        let bound = run(&media_engine(), encodings.clone(), true);
        let unbound = run(&media_engine(), encodings, false);

        assert_eq!(
            bound.len(),
            unbound.len(),
            "every bound stream is unbound: bound={bound:?} unbound={unbound:?}"
        );
        let bound_media = primary(&bound, 1000);
        let unbound_media = primary(&unbound, 1000);
        assert_eq!(bound_media.ssrc_fec, unbound_media.ssrc_fec);
        assert_eq!(bound_media.payload_type_fec, unbound_media.payload_type_fec);
        assert_eq!(bound_media.ssrc_rtx, unbound_media.ssrc_rtx);
    }

    /// A stream with no repair flows reports none — the association fields are not filled in
    /// speculatively from whatever the media engine happens to offer.
    #[test]
    fn a_stream_without_repair_flows_reports_no_association() {
        let streams = run(&media_engine(), vec![encoding("", 1000, None, None)], true);

        assert_eq!(
            1,
            streams.len(),
            "only the media stream is bound: {streams:?}"
        );
        let media = primary(&streams, 1000);
        assert_eq!(None, media.ssrc_fec);
        assert_eq!(None, media.payload_type_fec);
        assert_eq!(None, media.ssrc_rtx);
        assert_eq!(None, media.payload_type_rtx);
    }
}
