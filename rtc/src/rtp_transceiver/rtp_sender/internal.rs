use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::interceptor_registry::create_stream_info;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, RtpCodecKind, codec_parameters_fuzzy_search, find_fec_payload_type,
    find_rtx_payload_type,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_send_parameters::RTCRtpSendParameters;
use crate::rtp_transceiver::rtp_sender::set_parameter_options::RTCSetParameterOptions;
use interceptor::Interceptor;
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;
use std::marker::PhantomData;

/// Internal RTP sender implementation.
///
/// This structure manages the state and configuration of an RTP sender,
/// including track association, encoding parameters, codec selection, and negotiation status.
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtcrtpsender-interface
#[derive(Default, Debug, Clone)]
pub(crate) struct RTCRtpSenderInternal<I>
where
    I: Interceptor,
{
    /// The codec kind (audio or video) for this sender
    kind: RtpCodecKind,
    /// The media track being sent
    sender_track: MediaStreamTrack,
    /// Media stream IDs associated with this sender's track
    associated_media_stream_ids: Vec<MediaStreamId>,
    /// Encoding parameters for each simulcast/layered encoding
    send_encodings: Vec<RTCRtpEncodingParameters>,
    /// Negotiated codec parameters
    send_codecs: Vec<RTCRtpCodecParameters>,

    /// Cached parameters returned by get_parameters()
    last_returned_parameters: Option<RTCRtpSendParameters>,

    /// Whether SDP negotiation has occurred for this sender
    negotiated: bool,
    sent: bool,

    _phantom: PhantomData<I>,
}

impl<I> RTCRtpSenderInternal<I>
where
    I: Interceptor,
{
    /// Creates a new RTP sender internal state.
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec kind (audio or video)
    /// * `track` - The media track to send
    /// * `streams` - Media stream IDs to associate with the track (uses track's stream if empty)
    /// * `send_encodings` - Initial encoding parameters for the sender
    pub(crate) fn new(
        kind: RtpCodecKind,
        track: MediaStreamTrack,
        streams: Vec<MediaStreamId>,
        send_encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Self {
        let associated_media_stream_ids = if streams.is_empty() {
            vec![track.stream_id().to_string()]
        } else {
            streams
        };

        Self {
            kind,
            sender_track: track,
            associated_media_stream_ids,
            send_encodings,
            send_codecs: Vec::new(),

            last_returned_parameters: None,
            negotiated: false,
            sent: false,

            _phantom: PhantomData,
        }
    }

    /// Returns the media track being sent.
    pub(crate) fn track(&self) -> &MediaStreamTrack {
        &self.sender_track
    }

    /// Returns the codec kind (audio or video) for this sender.
    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    /// Returns the negotiated codec parameters for this sender.
    ///
    /// These are the codecs that were negotiated during SDP exchange
    /// and are available for sending.
    pub(crate) fn get_send_codecs(&self) -> &[RTCRtpCodecParameters] {
        &self.send_codecs
    }

    /// Returns the RTP capabilities for the specified codec kind.
    ///
    /// Filters codecs by the requested kind and returns available codecs
    /// and header extensions supported by the media engine.
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec kind to query capabilities for
    /// * `media_engine` - The media engine containing codec information
    ///
    /// # Returns
    ///
    /// `None` if the kind is unspecified, otherwise returns the capabilities.
    pub(crate) fn get_capabilities(
        &self,
        kind: RtpCodecKind,
        media_engine: &MediaEngine,
    ) -> Option<RTCRtpCapabilities> {
        if kind == RtpCodecKind::Unspecified {
            return None;
        }

        let rtp_parameters = media_engine
            .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Sendonly);

        Some(RTCRtpCapabilities {
            codecs: self
                .send_codecs
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
    /// Updates the sender's RTP send parameters.
    ///
    /// Validates and applies new encoding parameters including bitrate limits,
    /// frame rates, and resolution scaling.
    ///
    /// # Parameters
    ///
    /// * `parameters` - The new send parameters to apply
    /// * `_set_parameter_options` - Reserved for future options (currently unused)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The number of encodings doesn't match the current configuration
    /// - RIDs don't match between new and existing encodings
    /// - Invalid resolution scaling values are provided (must be >= 1.0)
    pub(crate) fn set_parameters(
        &mut self,
        mut parameters: RTCRtpSendParameters,
        _set_parameter_options: Option<RTCSetParameterOptions>,
    ) -> Result<()> {
        //if transceiver.stopping  {
        //  return Err(Error::InvalidStateError);
        //}

        //if self.last_returned_parameters.is_none() {
        //    return Err(Error::InvalidStateError);
        //}

        // Validate parameters by running the following setParameters validation steps:
        {
            //let codecs = &parameters.rtp_parameters.codecs;
            if parameters.encodings.len() != self.send_encodings.len() {
                return Err(Error::InvalidModificationError);
            }
            for (p, s) in parameters.encodings.iter().zip(self.send_encodings.iter()) {
                if p.rtp_coding_parameters.rid != s.rtp_coding_parameters.rid {
                    return Err(Error::InvalidModificationError);
                }
            }

            if self.kind() == RtpCodecKind::Audio {
                parameters.encodings.retain(|encoding| {
                    encoding.scale_resolution_down_by.is_none() && encoding.max_framerate.is_none()
                });
            } else {
                // Video
                parameters.encodings.iter_mut().for_each(|encoding| {
                    encoding.scale_resolution_down_by.get_or_insert(1.0);
                });

                if parameters
                    .encodings
                    .iter()
                    .any(|e| e.scale_resolution_down_by.is_some_and(|v| v < 1.0))
                {
                    return Err(Error::RangeError(
                        "scaleResolutionDownBy must be >= 1.0".to_string(),
                    ));
                }
            }
        }

        self.send_encodings = parameters.encodings;
        self.last_returned_parameters = None;

        Ok(())
    }

    /// Returns the sender's current RTP send parameters.
    ///
    /// Constructs and caches the send parameters including codecs, encodings,
    /// and header extensions. Subsequent calls return the cached version until
    /// `set_parameters` is called.
    ///
    /// # Parameters
    ///
    /// * `media_engine` - The media engine containing codec and extension information
    pub(crate) fn get_parameters(&mut self, media_engine: &MediaEngine) -> &RTCRtpSendParameters {
        if self.last_returned_parameters.is_none() {
            let mut rtp_parameters = media_engine
                .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Sendonly);

            rtp_parameters.codecs = self.send_codecs.clone();

            self.last_returned_parameters = Some(RTCRtpSendParameters {
                rtp_parameters,
                transaction_id: math_rand_alpha(16),
                encodings: self.send_encodings.clone(),
            });
        }

        self.last_returned_parameters.as_ref().unwrap()
    }

    /// Replaces the current track with a new media track.
    ///
    /// The new track must be of the same media kind (audio or video) as the existing track.
    ///
    /// # Parameters
    ///
    /// * `track` - The new media track to send
    ///
    /// # Errors
    ///
    /// Returns `Error::ErrRTPSenderNewTrackHasIncorrectKind` if the new track's kind
    /// doesn't match the sender's kind.
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-replacetrack)
    pub(crate) fn replace_track(&mut self, track: MediaStreamTrack) -> Result<()> {
        if self.kind() != track.kind() {
            return Err(Error::ErrRTPSenderNewTrackHasIncorrectKind);
        }

        //if transceiver.stopping  {
        //  return Err(Error::InvalidStateError);
        //}

        self.associated_media_stream_ids = vec![track.stream_id().to_string()];

        self.sender_track = track;

        Ok(())
    }

    /// Returns the media stream IDs associated with this sender's track.
    pub(crate) fn streams(&self) -> &[MediaStreamId] {
        &self.associated_media_stream_ids
    }

    /// Sets the media stream IDs for this sender's track.
    ///
    /// If the streams vector is empty, uses the track's own stream ID.
    ///
    /// # Parameters
    ///
    /// * `streams` - Vector of stream IDs to associate with the track
    pub(crate) fn set_streams(&mut self, streams: Vec<MediaStreamId>) {
        let associated_media_stream_ids = if streams.is_empty() {
            vec![self.sender_track.stream_id().to_string()]
        } else {
            streams
        };
        self.associated_media_stream_ids = associated_media_stream_ids;

        //TODO: https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-setstreams
        // Update the negotiation-needed flag for connection.
    }

    /// Returns whether this sender has been negotiated via SDP.
    pub(crate) fn is_negotiated(&self) -> bool {
        self.negotiated
    }

    /// Marks this sender as having been negotiated.
    pub(crate) fn set_negotiated(&mut self) {
        self.negotiated = true;
    }

    pub(crate) fn has_sent(&self) -> bool {
        self.sent
    }
    pub(crate) fn set_sent(&mut self) {
        self.sent = true;
    }

    /// Stops the sender (placeholder for future implementation).
    pub(crate) fn stop(&mut self, media_engine: &MediaEngine, interceptor: &mut I) -> Result<()> {
        if self.has_sent() && !self.track().codings().is_empty() {
            self.interceptor_local_streams_op(media_engine, interceptor, false);
        }

        self.negotiated = false;
        self.sent = false;

        Ok(())
    }

    /// Sets the preferred codecs for this sender.
    ///
    /// # Parameters
    ///
    /// * `codecs` - Vector of codec parameters in preference order
    pub(crate) fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) {
        self.send_codecs = codecs;
        self.last_returned_parameters = None;
    }

    /// Configures RTX (retransmission) and FEC (forward error correction) for all encodings.
    ///
    /// # Parameters
    ///
    /// * `is_rtx_enabled` - Whether to enable RTX
    /// * `is_fec_enabled` - Whether to enable FEC
    pub(crate) fn configure_rtx_and_fec(&mut self, is_rtx_enabled: bool, is_fec_enabled: bool) {
        for encoding in self.send_encodings.iter_mut() {
            if !is_rtx_enabled {
                encoding.rtp_coding_parameters.rtx = None;
            }
            if !is_fec_enabled {
                encoding.rtp_coding_parameters.fec = None;
            }
        }
    }

    pub(crate) fn interceptor_local_streams_op(
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
                let stream_info = create_stream_info(
                    ssrc,
                    coding
                        .rtp_coding_parameters
                        .rtx
                        .as_ref()
                        .map(|rtx| rtx.ssrc),
                    coding
                        .rtp_coding_parameters
                        .fec
                        .as_ref()
                        .map(|fec| fec.ssrc),
                    codec.payload_type,
                    find_rtx_payload_type(codec.payload_type, &parameters.rtp_parameters.codecs),
                    find_fec_payload_type(&parameters.rtp_parameters.codecs),
                    &codec.rtp_codec,
                    &parameters.rtp_parameters.header_extensions,
                );

                if is_binding {
                    interceptor.bind_local_stream(&stream_info);
                } else {
                    interceptor.unbind_local_stream(&stream_info);
                }
            }
        }
    }
}
