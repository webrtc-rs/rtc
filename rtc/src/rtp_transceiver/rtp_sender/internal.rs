use crate::media_stream::track::MediaStreamTrack;
use crate::media_stream::MediaStreamId;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_send_parameters::RTCRtpSendParameters;
use crate::rtp_transceiver::rtp_sender::set_parameter_options::RTCSetParameterOptions;

use shared::error::{Error, Result};
use shared::util::math_rand_alpha;

/// RTPSender allows an application to control how a given Track is encoded and transmitted to a remote peer
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtcrtpsender-interface
#[derive(Default, Debug, Clone)]
pub(crate) struct RTCRtpSenderInternal {
    kind: RtpCodecKind,
    sender_track: MediaStreamTrack,
    associated_media_stream_ids: Vec<MediaStreamId>,
    send_encodings: Vec<RTCRtpEncodingParameters>,
    send_codecs: Vec<RTCRtpCodecParameters>,

    last_returned_parameters: Option<RTCRtpSendParameters>,
    negotiated: bool,
}

impl RTCRtpSenderInternal {
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
        }
    }

    /// track returns the RTCRtpTransceiver track, or nil
    pub(crate) fn track(&self) -> &MediaStreamTrack {
        &self.sender_track
    }

    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
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

    /// The getParameters() method returns the RTCRtpSender object's current parameters for
    /// how track is encoded and transmitted to a remote RTCRtpReceiver.
    pub(crate) fn get_parameters(
        &mut self,
        media_engine: &mut MediaEngine,
    ) -> &RTCRtpSendParameters {
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

    /// replace_track replaces the track currently being used as the sender's source with a new TrackLocal.
    /// The new track must be of the same media kind (audio, video, etc) and switching the track should not
    /// require negotiation.
    /// https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-replacetrack
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

    pub(crate) fn streams(&self) -> &[MediaStreamId] {
        &self.associated_media_stream_ids
    }

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

    pub(crate) fn negotiated(&self) -> bool {
        self.negotiated
    }

    pub(crate) fn set_negotiated(&mut self) {
        self.negotiated = true;
    }

    pub(crate) fn stop(&mut self) -> Result<()> {
        //TODO:
        Ok(())
    }
}
