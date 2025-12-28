//TODO: #[cfg(test)]
//mod rtp_transceiver_test;

use crate::media::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::media::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use crate::media::rtp_transceiver::rtp_sender::rtp_codec::*;
use crate::media::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::media::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::media::rtp_transceiver::rtp_sender::rtp_header_extension_parameters::RTCRtpHeaderExtensionParameters;
use crate::media::rtp_transceiver::rtp_sender::RTCRtpSender;
use crate::media::track::track_local::TrackLocal;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use interceptor::{
    stream_info::{AssociatedStreamInfo, RTPHeaderExtension, StreamInfo},
    Attributes,
};
use log::trace;
use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};
use std::fmt;

pub mod direction;
pub(crate) mod fmtp;
pub mod rtp_receiver;
pub mod rtp_sender;

/// SSRC represents a synchronization source
/// A synchronization source is a randomly chosen
/// value meant to be globally unique within a particular
/// RTP session. Used to identify a single stream of media.
/// <https://tools.ietf.org/html/rfc3550#section-3>
#[allow(clippy::upper_case_acronyms)]
pub type SSRC = u32;

/// PayloadType identifies the format of the RTP payload and determines
/// its interpretation by the application. Each codec in a RTP Session
/// will have a different PayloadType
/// <https://tools.ietf.org/html/rfc3550#section-3>
pub type PayloadType = u8;

/// RTPRtxParameters dictionary contains information relating to retransmission (RTX) settings.
/// <https://draft.ortc.org/#dom-rtcrtprtxparameters>
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RTCRtpRtxParameters {
    pub ssrc: SSRC,
}

/// RTPTransceiverInit dictionary is used when calling the WebRTC function addTransceiver() to provide configuration options for the new transceiver.
pub struct RTCRtpTransceiverInit {
    pub direction: RTCRtpTransceiverDirection,
    pub send_encodings: Vec<RTCRtpEncodingParameters>,
    // Streams       []*Track
}

/// RTPTransceiver represents a combination of an RTPSender and an RTPReceiver that share a common mid.
#[derive(Default, Clone)]
pub struct RTCRtpTransceiver {
    pub(crate) mid: Option<String>,
    pub(crate) sender: RTCRtpSender,
    pub(crate) receiver: RTCRtpReceiver,
    pub(crate) direction: RTCRtpTransceiverDirection,
    pub(crate) current_direction: RTCRtpTransceiverDirection,

    pub(crate) codecs: Vec<RTCRtpCodecParameters>, // User provided codecs via set_codec_preferences

    pub(crate) stopped: bool,
    pub(crate) kind: RTPCodecType,
}

impl fmt::Debug for RTCRtpTransceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RTCRtpTransceiver")
            .field("mid", &self.mid)
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("direction", &self.direction)
            .field("current_direction", &self.current_direction)
            .field("codecs", &self.codecs)
            .field("stopped", &self.stopped)
            .field("kind", &self.kind)
            .finish()
    }
}

impl RTCRtpTransceiver {
    pub fn new(
        receiver: RTCRtpReceiver,
        sender: RTCRtpSender,
        direction: RTCRtpTransceiverDirection,
        kind: RTPCodecType,
        codecs: Vec<RTCRtpCodecParameters>,
    ) -> Self {
        Self {
            mid: None,
            sender,
            receiver,
            direction,
            current_direction: RTCRtpTransceiverDirection::Unspecified,

            codecs,
            stopped: false,
            kind,
        }
    }

    /// set_codec_preferences sets preferred list of supported codecs
    /// if codecs is empty or nil we reset to default from MediaEngine
    pub fn set_codec_preferences(
        &mut self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        for codec in &codecs {
            let media_engine_codecs = media_engine.get_codecs_by_kind(self.kind);
            let (_, match_type) = codec_parameters_fuzzy_search(codec, &media_engine_codecs);
            if match_type == CodecMatch::None {
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            }
        }

        self.codecs = codecs;

        Ok(())
    }

    /// Codecs returns list of supported codecs
    pub(crate) fn get_codecs(&self, media_engine: &MediaEngine) -> Vec<RTCRtpCodecParameters> {
        RTCRtpReceiver::get_codecs(&self.codecs, self.kind, media_engine)
    }

    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub fn sender(&self) -> &RTCRtpSender {
        &self.sender
    }
    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub fn sender_mut(&mut self) -> &mut RTCRtpSender {
        &mut self.sender
    }

    /// set_sender_track sets the RTPSender and Track to current transceiver
    pub fn set_sender_track(
        &mut self,
        sender: RTCRtpSender,
        track: Option<TrackLocal>,
    ) -> Result<()> {
        self.set_sender(sender);
        self.set_sending_track(track)
    }

    pub fn set_sender(&mut self, s: RTCRtpSender) {
        self.sender = s;
    }

    /// receiver returns the RTPTransceiver's RTPReceiver if it has one
    pub fn receiver(&self) -> &RTCRtpReceiver {
        &self.receiver
    }

    pub fn receiver_mut(&mut self) -> &mut RTCRtpReceiver {
        &mut self.receiver
    }

    pub(crate) fn set_receiver(&mut self, mut r: RTCRtpReceiver) {
        r.set_transceiver_codecs(Some(self.codecs.clone()));

        self.receiver.set_transceiver_codecs(None);

        self.receiver = r;
    }

    /// set_mid sets the RTPTransceiver's mid. If it was already set, will return an error.
    pub(crate) fn set_mid(&mut self, mid: String) -> Result<()> {
        if self.mid.is_some() {
            return Err(Error::ErrRTPTransceiverCannotChangeMid);
        }

        self.mid = Some(mid);
        Ok(())
    }

    /// mid gets the Transceiver's mid value. When not already set, this value will be set in CreateOffer or create_answer.
    pub fn mid(&self) -> &Option<String> {
        &self.mid
    }

    /// kind returns RTPTransceiver's kind.
    pub fn kind(&self) -> RTPCodecType {
        self.kind
    }

    /// direction returns the RTPTransceiver's desired direction.
    pub fn direction(&self) -> RTCRtpTransceiverDirection {
        self.direction
    }

    /// Set the direction of this transceiver. This might trigger a renegotiation.
    pub fn set_direction(&mut self, d: RTCRtpTransceiverDirection) {
        let previous: RTCRtpTransceiverDirection = self.direction;

        self.direction = d;

        if d != previous {
            trace!("Changing direction of transceiver from {previous} to {d}");
        }
    }

    /// current_direction returns the RTPTransceiver's current direction as negotiated.
    ///
    /// If this transceiver has never been negotiated or if it's stopped this returns [`RTCRtpTransceiverDirection::Unspecified`].
    pub fn current_direction(&self) -> RTCRtpTransceiverDirection {
        if self.stopped {
            return RTCRtpTransceiverDirection::Unspecified;
        }

        self.current_direction
    }
    pub(crate) fn set_current_direction(&mut self, d: RTCRtpTransceiverDirection) {
        let previous: RTCRtpTransceiverDirection = self.current_direction;
        self.current_direction = d;

        if d != previous {
            trace!("Changing current direction of transceiver from {previous} to {d}",);
        }
    }

    /// Perform any subsequent actions after altering the transceiver's direction.
    ///
    /// After changing the transceiver's direction this method should be called to perform any
    /// side-effects that results from the new direction, such as pausing/resuming the RTP receiver.
    pub(crate) fn process_new_current_direction(
        &self,
        previous_direction: RTCRtpTransceiverDirection,
    ) -> Result<()> {
        if self.stopped {
            return Ok(());
        }

        let current_direction = self.current_direction;
        if previous_direction != current_direction {
            let mid = &self.mid;
            trace!(
                    "Processing transceiver({mid:?}) direction change from {previous_direction} to {current_direction}"
                );
        } else {
            // no change.
            return Ok(());
        }

        /*TODO:
        {
            let receiver = self.receiver.lock().await;
            let pause_receiver = !current_direction.has_recv();

            if pause_receiver {
                receiver.pause().await?;
            } else {
                receiver.resume().await?;
            }
        }

        let pause_sender = !current_direction.has_send();
        {
            let sender = &*self.sender.lock().await;
            sender.set_paused(pause_sender);
        }*/

        Ok(())
    }

    /*
        /// stop irreversibly stops the RTPTransceiver
        pub fn stop(&self) -> Result<()> {
            if self.stopped.load(Ordering::SeqCst) {
                return Ok(());
            }

            self.stopped.store(true, Ordering::SeqCst);

            {
                let sender = self.sender.lock().await;
                sender.stop().await?;
            }
            {
                let r = self.receiver.lock().await;
                r.stop().await?;
            }

            self.set_direction_internal(RTCRtpTransceiverDirection::Inactive);

            Ok(())
        }
    */
    pub(crate) fn set_sending_track(&mut self, track: Option<TrackLocal>) -> Result<()> {
        let track_is_none = track.is_none();
        self.sender.replace_track(track)?;

        let direction = self.direction();
        let should_send = !track_is_none;
        let should_recv = direction.has_recv();
        self.set_direction(RTCRtpTransceiverDirection::from_send_recv(
            should_send,
            should_recv,
        ));

        Ok(())
    }
}

pub(crate) fn create_stream_info(
    id: String,
    ssrc: SSRC,
    payload_type: PayloadType,
    codec: RTCRtpCodec,
    webrtc_header_extensions: &[RTCRtpHeaderExtensionParameters],
    associated_stream: Option<AssociatedStreamInfo>,
) -> StreamInfo {
    let header_extensions: Vec<RTPHeaderExtension> = webrtc_header_extensions
        .iter()
        .map(|h| RTPHeaderExtension {
            id: h.id,
            uri: h.uri.clone(),
        })
        .collect();

    let feedbacks: Vec<_> = codec
        .rtcp_feedback
        .iter()
        .map(|f| interceptor::stream_info::RTCPFeedback {
            typ: f.typ.clone(),
            parameter: f.parameter.clone(),
        })
        .collect();

    StreamInfo {
        id,
        attributes: Attributes::new(),
        ssrc,
        payload_type,
        rtp_header_extensions: header_extensions,
        mime_type: codec.mime_type,
        clock_rate: codec.clock_rate,
        channels: codec.channels,
        sdp_fmtp_line: codec.sdp_fmtp_line,
        rtcp_feedback: feedbacks,
        associated_stream,
    }
}

pub(crate) fn find_by_mid(mid: &String, local_transceivers: &[RTCRtpTransceiver]) -> Option<usize> {
    local_transceivers
        .iter()
        .enumerate()
        .find(|(_i, t)| t.mid.as_ref() == Some(mid))
        .map(|(i, _v)| i)
}

/// Given a direction+type pluck a transceiver from the passed list
/// if no entry satisfies the requested type+direction return a inactive Transceiver
pub(crate) fn satisfy_type_and_direction(
    remote_kind: RTPCodecType,
    remote_direction: RTCRtpTransceiverDirection,
    local_transceivers: &mut [RTCRtpTransceiver],
) -> Option<&mut RTCRtpTransceiver> {
    // Get direction order from most preferred to least
    let get_preferred_directions = || -> Vec<RTCRtpTransceiverDirection> {
        match remote_direction {
            RTCRtpTransceiverDirection::Sendrecv => vec![
                RTCRtpTransceiverDirection::Recvonly,
                RTCRtpTransceiverDirection::Sendrecv,
            ],
            RTCRtpTransceiverDirection::Sendonly => vec![RTCRtpTransceiverDirection::Recvonly],
            RTCRtpTransceiverDirection::Recvonly => vec![
                RTCRtpTransceiverDirection::Sendonly,
                RTCRtpTransceiverDirection::Sendrecv,
            ],
            _ => vec![],
        }
    };

    for possible_direction in get_preferred_directions() {
        // Find the index first to avoid multiple mutable borrows
        if let Some(index) = local_transceivers.iter().position(|t| {
            t.mid.is_none() && t.kind == remote_kind && possible_direction == t.direction
        }) {
            return Some(&mut local_transceivers[index]);
        }
    }

    None
}
