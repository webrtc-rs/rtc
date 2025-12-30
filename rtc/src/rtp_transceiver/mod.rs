//TODO: #[cfg(test)]
//mod rtp_transceiver_test;

use crate::media_stream::track::MediaStreamTrack;
use crate::media_stream::MediaStreamId;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use crate::rtp_transceiver::rtp_sender::rtp_codec::*;
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::rtp_sender::RTCRtpSender;
use log::trace;
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

pub(crate) type RTCRtpTransceiverId = usize;

#[derive(Default, Debug, Clone)]
pub struct RTCRtpSenderId(pub(crate) RTCRtpTransceiverId);

#[derive(Default, Debug, Clone)]
pub struct RTCRtpReceiverId(pub(crate) RTCRtpTransceiverId);

/// RTPTransceiverInit dictionary is used when calling the WebRTC function addTransceiver() to provide configuration options for the new transceiver.
#[derive(Default, Clone)]
pub struct RTCRtpTransceiverInit {
    pub direction: RTCRtpTransceiverDirection,
    pub streams: Vec<MediaStreamId>,
    pub send_encodings: Vec<RTCRtpEncodingParameters>,
}

/// RTPTransceiver represents a combination of an RTPSender and an RTPReceiver that share a common mid.
#[derive(Default, Clone)]
pub struct RTCRtpTransceiver {
    mid: Option<String>,
    sender: RTCRtpSender,
    receiver: RTCRtpReceiver,
    direction: RTCRtpTransceiverDirection,
    current_direction: RTCRtpTransceiverDirection,
    preferred_codecs: Vec<RTCRtpCodecParameters>,
    stopped: bool,
}

impl fmt::Debug for RTCRtpTransceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RTCRtpTransceiver")
            .field("mid", &self.mid)
            .field("sender", &self.sender)
            .field("receiver", &self.receiver)
            .field("direction", &self.direction)
            .field("current_direction", &self.current_direction)
            .field("preferred_codecs", &self.preferred_codecs)
            .field("stopped", &self.stopped)
            .finish()
    }
}

impl RTCRtpTransceiver {
    pub(crate) fn new(
        kind: RtpCodecKind,
        track: Option<MediaStreamTrack>,
        init: RTCRtpTransceiverInit,
    ) -> Self {
        Self {
            mid: None,
            sender: RTCRtpSender::new(kind, track, init.streams, init.send_encodings),
            receiver: RTCRtpReceiver::new(kind),
            direction: init.direction,
            current_direction: RTCRtpTransceiverDirection::Unspecified,
            preferred_codecs: vec![],
            stopped: false,
        }
    }

    /// mid gets the Transceiver's mid value. When not already set, this value will be set in CreateOffer or create_answer.
    pub fn mid(&self) -> &Option<String> {
        &self.mid
    }

    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub fn sender(&self) -> &RTCRtpSender {
        &self.sender
    }
    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub fn sender_mut(&mut self) -> &mut RTCRtpSender {
        &mut self.sender
    }

    /// receiver returns the RTPTransceiver's RTPReceiver if it has one
    pub fn receiver(&self) -> &RTCRtpReceiver {
        &self.receiver
    }

    pub fn receiver_mut(&mut self) -> &mut RTCRtpReceiver {
        &mut self.receiver
    }

    /// direction returns the RTPTransceiver's desired direction.
    pub fn direction(&self) -> RTCRtpTransceiverDirection {
        self.direction
    }

    /// Set the direction of this transceiver. This might trigger a renegotiation.
    pub fn set_direction(&mut self, direction: RTCRtpTransceiverDirection) {
        let previous_direction: RTCRtpTransceiverDirection = self.direction;

        self.direction = direction;

        if direction != previous_direction {
            trace!("Changing direction of transceiver from {previous_direction} to {direction}");

            //TODO: https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction
            // Update the negotiation-needed flag for connection.
        }
    }

    /// current_direction returns the RTPTransceiver's current direction as negotiated.
    ///
    /// If this transceiver has never been negotiated or if it's stopped this returns [`RTCRtpTransceiverDirection::Unspecified`].
    pub fn current_direction(&self) -> RTCRtpTransceiverDirection {
        self.current_direction
    }

    /// stop irreversibly stops the RTPTransceiver
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.direction = RTCRtpTransceiverDirection::Inactive;
        self.current_direction = RTCRtpTransceiverDirection::Inactive;
    }

    /// set_codec_preferences sets preferred list of supported codecs
    /// if codecs is empty or nil we reset to default from MediaEngine
    pub fn set_codec_preferences(
        &mut self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        for codec in &codecs {
            let media_engine_codecs = media_engine.get_codecs_by_kind(self.receiver.kind());
            let (_, match_type) = codec_parameters_fuzzy_search(codec, &media_engine_codecs);
            if match_type == CodecMatch::None {
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            }
        }

        self.preferred_codecs = codecs;

        Ok(())
    }

    /// Codecs returns list of supported codecs
    pub(crate) fn get_codecs(&self, media_engine: &MediaEngine) -> Vec<RTCRtpCodecParameters> {
        RTCRtpReceiver::get_codecs(&self.preferred_codecs, self.kind(), media_engine)
    }

    /// set_mid sets the RTPTransceiver's mid. If it was already set, will return an error.
    pub(crate) fn set_mid(&mut self, mid: String) -> Result<()> {
        if self.mid.is_some() {
            return Err(Error::ErrRTPTransceiverCannotChangeMid);
        }

        self.mid = Some(mid);
        Ok(())
    }

    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.receiver.kind()
    }

    pub(crate) fn stopped(&self) -> bool {
        self.stopped
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
        }

        Ok(())
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
    remote_kind: RtpCodecKind,
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
            t.mid.is_none() && t.kind() == remote_kind && possible_direction == t.direction
        }) {
            return Some(&mut local_transceivers[index]);
        }
    }

    None
}
