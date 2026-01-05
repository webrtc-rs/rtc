//! RTP Media API
//!
//! This module provides the RTCRtpTransceiver, which represents a permanent pairing
//! of an [`RTCRtpSender`](rtp_sender::RTCRtpSender) and an [`RTCRtpReceiver`](rtp_receiver::RTCRtpReceiver),
//! along with shared state.
//!
//! # Overview
//!
//! A transceiver manages bidirectional media exchange for a single media type (audio or video).
//! It combines:
//! - An RTP sender for outgoing media
//! - An RTP receiver for incoming media  
//! - Shared state including direction, mid, and codec preferences
//!
//! # Examples
//!
//! ## Adding a transceiver from a track
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # fn example(audio_track: MediaStreamTrack) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! // Add a transceiver for sending audio
//! let init = RTCRtpTransceiverInit {
//!     direction: RTCRtpTransceiverDirection::Sendrecv,
//!     ..Default::default()
//! };
//!
//! let sender_id = peer_connection
//!     .add_transceiver_from_track(audio_track, Some(init))?;
//!
//! println!("Added sender with ID: {:?}", sender_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Adding a transceiver by media kind
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
//! # use rtc::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! // Add a video transceiver for receiving only
//! let init = RTCRtpTransceiverInit {
//!     direction: RTCRtpTransceiverDirection::Recvonly,
//!     ..Default::default()
//! };
//!
//! let receiver_id = peer_connection
//!     .add_transceiver_from_kind(RtpCodecKind::Video, Some(init))?;
//!
//! println!("Added receiver with ID: {:?}", receiver_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Controlling transceiver direction
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! // Iterate through transceivers and change direction
//! for transceiver_id in peer_connection.get_transceivers() {
//!     // Access the transceiver through peer_connection's internal methods
//!     // Note: Direct transceiver access may be internal API
//!     // This demonstrates the concept - actual usage depends on your API design
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Setting codec preferences
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
//! # fn example(preferred_codecs: Vec<RTCRtpCodecParameters>) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! // Codec preferences would be set through peer connection methods
//! // The exact API depends on your implementation
//! # Ok(())
//! # }
//! ```
//!
//! # Specification
//!
//! See [RTCRtpTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver) in the W3C WebRTC specification.

//TODO: #[cfg(test)]
//mod rtp_transceiver_test;

use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{MIME_TYPE_RTX, MediaEngine};
use crate::peer_connection::sdp::codecs_from_media_description;
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::internal::RTCRtpSenderInternal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::*;
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use log::trace;
use sdp::MediaDescription;
use shared::error::{Error, Result};
use std::collections::HashMap;
use std::fmt;
use unicase::UniCase;

pub(crate) mod direction;
pub(crate) mod fmtp;
pub mod rtp_receiver;
pub mod rtp_sender;

pub use direction::RTCRtpTransceiverDirection;

/// SSRC (Synchronization Source) identifier.
///
/// A synchronization source is a randomly chosen value meant to be globally unique
/// within a particular RTP session. It is used to identify a single stream of media.
///
/// # Specification
///
/// See [RFC 3550 Section 3](https://tools.ietf.org/html/rfc3550#section-3).
#[allow(clippy::upper_case_acronyms)]
pub type SSRC = u32;

/// RTP payload type identifier.
///
/// Identifies the format of the RTP payload and determines its interpretation by the
/// application. Each codec in an RTP session will have a different payload type.
///
/// # Specification
///
/// See [RFC 3550 Section 3](https://tools.ietf.org/html/rfc3550#section-3).
pub type PayloadType = u8;

/// RTP stream identifier.
///
/// Is used for unique identification of RTP stream
///
/// # Specification
///
/// See [RFC 8852 Section 3.1](https://tools.ietf.org/html/rfc8852#section-3.1).
pub type RtpStreamId = String;

/// Repaired RTP stream identifier.
///
/// Is used to identify which stream is to be repaired using a redundancy RTP stream
///
/// # Specification
///
/// See [RFC 8852 Section 3.2](https://tools.ietf.org/html/rfc8852#section-3.2).
pub type RepairedStreamId = String;

/// Internal identifier for an RTP transceiver.
pub type RTCRtpTransceiverId = usize;

/// Identifier for an `RTCRtpSender` within a peer connection.
///
/// Used to reference a specific RTP sender when calling methods like `remove_track`.
#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct RTCRtpSenderId(pub(crate) RTCRtpTransceiverId);

/// Identifier for an `RTCRtpReceiver` within a peer connection.
///
/// Used to reference a specific RTP receiver when handling incoming media.
#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct RTCRtpReceiverId(pub(crate) RTCRtpTransceiverId);

/// Initialization parameters for creating an `RTCRtpTransceiver`.
///
/// Used with `add_transceiver_from_track` or `add_transceiver_from_kind` to configure
/// the transceiver's initial direction and encoding parameters.
///
/// # Specification
///
/// See [RTCRtpTransceiverInit](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiverinit)
#[derive(Default, Clone)]
pub struct RTCRtpTransceiverInit {
    pub direction: RTCRtpTransceiverDirection,
    pub streams: Vec<MediaStreamId>,
    pub send_encodings: Vec<RTCRtpEncodingParameters>,
}

/// Internal representation of an RTP transceiver.
///
/// Represents a permanent pairing of an RTP sender and RTP receiver that share a common mid.
/// The transceiver manages the direction of media flow and codec preferences.
///
/// # Specification
///
/// See [RTCRtpTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver) in the W3C WebRTC specification.
#[derive(Default, Clone)]
pub(crate) struct RTCRtpTransceiver {
    mid: Option<String>,
    kind: RtpCodecKind,
    sender: Option<RTCRtpSenderInternal>,
    receiver: Option<RTCRtpReceiverInternal>,
    direction: RTCRtpTransceiverDirection,
    current_direction: RTCRtpTransceiverDirection,
    preferred_codecs: Vec<RTCRtpCodecParameters>,
    stopped: bool,
}

impl fmt::Debug for RTCRtpTransceiver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RTCRtpTransceiver")
            .field("mid", &self.mid)
            .field("kind", &self.kind)
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
            kind,
            sender: if let Some(track) = track {
                Some(RTCRtpSenderInternal::new(
                    kind,
                    track,
                    init.streams,
                    init.send_encodings,
                ))
            } else {
                None
            },
            receiver: if init.direction.has_recv() {
                Some(RTCRtpReceiverInternal::new(kind, vec![], vec![]))
            } else {
                None
            },
            direction: init.direction,
            current_direction: RTCRtpTransceiverDirection::Unspecified,
            preferred_codecs: vec![],
            stopped: false,
        }
    }

    /// Returns the media stream identification tag (mid) for this transceiver.
    ///
    /// The mid uniquely identifies the media description in the SDP. When not already set,
    /// this value will be assigned during `create_offer` or `create_answer`.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-mid).
    pub(crate) fn mid(&self) -> &Option<String> {
        &self.mid
    }

    /// Returns the media kind (audio or video) of this transceiver.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-mid).
    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub(crate) fn sender(&self) -> &Option<RTCRtpSenderInternal> {
        &self.sender
    }
    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub(crate) fn sender_mut(&mut self) -> &mut Option<RTCRtpSenderInternal> {
        &mut self.sender
    }

    /// receiver returns the RTPTransceiver's RTPReceiver if it has one
    pub(crate) fn receiver(&self) -> &Option<RTCRtpReceiverInternal> {
        &self.receiver
    }

    pub(crate) fn receiver_mut(&mut self) -> &mut Option<RTCRtpReceiverInternal> {
        &mut self.receiver
    }

    /// Returns the preferred direction of the transceiver.
    ///
    /// This indicates the direction that the application prefers for media flow.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub fn direction(&self) -> RTCRtpTransceiverDirection {
        self.direction
    }

    /// Sets the preferred direction of this transceiver.
    ///
    /// Changing the direction may trigger renegotiation to update the session description.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub(crate) fn set_direction(&mut self, direction: RTCRtpTransceiverDirection) {
        let previous_direction: RTCRtpTransceiverDirection = self.direction;

        self.direction = direction;

        if direction != previous_direction {
            trace!("Changing direction of transceiver from {previous_direction} to {direction}");

            //TODO: https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction
            // Update the negotiation-needed flag for connection.
        }
    }

    /// Returns the negotiated direction of the transceiver.
    ///
    /// This indicates the current direction as established by the most recent session description
    /// exchange. If this transceiver has never been negotiated or if it's stopped, this returns
    /// [`RTCRtpTransceiverDirection::Unspecified`].
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.currentDirection](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-currentdirection).
    pub(crate) fn current_direction(&self) -> RTCRtpTransceiverDirection {
        self.current_direction
    }

    /// Irreversibly stops the transceiver.
    ///
    /// After calling this method, the transceiver will no longer send or receive media.
    /// This operation cannot be undone.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.stop()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-stop).
    pub(crate) fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        self.direction = RTCRtpTransceiverDirection::Inactive;
        self.current_direction = RTCRtpTransceiverDirection::Inactive;
    }

    /// Sets the preferred codec list for this transceiver.
    ///
    /// This overrides the default codec preferences from the media engine. If an empty list is
    /// provided, the transceiver resets to use the default codecs from the media engine.
    ///
    /// # Errors
    ///
    /// Returns an error if any codec in the list is not supported by the media engine.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.setCodecPreferences()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-setcodecpreferences).
    pub(crate) fn set_codec_preferences(
        &mut self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        for codec in &codecs {
            let media_engine_codecs = media_engine.get_codecs_by_kind(self.kind());
            let (_, match_type) =
                codec_parameters_fuzzy_search(&codec.rtp_codec, &media_engine_codecs);
            if match_type == CodecMatch::None {
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            }
        }

        if let Some(sender) = self.sender_mut() {
            sender.set_codec_preferences(codecs.clone());
        }

        if let Some(receiver) = self.receiver_mut() {
            receiver.set_codec_preferences(codecs.clone());
        }

        self.preferred_codecs = codecs;

        Ok(())
    }

    pub(crate) fn get_codec_preferences(&self) -> &[RTCRtpCodecParameters] {
        &self.preferred_codecs
    }

    /// Codecs returns list of supported codecs
    pub(crate) fn get_codecs(&self, media_engine: &MediaEngine) -> Vec<RTCRtpCodecParameters> {
        RTCRtpReceiverInternal::get_codecs(&self.preferred_codecs, self.kind(), media_engine)
    }

    /// set_mid sets the RTPTransceiver's mid. If it was already set, will return an error.
    pub(crate) fn set_mid(&mut self, mid: String) -> Result<()> {
        if self.mid.is_some() {
            return Err(Error::ErrRTPTransceiverCannotChangeMid);
        }

        self.mid = Some(mid);
        Ok(())
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

    // match codecs from remote description, used when remote is offerer and creating a transceiver
    // from remote description with the aim of keeping order of codecs in remote description.
    pub(crate) fn set_codec_preferences_from_remote_description(
        &mut self,
        media: &MediaDescription,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        let mut remote_codecs = codecs_from_media_description(media)?;

        // make a copy as this slice is modified
        let mut left_codecs = media_engine.get_codecs_by_kind(self.kind);

        // find codec matches between what is in remote description and
        // the transceivers codecs and use payload type registered to
        // media engine.
        let mut payload_mapping = HashMap::new(); // for RTX re-mapping later
        let mut filter_by_match = |match_filter: CodecMatch| -> Vec<RTCRtpCodecParameters> {
            let mut filtered_codecs = vec![];
            for remote_codec_idx in (0..remote_codecs.len()).rev() {
                let remote_codec = &mut remote_codecs[remote_codec_idx];
                if UniCase::new(remote_codec.rtp_codec.mime_type.as_str())
                    == UniCase::new(MIME_TYPE_RTX)
                {
                    continue;
                }

                let (match_codec, match_type) =
                    codec_parameters_fuzzy_search(&remote_codec.rtp_codec, &left_codecs);
                if match_type == match_filter {
                    payload_mapping.insert(remote_codec.payload_type, match_codec.payload_type);

                    remote_codec.payload_type = match_codec.payload_type;
                    filtered_codecs.push(remote_codec.clone());

                    // removed matched codec for next round
                    remote_codecs.remove(remote_codec_idx);

                    let needle_fmtp = fmtp::parse(
                        match_codec.rtp_codec.mime_type.as_str(),
                        //match_codec.RTPCodecCapability.ClockRate,
                        //match_codec.RTPCodecCapability.Channels,
                        match_codec.rtp_codec.sdp_fmtp_line.as_str(),
                    );

                    for left_codec_idx in (0..left_codecs.len()).rev() {
                        let left_codec = &left_codecs[left_codec_idx];
                        let left_codec_fmtp = fmtp::parse(
                            left_codec.rtp_codec.mime_type.as_str(),
                            //left_codec.RTPCodecCapability.ClockRate,
                            //left_codec.RTPCodecCapability.Channels,
                            left_codec.rtp_codec.sdp_fmtp_line.as_str(),
                        );

                        if needle_fmtp.match_fmtp(&*left_codec_fmtp) {
                            left_codecs.remove(left_codec_idx);
                            break;
                        }
                    }
                }
            }

            filtered_codecs
        };

        let mut filtered_codecs = filter_by_match(CodecMatch::Exact);
        filtered_codecs.append(&mut filter_by_match(CodecMatch::Partial));

        // find RTX associations and add those
        for (remote_payload_type, media_engine_payload_type) in payload_mapping {
            let remote_rtx = find_rtx_payload_type(remote_payload_type, &remote_codecs);
            if remote_rtx.is_none() {
                continue;
            }

            if let Some(media_engine_rtx) =
                find_rtx_payload_type(media_engine_payload_type, &left_codecs)
            {
                for rtx_codec in &left_codecs {
                    if rtx_codec.payload_type == media_engine_rtx {
                        filtered_codecs.push(rtx_codec.clone());
                        break;
                    }
                }
            }
        }

        self.set_codec_preferences(filtered_codecs, media_engine)
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
