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
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # fn example(audio_track: MediaStreamTrack) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build()?;
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
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
//! # use rtc::rtp_transceiver::{RTCRtpTransceiverInit, RTCRtpTransceiverDirection};
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build()?;
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
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::RTCRtpTransceiverDirection;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build()?;
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
//! # use rtc::peer_connection::RTCPeerConnectionBuilder;
//! # use rtc::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
//! # fn example(preferred_codecs: Vec<RTCRtpCodecParameters>) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnectionBuilder::new().build()?;
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

use crate::media_stream::MediaStreamId;
use crate::peer_connection::RTCPeerConnection;
use crate::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
pub use direction::RTCRtpTransceiverDirection;
use interceptor::{Interceptor, NoopInterceptor};
use log::trace;
use shared::error::Result;

pub(crate) mod direction;
pub(crate) mod fmtp;
pub(crate) mod internal;
pub mod rtp_receiver;
pub mod rtp_sender;

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

impl From<RTCRtpSenderId> for RTCRtpTransceiverId {
    fn from(id: RTCRtpSenderId) -> Self {
        id.0
    }
}

impl From<RTCRtpReceiverId> for RTCRtpTransceiverId {
    fn from(id: RTCRtpReceiverId) -> Self {
        id.0
    }
}

/// Identifier for an `RTCRtpSender` within a peer connection.
///
/// Used to reference a specific RTP sender when calling methods like `remove_track`.
#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct RTCRtpSenderId(pub(crate) RTCRtpTransceiverId);

impl From<RTCRtpTransceiverId> for RTCRtpSenderId {
    fn from(id: RTCRtpTransceiverId) -> Self {
        Self(id)
    }
}

/// Identifier for an `RTCRtpReceiver` within a peer connection.
///
/// Used to reference a specific RTP receiver when handling incoming media.
#[derive(Default, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct RTCRtpReceiverId(pub(crate) RTCRtpTransceiverId);

impl From<RTCRtpTransceiverId> for RTCRtpReceiverId {
    fn from(id: RTCRtpTransceiverId) -> Self {
        Self(id)
    }
}

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
    /// The initial direction of the transceiver.
    pub direction: RTCRtpTransceiverDirection,
    /// The stream IDs associated with the transceiver's sender.
    pub streams: Vec<MediaStreamId>,
    /// The encoding parameters to use when sending media.
    pub send_encodings: Vec<RTCRtpEncodingParameters>,
}

/// RTCRtpTransceiver represents a permanent pairing of an RTP sender and RTP receiver that share a common mid.
/// The transceiver manages the direction of media flow and codec preferences.
///
/// # Specification
///
/// See [RTCRtpTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver) in the W3C WebRTC specification.
pub struct RTCRtpTransceiver<'a, I = NoopInterceptor>
where
    I: Interceptor,
{
    pub(crate) id: RTCRtpTransceiverId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection<I>,
}

impl<I> RTCRtpTransceiver<'_, I>
where
    I: Interceptor,
{
    /// Returns the media stream identification tag (mid) for this transceiver.
    ///
    /// The mid uniquely identifies the media description in the SDP. When not already set,
    /// this value will be assigned during `create_offer` or `create_answer`.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-mid).
    pub fn mid(&self) -> &Option<String> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        self.peer_connection.rtp_transceivers[self.id].mid()
    }

    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub fn sender(&self) -> Option<RTCRtpSenderId> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        if self.peer_connection.rtp_transceivers[self.id]
            .sender()
            .is_some()
        {
            Some(RTCRtpSenderId::from(self.id))
        } else {
            None
        }
    }

    /// receiver returns the RTPTransceiver's RTPReceiver if it has one
    pub fn receiver(&self) -> Option<RTCRtpReceiverId> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        if self.peer_connection.rtp_transceivers[self.id]
            .receiver()
            .is_some()
        {
            Some(RTCRtpReceiverId::from(self.id))
        } else {
            None
        }
    }

    /// Returns the preferred direction of the transceiver.
    ///
    /// This indicates the direction that the application prefers for media flow.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub fn direction(&self) -> RTCRtpTransceiverDirection {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        self.peer_connection.rtp_transceivers[self.id].direction()
    }

    /// Sets the preferred direction of this transceiver.
    ///
    /// Changing the direction may trigger renegotiation to update the session description.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub fn set_direction(&mut self, direction: RTCRtpTransceiverDirection) {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        let previous_direction = self.peer_connection.rtp_transceivers[self.id].direction();
        self.peer_connection.rtp_transceivers[self.id].set_direction(direction);
        // Compare the effective direction after the setter (rather than the requested value) so
        // any future normalization inside `set_direction` cannot bypass this check.
        let current_direction = self.peer_connection.rtp_transceivers[self.id].direction();

        // https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction
        // The direction setter is a no-op when the new direction equals the current one;
        // otherwise its final step updates the negotiation-needed flag for the connection,
        // which may fire a `negotiationneeded` event.
        if current_direction != previous_direction {
            trace!(
                "Changing direction of transceiver from {previous_direction} to {current_direction}"
            );
            self.peer_connection.on_transceiver_direction_changed();
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
    pub fn current_direction(&self) -> RTCRtpTransceiverDirection {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        self.peer_connection.rtp_transceivers[self.id].current_direction()
    }

    /// Irreversibly stops the transceiver.
    ///
    /// After calling this method, the transceiver will no longer send or receive media.
    /// This operation cannot be undone.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.stop()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-stop).
    pub fn stop(&mut self) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        self.peer_connection.rtp_transceivers[self.id].stop(
            &self.peer_connection.media_engine,
            &mut self.peer_connection.interceptor,
        )
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
    pub fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized,
        // so, [self.id] here is safe.
        self.peer_connection.rtp_transceivers[self.id]
            .set_codec_preferences(codecs, &self.peer_connection.media_engine)
    }
}

#[cfg(test)]
mod tests {
    use sansio::Protocol;

    use crate::peer_connection::configuration::media_engine::MediaEngine;
    use crate::peer_connection::event::RTCPeerConnectionEvent;
    use crate::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
    use crate::rtp_transceiver::RTCRtpTransceiverDirection;
    use crate::rtp_transceiver::rtp_sender::RtpCodecKind;

    fn build_pc() -> RTCPeerConnection {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .expect("register default codecs");
        RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build()
            .expect("build peer connection")
    }

    /// Drain every queued event and count the `OnNegotiationNeededEvent`s, driving only the
    /// public sans-I/O `Protocol` API (no private negotiation state is touched).
    fn count_negotiation_needed(pc: &mut RTCPeerConnection) -> usize {
        let mut count = 0;
        while let Some(event) = pc.poll_event() {
            if matches!(event, RTCPeerConnectionEvent::OnNegotiationNeededEvent) {
                count += 1;
            }
        }
        count
    }

    /// Complete a full offer/answer exchange so `offerer` settles back into a stable, idle
    /// negotiation state.
    fn negotiate(offerer: &mut RTCPeerConnection, answerer: &mut RTCPeerConnection) {
        let offer = offerer.create_offer(None).expect("create offer");
        offerer
            .set_local_description(offer.clone())
            .expect("offerer set local");
        answerer
            .set_remote_description(offer)
            .expect("answerer set remote");
        let answer = answerer.create_answer(None).expect("create answer");
        answerer
            .set_local_description(answer.clone())
            .expect("answerer set local");
        offerer
            .set_remote_description(answer)
            .expect("offerer set remote");
    }

    #[test]
    fn test_set_direction_triggers_negotiation_on_change() {
        let mut offerer = build_pc();
        let mut answerer = build_pc();

        let tid = offerer
            .add_transceiver_from_kind(RtpCodecKind::Video, None)
            .expect("add offerer transceiver");
        answerer
            .add_transceiver_from_kind(RtpCodecKind::Video, None)
            .expect("add answerer transceiver");

        negotiate(&mut offerer, &mut answerer);
        // Discard events produced by the initial negotiation.
        let _ = count_negotiation_needed(&mut offerer);

        let current = offerer.rtp_transceivers[tid].direction();
        let new_direction = if current == RTCRtpTransceiverDirection::Inactive {
            RTCRtpTransceiverDirection::Sendrecv
        } else {
            RTCRtpTransceiverDirection::Inactive
        };
        offerer
            .rtp_transceiver(tid)
            .expect("transceiver exists")
            .set_direction(new_direction);

        assert_eq!(
            count_negotiation_needed(&mut offerer),
            1,
            "changing the transceiver direction must trigger negotiation-needed",
        );
    }

    #[test]
    fn test_set_direction_noop_when_unchanged() {
        let mut offerer = build_pc();
        let mut answerer = build_pc();

        let tid = offerer
            .add_transceiver_from_kind(RtpCodecKind::Video, None)
            .expect("add offerer transceiver");
        answerer
            .add_transceiver_from_kind(RtpCodecKind::Video, None)
            .expect("add answerer transceiver");

        negotiate(&mut offerer, &mut answerer);
        let _ = count_negotiation_needed(&mut offerer);

        // Setting the current direction again must be a no-op.
        let current = offerer.rtp_transceivers[tid].direction();
        offerer
            .rtp_transceiver(tid)
            .expect("transceiver exists")
            .set_direction(current);

        assert_eq!(
            count_negotiation_needed(&mut offerer),
            0,
            "setting the same direction must not trigger negotiation-needed",
        );
    }
}
