//! RTP Receiver implementation following the W3C WebRTC specification.
//!
//! This module provides the [`RTCRtpReceiver`] which represents an RTP receiver
//! as defined in the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface).
//!
//! # Overview
//!
//! An RTP receiver manages the reception of media from a remote peer, providing:
//! - Access to the received media track
//! - RTP capabilities and receive parameters
//! - Contributing source (CSRC) and synchronization source (SSRC) information
//! - Statistics about received media
//!
//! # Examples
//!
//! ## Accessing the received track
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::media_stream::MediaStreamTrackId;
//! # use rtc::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(
//! #     receiver_id: RTCRtpReceiverId,
//! #     track_id: MediaStreamTrackId
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! // Get the receiver and access its track
//! if let Some(receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     let track = receiver.track();
//!     println!("Track ID: {}", track.track_id());
//!     println!("Track kind: {:?}", track.kind());
//!     println!("Track enabled: {}", track.enabled());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting receive parameters
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Get current receive parameters
//!     let params = receiver.get_parameters();
//!     
//!     println!("Codecs: {:?}", params.rtp_parameters.codecs);
//!     println!("Header extensions: {:?}", params.rtp_parameters.header_extensions);
//!     println!("RTCP CNAME: {}", params.rtp_parameters.rtcp.cname);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Checking receiver capabilities
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
//! # use rtc::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! if let Some(receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Check video capabilities
//!     if let Some(capabilities) = receiver.get_capabilities(RtpCodecKind::Video) {
//!         println!("Supported video codecs:");
//!         for codec in capabilities.codecs {
//!             println!("  - {} @ {} Hz", codec.mime_type, codec.clock_rate);
//!         }
//!     
//!         println!("Supported header extensions:");
//!         for ext in capabilities.header_extensions {
//!             println!("  - {}", ext.uri);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting contributing sources
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Get CSRC information for mixed audio
//!     for csrc in receiver.get_contributing_sources() {
//!         println!("CSRC: {}, timestamp: {:?}", csrc.source, csrc.timestamp);
//!         println!("  Audio level: {}", csrc.audio_level);
//!         println!("  RTP timestamp: {}", csrc.rtp_timestamp);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Getting synchronization sources
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # use rtc::rtp_transceiver::RTCRtpReceiverId;
//! # fn example(receiver_id: RTCRtpReceiverId) -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! if let Some(mut receiver) = peer_connection.rtp_receiver(receiver_id) {
//!     // Get SSRC information
//!     for ssrc in receiver.get_synchronization_sources() {
//!         println!("SSRC: {}, timestamp: {:?}", ssrc.source, ssrc.timestamp);
//!         println!("  RTP timestamp: {}", ssrc.rtp_timestamp);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Handling incoming receivers
//!
//! ```no_run
//! # use rtc::peer_connection::RTCPeerConnection;
//! # use rtc::peer_connection::configuration::RTCConfiguration;
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut peer_connection = RTCPeerConnection::new(RTCConfiguration::default())?;
//!
//! // After remote description is set, collect receiver IDs first
//! let receiver_ids: Vec<_> = peer_connection.get_receivers().collect();
//!
//! // Then iterate and process each receiver
//! for receiver_id in receiver_ids {
//!     if let Some(receiver) = peer_connection.rtp_receiver(receiver_id) {
//!         // Access the remote track (track_id would come from signaling)
//!         // Process the incoming media as needed
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Specifications
//!
//! * [W3C RTCRtpReceiver](https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface)
//! * [MDN RTCRtpReceiver](https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpReceiver)

//TODO: #[cfg(test)]
//mod rtp_receiver_test;

pub(crate) mod internal;
pub(crate) mod rtp_contributing_source;

use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::message::RTCMessage;
use crate::rtp_transceiver::RTCRtpReceiverId;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use sansio::Protocol;
use shared::error::Result;

pub use rtp_contributing_source::{RTCRtpContributingSource, RTCRtpSynchronizationSource};

/// Represents an RTP receiver for a media stream track.
///
/// The `RTCRtpReceiver` interface allows an application to inspect the receipt of a
/// [`MediaStreamTrack`] as defined in the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface).
///
/// # Lifetime
///
/// This struct borrows the [`RTCPeerConnection`] mutably, ensuring exclusive access
/// during RTP receiver operations.
pub struct RTCRtpReceiver<'a> {
    pub(crate) id: RTCRtpReceiverId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCRtpReceiver<'_> {
    /// Returns the track associated with this receiver.
    ///
    /// The [`track`](RTCRtpReceiver::track) method returns the [`MediaStreamTrack`] that is
    /// associated with this receiver as specified in the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-track).
    ///
    /// # Returns
    ///
    /// Returns a reference to the [`MediaStreamTrack`] associated with this receiver.
    pub fn track(&self) -> &MediaStreamTrack {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver
            .as_ref()
            .unwrap()
            .track()
    }

    /// Returns the RTP capabilities for the specified codec kind.
    ///
    /// The static [`get_capabilities`](RTCRtpReceiver::get_capabilities) method returns the most
    /// optimistic view of the capabilities of the system for receiving media of the given kind
    /// as defined in the [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-getcapabilities).
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec kind (audio or video)
    ///
    /// # Returns
    ///
    /// Returns the RTP capabilities supported by this receiver for the specified codec kind.
    pub fn get_capabilities(&self, kind: RtpCodecKind) -> Option<RTCRtpCapabilities> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver
            .as_ref()
            .unwrap()
            .get_capabilities(kind, &self.peer_connection.configuration.media_engine)
    }

    /// Returns the RTP receive parameters for this receiver.
    ///
    /// The [`get_parameters`](RTCRtpReceiver::get_parameters) method returns the current parameters
    /// for how the receiver's track is decoded as defined in the
    /// [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-getparameters).
    ///
    /// # Returns
    ///
    /// Returns a reference to the RTP receive parameters.
    pub fn get_parameters(&mut self) -> &RTCRtpReceiveParameters {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver
            .as_mut()
            .unwrap()
            .get_parameters(&self.peer_connection.configuration.media_engine)
    }

    /// Returns an iterator over the contributing sources for this receiver.
    ///
    /// The [`get_contributing_sources`](RTCRtpReceiver::get_contributing_sources) method returns
    /// information about the contributing sources (CSRCs) for the most recent RTP packets
    /// received by this receiver as defined in the
    /// [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-getcontributingsources).
    ///
    /// Contributing sources represent mixers or other entities that have contributed to the
    /// RTP stream.
    ///
    /// # Returns
    ///
    /// Returns an iterator over [`RTCRtpContributingSource`] objects.
    pub fn get_contributing_sources(&self) -> impl Iterator<Item = &RTCRtpContributingSource> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver
            .as_ref()
            .unwrap()
            .get_contributing_sources()
    }

    /// Returns an iterator over the synchronization sources for this receiver.
    ///
    /// The [`get_synchronization_sources`](RTCRtpReceiver::get_synchronization_sources) method
    /// returns information about the synchronization sources (SSRCs) for the most recent RTP
    /// packets received by this receiver as defined in the
    /// [W3C WebRTC specification](https://www.w3.org/TR/webrtc/#dom-rtcrtpreceiver-getsynchronizationsources).
    ///
    /// Synchronization sources represent the original sources of the RTP packets.
    ///
    /// # Returns
    ///
    /// Returns an iterator over [`RTCRtpSynchronizationSource`] objects.
    pub fn get_synchronization_sources(
        &self,
    ) -> impl Iterator<Item = &RTCRtpSynchronizationSource> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.
        self.peer_connection.rtp_transceivers[self.id.0]
            .receiver
            .as_ref()
            .unwrap()
            .get_synchronization_sources()
    }

    /// Writes RTCP feedback packets for this receiver.
    ///
    /// This method allows sending receiver-side RTCP feedback such as:
    /// - Receiver Reports (RR)
    /// - Picture Loss Indication (PLI)
    /// - Full Intra Request (FIR)
    /// - Negative Acknowledgements (NACK)
    ///
    /// # Parameters
    ///
    /// * `packets` - A vector of RTCP packets to send
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the packets were queued successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if internal handle_write returns error
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Send a Picture Loss Indication to request a keyframe
    /// use rtcp::picture_loss_indication::PictureLossIndication;
    ///
    /// let pli = PictureLossIndication {
    ///     sender_ssrc: 0,
    ///     media_ssrc: remote_ssrc,
    /// };
    /// receiver.write_rtcp(vec![Box::new(pli)])?;
    /// ```
    pub fn write_rtcp(&mut self, packets: Vec<Box<dyn rtcp::Packet>>) -> Result<()> {
        // peer_connection is mutable borrow, its rtp_transceivers won't be resized and
        // the direction won't be changed too, so, unwrap() here is safe.

        //TODO: handle rtcp media ssrc, header extension, etc.
        let receiver = self.peer_connection.rtp_transceivers[self.id.0]
            .receiver
            .as_mut()
            .unwrap();

        let track_id = receiver.track().track_id().to_string();
        self.peer_connection
            .handle_write(RTCMessage::RtcpPacket(track_id, packets))
    }
}
