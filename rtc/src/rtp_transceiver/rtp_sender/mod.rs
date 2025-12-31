//TODO: #[cfg(test)]
//mod rtp_sender_test;

pub(crate) mod internal;
pub mod rtcp_parameters;
pub mod rtp_capabilities;
pub mod rtp_codec;
pub mod rtp_codec_parameters;
pub mod rtp_coding_parameters;
pub mod rtp_encoding_parameters;
pub mod rtp_header_extension_capability;
pub mod rtp_header_extension_parameters;
pub mod rtp_parameters;
pub mod rtp_receiver_parameters;
pub mod rtp_send_parameters;
pub mod set_parameter_options;

use crate::media_stream::track::MediaStreamTrack;
use crate::media_stream::MediaStreamId;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::message::{RTCMessage, RTPMessage};
use crate::peer_connection::RTCPeerConnection;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use crate::rtp_transceiver::rtp_sender::rtp_send_parameters::RTCRtpSendParameters;
use crate::rtp_transceiver::rtp_sender::set_parameter_options::RTCSetParameterOptions;
use crate::rtp_transceiver::RTCRtpSenderId;
use sansio::Protocol;
use shared::error::{Error, Result};

pub struct RTCRtpSender<'a> {
    pub(crate) id: RTCRtpSenderId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCRtpSender<'_> {
    /// track returns the RTCRtpTransceiver track, or nil
    pub fn track(&self) -> Option<&MediaStreamTrack> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection.rtp_transceivers[self.id.0]
                .sender
                .track()
        } else {
            None
        }
    }

    pub fn get_capabilities(
        &self,
        kind: RtpCodecKind,
        media_engine: &mut MediaEngine,
    ) -> Option<RTCRtpCapabilities> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection.rtp_transceivers[self.id.0]
                .sender
                .get_capabilities(kind, media_engine)
        } else {
            None
        }
    }
    pub fn set_parameters(
        &mut self,
        parameters: RTCRtpSendParameters,
        set_parameter_options: Option<RTCSetParameterOptions>,
    ) -> Result<()> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection.rtp_transceivers[self.id.0]
                .sender
                .set_parameters(parameters, set_parameter_options)
        } else {
            Err(Error::ErrRTPSenderNotExisted)
        }
    }

    /// The getParameters() method returns the RTCRtpSender object's current parameters for
    /// how track is encoded and transmitted to a remote RTCRtpReceiver.
    pub fn get_parameters(
        &mut self,
        media_engine: &mut MediaEngine,
    ) -> Result<RTCRtpSendParameters> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .sender
                .get_parameters(media_engine))
        } else {
            Err(Error::ErrRTPSenderNotExisted)
        }
    }

    /// replace_track replaces the track currently being used as the sender's source with a new TrackLocal.
    /// The new track must be of the same media kind (audio, video, etc) and switching the track should not
    /// require negotiation.
    /// https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-replacetrack
    pub fn replace_track(&mut self, track: Option<MediaStreamTrack>) -> Result<()> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection.rtp_transceivers[self.id.0]
                .sender
                .replace_track(track)
        } else {
            Err(Error::ErrRTPSenderNotExisted)
        }
    }

    pub fn set_streams(&mut self, streams: Vec<MediaStreamId>) -> Result<()> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection.rtp_transceivers[self.id.0]
                .sender
                .set_streams(streams);
            Ok(())
        } else {
            Err(Error::ErrRTPSenderNotExisted)
        }
    }

    pub fn write_rtp(&mut self, packet: rtp::packet::Packet) -> Result<()> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection
                .handle_write(RTCMessage::Rtp(RTPMessage::Rtp(packet)))
        } else {
            Err(Error::ErrRTPSenderNotExisted)
        }
    }

    pub fn write_rtcp(&mut self, packets: Vec<Box<dyn rtcp::packet::Packet>>) -> Result<()> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection
                .handle_write(RTCMessage::Rtp(RTPMessage::Rtcp(packets)))
        } else {
            Err(Error::ErrRTPSenderNotExisted)
        }
    }
}
