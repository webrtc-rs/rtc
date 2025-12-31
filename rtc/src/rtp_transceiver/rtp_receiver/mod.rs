//TODO: #[cfg(test)]
//mod rtp_receiver_test;

pub(crate) mod internal;
pub(crate) mod rtp_contributing_source;

use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::RTCPeerConnection;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use crate::rtp_transceiver::RTCRtpReceiverId;

use crate::rtp_transceiver::rtp_receiver::rtp_contributing_source::{
    RTCRtpContributingSource, RTCRtpSynchronizationSource,
};
use shared::error::{Error, Result};

pub struct RTCRtpReceiver<'a> {
    pub(crate) id: RTCRtpReceiverId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCRtpReceiver<'_> {
    pub fn track(&self) -> Option<&MediaStreamTrack> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
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
                .receiver
                .get_capabilities(kind, media_engine)
        } else {
            None
        }
    }

    pub fn get_parameters(
        &self,
        media_engine: &mut MediaEngine,
    ) -> Result<RTCRtpReceiveParameters> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .get_parameters(media_engine))
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }

    pub fn get_contributing_sources(
        &self,
    ) -> Result<impl Iterator<Item = &RTCRtpContributingSource>> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .get_contributing_sources())
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }

    pub fn get_synchronization_sources(
        &self,
    ) -> Result<impl Iterator<Item = &RTCRtpSynchronizationSource>> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len() {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .get_synchronization_sources())
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }
}
