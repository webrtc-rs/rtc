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
use sansio::Protocol;

use crate::peer_connection::message::{RTCMessage, RTPMessage};
use crate::rtp_transceiver::rtp_receiver::rtp_contributing_source::{
    RTCRtpContributingSource, RTCRtpSynchronizationSource,
};
use shared::error::{Error, Result};

pub struct RTCRtpReceiver<'a> {
    pub(crate) id: RTCRtpReceiverId,
    pub(crate) peer_connection: &'a mut RTCPeerConnection,
}

impl RTCRtpReceiver<'_> {
    pub fn track(&self) -> Result<&MediaStreamTrack> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len()
            && self.peer_connection.rtp_transceivers[self.id.0]
                .direction()
                .has_recv()
        {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .as_ref()
                .ok_or(Error::ErrRTPReceiverNotExisted)?
                .track())
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }

    pub fn get_capabilities(
        &self,
        kind: RtpCodecKind,
        media_engine: &mut MediaEngine,
    ) -> Result<RTCRtpCapabilities> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len()
            && self.peer_connection.rtp_transceivers[self.id.0]
                .direction()
                .has_recv()
        {
            self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .as_ref()
                .ok_or(Error::ErrRTPReceiverNotExisted)?
                .get_capabilities(kind, media_engine)
                .ok_or(Error::ErrRTPReceiverNotExisted)
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }

    pub fn get_parameters(
        &self,
        media_engine: &mut MediaEngine,
    ) -> Result<RTCRtpReceiveParameters> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len()
            && self.peer_connection.rtp_transceivers[self.id.0]
                .direction()
                .has_recv()
        {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .as_ref()
                .ok_or(Error::ErrRTPReceiverNotExisted)?
                .get_parameters(media_engine))
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }

    pub fn get_contributing_sources(
        &self,
    ) -> Result<impl Iterator<Item = &RTCRtpContributingSource>> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len()
            && self.peer_connection.rtp_transceivers[self.id.0]
                .direction()
                .has_recv()
        {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .as_ref()
                .ok_or(Error::ErrRTPReceiverNotExisted)?
                .get_contributing_sources())
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }

    pub fn get_synchronization_sources(
        &self,
    ) -> Result<impl Iterator<Item = &RTCRtpSynchronizationSource>> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len()
            && self.peer_connection.rtp_transceivers[self.id.0]
                .direction()
                .has_recv()
        {
            Ok(self.peer_connection.rtp_transceivers[self.id.0]
                .receiver
                .as_ref()
                .ok_or(Error::ErrRTPReceiverNotExisted)?
                .get_synchronization_sources())
        } else {
            Err(Error::ErrRTPReceiverNotExisted)
        }
    }

    /// Write Receiver-related RTCP feedback
    pub fn write_rtcp(&mut self, packets: Vec<Box<dyn rtcp::Packet>>) -> Result<()> {
        if self.id.0 < self.peer_connection.rtp_transceivers.len()
            && self.peer_connection.rtp_transceivers[self.id.0]
                .direction()
                .has_recv()
        {
            //TODO: handle rtcp media ssrc, header extension, etc.
            self.peer_connection
                .handle_write(RTCMessage::Rtp(RTPMessage::Rtcp(packets)))
        } else {
            Err(Error::ErrRTPSenderNotExisted)
        }
    }
}
