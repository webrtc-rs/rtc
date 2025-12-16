use crate::data_channel::{RTCDataChannelId, RTCDataChannelInternal};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::message::TaggedRTCMessage;
use crate::peer_connection::RTCPeerConnection;
use shared::error::Error;
use shared::{Protocol, TaggedBytesMut};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Default, Clone)]
pub(crate) struct PeerConnectionInternal {
    pub(crate) data_channels: HashMap<RTCDataChannelId, RTCDataChannelInternal>,
}

impl Protocol<TaggedBytesMut, TaggedRTCMessage, RTCPeerConnectionEvent> for RTCPeerConnection {
    type Rout = TaggedRTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;

    fn handle_read(&mut self, _msg: TaggedBytesMut) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        todo!()
    }

    fn handle_write(&mut self, _msg: TaggedRTCMessage) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        todo!()
    }

    fn handle_event(&mut self, _evt: RTCPeerConnectionEvent) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        todo!()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        todo!()
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        todo!()
    }
}
