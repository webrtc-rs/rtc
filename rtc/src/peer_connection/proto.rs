use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::message::{RTCEvent, RTCMessage};
use crate::peer_connection::RTCPeerConnection;
use shared::error::Error;
use shared::{Protocol, TaggedBytesMut};
use std::time::Instant;

impl Protocol<TaggedBytesMut, RTCMessage, RTCEvent> for RTCPeerConnection {
    type Rout = RTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;

    fn handle_read(&mut self, _msg: TaggedBytesMut) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        todo!()
    }

    fn handle_write(&mut self, _msg: RTCMessage) -> Result<(), Self::Error> {
        todo!()
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        todo!()
    }

    fn handle_event(&mut self, _evt: RTCEvent) -> Result<(), Self::Error> {
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
