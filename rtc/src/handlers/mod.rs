use crate::messages::{RTCEvent, RTCMessage};
use shared::error::Error;
use shared::Transmit;
use std::time::Instant;

//pub mod demuxer;
//pub mod dtls;
//pub mod stun;

pub trait RTCHandler {
    /// Handles input message
    fn handle_transmit(&mut self, msg: Transmit<RTCMessage>) -> Vec<Transmit<RTCMessage>> {
        vec![msg]
    }

    /// Polls output message from internal transmit queue
    fn poll_transmit(&mut self) -> Option<Transmit<RTCMessage>> {
        None
    }

    fn poll_event(&mut self) -> Option<RTCEvent> {
        None
    }

    /// Handles a timeout event
    fn handle_timeout(&mut self, _now: Instant) {}

    /// Polls a timeout event
    fn poll_timeout(&mut self) -> Option<Instant> {
        None
    }

    /// Handle an error event
    fn handle_error(&mut self, _err: Error) {}

    /// Handle a close event
    fn handle_close(&mut self) {}
}
