//! An interceptor that hands inbound RTCP to the application.
//!
//! Inbound RTCP stops at the terminus unless something marks it, so a test that wants to *see* what
//! the chain received has to mark it — the same thing an application does, and the reason this
//! looks like an application's interceptor rather than a test fixture.
//!
//! Marking rather than switching is what makes the judgement per-packet: an SFU forwarding PLIs
//! marks those and leaves the receiver reports its own chain is acting on alone. These tests want
//! everything, so [`DeliverRtcp::new`] marks everything; [`DeliverRtcp::matching`] is the shape a
//! real application would reach for.

#![allow(dead_code)]

use rtc_interceptor::{Attribute, Interceptor, Packet, StreamInfo, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use std::collections::VecDeque;
use std::time::Instant;

/// Attaches [`Attribute::DeliverToApplication`] to inbound RTCP the predicate accepts.
pub struct DeliverRtcp {
    predicate: Box<dyn Fn(&TaggedPacket) -> bool + Send + Sync>,
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
}

impl DeliverRtcp {
    /// Mark every inbound RTCP packet.
    pub fn new() -> Self {
        Self::matching(|_| true)
    }

    /// Mark the inbound RTCP packets `predicate` accepts.
    pub fn matching(predicate: impl Fn(&TaggedPacket) -> bool + Send + Sync + 'static) -> Self {
        Self {
            predicate: Box::new(predicate),
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
        }
    }
}

impl Default for DeliverRtcp {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for DeliverRtcp {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        // Marked, not consumed: the packet carries on to the interceptors past this one, which are
        // still entitled to act on it. The terminus reads the mark at the end of the walk.
        if matches!(msg.message.packet, Packet::Rtcp(_)) && (self.predicate)(&msg) {
            msg.message.add(Attribute::DeliverToApplication);
        }
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for DeliverRtcp {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
