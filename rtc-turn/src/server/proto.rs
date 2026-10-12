use std::net::SocketAddr;
use std::time::Instant;

use bytes::BytesMut;
use shared::TaggedBytesMut;
use shared::error::{Error, Result};
use stun::error_code::ErrorCode;

use super::{AllocationId, Event, Server};

/// Host feedback accepted by the [`sansio::Protocol`] adapter.
#[non_exhaustive]
pub enum HostEvent {
    /// A relay socket bind completed (or failed).
    AllocationComplete {
        /// Caller-supplied current monotonic time.
        now: Instant,
        /// Identity emitted by AllocateRelay.
        allocation_id: AllocationId,
        /// Advertised address on success, normally 508 or 440 on failure.
        result: std::result::Result<SocketAddr, ErrorCode>,
    },
    /// A datagram arrived from a peer on a relay socket.
    PeerData {
        /// Caller-supplied receive time.
        now: Instant,
        /// Socket that received the datagram.
        allocation_id: AllocationId,
        /// Sender's transport address.
        peer: SocketAddr,
        /// Payload without TURN framing.
        data: BytesMut,
    },
}

/// Network actions, including writes, are ordered together through poll_event. The empty
/// read/write outputs avoid splitting socket release and related transmissions across queues.
impl sansio::Protocol<TaggedBytesMut, (), HostEvent> for Server {
    type Rout = ();
    type Wout = ();
    type Eout = Event;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, message: TaggedBytesMut) -> Result<()> {
        self.handle_datagram(message.now, message.transport, &message.message)
    }

    fn poll_read(&mut self) -> Option<()> {
        None
    }

    fn handle_write(&mut self, _: ()) -> Result<()> {
        Ok(())
    }

    fn poll_write(&mut self) -> Option<()> {
        None
    }

    fn handle_event(&mut self, event: HostEvent) -> Result<()> {
        match event {
            HostEvent::AllocationComplete {
                now,
                allocation_id,
                result,
            } => self.complete_allocate(now, allocation_id, result),
            HostEvent::PeerData {
                now,
                allocation_id,
                peer,
                data,
            } => self.handle_peer_data(now, allocation_id, peer, &data),
        }
    }

    fn poll_event(&mut self) -> Option<Event> {
        Server::poll_event(self)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        Server::handle_timeout(self, now)
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        Server::poll_timeout(self)
    }

    fn close(&mut self) -> Result<()> {
        Server::close(self);
        Ok(())
    }
}
