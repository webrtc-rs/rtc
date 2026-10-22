//! One client's allocation: the relayed address, and what the client may exchange through it.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use shared::TransportProtocol;
use stun::message::TransactionId;

use super::relay::RelayFamily;

/// Identifies an allocation: the client's address, the server address it talks to, and the
/// transport between them ([RFC 8656 §2.2]).
///
/// [RFC 8656 §2.2]: https://www.rfc-editor.org/rfc/rfc8656#section-2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FiveTuple {
    /// The client's transport address.
    pub client: SocketAddr,
    /// The server address the client sent to.
    pub server: SocketAddr,
    /// UDP or TCP between client and server.
    pub protocol: TransportProtocol,
}

/// A channel bound to a peer.
pub(crate) struct Channel {
    pub(crate) peer: SocketAddr,
    pub(crate) expires: Instant,
}

pub(crate) struct Allocation {
    /// Who created it; later requests on the five-tuple must authenticate as the same user.
    pub(crate) user_id: String,
    /// The local address the relay socket is bound to; peers send here.
    pub(crate) relay: SocketAddr,
    /// The address clients were told (`XOR-RELAYED-ADDRESS`).
    pub(crate) advertised: SocketAddr,
    pub(crate) family: RelayFamily,
    /// Transaction id of the Allocate that created this, so a retransmission of it is answered
    /// with the same success response rather than `437 Allocation Mismatch`.
    pub(crate) allocate_tid: TransactionId,
    pub(crate) expires: Instant,
    /// Peer IP address -> when its permission lapses. Permissions are per IP, not per port.
    pub(crate) permissions: HashMap<IpAddr, Instant>,
    pub(crate) channels: HashMap<u16, Channel>,
    /// The channel number bound to a peer address.
    pub(crate) peer_channels: HashMap<SocketAddr, u16>,
}

impl Allocation {
    pub(crate) fn has_permission(&self, ip: IpAddr, now: Instant) -> bool {
        self.permissions.get(&ip).is_some_and(|&exp| exp > now)
    }

    /// The live channel bound to `peer`, if any.
    pub(crate) fn channel_for(&self, peer: SocketAddr, now: Instant) -> Option<u16> {
        let number = *self.peer_channels.get(&peer)?;
        let channel = self.channels.get(&number)?;
        (channel.expires > now).then_some(number)
    }
}
