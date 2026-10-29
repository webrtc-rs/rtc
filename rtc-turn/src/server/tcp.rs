//! TCP allocations ([RFC 6062]): a client asks for a relay that speaks TCP to peers, and each peer
//! gets a data connection of its own.
//!
//! The server owns no sockets, so the application does the connecting, and tells the server how it
//! went. The flow, for a connection the client opens towards a peer:
//!
//! 1. The client's `Allocate` (over TCP, with `REQUESTED-TRANSPORT` TCP) asks the application to
//!    bind a TCP listener at the relay address: [`ServerEvent::BindRelayTcp`], answered with
//!    [`Server::relay_bound`] as for UDP.
//! 2. The client's `Connect` names a peer. The server asks the application to open a TCP
//!    connection to it *from the relay address*: [`ServerEvent::ConnectPeer`], answered with
//!    [`Server::peer_connected`] or [`Server::peer_connect_failed`]. On success the client is told
//!    the `CONNECTION-ID` of that peer connection.
//! 3. The client opens a second TCP connection to the server and sends `ConnectionBind` with that
//!    id, authenticating as before. The server answers, then asks the application to splice the
//!    two connections: [`ServerEvent::BindData`]. From then on the bytes are the application's —
//!    they are not fed to the server again.
//!
//! For a connection a peer opens to the relay address, the application calls
//! [`Server::peer_accepted`]; the server tells the client with a `ConnectionAttempt` indication
//! and the client binds a data connection as in step 3.
//!
//! A connection that no data connection is bound to within [`CONNECTION_BIND_TIMEOUT`] is closed
//! ([`ServerEvent::ClosePeer`]), as is every connection of an allocation that ends.
//!
//! [RFC 6062]: https://www.rfc-editor.org/rfc/rfc6062

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::RngExt;
use shared::{TaggedBytesMut, TransportContext};
use stun::message::{
    CLASS_INDICATION, METHOD_CONNECTION_ATTEMPT, Message, MessageType, Setter, TransactionId,
};

use super::{Server, ServerEvent, Timer};
use crate::proto::connid::ConnectionId;
use crate::proto::peeraddr::PeerAddress;

use super::allocation::FiveTuple;

/// How long the server waits for the application to connect to a peer, and for a client to bind a
/// data connection to a peer connection: at least thirty seconds ([RFC 6062 §5.2, §5.3]).
///
/// [RFC 6062 §5.2, §5.3]: https://www.rfc-editor.org/rfc/rfc6062#section-5.2
pub const CONNECTION_BIND_TIMEOUT: Duration = Duration::from_secs(30);

/// The most peer connections one TCP allocation may have at once, being opened or open. A client
/// holds state on the server for each, so an allocation cannot be allowed an unbounded number.
pub const MAX_PEER_CONNECTIONS_PER_ALLOCATION: usize = 256;

/// Identifies one peer connection the server has asked the application to open, or told it about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerConnId(pub u64);

/// Where a peer connection has got to.
pub(super) enum PeerStage {
    /// A `Connect` is waiting for the application to open the connection.
    Connecting {
        request: Message,
        reply_to: TransportContext,
        key: Vec<u8>,
    },
    /// The peer connection is open; no data connection is bound to it yet.
    Waiting,
    /// A data connection is bound; the application is splicing the two.
    Bound,
}

pub(super) struct PeerConn {
    /// The allocation it belongs to.
    pub(super) five: FiveTuple,
    pub(super) user_id: String,
    pub(super) relay: SocketAddr,
    pub(super) peer: SocketAddr,
    /// What the client names it by; 0 until the connection is open.
    pub(super) connection_id: u32,
    pub(super) stage: PeerStage,
    pub(super) timer: Option<(Instant, u64)>,
}

impl Server {
    /// Reports that the application opened the connection a [`ServerEvent::ConnectPeer`] asked
    /// for. The client is answered with the connection's id.
    pub fn peer_connected(&mut self, id: PeerConnId, now: Instant) {
        let Some(conn) = self.tcp_peers.get_mut(&id) else {
            // The request timed out or its allocation ended: the connection is not wanted.
            self.events.push_back(ServerEvent::ClosePeer(id));
            return;
        };
        let PeerStage::Connecting {
            request,
            reply_to,
            key,
        } = std::mem::replace(&mut conn.stage, PeerStage::Waiting)
        else {
            return;
        };
        let timer = conn.timer.take();
        if let Some(timer) = timer {
            self.timers.remove(&timer);
        }
        let connection_id = self.new_connection_id();
        let at = self.schedule(now + CONNECTION_BIND_TIMEOUT, Timer::TcpPeer(id));
        let conn = self.tcp_peers.get_mut(&id).expect("checked above");
        conn.connection_id = connection_id;
        conn.timer = Some(at);
        self.tcp_by_connection_id.insert(connection_id, id);
        let attrs: Vec<Box<dyn Setter>> = vec![Box::new(ConnectionId(connection_id))];
        self.reply_success(now, &reply_to, &request, attrs, Some(&key));
    }

    /// Reports that the application could not open the connection a [`ServerEvent::ConnectPeer`]
    /// asked for. The client gets `447 Connection Timeout or Failure`.
    pub fn peer_connect_failed(&mut self, id: PeerConnId, now: Instant) {
        self.fail_connect(id, now);
    }

    /// Reports that a peer opened a connection to the relay address `relay`.
    ///
    /// Returns the connection's id when the server will take it: the allocation exists, is a TCP
    /// one, and the client has a permission for the peer's address. The client is told with a
    /// `ConnectionAttempt` indication. When `None`, the application should close the connection.
    pub fn peer_accepted(
        &mut self,
        relay: SocketAddr,
        peer: SocketAddr,
        now: Instant,
    ) -> Option<PeerConnId> {
        let five = *self.by_relay.get(&relay)?;
        let allocation = self.allocations.get(&five)?;
        if !allocation.tcp || !allocation.has_permission(peer.ip(), now) {
            return None;
        }
        let user_id = allocation.user_id.clone();
        if self.peer_connections_of(&five) >= MAX_PEER_CONNECTIONS_PER_ALLOCATION {
            return None;
        }

        let id = PeerConnId(self.next_peer_id);
        self.next_peer_id += 1;
        let connection_id = self.new_connection_id();
        let timer = self.schedule(now + CONNECTION_BIND_TIMEOUT, Timer::TcpPeer(id));
        self.tcp_peers.insert(
            id,
            PeerConn {
                five,
                user_id,
                relay,
                peer,
                connection_id,
                stage: PeerStage::Waiting,
                timer: Some(timer),
            },
        );
        self.tcp_by_connection_id.insert(connection_id, id);

        let mut attempt = Message::new();
        let built = attempt.build(&[
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(
                METHOD_CONNECTION_ATTEMPT,
                CLASS_INDICATION,
            )),
            Box::new(ConnectionId(connection_id)),
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
            Box::new(stun::fingerprint::FINGERPRINT),
        ]);
        if built.is_ok() {
            self.transmits.push_back(TaggedBytesMut {
                now,
                transport: TransportContext {
                    local_addr: five.server,
                    peer_addr: five.client,
                    transport_protocol: five.protocol,
                    ecn: None,
                },
                message: bytes::BytesMut::from(&attempt.raw[..]),
            });
        }
        Some(id)
    }

    /// Reports that a connection the server knows of has closed — a peer connection, or a data
    /// connection bound to one (the application closes the other end of a splice itself).
    pub fn peer_closed(&mut self, id: PeerConnId) {
        self.forget_peer(id);
    }

    /// Whether a TCP allocation's peer connection `id` is still known to the server.
    pub fn has_peer_connection(&self, id: PeerConnId) -> bool {
        self.tcp_peers.contains_key(&id)
    }

    /// The ids of the peer connections the server knows of.
    pub fn peer_connection_ids(&self) -> impl Iterator<Item = PeerConnId> + '_ {
        self.tcp_peers.keys().copied()
    }

    /// How many peer connections the server knows of.
    pub fn peer_connection_count(&self) -> usize {
        self.tcp_peers.len()
    }

    /// How many peer connections the allocation `five` has.
    pub(super) fn peer_connections_of(&self, five: &FiveTuple) -> usize {
        self.tcp_peers.values().filter(|c| c.five == *five).count()
    }

    fn new_connection_id(&mut self) -> u32 {
        loop {
            let candidate: u32 = rand::rng().random();
            if candidate != 0 && !self.tcp_by_connection_id.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    /// Drops the record of a peer connection, cancelling its timer.
    pub(super) fn forget_peer(&mut self, id: PeerConnId) -> Option<PeerConn> {
        let conn = self.tcp_peers.remove(&id)?;
        if let Some(timer) = conn.timer {
            self.timers.remove(&timer);
        }
        if conn.connection_id != 0 {
            self.tcp_by_connection_id.remove(&conn.connection_id);
        }
        Some(conn)
    }

    /// Answers a pending `Connect` with `447` and closes the connection attempt.
    pub(super) fn fail_connect(&mut self, id: PeerConnId, now: Instant) {
        let Some(conn) = self.forget_peer(id) else {
            return;
        };
        self.events.push_back(ServerEvent::ClosePeer(id));
        if let PeerStage::Connecting {
            request,
            reply_to,
            key,
        } = conn.stage
        {
            self.reply_error(
                now,
                &reply_to,
                &request,
                stun::error_code::CODE_CONN_TIMEOUT_OR_FAILURE,
                Vec::new(),
                Some(&key),
            );
        }
    }

    /// Closes every peer connection of the allocation `five`, which is ending.
    pub(super) fn close_peers_of(&mut self, five: &FiveTuple) {
        let ids: Vec<PeerConnId> = self
            .tcp_peers
            .iter()
            .filter(|(_, c)| c.five == *five)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            self.forget_peer(id);
            self.events.push_back(ServerEvent::ClosePeer(id));
        }
    }

    /// A peer connection's timer fired.
    pub(super) fn tcp_peer_timeout(&mut self, id: PeerConnId, now: Instant) {
        let Some(conn) = self.tcp_peers.get(&id) else {
            return;
        };
        if conn.timer.is_some_and(|(at, _)| at > now) {
            return;
        }
        match conn.stage {
            PeerStage::Connecting { .. } => self.fail_connect(id, now),
            PeerStage::Waiting => {
                // No data connection came in time.
                self.forget_peer(id);
                self.events.push_back(ServerEvent::ClosePeer(id));
            }
            PeerStage::Bound => {}
        }
    }
}
