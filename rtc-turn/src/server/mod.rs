//! The Sans-I/O TURN server ([RFC 8656], with the IPv6 allocations of [RFC 6156]).
//!
//! The server owns no sockets and reads no clock. The application owns the sockets and feeds the
//! server what arrives; the server answers with datagrams to send and events to act on.
//!
//! # Sockets
//!
//! * One or more *listening* sockets receive requests from clients. Hand each datagram to
//!   `handle_read` with `transport.local_addr` set to the socket's address and
//!   `transport.peer_addr` to the client's. Over TCP or TLS, cut the byte stream into messages
//!   first with [`frame_length`](crate::proto::framing::frame_length).
//! * One *relay* socket per allocation receives what peers send to the relayed address. Hand
//!   those datagrams to `handle_read` too, with `transport.local_addr` set to the relay socket's
//!   address: the server tells a relay socket from a listening one by that address.
//!
//! Everything the server sends comes out of `poll_write`. A datagram whose
//! `transport.local_addr` is a relay socket's address goes to a peer from that socket; any other
//! goes to a client from the listening socket named there.
//!
//! # Allocating a relay
//!
//! The server cannot bind a socket, so an Allocate request is answered in two steps. The server
//! emits [`ServerEvent::BindRelay`](crate::server::ServerEvent::BindRelay) and holds the request; the application binds a UDP socket at
//! [`RelayPlan::bind`](crate::server::RelayPlan::bind) and reports the outcome with [`relay_bound`](crate::server::Server::relay_bound) or
//! [`relay_bind_failed`](crate::server::Server::relay_bind_failed), and only then does the client get its answer. When an allocation
//! ends the server emits [`ServerEvent::ReleaseRelay`](crate::server::ServerEvent::ReleaseRelay) and the application closes the socket.
//!
//! # Time
//!
//! Every input carries the current time (`TaggedBytesMut::now`, or the argument of
//! [`relay_bound`](crate::server::Server::relay_bound)); `poll_timeout` says when the server next needs
//! `handle_timeout`.
//!
//! [RFC 8656]: https://www.rfc-editor.org/rfc/rfc8656
//! [RFC 6156]: https://www.rfc-editor.org/rfc/rfc6156

#[cfg(test)]
mod server_test;

mod allocation;
/// Authentication, authorization and quota hooks.
pub mod auth;
mod handlers;
/// Choosing where relayed addresses live.
pub mod relay;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use crypto::RTCCryptoProvider;
use rand::RngExt;
use shared::error::{Error, Result};
use shared::{TaggedBytesMut, TransportContext};
use stun::message::{Message, TransactionId, is_stun_message};

use crate::proto::chandata::ChannelData;
use crate::proto::lifetime::DEFAULT_LIFETIME;

use allocation::Allocation;
pub use allocation::FiveTuple;
use auth::NonceManager;
pub use auth::{
    AuthCredentials, AuthHandler, AuthRequest, LongTermCredentials, PermissionHandler,
    QuotaHandler, generate_auth_key,
};
mod tcp;
#[cfg(test)]
mod tcp_test;
pub use relay::{
    RelayAddressGenerator, RelayAddressGeneratorNone, RelayAddressGeneratorPortRange,
    RelayAddressGeneratorStatic, RelayFamily, RelayPlan,
};
pub use tcp::{CONNECTION_BIND_TIMEOUT, MAX_PEER_CONNECTIONS_PER_ALLOCATION, PeerConnId};

/// How long a permission lasts without a refresh ([RFC 8656 §9]).
///
/// [RFC 8656 §9]: https://www.rfc-editor.org/rfc/rfc8656#section-9
pub const PERMISSION_LIFETIME: Duration = Duration::from_secs(5 * 60);
/// How long a channel binding lasts without a refresh ([RFC 8656 §12]).
///
/// [RFC 8656 §12]: https://www.rfc-editor.org/rfc/rfc8656#section-12
pub const CHANNEL_BIND_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// The longest allocation lifetime the server grants unless configured otherwise.
pub const MAX_ALLOCATION_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// Identifies a relay the server has asked the application to bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelayId(pub u64);

/// How long a reserved port waits to be claimed by a later Allocate ([RFC 8656 §7.2]).
///
/// [RFC 8656 §7.2]: https://www.rfc-editor.org/rfc/rfc8656#section-7.2
pub const RESERVATION_LIFETIME: Duration = Duration::from_secs(30);

/// How many times a relay on an even port is replanned when the application cannot bind the
/// port it was given (the port was taken).
const MAX_EVEN_PORT_ATTEMPTS: u8 = 8;

/// How the server is set up.
pub struct ServerConfig {
    /// The authentication realm clients are told to use.
    pub realm: String,
    /// Sent as `SOFTWARE` in responses when non-empty.
    pub software: String,
    /// Looks up the long-term credential of a user. Without one the server is STUN-only: it
    /// answers Binding requests and refuses everything else with `400 Bad Request`.
    pub auth_handler: Option<Arc<dyn AuthHandler>>,
    /// Decides where relays live. Without one the server is STUN-only (see `auth_handler`).
    pub relay_address_generator: Option<Box<dyn RelayAddressGenerator>>,
    /// Limits how many allocations a user may hold; unlimited when `None`.
    pub quota_handler: Option<Arc<dyn QuotaHandler>>,
    /// Decides which peer addresses a client may reach; every peer is allowed when `None`.
    pub permission_handler: Option<Arc<dyn PermissionHandler>>,
    /// The crypto provider for `MESSAGE-INTEGRITY` and nonces.
    pub crypto_provider: Arc<dyn RTCCryptoProvider>,
    /// The lifetime granted when a request names none. Defaults to ten minutes.
    pub default_allocation_lifetime: Duration,
    /// The longest lifetime granted, whatever is asked for. Defaults to one hour.
    pub max_allocation_lifetime: Duration,
    /// How long a permission lasts. Defaults to five minutes.
    pub permission_lifetime: Duration,
    /// How long a channel binding lasts. Defaults to ten minutes.
    pub channel_bind_timeout: Duration,
    /// How long to wait for the application to bind a relay before answering the client with
    /// `508 Insufficient Capacity`. Defaults to five seconds.
    pub relay_bind_timeout: Duration,
    /// How long a reserved port waits to be claimed. Defaults to thirty seconds.
    pub reservation_lifetime: Duration,
    /// Keep [RFC 6156]'s rule that an Allocate without `REQUESTED-ADDRESS-FAMILY` gets an IPv4
    /// relay. By default such a request gets the family of the address it arrived on, which is
    /// what browsers expect of a server listening on IPv6.
    ///
    /// [RFC 6156]: https://www.rfc-editor.org/rfc/rfc6156
    pub strict_address_family: bool,
}

impl ServerConfig {
    /// A configuration with the standard timeouts.
    pub fn new(
        realm: impl Into<String>,
        auth_handler: Arc<dyn AuthHandler>,
        relay_address_generator: Box<dyn RelayAddressGenerator>,
        crypto_provider: Arc<dyn RTCCryptoProvider>,
    ) -> Self {
        Self {
            auth_handler: Some(auth_handler),
            relay_address_generator: Some(relay_address_generator),
            ..Self::stun_only(realm, crypto_provider)
        }
    }

    /// A configuration for a server that only answers STUN Binding requests.
    pub fn stun_only(
        realm: impl Into<String>,
        crypto_provider: Arc<dyn RTCCryptoProvider>,
    ) -> Self {
        Self {
            realm: realm.into(),
            software: String::new(),
            auth_handler: None,
            relay_address_generator: None,
            quota_handler: None,
            permission_handler: None,
            crypto_provider,
            default_allocation_lifetime: DEFAULT_LIFETIME,
            max_allocation_lifetime: MAX_ALLOCATION_LIFETIME,
            permission_lifetime: PERMISSION_LIFETIME,
            channel_bind_timeout: CHANNEL_BIND_LIFETIME,
            relay_bind_timeout: Duration::from_secs(5),
            reservation_lifetime: RESERVATION_LIFETIME,
            strict_address_family: false,
        }
    }
}

/// Why an allocation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllocationEnd {
    /// Its lifetime ran out without a refresh.
    Expired,
    /// The client refreshed it with a lifetime of zero.
    Deleted,
    /// The server was closed.
    Closed,
}

/// What the server asks of the application.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServerEvent {
    /// Bind a UDP socket at `plan.bind`, then report it with [`relay_bound`](Server::relay_bound) (or
    /// [`relay_bind_failed`](Server::relay_bind_failed)). The client waits for the answer.
    BindRelay {
        /// Quote this back when reporting.
        id: RelayId,
        /// Where to bind, and the address that will be advertised.
        plan: RelayPlan,
    },
    /// Like [`BindRelay`](Self::BindRelay), for a TCP allocation ([RFC 6062]): bind a TCP
    /// listener at `plan.bind`, with address reuse so that connections to peers can be opened from
    /// the same local address. Report it with [`relay_bound`](Server::relay_bound) (or
    /// [`relay_bind_failed`](Server::relay_bind_failed)), and report each connection a peer opens
    /// to it with [`peer_accepted`](Server::peer_accepted). See [`PeerConnId`] for the rest of the
    /// flow.
    ///
    /// [RFC 6062]: https://www.rfc-editor.org/rfc/rfc6062
    BindRelayTcp {
        /// Quote this back when reporting.
        id: RelayId,
        /// Where to bind, and the address that will be advertised.
        plan: RelayPlan,
    },
    /// Open a TCP connection from `relay` (the local address of a TCP allocation's listener) to
    /// `peer`, then report it with [`peer_connected`](Server::peer_connected) or
    /// [`peer_connect_failed`](Server::peer_connect_failed).
    ConnectPeer {
        /// Quote this back when reporting.
        id: PeerConnId,
        /// The local address to connect from.
        relay: SocketAddr,
        /// The peer to connect to.
        peer: SocketAddr,
    },
    /// A client connection (`client` to `server`) has been bound to the peer connection `id`:
    /// splice the two, copying bytes both ways, and close both when either closes. The server
    /// is not given the bytes of that client connection again.
    BindData {
        /// The peer connection.
        id: PeerConnId,
        /// The client's end of the data connection.
        client: SocketAddr,
        /// The server's end of the data connection.
        server: SocketAddr,
    },
    /// Close the peer connection `id`: its allocation ended, or no data connection was bound to it
    /// in time.
    ClosePeer(PeerConnId),
    /// Close the relay socket bound at this address: its allocation ended.
    ReleaseRelay(SocketAddr),
    /// A client obtained an allocation.
    AllocationCreated {
        /// The allocation's five-tuple.
        five_tuple: FiveTuple,
        /// The authenticated user.
        user_id: String,
        /// The relayed address peers send to.
        relayed_addr: SocketAddr,
    },
    /// An allocation ended.
    AllocationDeleted {
        /// The allocation's five-tuple.
        five_tuple: FiveTuple,
        /// Why.
        reason: AllocationEnd,
    },
    /// A request failed authentication.
    AuthFailed {
        /// The client's address.
        client: SocketAddr,
        /// The username it presented.
        username: String,
    },
}

/// Where a pending Allocate has got to.
enum Stage {
    /// Waiting for the relay socket.
    Relay,
    /// The relay is bound and the allocation exists; waiting for the socket that holds the next
    /// port for a `RESERVATION-TOKEN`.
    Hold { relay: SocketAddr, token: [u8; 8] },
}

struct PendingAllocation {
    five: FiveTuple,
    /// What the Allocate request asked of the relay.
    user_id: String,
    key: Vec<u8>,
    family: RelayFamily,
    plan: RelayPlan,
    lifetime: Duration,
    request: Message,
    /// Where to send the answer.
    reply_to: TransportContext,
    /// The timer that gives up on the application; cancelled once it answers.
    timer: (Instant, u64),
    /// The request asked for an even port.
    even: bool,
    /// The request asked for a TCP allocation.
    tcp: bool,
    /// The request asked for the next port up to be reserved.
    reserve: bool,
    /// How many plans have been tried for an even port.
    attempts: u8,
    stage: Stage,
}

/// A port held for a later Allocate that quotes its token.
struct Reservation {
    /// The bound socket holding the port.
    relay: SocketAddr,
    advertised_ip: IpAddr,
    family: RelayFamily,
    expires: Instant,
}

enum Timer {
    Allocation(FiveTuple),
    Permission(FiveTuple, IpAddr),
    Channel(FiveTuple, u16),
    PendingRelay(RelayId),
    Reservation([u8; 8]),
    TcpPeer(PeerConnId),
}

/// The Sans-I/O TURN server; see the [module documentation](self).
pub struct Server {
    realm: String,
    software: String,
    crypto: Arc<dyn RTCCryptoProvider>,
    auth_handler: Option<Arc<dyn AuthHandler>>,
    generator: Option<Box<dyn RelayAddressGenerator>>,
    quota_handler: Option<Arc<dyn QuotaHandler>>,
    permission_handler: Option<Arc<dyn PermissionHandler>>,
    default_lifetime: Duration,
    max_lifetime: Duration,
    permission_lifetime: Duration,
    channel_bind_timeout: Duration,
    relay_bind_timeout: Duration,
    reservation_lifetime: Duration,
    strict_address_family: bool,

    nonces: NonceManager,
    allocations: HashMap<FiveTuple, Allocation>,
    by_relay: HashMap<SocketAddr, FiveTuple>,
    pending: HashMap<RelayId, PendingAllocation>,
    pending_by_tuple: HashMap<FiveTuple, RelayId>,
    reservations: HashMap<[u8; 8], Reservation>,
    /// The local address of each socket holding a reserved port -> its token.
    held: HashMap<SocketAddr, [u8; 8]>,
    next_relay_id: u64,
    tcp_peers: HashMap<PeerConnId, tcp::PeerConn>,
    tcp_by_connection_id: HashMap<u32, PeerConnId>,
    next_peer_id: u64,
    timers: BTreeMap<(Instant, u64), Timer>,
    timer_seq: u64,

    transmits: VecDeque<TaggedBytesMut>,
    events: VecDeque<ServerEvent>,
}

impl Server {
    /// Creates a server. `now` anchors nonce expiry; pass the current time.
    ///
    /// # Errors
    ///
    /// Fails if the relay address generator's configuration is invalid.
    pub fn new(config: ServerConfig, now: Instant) -> Result<Self> {
        if let Some(generator) = &config.relay_address_generator {
            generator.validate()?;
        }
        if config.realm.is_empty() {
            return Err(Error::Other("a TURN server needs a realm".to_owned()));
        }
        Ok(Self {
            realm: config.realm,
            software: config.software,
            nonces: NonceManager::new(config.crypto_provider.clone(), now),
            crypto: config.crypto_provider,
            auth_handler: config.auth_handler,
            generator: config.relay_address_generator,
            quota_handler: config.quota_handler,
            permission_handler: config.permission_handler,
            default_lifetime: config.default_allocation_lifetime,
            max_lifetime: config.max_allocation_lifetime,
            permission_lifetime: config.permission_lifetime,
            channel_bind_timeout: config.channel_bind_timeout,
            relay_bind_timeout: config.relay_bind_timeout,
            reservation_lifetime: config.reservation_lifetime,
            strict_address_family: config.strict_address_family,
            allocations: HashMap::new(),
            by_relay: HashMap::new(),
            pending: HashMap::new(),
            pending_by_tuple: HashMap::new(),
            reservations: HashMap::new(),
            held: HashMap::new(),
            next_relay_id: 1,
            tcp_peers: HashMap::new(),
            tcp_by_connection_id: HashMap::new(),
            next_peer_id: 1,
            timers: BTreeMap::new(),
            timer_seq: 0,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        })
    }

    /// How many allocations are live.
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// The five-tuples of the live allocations.
    pub fn allocations(&self) -> impl Iterator<Item = &FiveTuple> {
        self.allocations.keys()
    }

    /// The relayed address of the allocation on `five_tuple`.
    pub fn relayed_addr(&self, five_tuple: &FiveTuple) -> Option<SocketAddr> {
        self.allocations.get(five_tuple).map(|a| a.advertised)
    }

    /// Ends the allocation on `five_tuple`, as if its lifetime had run out. Returns whether there
    /// was one.
    pub fn delete_allocation(&mut self, five_tuple: &FiveTuple) -> bool {
        self.remove_allocation(five_tuple, AllocationEnd::Deleted)
    }

    /// Reports that the application bound the socket asked for by `id`, at `local_addr`.
    ///
    /// `local_addr` is the socket's own address (port included): later datagrams from it carry
    /// it as `transport.local_addr`. The pending Allocate is answered now.
    pub fn relay_bound(&mut self, id: RelayId, local_addr: SocketAddr, now: Instant) {
        let Some(mut pending) = self.pending.remove(&id) else {
            // The request timed out or its client went away: the socket is not wanted.
            self.events.push_back(ServerEvent::ReleaseRelay(local_addr));
            return;
        };
        self.timers.remove(&pending.timer);
        match pending.stage {
            Stage::Relay => {
                let advertised = SocketAddr::new(pending.plan.advertised_ip, local_addr.port());
                let allocation = Allocation {
                    user_id: pending.user_id.clone(),
                    relay: local_addr,
                    advertised,
                    family: pending.family,
                    allocate_tid: pending.request.transaction_id,
                    reservation_token: None,
                    tcp: pending.tcp,
                    expires: now + pending.lifetime,
                    permissions: HashMap::new(),
                    channels: HashMap::new(),
                    peer_channels: HashMap::new(),
                };
                self.schedule(allocation.expires, Timer::Allocation(pending.five));
                self.by_relay.insert(local_addr, pending.five);
                self.allocations.insert(pending.five, allocation);
                self.events.push_back(ServerEvent::AllocationCreated {
                    five_tuple: pending.five,
                    user_id: pending.user_id.clone(),
                    relayed_addr: advertised,
                });
                if pending.reserve {
                    // The next port up is held by a second socket, bound before the client is
                    // told the token, so that no one else can take it in the meantime.
                    let Some(next) = local_addr.port().checked_add(1) else {
                        self.fail_pending(now, pending, true);
                        return;
                    };
                    let mut token = [0u8; 8];
                    rand::rng().fill(&mut token);
                    pending.plan.bind.set_port(next);
                    pending.stage = Stage::Hold {
                        relay: local_addr,
                        token,
                    };
                    pending.timer =
                        self.schedule(now + self.relay_bind_timeout, Timer::PendingRelay(id));
                    self.events.push_back(ServerEvent::BindRelay {
                        id,
                        plan: pending.plan,
                    });
                    self.pending.insert(id, pending);
                } else {
                    self.pending_by_tuple.remove(&pending.five);
                    self.reply_allocate_success(
                        now,
                        &pending.reply_to,
                        &pending.request,
                        &pending.five,
                        &pending.key,
                    );
                }
            }
            Stage::Hold { relay: _, token } => {
                self.pending_by_tuple.remove(&pending.five);
                let expires = now + self.reservation_lifetime;
                self.schedule(expires, Timer::Reservation(token));
                self.held.insert(local_addr, token);
                self.reservations.insert(
                    token,
                    Reservation {
                        relay: local_addr,
                        advertised_ip: pending.plan.advertised_ip,
                        family: pending.family,
                        expires,
                    },
                );
                if let Some(allocation) = self.allocations.get_mut(&pending.five) {
                    allocation.reservation_token = Some(token);
                }
                self.reply_allocate_success(
                    now,
                    &pending.reply_to,
                    &pending.request,
                    &pending.five,
                    &pending.key,
                );
            }
        }
    }

    /// Reports that the application could not bind the socket asked for by `id`; the client gets
    /// `508 Insufficient Capacity`.
    ///
    /// A relay on an even port is first planned again, on another port, a few times: the port
    /// the generator picked at random may simply have been taken.
    pub fn relay_bind_failed(&mut self, id: RelayId, now: Instant) {
        let Some(mut pending) = self.pending.remove(&id) else {
            return;
        };
        self.timers.remove(&pending.timer);
        if matches!(pending.stage, Stage::Relay)
            && pending.even
            && pending.attempts < MAX_EVEN_PORT_ATTEMPTS
            && let Some(generator) = self.generator.as_mut()
            && let Ok(plan) = generator.plan_even(pending.family)
        {
            pending.attempts += 1;
            pending.plan = plan;
            pending.timer = self.schedule(now + self.relay_bind_timeout, Timer::PendingRelay(id));
            self.events.push_back(ServerEvent::BindRelay { id, plan });
            self.pending.insert(id, pending);
            return;
        }
        self.fail_pending(now, pending, false);
    }

    /// Gives up on a pending Allocate: answers `508`, and ends the allocation it had made if it
    /// got as far as creating one.
    fn fail_pending(&mut self, now: Instant, pending: PendingAllocation, forget_relay: bool) {
        self.pending_by_tuple.remove(&pending.five);
        if matches!(pending.stage, Stage::Hold { .. }) || forget_relay {
            self.remove_allocation(&pending.five, AllocationEnd::Deleted);
        }
        self.reply_error(
            now,
            &pending.reply_to,
            &pending.request,
            stun::error_code::CODE_INSUFFICIENT_CAPACITY,
            Vec::new(),
            Some(&pending.key),
        );
    }

    fn schedule(&mut self, at: Instant, timer: Timer) -> (Instant, u64) {
        self.timer_seq += 1;
        let key = (at, self.timer_seq);
        self.timers.insert(key, timer);
        key
    }

    fn remove_allocation(&mut self, five: &FiveTuple, reason: AllocationEnd) -> bool {
        let Some(allocation) = self.allocations.remove(five) else {
            return false;
        };
        self.by_relay.remove(&allocation.relay);
        self.close_peers_of(five);
        self.events
            .push_back(ServerEvent::ReleaseRelay(allocation.relay));
        self.events.push_back(ServerEvent::AllocationDeleted {
            five_tuple: *five,
            reason,
        });
        true
    }

    fn handle_client_datagram(&mut self, msg: TaggedBytesMut) {
        let now = msg.now;
        let ctx = msg.transport;
        let data = &msg.message[..];
        if is_stun_message(data) {
            let mut m = Message::new();
            m.raw = data.to_vec();
            if let Err(err) = m.decode() {
                log::debug!(
                    "dropping malformed STUN message from {}: {err}",
                    ctx.peer_addr
                );
                return;
            }
            self.handle_stun(now, &ctx, m);
        } else if ChannelData::is_channel_data(data) {
            self.handle_channel_data(now, &ctx, data);
        } else {
            log::trace!(
                "dropping a non-STUN, non-ChannelData datagram from {}",
                ctx.peer_addr
            );
        }
    }

    /// Data a peer sent to a relay: tell the client, as ChannelData if a channel is bound to the
    /// peer and as a Data indication otherwise.
    fn handle_peer_datagram(&mut self, msg: TaggedBytesMut) {
        let now = msg.now;
        let relay = msg.transport.local_addr;
        let peer = msg.transport.peer_addr;
        let Some(five) = self.by_relay.get(&relay).copied() else {
            return;
        };
        let Some(allocation) = self.allocations.get(&five) else {
            return;
        };
        if !allocation.has_permission(peer.ip(), now) {
            log::trace!("dropping data from {peer}: no permission on {relay}");
            return;
        }
        let to_client = TransportContext {
            local_addr: five.server,
            peer_addr: five.client,
            transport_protocol: five.protocol,
            ecn: None,
        };
        let payload = &msg.message[..];
        let framed = match allocation.channel_for(peer, now) {
            Some(number) if payload.len() <= u16::MAX as usize => {
                let mut out = BytesMut::with_capacity(4 + payload.len() + 3);
                out.extend_from_slice(&number.to_be_bytes());
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
                if five.protocol == shared::TransportProtocol::TCP {
                    // Over a stream ChannelData is padded to a multiple of four bytes.
                    while !out.len().is_multiple_of(4) {
                        out.extend_from_slice(&[0]);
                    }
                }
                out
            }
            Some(_) => return,
            None => match self.data_indication(peer, payload) {
                Some(out) => out,
                None => return,
            },
        };
        self.transmits.push_back(TaggedBytesMut {
            now,
            transport: to_client,
            message: framed,
        });
    }

    fn data_indication(&self, peer: SocketAddr, payload: &[u8]) -> Option<BytesMut> {
        use crate::proto::data::Data;
        use crate::proto::peeraddr::PeerAddress;
        use stun::fingerprint::FINGERPRINT;
        use stun::message::{CLASS_INDICATION, METHOD_DATA, MessageType};

        let mut m = Message::new();
        m.build(&[
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(METHOD_DATA, CLASS_INDICATION)),
            Box::new(PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }),
            Box::new(Data(payload.to_vec())),
            Box::new(FINGERPRINT),
        ])
        .ok()?;
        Some(BytesMut::from(&m.raw[..]))
    }
}

impl sansio::Protocol<TaggedBytesMut, TaggedBytesMut, ()> for Server {
    type Rout = ();
    type Wout = TaggedBytesMut;
    type Eout = ServerEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        if self.by_relay.contains_key(&msg.transport.local_addr) {
            self.handle_peer_datagram(msg);
        } else if self.held.contains_key(&msg.transport.local_addr) {
            // A reserved port belongs to no allocation yet: nothing may arrive on it.
        } else {
            self.handle_client_datagram(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    fn handle_write(&mut self, _msg: TaggedBytesMut) -> Result<()> {
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.events.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        while let Some(entry) = self.timers.first_entry() {
            if entry.key().0 > now {
                break;
            }
            let timer = entry.remove();
            // A timer is a hint: the state it points at may have been refreshed since, so it is
            // re-checked here rather than trusted.
            match timer {
                Timer::Allocation(five) => {
                    if self
                        .allocations
                        .get(&five)
                        .is_some_and(|a| a.expires <= now)
                    {
                        self.remove_allocation(&five, AllocationEnd::Expired);
                    }
                }
                Timer::Permission(five, ip) => {
                    if let Some(a) = self.allocations.get_mut(&five)
                        && a.permissions.get(&ip).is_some_and(|&exp| exp <= now)
                    {
                        a.permissions.remove(&ip);
                    }
                }
                Timer::Channel(five, number) => {
                    if let Some(a) = self.allocations.get_mut(&five)
                        && let Some(ch) = a.channels.get(&number)
                        && ch.expires <= now
                    {
                        let peer = ch.peer;
                        a.channels.remove(&number);
                        if a.peer_channels.get(&peer) == Some(&number) {
                            a.peer_channels.remove(&peer);
                        }
                    }
                }
                Timer::PendingRelay(id) => {
                    // The application never answered: no retry, whatever was asked for.
                    if let Some(pending) = self.pending.remove(&id) {
                        self.fail_pending(now, pending, false);
                    }
                }
                Timer::TcpPeer(id) => self.tcp_peer_timeout(id, now),
                Timer::Reservation(token) => {
                    if self
                        .reservations
                        .get(&token)
                        .is_some_and(|r| r.expires <= now)
                        && let Some(reservation) = self.reservations.remove(&token)
                    {
                        self.held.remove(&reservation.relay);
                        self.events
                            .push_back(ServerEvent::ReleaseRelay(reservation.relay));
                    }
                }
            }
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.timers.keys().next().map(|(at, _)| *at)
    }

    fn close(&mut self) -> Result<()> {
        let fives: Vec<FiveTuple> = self.allocations.keys().copied().collect();
        for five in fives {
            self.remove_allocation(&five, AllocationEnd::Closed);
        }
        for (_, reservation) in self.reservations.drain() {
            self.events
                .push_back(ServerEvent::ReleaseRelay(reservation.relay));
        }
        self.held.clear();
        self.tcp_peers.clear();
        self.tcp_by_connection_id.clear();
        self.pending.clear();
        self.pending_by_tuple.clear();
        self.timers.clear();
        Ok(())
    }
}
