//! A bounded Sans-I/O UDP TURN server.
//!
//! The host supplies time and credentials, consumes [`Event`]s, and owns all sockets.
//! [`Server::handle_datagram`] consumes client traffic. An Allocate produces an
//! [`Event::AllocateRelay`]; after binding a relay socket, the host calls
//! [`Server::complete_allocate`]. Peer traffic goes through [`Server::handle_peer_data`].
//! Expiry and Refresh(0) produce [`Event::ReleaseRelay`]. Always drain these events, including
//! on shutdown. A socket allocation that completes after cancellation must be closed by the
//! host when `complete_allocate` returns an error. IDs are never reused within a server instance.
//!
//! This first implementation covers UDP control and UDP relay, IPv4/IPv6 allocations,
//! RFC 5766 long-term authentication, permissions, channels and transaction replay.
//! EVEN-PORT / RESERVATION-TOKEN, DONT-FRAGMENT, TCP/TLS/DTLS control, RFC 6062 TCP relay,
//! and RFC 8489 password-algorithm negotiation are not implemented. Unsupported required
//! attributes produce 420, and unsupported relay transports produce 442. This is not a
//! claim of complete RFC 8656 compliance.

mod allocation;
mod auth;
mod config;
mod message;
mod proto;
mod relay;

#[cfg(test)]
mod server_test;

pub use config::{Authenticator, ServerConfig};
pub use proto::HostEvent;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use crypto::{RTCCryptoProvider, SecretVec};
use shared::error::{Error, Result};
use shared::{FiveTuple, TransportContext, TransportProtocol};
use stun::attributes::*;
use stun::error_code::*;
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::*;
use stun::uattrs::UnknownAttributes;
use stun::xoraddr::XorMappedAddress;

use crate::proto::PROTO_UDP;
use crate::proto::chandata::ChannelData;
use crate::proto::channum::ChannelNumber;
use crate::proto::data::Data;
use crate::proto::lifetime::Lifetime;
use crate::proto::peeraddr::PeerAddress;
use crate::proto::relayaddr::RelayedAddress;
use crate::proto::reqfamily::{
    REQUESTED_FAMILY_IPV4, REQUESTED_FAMILY_IPV6, RequestedAddressFamily,
};
use crate::proto::reqtrans::RequestedTransport;

const PERMISSION_LIFETIME: Duration = Duration::from_secs(300);
const CHANNEL_LIFETIME: Duration = Duration::from_secs(600);
const MAX_UDP_PAYLOAD: usize = 65_507;

/// An opaque, monotonically assigned identity for a host-owned relay socket.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct AllocationId(u64);

/// The address family requested for the relay, independently of the control socket's family.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum AddressFamily {
    /// Allocate an IPv4 UDP relay.
    Ipv4,
    /// Allocate an IPv6 UDP relay.
    Ipv6,
}

impl AddressFamily {
    fn matches(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

/// Network actions emitted by the protocol. The host performs them outside the core.
#[derive(Debug)]
#[non_exhaustive]
pub enum Event {
    /// Bind a UDP relay socket and report its advertised address with `complete_allocate`.
    AllocateRelay {
        /// Identifies the socket across allocation, forwarding and release.
        allocation_id: AllocationId,
        /// The client's control transport five-tuple.
        client: FiveTuple,
        /// Requested relay address family (IPv4 unless explicitly requested otherwise).
        family: AddressFamily,
    },
    /// Cancel a pending bind or close an active relay socket. Never discard this action.
    ReleaseRelay {
        /// Socket to release. Delayed bind completions must not resurrect it.
        allocation_id: AllocationId,
    },
    /// Send one UDP datagram from a control listener to a client.
    SendToClient {
        /// Listener and destination addresses, in the same orientation as inbound traffic.
        transport: TransportContext,
        /// STUN response, Data indication or ChannelData.
        data: BytesMut,
    },
    /// Send a payload to a peer from the relay socket identified by allocation_id.
    SendToPeer {
        /// Relay socket to use, never the control listener.
        allocation_id: AllocationId,
        /// Authorized destination address.
        peer: SocketAddr,
        /// Payload bytes without TURN framing.
        data: BytesMut,
    },
}

#[derive(Clone)]
struct Channel {
    peer: SocketAddr,
    expires: Instant,
}

#[derive(Clone)]
struct Allocation {
    id: AllocationId,
    username: String,
    key: SecretVec,
    relay: SocketAddr,
    expires: Instant,
    permissions: HashMap<IpAddr, Instant>,
    channels: HashMap<u16, Channel>,
    allocate_transaction_id: TransactionId,
    allocate_request: Vec<u8>,
    allocate_response: Vec<u8>,
}

struct Pending {
    id: AllocationId,
    username: String,
    key: SecretVec,
    request: Message,
    family: AddressFamily,
    lifetime: Duration,
    expires: Instant,
}

struct CachedResponse {
    request: Vec<u8>,
    response: Vec<u8>,
    expires: Instant,
}

/// UDP TURN protocol state, with no socket ownership, runtime dependency or clock reads.
pub struct Server {
    config: ServerConfig,
    authenticator: Arc<dyn Authenticator>,
    crypto: Arc<dyn RTCCryptoProvider>,
    epoch: Instant,
    now: Instant,
    nonce_key: SecretVec,
    next_id: u64,
    allocations: HashMap<FiveTuple, Allocation>,
    pending: HashMap<FiveTuple, Pending>,
    cache: HashMap<(FiveTuple, TransactionId), CachedResponse>,
    events: VecDeque<Event>,
    closed: bool,
}

impl Server {
    /// Construct a server with caller-supplied monotonic time and crypto provider.
    pub fn new(
        config: ServerConfig,
        authenticator: Arc<dyn Authenticator>,
        crypto: Arc<dyn RTCCryptoProvider>,
        now: Instant,
    ) -> Result<Self> {
        config.validate()?;
        let mut secret = SecretVec::new(vec![0u8; 32]);
        crypto
            .random()
            .fill(secret.as_mut())
            .map_err(|error| Error::Crypto(error.to_string()))?;
        // Fail during configuration rather than the first unauthenticated request.
        crypto
            .crypto()
            .new_hmac(crypto::HmacAlgorithm::Sha256, secret.as_ref())
            .map_err(|error| Error::Crypto(error.to_string()))?;
        Ok(Self {
            config,
            authenticator,
            crypto,
            epoch: now,
            now,
            nonce_key: secret,
            next_id: 0,
            allocations: HashMap::new(),
            pending: HashMap::new(),
            cache: HashMap::new(),
            events: VecDeque::new(),
            closed: false,
        })
    }

    /// Take the next network action. Drain before processing more input or advancing time.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Number of active relay allocations, excluding pending host socket binds.
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }

    /// Process one complete UDP datagram from a control listener.
    ///
    /// Malformed input returns an error without applying request side effects. The host should
    /// discard that packet and continue. Queue saturation also returns an error; drain
    /// events before retrying. Admission is checked before request side effects.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        transport: TransportContext,
        data: &[u8],
    ) -> Result<()> {
        if self.closed {
            return Err(Error::Other("TURN server is closed".into()));
        }
        self.handle_timeout(now)?;
        self.ensure_room(2)?;
        if transport.transport_protocol != TransportProtocol::UDP {
            return Err(Error::Other("TURN server accepts UDP control only".into()));
        }
        let tuple = FiveTuple::from(transport);
        if data.first().is_some_and(|byte| byte & 0xc0 == 0x40) {
            return self.channel_data(tuple, data);
        }
        // Send indications contain application data and need a larger bound than requests.
        if data.len() > MAX_UDP_PAYLOAD {
            return Err(Error::Other(
                "TURN datagram exceeds UDP payload limit".into(),
            ));
        }
        let mut request = message::decode(data)?;
        if request.typ.class == CLASS_INDICATION {
            if request.typ.method == METHOD_SEND {
                return self.send_indication(tuple, &request);
            }
            return Ok(());
        }
        if request.typ.class != CLASS_REQUEST {
            return Ok(());
        }
        if data.len() > self.config.max_request_bytes {
            return Err(Error::Other(
                "TURN control request exceeds configured limit".into(),
            ));
        }
        // Replay the exact bytes, without renewing lifetimes or reapplying mutations.
        if let Some(cached) = self.cache.get(&(tuple, request.transaction_id)) {
            if cached.request == data {
                let response = cached.response.clone();
                self.send_client(tuple, &response);
            }
            return Ok(());
        }
        // Allocate transaction IDs stay reserved while binding and for the allocation's
        // lifetime, even after the short response cache expires. Conflicting bytes (including
        // a different method) must not cache an error or mutate the original allocation.
        if let Some(allocation) = self.allocations.get(&tuple)
            && allocation.allocate_transaction_id == request.transaction_id
        {
            if allocation.allocate_request == data {
                let response = allocation.allocate_response.clone();
                self.send_client(tuple, &response);
            }
            return Ok(());
        }
        if self
            .pending
            .get(&tuple)
            .is_some_and(|pending| pending.request.transaction_id == request.transaction_id)
        {
            return Ok(());
        }
        if request.typ.method == METHOD_BINDING {
            let unknown = message::unknown_attributes(&request);
            if !unknown.is_empty() {
                return self.error_response(tuple, &request, CODE_UNKNOWN_ATTRIBUTE, None, unknown);
            }
            let mut response = message::response(&request, CLASS_SUCCESS_RESPONSE);
            XorMappedAddress {
                ip: tuple.peer_addr.ip(),
                port: tuple.peer_addr.port(),
            }
            .add_to(&mut response)?;
            return self.send_response(tuple, &request, response, None, false);
        }
        let identity = match self.authenticate(now, tuple, &mut request) {
            Ok(identity) => identity,
            Err((code, key)) => {
                return self.error_response(
                    tuple,
                    &request,
                    code,
                    key.as_ref().map(AsRef::as_ref),
                    vec![],
                );
            }
        };
        let unknown = message::unknown_attributes(&request);
        if !unknown.is_empty() {
            return self.error_response(
                tuple,
                &request,
                CODE_UNKNOWN_ATTRIBUTE,
                Some(identity.key.as_ref()),
                unknown,
            );
        }
        if request.typ.method == METHOD_ALLOCATE {
            return self.allocate(tuple, request, identity);
        }
        // Reserve replay capacity before accepting any mutating transaction.
        if self.cache.len() + self.pending.len() >= self.config.max_replay_entries {
            return self.error_response(
                tuple,
                &request,
                CODE_INSUFFICIENT_CAPACITY,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        let Some(allocation) = self.allocations.get(&tuple) else {
            return self.error_response(
                tuple,
                &request,
                CODE_ALLOC_MISMATCH,
                Some(identity.key.as_ref()),
                vec![],
            );
        };
        if allocation.username != identity.username {
            return self.error_response(
                tuple,
                &request,
                CODE_WRONG_CREDENTIALS,
                Some(identity.key.as_ref()),
                vec![],
            );
        }
        let previous = self.allocations[&tuple].clone();
        let previous_events = self.events.len();
        let result = match request.typ.method {
            METHOD_REFRESH => self.refresh(tuple, &request),
            METHOD_CREATE_PERMISSION => self.create_permission(tuple, &request),
            METHOD_CHANNEL_BIND => self.bind_channel(tuple, &request),
            _ => Err(CODE_BAD_REQUEST),
        };
        match result {
            Ok(response) => {
                let result = self.send_response(
                    tuple,
                    &request,
                    response,
                    Some(identity.key.as_ref()),
                    true,
                );
                if result.is_err() {
                    self.allocations.insert(tuple, previous);
                    self.events.truncate(previous_events);
                }
                result
            }
            Err(code) => {
                self.error_response(tuple, &request, code, Some(identity.key.as_ref()), vec![])
            }
        }
    }

    /// Complete a host relay bind. Supply its public/advertised address, not a wildcard.
    ///
    /// On failure, pass the STUN error to send (normally 508 or 440). On Err the host
    /// retains socket ownership: close unknown/cancelled IDs, or drain and retry on
    /// queue saturation. Never deliver peer traffic before this call succeeds.
    pub fn complete_allocate(
        &mut self,
        now: Instant,
        id: AllocationId,
        relay: std::result::Result<SocketAddr, ErrorCode>,
    ) -> Result<()> {
        self.handle_timeout(now)?;
        self.ensure_room(2)?;
        let tuple = self
            .pending
            .iter()
            .find_map(|(tuple, pending)| (pending.id == id).then_some(*tuple))
            .ok_or_else(|| Error::Other("unknown or expired TURN allocation ID".into()))?;
        let pending = self
            .pending
            .remove(&tuple)
            .expect("pending allocation was located");
        let address = match relay {
            Ok(address)
                if pending.family.matches(address.ip())
                    && address.port() != 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast() =>
            {
                address
            }
            Ok(_) => {
                self.events
                    .push_back(Event::ReleaseRelay { allocation_id: id });
                return self.error_response(
                    tuple,
                    &pending.request,
                    CODE_INSUFFICIENT_CAPACITY,
                    Some(pending.key.as_ref()),
                    vec![],
                );
            }
            Err(code) => {
                return self.error_response(
                    tuple,
                    &pending.request,
                    code,
                    Some(pending.key.as_ref()),
                    vec![],
                );
            }
        };
        let mut response = message::response(&pending.request, CLASS_SUCCESS_RESPONSE);
        RelayedAddress {
            ip: address.ip(),
            port: address.port(),
        }
        .add_to(&mut response)?;
        XorMappedAddress {
            ip: tuple.peer_addr.ip(),
            port: tuple.peer_addr.port(),
        }
        .add_to(&mut response)?;
        Lifetime(pending.lifetime).add_to(&mut response)?;
        // Encode before admitting state, so crypto failures cannot leave an unreported relay.
        let encoded = match self.finish_response(response, Some(pending.key.as_ref())) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.events
                    .push_back(Event::ReleaseRelay { allocation_id: id });
                return Err(error);
            }
        };
        if let Err(error) = self.remember(tuple, &pending.request, &encoded) {
            self.events
                .push_back(Event::ReleaseRelay { allocation_id: id });
            return Err(error);
        }
        self.allocations.insert(
            tuple,
            Allocation {
                id,
                username: pending.username,
                key: pending.key,
                relay: address,
                expires: now + pending.lifetime,
                permissions: HashMap::new(),
                channels: HashMap::new(),
                allocate_transaction_id: pending.request.transaction_id,
                allocate_request: pending.request.raw.clone(),
                allocate_response: encoded.clone(),
            },
        );
        self.send_client(tuple, &encoded);
        Ok(())
    }

    /// Process payload bytes received on a host relay socket.
    ///
    /// Data from peers without a live IP permission is silently discarded. A live channel
    /// uses ChannelData; otherwise the server sends a Data indication to the client.
    pub fn handle_peer_data(
        &mut self,
        now: Instant,
        id: AllocationId,
        peer: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        self.handle_timeout(now)?;
        self.ensure_room(1)?;
        let Some((tuple, allocation)) = self
            .allocations
            .iter()
            .find(|(_, allocation)| allocation.id == id)
        else {
            return Ok(());
        };
        let tuple = *tuple;
        if data.len() > MAX_UDP_PAYLOAD
            || !Self::permitted(allocation, peer, now)
            || !self.authenticator.allow_peer(&allocation.username, peer)
        {
            return Ok(());
        }
        let channel = allocation.channels.iter().find_map(|(number, channel)| {
            (channel.peer == peer && channel.expires > now).then_some(*number)
        });
        let encoded = if let Some(number) = channel {
            let mut packet = ChannelData {
                number: ChannelNumber(number),
                data: data.to_vec(),
                raw: vec![],
            };
            packet.encode();
            packet.raw
        } else {
            let mut packet = Message::new();
            packet.set_type(MessageType::new(METHOD_DATA, CLASS_INDICATION));
            packet.new_transaction_id()?;
            packet.write_header();
            PeerAddress {
                ip: peer.ip(),
                port: peer.port(),
            }
            .add_to(&mut packet)?;
            Data(data.to_vec()).add_to(&mut packet)?;
            packet.raw
        };
        if encoded.len() <= MAX_UDP_PAYLOAD {
            self.send_client(tuple, &encoded);
        }
        Ok(())
    }

    /// The earliest protocol deadline. The host schedules one timer and passes its time back.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.allocations
            .values()
            .flat_map(|allocation| {
                std::iter::once(allocation.expires)
                    .chain(allocation.permissions.values().copied())
                    .chain(allocation.channels.values().map(|channel| channel.expires))
            })
            .chain(self.pending.values().map(|pending| pending.expires))
            .chain(self.cache.values().map(|cached| cached.expires))
            .min()
    }

    /// Advance time and expire allocations, permissions, bindings and replay entries.
    ///
    /// Expiry always queues socket releases, even if regular output admission is saturated.
    /// Since the allocation table is bounded, this can add at most max_allocations events.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if now < self.now {
            return Err(Error::Other("TURN server time moved backwards".into()));
        }
        self.now = now;
        let expired: Vec<_> = self
            .allocations
            .iter()
            .filter_map(|(tuple, allocation)| (allocation.expires <= now).then_some(*tuple))
            .collect();
        for tuple in expired {
            self.release(tuple);
        }
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(tuple, pending)| (pending.expires <= now).then_some(*tuple))
            .collect();
        for tuple in expired {
            if let Some(pending) = self.pending.remove(&tuple) {
                self.events.push_back(Event::ReleaseRelay {
                    allocation_id: pending.id,
                });
            }
        }
        for allocation in self.allocations.values_mut() {
            allocation.permissions.retain(|_, expires| *expires > now);
            allocation
                .channels
                .retain(|_, channel| channel.expires > now);
        }
        self.cache.retain(|_, cached| cached.expires > now);
        Ok(())
    }

    /// Retire one allocation or pending bind after an unrecoverable host relay failure.
    ///
    /// Emits `ReleaseRelay` even when the regular output queue is full. Unknown or
    /// already retired IDs are ignored. Drain events to close the affected socket;
    /// other allocations and the control listener remain available.
    pub fn close_allocation(&mut self, id: AllocationId) {
        if let Some(tuple) = self
            .allocations
            .iter()
            .find_map(|(tuple, allocation)| (allocation.id == id).then_some(*tuple))
        {
            self.release(tuple);
        } else if let Some(tuple) = self
            .pending
            .iter()
            .find_map(|(tuple, pending)| (pending.id == id).then_some(*tuple))
        {
            self.pending.remove(&tuple);
            self.events
                .push_back(Event::ReleaseRelay { allocation_id: id });
        }
    }

    /// Retire all allocations and pending binds, emitting releases. Drain before destroying sockets.
    pub fn close(&mut self) {
        self.closed = true;
        for (_, allocation) in self.allocations.drain() {
            self.events.push_back(Event::ReleaseRelay {
                allocation_id: allocation.id,
            });
        }
        for (_, pending) in self.pending.drain() {
            self.events.push_back(Event::ReleaseRelay {
                allocation_id: pending.id,
            });
        }
        self.cache.clear();
    }

    fn ensure_room(&self, additional: usize) -> Result<()> {
        if self.events.len().saturating_add(additional) > self.config.max_events {
            return Err(Error::Other(
                "TURN output queue full; drain events before more input".into(),
            ));
        }
        Ok(())
    }

    fn release(&mut self, tuple: FiveTuple) {
        if let Some(allocation) = self.allocations.remove(&tuple) {
            self.events.push_back(Event::ReleaseRelay {
                allocation_id: allocation.id,
            });
        }
    }

    fn finish_response(&self, mut response: Message, key: Option<&[u8]>) -> Result<Vec<u8>> {
        if let Some(key) = key {
            MessageIntegrity::new_raw_integrity_with_provider(key.to_vec(), self.crypto.crypto())
                .add_to(&mut response)?;
        }
        FINGERPRINT.add_to(&mut response)?;
        Ok(response.raw)
    }

    fn send_response(
        &mut self,
        tuple: FiveTuple,
        request: &Message,
        response: Message,
        key: Option<&[u8]>,
        cache: bool,
    ) -> Result<()> {
        if cache {
            self.ensure_replay_room()?;
        }
        let encoded = self.finish_response(response, key)?;
        if cache {
            self.remember(tuple, request, &encoded)?;
        }
        self.send_client(tuple, &encoded);
        Ok(())
    }

    fn ensure_replay_room(&self) -> Result<()> {
        // Pending Allocate transactions own a reserved cache slot until host completion.
        if self.cache.len().saturating_add(self.pending.len()) >= self.config.max_replay_entries {
            return Err(Error::Other(
                "TURN replay cache full; retry after its next expiry".into(),
            ));
        }
        Ok(())
    }

    fn remember(&mut self, tuple: FiveTuple, request: &Message, response: &[u8]) -> Result<()> {
        self.ensure_replay_room()?;
        self.cache.insert(
            (tuple, request.transaction_id),
            CachedResponse {
                request: request.raw.clone(),
                response: response.to_vec(),
                expires: self.now + self.config.replay_lifetime,
            },
        );
        Ok(())
    }

    fn error_response(
        &mut self,
        tuple: FiveTuple,
        request: &Message,
        code: ErrorCode,
        key: Option<&[u8]>,
        unknown: Vec<AttrType>,
    ) -> Result<()> {
        let mut response = message::response(request, CLASS_ERROR_RESPONSE);
        code.add_to(&mut response)?;
        if code == CODE_UNAUTHORIZED || code == CODE_STALE_NONCE {
            self.add_challenge(self.now, tuple, &mut response)?;
        }
        if !unknown.is_empty() {
            UnknownAttributes(unknown).add_to(&mut response)?;
        }
        // Authenticated failures complete a transaction too: replay their exact bytes rather
        // than reevaluating it after credentials, quotas, permissions or host capacity change.
        // If no cache slot is available, discard the request without sending a terminal reply.
        self.send_response(tuple, request, response, key, key.is_some())
    }

    fn send_client(&mut self, tuple: FiveTuple, data: &[u8]) {
        self.events.push_back(Event::SendToClient {
            transport: TransportContext {
                local_addr: tuple.local_addr,
                peer_addr: tuple.peer_addr,
                transport_protocol: tuple.transport_protocol,
                ecn: None,
            },
            data: BytesMut::from(data),
        });
    }
}
