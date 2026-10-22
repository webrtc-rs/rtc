//! How the server answers each STUN method and ChannelData.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use shared::{TaggedBytesMut, TransportContext};
use stun::attributes::*;
use stun::error_code::*;
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::*;
use stun::textattrs::{Software, TextAttribute};
use stun::uattrs::UnknownAttributes;
use stun::xoraddr::XorMappedAddress;

use super::allocation::{Channel, FiveTuple};
use super::auth::AuthRequest;
use super::relay::RelayFamily;
use super::{PendingAllocation, RelayId, Server, ServerEvent, Timer};
use crate::proto::PROTO_UDP;
use crate::proto::channum::ChannelNumber;
use crate::proto::data::Data;
use crate::proto::evenport::EvenPort;
use crate::proto::lifetime::Lifetime;
use crate::proto::peeraddr::PeerAddress;
use crate::proto::relayaddr::RelayedAddress;
use crate::proto::reqtrans::RequestedTransport;

/// A request's author, once their credentials checked out.
struct Authed {
    user_id: String,
    key: Vec<u8>,
}

/// Attributes a TURN server understands in a request. A comprehension-required attribute (below
/// `0x8000`) outside this set makes the server answer `420 Unknown Attribute`.
const UNDERSTOOD: &[AttrType] = &[
    ATTR_MAPPED_ADDRESS,
    ATTR_USERNAME,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_ERROR_CODE,
    ATTR_UNKNOWN_ATTRIBUTES,
    ATTR_REALM,
    ATTR_NONCE,
    ATTR_XORMAPPED_ADDRESS,
    ATTR_CHANNEL_NUMBER,
    ATTR_LIFETIME,
    ATTR_XOR_PEER_ADDRESS,
    ATTR_DATA,
    ATTR_XOR_RELAYED_ADDRESS,
    ATTR_EVEN_PORT,
    ATTR_REQUESTED_TRANSPORT,
    ATTR_DONT_FRAGMENT,
    ATTR_RESERVATION_TOKEN,
    ATTR_REQUESTED_ADDRESS_FAMILY,
    ATTR_MESSAGE_INTEGRITY_SHA256,
    ATTR_PASSWORD_ALGORITHM,
    ATTR_USER_HASH,
];

fn five_tuple(ctx: &TransportContext) -> FiveTuple {
    FiveTuple {
        client: ctx.peer_addr,
        server: ctx.local_addr,
        protocol: ctx.transport_protocol,
    }
}

/// Decodes an `XOR-*-ADDRESS` attribute value.
fn decode_xor_address(value: &[u8], transaction_id: &TransactionId) -> Option<SocketAddr> {
    if value.len() < 8 {
        return None;
    }
    let family = u16::from_be_bytes([value[0], value[1]]);
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    let mut mask = [0u8; 16];
    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(&transaction_id.0);
    match family {
        0x01 if value.len() == 8 => {
            let mut ip = [0u8; 4];
            for i in 0..4 {
                ip[i] = value[4 + i] ^ mask[i];
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
        }
        0x02 if value.len() == 20 => {
            let mut ip = [0u8; 16];
            for i in 0..16 {
                ip[i] = value[4 + i] ^ mask[i];
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

/// Every `XOR-PEER-ADDRESS` in the message, or `None` if one is malformed.
fn peer_addresses(m: &Message) -> Option<Vec<SocketAddr>> {
    m.attributes
        .0
        .iter()
        .filter(|a| a.typ == ATTR_XOR_PEER_ADDRESS)
        .map(|a| decode_xor_address(&a.value, &m.transaction_id))
        .collect()
}

type Setters = Vec<Box<dyn Setter>>;

impl Server {
    fn transmit(&mut self, now: Instant, ctx: &TransportContext, m: &Message) {
        self.transmits.push_back(TaggedBytesMut {
            now,
            transport: TransportContext { ecn: None, ..*ctx },
            message: BytesMut::from(&m.raw[..]),
        });
    }

    /// Builds and queues a response to `req`, signed with `key` if there is one.
    fn respond(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        req: &Message,
        class: MessageClass,
        attrs: Setters,
        key: Option<&[u8]>,
    ) {
        let crypto = self.crypto.clone();
        let software = (!self.software.is_empty())
            .then(|| Software::new(ATTR_SOFTWARE, self.software.clone()));
        let mut out = Message::new();
        let mut setters: Vec<Box<dyn Setter + '_>> = vec![
            Box::new(req.transaction_id),
            Box::new(MessageType::new(req.typ.method, class)),
        ];
        for attr in attrs {
            setters.push(attr);
        }
        if let Some(software) = software {
            setters.push(Box::new(software));
        }
        if let Some(key) = key {
            setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                key.to_vec(),
                crypto.crypto(),
            )));
        }
        setters.push(Box::new(FINGERPRINT));
        match out.build(&setters) {
            Ok(()) => self.transmit(now, ctx, &out),
            Err(err) => log::warn!("could not build a response to {}: {err}", req.typ),
        }
    }

    pub(super) fn reply_error(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        req: &Message,
        code: ErrorCode,
        mut extra: Setters,
        key: Option<&[u8]>,
    ) {
        let mut attrs: Setters = vec![Box::new(code)];
        attrs.append(&mut extra);
        self.respond(now, ctx, req, CLASS_ERROR_RESPONSE, attrs, key);
    }

    fn reply_success(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        req: &Message,
        attrs: Setters,
        key: Option<&[u8]>,
    ) {
        self.respond(now, ctx, req, CLASS_SUCCESS_RESPONSE, attrs, key);
    }

    /// `401 Unauthorized` or `438 Stale Nonce`: the client is told the realm and a fresh nonce to
    /// sign its next request with.
    fn challenge(&mut self, now: Instant, ctx: &TransportContext, req: &Message, code: ErrorCode) {
        let Ok(nonce) = self.nonces.generate(now) else {
            self.reply_error(now, ctx, req, CODE_SERVER_ERROR, Vec::new(), None);
            return;
        };
        let extra: Setters = vec![
            Box::new(TextAttribute::new(ATTR_REALM, self.realm.clone())),
            Box::new(TextAttribute::new(ATTR_NONCE, nonce)),
        ];
        self.reply_error(now, ctx, req, code, extra, None);
    }

    /// Checks the long-term credentials on `m`. `None` means it has been answered (or dropped)
    /// already.
    fn authenticate(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        m: &mut Message,
    ) -> Option<Authed> {
        if !m.contains(ATTR_MESSAGE_INTEGRITY) {
            self.challenge(now, ctx, m, CODE_UNAUTHORIZED);
            return None;
        }
        let text = |attr| TextAttribute::get_from_as(m, attr).map(|t| t.text);
        let (Ok(username), Ok(realm), Ok(nonce)) =
            (text(ATTR_USERNAME), text(ATTR_REALM), text(ATTR_NONCE))
        else {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), None);
            return None;
        };
        if !self.nonces.validate(now, &nonce) {
            self.challenge(now, ctx, m, CODE_STALE_NONCE);
            return None;
        }
        let credentials = if realm == self.realm {
            self.auth_handler.auth(&AuthRequest {
                username: &username,
                realm: &realm,
                src_addr: ctx.peer_addr,
                method: m.typ.method,
            })
        } else {
            None
        };
        let crypto = self.crypto.clone();
        match credentials {
            Some(credentials)
                if MessageIntegrity::check(m, &credentials.key, crypto.crypto()).is_ok() =>
            {
                Some(Authed {
                    user_id: credentials.user_id,
                    key: credentials.key,
                })
            }
            _ => {
                log::debug!(
                    "authentication failed for {username:?} from {}",
                    ctx.peer_addr
                );
                self.events.push_back(ServerEvent::AuthFailed {
                    client: ctx.peer_addr,
                    username,
                });
                self.challenge(now, ctx, m, CODE_UNAUTHORIZED);
                None
            }
        }
    }

    /// `420 Unknown Attribute` if the request carries a comprehension-required attribute this
    /// server does not understand. Returns whether it did (and so was answered).
    fn reject_unknown_attributes(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        m: &Message,
        auth: &Authed,
    ) -> bool {
        let unknown: Vec<AttrType> = m
            .attributes
            .0
            .iter()
            .map(|a| a.typ)
            .filter(|t| t.value() < 0x8000 && !UNDERSTOOD.contains(t))
            .collect();
        if unknown.is_empty() {
            return false;
        }
        self.reply_error(
            now,
            ctx,
            m,
            CODE_UNKNOWN_ATTRIBUTE,
            vec![Box::new(UnknownAttributes(unknown))],
            Some(&auth.key),
        );
        true
    }

    pub(super) fn handle_stun(&mut self, now: Instant, ctx: &TransportContext, mut m: Message) {
        match (m.typ.class, m.typ.method) {
            (CLASS_REQUEST, METHOD_BINDING) => self.handle_binding(now, ctx, &m),
            (CLASS_REQUEST, METHOD_ALLOCATE) => self.handle_allocate(now, ctx, m),
            (CLASS_REQUEST, METHOD_REFRESH) => self.handle_refresh(now, ctx, &mut m),
            (CLASS_REQUEST, METHOD_CREATE_PERMISSION) => {
                self.handle_create_permission(now, ctx, &mut m)
            }
            (CLASS_REQUEST, METHOD_CHANNEL_BIND) => self.handle_channel_bind(now, ctx, &mut m),
            (CLASS_REQUEST, _) => {
                self.reply_error(now, ctx, &m, CODE_BAD_REQUEST, Vec::new(), None);
            }
            (CLASS_INDICATION, METHOD_SEND) => self.handle_send_indication(now, ctx, &m),
            _ => log::trace!("ignoring {} from {}", m.typ, ctx.peer_addr),
        }
    }

    fn handle_binding(&mut self, now: Instant, ctx: &TransportContext, m: &Message) {
        let mapped: Setters = vec![Box::new(XorMappedAddress {
            ip: ctx.peer_addr.ip(),
            port: ctx.peer_addr.port(),
        })];
        self.reply_success(now, ctx, m, mapped, None);
    }

    fn grant_lifetime(&self, requested: Option<Duration>) -> Duration {
        requested
            .unwrap_or(self.default_lifetime)
            .min(self.max_lifetime)
    }

    fn handle_allocate(&mut self, now: Instant, ctx: &TransportContext, mut m: Message) {
        let m = &mut m;
        let Some(auth) = self.authenticate(now, ctx, m) else {
            return;
        };
        let five = five_tuple(ctx);
        if let Some(existing) = self.allocations.get(&five) {
            if existing.allocate_tid == m.transaction_id && existing.user_id == auth.user_id {
                // The client retransmitted: answer again, identically.
                self.reply_allocate_success(now, ctx, m, &five, &auth.key);
            } else {
                self.reply_error(
                    now,
                    ctx,
                    m,
                    CODE_ALLOC_MISMATCH,
                    Vec::new(),
                    Some(&auth.key),
                );
            }
            return;
        }
        if let Some(id) = self.pending_by_tuple.get(&five) {
            if self.pending[id].request.transaction_id != m.transaction_id {
                self.reply_error(
                    now,
                    ctx,
                    m,
                    CODE_ALLOC_MISMATCH,
                    Vec::new(),
                    Some(&auth.key),
                );
            }
            // Otherwise a retransmission of a request still waiting on its relay: the answer
            // follows when the application binds it.
            return;
        }
        if self.reject_unknown_attributes(now, ctx, m, &auth) {
            return;
        }

        let mut transport = RequestedTransport::default();
        if transport.get_from(m).is_err() {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
        if transport.protocol != PROTO_UDP {
            self.reply_error(
                now,
                ctx,
                m,
                CODE_UNSUPPORTED_TRANS_PROTO,
                Vec::new(),
                Some(&auth.key),
            );
            return;
        }
        if m.contains(ATTR_DONT_FRAGMENT) {
            // A relay socket cannot promise to set the DF bit; say so, as the RFC prescribes.
            self.reply_error(
                now,
                ctx,
                m,
                CODE_UNKNOWN_ATTRIBUTE,
                vec![Box::new(UnknownAttributes(vec![ATTR_DONT_FRAGMENT]))],
                Some(&auth.key),
            );
            return;
        }
        let even = m.contains(ATTR_EVEN_PORT);
        if m.contains(ATTR_RESERVATION_TOKEN) {
            // Reservation tokens are never issued, so none can be valid.
            let code = if even {
                CODE_BAD_REQUEST
            } else {
                CODE_INSUFFICIENT_CAPACITY
            };
            self.reply_error(now, ctx, m, code, Vec::new(), Some(&auth.key));
            return;
        }
        if even {
            let mut even_port = EvenPort::default();
            if even_port.get_from(m).is_err() {
                self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
                return;
            }
            if even_port.reserve_port() {
                // Holding the next port for a later request is not supported.
                self.reply_error(
                    now,
                    ctx,
                    m,
                    CODE_INSUFFICIENT_CAPACITY,
                    Vec::new(),
                    Some(&auth.key),
                );
                return;
            }
        }
        let family = if m.contains(ATTR_REQUESTED_ADDRESS_FAMILY) {
            // A malformed attribute is a Bad Request; a well-formed one naming a family this
            // server does not know is `440`.
            let value = m
                .get_value(ATTR_REQUESTED_ADDRESS_FAMILY)
                .unwrap_or_default();
            match value {
                [0x01, ..] if value.len() == 4 => RelayFamily::V4,
                [0x02, ..] if value.len() == 4 => RelayFamily::V6,
                _ if value.len() == 4 => {
                    self.reply_error(
                        now,
                        ctx,
                        m,
                        CODE_ADDR_FAMILY_NOT_SUPPORTED,
                        Vec::new(),
                        Some(&auth.key),
                    );
                    return;
                }
                _ => {
                    self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
                    return;
                }
            }
        } else {
            RelayFamily::V4
        };
        let requested_lifetime = if m.contains(ATTR_LIFETIME) {
            let mut lifetime = Lifetime::default();
            if lifetime.get_from(m).is_err() {
                self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
                return;
            }
            Some(lifetime.0)
        } else {
            None
        };

        if let Some(quota) = &self.quota_handler
            && !quota.allow(&auth.user_id, &self.realm, ctx.peer_addr)
        {
            self.reply_error(
                now,
                ctx,
                m,
                CODE_ALLOC_QUOTA_REACHED,
                Vec::new(),
                Some(&auth.key),
            );
            return;
        }

        let plan = if even {
            self.generator.plan_even(family)
        } else {
            self.generator.plan(family, 0)
        };
        let plan = match plan {
            Ok(plan) => plan,
            Err(err) => {
                log::debug!("no relay for {family:?}: {err}");
                let code = if m.contains(ATTR_REQUESTED_ADDRESS_FAMILY) && !even {
                    CODE_ADDR_FAMILY_NOT_SUPPORTED
                } else {
                    CODE_INSUFFICIENT_CAPACITY
                };
                self.reply_error(now, ctx, m, code, Vec::new(), Some(&auth.key));
                return;
            }
        };

        let id = RelayId(self.next_relay_id);
        self.next_relay_id += 1;
        let lifetime = self.grant_lifetime(requested_lifetime);
        let timer = self.schedule(now + self.relay_bind_timeout, Timer::PendingRelay(id));
        self.pending.insert(
            id,
            PendingAllocation {
                five,
                user_id: auth.user_id,
                key: auth.key,
                family,
                plan,
                lifetime,
                request: std::mem::take(m),
                reply_to: *ctx,
                timer,
            },
        );
        self.pending_by_tuple.insert(five, id);
        self.events.push_back(ServerEvent::BindRelay { id, plan });
    }

    /// The `200` to an Allocate: the relayed address, the time left, and how the client looks
    /// from outside.
    pub(super) fn reply_allocate_success(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        req: &Message,
        five: &FiveTuple,
        key: &[u8],
    ) {
        let Some(allocation) = self.allocations.get(five) else {
            return;
        };
        let remaining = allocation.expires.saturating_duration_since(now);
        let attrs: Setters = vec![
            Box::new(RelayedAddress {
                ip: allocation.advertised.ip(),
                port: allocation.advertised.port(),
            }),
            Box::new(Lifetime(Duration::from_secs(remaining.as_secs().max(1)))),
            Box::new(XorMappedAddress {
                ip: five.client.ip(),
                port: five.client.port(),
            }),
        ];
        self.reply_success(now, ctx, req, attrs, Some(key));
    }

    /// The allocation `five` belongs to `auth`, or the error response why not.
    fn owned_allocation(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        m: &Message,
        auth: &Authed,
    ) -> Option<FiveTuple> {
        let five = five_tuple(ctx);
        match self.allocations.get(&five) {
            None => {
                self.reply_error(
                    now,
                    ctx,
                    m,
                    CODE_ALLOC_MISMATCH,
                    Vec::new(),
                    Some(&auth.key),
                );
                None
            }
            Some(a) if a.user_id != auth.user_id => {
                self.reply_error(
                    now,
                    ctx,
                    m,
                    CODE_WRONG_CREDENTIALS,
                    Vec::new(),
                    Some(&auth.key),
                );
                None
            }
            Some(_) => Some(five),
        }
    }

    fn handle_refresh(&mut self, now: Instant, ctx: &TransportContext, m: &mut Message) {
        let Some(auth) = self.authenticate(now, ctx, m) else {
            return;
        };
        if self.reject_unknown_attributes(now, ctx, m, &auth) {
            return;
        }
        let Some(five) = self.owned_allocation(now, ctx, m, &auth) else {
            return;
        };
        let requested = if m.contains(ATTR_LIFETIME) {
            let mut lifetime = Lifetime::default();
            if lifetime.get_from(m).is_err() {
                self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
                return;
            }
            Some(lifetime.0)
        } else {
            None
        };
        if requested == Some(Duration::ZERO) {
            self.remove_allocation(&five, super::AllocationEnd::Deleted);
            self.reply_success(
                now,
                ctx,
                m,
                vec![Box::new(Lifetime(Duration::ZERO))],
                Some(&auth.key),
            );
            return;
        }
        let granted = self.grant_lifetime(requested);
        let expires = now + granted;
        if let Some(a) = self.allocations.get_mut(&five) {
            a.expires = expires;
        }
        self.schedule(expires, Timer::Allocation(five));
        self.reply_success(
            now,
            ctx,
            m,
            vec![Box::new(Lifetime(granted))],
            Some(&auth.key),
        );
    }

    /// Whether the client may relay to `peer`; answers `403 Forbidden` if not.
    fn peer_allowed(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        m: &Message,
        auth: &Authed,
        peer: IpAddr,
    ) -> bool {
        let allowed = self
            .permission_handler
            .as_ref()
            .is_none_or(|h| h.allow(ctx.peer_addr, peer));
        if !allowed {
            self.reply_error(now, ctx, m, CODE_FORBIDDEN, Vec::new(), Some(&auth.key));
        }
        allowed
    }

    fn handle_create_permission(&mut self, now: Instant, ctx: &TransportContext, m: &mut Message) {
        let Some(auth) = self.authenticate(now, ctx, m) else {
            return;
        };
        if self.reject_unknown_attributes(now, ctx, m, &auth) {
            return;
        }
        let Some(five) = self.owned_allocation(now, ctx, m, &auth) else {
            return;
        };
        let peers = match peer_addresses(m) {
            Some(peers) if !peers.is_empty() => peers,
            _ => {
                self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
                return;
            }
        };
        let family = self.allocations[&five].family;
        // All or none: a request naming one unacceptable peer installs nothing.
        for peer in &peers {
            if !family.matches(peer.ip()) {
                self.reply_error(
                    now,
                    ctx,
                    m,
                    CODE_PEER_ADDR_FAMILY_MISMATCH,
                    Vec::new(),
                    Some(&auth.key),
                );
                return;
            }
            if !self.peer_allowed(now, ctx, m, &auth, peer.ip()) {
                return;
            }
        }
        let expires = now + self.permission_lifetime;
        for peer in &peers {
            self.install_permission(&five, peer.ip(), expires);
        }
        self.reply_success(now, ctx, m, Vec::new(), Some(&auth.key));
    }

    fn install_permission(&mut self, five: &FiveTuple, ip: IpAddr, expires: Instant) {
        if let Some(a) = self.allocations.get_mut(five) {
            a.permissions.insert(ip, expires);
            self.schedule(expires, Timer::Permission(*five, ip));
        }
    }

    fn handle_channel_bind(&mut self, now: Instant, ctx: &TransportContext, m: &mut Message) {
        let Some(auth) = self.authenticate(now, ctx, m) else {
            return;
        };
        if self.reject_unknown_attributes(now, ctx, m, &auth) {
            return;
        }
        let Some(five) = self.owned_allocation(now, ctx, m, &auth) else {
            return;
        };
        let mut number = ChannelNumber::default();
        let mut peer = PeerAddress::default();
        if number.get_from(m).is_err() || !number.valid() || peer.get_from(m).is_err() {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
        let peer = SocketAddr::new(peer.ip, peer.port);
        let number = number.0;
        if !self.allocations[&five].family.matches(peer.ip()) {
            self.reply_error(
                now,
                ctx,
                m,
                CODE_PEER_ADDR_FAMILY_MISMATCH,
                Vec::new(),
                Some(&auth.key),
            );
            return;
        }
        if !self.peer_allowed(now, ctx, m, &auth, peer.ip()) {
            return;
        }
        let allocation = &self.allocations[&five];
        // A number may name one peer and a peer one number, until the binding lapses.
        let number_taken = allocation
            .channels
            .get(&number)
            .is_some_and(|c| c.peer != peer && c.expires > now);
        let peer_taken = allocation.peer_channels.get(&peer).is_some_and(|&n| {
            n != number && allocation.channels.get(&n).is_some_and(|c| c.expires > now)
        });
        if number_taken || peer_taken {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
        let bound_until = now + self.channel_bind_timeout;
        if let Some(a) = self.allocations.get_mut(&five) {
            if let Some(old) = a.channels.get(&number)
                && old.peer != peer
            {
                let old_peer = old.peer;
                a.peer_channels.remove(&old_peer);
            }
            a.channels.insert(
                number,
                Channel {
                    peer,
                    expires: bound_until,
                },
            );
            a.peer_channels.insert(peer, number);
        }
        self.schedule(bound_until, Timer::Channel(five, number));
        // Binding a channel also installs (or refreshes) a permission for the peer's address.
        let permitted_until = now + self.permission_lifetime;
        self.install_permission(&five, peer.ip(), permitted_until);
        self.reply_success(now, ctx, m, Vec::new(), Some(&auth.key));
    }

    /// A Send indication: relay its payload to the peer, if there is permission. Indications are
    /// never answered, and never authenticated: the allocation is the credential.
    fn handle_send_indication(&mut self, now: Instant, ctx: &TransportContext, m: &Message) {
        let five = five_tuple(ctx);
        let Some(allocation) = self.allocations.get(&five) else {
            return;
        };
        let Some(peers) = peer_addresses(m) else {
            return;
        };
        let [peer] = peers[..] else {
            return;
        };
        let mut data = Data::default();
        if data.get_from(m).is_err() {
            return;
        }
        if !allocation.has_permission(peer.ip(), now) || !allocation.family.matches(peer.ip()) {
            log::trace!("dropping Send to {peer}: no permission");
            return;
        }
        self.relay_to_peer(now, allocation.relay, peer, data.0);
    }

    /// ChannelData from the client: relay its payload to the peer the channel names.
    pub(super) fn handle_channel_data(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        data: &[u8],
    ) {
        let five = five_tuple(ctx);
        let Some(allocation) = self.allocations.get(&five) else {
            return;
        };
        let number = u16::from_be_bytes([data[0], data[1]]);
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let Some(payload) = data.get(4..4 + length) else {
            return;
        };
        let Some(channel) = allocation.channels.get(&number) else {
            return;
        };
        if channel.expires <= now || !allocation.has_permission(channel.peer.ip(), now) {
            return;
        }
        let (relay, peer) = (allocation.relay, channel.peer);
        self.relay_to_peer(now, relay, peer, payload.to_vec());
    }

    fn relay_to_peer(
        &mut self,
        now: Instant,
        relay: SocketAddr,
        peer: SocketAddr,
        payload: Vec<u8>,
    ) {
        self.transmits.push_back(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: relay,
                peer_addr: peer,
                transport_protocol: shared::TransportProtocol::UDP,
                ecn: None,
            },
            message: BytesMut::from(&payload[..]),
        });
    }
}
