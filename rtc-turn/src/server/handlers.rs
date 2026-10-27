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

use super::allocation::Allocation;
use super::allocation::{Channel, FiveTuple};
use super::auth::AuthRequest;
use super::relay::RelayFamily;
use super::tcp::{PeerConn, PeerConnId, PeerStage};
use super::{PendingAllocation, RelayId, Server, ServerEvent, Stage, Timer};
use crate::proto::channum::ChannelNumber;
use crate::proto::connid::ConnectionId;
use crate::proto::data::Data;
use crate::proto::evenport::EvenPort;
use crate::proto::lifetime::Lifetime;
use crate::proto::peeraddr::PeerAddress;
use crate::proto::relayaddr::RelayedAddress;
use crate::proto::reqtrans::RequestedTransport;
use crate::proto::rsrvtoken::ReservationToken;
use crate::proto::{PROTO_TCP, PROTO_UDP};

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
    ATTR_CONNECTION_ID,
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
    m.iter_attributes()
        .filter(|a| a.typ == ATTR_XOR_PEER_ADDRESS)
        .map(|a| decode_xor_address(a.value, &m.transaction_id))
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

    pub(super) fn reply_success(
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
        let credentials = if realm == self.realm
            && let Some(handler) = &self.auth_handler
        {
            handler.auth(&AuthRequest {
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
    /// server does not understand ([RFC 8489 §6.3.1]). Returns whether it did (and so was
    /// answered).
    ///
    /// [RFC 8489 §6.3.1]: https://www.rfc-editor.org/rfc/rfc8489#section-6.3.1
    fn reject_unknown_attributes(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        m: &Message,
    ) -> bool {
        let unknown: Vec<AttrType> = m
            .iter_attributes()
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
            None,
        );
        true
    }

    pub(super) fn handle_stun(&mut self, now: Instant, ctx: &TransportContext, mut m: Message) {
        if m.typ.class == CLASS_REQUEST && self.reject_unknown_attributes(now, ctx, &m) {
            return;
        }
        let can_relay = self.generator.is_some() && self.auth_handler.is_some();
        match (m.typ.class, m.typ.method) {
            (CLASS_REQUEST, METHOD_BINDING) => self.handle_binding(now, ctx, &m),
            (
                CLASS_REQUEST,
                METHOD_ALLOCATE
                | METHOD_REFRESH
                | METHOD_CREATE_PERMISSION
                | METHOD_CHANNEL_BIND
                | METHOD_CONNECT
                | METHOD_CONNECTION_BIND,
            ) if !can_relay => {
                // A STUN-only server has no relays to offer.
                self.reply_error(now, ctx, &m, CODE_BAD_REQUEST, Vec::new(), None);
            }
            (CLASS_REQUEST, METHOD_ALLOCATE) => self.handle_allocate(now, ctx, m),
            (CLASS_REQUEST, METHOD_REFRESH) => self.handle_refresh(now, ctx, &mut m),
            (CLASS_REQUEST, METHOD_CREATE_PERMISSION) => {
                self.handle_create_permission(now, ctx, &mut m)
            }
            (CLASS_REQUEST, METHOD_CHANNEL_BIND) => self.handle_channel_bind(now, ctx, &mut m),
            (CLASS_REQUEST, METHOD_CONNECT) => self.handle_connect(now, ctx, &mut m),
            (CLASS_REQUEST, METHOD_CONNECTION_BIND) => {
                self.handle_connection_bind(now, ctx, &mut m)
            }
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

        let mut transport = RequestedTransport::default();
        if transport.get_from(m).is_err() {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
        // RFC 6062 §4.1: a TCP allocation is asked for over a TCP control connection, and takes
        // none of the options that name a datagram port.
        let tcp = transport.protocol == PROTO_TCP;
        let unsupported = match transport.protocol {
            PROTO_UDP => false,
            PROTO_TCP => ctx.transport_protocol != shared::TransportProtocol::TCP,
            _ => true,
        };
        if unsupported {
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
        if tcp && (m.contains(ATTR_EVEN_PORT) || m.contains(ATTR_RESERVATION_TOKEN)) {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
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
        let has_token = m.contains(ATTR_RESERVATION_TOKEN);
        // A token names a port already chosen, so neither an even port nor a family (which the
        // token's port settles) may be asked for beside it.
        if has_token && (even || m.contains(ATTR_REQUESTED_ADDRESS_FAMILY)) {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
        let mut reserve = false;
        if even {
            let mut even_port = EvenPort::default();
            if even_port.get_from(m).is_err() {
                self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
                return;
            }
            reserve = even_port.reserve_port();
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
            self.default_family(ctx)
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
        let lifetime = self.grant_lifetime(requested_lifetime);

        if has_token {
            self.claim_reservation(now, ctx, m, five, auth, lifetime);
            return;
        }

        let Some(generator) = self.generator.as_mut() else {
            return;
        };
        let plan = if even {
            generator.plan_even(family)
        } else {
            generator.plan(family, 0)
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
                even,
                tcp,
                reserve,
                attempts: 0,
                stage: Stage::Relay,
            },
        );
        self.pending_by_tuple.insert(five, id);
        self.events.push_back(if tcp {
            ServerEvent::BindRelayTcp { id, plan }
        } else {
            ServerEvent::BindRelay { id, plan }
        });
    }

    /// The family of relay an Allocate that names none gets: IPv4 under [RFC 6156]'s rule, or
    /// else the family of the address the request arrived on (the client's own, when the server
    /// listens on a wildcard).
    ///
    /// [RFC 6156]: https://www.rfc-editor.org/rfc/rfc6156
    fn default_family(&self, ctx: &TransportContext) -> RelayFamily {
        if self.strict_address_family {
            return RelayFamily::V4;
        }
        let mut ip = ctx.local_addr.ip();
        if ip.is_unspecified() {
            ip = ctx.peer_addr.ip();
        }
        match ip {
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => RelayFamily::V6,
            _ => RelayFamily::V4,
        }
    }

    /// An Allocate quoting a `RESERVATION-TOKEN`: the port held under it becomes the relay.
    fn claim_reservation(
        &mut self,
        now: Instant,
        ctx: &TransportContext,
        m: &Message,
        five: FiveTuple,
        auth: Authed,
        lifetime: Duration,
    ) {
        let token: Option<[u8; 8]> = m
            .get_value(ATTR_RESERVATION_TOKEN)
            .ok()
            .and_then(|v| v.try_into().ok());
        let reservation = token
            .filter(|t| self.reservations.get(t).is_some_and(|r| r.expires > now))
            .and_then(|t| self.reservations.remove(&t));
        let Some(reservation) = reservation else {
            // Unknown, spent or lapsed: nothing is held under it.
            self.reply_error(
                now,
                ctx,
                m,
                CODE_INSUFFICIENT_CAPACITY,
                Vec::new(),
                Some(&auth.key),
            );
            return;
        };
        self.held.remove(&reservation.relay);
        let advertised = SocketAddr::new(reservation.advertised_ip, reservation.relay.port());
        let expires = now + lifetime;
        self.allocations.insert(
            five,
            Allocation {
                user_id: auth.user_id.clone(),
                relay: reservation.relay,
                advertised,
                family: reservation.family,
                allocate_tid: m.transaction_id,
                reservation_token: None,
                tcp: false,
                expires,
                permissions: Default::default(),
                channels: Default::default(),
                peer_channels: Default::default(),
            },
        );
        self.by_relay.insert(reservation.relay, five);
        self.schedule(expires, Timer::Allocation(five));
        self.events.push_back(ServerEvent::AllocationCreated {
            five_tuple: five,
            user_id: auth.user_id,
            relayed_addr: advertised,
        });
        self.reply_allocate_success(now, ctx, m, &five, &auth.key);
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
        let mut attrs: Setters = vec![
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
        if let Some(token) = allocation.reservation_token {
            attrs.push(Box::new(ReservationToken(token.to_vec())));
        }
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
        let Some(five) = self.owned_allocation(now, ctx, m, &auth) else {
            return;
        };
        // A Refresh may not change the family of a relay ([RFC 6156 §4.2.2]); one that names a
        // family other than the allocation's is a mismatch.
        //
        // [RFC 6156 §4.2.2]: https://www.rfc-editor.org/rfc/rfc6156#section-4.2.2
        if m.contains(ATTR_REQUESTED_ADDRESS_FAMILY) {
            let value = m
                .get_value(ATTR_REQUESTED_ADDRESS_FAMILY)
                .unwrap_or_default();
            let family = match value {
                [0x01, ..] if value.len() == 4 => Some(RelayFamily::V4),
                [0x02, ..] if value.len() == 4 => Some(RelayFamily::V6),
                _ => None,
            };
            let code = if value.len() != 4 {
                Some(CODE_BAD_REQUEST)
            } else if family != Some(self.allocations[&five].family) {
                Some(CODE_PEER_ADDR_FAMILY_MISMATCH)
            } else {
                None
            };
            if let Some(code) = code {
                self.reply_error(now, ctx, m, code, Vec::new(), Some(&auth.key));
                return;
            }
        }
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
        let Some(five) = self.owned_allocation(now, ctx, m, &auth) else {
            return;
        };
        // Channels carry datagrams, which a TCP allocation (RFC 6062) does not relay.
        if self.allocations[&five].tcp {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
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
        if allocation.tcp {
            return;
        }
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
        if allocation.tcp {
            return;
        }
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

    /// `Connect` ([RFC 6062 §5.2]): open a TCP connection from the relay to a peer.
    ///
    /// [RFC 6062 §5.2]: https://www.rfc-editor.org/rfc/rfc6062#section-5.2
    fn handle_connect(&mut self, now: Instant, ctx: &TransportContext, m: &mut Message) {
        let Some(auth) = self.authenticate(now, ctx, m) else {
            return;
        };
        let Some(five) = self.owned_allocation(now, ctx, m, &auth) else {
            return;
        };
        if !self.allocations[&five].tcp {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
        let peer = match peer_addresses(m).as_deref() {
            Some([peer]) => *peer,
            _ => {
                self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
                return;
            }
        };
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
        // One connection per peer at a time, whether still being opened or already open (446).
        if self
            .tcp_peers
            .values()
            .any(|c| c.five == five && c.peer == peer)
        {
            self.reply_error(
                now,
                ctx,
                m,
                CODE_CONN_ALREADY_EXISTS,
                Vec::new(),
                Some(&auth.key),
            );
            return;
        }
        if self.peer_connections_of(&five) >= super::tcp::MAX_PEER_CONNECTIONS_PER_ALLOCATION {
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
        // Connecting to a peer is itself the permission to hear from it.
        let permitted_until = now + self.permission_lifetime;
        self.install_permission(&five, peer.ip(), permitted_until);

        let relay = self.allocations[&five].relay;
        let id = PeerConnId(self.next_peer_id);
        self.next_peer_id += 1;
        let timer = self.schedule(
            now + super::tcp::CONNECTION_BIND_TIMEOUT,
            Timer::TcpPeer(id),
        );
        self.tcp_peers.insert(
            id,
            PeerConn {
                five,
                user_id: auth.user_id,
                relay,
                peer,
                connection_id: 0,
                stage: PeerStage::Connecting {
                    request: std::mem::take(m),
                    reply_to: *ctx,
                    key: auth.key,
                },
                timer: Some(timer),
            },
        );
        self.events
            .push_back(ServerEvent::ConnectPeer { id, relay, peer });
    }

    /// `ConnectionBind` ([RFC 6062 §5.4]), on a new client connection: attach it to the peer
    /// connection the id names.
    ///
    /// [RFC 6062 §5.4]: https://www.rfc-editor.org/rfc/rfc6062#section-5.4
    fn handle_connection_bind(&mut self, now: Instant, ctx: &TransportContext, m: &mut Message) {
        let Some(auth) = self.authenticate(now, ctx, m) else {
            return;
        };
        let mut connection_id = ConnectionId::default();
        if connection_id.get_from(m).is_err() {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        }
        // The credentials must be the allocation's own: an id is not a capability.
        let id = self
            .tcp_by_connection_id
            .get(&connection_id.0)
            .copied()
            .filter(|id| {
                self.tcp_peers.get(id).is_some_and(|c| {
                    c.user_id == auth.user_id && matches!(c.stage, PeerStage::Waiting)
                })
            });
        let Some(id) = id else {
            self.reply_error(now, ctx, m, CODE_BAD_REQUEST, Vec::new(), Some(&auth.key));
            return;
        };
        if let Some(conn) = self.tcp_peers.get_mut(&id) {
            conn.stage = PeerStage::Bound;
            if let Some(timer) = conn.timer.take() {
                self.timers.remove(&timer);
            }
        }
        self.reply_success(now, ctx, m, vec![Box::new(connection_id)], Some(&auth.key));
        self.events.push_back(ServerEvent::BindData {
            id,
            client: ctx.peer_addr,
            server: ctx.local_addr,
        });
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
