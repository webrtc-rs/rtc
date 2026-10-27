//! ICE candidates: the addresses an agent can be reached at.
//!
//! A [`Candidate`](crate::candidate::Candidate) pairs a transport address with a [`CandidateType`](crate::candidate::CandidateType) — host, server-reflexive,
//! peer-reflexive or relay — and the bookkeeping ICE needs: a priority, a foundation, and
//! last-sent/last-received times that feed consent freshness.
//!
//! Type drives priority, and priority drives check order: host candidates are tried first
//! because they need no traversal, relay candidates last because they always cost an extra hop.
//! The [`foundation`](crate::candidate::Candidate::foundation) groups candidates that share a base and transport,
//! so redundant checks can be skipped.
//!
//! Each type has its own constructor module (`candidate_host`, `candidate_relay`, …), all
//! built on the shared [`CandidateConfig`](crate::candidate::CandidateConfig).

#[cfg(test)]
mod candidate_pair_test;
#[cfg(test)]
mod candidate_test;

//TODO: #[cfg(test)]
//TODO: mod candidate_relay_test;
/*TODO: #[cfg(test)]
TODO: mod candidate_server_reflexive_test;
*/

/// Host candidates: an address on a local interface.
pub mod candidate_host;
/// A local/remote candidate pair and its check state.
pub mod candidate_pair;
/// Peer-reflexive candidates, learned from an inbound check's source address.
pub mod candidate_peer_reflexive;
/// Relay candidates, allocated on a TURN server.
pub mod candidate_relay;
/// Server-reflexive candidates, learned from a STUN Binding response.
pub mod candidate_server_reflexive;

use crate::network_type::NetworkType;
use crate::tcp_type::TcpType;
use crc::{CRC_32_ISCSI, Crc};
use serde::{Deserialize, Serialize};
use shared::error::*;
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::candidate::candidate_host::CandidateHostConfig;
use crate::candidate::candidate_peer_reflexive::CandidatePeerReflexiveConfig;
use crate::candidate::candidate_relay::CandidateRelayConfig;
use crate::candidate::candidate_server_reflexive::CandidateServerReflexiveConfig;
use crate::network_type::determine_network_type;

pub(crate) const RECEIVE_MTU: usize = 8192;
pub(crate) const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;

/// The amount a TCP candidate's type preference is lowered by, relative to the same candidate
/// type over UDP (pion's `defaultTCPPriorityOffset`, from libwebrtc).
pub const DEFAULT_TCP_PRIORITY_OFFSET: u16 = 27;

/// The local preference a relay candidate gets for its relay protocol, from libwebrtc's
/// `RELAY_PROTOCOL_PREFERENCE` ordering: TLS < TCP < DTLS < UDP.
pub(crate) fn relay_protocol_preference(relay_protocol: &str) -> u16 {
    match relay_protocol {
        "tls" => 0,
        "tcp" => 1,
        "dtls" => 2,
        _ => 3,
    }
}

/// Indicates that the candidate is used for RTP.
pub(crate) const COMPONENT_RTP: u16 = 1;
/// Indicates that the candidate is used for RTCP.
pub(crate) const COMPONENT_RTCP: u16 = 0;

/// Represents the type of candidate `CandidateType` enum.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CandidateType {
    #[default]
    #[serde(rename = "unspecified")]
    /// No candidate type was set.
    Unspecified,
    #[serde(rename = "host")]
    /// An address on one of this host's own interfaces.
    ///
    /// Highest priority: reachable without traversal when both peers share a network.
    Host,
    #[serde(rename = "srflx")]
    /// This host's address as seen by a STUN server — its public mapping through the NAT.
    ServerReflexive,
    #[serde(rename = "prflx")]
    /// An address learned from a peer's inbound connectivity check.
    ///
    /// Discovered during checking rather than gathering, when a NAT maps a different port per
    /// destination.
    PeerReflexive,
    #[serde(rename = "relay")]
    /// An address allocated on a TURN server, which forwards on this host's behalf.
    ///
    /// Lowest priority: it always costs an extra hop.
    Relay,
}

// String makes CandidateType printable
impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
            CandidateType::Unspecified => "Unknown candidate type",
        };
        write!(f, "{s}")
    }
}

impl CandidateType {
    /// Returns the preference weight of a `CandidateType`.
    ///
    /// 4.1.2.2.  Guidelines for Choosing Type and Local Preferences
    /// The RECOMMENDED values are 126 for host candidates, 100
    /// for server reflexive candidates, 110 for peer reflexive candidates,
    /// and 0 for relayed candidates.
    #[must_use]
    pub const fn preference(self) -> u16 {
        match self {
            Self::Host => 126,
            Self::PeerReflexive => 110,
            Self::ServerReflexive => 100,
            Self::Relay | CandidateType::Unspecified => 0,
        }
    }
}

pub(crate) fn contains_candidate_type(
    candidate_type: CandidateType,
    candidate_type_list: &[CandidateType],
) -> bool {
    if candidate_type_list.is_empty() {
        return false;
    }
    for ct in candidate_type_list {
        if *ct == candidate_type {
            return true;
        }
    }
    false
}

/// One `a=candidate` extension attribute: a key/value pair after the `rport` field, such as
/// `generation 0` or `network-id 2` (RFC 5245 §15.1 `extension-att-name/extension-att-value`).
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct CandidateExtension {
    /// The extension's name.
    pub key: String,
    /// The extension's value; empty values are tolerated (seen in the wild).
    pub value: String,
}

impl CandidateExtension {
    /// Builds an extension from a key/value pair.
    pub fn new(key: &str, value: &str) -> Self {
        CandidateExtension {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }
}

/// Convey transport addresses related to the candidate, useful for diagnostics and other purposes.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct CandidateRelatedAddress {
    /// The address of the related candidate — the base this one was derived from.
    /// The candidate's address.
    pub address: String,
    /// The port of the related candidate.
    /// The candidate's port.
    pub port: u16,
}

// String makes CandidateRelatedAddress printable
impl fmt::Display for CandidateRelatedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " related {}:{}", self.address, self.port)
    }
}

#[derive(Default)]
/// The fields common to every candidate type, used when constructing one.
pub struct CandidateConfig {
    /// A unique identifier for this candidate; generated when left empty.
    pub candidate_id: String,
    /// The transport, `udp` or `tcp`.
    pub network: String,
    /// The candidate's address.
    pub address: String,
    /// The candidate's port.
    pub port: u16,
    /// The RTP component id: `1` for RTP, `2` for RTCP when not multiplexed.
    pub component: u16,
    /// The candidate priority; computed from the type and local preference when zero.
    pub priority: u32,
    /// The foundation, which groups candidates that share a base and transport.
    ///
    /// Pairs with the same foundation are checked together, so redundant checks are avoided.
    pub foundation: String,
}

#[derive(Clone, Debug)]
/// One ICE candidate: a transport address this agent can be reached at, or can reach a peer
/// at, together with its type, priority and liveness bookkeeping.
pub struct Candidate {
    pub(crate) id: String,
    pub(crate) network_type: NetworkType,
    pub(crate) candidate_type: CandidateType,

    pub(crate) component: u16,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) related_address: Option<CandidateRelatedAddress>,
    pub(crate) tcp_type: TcpType,

    pub(crate) resolved_addr: SocketAddr,

    /// When traffic was last sent on this candidate, or `None` if none ever has been.
    pub(crate) last_sent: Option<Instant>,
    /// When traffic was last received on this candidate, or `None` if none ever has been.
    pub(crate) last_received: Option<Instant>,

    pub(crate) foundation_override: String,
    pub(crate) priority_override: u32,
    /// The transport between this agent and the relay server (`udp`, `tcp`, `tls`, `dtls`);
    /// empty for candidates that are not relayed.
    pub(crate) relay_protocol: String,

    pub(crate) network: String,

    pub(crate) url: Option<String>,

    /// Extension attributes carried on this candidate (`generation`, `network-id`, ...).
    pub(crate) extensions: Vec<CandidateExtension>,

    /// How much a TCP candidate's type preference is lowered relative to UDP. Stamped by the
    /// agent from its configuration; standalone candidates use the default of 27.
    pub(crate) tcp_priority_offset: u16,

    /// The local preference of a relay candidate, derived from its relay protocol. Only read
    /// for relay candidates.
    pub(crate) relay_local_preference: u16,
}

impl Default for Candidate {
    fn default() -> Self {
        Self {
            id: String::new(),
            network_type: NetworkType::Unspecified,
            candidate_type: CandidateType::default(),

            component: 0,
            address: String::new(),
            port: 0,
            related_address: None,
            tcp_type: TcpType::default(),

            resolved_addr: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),

            last_sent: None,
            last_received: None,

            foundation_override: String::new(),
            priority_override: 0,
            relay_protocol: String::new(),
            network: String::new(),

            url: None,

            extensions: vec![],
            tcp_priority_offset: DEFAULT_TCP_PRIORITY_OFFSET,
            relay_local_preference: DEFAULT_LOCAL_PREFERENCE,
        }
    }
}

// String makes the candidateBase printable
impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(related_address) = self.related_address() {
            write!(
                f,
                "{} {} {}:{}{}",
                self.network_type(),
                self.candidate_type(),
                self.address(),
                self.port(),
                related_address,
            )
        } else {
            write!(
                f,
                "{} {} {}:{}",
                self.network_type(),
                self.candidate_type(),
                self.address(),
                self.port(),
            )
        }
    }
}

impl Candidate {
    /// The candidate's foundation, computed from its type, base address and transport.
    ///
    /// A foundation groups equivalent candidates; it is deterministic bookkeeping rather than a
    /// secret, random identifier. CRC-32C is therefore intentional here.
    pub fn foundation(&self) -> String {
        if !self.foundation_override.is_empty() {
            return self.foundation_override.clone();
        }

        let mut buf = vec![];
        buf.extend_from_slice(self.candidate_type().to_string().as_bytes());
        buf.extend_from_slice(self.address.as_bytes());
        buf.extend_from_slice(self.network_type().to_string().as_bytes());

        let checksum = Crc::<u32>::new(&CRC_32_ISCSI).checksum(&buf);

        format!("{checksum}")
    }

    /// Returns Candidate ID.
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    /// Returns candidate component.
    pub fn component(&self) -> u16 {
        self.component
    }

    /// Sets candidate component.
    pub fn set_component(&mut self, component: u16) {
        self.component = component;
    }

    /// When traffic was last received on this candidate.
    ///
    /// `None` until the first packet arrives. A freshly constructed or freshly parsed candidate
    /// has not received anything, and previously said it had — it was seeded with the
    /// construction instant, which also meant every candidate constructor needed a clock.
    pub fn last_received(&self) -> Option<Instant> {
        self.last_received
    }

    /// When traffic was last sent on this candidate, or `None` if none ever has been.
    pub fn last_sent(&self) -> Option<Instant> {
        self.last_sent
    }

    /// Returns candidate NetworkType.
    pub fn network_type(&self) -> NetworkType {
        self.network_type
    }

    /// Returns Candidate Address.
    pub fn address(&self) -> &str {
        self.address.as_str()
    }

    /// Returns Candidate Port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The type preference of this candidate on its transport: the RFC 8445 §5.1.2.2 value,
    /// lowered by the agent's TCP priority offset for TCP candidates.
    pub fn type_preference(&self) -> u16 {
        self.type_preference_for(self.candidate_type())
    }

    /// Computes the priority for this ICE Candidate.
    pub fn priority(&self) -> u32 {
        if self.priority_override != 0 {
            return self.priority_override;
        }

        // The local preference MUST be an integer from 0 (lowest preference) to
        // 65535 (highest preference) inclusive.  When there is only a single IP
        // address, this value SHOULD be set to 65535.  If there are multiple
        // candidates for a particular component for a particular data stream
        // that have the same type, the local preference MUST be unique for each
        // one.
        //
        // `256 - component` wraps in 16 bits, as in pion: a component above 256 (the field is
        // remote-supplied) must not overflow.
        (1 << 24) * u32::from(self.type_preference())
            + (1 << 8) * u32::from(self.local_preference())
            + u32::from(256u16.wrapping_sub(self.component()))
    }

    /// The type preference a candidate of `candidate_type` has on this candidate's transport:
    /// the RFC 8445 §5.1.2.2 value, lowered by the TCP priority offset for TCP candidates.
    /// Relay candidates (preference 0) are unaffected.
    pub(crate) fn type_preference_for(&self, candidate_type: CandidateType) -> u16 {
        let pref = candidate_type.preference();
        if pref == 0 {
            return 0;
        }

        if self.network_type.is_tcp() {
            pref.saturating_sub(self.tcp_priority_offset)
        } else {
            pref
        }
    }

    /// The value a Binding request sent from this candidate carries in its `PRIORITY`
    /// attribute: the candidate's priority recomputed with the type preference of a
    /// peer-reflexive candidate (RFC 8445 §7.1.1).
    ///
    /// The remote agent gives this priority to the peer-reflexive candidate it learns from the
    /// request (§7.3.1.3); sending the candidate's own type preference would let that candidate
    /// rank equal to the host candidate it was discovered through.
    pub(crate) fn prflx_priority(&self) -> u32 {
        (1 << 24) * u32::from(self.type_preference_for(CandidateType::PeerReflexive))
            + self.priority() % (1 << 24)
    }

    /// Returns `Option<CandidateRelatedAddress>`.
    pub fn related_address(&self) -> Option<CandidateRelatedAddress> {
        self.related_address.as_ref().cloned()
    }

    /// Returns candidate type.
    pub fn candidate_type(&self) -> CandidateType {
        self.candidate_type
    }

    /// The TCP role for ICE-TCP candidates; `Unspecified` for UDP.
    pub fn tcp_type(&self) -> TcpType {
        self.tcp_type
    }

    /// The STUN or TURN server this candidate was gathered from, if any.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Returns the string representation of the ICECandidate.
    pub fn marshal(&self) -> String {
        // An empty foundation round-trips through parsing as a single space; emit it empty.
        let foundation = if self.foundation() == " " {
            String::new()
        } else {
            self.foundation()
        };

        let mut val = format!(
            "{} {} {} {} {} {} typ {}",
            foundation,
            self.component(),
            self.network_type().network_short(),
            self.priority(),
            remove_zone_id_from_address(self.address()),
            self.port(),
            self.candidate_type()
        );

        if let Some(related_address) = self.related_address()
            && !related_address.address.is_empty()
            && related_address.port != 0
        {
            val += format!(
                " raddr {} rport {}",
                related_address.address, related_address.port,
            )
            .as_str();
        }

        let extensions = self.marshal_extensions();
        if !extensions.is_empty() {
            val += format!(" {extensions}").as_str();
        }

        val
    }

    /// The candidate's socket address.
    pub fn addr(&self) -> SocketAddr {
        self.resolved_addr
    }

    /// Returns the candidate's base address: the local transport address the
    /// candidate was derived from, i.e. the address packets for this candidate
    /// must be sent from (RFC 8445 §5.1.1).
    ///
    /// For server-reflexive and peer-reflexive candidates this is the related
    /// (host) address; for host and relay candidates the base is the candidate
    /// address itself.
    pub fn base_addr(&self) -> SocketAddr {
        match self.candidate_type {
            CandidateType::ServerReflexive | CandidateType::PeerReflexive => self
                .related_address
                .as_ref()
                .and_then(|ra| {
                    ra.address
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| SocketAddr::new(ip, ra.port))
                })
                .unwrap_or(self.resolved_addr),
            _ => self.resolved_addr,
        }
    }

    /// Records traffic on this candidate, updating its last-sent or last-received time.
    ///
    /// Feeds consent freshness — a pair that stops seeing traffic is eventually abandoned.
    pub fn seen(&mut self, now: Instant, outbound: bool) {
        if outbound {
            self.set_last_sent(now);
        } else {
            self.set_last_received(now);
        }
    }

    /// Used to compare two candidateBases.
    pub fn equal(&self, other: &Candidate) -> bool {
        self.network_type() == other.network_type()
            && self.candidate_type() == other.candidate_type()
            && self.address() == other.address()
            && self.port() == other.port()
            && self.tcp_type() == other.tcp_type()
            && self.related_address() == other.related_address()
    }

    /// Whether both candidates name the same transport address: the same network type, address
    /// and port, and TCP type (pion's `transportAddressEqual`). Unlike [`Candidate::equal`] the
    /// candidate type does not matter, which is what finds a signaled candidate that a
    /// peer-reflexive one already stands in for.
    pub(crate) fn transport_address_equal(&self, other: &Candidate) -> bool {
        self.network_type() == other.network_type()
            && self.tcp_type() == other.tcp_type()
            && self.addr() == other.addr()
    }

    /// Same as [`Self::equal`], but also compares the extension attributes.
    pub fn deep_equal(&self, other: &Candidate) -> bool {
        self.equal(other) && self.extensions_equal(&other.extensions)
    }

    /// Returns true if this candidate can be paired with `other` according to
    /// ICE candidate pairing rules.
    ///
    /// Candidates must share the same network type (protocol and address family)
    /// and have compatible TCP types (RFC 6544). UDP candidates use
    /// `TcpType::Unspecified`.
    pub(crate) fn can_pair_with(&self, other: &Candidate) -> bool {
        if self.network_type() != other.network_type() {
            return false;
        }

        match (self.tcp_type(), other.tcp_type()) {
            (TcpType::Active, TcpType::Passive) => true,
            (TcpType::Passive, TcpType::Active) => true,
            (TcpType::SimultaneousOpen, TcpType::SimultaneousOpen) => true,
            (TcpType::Unspecified, TcpType::Unspecified) => true, // UDP candidates
            _ => false,
        }
    }

    /// Sets the resolved IP, deriving the network type from it.
    ///
    /// # Errors
    ///
    /// Fails if `ip`'s family does not match this candidate's network type.
    pub fn set_ip(&mut self, ip: &IpAddr) -> Result<()> {
        self.network_type = determine_network_type(&self.network, ip)?;
        self.resolved_addr = SocketAddr::new(*ip, self.port); //TODO:  create_addr(network_type, *ip, self.port);
        Ok(())
    }
}

impl Candidate {
    /// Records that traffic was received on this candidate at `now`.
    pub fn set_last_received(&mut self, now: Instant) {
        self.last_received = Some(now);
    }

    /// Records that traffic was sent on this candidate at `now`.
    pub fn set_last_sent(&mut self, now: Instant) {
        self.last_sent = Some(now);
    }

    /// The transport between this agent and the relay server, for a relay candidate
    /// (`udp`, `tcp`, `tls` or `dtls`); empty for any other kind.
    pub fn relay_protocol(&self) -> &str {
        &self.relay_protocol
    }

    /// Returns the local preference for this candidate.
    pub fn local_preference(&self) -> u16 {
        if self.candidate_type == CandidateType::Relay {
            // libwebrtc orders relay protocols: TLS < TCP < DTLS < UDP. The value feeds the
            // priority formula's local-preference field for relay candidates.
            return self.relay_local_preference;
        }

        if self.network_type().is_tcp() {
            // RFC 6544, section 4.2
            //
            // In Section 4.1.2.1 of [RFC5245], a recommended formula for UDP ICE
            // candidate prioritization is defined.  For TCP candidates, the same
            // formula and candidate type preferences SHOULD be used, and the
            // RECOMMENDED type preferences for the new candidate types defined in
            // this document (see Section 5) are 105 for NAT-assisted candidates and
            // 75 for UDP-tunneled candidates.
            //
            // (...)
            //
            // With TCP candidates, the local preference part of the recommended
            // priority formula is updated to also include the directionality
            // (active, passive, or simultaneous-open) of the TCP connection.  The
            // RECOMMENDED local preference is then defined as:
            //
            //     local preference = (2^13) * direction-pref + other-pref
            //
            // The direction-pref MUST be between 0 and 7 (both inclusive), with 7
            // being the most preferred.  The other-pref MUST be between 0 and 8191
            // (both inclusive), with 8191 being the most preferred.  It is
            // RECOMMENDED that the host, UDP-tunneled, and relayed TCP candidates
            // have the direction-pref assigned as follows: 6 for active, 4 for
            // passive, and 2 for S-O.  For the NAT-assisted and server reflexive
            // candidates, the RECOMMENDED values are: 6 for S-O, 4 for active, and
            // 2 for passive.
            //
            // (...)
            //
            // If any two candidates have the same type-preference and direction-
            // pref, they MUST have a unique other-pref.  With this specification,
            // this usually only happens with multi-homed hosts, in which case
            // other-pref is the preference for the particular IP address from which
            // the candidate was obtained.  When there is only a single IP address,
            // this value SHOULD be set to the maximum allowed value (8191).
            let other_pref: u16 = 8191;

            let direction_pref: u16 = match self.candidate_type() {
                CandidateType::Host | CandidateType::Relay => match self.tcp_type() {
                    TcpType::Active => 6,
                    TcpType::Passive => 4,
                    TcpType::SimultaneousOpen => 2,
                    TcpType::Unspecified => 0,
                },
                CandidateType::PeerReflexive | CandidateType::ServerReflexive => {
                    match self.tcp_type() {
                        TcpType::SimultaneousOpen => 6,
                        TcpType::Active => 4,
                        TcpType::Passive => 2,
                        TcpType::Unspecified => 0,
                    }
                }
                CandidateType::Unspecified => 0,
            };

            (1 << 13) * direction_pref + other_pref
        } else {
            DEFAULT_LOCAL_PREFERENCE
        }
    }

    /// The candidate's extension attributes, with a manually-set TCP type reported first as a
    /// `tcptype` extension (the stored form and the wire form of the same information).
    pub fn extensions(&self) -> Vec<CandidateExtension> {
        let mut extensions = Vec::with_capacity(self.extensions.len() + 1);
        if self.tcp_type != TcpType::Unspecified {
            extensions.push(CandidateExtension {
                key: "tcptype".to_owned(),
                value: self.tcp_type.to_string(),
            });
        }
        extensions.extend(self.extensions.iter().cloned());
        extensions
    }

    /// Replaces the candidate's extension attributes.
    pub fn set_extensions(&mut self, extensions: Vec<CandidateExtension>) {
        self.extensions = extensions;
    }

    /// Returns the extension stored under `key`, if any. A manually-set TCP type answers for
    /// `tcptype` even when no stored extension carries it.
    pub fn get_extension(&self, key: &str) -> Option<CandidateExtension> {
        for extension in &self.extensions {
            if extension.key == key {
                return Some(extension.clone());
            }
        }

        if key == "tcptype" && self.tcp_type != TcpType::Unspecified {
            return Some(CandidateExtension {
                key: key.to_owned(),
                value: self.tcp_type.to_string(),
            });
        }

        None
    }

    /// Adds (or replaces the first) extension attribute. `tcptype` writes the candidate's TCP
    /// type instead of being stored; an empty key is an error.
    pub fn add_extension(&mut self, ext: CandidateExtension) -> Result<()> {
        if ext.key == "tcptype" {
            let tcp_type = TcpType::from(ext.value.as_str());
            if tcp_type == TcpType::Unspecified {
                return Err(Error::Other(format!(
                    "{:?}: invalid or unsupported TCPtype {}",
                    Error::ErrParseTcpType,
                    ext.value
                )));
            }
            self.tcp_type = tcp_type;
            return Ok(());
        }

        if ext.key.is_empty() {
            return Err(Error::Other(format!(
                "{:?}: key is empty",
                Error::ErrParseExtension
            )));
        }

        // Per spec extensions are not explicitly unique; setting one twice replaces the first.
        for existing in self.extensions.iter_mut() {
            if existing.key == ext.key {
                *existing = ext;
                return Ok(());
            }
        }
        self.extensions.push(ext);
        Ok(())
    }

    /// Removes the extension stored under `key`. Removing `tcptype` also clears a manually-set
    /// TCP type. Returns whether anything was removed.
    pub fn remove_extension(&mut self, key: &str) -> bool {
        let mut removed = false;
        if key == "tcptype" && self.tcp_type != TcpType::Unspecified {
            self.tcp_type = TcpType::Unspecified;
            removed = true;
        }

        if let Some(index) = self.extensions.iter().position(|ext| ext.key == key) {
            self.extensions.remove(index);
            removed = true;
        }

        removed
    }

    /// The wire form of the extension attributes: `key value key value ...`.
    pub fn marshal_extensions(&self) -> String {
        self.extensions()
            .iter()
            .map(|ext| format!("{} {}", ext.key, ext.value))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Whether this candidate's stored extensions equal `other` as a multiset (order-insensitive).
    pub fn extensions_equal(&self, other: &[CandidateExtension]) -> bool {
        if self.extensions.len() != other.len() {
            return false;
        }
        if self.extensions.is_empty() {
            return true;
        }
        if self.extensions.len() == 1 {
            return self.extensions[0] == other[0];
        }

        let mut freq: HashMap<&CandidateExtension, usize> = HashMap::new();
        for ext in &self.extensions {
            *freq.entry(ext).or_default() += 1;
        }
        for ext in other {
            match freq.get_mut(ext) {
                Some(count) if *count > 0 => *count -= 1,
                _ => return false,
            }
        }
        true
    }
}

/// Strips an IPv6 zone ID (`%eth0`) from an address: it identifies a local interface, which
/// does not survive into a candidate (pion ice#704).
fn remove_zone_id_from_address(addr: &str) -> &str {
    match addr.split_once('%') {
        Some((before, _)) => before,
        None => addr,
    }
}

/// Parses a candidate address into an IP, ignoring any IPv6 zone ID: Go's `netip.ParseAddr`
/// accepts zones (even with spaces) but Rust's `IpAddr` has nowhere to carry one, and a zone
/// never survives into a candidate anyway.
pub(crate) fn parse_candidate_ip(address: &str) -> Result<IpAddr> {
    match remove_zone_id_from_address(address).parse() {
        Ok(ip) => Ok(ip),
        Err(_) => Err(Error::ErrAddressParseFailed),
    }
}

/// Reads an ice-char token: ALPHA / DIGIT / "+" / "/", stopping at a space or the end of the
/// string, and enforcing a length limit (RFC 8839 grammar).
fn read_candidate_char_token(raw: &str, start: usize, limit: usize) -> Result<(&str, usize)> {
    for (i, char) in raw[start..].char_indices() {
        if char == ' ' {
            return Ok((&raw[start..start + i], start + i + 1));
        }

        if i >= limit {
            return Err(Error::Other(format!(
                "token too long: {} expected 1x{limit}",
                &raw[start..start + i]
            )));
        }

        if !char.is_ascii_alphanumeric() && char != '+' && char != '/' {
            return Err(Error::Other(format!("invalid ice-char token: {char}")));
        }
    }

    Ok((&raw[start..], raw.len()))
}

/// Reads a token until a space or the end of the string (no character validation).
fn read_candidate_string_token(raw: &str, start: usize) -> (&str, usize) {
    match raw[start..].find(' ') {
        Some(i) => (&raw[start..start + i], start + i + 1),
        None => (&raw[start..], raw.len()),
    }
}

/// Reads a digit token, stopping at a space or the end of the string, enforcing a length limit.
/// The value accumulates in a u64 so a 10-digit token cannot overflow before the range check.
fn read_candidate_digit_token(raw: &str, start: usize, limit: usize) -> Result<(u64, usize)> {
    let mut val: u64 = 0;
    for (i, char) in raw[start..].char_indices() {
        if char == ' ' {
            return Ok((val, start + i + 1));
        }

        if i >= limit {
            return Err(Error::Other(format!(
                "token too long: {} expected 1x{limit}",
                &raw[start..start + i]
            )));
        }

        if !char.is_ascii_digit() {
            return Err(Error::Other(format!("invalid digit token: {char}")));
        }

        val = val * 10 + u64::from(char as u8 - b'0');
    }

    Ok((val, raw.len()))
}

/// Reads and validates an RFC 4566 port (1*5DIGIT, at most 65535).
fn read_candidate_port(raw: &str, start: usize) -> Result<(u16, usize)> {
    let (port, pos) = read_candidate_digit_token(raw, start, 5)?;
    if port > u16::MAX as u64 {
        return Err(Error::Other(format!("invalid RFC 4566 port {port}")));
    }
    Ok((port as u16, pos))
}

/// Reads an RFC 8445 component-id (1*5DIGIT, at most 65535).
fn read_candidate_component(raw: &str, start: usize) -> Result<(u16, usize)> {
    let (component, pos) = read_candidate_digit_token(raw, start, 5)?;
    if component > u16::MAX as u64 {
        return Err(Error::Other(format!(
            "invalid RFC 8445 component-id {component}"
        )));
    }
    Ok((component as u16, pos))
}

/// Reads an RFC 8445 priority (1*10DIGIT, at most 2^32-1).
fn read_candidate_priority(raw: &str, start: usize) -> Result<(u32, usize)> {
    let (priority, pos) = read_candidate_digit_token(raw, start, 10)?;
    if priority > u32::MAX as u64 {
        return Err(Error::Other(format!(
            "invalid RFC 8445 priority {priority}"
        )));
    }
    Ok((priority as u32, pos))
}

/// Reads an RFC 4566 byte-string token: any byte except NUL, CR or LF, stopping at a space.
fn read_candidate_byte_string(raw: &str, start: usize) -> Result<(&str, usize)> {
    for (i, char) in raw[start..].char_indices() {
        if char == ' ' {
            return Ok((&raw[start..start + i], start + i + 1));
        }

        // 1*(%x01-09/%x0B-0C/%x0E-FF)
        if char != '\u{01}' {
            let code = char as u32;
            if !((0x01..=0x09).contains(&code)
                || (0x0B..=0x0C).contains(&code)
                || (0x0E..=0xFF).contains(&code))
            {
                return Err(Error::Other(format!(
                    "invalid byte-string character: {char:?}"
                )));
            }
        }
    }

    Ok((&raw[start..], raw.len()))
}

/// Reads and validates `raddr`/`rport` when present (RFC 5245 §15.1).
fn try_read_relative_addrs(raw: &str, start: usize) -> Result<(String, u16, usize)> {
    let (key, mut pos) = read_candidate_string_token(raw, start);
    if key != "raddr" {
        return Ok((String::new(), 0, start));
    }

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected raddr value in {raw}",
            Error::ErrParseRelatedAddr
        )));
    }

    let (raddr, new_pos) = read_candidate_string_token(raw, pos);
    pos = new_pos;

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected rport in {raw}",
            Error::ErrParseRelatedAddr
        )));
    }

    let (key, new_pos) = read_candidate_string_token(raw, pos);
    pos = new_pos;
    if key != "rport" {
        return Err(Error::Other(format!(
            "{:?}: expected rport in {raw}",
            Error::ErrParseRelatedAddr
        )));
    }

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected rport value in {raw}",
            Error::ErrParseRelatedAddr
        )));
    }

    let (rport, pos) = read_candidate_port(raw, pos)?;

    Ok((raddr.to_owned(), rport, pos))
}

/// Parses the candidate extensions: `*(SP extension-att-name SP extension-att-value)` where both
/// are byte-strings. A `tcptype` extension is extracted separately instead of being stored.
fn unmarshal_candidate_extensions(raw: &str) -> Result<(Vec<CandidateExtension>, Option<String>)> {
    let mut extensions = vec![];
    let mut tcp_type_raw: Option<String> = None;

    if raw.is_empty() {
        return Ok((extensions, tcp_type_raw));
    }

    if raw.starts_with(' ') {
        return Err(Error::Other(format!(
            "{:?}: unexpected space {raw}",
            Error::ErrParseExtension
        )));
    }

    let mut i = 0;
    while i < raw.len() {
        let (key, next) = read_candidate_byte_string(raw, i)?;
        i = next;

        // Not spec-compliant, but empty values are seen in the wild: a trailing key with no
        // value keeps an empty value.
        let mut value = "";
        if i < raw.len() {
            let (v, next) = read_candidate_byte_string(raw, i)?;
            value = v;
            i = next;
        }

        if key == "tcptype" {
            tcp_type_raw = Some(value.to_owned());
            continue;
        }

        extensions.push(CandidateExtension {
            key: key.to_owned(),
            value: value.to_owned(),
        });
    }

    Ok((extensions, tcp_type_raw))
}

/// Creates a Candidate from its string representation (RFC 5245 §15.1).
pub fn unmarshal_candidate(raw: &str) -> Result<Candidate> {
    // Handle candidates with the "candidate:" prefix as defined in RFC 5245 section 15.1.
    let raw = raw.strip_prefix("candidate:").unwrap_or(raw);

    // foundation ( 1*32ice-char ); an empty one is not compliant but seen in the wild.
    let (foundation, mut pos) = read_candidate_char_token(raw, 0, 32)
        .map_err(|err| Error::Other(format!("{:?}: {err} in {raw}", Error::ErrParseFoundation)))?;
    let foundation = foundation.to_owned();

    // Empty foundation, not RFC 8445 compliant but seen in the wild
    let foundation = if foundation.is_empty() {
        " ".to_owned()
    } else {
        foundation
    };

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected component in {raw}",
            Error::ErrAttributeTooShortIceCandidate
        )));
    }

    // component-id ( 1*5DIGIT )
    let (component, new_pos) = read_candidate_component(raw, pos)
        .map_err(|err| Error::Other(format!("{:?}: {err} in {raw}", Error::ErrParseComponent)))?;
    pos = new_pos;

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected transport in {raw}",
            Error::ErrAttributeTooShortIceCandidate
        )));
    }

    // transport ( "UDP" / transport-extension ; from RFC 3261 )
    let (protocol, new_pos) = read_candidate_string_token(raw, pos);
    let protocol = protocol.to_owned();
    pos = new_pos;

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected priority in {raw}",
            Error::ErrAttributeTooShortIceCandidate
        )));
    }

    // priority ( 1*10DIGIT )
    let (priority, new_pos) = read_candidate_priority(raw, pos)
        .map_err(|err| Error::Other(format!("{:?}: {err} in {raw}", Error::ErrParsePriority)))?;
    pos = new_pos;

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected address in {raw}",
            Error::ErrAttributeTooShortIceCandidate
        )));
    }

    // connection-address, from RFC 4566
    let (address, new_pos) = read_candidate_string_token(raw, pos);
    let address = remove_zone_id_from_address(address).to_owned();
    pos = new_pos;

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected port in {raw}",
            Error::ErrAttributeTooShortIceCandidate
        )));
    }

    // port from RFC 4566
    let (port, new_pos) = read_candidate_port(raw, pos)
        .map_err(|err| Error::Other(format!("{:?}: {err} in {raw}", Error::ErrParsePort)))?;
    pos = new_pos;

    // "typ"
    let (type_key, new_pos) = read_candidate_string_token(raw, pos);
    pos = new_pos;
    if type_key != "typ" {
        return Err(Error::Other(format!(
            "{:?} ({type_key})",
            Error::ErrUnknownCandidateType
        )));
    }

    if pos >= raw.len() {
        return Err(Error::Other(format!(
            "{:?}: expected candidate type in {raw}",
            Error::ErrAttributeTooShortIceCandidate
        )));
    }

    // cand-type ( "host" / "srflx" / "prflx" / "relay" )
    let (typ, new_pos) = read_candidate_string_token(raw, pos);
    let typ = typ.to_owned();
    pos = new_pos;

    let (raddr, rport, pos) = try_read_relative_addrs(raw, pos)?;

    let mut tcp_type = TcpType::Unspecified;
    let mut extensions = vec![];

    if pos < raw.len() {
        let (parsed_extensions, tcp_type_raw) = unmarshal_candidate_extensions(&raw[pos..])?;
        extensions = parsed_extensions;

        if let Some(tcp_type_raw) = tcp_type_raw
            && !tcp_type_raw.is_empty()
        {
            tcp_type = TcpType::from(tcp_type_raw.as_str());
            if tcp_type == TcpType::Unspecified {
                return Err(Error::Other(format!(
                    "{:?}: invalid or unsupported TCPtype {tcp_type_raw}",
                    Error::ErrParseTcpType
                )));
            }
        }
    }

    let base_config = CandidateConfig {
        network: protocol,
        address,
        port,
        component,
        priority,
        foundation,
        ..CandidateConfig::default()
    };

    let candidate = match typ.as_str() {
        "host" => CandidateHostConfig {
            base_config,
            tcp_type,
        }
        .new_candidate_host()?,
        "srflx" => CandidateServerReflexiveConfig {
            base_config,
            rel_addr: raddr,
            rel_port: rport,
            url: None,
        }
        .new_candidate_server_reflexive()?,
        "prflx" => CandidatePeerReflexiveConfig {
            base_config,
            rel_addr: raddr,
            rel_port: rport,
        }
        .new_candidate_peer_reflexive()?,
        "relay" => CandidateRelayConfig {
            base_config,
            rel_addr: raddr,
            rel_port: rport,
            url: None,
            relay_protocol: String::new(),
        }
        .new_candidate_relay()?,
        _ => {
            return Err(Error::Other(format!(
                "{:?} ({typ})",
                Error::ErrUnknownCandidateType
            )));
        }
    };

    let mut candidate = candidate;
    candidate.set_extensions(extensions);
    Ok(candidate)
}
