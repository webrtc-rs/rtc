#[cfg(test)]
mod candidate_pair_test;
#[cfg(test)]
mod candidate_test;

//TODO: #[cfg(test)]
//TODO: mod candidate_relay_test;
/*TODO: #[cfg(test)]
TODO: mod candidate_server_reflexive_test;
*/

pub mod candidate_host;
pub mod candidate_pair;
pub mod candidate_peer_reflexive;
pub mod candidate_relay;
pub mod candidate_server_reflexive;

use crate::network_type::NetworkType;
use crate::tcp_type::TcpType;
use crc::{Crc, CRC_32_ISCSI};
use serde::{Deserialize, Serialize};
use shared::error::*;
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

/// Indicates that the candidate is used for RTP.
pub(crate) const COMPONENT_RTP: u16 = 1;
/// Indicates that the candidate is used for RTCP.
pub(crate) const COMPONENT_RTCP: u16 = 0;

/// Represents the type of candidate `CandidateType` enum.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateType {
    #[default]
    #[serde(rename = "unspecified")]
    Unspecified,
    #[serde(rename = "host")]
    Host,
    #[serde(rename = "srflx")]
    ServerReflexive,
    #[serde(rename = "prflx")]
    PeerReflexive,
    #[serde(rename = "relay")]
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

/// Convey transport addresses related to the candidate, useful for diagnostics and other purposes.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct CandidateRelatedAddress {
    pub address: String,
    pub port: u16,
}

// String makes CandidateRelatedAddress printable
impl fmt::Display for CandidateRelatedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, " related {}:{}", self.address, self.port)
    }
}

#[derive(Default)]
pub struct CandidateConfig {
    pub candidate_id: String,
    pub network: String,
    pub address: String,
    pub port: u16,
    pub component: u16,
    pub priority: u32,
    pub foundation: String,
}

#[derive(Clone)]
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

    pub(crate) last_sent: Instant,
    pub(crate) last_received: Instant,

    pub(crate) foundation_override: String,
    pub(crate) priority_override: u32,

    pub(crate) network: String,
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

            last_sent: Instant::now(),
            last_received: Instant::now(),

            foundation_override: String::new(),
            priority_override: 0,
            network: String::new(),
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
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// Returns candidate component.
    pub fn component(&self) -> u16 {
        self.component
    }

    /// Sets candidate component.
    pub fn set_component(&mut self, component: u16) {
        self.component = component;
    }

    /// Returns a time indicating the last time this candidate was received.
    pub fn last_received(&self) -> Instant {
        self.last_received
    }

    /// Returns a time indicating the last time this candidate was sent.
    pub fn last_sent(&self) -> Instant {
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
        (1 << 24) * u32::from(self.candidate_type().preference())
            + (1 << 8) * u32::from(self.local_preference())
            + (256 - u32::from(self.component()))
    }

    /// Returns `Option<CandidateRelatedAddress>`.
    pub fn related_address(&self) -> Option<CandidateRelatedAddress> {
        self.related_address.as_ref().cloned()
    }

    /// Returns candidate type.
    pub fn candidate_type(&self) -> CandidateType {
        self.candidate_type
    }

    pub fn tcp_type(&self) -> TcpType {
        self.tcp_type
    }

    /// Returns the string representation of the ICECandidate.
    pub fn marshal(&self) -> String {
        let mut val = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation(),
            self.component(),
            self.network_type().network_short(),
            self.priority(),
            self.address(),
            self.port(),
            self.candidate_type()
        );

        if self.tcp_type != TcpType::Unspecified {
            val += format!(" tcptype {}", self.tcp_type()).as_str();
        }

        if let Some(related_address) = self.related_address() {
            val += format!(
                " raddr {} rport {}",
                related_address.address, related_address.port,
            )
            .as_str();
        }

        val
    }

    pub fn addr(&self) -> SocketAddr {
        self.resolved_addr
    }

    pub fn seen(&mut self, outbound: bool) {
        let now = Instant::now();

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
}

impl Candidate {
    pub fn set_last_received(&mut self, now: Instant) {
        self.last_received = now;
    }

    pub fn set_last_sent(&mut self, now: Instant) {
        self.last_sent = now;
    }

    /// Returns the local preference for this candidate.
    pub fn local_preference(&self) -> u16 {
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
}

/// Creates a Candidate from its string representation.
pub fn unmarshal_candidate(raw: &str) -> Result<Candidate> {
    let split: Vec<&str> = raw.split_whitespace().collect();
    if split.len() < 8 {
        return Err(Error::Other(format!(
            "{:?} ({})",
            Error::ErrAttributeTooShortIceCandidate,
            split.len()
        )));
    }

    // Foundation
    let foundation = split[0].to_owned();

    // Component
    let component: u16 = split[1].parse()?;

    // Network
    let network = split[2].to_owned();

    // Priority
    let priority: u32 = split[3].parse()?;

    // Address
    let address = split[4].to_owned();

    // Port
    let port: u16 = split[5].parse()?;

    let typ = split[7];

    let mut rel_addr = String::new();
    let mut rel_port = 0;
    let mut tcp_type = TcpType::Unspecified;

    if split.len() > 8 {
        let split2 = &split[8..];

        if split2[0] == "raddr" {
            if split2.len() < 4 {
                return Err(Error::Other(format!(
                    "{:?}: incorrect length",
                    Error::ErrParseRelatedAddr
                )));
            }

            // RelatedAddress
            split2[1].clone_into(&mut rel_addr);

            // RelatedPort
            rel_port = split2[3].parse()?;
        } else if split2[0] == "tcptype" {
            if split2.len() < 2 {
                return Err(Error::Other(format!(
                    "{:?}: incorrect length",
                    Error::ErrParseType
                )));
            }

            tcp_type = TcpType::from(split2[1]);
        }
    }

    match typ {
        "host" => {
            let config = CandidateHostConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                tcp_type,
            };
            config.new_candidate_host()
        }
        "srflx" => {
            let config = CandidateServerReflexiveConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                rel_addr,
                rel_port,
            };
            config.new_candidate_server_reflexive()
        }
        "prflx" => {
            let config = CandidatePeerReflexiveConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                rel_addr,
                rel_port,
            };

            config.new_candidate_peer_reflexive()
        }
        "relay" => {
            let config = CandidateRelayConfig {
                base_config: CandidateConfig {
                    network,
                    address,
                    port,
                    component,
                    priority,
                    foundation,
                    ..CandidateConfig::default()
                },
                rel_addr,
                rel_port,
            };
            config.new_candidate_relay()
        }
        _ => Err(Error::Other(format!(
            "{:?} ({})",
            Error::ErrUnknownCandidateType,
            typ
        ))),
    }
}
