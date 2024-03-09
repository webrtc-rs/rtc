#[cfg(test)]
mod candidate_pair_test;
#[cfg(test)]
mod candidate_test;

//TODO: #[cfg(test)]
//TODO: mod candidate_relay_test;
/*#[cfg(test)]
mod candidate_server_reflexive_test;
*/

pub mod candidate_base;
pub mod candidate_host;
pub mod candidate_pair;
pub mod candidate_peer_reflexive;
pub mod candidate_relay;
pub mod candidate_server_reflexive;

use crate::network_type::NetworkType;
use crate::tcp_type::TcpType;
use serde::Serialize;
use shared::error::*;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

pub(crate) const RECEIVE_MTU: usize = 8192;
pub(crate) const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;

/// Indicates that the candidate is used for RTP.
pub(crate) const COMPONENT_RTP: u16 = 1;
/// Indicates that the candidate is used for RTCP.
pub(crate) const COMPONENT_RTCP: u16 = 0;

/// Candidate represents an ICE candidate
pub trait Candidate: fmt::Display {
    /// An arbitrary string used in the freezing algorithm to
    /// group similar candidates.  It is the same for two candidates that
    /// have the same type, base IP address, protocol (UDP, TCP, etc.),
    /// and STUN or TURN server.
    fn foundation(&self) -> String;

    /// A unique identifier for just this candidate
    /// Unlike the foundation this is different for each candidate.
    fn id(&self) -> String;

    /// A component is a piece of a data stream.
    /// An example is one for RTP, and one for RTCP
    fn component(&self) -> u16;
    fn set_component(&mut self, c: u16);

    /// The last time this candidate received traffic
    fn last_received(&self) -> Instant;

    /// The last time this candidate sent traffic
    fn last_sent(&self) -> Instant;

    fn network_type(&self) -> NetworkType;
    fn address(&self) -> String;
    fn port(&self) -> u16;

    fn priority(&self) -> u32;

    /// A transport address related to candidate,
    /// which is useful for diagnostics and other purposes.
    fn related_address(&self) -> Option<CandidateRelatedAddress>;

    fn candidate_type(&self) -> CandidateType;
    fn tcp_type(&self) -> TcpType;

    fn marshal(&self) -> String;

    fn addr(&self) -> SocketAddr;

    fn close(&self) -> Result<()>;
    fn seen(&mut self, outbound: bool);

    fn write_to(&mut self, raw: &[u8], dst: &dyn Candidate) -> Result<usize>;
    fn equal(&self, other: &dyn Candidate) -> bool;
    fn set_ip(&mut self, ip: &IpAddr) -> Result<()>;
}

/// Represents the type of candidate `CandidateType` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CandidateType {
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

impl Default for CandidateType {
    fn default() -> Self {
        Self::Unspecified
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
