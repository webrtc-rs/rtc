//! Fields shared by session and media descriptions.
//!
//! `c=` connection data ([`ConnectionInformation`](crate::description::common::ConnectionInformation), [`Address`](crate::description::common::Address)), `b=` bandwidth
//! ([`Bandwidth`](crate::description::common::Bandwidth)) and `a=` attributes ([`Attribute`](crate::description::common::Attribute)) may appear at either level in SDP, with
//! the media-level value overriding the session-level one — so they are modelled once here.
//!
//! An [`Attribute`](crate::description::common::Attribute) with no value is a flag, which is how `a=rtcp-mux` and the direction
//! attributes are expressed.
use std::fmt;

use super::session::ATTR_KEY_CANDIDATE;

/// Information describes the "i=" field which provides textual information
/// about the session.
pub type Information = String;

/// ConnectionInformation defines the representation for the "c=" field
/// containing connection data.
#[derive(Debug, Default, Clone)]
pub struct ConnectionInformation {
    /// The network type, always `IN` (Internet) in practice.
    pub network_type: String,
    /// The address type, `IP4` or `IP6`.
    pub address_type: String,
    /// The connection address, absent for a bare `c=` line.
    pub address: Option<Address>,
}

impl fmt::Display for ConnectionInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(address) = &self.address {
            write!(f, "{} {} {}", self.network_type, self.address_type, address,)
        } else {
            write!(f, "{} {}", self.network_type, self.address_type,)
        }
    }
}

/// Address describes a structured address token from within the "c=" field.
#[derive(Debug, Default, Clone)]
pub struct Address {
    /// The address itself: a host name, IPv4/IPv6 literal, or multicast group.
    pub address: String,
    /// The multicast TTL, for multicast addresses.
    pub ttl: Option<isize>,
    /// The number of consecutive multicast addresses in the range.
    pub range: Option<isize>,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)?;
        if let Some(t) = &self.ttl {
            write!(f, "/{t}")?;
        }
        if let Some(r) = &self.range {
            write!(f, "/{r}")?;
        }
        Ok(())
    }
}

/// Bandwidth describes an optional field which denotes the proposed bandwidth
/// to be used by the session or media.
#[derive(Debug, Default, Clone)]
pub struct Bandwidth {
    /// Whether the bandwidth type is experimental, written with an `X-` prefix.
    pub experimental: bool,
    /// The bandwidth modifier, such as `AS` (application-specific) or `CT` (conference total).
    pub bandwidth_type: String,
    /// The proposed bandwidth in kilobits per second.
    pub bandwidth: u64,
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let output = if self.experimental { "X-" } else { "" };
        write!(f, "{}{}:{}", output, self.bandwidth_type, self.bandwidth)
    }
}

/// EncryptionKey describes the "k=" which conveys encryption key information.
pub type EncryptionKey = String;

/// Attribute describes the "a=" field which represents the primary means for
/// extending SDP.
#[derive(Debug, Default, Clone)]
pub struct Attribute {
    /// The attribute name, the part before the `:`.
    pub key: String,
    /// The attribute value, or `None` for a flag attribute such as `a=rtcp-mux`.
    pub value: Option<String>,
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value) = &self.value {
            write!(f, "{}:{}", self.key, value)
        } else {
            write!(f, "{}", self.key)
        }
    }
}

impl Attribute {
    /// new constructs a new attribute
    pub fn new(key: String, value: Option<String>) -> Self {
        Attribute { key, value }
    }

    /// is_ice_candidate returns true if the attribute key equals "candidate".
    pub fn is_ice_candidate(&self) -> bool {
        self.key.as_str() == ATTR_KEY_CANDIDATE
    }
}
