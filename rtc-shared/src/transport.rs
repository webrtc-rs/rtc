use bytes::BytesMut;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;

/// Explicit congestion notification codepoint
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EcnCodepoint {
    #[doc(hidden)]
    Ect0 = 0b10,
    #[doc(hidden)]
    Ect1 = 0b01,
    #[doc(hidden)]
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create new object from the given bits
    pub fn from_bits(x: u8) -> Option<Self> {
        use self::EcnCodepoint::*;
        Some(match x & 0b11 {
            0b10 => Ect0,
            0b01 => Ect1,
            0b11 => Ce,
            _ => {
                return None;
            }
        })
    }
}

/// Type of transport protocol, either UDP or TCP
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TransportProtocol {
    /// UDP
    #[default]
    UDP,
    /// TCP
    TCP,
}

/// Transport Context with local address, peer address, ECN, protocol, etc.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransportContext {
    /// Local socket address, either IPv4 or IPv6
    pub local_addr: SocketAddr,
    /// Peer socket address, either IPv4 or IPv6
    pub peer_addr: SocketAddr,
    /// Type of transport protocol, either UDP or TCP
    pub transport_protocol: TransportProtocol,
    /// Explicit congestion notification bits to set on the packet
    pub ecn: Option<EcnCodepoint>,
}

impl Default for TransportContext {
    fn default() -> Self {
        Self {
            local_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            peer_addr: SocketAddr::from_str("0.0.0.0:0").unwrap(),
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        }
    }
}

/// A generic transmit with [TransportContext]
pub struct TransportMessage<T> {
    /// Received/Sent time
    pub now: Instant,
    /// A transport context with [local_addr](TransportContext::local_addr) and [peer_addr](TransportContext::peer_addr)
    pub transport: TransportContext,
    /// Message body with generic type
    pub message: T,
}

/// BytesMut type transmit with [TransportContext]
pub type TaggedBytesMut = TransportMessage<BytesMut>;

/// String type transmit with [TransportContext]
pub type TaggedString = TransportMessage<String>;

/// Four Tuple consists of local address and peer address
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FourTuple {
    /// Local socket address, either IPv4 or IPv6
    pub local_addr: SocketAddr,
    /// Peer socket address, either IPv4 or IPv6
    pub peer_addr: SocketAddr,
}

impl From<&TransportContext> for FourTuple {
    fn from(value: &TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
        }
    }
}

impl From<TransportContext> for FourTuple {
    fn from(value: TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
        }
    }
}

/// Five Tuple consists of local address, peer address and protocol
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct FiveTuple {
    /// Local socket address, either IPv4 or IPv6
    pub local_addr: SocketAddr,
    /// Peer socket address, either IPv4 or IPv6
    pub peer_addr: SocketAddr,
    /// Type of protocol, either UDP or TCP
    pub transport_protocol: TransportProtocol,
}

impl From<&TransportContext> for FiveTuple {
    fn from(value: &TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
            transport_protocol: value.transport_protocol,
        }
    }
}

impl From<TransportContext> for FiveTuple {
    fn from(value: TransportContext) -> Self {
        Self {
            local_addr: value.local_addr,
            peer_addr: value.peer_addr,
            transport_protocol: value.transport_protocol,
        }
    }
}
