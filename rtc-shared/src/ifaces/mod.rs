/// Platform-specific interface enumeration (FFI into the OS).
pub mod ffi;
pub use ffi::ifaces;

#[derive(PartialEq, Eq, Debug, Clone)]
/// The next hop configured for an interface address.
pub enum NextHop {
    /// The broadcast address of the attached network.
    Broadcast(::std::net::SocketAddr),
    /// The destination address, for point-to-point links.
    Destination(::std::net::SocketAddr),
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// The address family or link type an [`Interface`] entry describes.
pub enum Kind {
    /// A raw packet-level (link layer) address.
    Packet,
    /// A link-layer address, such as a MAC address.
    Link,
    /// An IPv4 address.
    Ipv4,
    /// An IPv6 address.
    Ipv6,
    /// An address family this crate does not recognise, carrying the raw OS value.
    Unknow(i32),
}

#[derive(Debug, Clone)]
/// One address on one local network interface.
///
/// ICE gathering walks these to produce host candidates.
pub struct Interface {
    /// The OS name of the interface, such as `en0` or `eth0`.
    pub name: String,
    /// Which address family or link type this entry describes.
    pub kind: Kind,
    /// The address itself, if the OS reported one.
    pub addr: Option<::std::net::SocketAddr>,
    /// The netmask for [`Self::addr`], if the OS reported one.
    pub mask: Option<::std::net::SocketAddr>,
    /// The broadcast or point-to-point destination address, if any.
    pub hop: Option<NextHop>,
}
