//! Socket utilities for mDNS.
//!
//! This module provides [`MulticastSocket`], a builder for creating properly
//! configured UDP sockets for mDNS communication.
//!
//! # Example
//!
//! ```rust,ignore
//! use rtc_mdns::MulticastSocket;
//! use std::net::SocketAddr;
//!
//! let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
//! let std_socket = MulticastSocket::new(bind_addr).into_std()?;
//!
//! // For tokio:
//! let socket = tokio::net::UdpSocket::from_std(std_socket)?;
//! ```

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

use crate::MDNS_PORT;
use crate::proto::MDNS_MULTICAST_IPV4;
use socket2::{Domain, Protocol, Socket, Type};

/// A builder for creating multicast UDP sockets suitable for mDNS.
///
/// `MulticastSocket` provides a convenient way to create properly configured
/// UDP sockets for mDNS communication. The resulting socket will be:
///
/// - Bound to the specified address (typically `0.0.0.0:5353`)
/// - Configured with `SO_REUSEADDR` enabled
/// - Configured with `SO_REUSEPORT` enabled (on supported platforms)
/// - Set to non-blocking mode for async compatibility
/// - Joined to the mDNS multicast group (224.0.0.251)
///
/// # Examples
///
/// Basic usage with tokio:
///
/// ```rust,ignore
/// use rtc_mdns::MulticastSocket;
/// use std::net::SocketAddr;
///
/// let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
/// let std_socket = MulticastSocket::new(bind_addr).into_std()?;
/// let socket = tokio::net::UdpSocket::from_std(std_socket)?;
/// ```
///
/// With a specific network interface:
///
/// ```rust,ignore
/// use rtc_mdns::MulticastSocket;
/// use std::net::{Ipv4Addr, SocketAddr};
///
/// let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
/// let interface = Ipv4Addr::new(192, 168, 1, 100);
/// let std_socket = MulticastSocket::new(bind_addr)
///     .with_interface(interface)
///     .into_std()?;
/// ```
#[derive(Debug, Clone)]
pub struct MulticastSocket {
    multicast_local_ipv4: Option<Ipv4Addr>,
    multicast_local_port: Option<u16>,
    interface: Option<Ipv4Addr>,
}

impl Default for MulticastSocket {
    fn default() -> Self {
        Self::new()
    }
}

impl MulticastSocket {
    /// Creates a new `MulticastSocket` builder with the specified bind address.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - The local address to bind to. Use `0.0.0.0:5353` to listen
    ///   on all interfaces on the standard mDNS port.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MulticastSocket;
    ///
    /// let builder = MulticastSocket::new();
    /// ```
    pub fn new() -> Self {
        Self {
            multicast_local_ipv4: None,
            multicast_local_port: None,
            interface: None,
        }
    }

    pub fn with_multicast_local_ipv4(mut self, multicast_local_ipv4: Ipv4Addr) -> Self {
        self.multicast_local_ipv4 = Some(multicast_local_ipv4);
        self
    }

    pub fn with_multicast_local_port(mut self, multicast_local_port: u16) -> Self {
        self.multicast_local_port = Some(multicast_local_port);
        self
    }

    /// Sets a specific network interface for multicast operations.
    ///
    /// If not set, the socket joins the multicast group on all interfaces
    /// (`INADDR_ANY`).
    ///
    /// # Arguments
    ///
    /// * `interface` - The IPv4 address of the network interface to use.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::MulticastSocket;
    /// use std::net::Ipv4Addr;
    ///
    /// let builder = MulticastSocket::new()
    ///     .with_interface(Ipv4Addr::new(192, 168, 1, 100));
    /// ```
    pub fn with_interface(mut self, interface: Ipv4Addr) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Converts this builder into a configured `std::net::UdpSocket`.
    ///
    /// This method creates the socket with the following configuration:
    /// - `SO_REUSEADDR` enabled (allows multiple processes to bind)
    /// - `SO_REUSEPORT` enabled on Unix platforms (except Solaris/illumos)
    /// - Non-blocking mode enabled (for async compatibility)
    /// - Joined to the mDNS multicast group (224.0.0.251)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket creation fails
    /// - Setting socket options fails
    /// - Binding to the address fails
    /// - Joining the multicast group fails
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use rtc_mdns::MulticastSocket;
    /// use std::net::SocketAddr;
    ///
    /// let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    /// let std_socket = MulticastSocket::new(bind_addr).into_std()?;
    ///
    /// // Use with tokio:
    /// let socket = tokio::net::UdpSocket::from_std(std_socket)?;
    /// ```
    ///
    /// # Platform Notes
    ///
    /// - On Unix-like systems (except Solaris/illumos), `SO_REUSEPORT` is enabled
    ///   to allow multiple processes to bind to the same port.
    pub fn into_std(self) -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

        // Enable address reuse for multiple processes
        socket.set_reuse_address(true)?;

        // Enable port reuse on supported platforms
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket.set_reuse_port(true)?;

        // Set non-blocking mode for async compatibility
        socket.set_nonblocking(true)?;

        let multicast_local_ip = if let Some(multicast_local_ipv4) = self.multicast_local_ipv4 {
            IpAddr::V4(multicast_local_ipv4)
        } else if cfg!(target_os = "linux") {
            IpAddr::V4(MDNS_MULTICAST_IPV4)
        } else {
            // DNS_MULTICAST_IPV4 doesn't work on Mac/Win,
            // only 0.0.0.0 works fine, even 127.0.0.1 doesn't work
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        };

        let multicast_local_port = if let Some(multicast_local_port) = self.multicast_local_port {
            multicast_local_port
        } else {
            MDNS_PORT
        };

        let multicast_local_addr = SocketAddr::new(multicast_local_ip, multicast_local_port);

        // Bind to the specified address
        socket.bind(&multicast_local_addr.into())?;

        // Join the mDNS multicast group
        let iface = self.interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
        socket.join_multicast_v4(&MDNS_MULTICAST_IPV4, &iface)?;

        Ok(socket.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::MDNS_PORT;
    use std::str::FromStr;

    #[test]
    fn test_multicast_constants() {
        assert_eq!(MDNS_MULTICAST_IPV4, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(MDNS_PORT, 5353);
    }

    #[test]
    fn test_multicast_socket_builder() {
        let builder = MulticastSocket::new()
            .with_multicast_local_ipv4(Ipv4Addr::from_str("0.0.0.0").unwrap())
            .with_multicast_local_port(5353);
        assert!(builder.multicast_local_ipv4.is_some());
        assert!(builder.multicast_local_port.is_some());
        assert!(builder.interface.is_none());
    }

    #[test]
    fn test_multicast_socket_with_interface() {
        let interface = Ipv4Addr::new(192, 168, 1, 100);
        let builder = MulticastSocket::new()
            .with_multicast_local_ipv4(Ipv4Addr::from_str("0.0.0.0").unwrap())
            .with_multicast_local_port(5353)
            .with_interface(interface);
        assert_eq!(builder.interface, Some(interface));
    }

    // Note: Socket creation tests would require actual network access
    // and might conflict with other mDNS services, so we keep them minimal
}
