//! Choosing where a relayed transport address lives.
//!
//! The server owns no sockets, so it cannot bind a relay itself. A generator decides which local
//! address a new relay should bind and which IP address to advertise to the client for it (the two
//! differ behind a NAT or a load balancer); the application binds the socket and reports back.

use rand::RngExt;
use shared::error::{Error, Result};
use std::net::{IpAddr, SocketAddr};

/// The address family a relay is to be allocated in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayFamily {
    /// An IPv4 relayed address.
    V4,
    /// An IPv6 relayed address ([RFC 6156]).
    ///
    /// [RFC 6156]: https://www.rfc-editor.org/rfc/rfc6156
    V6,
}

impl RelayFamily {
    /// Whether `ip` belongs to this family.
    pub fn matches(self, ip: IpAddr) -> bool {
        matches!(
            (self, ip),
            (RelayFamily::V4, IpAddr::V4(_)) | (RelayFamily::V6, IpAddr::V6(_))
        )
    }
}

/// Where to bind a new relay, and what address clients are told about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPlan {
    /// The local address to bind a UDP socket to. Port 0 means "any": the address the socket ends
    /// up with is what the application reports back.
    pub bind: SocketAddr,
    /// The IP address put in `XOR-RELAYED-ADDRESS`; the port is the one the socket was bound to.
    pub advertised_ip: IpAddr,
}

/// Decides where relays live. Implement this to place relays on particular interfaces or ports.
pub trait RelayAddressGenerator: Send {
    /// Checks the configuration, once, when the server is created.
    fn validate(&self) -> Result<()>;

    /// Plans a relay in `family`. `port` is the port the client's request dictates (a reservation
    /// token's successor port), or 0 when any will do.
    fn plan(&mut self, family: RelayFamily, port: u16) -> Result<RelayPlan>;

    /// Plans a relay on an even port, for `EVEN-PORT` requests (RTP on the even port, RTCP on the
    /// next one up). Generators that cannot choose ports return an error, which the server turns
    /// into `508 Insufficient Capacity`.
    fn plan_even(&mut self, _family: RelayFamily) -> Result<RelayPlan> {
        Err(Error::Other(
            "this relay address generator cannot choose an even port".to_owned(),
        ))
    }
}

/// A random even port in the dynamic range (49152–65534), for generators that leave the choice of
/// port to the operating system: it cannot be asked for an even one, so one is proposed and the
/// server plans again if the application finds it taken.
fn random_even_dynamic_port() -> u16 {
    rand::rng().random_range(49152u16..=65534) & !1
}

/// Binds every relay to `address` on a port the operating system picks, and advertises
/// `relay_address`.
pub struct RelayAddressGeneratorStatic {
    /// The IP address told to clients. Typically the machine's public address.
    pub relay_address: IpAddr,
    /// The local IP address relays bind to (`0.0.0.0` for all interfaces).
    pub address: IpAddr,
}

impl RelayAddressGenerator for RelayAddressGeneratorStatic {
    fn validate(&self) -> Result<()> {
        if self.relay_address.is_unspecified() {
            return Err(Error::Other(
                "relay_address must be a specific address".to_owned(),
            ));
        }
        Ok(())
    }

    fn plan(&mut self, family: RelayFamily, port: u16) -> Result<RelayPlan> {
        if !family.matches(self.relay_address) {
            return Err(Error::Other(format!(
                "no relay address for family {family:?}"
            )));
        }
        Ok(RelayPlan {
            bind: SocketAddr::new(self.address, port),
            advertised_ip: self.relay_address,
        })
    }

    fn plan_even(&mut self, family: RelayFamily) -> Result<RelayPlan> {
        self.plan(family, random_even_dynamic_port())
    }
}

/// Binds relays to ports in `min_port..=max_port`, so a firewall can be opened for exactly that
/// range.
pub struct RelayAddressGeneratorPortRange {
    /// The IP address told to clients.
    pub relay_address: IpAddr,
    /// The local IP address relays bind to.
    pub address: IpAddr,
    /// The lowest port to use.
    pub min_port: u16,
    /// The highest port to use.
    pub max_port: u16,
}

impl RelayAddressGeneratorPortRange {
    fn pick(&self, even: bool) -> u16 {
        let (lo, hi) = (self.min_port as u32, self.max_port as u32);
        let mut rng = rand::rng();
        loop {
            let port = rng.random_range(lo..=hi) as u16;
            if !even || port.is_multiple_of(2) {
                return port;
            }
            // A range holding no even port at all is rejected by `validate`, so this ends.
        }
    }
}

impl RelayAddressGenerator for RelayAddressGeneratorPortRange {
    fn validate(&self) -> Result<()> {
        if self.min_port == 0 || self.max_port < self.min_port {
            return Err(Error::Other("invalid relay port range".to_owned()));
        }
        if self.relay_address.is_unspecified() {
            return Err(Error::Other(
                "relay_address must be a specific address".to_owned(),
            ));
        }
        Ok(())
    }

    fn plan(&mut self, family: RelayFamily, port: u16) -> Result<RelayPlan> {
        if !family.matches(self.relay_address) {
            return Err(Error::Other(format!(
                "no relay address for family {family:?}"
            )));
        }
        let port = if port != 0 { port } else { self.pick(false) };
        Ok(RelayPlan {
            bind: SocketAddr::new(self.address, port),
            advertised_ip: self.relay_address,
        })
    }

    fn plan_even(&mut self, family: RelayFamily) -> Result<RelayPlan> {
        // Needs an even port whose successor is still in range.
        let lo = self.min_port.div_ceil(2) * 2;
        if lo >= self.max_port {
            return Err(Error::Other("no even port pair in the range".to_owned()));
        }
        let mut plan = self.plan(family, 0)?;
        let mut port = self.pick(true);
        while port >= self.max_port || port < lo {
            port = self.pick(true);
        }
        plan.bind.set_port(port);
        Ok(plan)
    }
}

/// Advertises the very address it binds: for servers that run directly on their public address.
pub struct RelayAddressGeneratorNone {
    /// The local IP address relays bind to, and the one advertised.
    pub address: IpAddr,
}

impl RelayAddressGenerator for RelayAddressGeneratorNone {
    fn validate(&self) -> Result<()> {
        if self.address.is_unspecified() {
            return Err(Error::Other(
                "address must be a specific address".to_owned(),
            ));
        }
        Ok(())
    }

    fn plan(&mut self, family: RelayFamily, port: u16) -> Result<RelayPlan> {
        if !family.matches(self.address) {
            return Err(Error::Other(format!("no address for family {family:?}")));
        }
        Ok(RelayPlan {
            bind: SocketAddr::new(self.address, port),
            advertised_ip: self.address,
        })
    }

    fn plan_even(&mut self, family: RelayFamily) -> Result<RelayPlan> {
        self.plan(family, random_even_dynamic_port())
    }
}
