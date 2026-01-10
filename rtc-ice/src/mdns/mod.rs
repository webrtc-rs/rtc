//#[cfg(test)]
//mod mdns_test;

use mdns::{MDNS_DEST_ADDR, Mdns};
use mdns::{MDNS_PORT, MdnsConfig};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use uuid::Uuid;

use shared::error::{Error, Result};

/// Represents the different Multicast modes that ICE can run.
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
pub enum MulticastDnsMode {
    /// Means remote mDNS candidates will be discarded, and local host candidates will use IPs.
    Disabled,

    /// Means remote mDNS candidates will be accepted, and local host candidates will use IPs.
    #[default]
    QueryOnly,

    /// Means remote mDNS candidates will be accepted, and local host candidates will use mDNS.
    QueryAndGather,
}

pub(crate) fn generate_multicast_dns_name() -> String {
    // https://tools.ietf.org/id/draft-ietf-rtcweb-mdns-ice-candidates-02.html#gathering
    // The unique name MUST consist of a version 4 UUID as defined in [RFC4122], followed by “.local”.
    let u = Uuid::new_v4();
    format!("{u}.local")
}

pub(crate) fn create_multicast_dns(
    mdns_mode: MulticastDnsMode,
    mdns_name: &str,
    mdns_query_timeout: &Option<Duration>,
    dest_addr: &str,
) -> Result<Option<Mdns>> {
    let local_names = match mdns_mode {
        MulticastDnsMode::QueryOnly => vec![],
        MulticastDnsMode::QueryAndGather => vec![mdns_name.to_owned()],
        MulticastDnsMode::Disabled => return Ok(None),
    };

    let local_addr = if dest_addr.is_empty() {
        //TODO: why DEFAULT_DEST_ADDR doesn't work on Mac/Win?
        if cfg!(target_os = "linux") {
            MDNS_DEST_ADDR
        } else {
            SocketAddr::from_str("0.0.0.0:5353")?
        }
    } else {
        let local_addr = SocketAddr::from_str(dest_addr)?;
        if local_addr.port() != MDNS_PORT {
            return Err(Error::ErrMDNSPortNotSupported);
        }
        local_addr
    };
    log::info!("mDNS is using {local_addr} as dest_addr");

    let mut config = MdnsConfig::new()
        .with_local_names(local_names)
        .with_local_addr(local_addr);
    if let Some(query_timeout) = mdns_query_timeout {
        config = config.with_query_timeout(*query_timeout);
    }

    let mdns_server = Mdns::new(config);

    Ok(Some(mdns_server))
}
