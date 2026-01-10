//#[cfg(test)]
//mod mdns_test;

use mdns::MdnsConfig;
use mdns::{MDNS_MULTICAST_IPV4, Mdns};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use uuid::Uuid;

use shared::error::Result;

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
    mdns_local_name: &str,
    mdns_local_ip: &Option<IpAddr>,
    mdns_query_timeout: &Option<Duration>,
) -> Result<Option<Mdns>> {
    let local_names = match mdns_mode {
        MulticastDnsMode::QueryOnly => vec![],
        MulticastDnsMode::QueryAndGather => vec![mdns_local_name.to_owned()],
        MulticastDnsMode::Disabled => return Ok(None),
    };

    let local_ip = if let Some(local_ip) = mdns_local_ip {
        *local_ip
    } else {
        if cfg!(target_os = "linux") {
            IpAddr::V4(MDNS_MULTICAST_IPV4)
        } else {
            // MDNS_MULTICAST_IPV4 doesn't work on Mac/Win,
            // only 0.0.0.0 works fine, even 127.0.0.1 doesn't work
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
        }
    };
    log::info!("mDNS is using {local_ip} as local ip");

    let mut config = MdnsConfig::new()
        .with_local_names(local_names)
        .with_local_ip(local_ip);
    if let Some(query_timeout) = mdns_query_timeout {
        config = config.with_query_timeout(*query_timeout);
    }

    let mdns_server = Mdns::new(config);

    Ok(Some(mdns_server))
}
