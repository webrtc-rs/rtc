use super::*;
use crate::network_type::determine_network_type;
use crate::rand::generate_cand_id;
use shared::error::*;

/// The config required to create a new `CandidateRelay`.
#[derive(Default)]
pub struct CandidateRelayConfig {
    /// The fields shared by every candidate type.
    pub base_config: CandidateConfig,

    /// The base address this candidate was derived from, reported as `raddr`.
    pub rel_addr: String,
    /// The base port, reported as `rport`.
    pub rel_port: u16,

    /// The server this candidate was gathered from.
    pub url: Option<String>,

    /// The transport between this agent and the relay server: `udp` (the default when empty),
    /// `tcp`, `tls` or `dtls`. It sets the candidate's local preference, so a relay reached
    /// over UDP outranks one reached over TCP, and a plain one outranks a TLS one.
    pub relay_protocol: String,
}

/// The local preference of a relay candidate reached over `relay_protocol` (pion's
/// `relayProtocolPreference`).
pub(crate) fn relay_protocol_preference(relay_protocol: &str) -> u16 {
    match relay_protocol {
        "tls" => 0,
        "tcp" => 1,
        "dtls" => 2,
        _ => 3,
    }
}

/// The relay protocol a TURN server URL implies: `turn:` over UDP or TCP, `turns:` over TCP
/// (TLS) or UDP (DTLS). Anything unparsable is taken as UDP.
pub fn relay_protocol_from_url(url: &str) -> &'static str {
    match crate::url::Url::parse_url(url) {
        Ok(url) => match (url.is_secure(), url.proto) {
            (false, crate::url::ProtoType::Tcp) => "tcp",
            (true, crate::url::ProtoType::Udp) => "dtls",
            (true, _) => "tls",
            _ => "udp",
        },
        Err(_) => "udp",
    }
}

impl CandidateRelayConfig {
    /// Creates a new relay candidate.
    pub fn new_candidate_relay(self) -> Result<Candidate> {
        let mut candidate_id = self.base_config.candidate_id;
        if candidate_id.is_empty() {
            candidate_id = generate_cand_id();
        }

        let ip: IpAddr = match self.base_config.address.parse() {
            Ok(ip) => ip,
            Err(_) => return Err(Error::ErrAddressParseFailed),
        };
        let network_type = determine_network_type(&self.base_config.network, &ip)?;

        Ok(Candidate {
            id: candidate_id,
            network_type,
            candidate_type: CandidateType::Relay,
            address: self.base_config.address,
            port: self.base_config.port,
            resolved_addr: SocketAddr::new(ip, self.base_config.port),
            component: self.base_config.component,
            foundation_override: self.base_config.foundation,
            priority_override: self.base_config.priority,
            related_address: Some(CandidateRelatedAddress {
                address: self.rel_addr,
                port: self.rel_port,
            }),
            url: self.url,
            relay_local_preference: relay_protocol_preference(&self.relay_protocol),
            ..Candidate::default()
        })
    }
}
