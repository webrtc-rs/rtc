use super::*;
use crate::rand::generate_cand_id;

/// The config required to create a new `CandidateHost`.
#[derive(Default)]
pub struct CandidateHostConfig {
    pub base_config: CandidateConfig,

    pub tcp_type: TcpType,
}

impl CandidateHostConfig {
    /// Creates a new host candidate.
    pub fn new_candidate_host(self) -> Result<Candidate> {
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
            candidate_type: CandidateType::Host,
            address: self.base_config.address,
            port: self.base_config.port,
            resolved_addr: SocketAddr::new(ip, self.base_config.port),
            component: self.base_config.component,
            foundation_override: self.base_config.foundation,
            priority_override: self.base_config.priority,
            network: self.base_config.network,
            tcp_type: self.tcp_type,
            ..Candidate::default()
        })
    }
}
