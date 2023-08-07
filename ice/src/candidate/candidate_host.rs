use super::candidate_base::*;
use super::*;
use crate::rand::generate_cand_id;

/// The config required to create a new `CandidateHost`.
#[derive(Default)]
pub struct CandidateHostConfig {
    pub base_config: CandidateBaseConfig,
}

impl CandidateHostConfig {
    /// Creates a new host candidate.
    pub fn new_candidate_host(self) -> Result<CandidateBase> {
        let mut candidate_id = self.base_config.candidate_id;
        if candidate_id.is_empty() {
            candidate_id = generate_cand_id();
        }

        let c = CandidateBase {
            id: candidate_id,
            address: self.base_config.address.clone(),
            candidate_type: CandidateType::Host,
            component: self.base_config.component,
            port: self.base_config.port,
            foundation_override: self.base_config.foundation,
            priority_override: self.base_config.priority,
            network: self.base_config.network,
            //conn: self.base_config.conn,
            ..CandidateBase::default()
        };

        if !self.base_config.address.ends_with(".local") {
            //TODO: let ip = self.base_config.address.parse()?;
            //TODO: c.set_ip(&ip)?;
        };

        Ok(c)
    }
}
