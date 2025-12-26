use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use ice::candidate::{Candidate, CandidateType};
use ice::tcp_type::TcpType;
use ice::{Agent, AgentConfig};
use shared::error::{Error, Result};
use std::sync::Arc;

pub mod candidate;
pub mod candidate_pair;
pub mod candidate_type;
pub mod parameters;
pub mod protocol;
pub mod role;
pub mod server;
pub mod state;

/// ICETransport allows an application access to information about the ICE
/// transport over which packets are sent and received.
#[derive(Default)]
pub struct RTCIceTransport {
    pub(crate) agent: Agent,

    pub(crate) ice_gathering_state: RTCIceGatheringState,
    pub(crate) ice_connection_state: RTCIceConnectionState,
}

impl RTCIceTransport {
    /// creates a new RTCIceTransport
    pub(crate) fn new(local_ufrag: String, local_pwd: String) -> Result<Self> {
        let agent = Agent::new(Arc::new(AgentConfig {
            urls: vec![],
            local_ufrag,
            local_pwd,
            disconnected_timeout: None,
            failed_timeout: None,
            keepalive_interval: None,
            candidate_types: vec![],
            check_interval: Default::default(),
            max_binding_requests: None,
            is_controlling: false,
            lite: false,
            host_acceptance_min_wait: None,
            srflx_acceptance_min_wait: None,
            prflx_acceptance_min_wait: None,
            relay_acceptance_min_wait: None,
            insecure_skip_verify: false,
        }))?;

        Ok(RTCIceTransport {
            agent,
            ..Default::default()
        })
    }

    /// get_local_parameters returns the ICE parameters of the ICEGatherer.
    pub(crate) fn get_local_parameters(&self) -> Result<RTCIceParameters> {
        let (frag, pwd) = self.get_local_user_credentials();

        Ok(RTCIceParameters {
            username_fragment: frag.to_string(),
            password: pwd.to_string(),
            ice_lite: false,
        })
    }

    /// get_local_candidates returns the sequence of valid local candidates associated with the ICEGatherer.
    pub(crate) fn get_local_candidates(&self) -> Result<Vec<RTCIceCandidate>> {
        Ok(RTCIceTransport::rtc_ice_candidates_from_ice_candidates(
            self.agent.get_local_candidates(),
        ))
    }

    /// Returns the local user credentials.
    pub(crate) fn get_local_user_credentials(&self) -> (&str, &str) {
        (
            self.agent.get_local_credentials().ufrag.as_str(),
            self.agent.get_local_credentials().pwd.as_str(),
        )
    }

    /// Returns the remote user credentials.
    pub(crate) fn get_remote_user_credentials(&self) -> (&str, &str) {
        if let Some(remote_credentials) = self.agent.get_remote_credentials() {
            (
                remote_credentials.ufrag.as_str(),
                remote_credentials.pwd.as_str(),
            )
        } else {
            ("", "")
        }
    }

    /// Conversion for ice_candidates
    fn rtc_ice_candidates_from_ice_candidates(
        ice_candidates: &[Candidate],
    ) -> Vec<RTCIceCandidate> {
        ice_candidates.iter().map(|c| c.into()).collect()
    }

    pub(crate) fn have_remote_credentials_change(&self, new_ufrag: &str, new_pwd: &str) -> bool {
        let (ufrag, upwd) = self.get_remote_user_credentials();
        ufrag != new_ufrag || upwd != new_pwd
    }

    pub(crate) fn set_remote_credentials(
        &mut self,
        remote_ufrag: String,
        remote_pwd: String,
    ) -> Result<()> {
        if remote_ufrag.is_empty() {
            return Err(Error::ErrRemoteUfragEmpty);
        } else if remote_pwd.is_empty() {
            return Err(Error::ErrRemotePwdEmpty);
        }

        self.agent
            .set_remote_credentials(remote_ufrag, remote_pwd)?;

        Ok(())
    }

    /// Adds a new remote candidate.
    pub(crate) fn add_remote_candidate(&mut self, c: Candidate) -> Result<()> {
        // cannot check for network yet because it might not be applied
        // when mDNS hostame is used.
        if c.tcp_type() == TcpType::Active {
            // TCP Candidates with tcptype active will probe server passive ones, so
            // no need to do anything with them.
            log::info!("Ignoring remote candidate with tcpType active: {c}");
            return Ok(());
        }

        // If we have a mDNS Candidate lets fully resolve it before adding it locally
        if c.candidate_type() == CandidateType::Host && c.address().ends_with(".local") {
            //TODO: if self.mdns_mode == MulticastDnsMode::Disabled {
            log::warn!(
                "remote mDNS candidate is not supported due to that mDNS is disabled: ({})",
                c.address()
            );
            return Ok(());
        }

        self.agent.add_remote_candidate(c)
    }

    pub(crate) fn add_local_candidate(&mut self, c: Candidate) -> Result<()> {
        // If we have a mDNS Candidate lets fully resolve it before adding it locally
        if c.candidate_type() == CandidateType::Host && c.address().ends_with(".local") {
            //TODO: if self.mdns_mode == MulticastDnsMode::Disabled {
            log::warn!(
                "local mDNS candidate is not supported due to that mDNS is disabled: ({})",
                c.address()
            );
            return Ok(());
        }

        self.agent.add_local_candidate(c)
    }

    /// Role indicates the current role of the ICE transport.
    pub(crate) fn role(&self) -> RTCIceRole {
        if self.agent.role() {
            RTCIceRole::Controlling
        } else {
            RTCIceRole::Controlled
        }
    }

    /// set current role of the ICE transport.
    pub(crate) fn set_role(&mut self, role: RTCIceRole) {
        self.agent.set_role(role == RTCIceRole::Controlling);
    }

    pub(crate) fn state(&self) -> RTCIceTransportState {
        self.agent.state().into()
    }

    /// restart is not exposed currently because ORTC has users create a whole new ICETransport
    /// so for now lets keep it private so we don't cause ORTC users to depend on non-standard APIs
    pub(crate) fn restart(
        &mut self,
        ufrag: String,
        pwd: String,
        keep_local_candidates: bool,
    ) -> Result<()> {
        self.agent.restart(ufrag, pwd, keep_local_candidates)
    }

    pub(crate) fn start(
        &mut self,
        local_ice_role: RTCIceRole,
        remote_ice_parameters: RTCIceParameters,
    ) -> Result<()> {
        if self.state() != RTCIceTransportState::New {
            return Err(Error::ErrICETransportNotInNew);
        }

        self.agent.start_connectivity_checks(
            local_ice_role == RTCIceRole::Controlling,
            remote_ice_parameters.username_fragment,
            remote_ice_parameters.password,
        )?;

        Ok(())
    }
}
