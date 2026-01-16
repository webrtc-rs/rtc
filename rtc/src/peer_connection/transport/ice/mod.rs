use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use ice::candidate::Candidate;
use ice::tcp_type::TcpType;
use ice::{Agent, AgentConfig};
use shared::error::{Error, Result};
use std::sync::Arc;

pub(crate) mod candidate;
pub(crate) mod candidate_pair;
pub(crate) mod candidate_type;
pub(crate) mod parameters;
pub(crate) mod protocol;
pub(crate) mod role;
pub(crate) mod server;
pub(crate) mod state;

/// ICETransport allows an application access to information about the ICE
/// transport over which packets are sent and received.
#[derive(Default)]
pub(crate) struct RTCIceTransport {
    pub(crate) agent: Agent,

    pub(crate) ice_gathering_state: RTCIceGatheringState,
    pub(crate) ice_connection_state: RTCIceConnectionState,
}

impl RTCIceTransport {
    /// creates a new RTCIceTransport
    pub(crate) fn new(agent_config: AgentConfig) -> Result<Self> {
        let agent = Agent::new(Arc::new(agent_config))?;

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

        let _ = self.agent.add_remote_candidate(c)?;
        Ok(())
    }

    pub(crate) fn add_local_candidate(&mut self, c: Candidate) -> Result<()> {
        let _ = self.agent.add_local_candidate(c)?;
        Ok(())
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
