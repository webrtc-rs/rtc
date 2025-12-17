use crate::transport::ice::candidate::RTCIceCandidate;
use crate::transport::ice::parameters::RTCIceParameters;
use crate::transport::ice::role::RTCIceRole;
use crate::transport::ice::state::RTCIceTransportState;
use ice::candidate::{Candidate, CandidateType};
use ice::rand::{generate_pwd, generate_ufrag};
use ice::tcp_type::TcpType;
use shared::error::{Error, Result};

pub mod candidate;
pub mod candidate_pair;
pub mod candidate_type;
pub mod parameters;
pub mod protocol;
pub mod role;
pub mod server;
pub mod state;

#[derive(Default, Clone)]
pub(crate) struct UfragPwd {
    pub(crate) local_ufrag: String,
    pub(crate) local_pwd: String,
    pub(crate) remote_ufrag: String,
    pub(crate) remote_pwd: String,
}

/// ICETransport allows an application access to information about the ICE
/// transport over which packets are sent and received.
#[derive(Default, Clone)]
pub struct RTCIceTransport {
    //pub(crate) gatherer: Arc<RTCIceGatherer>,
    //on_connection_state_change_handler: Arc<ArcSwapOption<Mutex<OnConnectionStateChangeHdlrFn>>>,
    //on_selected_candidate_pair_change_handler:
    //    Arc<ArcSwapOption<Mutex<OnSelectedCandidatePairChangeHdlrFn>>>,
    state: RTCIceTransportState,
    role: RTCIceRole,

    ufrag_pwd: UfragPwd,
    local_candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
}

impl RTCIceTransport {
    /// creates a new RTCIceTransport
    pub(crate) fn new(mut ufrag: String, mut pwd: String) -> Result<Self> {
        if ufrag.is_empty() {
            ufrag = generate_ufrag();
        }
        if pwd.is_empty() {
            pwd = generate_pwd();
        }

        if ufrag.len() * 8 < 24 {
            return Err(Error::ErrLocalUfragInsufficientBits);
        }
        if pwd.len() * 8 < 128 {
            return Err(Error::ErrLocalPwdInsufficientBits);
        }

        Ok(RTCIceTransport {
            state: RTCIceTransportState::New,
            role: RTCIceRole::Unspecified,
            ufrag_pwd: UfragPwd {
                local_ufrag: ufrag,
                local_pwd: pwd,
                remote_ufrag: String::new(),
                remote_pwd: String::new(),
            },
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
            &self.local_candidates,
        ))
    }

    /// Returns the local user credentials.
    pub(crate) fn get_local_user_credentials(&self) -> (&str, &str) {
        (
            self.ufrag_pwd.local_ufrag.as_str(),
            self.ufrag_pwd.local_pwd.as_str(),
        )
    }

    /// Returns the remote user credentials.
    pub(crate) fn get_remote_user_credentials(&self) -> (&str, &str) {
        (
            self.ufrag_pwd.remote_ufrag.as_str(),
            self.ufrag_pwd.remote_pwd.as_str(),
        )
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

        self.ufrag_pwd.remote_ufrag = remote_ufrag;
        self.ufrag_pwd.remote_pwd = remote_pwd;

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

        self.remote_candidates.push(c);

        Ok(())
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

        self.local_candidates.push(c);

        Ok(())
    }

    /// Role indicates the current role of the ICE transport.
    pub(crate) fn role(&self) -> RTCIceRole {
        self.role
    }

    /// set current role of the ICE transport.
    pub(crate) fn set_role(&mut self, role: RTCIceRole) {
        self.role = role;
    }

    /// restart is not exposed currently because ORTC has users create a whole new ICETransport
    /// so for now lets keep it private so we don't cause ORTC users to depend on non-standard APIs
    pub(crate) fn restart(&self) -> Result<()> {
        //TODO:
        Ok(())
    }
}
