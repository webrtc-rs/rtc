use crate::transport::ice::candidate::RTCIceCandidate;
use crate::transport::ice::parameters::RTCIceParameters;
use crate::transport::ice::role::RTCIceRole;
use crate::transport::ice::state::RTCIceTransportState;
use ice::candidate::Candidate;
use shared::error::Result;

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
    pub(crate) fn new(/*gatherer: Arc<RTCIceGatherer>*/) -> Self {
        RTCIceTransport {
            state: RTCIceTransportState::New,
            //gatherer,
            ..Default::default()
        }
    }

    /// get_local_parameters returns the ICE parameters of the ICEGatherer.
    pub(crate) fn get_local_parameters(&self) -> Result<RTCIceParameters> {
        let (frag, pwd) = self.get_local_user_credentials();

        Ok(RTCIceParameters {
            username_fragment: frag,
            password: pwd,
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
    pub fn get_local_user_credentials(&self) -> (String, String) {
        (
            self.ufrag_pwd.local_ufrag.clone(),
            self.ufrag_pwd.local_pwd.clone(),
        )
    }

    /// Returns the remote user credentials.
    pub fn get_remote_user_credentials(&self) -> (String, String) {
        (
            self.ufrag_pwd.remote_ufrag.clone(),
            self.ufrag_pwd.remote_pwd.clone(),
        )
    }

    /// Conversion for ice_candidates
    fn rtc_ice_candidates_from_ice_candidates(
        ice_candidates: &[Candidate],
    ) -> Vec<RTCIceCandidate> {
        ice_candidates.iter().map(|c| c.into()).collect()
    }
}
