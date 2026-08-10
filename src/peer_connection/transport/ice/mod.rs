use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::transport::RTCTransportId;
use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;
use crate::peer_connection::transport::ice::candidate_pair::RTCIceCandidatePair;
use crate::peer_connection::transport::ice::component::RTCIceComponent;
use crate::peer_connection::transport::ice::parameters::RTCIceParameters;
use crate::peer_connection::transport::ice::role::RTCIceRole;
use crate::peer_connection::transport::ice::state::RTCIceTransportState;
use crypto::RTCCryptoProvider;
use ice::candidate::Candidate;
use ice::tcp_type::TcpType;
use ice::{Agent, AgentConfig};
use shared::error::{Error, Result};
use std::sync::Arc;
use std::time::Instant;

pub(crate) mod candidate;
pub(crate) mod candidate_pair;
pub(crate) mod candidate_type;
pub(crate) mod component;
pub(crate) mod parameters;
pub(crate) mod protocol;
pub(crate) mod role;
pub(crate) mod server;
pub(crate) mod state;

/// ICETransport allows an application access to information about the ICE
/// transport over which packets are sent and received.
pub(crate) struct IceTransport {
    pub(crate) agent: Agent,

    pub(crate) id: RTCTransportId,

    pub(crate) ice_gathering_state: RTCIceGatheringState,
    pub(crate) ice_connection_state: RTCIceConnectionState,
}

impl IceTransport {
    /// creates a new IceTransport
    pub(crate) fn new(
        now: Instant,
        agent_config: AgentConfig,
        crypto_provider: Arc<dyn RTCCryptoProvider>,
        id: RTCTransportId,
    ) -> Result<Self> {
        let agent = Agent::new(now, Arc::new(agent_config), crypto_provider)?;

        Ok(IceTransport {
            agent,
            id,
            ice_gathering_state: RTCIceGatheringState::New,
            ice_connection_state: RTCIceConnectionState::default(),
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
        Ok(IceTransport::rtc_ice_candidates_from_ice_candidates(
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

    /// W3C `IceTransport.getRemoteParameters()`: the remote ICE parameters received via
    /// `setRemoteDescription`.
    ///
    /// `None` if they have not been received yet. Note the difference from
    /// [`Self::get_remote_user_credentials`], which reports absent credentials as a pair of empty
    /// strings — a caller cannot tell those from a peer that genuinely sent empty ones, and the
    /// spec is explicit that this returns null.
    pub(crate) fn get_remote_parameters(&self) -> Option<RTCIceParameters> {
        let (username_fragment, password) = self.get_remote_user_credentials();
        if username_fragment.is_empty() && password.is_empty() {
            return None;
        }

        Some(RTCIceParameters {
            username_fragment: username_fragment.to_string(),
            password: password.to_string(),
            ice_lite: false,
        })
    }

    /// W3C `IceTransport.gatheringState`.
    ///
    /// The spec types this as `RTCIceGathererState`, a second enum whose values are identical to
    /// `RTCIceGatheringState`'s (`new`/`gathering`/`complete`). This crate carries one enum for
    /// both.
    pub(crate) fn gathering_state(&self) -> RTCIceGatheringState {
        self.ice_gathering_state
    }

    /// W3C `IceTransport.component`.
    ///
    /// Always [`RTCIceComponent::Rtp`]. RTCP multiplexing is required here — `RTCRtcpMuxPolicy`
    /// has the single value `"require"` — and for a muxed transport the spec itself specifies this
    /// value, so it is conformance rather than a simplification.
    pub(crate) fn component(&self) -> RTCIceComponent {
        RTCIceComponent::Rtp
    }

    /// W3C `IceTransport.getSelectedCandidatePair()`.
    ///
    /// `None` until ICE has nominated a pair.
    pub(crate) fn get_selected_candidate_pair(&self) -> Option<RTCIceCandidatePair> {
        let (local, remote) = self.agent.get_selected_candidate_pair()?;
        Some(RTCIceCandidatePair::new(local.into(), remote.into()))
    }

    /// W3C `IceTransport.getRemoteCandidates()`: the remote candidates received so far.
    pub(crate) fn get_remote_candidates(&self) -> Vec<RTCIceCandidate> {
        IceTransport::rtc_ice_candidates_from_ice_candidates(self.agent.get_remote_candidates())
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

    pub(crate) fn add_local_candidate(&mut self, c: Candidate) -> Result<bool> {
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

    /// Stages ICE-restart credentials so an offer can advertise them.
    ///
    /// Does not disturb the live session; see [`ice::Agent::generate_restart_credentials`].
    pub(crate) fn generate_restart_credentials(
        &mut self,
        ufrag: String,
        pwd: String,
    ) -> Result<()> {
        self.agent.generate_restart_credentials(ufrag, pwd)
    }

    /// Whether an ICE restart has been staged but not yet applied.
    pub(crate) fn has_pending_restart(&self) -> bool {
        self.agent.has_pending_restart()
    }

    /// Applies a staged ICE restart, restarting the agent's timers at `now`.
    pub(crate) fn apply_restart(
        &mut self,
        now: Instant,
        keep_local_candidates: bool,
    ) -> Result<()> {
        self.agent.apply_restart(now, keep_local_candidates)
    }

    pub(crate) fn start(
        &mut self,
        now: Instant,
        local_ice_role: RTCIceRole,
        remote_ice_parameters: RTCIceParameters,
    ) -> Result<()> {
        if self.state() != RTCIceTransportState::New {
            return Err(Error::ErrICETransportNotInNew);
        }

        self.agent.start_connectivity_checks(
            now,
            local_ice_role == RTCIceRole::Controlling,
            remote_ice_parameters.username_fragment,
            remote_ice_parameters.password,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::peer_connection::transport::{RTCTransportId, TransportKind};

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }
    use super::*;

    fn transport() -> IceTransport {
        let crypto_provider =
            crypto::default_provider().expect("a built-in crypto provider is enabled for tests");
        IceTransport::new(
            Instant::now(),
            AgentConfig::default(),
            crypto_provider,
            test_transport_id(TransportKind::Ice),
        )
        .expect("ice transport")
    }

    // W3C types this `RTCIceGathererState`; this crate carries the structurally identical
    // `RTCIceGatheringState` for both. The field was already assigned by the negotiation paths —
    // only the accessor was missing.
    #[test]
    fn gathering_state_reports_the_tracked_field() {
        let mut ice_transport = transport();
        assert_eq!(RTCIceGatheringState::New, ice_transport.gathering_state());

        ice_transport.ice_gathering_state = RTCIceGatheringState::Gathering;
        assert_eq!(
            RTCIceGatheringState::Gathering,
            ice_transport.gathering_state()
        );

        ice_transport.ice_gathering_state = RTCIceGatheringState::Complete;
        assert_eq!(
            RTCIceGatheringState::Complete,
            ice_transport.gathering_state()
        );
    }

    // The spec is explicit that this returns null before the remote description supplies
    // credentials. `get_remote_user_credentials()` reports that case as a pair of empty strings,
    // which a caller cannot distinguish from a peer that sent empty ones.
    #[test]
    fn remote_parameters_are_none_until_credentials_arrive() {
        let mut ice_transport = transport();
        assert_eq!(("", ""), ice_transport.get_remote_user_credentials());
        assert!(
            ice_transport.get_remote_parameters().is_none(),
            "no remote description has been applied"
        );

        ice_transport
            .set_remote_credentials(
                "remoteUfrag".to_owned(),
                "remotePasswordThatIsLongEnough".to_owned(),
            )
            .expect("set remote credentials");

        let params = ice_transport
            .get_remote_parameters()
            .expect("credentials have been applied");
        assert_eq!("remoteUfrag", params.username_fragment);
        assert_eq!("remotePasswordThatIsLongEnough", params.password);
    }

    // Under required RTCP multiplexing the spec itself specifies "rtp" for a transport carrying
    // both, so this is conformance rather than a stand-in.
    #[test]
    fn component_is_rtp_under_rtcp_mux() {
        assert_eq!(RTCIceComponent::Rtp, transport().component());
    }

    #[test]
    fn selected_candidate_pair_and_remote_candidates_are_empty_before_ice_runs() {
        let ice_transport = transport();
        assert!(ice_transport.get_selected_candidate_pair().is_none());
        assert!(ice_transport.get_remote_candidates().is_empty());
    }
}
