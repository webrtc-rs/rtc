use crate::transport::ice::role::RTCIceRole;
use crate::transport::ice::state::RTCIceTransportState;

pub mod candidate;
pub mod candidate_pair;
pub mod candidate_type;
pub mod protocol;
pub mod role;
pub mod server;
pub mod state;

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
}
