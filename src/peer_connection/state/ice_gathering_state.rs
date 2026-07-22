use std::fmt;

/// Describes the state of the ICE candidate gathering process.
///
/// `RTCIceGatheringState` indicates the progress of gathering local ICE candidates,
/// which are network addresses that can be used for peer-to-peer connectivity.
/// The gathering process collects candidates from local network interfaces, STUN
/// servers, and TURN servers.
///
/// # Gathering Process
///
/// The ICE agent gathers candidates in this sequence:
///
/// 1. **New** - Gathering has not started
/// 2. **Gathering** - Actively collecting candidates from network interfaces and servers
/// 3. **Complete** - All candidates have been gathered
///
/// Once in the Complete state, all discovered candidates are available and the
/// offer/answer can be safely transmitted to the remote peer.
///
/// # Examples
///
/// ## Monitoring Gathering Progress
///
/// ```no_run
/// use rtc::peer_connection::state::RTCIceGatheringState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(state) => {
///         match state {
///             RTCIceGatheringState::New => {
///                 println!("Gathering not started yet");
///             }
///             RTCIceGatheringState::Gathering => {
///                 println!("Gathering ICE candidates from network interfaces...");
///                 println!("Candidates will be available via OnIceCandidate events");
///             }
///             RTCIceGatheringState::Complete => {
///                 println!("All ICE candidates gathered!");
///                 println!("Safe to send complete SDP to remote peer");
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// ## Waiting for Gathering to Complete
///
/// ```no_run
/// use rtc::peer_connection::state::RTCIceGatheringState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn example(event: RTCPeerConnectionEvent) -> bool {
/// // Check if gathering is complete before sending offer
/// if let RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(state) = event {
///     if state == RTCIceGatheringState::Complete {
///         println!("Ready to send offer with all candidates");
///         return true;
///     }
/// }
/// false
/// # }
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::state::RTCIceGatheringState;
///
/// // Convert to string
/// let state = RTCIceGatheringState::Gathering;
/// assert_eq!(state.to_string(), "gathering");
///
/// // Parse from string
/// let parsed: RTCIceGatheringState = "complete".into();
/// assert_eq!(parsed, RTCIceGatheringState::Complete);
/// ```
///
/// ## Trickle ICE vs. Complete Gathering
///
/// ```no_run
/// use rtc::peer_connection::state::RTCIceGatheringState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_gathering(event: RTCPeerConnectionEvent, use_trickle_ice: bool) {
/// match event {
///     RTCPeerConnectionEvent::OnIceGatheringStateChangeEvent(state) => {
///         if use_trickle_ice {
///             // Trickle ICE: Send candidates as they arrive
///             println!("Send each candidate immediately via OnIceCandidate event");
///         } else if state == RTCIceGatheringState::Complete {
///             // Wait for all candidates before sending offer
///             println!("Send complete offer with all candidates included");
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// # Specifications
///
/// - [W3C RTCPeerConnection.iceGatheringState]
/// - [MDN RTCPeerConnection.iceGatheringState]
/// - [RFC 8445] - ICE Protocol
/// - [RFC 8838] - Trickle ICE
///
/// [W3C RTCPeerConnection.iceGatheringState]: https://w3c.github.io/webrtc-pc/#dom-peerconnection-ice-gathering-state
/// [MDN RTCPeerConnection.iceGatheringState]: https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/iceGatheringState
/// [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
/// [RFC 8838]: https://datatracker.ietf.org/doc/html/rfc8838
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCIceGatheringState {
    /// State not specified. This should not occur in normal operation.
    #[default]
    Unspecified,

    /// ICE agent is waiting to gather candidates.
    ///
    /// This is the initial state before gathering begins. Any of the ICE
    /// transports are in the "new" gathering state and none are in "gathering"
    /// state, or there are no transports.
    ///
    /// Gathering starts when the first local description is set.
    New,

    /// ICE agent is actively gathering candidates.
    ///
    /// The agent is collecting local network addresses, querying STUN servers
    /// for server-reflexive addresses, and potentially allocating TURN relays.
    /// At least one ICE transport is in the "gathering" state.
    ///
    /// Candidates become available through OnIceCandidate events during this
    /// phase. For trickle ICE, send each candidate to the remote peer as it
    /// arrives.
    Gathering,

    /// ICE agent has finished gathering all candidates.
    ///
    /// All ICE transports have finished gathering. At least one ICE transport
    /// exists, and all are in the "completed" gathering state.
    ///
    /// The local description now contains all possible candidates. It's safe
    /// to send the complete offer/answer to the remote peer if not using
    /// trickle ICE.
    Complete,
}

const ICE_GATHERING_STATE_NEW_STR: &str = "new";
const ICE_GATHERING_STATE_GATHERING_STR: &str = "gathering";
const ICE_GATHERING_STATE_COMPLETE_STR: &str = "complete";

/// takes a string and converts it to ICEGatheringState
impl From<&str> for RTCIceGatheringState {
    fn from(raw: &str) -> Self {
        match raw {
            ICE_GATHERING_STATE_NEW_STR => RTCIceGatheringState::New,
            ICE_GATHERING_STATE_GATHERING_STR => RTCIceGatheringState::Gathering,
            ICE_GATHERING_STATE_COMPLETE_STR => RTCIceGatheringState::Complete,
            _ => RTCIceGatheringState::Unspecified,
        }
    }
}

impl fmt::Display for RTCIceGatheringState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCIceGatheringState::New => write!(f, "{ICE_GATHERING_STATE_NEW_STR}"),
            RTCIceGatheringState::Gathering => write!(f, "{ICE_GATHERING_STATE_GATHERING_STR}"),
            RTCIceGatheringState::Complete => {
                write!(f, "{ICE_GATHERING_STATE_COMPLETE_STR}")
            }
            _ => write!(
                f,
                "{}",
                crate::peer_connection::configuration::UNSPECIFIED_STR
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_ice_gathering_state() {
        let tests = vec![
            ("Unspecified", RTCIceGatheringState::Unspecified),
            ("new", RTCIceGatheringState::New),
            ("gathering", RTCIceGatheringState::Gathering),
            ("complete", RTCIceGatheringState::Complete),
        ];

        for (state_string, expected_state) in tests {
            assert_eq!(RTCIceGatheringState::from(state_string), expected_state);
        }
    }

    #[test]
    fn test_ice_gathering_state_string() {
        let tests = vec![
            (RTCIceGatheringState::Unspecified, "Unspecified"),
            (RTCIceGatheringState::New, "new"),
            (RTCIceGatheringState::Gathering, "gathering"),
            (RTCIceGatheringState::Complete, "complete"),
        ];

        for (state, expected_string) in tests {
            assert_eq!(state.to_string(), expected_string);
        }
    }
}
