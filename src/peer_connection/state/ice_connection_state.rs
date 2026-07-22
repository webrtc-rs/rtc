use crate::peer_connection::configuration::UNSPECIFIED_STR;
use ice::state::ConnectionState;
use std::fmt;

/// Indicates the state of the ICE connection.
///
/// `RTCIceConnectionState` describes the current state of the ICE (Interactive
/// Connectivity Establishment) transport layer, which is responsible for establishing
/// network connectivity between peers through NAT traversal.
///
/// # State Transitions
///
/// The ICE connection typically progresses through these states:
///
/// 1. **New** - Initial state, no connectivity checks yet
/// 2. **Checking** - ICE agent is checking candidate pairs
/// 3. **Connected** - At least one working candidate pair found
/// 4. **Completed** - ICE has finished checking all candidates
///
/// The connection may also enter error states:
///
/// - **Disconnected** - Connectivity lost but recovery possible
/// - **Failed** - All candidate pairs failed, connection cannot be established
/// - **Closed** - Connection has been closed
///
/// # Examples
///
/// ## Monitoring ICE State Changes
///
/// ```no_run
/// use rtc::peer_connection::state::RTCIceConnectionState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
///         match state {
///             RTCIceConnectionState::New => {
///                 println!("ICE connectivity checking not started");
///             }
///             RTCIceConnectionState::Checking => {
///                 println!("ICE agent is checking connectivity...");
///             }
///             RTCIceConnectionState::Connected => {
///                 println!("ICE connected! Media can flow.");
///             }
///             RTCIceConnectionState::Completed => {
///                 println!("ICE finished checking all candidates");
///             }
///             RTCIceConnectionState::Disconnected => {
///                 println!("ICE connection lost - may reconnect");
///             }
///             RTCIceConnectionState::Failed => {
///                 println!("ICE failed - cannot establish connection");
///             }
///             RTCIceConnectionState::Closed => {
///                 println!("ICE connection closed");
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::state::RTCIceConnectionState;
///
/// // Convert state to string
/// let state = RTCIceConnectionState::Connected;
/// assert_eq!(state.to_string(), "connected");
///
/// // Parse from string
/// let parsed: RTCIceConnectionState = "checking".into();
/// assert_eq!(parsed, RTCIceConnectionState::Checking);
/// ```
///
/// ## Checking for Active Connection
///
/// ```
/// use rtc::peer_connection::state::RTCIceConnectionState;
///
/// fn is_ice_active(state: RTCIceConnectionState) -> bool {
///     matches!(
///         state,
///         RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
///     )
/// }
///
/// assert!(is_ice_active(RTCIceConnectionState::Connected));
/// assert!(is_ice_active(RTCIceConnectionState::Completed));
/// assert!(!is_ice_active(RTCIceConnectionState::Disconnected));
/// ```
///
/// # Specifications
///
/// - [W3C RTCPeerConnection.iceConnectionState]
/// - [MDN RTCPeerConnection.iceConnectionState]
/// - [RFC 8445] - ICE Protocol
///
/// [W3C RTCPeerConnection.iceConnectionState]: https://w3c.github.io/webrtc-pc/#dom-peerconnection-ice-connection-state
/// [MDN RTCPeerConnection.iceConnectionState]: https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/iceConnectionState
/// [RFC 8445]: https://datatracker.ietf.org/doc/html/rfc8445
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCIceConnectionState {
    /// State not specified. This should not occur in normal operation.
    #[default]
    Unspecified,

    /// ICE agent is gathering addresses or waiting to be given remote candidates.
    ///
    /// This is the initial state before connectivity checks begin. Any of the
    /// ICE transports are in the "new" state and none are in "checking",
    /// "disconnected", or "failed" state, or all ICE transports are in the
    /// "closed" state, or there are no transports.
    New,

    /// ICE agent has been given remote candidates and is checking pairs.
    ///
    /// The ICE agent is actively checking candidate pairs to find a working
    /// connection. At least one ICE transport is in the "checking" state and
    /// none are in "disconnected" or "failed" state.
    Checking,

    /// ICE agent has found a usable connection for all components.
    ///
    /// A working candidate pair has been found and is being used for
    /// communication. All ICE transports are in "connected", "completed",
    /// or "closed" state, and at least one is in the "connected" state.
    ///
    /// Media can flow in this state.
    Connected,

    /// ICE agent has finished gathering and checking candidates.
    ///
    /// The ICE agent has finished checking all candidate pairs and found
    /// working connections. All ICE transports are in "completed" or "closed"
    /// state, and at least one is in "completed" state.
    ///
    /// This is a more stable state than Connected.
    Completed,

    /// ICE connection has been lost, but recovery may be possible.
    ///
    /// The connection was working but has been lost. The ICE agent may be
    /// able to re-establish connectivity through ICE restart. At least one
    /// ICE transport is in "disconnected" state and none are in "failed" state.
    ///
    /// Consider triggering ICE restart if this state persists.
    Disconnected,

    /// ICE agent has determined that connection is not possible.
    ///
    /// All candidate pairs have failed connectivity checks. At least one ICE
    /// transport is in the "failed" state. Connection cannot be established
    /// without ICE restart.
    ///
    /// This typically indicates NAT/firewall issues or network problems.
    Failed,

    /// ICE agent has shut down and is no longer processing candidates.
    ///
    /// The peer connection's `isClosed` is true. No further ICE processing
    /// will occur.
    Closed,
}

const ICE_CONNECTION_STATE_NEW_STR: &str = "new";
const ICE_CONNECTION_STATE_CHECKING_STR: &str = "checking";
const ICE_CONNECTION_STATE_CONNECTED_STR: &str = "connected";
const ICE_CONNECTION_STATE_COMPLETED_STR: &str = "completed";
const ICE_CONNECTION_STATE_DISCONNECTED_STR: &str = "disconnected";
const ICE_CONNECTION_STATE_FAILED_STR: &str = "failed";
const ICE_CONNECTION_STATE_CLOSED_STR: &str = "closed";

/// takes a string and converts it to iceconnection_state
impl From<&str> for RTCIceConnectionState {
    fn from(raw: &str) -> Self {
        match raw {
            ICE_CONNECTION_STATE_NEW_STR => RTCIceConnectionState::New,
            ICE_CONNECTION_STATE_CHECKING_STR => RTCIceConnectionState::Checking,
            ICE_CONNECTION_STATE_CONNECTED_STR => RTCIceConnectionState::Connected,
            ICE_CONNECTION_STATE_COMPLETED_STR => RTCIceConnectionState::Completed,
            ICE_CONNECTION_STATE_DISCONNECTED_STR => RTCIceConnectionState::Disconnected,
            ICE_CONNECTION_STATE_FAILED_STR => RTCIceConnectionState::Failed,
            ICE_CONNECTION_STATE_CLOSED_STR => RTCIceConnectionState::Closed,
            _ => RTCIceConnectionState::Unspecified,
        }
    }
}

impl From<u8> for RTCIceConnectionState {
    fn from(v: u8) -> Self {
        match v {
            1 => RTCIceConnectionState::New,
            2 => RTCIceConnectionState::Checking,
            3 => RTCIceConnectionState::Connected,
            4 => RTCIceConnectionState::Completed,
            5 => RTCIceConnectionState::Disconnected,
            6 => RTCIceConnectionState::Failed,
            7 => RTCIceConnectionState::Closed,
            _ => RTCIceConnectionState::Unspecified,
        }
    }
}

impl fmt::Display for RTCIceConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCIceConnectionState::New => ICE_CONNECTION_STATE_NEW_STR,
            RTCIceConnectionState::Checking => ICE_CONNECTION_STATE_CHECKING_STR,
            RTCIceConnectionState::Connected => ICE_CONNECTION_STATE_CONNECTED_STR,
            RTCIceConnectionState::Completed => ICE_CONNECTION_STATE_COMPLETED_STR,
            RTCIceConnectionState::Disconnected => ICE_CONNECTION_STATE_DISCONNECTED_STR,
            RTCIceConnectionState::Failed => ICE_CONNECTION_STATE_FAILED_STR,
            RTCIceConnectionState::Closed => ICE_CONNECTION_STATE_CLOSED_STR,
            RTCIceConnectionState::Unspecified => UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}

impl From<ConnectionState> for RTCIceConnectionState {
    fn from(raw: ConnectionState) -> Self {
        match raw {
            ConnectionState::New => RTCIceConnectionState::New,
            ConnectionState::Checking => RTCIceConnectionState::Checking,
            ConnectionState::Connected => RTCIceConnectionState::Connected,
            ConnectionState::Completed => RTCIceConnectionState::Completed,
            ConnectionState::Failed => RTCIceConnectionState::Failed,
            ConnectionState::Disconnected => RTCIceConnectionState::Disconnected,
            ConnectionState::Closed => RTCIceConnectionState::Closed,
            _ => RTCIceConnectionState::Unspecified,
        }
    }
}

impl RTCIceConnectionState {
    pub(crate) fn to_ice(self) -> ConnectionState {
        match self {
            RTCIceConnectionState::New => ConnectionState::New,
            RTCIceConnectionState::Checking => ConnectionState::Checking,
            RTCIceConnectionState::Connected => ConnectionState::Connected,
            RTCIceConnectionState::Completed => ConnectionState::Completed,
            RTCIceConnectionState::Failed => ConnectionState::Failed,
            RTCIceConnectionState::Disconnected => ConnectionState::Disconnected,
            RTCIceConnectionState::Closed => ConnectionState::Closed,
            _ => ConnectionState::Unspecified,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_ice_connection_state() {
        let tests = vec![
            (UNSPECIFIED_STR, RTCIceConnectionState::Unspecified),
            ("new", RTCIceConnectionState::New),
            ("checking", RTCIceConnectionState::Checking),
            ("connected", RTCIceConnectionState::Connected),
            ("completed", RTCIceConnectionState::Completed),
            ("disconnected", RTCIceConnectionState::Disconnected),
            ("failed", RTCIceConnectionState::Failed),
            ("closed", RTCIceConnectionState::Closed),
        ];

        for (state_string, expected_state) in tests {
            assert_eq!(
                RTCIceConnectionState::from(state_string),
                expected_state,
                "testCase: {expected_state}",
            );
        }
    }

    #[test]
    fn test_ice_connection_state_string() {
        let tests = vec![
            (RTCIceConnectionState::Unspecified, UNSPECIFIED_STR),
            (RTCIceConnectionState::New, "new"),
            (RTCIceConnectionState::Checking, "checking"),
            (RTCIceConnectionState::Connected, "connected"),
            (RTCIceConnectionState::Completed, "completed"),
            (RTCIceConnectionState::Disconnected, "disconnected"),
            (RTCIceConnectionState::Failed, "failed"),
            (RTCIceConnectionState::Closed, "closed"),
        ];

        for (state, expected_string) in tests {
            assert_eq!(state.to_string(), expected_string)
        }
    }
}
