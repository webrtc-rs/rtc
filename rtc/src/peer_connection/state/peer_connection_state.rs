use crate::peer_connection::configuration::UNSPECIFIED_STR;
use std::fmt;

/// Indicates the overall state of the peer connection.
///
/// `RTCPeerConnectionState` is an aggregate state that combines the states of
/// both the ICE transport layer and the DTLS transport layer. It provides a
/// high-level view of whether the connection is ready for media to flow.
///
/// # State Determination
///
/// This state is derived from the combination of:
///
/// - **ICE transport states** - Network connectivity
/// - **DTLS transport states** - Encryption handshake
///
/// The peer connection is only fully "connected" when both ICE and DTLS are
/// successfully established.
///
/// # State Transitions
///
/// Typical progression for a successful connection:
///
/// ```text
/// New → Connecting → Connected
/// ```
///
/// If problems occur:
///
/// ```text
/// Connected → Disconnected → (may recover to Connected)
/// Connected → Failed (permanent failure)
/// Any state → Closed (connection closed)
/// ```
///
/// # Examples
///
/// ## Monitoring Overall Connection State
///
/// ```no_run
/// use rtc::peer_connection::state::RTCPeerConnectionState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
///         match state {
///             RTCPeerConnectionState::New => {
///                 println!("Connection initialized");
///             }
///             RTCPeerConnectionState::Connecting => {
///                 println!("Establishing connection (ICE + DTLS)...");
///             }
///             RTCPeerConnectionState::Connected => {
///                 println!("✓ Connection established - media can flow!");
///             }
///             RTCPeerConnectionState::Disconnected => {
///                 println!("⚠ Connection lost - may reconnect automatically");
///             }
///             RTCPeerConnectionState::Failed => {
///                 println!("✗ Connection failed - requires ICE restart");
///             }
///             RTCPeerConnectionState::Closed => {
///                 println!("Connection closed");
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// ## Checking if Connection is Active
///
/// ```
/// use rtc::peer_connection::state::RTCPeerConnectionState;
///
/// fn is_connected(state: RTCPeerConnectionState) -> bool {
///     matches!(state, RTCPeerConnectionState::Connected)
/// }
///
/// fn can_send_media(state: RTCPeerConnectionState) -> bool {
///     matches!(state, RTCPeerConnectionState::Connected)
/// }
///
/// assert!(is_connected(RTCPeerConnectionState::Connected));
/// assert!(!is_connected(RTCPeerConnectionState::Connecting));
/// assert!(can_send_media(RTCPeerConnectionState::Connected));
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::state::RTCPeerConnectionState;
///
/// // Convert to string
/// let state = RTCPeerConnectionState::Connected;
/// assert_eq!(state.to_string(), "connected");
///
/// // Parse from string
/// let parsed: RTCPeerConnectionState = "connecting".into();
/// assert_eq!(parsed, RTCPeerConnectionState::Connecting);
/// ```
///
/// ## Handling Disconnections
///
/// ```no_run
/// use rtc::peer_connection::state::RTCPeerConnectionState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_disconnection(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
///         match state {
///             RTCPeerConnectionState::Disconnected => {
///                 println!("Connection lost - ICE will try to reconnect");
///                 // Optionally: Show reconnecting UI
///                 // Wait for automatic recovery or timeout
///             }
///             RTCPeerConnectionState::Failed => {
///                 println!("Connection failed permanently");
///                 // Typically: Trigger ICE restart
///                 // Or: Close and recreate connection
///             }
///             RTCPeerConnectionState::Connected => {
///                 println!("Connection restored!");
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// # Specifications
///
/// - [W3C RTCPeerConnection.connectionState]
/// - [MDN RTCPeerConnection.connectionState]
///
/// [W3C RTCPeerConnection.connectionState]: https://w3c.github.io/webrtc-pc/#dom-peerconnection-connection-state
/// [MDN RTCPeerConnection.connectionState]: https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/connectionState
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCPeerConnectionState {
    /// State not specified. This should not occur in normal operation.
    #[default]
    Unspecified,

    /// Connection is in initial state.
    ///
    /// Any of the ICE or DTLS transports are in the "new" state and none are
    /// in "connecting", "checking", "failed", or "disconnected" state, or all
    /// transports are in "closed" state, or there are no transports.
    New,

    /// Connection establishment is in progress.
    ///
    /// At least one ICE or DTLS transport is in the "connecting" or "checking"
    /// state and none are in "failed" state. This indicates that ICE connectivity
    /// checks are running and/or DTLS handshake is in progress.
    ///
    /// Media cannot flow yet in this state.
    Connecting,

    /// Connection is established and media can flow.
    ///
    /// All ICE and DTLS transports are in "connected", "completed", or "closed"
    /// state, and at least one is in "connected" or "completed" state. Both
    /// ICE connectivity and DTLS encryption are successfully established.
    ///
    /// This is the desired state for active media communication.
    Connected,

    /// Connection was established but has been lost.
    ///
    /// At least one ICE or DTLS transport is in "disconnected" state and none
    /// are in "failed", "connecting", or "checking" state. This may be a
    /// temporary condition due to network changes.
    ///
    /// ICE will attempt to restore connectivity automatically. If it succeeds,
    /// the state will return to Connected. If it fails, the state will move to
    /// Failed.
    Disconnected,

    /// Connection has permanently failed.
    ///
    /// At least one ICE or DTLS transport is in "failed" state. The connection
    /// cannot be established or restored without intervention, typically
    /// requiring an ICE restart.
    ///
    /// Common causes: NAT/firewall blocking, network unreachable, DTLS
    /// handshake failure.
    Failed,

    /// Connection has been closed.
    ///
    /// The peer connection's `isClosed` member is true. All transports have
    /// been shut down. No further communication is possible.
    Closed,
}

const PEER_CONNECTION_STATE_NEW_STR: &str = "new";
const PEER_CONNECTION_STATE_CONNECTING_STR: &str = "connecting";
const PEER_CONNECTION_STATE_CONNECTED_STR: &str = "connected";
const PEER_CONNECTION_STATE_DISCONNECTED_STR: &str = "disconnected";
const PEER_CONNECTION_STATE_FAILED_STR: &str = "failed";
const PEER_CONNECTION_STATE_CLOSED_STR: &str = "closed";

impl From<&str> for RTCPeerConnectionState {
    fn from(raw: &str) -> Self {
        match raw {
            PEER_CONNECTION_STATE_NEW_STR => RTCPeerConnectionState::New,
            PEER_CONNECTION_STATE_CONNECTING_STR => RTCPeerConnectionState::Connecting,
            PEER_CONNECTION_STATE_CONNECTED_STR => RTCPeerConnectionState::Connected,
            PEER_CONNECTION_STATE_DISCONNECTED_STR => RTCPeerConnectionState::Disconnected,
            PEER_CONNECTION_STATE_FAILED_STR => RTCPeerConnectionState::Failed,
            PEER_CONNECTION_STATE_CLOSED_STR => RTCPeerConnectionState::Closed,
            _ => RTCPeerConnectionState::Unspecified,
        }
    }
}

impl From<u8> for RTCPeerConnectionState {
    fn from(v: u8) -> Self {
        match v {
            1 => RTCPeerConnectionState::New,
            2 => RTCPeerConnectionState::Connecting,
            3 => RTCPeerConnectionState::Connected,
            4 => RTCPeerConnectionState::Disconnected,
            5 => RTCPeerConnectionState::Failed,
            6 => RTCPeerConnectionState::Closed,
            _ => RTCPeerConnectionState::Unspecified,
        }
    }
}

impl fmt::Display for RTCPeerConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCPeerConnectionState::New => PEER_CONNECTION_STATE_NEW_STR,
            RTCPeerConnectionState::Connecting => PEER_CONNECTION_STATE_CONNECTING_STR,
            RTCPeerConnectionState::Connected => PEER_CONNECTION_STATE_CONNECTED_STR,
            RTCPeerConnectionState::Disconnected => PEER_CONNECTION_STATE_DISCONNECTED_STR,
            RTCPeerConnectionState::Failed => PEER_CONNECTION_STATE_FAILED_STR,
            RTCPeerConnectionState::Closed => PEER_CONNECTION_STATE_CLOSED_STR,
            RTCPeerConnectionState::Unspecified => UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum NegotiationNeededState {
    /// NegotiationNeededStateEmpty not running and queue is empty
    #[default]
    Empty,
    /// NegotiationNeededStateEmpty running and queue is empty
    Run,
    /// NegotiationNeededStateEmpty running and queue
    Queue,
}

impl From<u8> for NegotiationNeededState {
    fn from(v: u8) -> Self {
        match v {
            1 => NegotiationNeededState::Run,
            2 => NegotiationNeededState::Queue,
            _ => NegotiationNeededState::Empty,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_peer_connection_state() {
        let tests = vec![
            (UNSPECIFIED_STR, RTCPeerConnectionState::Unspecified),
            ("new", RTCPeerConnectionState::New),
            ("connecting", RTCPeerConnectionState::Connecting),
            ("connected", RTCPeerConnectionState::Connected),
            ("disconnected", RTCPeerConnectionState::Disconnected),
            ("failed", RTCPeerConnectionState::Failed),
            ("closed", RTCPeerConnectionState::Closed),
        ];

        for (state_string, expected_state) in tests {
            assert_eq!(
                RTCPeerConnectionState::from(state_string),
                expected_state,
                "testCase: {expected_state}",
            );
        }
    }

    #[test]
    fn test_peer_connection_state_string() {
        let tests = vec![
            (RTCPeerConnectionState::Unspecified, UNSPECIFIED_STR),
            (RTCPeerConnectionState::New, "new"),
            (RTCPeerConnectionState::Connecting, "connecting"),
            (RTCPeerConnectionState::Connected, "connected"),
            (RTCPeerConnectionState::Disconnected, "disconnected"),
            (RTCPeerConnectionState::Failed, "failed"),
            (RTCPeerConnectionState::Closed, "closed"),
        ];

        for (state, expected_string) in tests {
            assert_eq!(state.to_string(), expected_string)
        }
    }
}
