use std::fmt;

/// Indicates the state of the DTLS transport.
///
/// `RTCDtlsTransportState` describes the current state of the DTLS encryption
/// layer, which provides end-to-end encryption for WebRTC media and data.
///
/// # State Progression
///
/// The typical DTLS connection progresses through these states:
///
/// ```text
/// New → Connecting → Connected
/// ```
///
/// If problems occur or the connection is closed:
///
/// ```text
/// Connected → Closed (intentional shutdown)
/// Connecting → Failed (handshake failure)
/// ```
///
/// # Examples
///
/// ## Monitoring DTLS State
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsTransportState;
///
/// fn handle_dtls_state(state: RTCDtlsTransportState) {
///     match state {
///         RTCDtlsTransportState::New => {
///             println!("DTLS not started yet");
///         }
///         RTCDtlsTransportState::Connecting => {
///             println!("DTLS handshake in progress...");
///         }
///         RTCDtlsTransportState::Connected => {
///             println!("DTLS encryption established!");
///         }
///         RTCDtlsTransportState::Failed => {
///             println!("DTLS handshake failed");
///         }
///         RTCDtlsTransportState::Closed => {
///             println!("DTLS connection closed");
///         }
///         _ => {}
///     }
/// }
/// ```
///
/// ## Checking for Secure Connection
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsTransportState;
///
/// fn is_encrypted(dtls_state: RTCDtlsTransportState) -> bool {
///     dtls_state == RTCDtlsTransportState::Connected
/// }
///
/// assert!(is_encrypted(RTCDtlsTransportState::Connected));
/// assert!(!is_encrypted(RTCDtlsTransportState::Connecting));
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsTransportState;
///
/// let state = RTCDtlsTransportState::Connected;
/// assert_eq!(state.to_string(), "connected");
///
/// let parsed: RTCDtlsTransportState = "connecting".into();
/// assert_eq!(parsed, RTCDtlsTransportState::Connecting);
/// ```
///
/// # Specifications
///
/// - [W3C RTCDtlsTransport.state]
/// - [MDN RTCDtlsTransport.state]
/// - [RFC 6347] - DTLS 1.2
///
/// [W3C RTCDtlsTransport.state]: https://w3c.github.io/webrtc-pc/#dom-rtcdtlstransportstate
/// [MDN RTCDtlsTransport.state]: https://developer.mozilla.org/en-US/docs/Web/API/RTCDtlsTransport/state
/// [RFC 6347]: https://datatracker.ietf.org/doc/html/rfc6347
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCDtlsTransportState {
    /// State not specified. This should not occur in normal operation.
    #[default]
    Unspecified = 0,

    /// DTLS has not started negotiating yet.
    ///
    /// This is the initial state before the DTLS handshake begins. The transport
    /// is waiting for ICE to establish connectivity before starting DTLS.
    New = 1,

    /// DTLS handshake is in progress.
    ///
    /// DTLS is actively negotiating a secure connection and verifying the remote
    /// fingerprint. The handshake involves:
    ///
    /// - Exchange of certificates
    /// - Verification of certificate fingerprints
    /// - Key derivation for encryption
    ///
    /// Media cannot flow yet in this state.
    Connecting = 2,

    /// DTLS has completed negotiation successfully.
    ///
    /// A secure connection has been established and the remote fingerprint has
    /// been verified. Encryption keys have been derived and the connection is
    /// ready for encrypted media or data transmission.
    ///
    /// This is the desired state for active communication.
    Connected = 3,

    /// Transport has been closed intentionally.
    ///
    /// The transport has been closed as a result of:
    ///
    /// - Receipt of a close_notify alert from the peer
    /// - Local call to close() on the peer connection
    ///
    /// No further DTLS communication is possible.
    Closed = 4,

    /// Transport has failed due to an error.
    ///
    /// The DTLS handshake or connection has failed due to:
    ///
    /// - Receipt of an error alert
    /// - Failure to validate the remote fingerprint
    /// - Timeout during handshake
    /// - Certificate validation errors
    ///
    /// Common causes include fingerprint mismatch or network issues. Connection
    /// cannot be recovered without reestablishing from scratch.
    Failed = 5,
}

const DTLS_TRANSPORT_STATE_NEW_STR: &str = "new";
const DTLS_TRANSPORT_STATE_CONNECTING_STR: &str = "connecting";
const DTLS_TRANSPORT_STATE_CONNECTED_STR: &str = "connected";
const DTLS_TRANSPORT_STATE_CLOSED_STR: &str = "closed";
const DTLS_TRANSPORT_STATE_FAILED_STR: &str = "failed";

impl From<&str> for RTCDtlsTransportState {
    fn from(raw: &str) -> Self {
        match raw {
            DTLS_TRANSPORT_STATE_NEW_STR => RTCDtlsTransportState::New,
            DTLS_TRANSPORT_STATE_CONNECTING_STR => RTCDtlsTransportState::Connecting,
            DTLS_TRANSPORT_STATE_CONNECTED_STR => RTCDtlsTransportState::Connected,
            DTLS_TRANSPORT_STATE_CLOSED_STR => RTCDtlsTransportState::Closed,
            DTLS_TRANSPORT_STATE_FAILED_STR => RTCDtlsTransportState::Failed,
            _ => RTCDtlsTransportState::Unspecified,
        }
    }
}

impl From<u8> for RTCDtlsTransportState {
    fn from(v: u8) -> Self {
        match v {
            1 => RTCDtlsTransportState::New,
            2 => RTCDtlsTransportState::Connecting,
            3 => RTCDtlsTransportState::Connected,
            4 => RTCDtlsTransportState::Closed,
            5 => RTCDtlsTransportState::Failed,
            _ => RTCDtlsTransportState::Unspecified,
        }
    }
}

impl fmt::Display for RTCDtlsTransportState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCDtlsTransportState::New => DTLS_TRANSPORT_STATE_NEW_STR,
            RTCDtlsTransportState::Connecting => DTLS_TRANSPORT_STATE_CONNECTING_STR,
            RTCDtlsTransportState::Connected => DTLS_TRANSPORT_STATE_CONNECTED_STR,
            RTCDtlsTransportState::Closed => DTLS_TRANSPORT_STATE_CLOSED_STR,
            RTCDtlsTransportState::Failed => DTLS_TRANSPORT_STATE_FAILED_STR,
            RTCDtlsTransportState::Unspecified => {
                crate::peer_connection::configuration::UNSPECIFIED_STR
            }
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_dtls_transport_state() {
        let tests = vec![
            (
                crate::peer_connection::configuration::UNSPECIFIED_STR,
                RTCDtlsTransportState::Unspecified,
            ),
            ("new", RTCDtlsTransportState::New),
            ("connecting", RTCDtlsTransportState::Connecting),
            ("connected", RTCDtlsTransportState::Connected),
            ("closed", RTCDtlsTransportState::Closed),
            ("failed", RTCDtlsTransportState::Failed),
        ];

        for (state_string, expected_state) in tests {
            assert_eq!(
                RTCDtlsTransportState::from(state_string),
                expected_state,
                "testCase: {expected_state}",
            );
        }
    }

    #[test]
    fn test_dtls_transport_state_string() {
        let tests = vec![
            (
                RTCDtlsTransportState::Unspecified,
                crate::peer_connection::configuration::UNSPECIFIED_STR,
            ),
            (RTCDtlsTransportState::New, "new"),
            (RTCDtlsTransportState::Connecting, "connecting"),
            (RTCDtlsTransportState::Connected, "connected"),
            (RTCDtlsTransportState::Closed, "closed"),
            (RTCDtlsTransportState::Failed, "failed"),
        ];

        for (state, expected_string) in tests {
            assert_eq!(state.to_string(), expected_string)
        }
    }
}
