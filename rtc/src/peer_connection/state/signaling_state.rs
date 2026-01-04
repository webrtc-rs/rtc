use std::fmt;

use crate::peer_connection::sdp::sdp_type::RTCSdpType;
use shared::error::{Error, Result};

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub(crate) enum StateChangeOp {
    #[default]
    SetLocal,
    SetRemote,
}

impl fmt::Display for StateChangeOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            StateChangeOp::SetLocal => write!(f, "SetLocal"),
            StateChangeOp::SetRemote => write!(f, "SetRemote"),
            //_ => write!(f, UNSPECIFIED_STR),
        }
    }
}

/// Indicates the state of the SDP offer/answer negotiation process.
///
/// `RTCSignalingState` describes the current state of the SDP (Session Description
/// Protocol) signaling exchange between local and remote peers. The signaling state
/// tracks progress through the offer/answer model defined in RFC 3264.
///
/// # Signaling Flow
///
/// The typical offer/answer exchange follows this pattern:
///
/// **Initiating Peer (Offerer):**
/// ```text
/// Stable → (setLocalDescription with offer) → HaveLocalOffer
///       → (setRemoteDescription with answer) → Stable
/// ```
///
/// **Responding Peer (Answerer):**
/// ```text
/// Stable → (setRemoteDescription with offer) → HaveRemoteOffer
///       → (setLocalDescription with answer) → Stable
/// ```
///
/// Provisional answers add intermediate states:
/// ```text
/// HaveLocalOffer → (setRemoteDescription with pranswer) → HaveRemotePranswer
///                → (setRemoteDescription with answer) → Stable
/// ```
///
/// # State Machine Rules
///
/// The signaling state machine enforces valid transitions according to the
/// WebRTC specification. Invalid transitions (e.g., setting an answer when
/// in Stable state) will result in errors.
///
/// # Examples
///
/// ## Monitoring Signaling State (Offerer)
///
/// ```no_run
/// use rtc::peer_connection::state::RTCSignalingState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_event_offerer(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
///         match state {
///             RTCSignalingState::Stable => {
///                 println!("Ready to create new offer");
///             }
///             RTCSignalingState::HaveLocalOffer => {
///                 println!("Offer sent, waiting for answer from remote peer");
///             }
///             RTCSignalingState::HaveRemotePranswer => {
///                 println!("Received provisional answer, waiting for final answer");
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// ## Monitoring Signaling State (Answerer)
///
/// ```no_run
/// use rtc::peer_connection::state::RTCSignalingState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_event_answerer(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
///         match state {
///             RTCSignalingState::HaveRemoteOffer => {
///                 println!("Received offer from remote peer");
///                 println!("Need to create and set answer");
///             }
///             RTCSignalingState::Stable => {
///                 println!("Answer sent and accepted - negotiation complete");
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// ## Checking if Negotiation is in Progress
///
/// ```
/// use rtc::peer_connection::state::RTCSignalingState;
///
/// fn is_negotiating(state: RTCSignalingState) -> bool {
///     !matches!(state, RTCSignalingState::Stable | RTCSignalingState::Closed)
/// }
///
/// fn can_create_offer(state: RTCSignalingState) -> bool {
///     matches!(state, RTCSignalingState::Stable)
/// }
///
/// assert!(!is_negotiating(RTCSignalingState::Stable));
/// assert!(is_negotiating(RTCSignalingState::HaveLocalOffer));
/// assert!(can_create_offer(RTCSignalingState::Stable));
/// assert!(!can_create_offer(RTCSignalingState::HaveRemoteOffer));
/// ```
///
/// ## String Conversion
///
/// ```
/// use rtc::peer_connection::state::RTCSignalingState;
///
/// // Convert to string
/// let state = RTCSignalingState::HaveLocalOffer;
/// assert_eq!(state.to_string(), "have-local-offer");
///
/// // Parse from string
/// let parsed: RTCSignalingState = "have-remote-offer".into();
/// assert_eq!(parsed, RTCSignalingState::HaveRemoteOffer);
/// ```
///
/// ## Handling State Transitions
///
/// ```no_run
/// use rtc::peer_connection::state::RTCSignalingState;
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_transitions(event: RTCPeerConnectionEvent, is_offerer: bool) {
/// match event {
///     RTCPeerConnectionEvent::OnSignalingStateChangeEvent(state) => {
///         match (is_offerer, state) {
///             (true, RTCSignalingState::Stable) => {
///                 println!("Ready to renegotiate if needed");
///             }
///             (true, RTCSignalingState::HaveLocalOffer) => {
///                 // Offer created and set locally
///                 println!("Send offer SDP to remote peer via signaling channel");
///             }
///             (false, RTCSignalingState::HaveRemoteOffer) => {
///                 // Offer received from remote
///                 println!("Create and send answer");
///             }
///             (false, RTCSignalingState::Stable) => {
///                 println!("Negotiation complete");
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
/// - [W3C RTCPeerConnection.signalingState]
/// - [MDN RTCPeerConnection.signalingState]
/// - [RFC 3264] - Offer/Answer Model
///
/// [W3C RTCPeerConnection.signalingState]: https://w3c.github.io/webrtc-pc/#dom-peerconnection-signaling-state
/// [MDN RTCPeerConnection.signalingState]: https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/signalingState
/// [RFC 3264]: https://datatracker.ietf.org/doc/html/rfc3264
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCSignalingState {
    /// State not specified. This should not occur in normal operation.
    Unspecified = 0,

    /// No offer/answer exchange is in progress.
    ///
    /// This is the initial state and also the state after a successful
    /// offer/answer exchange completes. In this state:
    ///
    /// - Both local and remote descriptions may be null (initial state)
    /// - Or both descriptions are set (after successful negotiation)
    ///
    /// A new negotiation can only be started from this state. This is the
    /// default state.
    #[default]
    Stable,

    /// Local offer has been set, waiting for remote answer.
    ///
    /// A local description of type "offer" has been successfully applied via
    /// `setLocalDescription()`. The local peer is now waiting for the remote
    /// peer to respond with an answer or provisional answer.
    ///
    /// Transition: Stable → (setLocalDescription with offer) → HaveLocalOffer
    HaveLocalOffer,

    /// Remote offer has been set, need to create local answer.
    ///
    /// A remote description of type "offer" has been successfully applied via
    /// `setRemoteDescription()`. The local peer should now create and set a
    /// local answer (or provisional answer) to complete the negotiation.
    ///
    /// Transition: Stable → (setRemoteDescription with offer) → HaveRemoteOffer
    HaveRemoteOffer,

    /// Remote offer received, local provisional answer set.
    ///
    /// A remote description of type "offer" was applied, followed by a local
    /// description of type "pranswer" (provisional answer). The local peer
    /// will later send a final answer to complete negotiation.
    ///
    /// Provisional answers allow early media to flow before final codec/
    /// transport selection is complete.
    ///
    /// Transition: HaveRemoteOffer → (setLocalDescription with pranswer) → HaveLocalPranswer
    HaveLocalPranswer,

    /// Local offer sent, remote provisional answer received.
    ///
    /// A local description of type "offer" was applied, followed by a remote
    /// description of type "pranswer" (provisional answer). The remote peer
    /// will later send a final answer to complete negotiation.
    ///
    /// Transition: HaveLocalOffer → (setRemoteDescription with pranswer) → HaveRemotePranswer
    HaveRemotePranswer,

    /// The peer connection has been closed.
    ///
    /// No further signaling operations are possible. The connection must be
    /// recreated to establish communication again.
    Closed,
}

const SIGNALING_STATE_STABLE_STR: &str = "stable";
const SIGNALING_STATE_HAVE_LOCAL_OFFER_STR: &str = "have-local-offer";
const SIGNALING_STATE_HAVE_REMOTE_OFFER_STR: &str = "have-remote-offer";
const SIGNALING_STATE_HAVE_LOCAL_PRANSWER_STR: &str = "have-local-pranswer";
const SIGNALING_STATE_HAVE_REMOTE_PRANSWER_STR: &str = "have-remote-pranswer";
const SIGNALING_STATE_CLOSED_STR: &str = "closed";

impl From<&str> for RTCSignalingState {
    fn from(raw: &str) -> Self {
        match raw {
            SIGNALING_STATE_STABLE_STR => RTCSignalingState::Stable,
            SIGNALING_STATE_HAVE_LOCAL_OFFER_STR => RTCSignalingState::HaveLocalOffer,
            SIGNALING_STATE_HAVE_REMOTE_OFFER_STR => RTCSignalingState::HaveRemoteOffer,
            SIGNALING_STATE_HAVE_LOCAL_PRANSWER_STR => RTCSignalingState::HaveLocalPranswer,
            SIGNALING_STATE_HAVE_REMOTE_PRANSWER_STR => RTCSignalingState::HaveRemotePranswer,
            SIGNALING_STATE_CLOSED_STR => RTCSignalingState::Closed,
            _ => RTCSignalingState::Unspecified,
        }
    }
}

impl fmt::Display for RTCSignalingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCSignalingState::Stable => write!(f, "{SIGNALING_STATE_STABLE_STR}"),
            RTCSignalingState::HaveLocalOffer => {
                write!(f, "{SIGNALING_STATE_HAVE_LOCAL_OFFER_STR}")
            }
            RTCSignalingState::HaveRemoteOffer => {
                write!(f, "{SIGNALING_STATE_HAVE_REMOTE_OFFER_STR}")
            }
            RTCSignalingState::HaveLocalPranswer => {
                write!(f, "{SIGNALING_STATE_HAVE_LOCAL_PRANSWER_STR}")
            }
            RTCSignalingState::HaveRemotePranswer => {
                write!(f, "{SIGNALING_STATE_HAVE_REMOTE_PRANSWER_STR}")
            }
            RTCSignalingState::Closed => write!(f, "{SIGNALING_STATE_CLOSED_STR}"),
            _ => write!(
                f,
                "{}",
                crate::peer_connection::configuration::UNSPECIFIED_STR
            ),
        }
    }
}

impl From<u8> for RTCSignalingState {
    fn from(v: u8) -> Self {
        match v {
            1 => RTCSignalingState::Stable,
            2 => RTCSignalingState::HaveLocalOffer,
            3 => RTCSignalingState::HaveRemoteOffer,
            4 => RTCSignalingState::HaveLocalPranswer,
            5 => RTCSignalingState::HaveRemotePranswer,
            6 => RTCSignalingState::Closed,
            _ => RTCSignalingState::Unspecified,
        }
    }
}

pub(crate) fn check_next_signaling_state(
    cur: RTCSignalingState,
    next: RTCSignalingState,
    op: StateChangeOp,
    sdp_type: RTCSdpType,
) -> Result<RTCSignalingState> {
    // Special case for rollbacks
    if sdp_type == RTCSdpType::Rollback && cur == RTCSignalingState::Stable {
        return Err(Error::ErrSignalingStateCannotRollback);
    }

    // 4.3.1 valid state transitions
    match cur {
        RTCSignalingState::Stable => {
            match op {
                StateChangeOp::SetLocal => {
                    // stable->SetLocal(offer)->have-local-offer
                    if sdp_type == RTCSdpType::Offer && next == RTCSignalingState::HaveLocalOffer {
                        return Ok(next);
                    }
                }
                StateChangeOp::SetRemote => {
                    // stable->SetRemote(offer)->have-remote-offer
                    if sdp_type == RTCSdpType::Offer && next == RTCSignalingState::HaveRemoteOffer {
                        return Ok(next);
                    }
                }
            }
        }
        RTCSignalingState::HaveLocalOffer => {
            if op == StateChangeOp::SetRemote {
                match sdp_type {
                    // have-local-offer->SetRemote(answer)->stable
                    RTCSdpType::Answer => {
                        if next == RTCSignalingState::Stable {
                            return Ok(next);
                        }
                    }
                    // have-local-offer->SetRemote(pranswer)->have-remote-pranswer
                    RTCSdpType::Pranswer => {
                        if next == RTCSignalingState::HaveRemotePranswer {
                            return Ok(next);
                        }
                    }
                    _ => {}
                }
            } else if op == StateChangeOp::SetLocal
                && sdp_type == RTCSdpType::Offer
                && next == RTCSignalingState::HaveLocalOffer
            {
                return Ok(next);
            }
        }
        RTCSignalingState::HaveRemotePranswer => {
            if op == StateChangeOp::SetRemote && sdp_type == RTCSdpType::Answer {
                // have-remote-pranswer->SetRemote(answer)->stable
                if next == RTCSignalingState::Stable {
                    return Ok(next);
                }
            }
        }
        RTCSignalingState::HaveRemoteOffer => {
            if op == StateChangeOp::SetLocal {
                match sdp_type {
                    // have-remote-offer->SetLocal(answer)->stable
                    RTCSdpType::Answer => {
                        if next == RTCSignalingState::Stable {
                            return Ok(next);
                        }
                    }
                    // have-remote-offer->SetLocal(pranswer)->have-local-pranswer
                    RTCSdpType::Pranswer => {
                        if next == RTCSignalingState::HaveLocalPranswer {
                            return Ok(next);
                        }
                    }
                    _ => {}
                }
            }
        }
        RTCSignalingState::HaveLocalPranswer => {
            if op == StateChangeOp::SetLocal && sdp_type == RTCSdpType::Answer {
                // have-local-pranswer->SetLocal(answer)->stable
                if next == RTCSignalingState::Stable {
                    return Ok(next);
                }
            }
        }
        _ => {
            return Err(Error::ErrSignalingStateProposedTransitionInvalid(format!(
                "from {} applying {} {}",
                cur,
                sdp_type,
                op == StateChangeOp::SetLocal
            )));
        }
    };

    Err(Error::ErrSignalingStateProposedTransitionInvalid(format!(
        "from {} applying {} {}",
        cur,
        op == StateChangeOp::SetLocal,
        sdp_type
    )))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_signaling_state() {
        let tests = vec![
            ("Unspecified", RTCSignalingState::Unspecified),
            ("stable", RTCSignalingState::Stable),
            ("have-local-offer", RTCSignalingState::HaveLocalOffer),
            ("have-remote-offer", RTCSignalingState::HaveRemoteOffer),
            ("have-local-pranswer", RTCSignalingState::HaveLocalPranswer),
            (
                "have-remote-pranswer",
                RTCSignalingState::HaveRemotePranswer,
            ),
            ("closed", RTCSignalingState::Closed),
        ];

        for (state_string, expected_state) in tests {
            assert_eq!(RTCSignalingState::from(state_string), expected_state);
        }
    }

    #[test]
    fn test_signaling_state_string() {
        let tests = vec![
            (RTCSignalingState::Unspecified, "Unspecified"),
            (RTCSignalingState::Stable, "stable"),
            (RTCSignalingState::HaveLocalOffer, "have-local-offer"),
            (RTCSignalingState::HaveRemoteOffer, "have-remote-offer"),
            (RTCSignalingState::HaveLocalPranswer, "have-local-pranswer"),
            (
                RTCSignalingState::HaveRemotePranswer,
                "have-remote-pranswer",
            ),
            (RTCSignalingState::Closed, "closed"),
        ];

        for (state, expected_string) in tests {
            assert_eq!(state.to_string(), expected_string);
        }
    }

    #[test]
    fn test_signaling_state_transitions() {
        let tests = vec![
            (
                "stable->SetLocal(offer)->have-local-offer",
                RTCSignalingState::Stable,
                RTCSignalingState::HaveLocalOffer,
                StateChangeOp::SetLocal,
                RTCSdpType::Offer,
                None,
            ),
            (
                "stable->SetRemote(offer)->have-remote-offer",
                RTCSignalingState::Stable,
                RTCSignalingState::HaveRemoteOffer,
                StateChangeOp::SetRemote,
                RTCSdpType::Offer,
                None,
            ),
            (
                "have-local-offer->SetRemote(answer)->stable",
                RTCSignalingState::HaveLocalOffer,
                RTCSignalingState::Stable,
                StateChangeOp::SetRemote,
                RTCSdpType::Answer,
                None,
            ),
            (
                "have-local-offer->SetRemote(pranswer)->have-remote-pranswer",
                RTCSignalingState::HaveLocalOffer,
                RTCSignalingState::HaveRemotePranswer,
                StateChangeOp::SetRemote,
                RTCSdpType::Pranswer,
                None,
            ),
            (
                "have-remote-pranswer->SetRemote(answer)->stable",
                RTCSignalingState::HaveRemotePranswer,
                RTCSignalingState::Stable,
                StateChangeOp::SetRemote,
                RTCSdpType::Answer,
                None,
            ),
            (
                "have-remote-offer->SetLocal(answer)->stable",
                RTCSignalingState::HaveRemoteOffer,
                RTCSignalingState::Stable,
                StateChangeOp::SetLocal,
                RTCSdpType::Answer,
                None,
            ),
            (
                "have-remote-offer->SetLocal(pranswer)->have-local-pranswer",
                RTCSignalingState::HaveRemoteOffer,
                RTCSignalingState::HaveLocalPranswer,
                StateChangeOp::SetLocal,
                RTCSdpType::Pranswer,
                None,
            ),
            (
                "have-local-pranswer->SetLocal(answer)->stable",
                RTCSignalingState::HaveLocalPranswer,
                RTCSignalingState::Stable,
                StateChangeOp::SetLocal,
                RTCSdpType::Answer,
                None,
            ),
            (
                "(invalid) stable->SetRemote(pranswer)->have-remote-pranswer",
                RTCSignalingState::Stable,
                RTCSignalingState::HaveRemotePranswer,
                StateChangeOp::SetRemote,
                RTCSdpType::Pranswer,
                Some(Error::ErrSignalingStateProposedTransitionInvalid(format!(
                    "from {} applying {} {}",
                    RTCSignalingState::Stable,
                    false,
                    RTCSdpType::Pranswer
                ))),
            ),
            (
                "(invalid) stable->SetRemote(rollback)->have-local-offer",
                RTCSignalingState::Stable,
                RTCSignalingState::HaveLocalOffer,
                StateChangeOp::SetRemote,
                RTCSdpType::Rollback,
                Some(Error::ErrSignalingStateCannotRollback),
            ),
        ];

        for (desc, cur, next, op, sdp_type, expected_err) in tests {
            let result = check_next_signaling_state(cur, next, op, sdp_type);
            match (&result, &expected_err) {
                (Ok(got), None) => {
                    assert_eq!(*got, next, "{desc} state mismatch");
                }
                (Err(got), Some(err)) => {
                    assert_eq!(got.to_string(), err.to_string(), "{desc} error mismatch");
                }
                _ => {
                    panic!("{desc}: expected {expected_err:?}, but got {result:?}");
                }
            };
        }
    }
}
