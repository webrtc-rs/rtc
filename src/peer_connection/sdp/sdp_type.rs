use std::fmt;

use crate::peer_connection::configuration::UNSPECIFIED_STR;
use serde::{Deserialize, Serialize};

/// Describes the type of a session description in the SDP offer/answer model.
///
/// `RTCSdpType` is used to indicate whether an [`RTCSessionDescription`](super::RTCSessionDescription)
/// represents an offer, answer, provisional answer, or rollback operation in the
/// WebRTC negotiation process.
///
/// # Offer/Answer Flow
///
/// The typical negotiation sequence is:
///
/// 1. Peer A creates an **Offer** describing their capabilities
/// 2. Peer B creates an **Answer** (or **Pranswer**) in response
/// 3. Both peers apply the descriptions to establish the connection
/// 4. If negotiation fails, either peer can use **Rollback** to return to stable state
///
/// # Examples
///
/// ## Creating Different SDP Types
///
/// ```
/// use rtc::peer_connection::sdp::RTCSdpType;
///
/// // Create an offer type
/// let offer_type = RTCSdpType::Offer;
/// assert_eq!(offer_type.to_string(), "offer");
///
/// // Create an answer type
/// let answer_type = RTCSdpType::Answer;
/// assert_eq!(answer_type.to_string(), "answer");
///
/// // Parse from string
/// let parsed: RTCSdpType = "pranswer".into();
/// assert_eq!(parsed, RTCSdpType::Pranswer);
/// ```
///
/// ## Checking SDP Type
///
/// ```no_run
/// use rtc::peer_connection::sdp::{RTCSessionDescription, RTCSdpType};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let description = RTCSessionDescription::offer("v=0...".to_string())?;
///
/// match description.sdp_type {
///     RTCSdpType::Offer => println!("This is an offer"),
///     RTCSdpType::Answer => println!("This is an answer"),
///     RTCSdpType::Pranswer => println!("This is a provisional answer"),
///     RTCSdpType::Rollback => println!("This is a rollback"),
///     RTCSdpType::Unspecified => println!("Type not specified"),
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Serialization
///
/// ```
/// use rtc::peer_connection::sdp::RTCSdpType;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Serialize to JSON
/// let offer = RTCSdpType::Offer;
/// let json = serde_json::to_string(&offer)?;
/// assert_eq!(json, "\"offer\"");
///
/// // Deserialize from JSON
/// let parsed: RTCSdpType = serde_json::from_str("\"answer\"")?;
/// assert_eq!(parsed, RTCSdpType::Answer);
/// # Ok(())
/// # }
/// ```
///
/// # Specifications
///
/// - [W3C RTCSessionDescription.type]
/// - [MDN RTCSessionDescription.type]
/// - [RFC 3264] - Offer/Answer Model
///
/// [W3C RTCSessionDescription.type]: https://w3c.github.io/webrtc-pc/#dom-rtcsessiondescription-type
/// [MDN RTCSessionDescription.type]: https://developer.mozilla.org/en-US/docs/Web/API/RTCSessionDescription/type
/// [RFC 3264]: https://datatracker.ietf.org/doc/html/rfc3264
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum RTCSdpType {
    /// Type not specified. This is the default value and should not be used
    /// in actual WebRTC negotiation.
    #[default]
    Unspecified = 0,

    /// Indicates that a description MUST be treated as an SDP offer.
    ///
    /// An offer is created by the initiating peer and describes their media
    /// capabilities, supported codecs, ICE candidates, and other session parameters.
    /// The remote peer responds to an offer with an answer.
    ///
    /// # Use Case
    ///
    /// Use when:
    /// - Starting a new WebRTC connection (initial offer)
    /// - Renegotiating an existing connection (renegotiation offer)
    /// - Adding or removing media tracks
    #[serde(rename = "offer")]
    Offer,

    /// Indicates that a description MUST be treated as a provisional SDP answer.
    ///
    /// A provisional answer (pranswer) is a non-final answer that can be sent
    /// before the final answer. It allows early media to flow while negotiation
    /// continues. A pranswer may be applied as a response to an SDP offer, or
    /// as an update to a previously sent pranswer.
    ///
    /// # Use Case
    ///
    /// Use when:
    /// - You want to start media flow immediately with a subset of capabilities
    /// - Final codec/transport selection is still being determined
    /// - Implementing early media scenarios (e.g., ringback tones)
    ///
    /// # Note
    ///
    /// Pranswers are less commonly used in modern WebRTC applications.
    /// Most implementations send a final answer immediately.
    #[serde(rename = "pranswer")]
    Pranswer,

    /// Indicates that a description MUST be treated as a final SDP answer.
    ///
    /// A final answer completes the offer-answer exchange. It is created by
    /// the remote peer in response to an offer and describes which codecs,
    /// media formats, and transport parameters have been agreed upon.
    /// An answer may also be used as an update to a previously sent pranswer.
    ///
    /// # Use Case
    ///
    /// Use when:
    /// - Responding to an offer with final negotiated parameters
    /// - Completing a pranswer with final codec/transport selection
    /// - Accepting or rejecting media tracks in the offer
    #[serde(rename = "answer")]
    Answer,

    /// Indicates that a description MUST be treated as canceling the current
    /// SDP negotiation.
    ///
    /// Rollback moves the SDP offer and answer back to what they were in the
    /// previous stable state. The local or remote SDP descriptions in the
    /// previous stable state could be null if there has not yet been a
    /// successful offer-answer negotiation.
    ///
    /// # Use Case
    ///
    /// Use when:
    /// - Negotiation fails and you want to retry
    /// - Canceling an in-progress negotiation
    /// - Recovering from glare (both peers send offers simultaneously)
    /// - Implementing sophisticated signaling retry logic
    ///
    /// # Note
    ///
    /// After a rollback, the connection returns to its previous stable state,
    /// and a new negotiation can be started.
    #[serde(rename = "rollback")]
    Rollback,
}

const SDP_TYPE_OFFER_STR: &str = "offer";
const SDP_TYPE_PRANSWER_STR: &str = "pranswer";
const SDP_TYPE_ANSWER_STR: &str = "answer";
const SDP_TYPE_ROLLBACK_STR: &str = "rollback";

/// creates an SDPType from a string
impl From<&str> for RTCSdpType {
    fn from(raw: &str) -> Self {
        match raw {
            SDP_TYPE_OFFER_STR => RTCSdpType::Offer,
            SDP_TYPE_PRANSWER_STR => RTCSdpType::Pranswer,
            SDP_TYPE_ANSWER_STR => RTCSdpType::Answer,
            SDP_TYPE_ROLLBACK_STR => RTCSdpType::Rollback,
            _ => RTCSdpType::Unspecified,
        }
    }
}

impl fmt::Display for RTCSdpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCSdpType::Offer => write!(f, "{SDP_TYPE_OFFER_STR}"),
            RTCSdpType::Pranswer => write!(f, "{SDP_TYPE_PRANSWER_STR}"),
            RTCSdpType::Answer => write!(f, "{SDP_TYPE_ANSWER_STR}"),
            RTCSdpType::Rollback => write!(f, "{SDP_TYPE_ROLLBACK_STR}"),
            _ => write!(f, "{}", UNSPECIFIED_STR),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_sdp_type() {
        let tests = vec![
            ("Unspecified", RTCSdpType::Unspecified),
            ("offer", RTCSdpType::Offer),
            ("pranswer", RTCSdpType::Pranswer),
            ("answer", RTCSdpType::Answer),
            ("rollback", RTCSdpType::Rollback),
        ];

        for (sdp_type_string, expected_sdp_type) in tests {
            assert_eq!(RTCSdpType::from(sdp_type_string), expected_sdp_type);
        }
    }

    #[test]
    fn test_sdp_type_string() {
        let tests = vec![
            (RTCSdpType::Unspecified, "Unspecified"),
            (RTCSdpType::Offer, "offer"),
            (RTCSdpType::Pranswer, "pranswer"),
            (RTCSdpType::Answer, "answer"),
            (RTCSdpType::Rollback, "rollback"),
        ];

        for (sdp_type, expected_string) in tests {
            assert_eq!(sdp_type.to_string(), expected_string);
        }
    }
}
