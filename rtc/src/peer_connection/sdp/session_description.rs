use std::fmt::Display;
use std::io::Cursor;

use sdp::description::session::SessionDescription;
use serde::{Deserialize, Serialize};

use super::sdp_type::RTCSdpType;
use shared::error::Result;

/// Represents a session description in the SDP offer/answer model.
///
/// `RTCSessionDescription` is used to expose local and remote session descriptions
/// in WebRTC. It contains the SDP (Session Description Protocol) text that describes
/// media capabilities, transport addresses, codecs, and other session parameters.
///
/// # Structure
///
/// The session description consists of:
///
/// - **`sdp_type`**: The type of description ([`RTCSdpType`])
/// - **`sdp`**: The SDP content as a string (text format defined in RFC 8866)
/// - **`parsed`**: Internal cached parsed representation (not serialized)
///
/// # Usage Pattern
///
/// Session descriptions are typically:
///
/// 1. Created using [`offer()`](Self::offer), [`answer()`](Self::answer),
///    or [`pranswer()`](Self::pranswer) constructor methods
/// 2. Serialized to JSON for transmission over the signaling channel
/// 3. Deserialized on the remote peer
/// 4. Applied to the peer connection to establish media
///
/// # Examples
///
/// ## Creating an Offer Description
///
/// ```no_run
/// use rtc::peer_connection::sdp::{RTCSessionDescription, RTCSdpType};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // In a real application, this SDP would come from create_offer()
/// let sdp_text = r#"v=0
/// o=- 123456789 2 IN IP4 127.0.0.1
/// s=-
/// t=0 0
/// m=audio 9 UDP/TLS/RTP/SAVPF 111
/// "#.to_string();
///
/// // Wrap in RTCSessionDescription
/// let offer = RTCSessionDescription::offer(sdp_text)?;
///
/// assert_eq!(offer.sdp_type, RTCSdpType::Offer);
/// println!("Offer ready to send: {}", offer);
/// # Ok(())
/// # }
/// ```
///
/// ## Creating an Answer Description
///
/// ```no_run
/// use rtc::peer_connection::sdp::RTCSessionDescription;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let sdp_text = "v=0\r\no=- 987654321 2 IN IP4 127.0.0.1\r\n...".to_string();
/// let answer = RTCSessionDescription::answer(sdp_text)?;
///
/// println!("Answer SDP type: {}", answer.sdp_type);
/// # Ok(())
/// # }
/// ```
///
/// ## Signaling Exchange via JSON
///
/// ```no_run
/// use rtc::peer_connection::sdp::{RTCSessionDescription, RTCSdpType};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Peer A: Create and serialize offer
/// let offer = RTCSessionDescription::offer("v=0...".to_string())?;
/// let json = serde_json::to_string(&offer)?;
/// // Send json over signaling channel (WebSocket, HTTP, etc.)
///
/// // Peer B: Receive and deserialize offer
/// let received_offer: RTCSessionDescription = serde_json::from_str(&json)?;
/// assert_eq!(received_offer.sdp_type, RTCSdpType::Offer);
///
/// // Peer B: Create answer (after set_remote_description and create_answer)
/// let answer = RTCSessionDescription::answer("v=0...".to_string())?;
/// let answer_json = serde_json::to_string(&answer)?;
/// // Send answer_json back to Peer A
/// # Ok(())
/// # }
/// ```
///
/// ## Parsing SDP Content
///
/// ```no_run
/// use rtc::peer_connection::sdp::RTCSessionDescription;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let description = RTCSessionDescription::offer("v=0\r\no=- 123 456 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n".to_string())?;
///
/// // Access the parsed SDP structure
/// let parsed = description.unmarshal()?;
/// println!("Session version: {}", parsed.version);
/// println!("Session name: {}", parsed.session_name);
/// println!("Media sections: {}", parsed.media_descriptions.len());
/// # Ok(())
/// # }
/// ```
///
/// ## Using Provisional Answers
///
/// ```no_run
/// use rtc::peer_connection::sdp::RTCSessionDescription;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Send a provisional answer with limited codecs
/// let sdp_text = "v=0\r\no=- 111 222 IN IP4 0.0.0.0\r\n...".to_string();
/// let pranswer = RTCSessionDescription::pranswer(sdp_text.clone())?;
///
/// // Later, send final answer with all negotiated parameters
/// let final_answer = RTCSessionDescription::answer(sdp_text)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Displaying SDP for Debugging
///
/// ```no_run
/// use rtc::peer_connection::sdp::RTCSessionDescription;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let offer = RTCSessionDescription::offer("v=0\r\no=- 123 456 IN IP4 0.0.0.0\r\ns=-\r\n".to_string())?;
///
/// // Display formats SDP with CRLF converted to LF for readability
/// println!("{}", offer);
/// // Output: type: offer, sdp:
/// // v=0
/// // o=- 123 456 IN IP4 0.0.0.0
/// // s=-
/// # Ok(())
/// # }
/// ```
///
/// # Specifications
///
/// - [W3C RTCSessionDescription]
/// - [MDN RTCSessionDescription]
/// - [RFC 8866] - SDP: Session Description Protocol
/// - [RFC 3264] - Offer/Answer Model with SDP
///
/// [W3C RTCSessionDescription]: https://w3c.github.io/webrtc-pc/#rtcsessiondescription-class
/// [MDN RTCSessionDescription]: https://developer.mozilla.org/en-US/docs/Web/API/RTCSessionDescription
/// [RFC 8866]: https://datatracker.ietf.org/doc/html/rfc8866
/// [RFC 3264]: https://datatracker.ietf.org/doc/html/rfc3264
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RTCSessionDescription {
    /// The type of this session description (offer, answer, pranswer, or rollback).
    #[serde(rename = "type")]
    pub sdp_type: RTCSdpType,

    /// The SDP content as a string.
    ///
    /// This is the raw SDP text conforming to RFC 8866 format. It contains
    /// session-level and media-level descriptions including codecs, transport
    /// addresses, ICE candidates, and DTLS fingerprints.
    pub sdp: String,

    /// Internal cached parsed SDP structure.
    ///
    /// This field is never initialized by callers and is used internally for
    /// performance optimization. It is not included in JSON serialization.
    #[serde(skip)]
    pub(crate) parsed: Option<SessionDescription>,
}

impl Display for RTCSessionDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "type: {}, sdp:\n{}",
            self.sdp_type,
            self.sdp.replace("\r\n", "\n")
        )
    }
}

impl RTCSessionDescription {
    /// Creates an answer session description from SDP text.
    ///
    /// This constructor validates and parses the SDP, wrapping it in an
    /// `RTCSessionDescription` with type [`RTCSdpType::Answer`]. Use this
    /// when creating the final response to an offer.
    ///
    /// # Parameters
    ///
    /// - `sdp`: The SDP content as a string (RFC 8866 format)
    ///
    /// # Returns
    ///
    /// Returns `Ok(RTCSessionDescription)` if the SDP is valid, or `Err` if
    /// parsing fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtc::peer_connection::sdp::{RTCSessionDescription, RTCSdpType};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Typically this SDP comes from create_answer()
    /// let sdp = r#"v=0
    /// o=- 987654321 2 IN IP4 192.168.1.100
    /// s=-
    /// t=0 0
    /// m=audio 9 UDP/TLS/RTP/SAVPF 111
    /// "#.to_string();
    ///
    /// let answer = RTCSessionDescription::answer(sdp)?;
    /// assert_eq!(answer.sdp_type, RTCSdpType::Answer);
    ///
    /// // The SDP is automatically validated and parsed (internally)
    /// // Access parsed structure with unmarshal()
    /// let parsed = answer.unmarshal()?;
    /// println!("Answer has {} media section(s)", parsed.media_descriptions.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn answer(sdp: String) -> Result<RTCSessionDescription> {
        let mut desc = RTCSessionDescription {
            sdp,
            sdp_type: RTCSdpType::Answer,
            parsed: None,
        };

        let parsed = desc.unmarshal()?;
        desc.parsed = Some(parsed);

        Ok(desc)
    }

    /// Creates an offer session description from SDP text.
    ///
    /// This constructor validates and parses the SDP, wrapping it in an
    /// `RTCSessionDescription` with type [`RTCSdpType::Offer`]. Use this
    /// when creating the initial offer to start negotiation.
    ///
    /// # Parameters
    ///
    /// - `sdp`: The SDP content as a string (RFC 8866 format)
    ///
    /// # Returns
    ///
    /// Returns `Ok(RTCSessionDescription)` if the SDP is valid, or `Err` if
    /// parsing fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtc::peer_connection::sdp::{RTCSessionDescription, RTCSdpType};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Typically this SDP comes from create_offer()
    /// let sdp = r#"v=0
    /// o=- 123456789 2 IN IP4 192.168.1.1
    /// s=-
    /// t=0 0
    /// m=video 9 UDP/TLS/RTP/SAVPF 96
    /// "#.to_string();
    ///
    /// let offer = RTCSessionDescription::offer(sdp)?;
    /// assert_eq!(offer.sdp_type, RTCSdpType::Offer);
    ///
    /// // Parsed structure is available immediately
    /// let parsed = offer.unmarshal()?;
    /// println!("Offer has {} media section(s)", parsed.media_descriptions.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn offer(sdp: String) -> Result<RTCSessionDescription> {
        let mut desc = RTCSessionDescription {
            sdp,
            sdp_type: RTCSdpType::Offer,
            parsed: None,
        };

        let parsed = desc.unmarshal()?;
        desc.parsed = Some(parsed);

        Ok(desc)
    }

    /// Creates a provisional answer session description from SDP text.
    ///
    /// This constructor validates and parses the SDP, wrapping it in an
    /// `RTCSessionDescription` with type [`RTCSdpType::Pranswer`]. Use this
    /// when you want to send a preliminary answer before the final answer,
    /// allowing early media to flow.
    ///
    /// # Parameters
    ///
    /// - `sdp`: The SDP content as a string (RFC 8866 format)
    ///
    /// # Returns
    ///
    /// Returns `Ok(RTCSessionDescription)` if the SDP is valid, or `Err` if
    /// parsing fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtc::peer_connection::sdp::{RTCSessionDescription, RTCSdpType};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Send provisional answer with a subset of codecs
    /// let early_sdp = r#"v=0
    /// o=- 555555555 2 IN IP4 192.168.1.50
    /// s=-
    /// t=0 0
    /// m=audio 9 UDP/TLS/RTP/SAVPF 0
    /// "#.to_string();
    ///
    /// let pranswer = RTCSessionDescription::pranswer(early_sdp)?;
    /// assert_eq!(pranswer.sdp_type, RTCSdpType::Pranswer);
    ///
    /// // Later, send final answer with all negotiated parameters
    /// // let final_answer = RTCSessionDescription::answer(final_sdp)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// Provisional answers are less commonly used in modern WebRTC. Consider
    /// whether sending a final answer immediately is more appropriate for your
    /// use case.
    pub fn pranswer(sdp: String) -> Result<RTCSessionDescription> {
        let mut desc = RTCSessionDescription {
            sdp,
            sdp_type: RTCSdpType::Pranswer,
            parsed: None,
        };

        let parsed = desc.unmarshal()?;
        desc.parsed = Some(parsed);

        Ok(desc)
    }

    /// Parses the SDP text into a structured format.
    ///
    /// This method deserializes the SDP string into a parsed
    /// [`SessionDescription`](sdp::description::session::SessionDescription)
    /// structure that provides programmatic access to session and media
    /// attributes. The parsed structure is also cached internally for
    /// performance.
    ///
    /// # Returns
    ///
    /// Returns `Ok(SessionDescription)` containing the parsed SDP structure,
    /// or `Err` if the SDP is malformed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rtc::peer_connection::sdp::RTCSessionDescription;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let offer = RTCSessionDescription::offer(
    ///     "v=0\r\no=- 123 456 IN IP4 0.0.0.0\r\ns=WebRTC Session\r\nt=0 0\r\n".to_string()
    /// )?;
    ///
    /// // Parse SDP to access structure
    /// let parsed = offer.unmarshal()?;
    /// println!("SDP version: {}", parsed.version);
    /// println!("Session name: {}", parsed.session_name);
    /// println!("Number of media sections: {}", parsed.media_descriptions.len());
    ///
    /// // Can be called multiple times (returns same result)
    /// let parsed_again = offer.unmarshal()?;
    /// assert_eq!(parsed.version, parsed_again.version);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Performance
    ///
    /// This method parses the SDP each time it's called. For repeated access,
    /// consider caching the result.
    pub fn unmarshal(&self) -> Result<SessionDescription> {
        let mut reader = Cursor::new(self.sdp.as_bytes());
        let parsed = SessionDescription::unmarshal(&mut reader)?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    //TODO:use crate::api::media_engine::MediaEngine;
    //TODO:use crate::api::APIBuilder;
    //TODO:use crate::peer_connection::configuration::RTCConfiguration;

    #[test]
    fn test_session_description_json() {
        let tests = vec![
            (
                RTCSessionDescription {
                    sdp_type: RTCSdpType::Offer,
                    sdp: "sdp".to_owned(),
                    parsed: None,
                },
                r#"{"type":"offer","sdp":"sdp"}"#,
            ),
            (
                RTCSessionDescription {
                    sdp_type: RTCSdpType::Pranswer,
                    sdp: "sdp".to_owned(),
                    parsed: None,
                },
                r#"{"type":"pranswer","sdp":"sdp"}"#,
            ),
            (
                RTCSessionDescription {
                    sdp_type: RTCSdpType::Answer,
                    sdp: "sdp".to_owned(),
                    parsed: None,
                },
                r#"{"type":"answer","sdp":"sdp"}"#,
            ),
            (
                RTCSessionDescription {
                    sdp_type: RTCSdpType::Rollback,
                    sdp: "sdp".to_owned(),
                    parsed: None,
                },
                r#"{"type":"rollback","sdp":"sdp"}"#,
            ),
            (
                RTCSessionDescription {
                    sdp_type: RTCSdpType::Unspecified,
                    sdp: "sdp".to_owned(),
                    parsed: None,
                },
                r#"{"type":"Unspecified","sdp":"sdp"}"#,
            ),
        ];

        for (desc, expected_string) in tests {
            let result = serde_json::to_string(&desc);
            assert!(result.is_ok(), "testCase: marshal err: {result:?}");
            let desc_data = result.unwrap();
            assert_eq!(desc_data, expected_string, "string is not expected");

            let result = serde_json::from_str::<RTCSessionDescription>(&desc_data);
            assert!(result.is_ok(), "testCase: unmarshal err: {result:?}");
            if let Ok(sd) = result {
                assert!(sd.sdp == desc.sdp && sd.sdp_type == desc.sdp_type);
            }
        }
    }

    /*TODO:
    #[tokio::test]
    async fn test_session_description_answer() -> Result<()> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let api = APIBuilder::new().with_media_engine(m).build();

        let offer_pc = api.new_peer_connection(RTCConfiguration::default()).await?;
        let answer_pc = api.new_peer_connection(RTCConfiguration::default()).await?;

        let _ = offer_pc.create_data_channel("foo", None).await?;
        let offer = offer_pc.create_offer(None).await?;
        answer_pc.set_remote_description(offer).await?;

        let answer = answer_pc.create_answer(None).await?;

        let desc = RTCSessionDescription::answer(answer.sdp.clone())?;

        assert!(desc.sdp_type == RTCSdpType::Answer);
        assert!(desc.parsed.is_some());

        assert_eq!(answer.unmarshal()?.marshal(), desc.unmarshal()?.marshal());

        Ok(())
    }

    #[tokio::test]
    async fn test_session_description_offer() -> Result<()> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let api = APIBuilder::new().with_media_engine(m).build();

        let pc = api.new_peer_connection(RTCConfiguration::default()).await?;
        let offer = pc.create_offer(None).await?;

        let desc = RTCSessionDescription::offer(offer.sdp.clone())?;

        assert!(desc.sdp_type == RTCSdpType::Offer);
        assert!(desc.parsed.is_some());

        assert_eq!(offer.unmarshal()?.marshal(), desc.unmarshal()?.marshal());

        Ok(())
    }

    #[tokio::test]
    async fn test_session_description_pranswer() -> Result<()> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let api = APIBuilder::new().with_media_engine(m).build();

        let offer_pc = api.new_peer_connection(RTCConfiguration::default()).await?;
        let answer_pc = api.new_peer_connection(RTCConfiguration::default()).await?;

        let _ = offer_pc.create_data_channel("foo", None).await?;
        let offer = offer_pc.create_offer(None).await?;
        answer_pc.set_remote_description(offer).await?;

        let answer = answer_pc.create_answer(None).await?;

        let desc = RTCSessionDescription::pranswer(answer.sdp)?;

        assert!(desc.sdp_type == RTCSdpType::Pranswer);
        assert!(desc.parsed.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_session_description_unmarshal() -> Result<()> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let api = APIBuilder::new().with_media_engine(m).build();

        let pc = api.new_peer_connection(RTCConfiguration::default()).await?;

        let offer = pc.create_offer(None).await?;

        let desc = RTCSessionDescription {
            sdp_type: offer.sdp_type,
            sdp: offer.sdp,
            ..Default::default()
        };

        assert!(desc.parsed.is_none());

        let parsed1 = desc.unmarshal()?;
        let parsed2 = desc.unmarshal()?;

        pc.close().await?;

        // check if the two parsed results _really_ match, could be affected by internal caching
        assert_eq!(parsed1.marshal(), parsed2.marshal());

        Ok(())
    }*/
}
