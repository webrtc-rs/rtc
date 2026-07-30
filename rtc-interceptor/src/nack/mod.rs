//! NACK interceptors (internal module).
//!
//! `NackGeneratorInterceptor` and `NackResponderInterceptor` are re-exported from the crate
//! root, where the user-facing documentation and examples live so that rustdoc renders them.
//!
//! # References
//!
//! - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - RTP/AVPF (NACK feedback)
//! - [RFC 4588](https://datatracker.ietf.org/doc/html/rfc4588) - RTP Retransmission (RTX)
pub(crate) mod generator;
pub(crate) mod receive_log;
pub(crate) mod responder;
pub(crate) mod send_buffer;

use crate::stream_info::StreamInfo;

/// Check if a stream supports NACK feedback.
///
/// Returns `true` if the stream has an RTCPFeedback entry with `type: "nack"`
/// and empty `parameter`.
pub(crate) fn stream_supports_nack(info: &StreamInfo) -> bool {
    info.rtcp_feedback
        .iter()
        .any(|fb| fb.typ == "nack" && fb.parameter.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::RTCPFeedback;

    #[test]
    fn test_stream_supports_nack() {
        // Stream with nack support
        let info_with_nack = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        assert!(stream_supports_nack(&info_with_nack));

        // Stream with nack-pli (not generic nack)
        let info_with_nack_pli = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "pli".to_string(),
            }],
            ..Default::default()
        };
        assert!(!stream_supports_nack(&info_with_nack_pli));

        // Stream without nack
        let info_without_nack = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "goog-remb".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        assert!(!stream_supports_nack(&info_without_nack));

        // Stream with no feedback
        let info_no_feedback = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![],
            ..Default::default()
        };
        assert!(!stream_supports_nack(&info_no_feedback));
    }
}
