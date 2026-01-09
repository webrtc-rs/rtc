//! NACK (Negative Acknowledgement) Interceptors.
//!
//! This module provides interceptors for handling RTCP NACK-based packet loss recovery
//! as specified in RFC 4585 (Extended RTP Profile for RTCP-Based Feedback).
//!
//! # Interceptors
//!
//! - [`NackGeneratorInterceptor`]: Monitors incoming RTP packets and generates
//!   NACK requests for missing packets.
//! - [`NackResponderInterceptor`]: Buffers outgoing RTP packets and retransmits
//!   them when NACK requests are received.
//!
//! # How NACK Works
//!
//! 1. **Detection**: The receiver detects missing packets by tracking sequence numbers
//! 2. **Request**: The receiver sends an RTCP NACK packet listing missing sequence numbers
//! 3. **Retransmission**: The sender retransmits the requested packets
//!
//! # RTX Support (RFC 4588)
//!
//! The responder supports RFC 4588 RTX (Retransmission) format, which uses a separate
//! SSRC and payload type for retransmissions. This allows the receiver to distinguish
//! between original and retransmitted packets. RTX is enabled by setting `ssrc_rtx`
//! and `payload_type_rtx` in [`StreamInfo`](crate::StreamInfo).
//!
//! # NACK Support Detection
//!
//! Both interceptors check if a stream supports NACK by looking for an [`RTCPFeedback`](crate::RTCPFeedback)
//! entry with `type: "nack"` and empty `parameter`. Streams without NACK support
//! are passed through without modification.
//!
//! # References
//!
//! - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - Extended RTP Profile for RTCP-Based Feedback (RTP/AVPF)
//! - [RFC 4588](https://datatracker.ietf.org/doc/html/rfc4588) - RTP Retransmission Payload Format
//!
//! # Example
//!
//! ```ignore
//! use rtc_interceptor::{Registry, NackGeneratorBuilder, NackResponderBuilder};
//! use std::time::Duration;
//!
//! let chain = Registry::new()
//!     // Generator for incoming streams (detects loss, sends NACKs)
//!     .with(NackGeneratorBuilder::new()
//!         .with_size(512)           // Buffer size for tracking
//!         .with_interval(Duration::from_millis(100))  // NACK generation interval
//!         .with_skip_last_n(2)      // Skip recent packets (may just be delayed)
//!         .build())
//!     // Responder for outgoing streams (buffers packets, handles NACKs)
//!     .with(NackResponderBuilder::new()
//!         .with_size(1024)          // Buffer size for retransmission
//!         .build())
//!     .build();
//! ```

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
