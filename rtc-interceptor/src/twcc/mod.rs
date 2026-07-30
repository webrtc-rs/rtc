//! TWCC interceptors (internal module).
//!
//! `TwccSenderInterceptor` and `TwccReceiverInterceptor` are re-exported from the crate root,
//! where the user-facing documentation and examples live so that rustdoc renders them.
//!
//! # References
//!
//! - [draft-holmer-rmcat-transport-wide-cc-extensions-01](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01)
//!   - RTP Extensions for Transport-wide Congestion Control
pub(crate) mod arrival_time_map;
pub(crate) mod receiver;
pub(crate) mod recorder;
pub(crate) mod sender;

use crate::stream_info::StreamInfo;

/// The URI for the transport-wide CC RTP header extension.
pub const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

/// Check if a stream supports transport-wide CC based on its header extensions.
pub(crate) fn stream_supports_twcc(info: &StreamInfo) -> Option<u8> {
    info.rtp_header_extensions
        .iter()
        .find(|ext| ext.uri == TRANSPORT_CC_URI)
        .map(|ext| ext.id as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::RTPHeaderExtension;

    #[test]
    fn test_stream_supports_twcc() {
        // Stream with TWCC support
        let info = StreamInfo {
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: TRANSPORT_CC_URI.to_string(),
                id: 5,
            }],
            ..Default::default()
        };
        assert_eq!(stream_supports_twcc(&info), Some(5));

        // Stream without TWCC support
        let info = StreamInfo {
            rtp_header_extensions: vec![],
            ..Default::default()
        };
        assert_eq!(stream_supports_twcc(&info), None);

        // Stream with other extensions but not TWCC
        let info = StreamInfo {
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
                id: 1,
            }],
            ..Default::default()
        };
        assert_eq!(stream_supports_twcc(&info), None);
    }
}
