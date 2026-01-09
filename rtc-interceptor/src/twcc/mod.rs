//! TWCC (Transport Wide Congestion Control) Interceptors
//!
//! This module provides interceptors for Transport Wide Congestion Control
//! as specified in:
//! <https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01>
//!
//! - [`TwccSenderInterceptor`]: Adds transport-wide sequence numbers to outgoing RTP packets.
//! - [`TwccReceiverInterceptor`]: Tracks incoming RTP packets and generates TWCC feedback.
//!
//! # Example
//!
//! ```ignore
//! use rtc_interceptor::{Registry, TwccSenderBuilder, TwccReceiverBuilder};
//! use std::time::Duration;
//!
//! let chain = Registry::new()
//!     .with(TwccSenderBuilder::new().build())
//!     .with(TwccReceiverBuilder::new()
//!         .with_interval(Duration::from_millis(100))
//!         .build())
//!     .build();
//! ```

mod arrival_time_map;
pub mod receiver;
mod recorder;
pub mod sender;

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
