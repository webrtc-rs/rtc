//! TWCC (Transport Wide Congestion Control) Interceptors.
//!
//! This module provides interceptors for Transport Wide Congestion Control,
//! a bandwidth estimation mechanism that provides detailed per-packet feedback.
//!
//! # Interceptors
//!
//! - [`TwccSenderInterceptor`]: Adds transport-wide sequence numbers to outgoing RTP packets.
//! - [`TwccReceiverInterceptor`]: Tracks incoming RTP packets and generates TransportLayerCC feedback.
//!
//! # How TWCC Works
//!
//! 1. **Sender**: Adds a transport-wide sequence number to each RTP packet via header extension
//! 2. **Receiver**: Records arrival time of each packet by sequence number
//! 3. **Feedback**: Receiver periodically sends TransportLayerCC RTCP packets with arrival info
//! 4. **Estimation**: Sender uses feedback to estimate available bandwidth
//!
//! # Sequence Number Sharing
//!
//! Unlike per-stream RTP sequence numbers, TWCC sequence numbers are shared across
//! all streams in a session. This allows the sender to correlate feedback across
//! multiple media tracks for more accurate bandwidth estimation.
//!
//! # TWCC Support Detection
//!
//! Interceptors detect TWCC support by checking [`StreamInfo::rtp_header_extensions`](crate::StreamInfo::rtp_header_extensions)
//! for the TWCC header extension URI. Streams without the extension are passed through
//! without modification.
//!
//! # References
//!
//! - [draft-holmer-rmcat-transport-wide-cc-extensions-01](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01) - RTP Extensions for Transport-wide Congestion Control
//!
//! # Example
//!
//! ```ignore
//! use rtc_interceptor::{Registry, TwccSenderBuilder, TwccReceiverBuilder};
//! use std::time::Duration;
//!
//! let chain = Registry::new()
//!     // Sender: adds TWCC sequence numbers to outgoing packets
//!     .with(TwccSenderBuilder::new().build())
//!     // Receiver: generates TWCC feedback for incoming packets
//!     .with(TwccReceiverBuilder::new()
//!         .with_interval(Duration::from_millis(100))  // Feedback interval
//!         .build())
//!     .build();
//! ```
//!
//! # Stream Configuration
//!
//! To enable TWCC for a stream, include the header extension in [`StreamInfo`](crate::StreamInfo):
//!
//! ```ignore
//! use rtc_interceptor::{StreamInfo, RTPHeaderExtension};
//!
//! let stream_info = StreamInfo {
//!     ssrc: 0x12345678,
//!     rtp_header_extensions: vec![RTPHeaderExtension {
//!         uri: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01".to_string(),
//!         id: 5,  // Extension ID negotiated via SDP
//!     }],
//!     ..Default::default()
//! };
//! ```

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
