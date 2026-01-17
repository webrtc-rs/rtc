//! Statistics module for WebRTC.
//!
//! This module provides:
//! - `stats` - W3C WebRTC Statistics API types
//! - `report` - Statistics report generation
//!
//! # Stats Selection
//!
//! When calling `get_stats()`, you can optionally provide a [`StatsSelector`]
//! to filter the returned statistics to only those relevant to a specific
//! sender or receiver.
//!
//! # Example
//!
//! ```ignore
//! use rtc::statistics::StatsSelector;
//!
//! // Get all stats
//! let all_stats = pc.get_stats(Instant::now(), StatsSelector::None);
//!
//! // Get stats for a specific sender
//! let sender_stats = pc.get_stats(Instant::now(), StatsSelector::Sender(sender_id));
//! ```

use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};

#[cfg(test)]
mod statistics_tests;

pub(crate) mod accumulator;
pub mod report;
pub mod stats;

/// Selector for filtering statistics in `get_stats()`.
///
/// This enum corresponds to the optional `selector` parameter in the
/// W3C WebRTC `getStats()` method. When provided, it filters the returned
/// statistics to only those relevant to the specified sender or receiver.
///
/// # W3C Reference
///
/// See [The stats selection algorithm](https://www.w3.org/TR/webrtc/#the-stats-selection-algorithm)
///
/// # Variants
///
/// - `None` - Return all statistics for the entire connection
/// - `Sender` - Return statistics for a specific RTP sender and referenced objects
/// - `Receiver` - Return statistics for a specific RTP receiver and referenced objects
pub enum StatsSelector {
    /// Gather stats for the whole connection.
    ///
    /// Returns all available statistics objects including peer connection,
    /// transport, ICE candidates, codecs, data channels, and all RTP streams.
    None,

    /// Gather stats for a specific RTP sender.
    ///
    /// Returns:
    /// - All `RTCOutboundRtpStreamStats` for streams being sent by this sender
    /// - All stats objects referenced by those outbound streams (transport,
    ///   codec, remote inbound stats, etc.)
    Sender(RTCRtpSenderId),

    /// Gather stats for a specific RTP receiver.
    ///
    /// Returns:
    /// - All `RTCInboundRtpStreamStats` for streams being received by this receiver
    /// - All stats objects referenced by those inbound streams (transport,
    ///   codec, remote outbound stats, etc.)
    Receiver(RTCRtpReceiverId),
}
