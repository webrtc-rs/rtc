//! Peer connection statistics accumulator.

use crate::statistics::stats::peer_connection::RTCPeerConnectionStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated peer connection level statistics.
///
/// This struct tracks aggregate stats for the peer connection, such as
/// the number of data channels opened and closed.
#[derive(Debug, Default)]
pub struct PeerConnectionStatsAccumulator {
    /// Total number of data channels opened.
    pub data_channels_opened: u32,
    /// Total number of data channels closed.
    pub data_channels_closed: u32,
}

impl PeerConnectionStatsAccumulator {
    /// Called when a data channel is opened.
    pub fn on_data_channel_opened(&mut self) {
        self.data_channels_opened += 1;
    }

    /// Called when a data channel is closed.
    pub fn on_data_channel_closed(&mut self) {
        self.data_channels_closed += 1;
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant) -> RTCPeerConnectionStats {
        RTCPeerConnectionStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::PeerConnection,
                id: "RTCPeerConnection".to_string(),
            },
            data_channels_opened: self.data_channels_opened,
            data_channels_closed: self.data_channels_closed,
        }
    }
}
