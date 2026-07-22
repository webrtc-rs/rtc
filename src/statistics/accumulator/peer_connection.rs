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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = PeerConnectionStatsAccumulator::default();
        assert_eq!(acc.data_channels_opened, 0);
        assert_eq!(acc.data_channels_closed, 0);
    }

    #[test]
    fn test_on_data_channel_opened() {
        let mut acc = PeerConnectionStatsAccumulator::default();
        acc.on_data_channel_opened();
        assert_eq!(acc.data_channels_opened, 1);
        assert_eq!(acc.data_channels_closed, 0);

        acc.on_data_channel_opened();
        acc.on_data_channel_opened();
        assert_eq!(acc.data_channels_opened, 3);
    }

    #[test]
    fn test_on_data_channel_closed() {
        let mut acc = PeerConnectionStatsAccumulator::default();
        acc.on_data_channel_closed();
        assert_eq!(acc.data_channels_opened, 0);
        assert_eq!(acc.data_channels_closed, 1);

        acc.on_data_channel_closed();
        assert_eq!(acc.data_channels_closed, 2);
    }

    #[test]
    fn test_open_and_close_sequence() {
        let mut acc = PeerConnectionStatsAccumulator::default();

        // Open 3 channels
        acc.on_data_channel_opened();
        acc.on_data_channel_opened();
        acc.on_data_channel_opened();

        // Close 2 channels
        acc.on_data_channel_closed();
        acc.on_data_channel_closed();

        assert_eq!(acc.data_channels_opened, 3);
        assert_eq!(acc.data_channels_closed, 2);
    }

    #[test]
    fn test_snapshot() {
        let mut acc = PeerConnectionStatsAccumulator::default();
        acc.on_data_channel_opened();
        acc.on_data_channel_opened();
        acc.on_data_channel_closed();

        let now = Instant::now();
        let stats = acc.snapshot(now);

        assert_eq!(stats.stats.id, "RTCPeerConnection");
        assert_eq!(stats.stats.typ, RTCStatsType::PeerConnection);
        assert_eq!(stats.stats.timestamp, now);
        assert_eq!(stats.data_channels_opened, 2);
        assert_eq!(stats.data_channels_closed, 1);
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let mut acc = PeerConnectionStatsAccumulator::default();
        acc.on_data_channel_opened();
        acc.on_data_channel_closed();

        let now = Instant::now();
        let stats = acc.snapshot(now);

        // Verify JSON serialization works
        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"dataChannelsOpened\":1"));
        assert!(json.contains("\"dataChannelsClosed\":1"));
        assert!(json.contains("\"type\":\"peer-connection\""));
    }
}
