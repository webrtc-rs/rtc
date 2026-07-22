//! Data channel statistics accumulator.

use crate::data_channel::RTCDataChannelState;
use crate::statistics::stats::data_channel::RTCDataChannelStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated data channel statistics.
///
/// This struct tracks message/byte counters and state for a data channel.
#[derive(Debug, Default)]
pub struct DataChannelStatsAccumulator {
    /// The data channel identifier.
    pub data_channel_identifier: u16,
    /// The label assigned to the data channel.
    pub label: String,
    /// The sub-protocol name.
    pub protocol: String,
    /// The current state of the data channel.
    pub state: RTCDataChannelState,

    // Message/byte counters
    /// Total messages sent through the data channel.
    pub messages_sent: u32,
    /// Total bytes sent through the data channel.
    pub bytes_sent: u64,
    /// Total messages received through the data channel.
    pub messages_received: u32,
    /// Total bytes received through the data channel.
    pub bytes_received: u64,
}

impl DataChannelStatsAccumulator {
    /// Called when a message is sent through the data channel.
    pub fn on_message_sent(&mut self, bytes: usize) {
        self.messages_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Called when a message is received through the data channel.
    pub fn on_message_received(&mut self, bytes: usize) {
        self.messages_received += 1;
        self.bytes_received += bytes as u64;
    }

    /// Called when the data channel state changes.
    pub fn on_state_changed(&mut self, state: RTCDataChannelState) {
        self.state = state;
    }

    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: String) -> RTCDataChannelStats {
        RTCDataChannelStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::DataChannel,
                id,
            },
            data_channel_identifier: self.data_channel_identifier,
            label: self.label.clone(),
            protocol: self.protocol.clone(),
            state: self.state,
            messages_sent: self.messages_sent,
            bytes_sent: self.bytes_sent,
            messages_received: self.messages_received,
            bytes_received: self.bytes_received,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = DataChannelStatsAccumulator::default();
        assert_eq!(acc.data_channel_identifier, 0);
        assert_eq!(acc.label, "");
        assert_eq!(acc.protocol, "");
        assert_eq!(acc.state, RTCDataChannelState::default());
        assert_eq!(acc.messages_sent, 0);
        assert_eq!(acc.bytes_sent, 0);
        assert_eq!(acc.messages_received, 0);
        assert_eq!(acc.bytes_received, 0);
    }

    #[test]
    fn test_on_message_sent() {
        let mut acc = DataChannelStatsAccumulator::default();

        acc.on_message_sent(100);
        assert_eq!(acc.messages_sent, 1);
        assert_eq!(acc.bytes_sent, 100);

        acc.on_message_sent(200);
        assert_eq!(acc.messages_sent, 2);
        assert_eq!(acc.bytes_sent, 300);
    }

    #[test]
    fn test_on_message_received() {
        let mut acc = DataChannelStatsAccumulator::default();

        acc.on_message_received(50);
        assert_eq!(acc.messages_received, 1);
        assert_eq!(acc.bytes_received, 50);

        acc.on_message_received(150);
        assert_eq!(acc.messages_received, 2);
        assert_eq!(acc.bytes_received, 200);
    }

    #[test]
    fn test_on_state_changed() {
        let mut acc = DataChannelStatsAccumulator::default();

        acc.on_state_changed(RTCDataChannelState::Connecting);
        assert_eq!(acc.state, RTCDataChannelState::Connecting);

        acc.on_state_changed(RTCDataChannelState::Open);
        assert_eq!(acc.state, RTCDataChannelState::Open);

        acc.on_state_changed(RTCDataChannelState::Closing);
        assert_eq!(acc.state, RTCDataChannelState::Closing);

        acc.on_state_changed(RTCDataChannelState::Closed);
        assert_eq!(acc.state, RTCDataChannelState::Closed);
    }

    #[test]
    fn test_bidirectional_traffic() {
        let mut acc = DataChannelStatsAccumulator::default();

        // Simulate bidirectional traffic
        acc.on_message_sent(100);
        acc.on_message_received(50);
        acc.on_message_sent(200);
        acc.on_message_received(150);
        acc.on_message_sent(300);

        assert_eq!(acc.messages_sent, 3);
        assert_eq!(acc.bytes_sent, 600);
        assert_eq!(acc.messages_received, 2);
        assert_eq!(acc.bytes_received, 200);
    }

    #[test]
    fn test_snapshot() {
        let mut acc = DataChannelStatsAccumulator {
            data_channel_identifier: 42,
            label: "test-channel".to_string(),
            protocol: "json".to_string(),
            state: RTCDataChannelState::Open,
            ..Default::default()
        };

        acc.on_message_sent(100);
        acc.on_message_received(50);

        let now = Instant::now();
        let stats = acc.snapshot(now, "RTCDataChannel_42".to_string());

        assert_eq!(stats.stats.id, "RTCDataChannel_42");
        assert_eq!(stats.stats.typ, RTCStatsType::DataChannel);
        assert_eq!(stats.stats.timestamp, now);
        assert_eq!(stats.data_channel_identifier, 42);
        assert_eq!(stats.label, "test-channel");
        assert_eq!(stats.protocol, "json");
        assert_eq!(stats.state, RTCDataChannelState::Open);
        assert_eq!(stats.messages_sent, 1);
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.messages_received, 1);
        assert_eq!(stats.bytes_received, 50);
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let mut acc = DataChannelStatsAccumulator {
            data_channel_identifier: 1,
            label: "my-channel".to_string(),
            protocol: "".to_string(),
            state: RTCDataChannelState::Open,
            ..Default::default()
        };

        acc.on_message_sent(256);
        acc.on_message_received(128);

        let now = Instant::now();
        let stats = acc.snapshot(now, "RTCDataChannel_1".to_string());

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"dataChannelIdentifier\":1"));
        assert!(json.contains("\"label\":\"my-channel\""));
        assert!(json.contains("\"messagesSent\":1"));
        assert!(json.contains("\"bytesSent\":256"));
        assert!(json.contains("\"messagesReceived\":1"));
        assert!(json.contains("\"bytesReceived\":128"));
        assert!(json.contains("\"type\":\"data-channel\""));
    }
}
