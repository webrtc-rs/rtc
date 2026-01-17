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
