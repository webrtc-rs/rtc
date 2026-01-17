//! Statistics module for WebRTC.
//!
//! This module provides:
//! - `stats` - W3C WebRTC Statistics API types
//! - `report` - Statistics report generation

use crate::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId};

#[cfg(test)]
mod statistics_tests;

pub(crate) mod accumulator;
pub mod report;
pub mod stats;

pub enum StatsSelector {
    None,

    Sender(RTCRtpSenderId),

    Receiver(RTCRtpReceiverId),
}
