//! Statistics module for WebRTC.
//!
//! This module provides:
//! - `stats` - W3C WebRTC Statistics API types
//! - `accumulator` - Incremental statistics accumulation (internal)
//! - `report` - Statistics report generation

pub(crate) mod accumulator;
pub mod report;
pub mod stats;

#[cfg(test)]
mod statistics_tests;
