//! Statistics module for WebRTC.
//!
//! This module provides:
//! - `stats` - W3C WebRTC Statistics API types
//! - `accumulator` - Incremental statistics accumulation
//! - `report` - Statistics report generation

pub mod accumulator;
pub mod report;
pub mod stats;
