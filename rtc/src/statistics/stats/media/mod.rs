//! Media statistics types.
//!
//! This module contains statistics types for media sources and audio playout:
//!
//! - [`audio_playout::RTCAudioPlayoutStats`] - Audio playout device statistics
//! - [`audio_source::RTCAudioSourceStats`] - Audio capture source statistics
//! - [`video_source::RTCVideoSourceStats`] - Video capture source statistics
//! - [`media_source::RTCMediaSourceStats`] - Base media source statistics

pub mod audio_playout;
pub mod audio_source;
pub mod media_source;
pub mod video_source;
