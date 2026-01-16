//! MediaStreamTrack State
//!
//! This module defines the lifecycle state of a [`MediaStreamTrack`](super::MediaStreamTrack).
//!
//! # Specification
//!
//! See [MediaStreamTrack.readyState](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-readystate).

use crate::peer_connection::configuration::UNSPECIFIED_STR;
use std::fmt;

/// Represents the lifecycle state of a media stream track.
///
/// A track progresses through these states during its lifetime. Once a track
/// reaches the "ended" state, it cannot return to "live" state.
///
/// # Specification
///
/// See [MediaStreamTrackState](https://www.w3.org/TR/mediacapture-streams/#idl-def-mediastreamtrackstate)
/// in the W3C Media Capture and Streams specification.
///
/// # Examples
///
/// ```
/// use rtc::media_stream::MediaStreamTrackState;
///
/// let state = MediaStreamTrackState::Live;
/// assert_eq!(state.to_string(), "live");
///
/// let state = MediaStreamTrackState::Ended;
/// assert_eq!(state.to_string(), "ended");
/// ```
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MediaStreamTrackState {
    /// Unspecified or unknown state.
    Unspecified,

    /// The track is active and providing media data.
    ///
    /// A live track can produce media frames or samples. This is the initial
    /// state of a track when it's created.
    ///
    /// # Specification
    ///
    /// See [live state](https://www.w3.org/TR/mediacapture-streams/#idl-def-mediastreamtrackstate-live).
    #[default]
    Live,

    /// The track has permanently ended.
    ///
    /// An ended track no longer provides media data and cannot be restarted.
    /// This state is reached when:
    /// - [`stop()`](super::track::MediaStreamTrack::stop) is called
    /// - The media source is disconnected or removed
    /// - The user agent decides to end the track
    ///
    /// # Specification
    ///
    /// See [ended state](https://www.w3.org/TR/mediacapture-streams/#idl-def-mediastreamtrackstate-ended).
    Ended,
}

const MEDIA_STREAM_TRACK_STATE_LIVE_STR: &str = "live";
const MEDIA_STREAM_TRACK_STATE_ENDED_STR: &str = "ended";

impl From<&str> for MediaStreamTrackState {
    fn from(raw: &str) -> Self {
        match raw {
            MEDIA_STREAM_TRACK_STATE_LIVE_STR => MediaStreamTrackState::Live,
            MEDIA_STREAM_TRACK_STATE_ENDED_STR => MediaStreamTrackState::Ended,
            _ => MediaStreamTrackState::Unspecified,
        }
    }
}

impl fmt::Display for MediaStreamTrackState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            MediaStreamTrackState::Live => MEDIA_STREAM_TRACK_STATE_LIVE_STR,
            MediaStreamTrackState::Ended => MEDIA_STREAM_TRACK_STATE_ENDED_STR,
            MediaStreamTrackState::Unspecified => UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}
