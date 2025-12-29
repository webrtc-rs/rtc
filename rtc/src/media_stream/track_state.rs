use std::fmt;

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MediaStreamTrackState {
    Unspecified,
    #[default]
    Live,
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
            MediaStreamTrackState::Unspecified => {
                crate::peer_connection::configuration::UNSPECIFIED_STR
            }
        };
        write!(f, "{s}")
    }
}
