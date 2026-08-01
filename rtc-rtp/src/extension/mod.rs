use std::borrow::Cow;
use std::fmt;

use shared::{
    error::Result,
    marshal::{Marshal, MarshalSize},
};

/// Absolute send time, for one-way-delay based bandwidth estimation.
pub mod abs_send_time_extension;
/// Per-packet audio loudness and voice activity ([RFC 6464]).
pub mod audio_level_extension;
/// A requested playout-delay range, for latency/smoothness trade-offs.
pub mod playout_delay_extension;
/// The transport-wide sequence number that TWCC feedback refers to.
pub mod transport_cc_extension;
/// Camera direction and rotation (CVO), so a receiver can display video upright.
pub mod video_orientation_extension;

/// A generic RTP header extension.
#[non_exhaustive]
pub enum HeaderExtension {
    /// The absolute-send-time extension.
    AbsSendTime(abs_send_time_extension::AbsSendTimeExtension),
    /// The audio-level extension.
    AudioLevel(audio_level_extension::AudioLevelExtension),
    /// The playout-delay extension.
    PlayoutDelay(playout_delay_extension::PlayoutDelayExtension),
    /// The transport-wide CC extension.
    TransportCc(transport_cc_extension::TransportCcExtension),
    /// The video-orientation extension.
    VideoOrientation(video_orientation_extension::VideoOrientationExtension),

    /// A custom extension
    Custom {
        /// The extension's canonical URI, which is what SDP negotiates ids against.
        uri: Cow<'static, str>,
        /// The extension value, erased so extensions of different types can be held together.
        extension: Box<dyn Marshal + 'static>,
    },
}

impl HeaderExtension {
    /// The extension's URI.
    pub fn uri(&self) -> Cow<'static, str> {
        use HeaderExtension::*;

        match self {
            AbsSendTime(_) => "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".into(),
            AudioLevel(_) => "urn:ietf:params:rtp-hdrext:ssrc-audio-level".into(),
            PlayoutDelay(_) => "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay".into(),
            TransportCc(_) => {
                "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01".into()
            }
            VideoOrientation(_) => "urn:3gpp:video-orientation".into(),
            Custom { uri, .. } => uri.clone(),
        }
    }

    /// Whether both refer to the same extension, comparing URIs rather than values.
    pub fn is_same(&self, other: &Self) -> bool {
        use HeaderExtension::*;
        match (self, other) {
            (AbsSendTime(_), AbsSendTime(_)) => true,
            (AudioLevel(_), AudioLevel(_)) => true,
            (TransportCc(_), TransportCc(_)) => true,
            (VideoOrientation(_), VideoOrientation(_)) => true,
            (Custom { uri, .. }, Custom { uri: other_uri, .. }) => uri == other_uri,
            _ => false,
        }
    }
}

impl MarshalSize for HeaderExtension {
    fn marshal_size(&self) -> usize {
        use HeaderExtension::*;
        match self {
            AbsSendTime(ext) => ext.marshal_size(),
            AudioLevel(ext) => ext.marshal_size(),
            PlayoutDelay(ext) => ext.marshal_size(),
            TransportCc(ext) => ext.marshal_size(),
            VideoOrientation(ext) => ext.marshal_size(),
            Custom { extension: ext, .. } => ext.marshal_size(),
        }
    }
}

impl Marshal for HeaderExtension {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize> {
        use HeaderExtension::*;
        match self {
            AbsSendTime(ext) => ext.marshal_to(buf),
            AudioLevel(ext) => ext.marshal_to(buf),
            PlayoutDelay(ext) => ext.marshal_to(buf),
            TransportCc(ext) => ext.marshal_to(buf),
            VideoOrientation(ext) => ext.marshal_to(buf),
            Custom { extension: ext, .. } => ext.marshal_to(buf),
        }
    }
}

impl fmt::Debug for HeaderExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use HeaderExtension::*;

        match self {
            AbsSendTime(ext) => f.debug_tuple("AbsSendTime").field(ext).finish(),
            AudioLevel(ext) => f.debug_tuple("AudioLevel").field(ext).finish(),
            PlayoutDelay(ext) => f.debug_tuple("PlayoutDelay").field(ext).finish(),
            TransportCc(ext) => f.debug_tuple("TransportCc").field(ext).finish(),
            VideoOrientation(ext) => f.debug_tuple("VideoOrientation").field(ext).finish(),
            Custom { uri, extension: _ } => f.debug_struct("Custom").field("uri", uri).finish(),
        }
    }
}
