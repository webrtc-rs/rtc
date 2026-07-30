//! `a=extmap` RTP header-extension declarations.
//!
//! An [`ExtMap`](crate::extmap::ExtMap) binds a header-extension URI to the small integer id that will appear in RTP
//! packets. Both sides must agree, which is the whole point of negotiating it in SDP: the id is
//! per-session, while the URI is the stable name.
//!
//! The `*_URI` constants are the extensions this stack uses — audio level, video orientation,
//! absolute send time, transport-wide CC, and the SDES ids that make simulcast demultiplexing
//! possible.
#[cfg(test)]
mod extmap_test;

use super::direction::*;
use crate::description::common::*;
use shared::error::{Error, Result};

use std::fmt;
use std::io;
use url::Url;

/// Default ext values
pub const DEF_EXT_MAP_VALUE_ABS_SEND_TIME: usize = 1;
/// The default id this crate assigns to the transport-wide CC extension.
pub const DEF_EXT_MAP_VALUE_TRANSPORT_CC: usize = 2;
/// The default id assigned to the SDES `mid` extension.
pub const DEF_EXT_MAP_VALUE_SDES_MID: usize = 3;
/// The default id assigned to the SDES RTP stream id extension.
pub const DEF_EXT_MAP_VALUE_SDES_RTP_STREAM_ID: usize = 4;

/// The absolute-send-time extension URI, used for bandwidth estimation.
pub const ABS_SEND_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
/// The transport-wide congestion control extension URI.
pub const TRANSPORT_CC_URI: &str =
    "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";
/// The SDES `mid` extension URI, which tags each packet with its m-line.
pub const SDES_MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";
/// The SDES RTP stream id (RID) extension URI, which identifies a simulcast layer.
pub const SDES_RTP_STREAM_ID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id";
/// The SDES repaired RTP stream id extension URI, which identifies an RTX layer's target.
pub const SDES_REPAIR_RTP_STREAM_ID_URI: &str =
    "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id";

/// The audio-level extension URI, carrying per-packet loudness.
pub const AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:ssrc-audio-level";
/// The video-orientation (CVO) extension URI, carrying rotation flags.
pub const VIDEO_ORIENTATION_URI: &str = "urn:3gpp:video-orientation";

/// ExtMap represents the activation of a single RTP header extension
#[derive(Debug, Clone, Default)]
pub struct ExtMap {
    /// The id this extension is negotiated under, as it appears in RTP packets.
    pub value: u16,
    /// The direction the extension applies in, if the attribute restricted it.
    pub direction: Direction,
    /// The extension's canonical URI.
    pub uri: Option<Url>,
    /// Extension-specific attributes trailing the URI.
    pub ext_attr: Option<String>,
}

impl fmt::Display for ExtMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)?;

        if self.direction != Direction::Unspecified {
            write!(f, "/{}", self.direction)?;
        }

        if let Some(uri) = &self.uri {
            write!(f, " {uri}")?;
        }

        if let Some(ext_attr) = &self.ext_attr {
            write!(f, " {ext_attr}")?;
        }

        Ok(())
    }
}

impl ExtMap {
    /// converts this object to an Attribute
    pub fn convert(&self) -> Attribute {
        Attribute {
            key: "extmap".to_string(),
            value: Some(self.to_string()),
        }
    }

    /// unmarshal creates an Extmap from a string
    pub fn unmarshal<R: io::BufRead>(reader: &mut R) -> Result<Self> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let parts: Vec<&str> = line.trim().splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(Error::ParseExtMap(line));
        }

        let fields: Vec<&str> = parts[1].split_whitespace().collect();
        if fields.len() < 2 {
            return Err(Error::ParseExtMap(line));
        }

        let valdir: Vec<&str> = fields[0].split('/').collect();
        let value = valdir[0].parse::<u16>()?;
        // RFC 8285 section 4.3: the two-byte-header extension ID is "in the
        // range 1-255 inclusive" (0 is reserved for padding). One-byte-header
        // IDs (1-14) are a subset of the same range.
        if !(1..=255).contains(&value) {
            return Err(Error::ParseExtMap(format!(
                "{} -- extmap key must be in the range 1-255",
                valdir[0]
            )));
        }

        let mut direction = Direction::Unspecified;
        if valdir.len() == 2 {
            direction = Direction::new(valdir[1]);
            if direction == Direction::Unspecified {
                return Err(Error::ParseExtMap(format!(
                    "unknown direction from {}",
                    valdir[1]
                )));
            }
        }

        let uri = Some(Url::parse(fields[1])?);

        let ext_attr = if fields.len() == 3 {
            Some(fields[2].to_owned())
        } else {
            None
        };

        Ok(ExtMap {
            value,
            direction,
            uri,
            ext_attr,
        })
    }

    /// marshal creates a string from an ExtMap
    pub fn marshal(&self) -> String {
        "extmap:".to_string() + self.to_string().as_str()
    }
}
