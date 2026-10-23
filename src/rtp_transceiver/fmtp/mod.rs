pub(crate) mod av1;
pub(crate) mod generic;
pub(crate) mod h264;
pub(crate) mod h265;
pub(crate) mod vp9;

use std::any::Any;
use std::collections::HashMap;
use std::fmt;

use av1::Av1Fmtp;
use generic::GenericFmtp;
use h264::H264Fmtp;
use h265::H265Fmtp;
use vp9::Vp9Fmtp;

/// Fmtp interface for implementing custom
/// Fmtp parsers based on mime_type
pub(crate) trait Fmtp: fmt::Debug {
    /// mime_type returns the mime_type associated with
    /// the fmtp
    fn mime_type(&self) -> &str;

    /// match_fmtp compares two fmtp descriptions for
    /// compatibility based on the mime_type    
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool;

    /// parameter returns a value for the associated key
    /// if contained in the parsed fmtp string
    fn parameter(&self, key: &str) -> Option<&String>;

    fn equal(&self, other: &dyn Fmtp) -> bool;
    fn as_any(&self) -> &dyn Any;
}

impl PartialEq for dyn Fmtp {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

/// The clock rate implied by an omitted one, as pion's `defaultClockRate`.
fn default_clock_rate(mime_type: &str) -> u32 {
    let mime_type = mime_type.to_ascii_lowercase();
    match mime_type.as_str() {
        "audio/opus" => 48000,
        "audio/pcmu" | "audio/pcma" => 8000,
        _ => 90000,
    }
}

/// The channel count implied by an omitted encoding parameter: one for audio, except Opus
/// which RFC 7587 fixes at two. Video has none, so zero.
fn default_channels(mime_type: &str) -> u16 {
    let mime_type = mime_type.to_ascii_lowercase();
    if mime_type == "audio/opus" {
        2
    } else if mime_type.starts_with("audio/") {
        1
    } else {
        0
    }
}

/// Whether two clock rates are equal, where zero means the codec's default.
pub(crate) fn clock_rate_equal(mime_type: &str, a: u32, b: u32) -> bool {
    let a = if a == 0 {
        default_clock_rate(mime_type)
    } else {
        a
    };
    let b = if b == 0 {
        default_clock_rate(mime_type)
    } else {
        b
    };
    a == b
}

/// Whether two channel counts are equal, where zero means the codec's default and, after that,
/// one (RFC 8866: the count "may be omitted if the number of channels is one").
pub(crate) fn channels_equal(mime_type: &str, a: u16, b: u16) -> bool {
    let a = if a == 0 {
        default_channels(mime_type)
    } else {
        a
    };
    let b = if b == 0 {
        default_channels(mime_type)
    } else {
        b
    };
    a.max(1) == b.max(1)
}

/// parse parses an fmtp string based on the MimeType
pub(crate) fn parse(mime_type: &str, clock_rate: u32, channels: u16, line: &str) -> Box<dyn Fmtp> {
    let mut parameters = HashMap::new();
    for p in line.split(';').collect::<Vec<&str>>() {
        let pp: Vec<&str> = p.trim().splitn(2, '=').collect();
        let key = pp[0].to_lowercase();
        let value = if pp.len() > 1 {
            pp[1].to_owned()
        } else {
            String::new()
        };
        parameters.insert(key, value);
    }

    match mime_type.to_ascii_lowercase().as_str() {
        "video/h264" => Box::new(H264Fmtp { parameters }),
        "video/h265" => Box::new(H265Fmtp { parameters }),
        "video/vp9" => Box::new(Vp9Fmtp { parameters }),
        "video/av1" => Box::new(Av1Fmtp { parameters }),
        _ => Box::new(GenericFmtp {
            mime_type: mime_type.to_owned(),
            clock_rate,
            channels,
            parameters,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_picks_the_codec_specific_matcher() {
        // pion `TestParse`: the mime type selects the parser and keeps lowercased keys.
        for (mime, want) in [
            ("video/h264", "video/h264"),
            ("video/H265", "video/h265"),
            ("video/vp9", "video/vp9"),
            ("video/AV1", "video/av1"),
            ("generic", "generic"),
        ] {
            let f = parse(mime, 90000, 2, "Key=value");
            assert_eq!(f.mime_type(), want);
            assert_eq!(f.parameter("key").map(String::as_str), Some("value"));
        }
    }
}
