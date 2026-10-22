#[cfg(test)]
mod util_test;

use shared::error::{Error, Result};

use std::collections::HashMap;
use std::fmt;

/// The `a=` line prefix.
pub const ATTRIBUTE_KEY: &str = "a=";

/// ConnectionRole indicates which of the end points should initiate the connection establishment
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionRole {
    #[default]
    /// No `a=setup` attribute was present.
    Unspecified,

    /// ConnectionRoleActive indicates the endpoint will initiate an outgoing connection.
    Active,

    /// ConnectionRolePassive indicates the endpoint will accept an incoming connection.
    Passive,

    /// ConnectionRoleActpass indicates the endpoint is willing to accept an incoming connection or to initiate an outgoing connection.
    Actpass,

    /// ConnectionRoleHoldconn indicates the endpoint does not want the connection to be established for the time being.
    Holdconn,
}

const CONNECTION_ROLE_ACTIVE_STR: &str = "active";
const CONNECTION_ROLE_PASSIVE_STR: &str = "passive";
const CONNECTION_ROLE_ACTPASS_STR: &str = "actpass";
const CONNECTION_ROLE_HOLDCONN_STR: &str = "holdconn";

impl fmt::Display for ConnectionRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ConnectionRole::Active => CONNECTION_ROLE_ACTIVE_STR,
            ConnectionRole::Passive => CONNECTION_ROLE_PASSIVE_STR,
            ConnectionRole::Actpass => CONNECTION_ROLE_ACTPASS_STR,
            ConnectionRole::Holdconn => CONNECTION_ROLE_HOLDCONN_STR,
            _ => "Unspecified",
        };
        write!(f, "{s}")
    }
}

impl From<u8> for ConnectionRole {
    fn from(v: u8) -> Self {
        match v {
            1 => ConnectionRole::Active,
            2 => ConnectionRole::Passive,
            3 => ConnectionRole::Actpass,
            4 => ConnectionRole::Holdconn,
            _ => ConnectionRole::Unspecified,
        }
    }
}

impl From<&str> for ConnectionRole {
    fn from(raw: &str) -> Self {
        match raw {
            CONNECTION_ROLE_ACTIVE_STR => ConnectionRole::Active,
            CONNECTION_ROLE_PASSIVE_STR => ConnectionRole::Passive,
            CONNECTION_ROLE_ACTPASS_STR => ConnectionRole::Actpass,
            CONNECTION_ROLE_HOLDCONN_STR => ConnectionRole::Holdconn,
            _ => ConnectionRole::Unspecified,
        }
    }
}

/// https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-26#section-5.2.1
/// Session ID is recommended to be constructed by generating a 64-bit
/// quantity with the highest bit set to zero and the remaining 63-bits
/// being cryptographically random.
pub(crate) fn new_session_id() -> u64 {
    let c = u64::MAX ^ (1u64 << 63);
    rand::random::<u64>() & c
}

// Codec represents a codec
#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// One codec offered by a media section, assembled from its `a=rtpmap`, `a=fmtp` and
/// `a=rtcp-fb` attributes.
pub struct Codec {
    /// The RTP payload type that identifies this codec in the stream.
    pub payload_type: u8,
    /// The encoding name, such as `VP8` or `opus`.
    pub name: String,
    /// The RTP clock rate in Hz.
    pub clock_rate: u32,
    /// Codec-specific encoding parameters — the channel count, for audio.
    pub encoding_parameters: String,
    /// The `a=fmtp` format parameters, verbatim.
    pub fmtp: String,
    /// The `a=rtcp-fb` feedback types negotiated for this codec, such as `nack` or `goog-remb`.
    pub rtcp_feedback: Vec<String>,
}

impl fmt::Display for Codec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}/{}/{} ({}) [",
            self.payload_type, self.name, self.clock_rate, self.encoding_parameters, self.fmtp,
        )?;

        let mut first = true;
        for part in &self.rtcp_feedback {
            if first {
                first = false;
                write!(f, "{part}")?;
            } else {
                write!(f, ", {part}")?;
            }
        }

        write!(f, "]")
    }
}

/// `strconv.ParseUint(s, 10, 8)`: digits only, no sign.
fn parse_u8(s: &str) -> Result<u8> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::MissingColon);
    }
    Ok(s.parse::<u8>()?)
}

/// Splits `s` on `sep` into exactly two parts, as `split(sep)` would yield them, or reports that
/// there were more or fewer. Written with the iterator directly: collecting into a `Vec` just to
/// count and index costs an allocation per call, and these run once per attribute.
fn split_exactly_two(s: &str, sep: char) -> Option<(&str, &str)> {
    let mut parts = s.split(sep);
    let first = parts.next()?;
    let second = parts.next()?;
    parts.next().is_none().then_some((first, second))
}

pub(crate) fn parse_rtpmap(rtpmap: &str) -> Result<Codec> {
    // a=rtpmap:<payload type> <encoding name>/<clock rate>[/<encoding parameters>]
    let (head, encoding) = split_exactly_two(rtpmap, ' ').ok_or(Error::MissingWhitespace)?;

    let (_, payload_type) = split_exactly_two(head, ':').ok_or(Error::MissingColon)?;
    let payload_type = parse_u8(payload_type)?;

    let mut parts = encoding.split('/');
    let name = parts.next().unwrap_or_default().to_string();
    let clock_rate = match parts.next() {
        Some(rate) => {
            if rate.is_empty() || !rate.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::MissingColon);
            }
            rate.parse::<u32>()?
        }
        None => 0,
    };
    let encoding_parameters = parts.next().unwrap_or_default().to_string();

    Ok(Codec {
        payload_type,
        name,
        clock_rate,
        encoding_parameters,
        ..Default::default()
    })
}

pub(crate) fn parse_fmtp(fmtp: &str) -> Result<Codec> {
    // a=fmtp:<format> <format specific parameters>
    let (head, format_params) = fmtp.split_once(' ').ok_or(Error::MissingWhitespace)?;

    let (_, payload_type) = split_exactly_two(head, ':').ok_or(Error::MissingColon)?;
    let payload_type = parse_u8(payload_type)?;

    Ok(Codec {
        payload_type,
        fmtp: format_params.to_string(),
        ..Default::default()
    })
}

/// Parses `a=rtcp-fb:<payload type> <type> [<parameter>]`. The payload type may be the wildcard
/// `*`, in which case the second value is `true` and the codec's payload type is meaningless.
pub(crate) fn parse_rtcp_fb(rtcp_fb: &str) -> Result<(Codec, bool)> {
    let (head, feedback) = rtcp_fb.split_once(' ').ok_or(Error::MissingWhitespace)?;

    let (_, payload_type) = split_exactly_two(head, ':').ok_or(Error::MissingColon)?;

    let is_wildcard = payload_type == "*";
    let payload_type = if is_wildcard {
        0
    } else {
        parse_u8(payload_type)?
    };

    Ok((
        Codec {
            payload_type,
            rtcp_feedback: vec![feedback.to_string()],
            ..Default::default()
        },
        is_wildcard,
    ))
}

pub(crate) fn merge_codecs(mut codec: Codec, codecs: &mut HashMap<u8, Codec>) {
    let saved_codec = codecs.entry(codec.payload_type).or_default();
    if saved_codec.payload_type == 0 {
        saved_codec.payload_type = codec.payload_type
    }
    if saved_codec.name.is_empty() {
        saved_codec.name = codec.name
    }
    if saved_codec.clock_rate == 0 {
        saved_codec.clock_rate = codec.clock_rate
    }
    if saved_codec.encoding_parameters.is_empty() {
        saved_codec.encoding_parameters = codec.encoding_parameters
    }
    if saved_codec.fmtp.is_empty() {
        saved_codec.fmtp = codec.fmtp
    }
    saved_codec.rtcp_feedback.append(&mut codec.rtcp_feedback);
}

impl Codec {
    /// Adds a feedback type unless it is already listed.
    pub(crate) fn append_rtcp_feedback(&mut self, rtcp_feedback: &str) {
        if !self.rtcp_feedback.iter().any(|f| f == rtcp_feedback) {
            self.rtcp_feedback.push(rtcp_feedback.to_owned());
        }
    }
}

fn equivalent_fmtp(want: &str, got: &str) -> bool {
    let mut want_split: Vec<&str> = want.split(';').collect();
    let mut got_split: Vec<&str> = got.split(';').collect();

    if want_split.len() != got_split.len() {
        return false;
    }

    want_split.sort_unstable();
    got_split.sort_unstable();

    for (i, &want_part) in want_split.iter().enumerate() {
        let want_part = want_part.trim();
        let got_part = got_split[i].trim();
        if got_part != want_part {
            return false;
        }
    }

    true
}

pub(crate) fn codecs_match(wanted: &Codec, got: &Codec) -> bool {
    if !wanted.name.is_empty() && wanted.name.to_lowercase() != got.name.to_lowercase() {
        return false;
    }
    if wanted.clock_rate != 0 && wanted.clock_rate != got.clock_rate {
        return false;
    }
    if !wanted.encoding_parameters.is_empty()
        && wanted.encoding_parameters != got.encoding_parameters
    {
        return false;
    }
    if !wanted.fmtp.is_empty() && !equivalent_fmtp(&wanted.fmtp, &got.fmtp) {
        return false;
    }

    true
}
