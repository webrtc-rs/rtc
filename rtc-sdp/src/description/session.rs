//! The session description — a whole SDP document.
//!
//! A [`SessionDescription`](crate::description::session::SessionDescription) is the session-level fields (`v=`, `o=`, `s=`, `t=`, …) followed by
//! any number of [`MediaDescription`](crate::description::media::MediaDescription)s. `unmarshal` parses one
//! from a string and `marshal` prints it back; the round trip is faithful, including attributes
//! this crate does not interpret.
//!
//! The `ATTR_KEY_*` constants name the `a=` attributes WebRTC relies on — `mid`, `msid`,
//! `setup`, `rtcp-mux`, `extmap` and the direction flags — and the `SEMANTIC_TOKEN_*` constants
//! name the grouping semantics used with `a=group` and `a=msid-semantic`.

use super::text_writer::TextWriter;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, io};

use crate::lexer::*;
use crate::util::*;
use shared::error::{Error, Result};

use super::common::*;
use super::media::*;

/// Constants for SDP attributes used in JSEP
pub const ATTR_KEY_CANDIDATE: &str = "candidate";
/// `a=end-of-candidates`: ICE gathering for this section is complete.
pub const ATTR_KEY_END_OF_CANDIDATES: &str = "end-of-candidates";
/// `a=identity`: an identity assertion for the session.
pub const ATTR_KEY_IDENTITY: &str = "identity";
/// `a=group`: groups m-lines, as BUNDLE does.
pub const ATTR_KEY_GROUP: &str = "group";
/// `a=ssrc`: declares an SSRC and its attributes.
pub const ATTR_KEY_SSRC: &str = "ssrc";
/// `a=ssrc-group`: relates SSRCs, such as an RTX stream to its primary.
pub const ATTR_KEY_SSRC_GROUP: &str = "ssrc-group";
/// `a=msid`: associates a track with a media stream.
pub const ATTR_KEY_MSID: &str = "msid";
/// `a=msid-semantic`: declares the semantics used by `a=msid`.
pub const ATTR_KEY_MSID_SEMANTIC: &str = "msid-semantic";
/// `a=setup`: the DTLS role — `active`, `passive` or `actpass`.
pub const ATTR_KEY_CONNECTION_SETUP: &str = "setup";
/// `a=mid`: the media identification tag that names this m-line.
pub const ATTR_KEY_MID: &str = "mid";
/// `a=ice-lite`: the endpoint is an ICE-lite implementation.
pub const ATTR_KEY_ICELITE: &str = "ice-lite";
/// `a=rtcp-mux`: RTP and RTCP share one port.
pub const ATTR_KEY_RTCPMUX: &str = "rtcp-mux";
/// `a=rtcp-rsize`: reduced-size RTCP is supported.
pub const ATTR_KEY_RTCPRSIZE: &str = "rtcp-rsize";
/// `a=inactive`: neither send nor receive.
pub const ATTR_KEY_INACTIVE: &str = "inactive";
/// `a=recvonly`: receive only.
pub const ATTR_KEY_RECV_ONLY: &str = "recvonly";
/// `a=sendonly`: send only.
pub const ATTR_KEY_SEND_ONLY: &str = "sendonly";
/// `a=sendrecv`: send and receive.
pub const ATTR_KEY_SEND_RECV: &str = "sendrecv";
/// `a=extmap`: maps an RTP header-extension URI to an id.
pub const ATTR_KEY_EXT_MAP: &str = "extmap";
/// `a=extmap-allow-mixed`: one- and two-byte header extensions may be mixed.
pub const ATTR_KEY_EXTMAP_ALLOW_MIXED: &str = "extmap-allow-mixed";
/// `a=max-message-size`: the largest SCTP message this endpoint accepts.
pub const ATTR_KEY_MAX_MESSAGE_SIZE: &str = "max-message-size";

/// Constants for semantic tokens used in JSEP
pub const SEMANTIC_TOKEN_LIP_SYNCHRONIZATION: &str = "LS";
/// `FID`: flow identification — the SSRCs carry the same content, as RTX does.
pub const SEMANTIC_TOKEN_FLOW_IDENTIFICATION: &str = "FID";
/// `FEC`: one SSRC carries error-correction data for another.
pub const SEMANTIC_TOKEN_FORWARD_ERROR_CORRECTION: &str = "FEC";
// https://datatracker.ietf.org/doc/html/rfc5956#section-4.1
/// `FEC-FR`: the FEC framework grouping semantic.
pub const SEMANTIC_TOKEN_FORWARD_ERROR_CORRECTION_FRAMEWORK: &str = "FEC-FR";
/// `WMS`: WebRTC media streams, used with `a=msid-semantic`.
pub const SEMANTIC_TOKEN_WEBRTC_MEDIA_STREAMS: &str = "WMS";

/// Version describes the value provided by the "v=" field which gives
/// the version of the Session Description Protocol.
pub type Version = isize;

/// Origin defines the structure for the "o=" field which provides the
/// originator of the session plus a session identifier and version number.
#[derive(Debug, Default, Clone)]
pub struct Origin {
    /// The originator's user name, or `-` when withheld.
    pub username: String,
    /// A globally unique session identifier.
    pub session_id: u64,
    /// Incremented on each modification of the session description.
    pub session_version: u64,
    /// The network type, always `IN` in practice.
    pub network_type: String,
    /// The address type, `IP4` or `IP6`.
    pub address_type: String,
    /// The originator's address. WebRTC does not use it and sends a placeholder.
    pub unicast_address: String,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.username)?;
        write!(f, " {} {} ", self.session_id, self.session_version)?;
        f.write_str(&self.network_type)?;
        f.write_str(" ")?;
        f.write_str(&self.address_type)?;
        f.write_str(" ")?;
        f.write_str(&self.unicast_address)
    }
}

impl Origin {
    /// An empty session description with SDP version 0.
    pub fn new() -> Self {
        Origin {
            username: "".to_owned(),
            session_id: 0,
            session_version: 0,
            network_type: "".to_owned(),
            address_type: "".to_owned(),
            unicast_address: "".to_owned(),
        }
    }
}

/// SessionName describes a structured representations for the "s=" field
/// and is the textual session name.
pub type SessionName = String;

/// EmailAddress describes a structured representations for the "e=" line
/// which specifies email contact information for the person responsible for
/// the conference.
pub type EmailAddress = String;

/// PhoneNumber describes a structured representations for the "p=" line
/// specify phone contact information for the person responsible for the
/// conference.
pub type PhoneNumber = String;

/// TimeZone defines the structured object for "z=" line which describes
/// repeated sessions scheduling.
#[derive(Debug, Default, Clone)]
pub struct TimeZone {
    /// The time at which the offset takes effect.
    pub adjustment_time: u64,
    /// The offset from the session's base time, in seconds.
    pub offset: i64,
}

impl fmt::Display for TimeZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.adjustment_time, self.offset)
    }
}

/// TimeDescription describes "t=", "r=" fields of the session description
/// which are used to specify the start and stop times for a session as well as
/// repeat intervals and durations for the scheduled session.
#[derive(Debug, Default, Clone)]
pub struct TimeDescription {
    /// `t=<start-time> <stop-time>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.9>
    pub timing: Timing,

    /// `r=<repeat interval> <active duration> <offsets from start-time>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.10>
    pub repeat_times: Vec<RepeatTime>,
}

/// Timing defines the "t=" field's structured representation for the start and
/// stop times.
#[derive(Debug, Default, Clone)]
pub struct Timing {
    /// Session start time in NTP seconds; `0` means unbounded.
    pub start_time: u64,
    /// Session stop time in NTP seconds; `0` means unbounded.
    pub stop_time: u64,
}

impl fmt::Display for Timing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.start_time, self.stop_time)
    }
}

/// RepeatTime describes the "r=" fields of the session description which
/// represents the intervals and durations for repeated scheduled sessions.
#[derive(Debug, Default, Clone)]
pub struct RepeatTime {
    /// How often the session repeats, in seconds.
    pub interval: i64,
    /// How long each repetition lasts, in seconds.
    pub duration: i64,
    /// Offsets from the start time at which the session repeats.
    pub offsets: Vec<i64>,
}

impl fmt::Display for RepeatTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.interval, self.duration)?;

        for value in &self.offsets {
            write!(f, " {value}")?;
        }
        Ok(())
    }
}

/// SessionDescription is a a well-defined format for conveying sufficient
/// information to discover and participate in a multimedia session.
#[derive(Debug, Default, Clone)]
pub struct SessionDescription {
    /// `v=0`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.1>
    pub version: Version,

    /// `o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.2>
    pub origin: Origin,

    /// `s=<session name>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.3>
    pub session_name: SessionName,

    /// `i=<session description>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.4>
    pub session_information: Option<Information>,

    /// `u=<uri>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.5>
    pub uri: Option<String>,

    /// `e=<email-address>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.6>
    pub email_address: Option<EmailAddress>,

    /// `p=<phone-number>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.6>
    pub phone_number: Option<PhoneNumber>,

    /// `c=<nettype> <addrtype> <connection-address>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.7>
    pub connection_information: Option<ConnectionInformation>,

    /// `b=<bwtype>:<bandwidth>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.8>
    pub bandwidth: Vec<Bandwidth>,

    /// <https://tools.ietf.org/html/rfc4566#section-5.9>
    /// <https://tools.ietf.org/html/rfc4566#section-5.10>
    pub time_descriptions: Vec<TimeDescription>,

    /// `z=<adjustment time> <offset> <adjustment time> <offset> ...`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.11>
    pub time_zones: Vec<TimeZone>,

    /// `k=<method>`
    ///
    /// `k=<method>:<encryption key>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.12>
    pub encryption_key: Option<EncryptionKey>,

    /// `a=<attribute>`
    ///
    /// `a=<attribute>:<value>`
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5.13>
    pub attributes: Vec<Attribute>,

    /// <https://tools.ietf.org/html/rfc4566#section-5.14>
    pub media_descriptions: Vec<MediaDescription>,
}

impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

impl SessionDescription {
    /// Writes the SDP text to any `fmt::Write`.
    ///
    /// Generic rather than taking a `Formatter`, so `marshal` writes into a `String` through
    /// direct, inlinable calls instead of one dynamic dispatch per piece of every line.
    fn write_to<W: fmt::Write>(&self, f: &mut W) -> fmt::Result {
        write_key_value(f, "v=", Some(&self.version))?;
        write_key_value(f, "o=", Some(&self.origin))?;
        write_key_value(f, "s=", Some(&self.session_name))?;

        write_key_value(f, "i=", self.session_information.as_ref())?;

        if let Some(uri) = &self.uri {
            write_key_value(f, "u=", Some(uri))?;
        }
        write_key_value(f, "e=", self.email_address.as_ref())?;
        write_key_value(f, "p=", self.phone_number.as_ref())?;
        if let Some(connection_information) = &self.connection_information {
            write_key_value(f, "c=", Some(&connection_information))?;
        }

        for bandwidth in &self.bandwidth {
            write_key_value(f, "b=", Some(&bandwidth))?;
        }
        for time_description in &self.time_descriptions {
            write_key_value(f, "t=", Some(&time_description.timing))?;
            for repeat_time in &time_description.repeat_times {
                write_key_value(f, "r=", Some(&repeat_time))?;
            }
        }

        write_key_slice_of_values(f, "z=", &self.time_zones)?;

        write_key_value(f, "k=", self.encryption_key.as_ref())?;
        for attribute in &self.attributes {
            write_attribute_line(f, attribute)?;
        }

        for media_description in &self.media_descriptions {
            write_key_value(f, "m=", Some(&media_description.media_name))?;
            write_key_value(f, "i=", media_description.media_title.as_ref())?;
            if let Some(connection_information) = &media_description.connection_information {
                write_key_value(f, "c=", Some(&connection_information))?;
            }
            for bandwidth in &media_description.bandwidth {
                write_key_value(f, "b=", Some(&bandwidth))?;
            }
            write_key_value(f, "k=", media_description.encryption_key.as_ref())?;
            for attribute in &media_description.attributes {
                write_attribute_line(f, attribute)?;
            }
        }

        Ok(())
    }
}

/// Writes one `a=` line.
///
/// Attributes are the bulk of an SDP (hundreds of lines in a browser offer), so this appends the
/// pieces directly instead of going through the formatting machinery twice per line.
fn write_attribute_line<W: fmt::Write>(f: &mut W, attribute: &Attribute) -> fmt::Result {
    f.write_str("a=")?;
    f.write_str(&attribute.key)?;
    if let Some(value) = &attribute.value {
        f.write_str(":")?;
        f.write_str(value)?;
    }
    f.write_str(END_LINE)
}

/// Reset cleans the SessionDescription, and sets all fields back to their default values
impl SessionDescription {
    /// API to match draft-ietf-rtcweb-jsep
    /// Move to webrtc or its own package?
    /// NewJSEPSessionDescription creates a new SessionDescription with
    /// some settings that are required by the JSEP spec.
    pub fn new_jsep_session_description(identity: bool) -> Self {
        let d = SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id: new_session_id(),
                session_version: SystemTime::now() // Exemption: wall-clock is correct here to generate random SDP session version
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .subsec_nanos() as u64,
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                unicast_address: "0.0.0.0".to_string(),
            },
            session_name: "-".to_string(),
            session_information: None,
            uri: None,
            email_address: None,
            phone_number: None,
            connection_information: None,
            bandwidth: vec![],
            time_descriptions: vec![TimeDescription {
                timing: Timing {
                    start_time: 0,
                    stop_time: 0,
                },
                repeat_times: vec![],
            }],
            time_zones: vec![],
            encryption_key: None,
            attributes: vec![], // TODO: implement trickle ICE
            media_descriptions: vec![],
        };

        if identity {
            d.with_property_attribute(ATTR_KEY_IDENTITY.to_string())
        } else {
            d
        }
    }

    /// WithPropertyAttribute adds a property attribute 'a=key' to the session description
    pub fn with_property_attribute(mut self, key: String) -> Self {
        self.attributes.push(Attribute::new(key, None));
        self
    }

    /// WithValueAttribute adds a value attribute 'a=key:value' to the session description
    pub fn with_value_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.push(Attribute::new(key, Some(value)));
        self
    }

    /// WithFingerprint adds a fingerprint to the session description
    pub fn with_fingerprint(self, algorithm: String, value: String) -> Self {
        self.with_value_attribute("fingerprint".to_string(), algorithm + " " + value.as_str())
    }

    /// WithMedia adds a media description to the session description
    pub fn with_media(mut self, md: MediaDescription) -> Self {
        self.media_descriptions.push(md);
        self
    }

    /// Parses the session description's `a=rtpmap`, `a=fmtp` and `a=rtcp-fb` attributes and
    /// returns the codecs by payload type. The static payload types 0 (PCMU), 8 (PCMA) and
    /// 9 (G722) are present without an `a=rtpmap`, and a wildcard `a=rtcp-fb:*` applies to every
    /// codec. Build the map once to look up several payload types.
    pub fn codec_map(&self) -> HashMap<u8, Codec> {
        let mut codecs: HashMap<u8, Codec> = HashMap::from([
            (
                0,
                Codec {
                    payload_type: 0,
                    name: "PCMU".to_owned(),
                    clock_rate: 8000,
                    ..Default::default()
                },
            ),
            (
                8,
                Codec {
                    payload_type: 8,
                    name: "PCMA".to_owned(),
                    clock_rate: 8000,
                    ..Default::default()
                },
            ),
            (
                9,
                Codec {
                    payload_type: 9,
                    name: "G722".to_owned(),
                    clock_rate: 8000,
                    ..Default::default()
                },
            ),
        ]);

        let mut wildcard_rtcp_feedback: Vec<String> = vec![];
        let mut attr = String::new();
        for m in &self.media_descriptions {
            for a in &m.attributes {
                // Only these three carry codec information. Most attributes in a browser's
                // offer are none of them, so they are rejected on the key before any text is
                // built. (A key may hold the whole `rtpmap:96 VP8/90000` text, with no value, when
                // a description is assembled by hand, hence a prefix test.)
                let key = a.key.as_str();
                if !(key.starts_with("rtpmap")
                    || key.starts_with("fmtp")
                    || key.starts_with("rtcp-fb"))
                {
                    continue;
                }
                // One buffer for every attribute, rather than a fresh string for each.
                attr.clear();
                let _ = write!(attr, "{a}");
                if attr.starts_with("rtpmap:") {
                    if let Ok(codec) = parse_rtpmap(&attr) {
                        merge_codecs(codec, &mut codecs);
                    }
                } else if attr.starts_with("fmtp:") {
                    if let Ok(codec) = parse_fmtp(&attr) {
                        merge_codecs(codec, &mut codecs);
                    }
                } else if attr.starts_with("rtcp-fb:") {
                    match parse_rtcp_fb(&attr) {
                        Ok((codec, true)) => wildcard_rtcp_feedback.extend(codec.rtcp_feedback),
                        Ok((codec, false)) => merge_codecs(codec, &mut codecs),
                        Err(_) => {}
                    }
                }
            }
        }

        for codec in codecs.values_mut() {
            for fb in &wildcard_rtcp_feedback {
                codec.append_rtcp_feedback(fb);
            }
        }

        codecs
    }

    fn build_codec_map(&self) -> HashMap<u8, Codec> {
        self.codec_map()
    }

    /// The codecs for the given payload types, in order, skipping those the description does
    /// not define.
    pub fn get_codecs_for_payload_types(&self, payload_types: &[u8]) -> Vec<Codec> {
        let codecs = self.codec_map();
        payload_types
            .iter()
            .filter_map(|pt| codecs.get(pt).cloned())
            .collect()
    }

    /// get_codec_for_payload_type scans the SessionDescription for the given payload type and returns the codec
    pub fn get_codec_for_payload_type(&self, payload_type: u8) -> Result<Codec> {
        let codecs = self.build_codec_map();

        if let Some(codec) = codecs.get(&payload_type) {
            Ok(codec.clone())
        } else {
            Err(Error::PayloadTypeNotFound)
        }
    }

    /// get_payload_type_for_codec scans the SessionDescription for a codec that matches the provided codec
    /// as closely as possible and returns its payload type
    pub fn get_payload_type_for_codec(&self, wanted: &Codec) -> Result<u8> {
        let codecs = self.build_codec_map();

        for (payload_type, codec) in codecs.iter() {
            if codecs_match(wanted, codec) {
                return Ok(*payload_type);
            }
        }

        Err(Error::CodecNotFound)
    }

    /// Returns whether an attribute exists
    pub fn has_attribute(&self, key: &str) -> bool {
        self.attributes.iter().any(|a| a.key == key)
    }

    /// Attribute returns the value of an attribute and if it exists
    pub fn attribute(&self, key: &str) -> Option<&str> {
        for a in &self.attributes {
            if a.key == key {
                return a.value.as_deref();
            }
        }
        None
    }

    /// Marshal takes a SDP struct to text
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5>
    ///
    /// Session description
    ///    v=  (protocol version)
    ///    o=  (originator and session identifier)
    ///    s=  (session name)
    ///    i=* (session information)
    ///    u=* (URI of description)
    ///    e=* (email address)
    ///    p=* (phone number)
    ///    c=* (connection information -- not required if included in
    ///         all media)
    ///    b=* (zero or more bandwidth information lines)
    ///    One or more time descriptions ("t=" and "r=" lines; see below)
    ///    z=* (time zone adjustments)
    ///    k=* (encryption key)
    ///    a=* (zero or more session attribute lines)
    ///    Zero or more media descriptions
    ///
    /// Time description
    ///    t=  (time the session is active)
    ///    r=* (zero or more repeat times)
    ///
    /// Media description, if present
    ///    m=  (media name and transport address)
    ///    i=* (media title)
    ///    c=* (connection information -- optional if included at
    ///         session level)
    ///    b=* (zero or more bandwidth information lines)
    ///    k=* (encryption key)
    ///    a=* (zero or more media attribute lines)
    pub fn marshal(&self) -> String {
        // Sized from the attribute count, which dominates: a browser's attribute lines average
        // about 30 bytes, so 32 per line leaves room without walking every key and value first.
        let capacity = 256
            + 32 * self.attributes.len()
            + self
                .media_descriptions
                .iter()
                .map(|m| 160 + 32 * m.attributes.len())
                .sum::<usize>();

        let mut out = TextWriter::with_capacity(capacity);
        // Writing into memory cannot fail.
        let _ = self.write_to(&mut out);
        out.into_string()
    }

    /// Unmarshal is the primary function that deserializes the session description
    /// message and stores it inside of a structured SessionDescription object.
    ///
    /// The States Transition Table describes the computation flow between functions
    /// (namely s1, s2, s3, ...) for a parsing procedure that complies with the
    /// specifications laid out by the rfc4566#section-5 as well as by JavaScript
    /// Session Establishment Protocol draft. Links:
    ///     <https://tools.ietf.org/html/rfc4566#section-5>
    ///     <https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-24>
    ///
    /// <https://tools.ietf.org/html/rfc4566#section-5>
    ///
    /// Session description
    ///    v=  (protocol version)
    ///    o=  (originator and session identifier)
    ///    s=  (session name)
    ///    i=* (session information)
    ///    u=* (URI of description)
    ///    e=* (email address)
    ///    p=* (phone number)
    ///    c=* (connection information -- not required if included in
    ///         all media)
    ///    b=* (zero or more bandwidth information lines)
    ///    One or more time descriptions ("t=" and "r=" lines; see below)
    ///    z=* (time zone adjustments)
    ///    k=* (encryption key)
    ///    a=* (zero or more session attribute lines)
    ///    Zero or more media descriptions
    ///
    /// Time description
    ///    t=  (time the session is active)
    ///    r=* (zero or more repeat times)
    ///
    /// Media description, if present
    ///    m=  (media name and transport address)
    ///    i=* (media title)
    ///    c=* (connection information -- optional if included at
    ///         session level)
    ///    b=* (zero or more bandwidth information lines)
    ///    k=* (encryption key)
    ///    a=* (zero or more media attribute lines)
    ///
    /// In order to generate the following state table and draw subsequent
    /// deterministic finite-state automota ("DFA") the following regex was used to
    /// derive the DFA:
    ///    vosi?u?e?p?c?b*(tr*)+z?k?a*(mi?c?b*k?a*)*
    /// possible place and state to exit:
    ///                    **   * * *  ** * * * *
    ///                    99   1 1 1  11 1 1 1 1
    ///                         3 1 1  26 5 5 4 4
    ///
    /// Please pay close attention to the `k`, and `a` parsing states. In the table
    /// below in order to distinguish between the states belonging to the media
    /// description as opposed to the session description, the states are marked
    /// with an asterisk ("a*", "k*").
    ///
    /// ```ignore
    /// +--------+----+-------+----+-----+----+-----+---+----+----+---+---+-----+---+---+----+---+----+
    /// | STATES | a* | a*,k* | a  | a,k | b  | b,c | e | i  | m  | o | p | r,t | s | t | u  | v | z  |
    /// +--------+----+-------+----+-----+----+-----+---+----+----+---+---+-----+---+---+----+---+----+
    /// |   s1   |    |       |    |     |    |     |   |    |    |   |   |     |   |   |    | 2 |    |
    /// |   s2   |    |       |    |     |    |     |   |    |    | 3 |   |     |   |   |    |   |    |
    /// |   s3   |    |       |    |     |    |     |   |    |    |   |   |     | 4 |   |    |   |    |
    /// |   s4   |    |       |    |     |    |   5 | 6 |  7 |    |   | 8 |     |   | 9 | 10 |   |    |
    /// |   s5   |    |       |    |     |  5 |     |   |    |    |   |   |     |   | 9 |    |   |    |
    /// |   s6   |    |       |    |     |    |   5 |   |    |    |   | 8 |     |   | 9 |    |   |    |
    /// |   s7   |    |       |    |     |    |   5 | 6 |    |    |   | 8 |     |   | 9 | 10 |   |    |
    /// |   s8   |    |       |    |     |    |   5 |   |    |    |   |   |     |   | 9 |    |   |    |
    /// |   s9   |    |       |    |  11 |    |     |   |    | 12 |   |   |   9 |   |   |    |   | 13 |
    /// |   s10  |    |       |    |     |    |   5 | 6 |    |    |   | 8 |     |   | 9 |    |   |    |
    /// |   s11  |    |       | 11 |     |    |     |   |    | 12 |   |   |     |   |   |    |   |    |
    /// |   s12  |    |    14 |    |     |    |  15 |   | 16 | 12 |   |   |     |   |   |    |   |    |
    /// |   s13  |    |       |    |  11 |    |     |   |    | 12 |   |   |     |   |   |    |   |    |
    /// |   s14  | 14 |       |    |     |    |     |   |    | 12 |   |   |     |   |   |    |   |    |
    /// |   s15  |    |    14 |    |     | 15 |     |   |    | 12 |   |   |     |   |   |    |   |    |
    /// |   s16  |    |    14 |    |     |    |  15 |   |    | 12 |   |   |     |   |   |    |   |    |
    /// +--------+----+-------+----+-----+----+-----+---+----+----+---+---+-----+---+---+----+---+----+
    /// ```
    pub fn unmarshal<R: io::BufRead + io::Seek>(reader: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        super::unmarshal::unmarshal_bytes(&data)
    }
}

impl From<SessionDescription> for String {
    fn from(sdp: SessionDescription) -> String {
        sdp.marshal()
    }
}

impl TryFrom<String> for SessionDescription {
    type Error = Error;
    fn try_from(sdp_string: String) -> Result<Self> {
        let mut reader = io::Cursor::new(sdp_string.as_bytes());
        let session_description = SessionDescription::unmarshal(&mut reader)?;
        Ok(session_description)
    }
}
