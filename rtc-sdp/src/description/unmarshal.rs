//! SDP parsing, a line-for-line port of pion/sdp's lexer and state machine so both accept and
//! reject exactly the same documents. The states `s1`..`s16` are the DFA documented on
//! [`SessionDescription::unmarshal`](super::session::SessionDescription::unmarshal).

use shared::error::{Error, Result};
use smol_str::SmolStr;

use super::common::*;
use super::media::*;
use super::session::*;

#[derive(Debug)]
enum Fail {
    /// The byte at this position cannot continue the line.
    Syntax(usize),
    Eof,
    Value(String),
    Numeric(String),
    Port(String),
    Url(String),
    /// A required field was absent; only used internally to apply pion's defaults.
    FieldMissing,
}

impl From<Fail> for Error {
    fn from(f: Fail) -> Error {
        match f {
            Fail::Syntax(i) => Error::SdpInvalidSyntax(format!("syntax error at pos {i}")),
            Fail::Eof => Error::SdpInvalidSyntax("unexpected end of input".into()),
            Fail::Value(v) | Fail::Numeric(v) | Fail::Port(v) | Fail::Url(v) => {
                Error::SdpInvalidValue(v)
            }
            Fail::FieldMissing => Error::SdpInvalidSyntax("field missing".into()),
        }
    }
}

type R<T> = std::result::Result<T, Fail>;

fn is_newline(ch: u8) -> bool {
    ch == b'\n' || ch == b'\r'
}

fn is_whitespace(ch: u8) -> bool {
    ch == b' ' || ch == b'\t'
}

struct Lexer<'a> {
    value: &'a [u8],
    /// `value` as text, when all of it is valid UTF-8 (nearly always). Validated once up front
    /// rather than once per line; if it is not valid, each field is converted lossily instead.
    text: Option<&'a str>,
    pos: usize,
    desc: SessionDescription,
}

type StateFn = fn(&mut Lexer<'_>) -> R<Option<State>>;
struct State(StateFn);

impl<'a> Lexer<'a> {
    fn syntax_error(&self) -> Fail {
        Fail::Syntax(self.pos.saturating_sub(1))
    }

    fn read_byte(&mut self) -> R<u8> {
        match self.value.get(self.pos) {
            Some(&ch) => {
                self.pos += 1;
                Ok(ch)
            }
            None => Err(Fail::Eof),
        }
    }

    fn unread_byte(&mut self) {
        self.pos = self.pos.saturating_sub(1);
    }

    fn next_line(&mut self) -> R<()> {
        loop {
            match self.read_byte() {
                Err(Fail::Eof) => return Ok(()),
                Err(e) => return Err(e),
                Ok(ch) if !is_newline(ch) => {
                    self.unread_byte();
                    return Ok(());
                }
                Ok(_) => {}
            }
        }
    }

    fn read_whitespace(&mut self) {
        while let Some(&ch) = self.value.get(self.pos) {
            if !is_whitespace(ch) {
                return;
            }
            self.pos += 1;
        }
    }

    fn read_uint64_field(&mut self) -> R<u64> {
        let mut i: u64 = 0;
        loop {
            let ch = match self.read_byte() {
                Err(Fail::Eof) if i > 0 => break,
                Err(e) => return Err(e),
                Ok(ch) => ch,
            };
            if is_newline(ch) {
                self.unread_byte();
                break;
            }
            if is_whitespace(ch) {
                self.read_whitespace();
                break;
            }
            match ch {
                b'0'..=b'9' => i = i.wrapping_mul(10).wrapping_add(u64::from(ch - b'0')),
                _ => return Err(self.syntax_error()),
            }
        }
        Ok(i)
    }

    /// Returns the next field on this line, or an empty string if there are no more.
    fn read_field(&mut self) -> R<String> {
        let start = self.pos;
        let mut stop;
        loop {
            stop = self.pos;
            let ch = match self.read_byte() {
                Err(Fail::Eof) if stop > start => break,
                Err(e) => return Err(e),
                Ok(ch) => ch,
            };
            if is_newline(ch) {
                self.unread_byte();
                break;
            }
            if is_whitespace(ch) {
                self.read_whitespace();
                break;
            }
        }
        Ok(self.text_at(start, stop).into_owned())
    }

    /// [`read_field`](Self::read_field) without the allocation for short fields: a token of up to
    /// 23 bytes (nearly every one on an `m=` or `c=` line) is stored inline.
    fn read_field_small(&mut self) -> R<SmolStr> {
        let start = self.pos;
        let mut stop;
        loop {
            stop = self.pos;
            let ch = match self.read_byte() {
                Err(Fail::Eof) if stop > start => break,
                Err(e) => return Err(e),
                Ok(ch) => ch,
            };
            if is_newline(ch) {
                self.unread_byte();
                break;
            }
            if is_whitespace(ch) {
                self.read_whitespace();
                break;
            }
        }
        Ok(SmolStr::new(self.text_at(start, stop)))
    }

    /// How many `a=` lines come before the next `m=` line (or the end), counted from here, so the
    /// attribute list can be sized once instead of growing by doubling: a browser's media section
    /// holds a hundred or more, and each doubling copies everything so far.
    fn count_attributes(&self) -> usize {
        let mut rest = &self.value[self.pos.min(self.value.len())..];
        let mut count = 0;
        while !rest.is_empty() {
            let line_end = memchr::memchr(b'\n', rest).map_or(rest.len(), |i| i + 1);
            let line = rest[..line_end].trim_ascii_start();
            if line.starts_with(b"m=") {
                break;
            }
            if line.starts_with(b"a=") {
                count += 1;
            }
            rest = &rest[line_end..];
        }
        count
    }

    fn read_required_field(&mut self) -> R<String> {
        let field = self.read_field()?;
        if field.is_empty() {
            return Err(Fail::FieldMissing);
        }
        Ok(field)
    }

    /// Returns the bytes until the end of the line.
    fn read_line(&mut self) -> R<String> {
        Ok(self.read_line_lossy()?.into_owned())
    }

    /// Like [`read_line`](Self::read_line), but borrows from the input when it is valid UTF-8, so
    /// a caller that only needs to split the line does not pay for a copy of all of it first.
    fn read_line_lossy(&mut self) -> R<std::borrow::Cow<'a, str>> {
        let input: &'a [u8] = self.value;
        let start = self.pos;
        let Some(len) = memchr::memchr(b'\n', &input[start..]) else {
            // No terminator: the line runs off the end of the input.
            self.pos = input.len();
            return Err(Fail::Eof);
        };
        let newline = start + len;
        self.pos = newline + 1;
        // pion trims the terminator by counting: one for the `\n` plus one for every `\r` seen on
        // the line, wherever it is. Reproduced exactly, including for a stray `\r` mid-line.
        // The common cases (no `\r`, or a single one right before the `\n`) cost one search.
        let line = &input[start..newline];
        let carriage_returns = match memchr::memchr(b'\r', line) {
            None => 0,
            Some(first) => 1 + line[first + 1..].iter().filter(|&&b| b == b'\r').count(),
        };
        let end = (self.pos.saturating_sub(1 + carriage_returns)).max(start);
        Ok(self.text_at(start, end))
    }

    /// The text of `value[start..end]`: borrowed when the input is valid UTF-8 and the range
    /// falls on character boundaries (trimming by count can, in principle, cut a multi-byte
    /// character in two), converted lossily otherwise.
    fn text_at(&self, start: usize, end: usize) -> std::borrow::Cow<'a, str> {
        if let Some(text) = self.text
            && let Some(slice) = text.get(start..end)
        {
            return std::borrow::Cow::Borrowed(slice);
        }
        String::from_utf8_lossy(&self.value[start..end])
    }

    fn read_type(&mut self) -> R<u8> {
        loop {
            let first = self.read_byte()?;
            if is_newline(first) {
                continue;
            }
            let second = self.read_byte()?;
            if second != b'=' {
                return Err(self.syntax_error());
            }
            return Ok(first);
        }
    }

    /// Reads the next line type and picks the handler `pick` allows for it; any other type is
    /// a syntax error.
    fn handle_type(&mut self, pick: fn(u8) -> Option<StateFn>) -> R<Option<State>> {
        match self.read_type() {
            Ok(key) => match pick(key) {
                Some(f) => Ok(Some(State(f))),
                None => Err(self.syntax_error()),
            },
            // pion treats a clean end of input between lines as the end of the document.
            Err(Fail::Eof) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn last_media(&mut self) -> &mut MediaDescription {
        self.desc
            .media_descriptions
            .last_mut()
            .expect("states reaching a media line follow an m= line")
    }

    fn unmarshal_connection_information(&mut self) -> R<ConnectionInformation> {
        let network_type = self.read_field_small()?;
        if network_type != "IN" {
            return Err(Fail::Value(network_type.into()));
        }
        let address_type = self.read_field_small()?;
        if address_type != "IP4" && address_type != "IP6" {
            return Err(Fail::Value(address_type.into()));
        }
        let address = self.read_field_small()?;
        let address = if address.is_empty() {
            None
        } else {
            Some(Address {
                address,
                ..Default::default()
            })
        };
        self.next_line()?;
        Ok(ConnectionInformation {
            network_type,
            address_type,
            address,
        })
    }
}

pub(super) fn unmarshal_bytes(value: &[u8]) -> Result<SessionDescription> {
    let mut lex = Lexer {
        value,
        text: std::str::from_utf8(value).ok(),
        pos: 0,
        desc: SessionDescription::default(),
    };
    let mut state = Some(State(s1));
    while let Some(State(f)) = state {
        state = f(&mut lex)?;
    }
    Ok(lex.desc)
}

macro_rules! state {
    ($name:ident, $( $key:literal => $f:ident ),+ $(,)?) => {
        fn $name(l: &mut Lexer<'_>) -> R<Option<State>> {
            l.handle_type(|key| match key {
                $( $key => Some($f), )+
                _ => None,
            })
        }
    };
}

state!(s1, b'v' => unmarshal_protocol_version);
state!(s2, b'o' => unmarshal_origin);
state!(s3, b's' => unmarshal_session_name);
state!(s4,
    b'i' => unmarshal_session_information,
    b'u' => unmarshal_uri,
    b'e' => unmarshal_email,
    b'p' => unmarshal_phone,
    b'c' => unmarshal_session_connection_information,
    b'b' => unmarshal_session_bandwidth,
    b't' => unmarshal_timing,
);
state!(s5, b'b' => unmarshal_session_bandwidth, b't' => unmarshal_timing);
state!(s6,
    b'p' => unmarshal_phone,
    b'c' => unmarshal_session_connection_information,
    b'b' => unmarshal_session_bandwidth,
    b't' => unmarshal_timing,
);
state!(s7,
    b'u' => unmarshal_uri,
    b'e' => unmarshal_email,
    b'p' => unmarshal_phone,
    b'c' => unmarshal_session_connection_information,
    b'b' => unmarshal_session_bandwidth,
    b't' => unmarshal_timing,
);
state!(s8,
    b'c' => unmarshal_session_connection_information,
    b'b' => unmarshal_session_bandwidth,
    b't' => unmarshal_timing,
);
state!(s9,
    b'z' => unmarshal_time_zones,
    b'k' => unmarshal_session_encryption_key,
    b'a' => unmarshal_session_attribute,
    b'r' => unmarshal_repeat_times,
    b't' => unmarshal_timing,
    b'm' => unmarshal_media_description,
);
state!(s10,
    b'e' => unmarshal_email,
    b'p' => unmarshal_phone,
    b'c' => unmarshal_session_connection_information,
    b'b' => unmarshal_session_bandwidth,
    b't' => unmarshal_timing,
);
state!(s11, b'a' => unmarshal_session_attribute, b'm' => unmarshal_media_description);
state!(s12,
    b'a' => unmarshal_media_attribute,
    b'k' => unmarshal_media_encryption_key,
    b'b' => unmarshal_media_bandwidth,
    b'c' => unmarshal_media_connection_information,
    b'i' => unmarshal_media_title,
    b'm' => unmarshal_media_description,
);
state!(s13,
    b'a' => unmarshal_session_attribute,
    b'k' => unmarshal_session_encryption_key,
    b'm' => unmarshal_media_description,
);
state!(s14,
    b'a' => unmarshal_media_attribute,
    b'k' => unmarshal_media_encryption_key,
    b'b' => unmarshal_media_bandwidth,
    b'c' => unmarshal_media_connection_information,
    b'i' => unmarshal_media_title,
    b'm' => unmarshal_media_description,
);
state!(s15,
    b'a' => unmarshal_media_attribute,
    b'k' => unmarshal_media_encryption_key,
    b'b' => unmarshal_media_bandwidth,
    b'c' => unmarshal_media_connection_information,
    b'i' => unmarshal_media_title,
    b'm' => unmarshal_media_description,
);
state!(s16,
    b'a' => unmarshal_media_attribute,
    b'k' => unmarshal_media_encryption_key,
    b'c' => unmarshal_media_connection_information,
    b'b' => unmarshal_media_bandwidth,
    b'i' => unmarshal_media_title,
    b'm' => unmarshal_media_description,
);

fn next(f: StateFn) -> R<Option<State>> {
    Ok(Some(State(f)))
}

fn unmarshal_protocol_version(l: &mut Lexer<'_>) -> R<Option<State>> {
    let version = l.read_uint64_field()?;
    // JSEP requires the version to be 0.
    // https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-24#section-5.8.1
    if version != 0 {
        return Err(Fail::Value(version.to_string()));
    }
    l.next_line()?;
    next(s2)
}

fn unmarshal_origin(l: &mut Lexer<'_>) -> R<Option<State>> {
    l.desc.origin.username = l.read_field()?;
    l.desc.origin.session_id = l.read_uint64_field()?;
    l.desc.origin.session_version = l.read_uint64_field()?;
    l.desc.origin.network_type = l.read_field()?;
    if l.desc.origin.network_type != "IN" {
        return Err(Fail::Value(l.desc.origin.network_type.clone()));
    }

    // A missing address type or address gets a default, for IP-camera compatibility.
    match l.read_required_field() {
        Ok(t) => l.desc.origin.address_type = t,
        Err(Fail::FieldMissing) => {
            l.desc.origin.address_type = "IP4".into();
            l.desc.origin.unicast_address = "0.0.0.0".into();
        }
        Err(e) => return Err(e),
    }
    if l.desc.origin.address_type != "IP4" && l.desc.origin.address_type != "IP6" {
        return Err(Fail::Value(l.desc.origin.address_type.clone()));
    }

    match l.read_required_field() {
        Ok(a) => l.desc.origin.unicast_address = a,
        Err(Fail::FieldMissing) => {
            l.desc.origin.unicast_address = if l.desc.origin.address_type == "IP6" {
                "::".into()
            } else {
                "0.0.0.0".into()
            };
        }
        Err(e) => return Err(e),
    }

    l.next_line()?;
    next(s3)
}

fn unmarshal_session_name(l: &mut Lexer<'_>) -> R<Option<State>> {
    l.desc.session_name = l.read_line()?;
    next(s4)
}

fn unmarshal_session_information(l: &mut Lexer<'_>) -> R<Option<State>> {
    l.desc.session_information = Some(l.read_line()?);
    next(s7)
}

fn unmarshal_uri(l: &mut Lexer<'_>) -> R<Option<State>> {
    let value = l.read_line()?;
    if !is_valid_uri(&value) {
        return Err(Fail::Url(value));
    }
    l.desc.uri = Some(value);
    next(s10)
}

fn unmarshal_email(l: &mut Lexer<'_>) -> R<Option<State>> {
    l.desc.email_address = Some(l.read_line()?);
    next(s6)
}

fn unmarshal_phone(l: &mut Lexer<'_>) -> R<Option<State>> {
    l.desc.phone_number = Some(l.read_line()?);
    next(s8)
}

fn unmarshal_session_connection_information(l: &mut Lexer<'_>) -> R<Option<State>> {
    l.desc.connection_information = Some(l.unmarshal_connection_information()?);
    next(s5)
}

fn unmarshal_bandwidth(value: &str) -> R<Bandwidth> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 2 {
        return Err(Fail::Value(value.to_owned()));
    }
    let (experimental, kind) = match parts[0].strip_prefix("X-") {
        Some(rest) => (true, rest),
        None => {
            if !matches!(parts[0], "CT" | "AS" | "TIAS" | "RS" | "RR") {
                return Err(Fail::Value(parts[0].to_owned()));
            }
            (false, parts[0])
        }
    };
    let bandwidth = parts[1]
        .parse::<u64>()
        .ok()
        .filter(|_| parts[1].bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| Fail::Numeric(parts[1].to_owned()))?;
    Ok(Bandwidth {
        experimental,
        bandwidth_type: kind.to_owned(),
        bandwidth,
    })
}

fn unmarshal_session_bandwidth(l: &mut Lexer<'_>) -> R<Option<State>> {
    let value = l.read_line()?;
    let bandwidth = unmarshal_bandwidth(&value).map_err(|_| Fail::Value(format!("b={value}")))?;
    l.desc.bandwidth.push(bandwidth);
    next(s5)
}

fn unmarshal_timing(l: &mut Lexer<'_>) -> R<Option<State>> {
    let start_time = l.read_uint64_field()?;
    let stop_time = l.read_uint64_field()?;
    l.next_line()?;
    l.desc.time_descriptions.push(TimeDescription {
        timing: Timing {
            start_time,
            stop_time,
        },
        repeat_times: vec![],
    });
    next(s9)
}

fn unmarshal_repeat_times(l: &mut Lexer<'_>) -> R<Option<State>> {
    let field = l.read_field()?;
    let interval = parse_time_units(&field)?;
    let field = l.read_field()?;
    let duration = parse_time_units(&field)?;
    let mut offsets = vec![];
    loop {
        let field = l.read_field()?;
        if field.is_empty() {
            break;
        }
        offsets.push(parse_time_units(&field)?);
    }
    l.next_line()?;
    // `r=` is only reachable after a `t=`, so a time description always exists.
    if let Some(td) = l.desc.time_descriptions.last_mut() {
        td.repeat_times.push(RepeatTime {
            interval,
            duration,
            offsets,
        });
    }
    next(s9)
}

fn unmarshal_time_zones(l: &mut Lexer<'_>) -> R<Option<State>> {
    // z=<adjustment time> <offset> <adjustment time> <offset> ...
    loop {
        let adjustment_time = l.read_uint64_field()?;
        let offset = l.read_field()?;
        if offset.is_empty() {
            break;
        }
        let offset = parse_time_units(&offset)?;
        l.desc.time_zones.push(TimeZone {
            adjustment_time,
            offset,
        });
    }
    l.next_line()?;
    next(s13)
}

fn unmarshal_session_encryption_key(l: &mut Lexer<'_>) -> R<Option<State>> {
    l.desc.encryption_key = Some(l.read_line()?);
    next(s11)
}

fn attribute_from(line: std::borrow::Cow<'_, str>) -> Attribute {
    match memchr::memchr(b':', line.as_bytes()) {
        // pion keeps `a=foo:` as a flag attribute, indistinguishable from `a=foo`.
        Some(i) if i > 0 && i + 1 < line.len() => Attribute {
            key: SmolStr::new(&line[..i]),
            value: Some(SmolStr::new(&line[i + 1..])),
        },
        Some(i) if i > 0 => Attribute {
            key: SmolStr::new(&line[..i]),
            value: None,
        },
        _ => Attribute {
            key: SmolStr::new(&*line),
            value: None,
        },
    }
}

fn unmarshal_session_attribute(l: &mut Lexer<'_>) -> R<Option<State>> {
    if l.desc.attributes.is_empty() {
        let n = l.count_attributes();
        l.desc.attributes.reserve_exact(n);
    }
    let value = l.read_line_lossy()?;
    l.desc.attributes.push(attribute_from(value));
    next(s11)
}

fn parse_port(value: &str) -> R<isize> {
    let port: isize = go_atoi(value).ok_or_else(|| Fail::Port(value.to_owned()))?;
    if !(0..=65535).contains(&port) {
        return Err(Fail::Port(value.to_owned()));
    }
    Ok(port)
}

/// `strconv.Atoi`: an optional sign followed by one or more digits, nothing else.
fn go_atoi(s: &str) -> Option<isize> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn unmarshal_media_description(l: &mut Lexer<'_>) -> R<Option<State>> {
    let mut md = MediaDescription::default();

    let field = l.read_field_small()?;
    if !matches!(
        field.as_str(),
        "audio" | "video" | "text" | "application" | "message"
    ) {
        return Err(Fail::Value(field.into()));
    }
    md.media_name.media = field;

    let field = l.read_field_small()?;
    let mut parts = field.split('/');
    let first = parts.next().unwrap_or("");
    md.media_name.port.value = parse_port(first)?;
    if let Some(range) = parts.next() {
        md.media_name.port.range = Some(go_atoi(range).ok_or_else(|| Fail::Value(field.to_string()))?);
    }

    // RFC 8866 §5.14: <proto> is an extensible token, so unregistered protocols are accepted
    // (pion rejects them); an empty token, as in `//`, is still malformed.
    let field = l.read_field_small()?;
    for proto in field.split('/') {
        if proto.is_empty() {
            return Err(Fail::Numeric(field.to_string()));
        }
        md.media_name.protos.push(SmolStr::new(proto));
    }

    // One format per remaining token on the line: a browser's video section lists a dozen or
    // more, and growing the list by doubling costs several allocations.
    {
        let rest = &l.value[l.pos.min(l.value.len())..];
        let line = &rest[..memchr::memchr(b'\n', rest).unwrap_or(rest.len())];
        md.media_name.formats.reserve_exact(line.split(|b| *b == b' ').filter(|t| !t.is_empty()).count());
    }
    loop {
        let field = l.read_field_small()?;
        if field.is_empty() {
            break;
        }
        md.media_name.formats.push(field);
    }

    l.next_line()?;
    md.attributes.reserve_exact(l.count_attributes());
    l.desc.media_descriptions.push(md);
    next(s12)
}

fn unmarshal_media_title(l: &mut Lexer<'_>) -> R<Option<State>> {
    let value = l.read_line()?;
    l.last_media().media_title = Some(value);
    next(s16)
}

fn unmarshal_media_connection_information(l: &mut Lexer<'_>) -> R<Option<State>> {
    let ci = l.unmarshal_connection_information()?;
    l.last_media().connection_information = Some(ci);
    next(s15)
}

fn unmarshal_media_bandwidth(l: &mut Lexer<'_>) -> R<Option<State>> {
    let value = l.read_line()?;
    let bandwidth =
        unmarshal_bandwidth(&value).map_err(|_| Fail::Syntax(l.pos.saturating_sub(1)))?;
    l.last_media().bandwidth.push(bandwidth);
    next(s15)
}

fn unmarshal_media_encryption_key(l: &mut Lexer<'_>) -> R<Option<State>> {
    let value = l.read_line()?;
    l.last_media().encryption_key = Some(value);
    next(s14)
}

fn unmarshal_media_attribute(l: &mut Lexer<'_>) -> R<Option<State>> {
    let value = l.read_line_lossy()?;
    l.last_media().attributes.push(attribute_from(value));
    next(s14)
}

fn parse_time_units(value: &str) -> R<i64> {
    let invalid = || Fail::Value(value.to_owned());
    let last = *value.as_bytes().last().ok_or_else(invalid)?;
    let (digits, unit): (&str, i64) = match last {
        b'd' => (&value[..value.len() - 1], 86400),
        b'h' => (&value[..value.len() - 1], 3600),
        b'm' => (&value[..value.len() - 1], 60),
        b's' => (&value[..value.len() - 1], 1),
        _ => (value, 1),
    };
    let num = go_parse_i64(digits).ok_or_else(invalid)?;
    // pion wraps on overflow; a wrapped time is a wrong time, so refuse it.
    num.checked_mul(unit).ok_or_else(invalid)
}

/// `strconv.ParseInt(s, 10, 64)`.
fn go_parse_i64(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Accepts what Go's `url.Parse` accepts, for the inputs `u=` lines realistically carry: no
/// control characters, a scheme made of scheme characters, no colon in the first path
/// segment of a scheme-less reference, well-formed percent escapes and a numeric port.
fn is_valid_uri(raw: &str) -> bool {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let bytes = raw.as_bytes();
    let mut scheme_end = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if i > 0 => {}
            b':' => {
                if i == 0 {
                    return false;
                }
                scheme_end = Some(i);
                break;
            }
            _ => break,
        }
    }
    let rest = match scheme_end {
        Some(i) => &raw[i + 1..],
        None => {
            let colon = raw.find(':');
            let slash = raw.find('/');
            if let Some(c) = colon
                && slash.is_none_or(|s| c < s)
            {
                return false;
            }
            raw
        }
    };
    // Percent escapes must be %XX.
    let rb = rest.as_bytes();
    let mut i = 0;
    while i < rb.len() {
        if rb[i] == b'%' {
            let hex = rb.get(i + 1..i + 3);
            if !hex.is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    // A numeric port after the host, when there is an authority.
    if let Some(auth) = rest.strip_prefix("//") {
        let auth = auth.split(['/', '?', '#']).next().unwrap_or("");
        let host_port = auth.rsplit('@').next().unwrap_or("");
        if !host_port.starts_with('[')
            && let Some((_, port)) = host_port.rsplit_once(':')
            && !port.bytes().all(|b| b.is_ascii_digit())
        {
            return false;
        }
    }
    true
}
