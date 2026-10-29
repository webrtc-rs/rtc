//! DNS-SD (RFC 6763) helper layer: service-instance naming, validation and
//! record construction.
//!
//! This module ports the pure helper layer of pion/mdns's DNS-SD support
//! (`dns_sd.go` and `records.go`): the naming rules for service instances,
//! TXT entry encoding, and the builders/parsers for the DNS resource records
//! (PTR, SRV, TXT, A, AAAA) that a DNS-SD responder emits. Everything here is
//! pure computation — no sockets, no clock, no protocol state machine — so the
//! later client/server work (browsing, advertising) can build on it.
//!
//! Ported from <https://github.com/pion/mdns/tree/v2.2.2> (files `dns_sd.go`,
//! `records.go` and their tests); observable behaviour — what is accepted,
//! rejected, and the exact bytes of every built record — matches pion.

pub(crate) mod records;

#[cfg(test)]
mod dnssd_test;

pub use records::{
    BROWSE_TTL, MAX_TXT_STRING_LEN, TxtEntry, decode_txt_record_strings, encode_txt_record_strings,
    new_txt_binary, new_txt_flag, new_txt_string, validate_txt_entries,
};

use shared::error::{Error, Result};

/// The meta-query name for discovering all service types on the network
/// (RFC 6763 §9).
///
/// A PTR query for `_services._dns-sd._udp.<domain>` yields PTR records whose
/// rdata is the two-label `<Service>` name plus the domain.
pub const SERVICE_TYPE_ENUMERATION_NAME: &str = "_services._dns-sd._udp";

/// The maximum length of a DNS label (RFC 1035 §2.3.4), which constrains the
/// instance portion of a service instance name.
pub const MAX_INSTANCE_NAME_LEN: usize = 63;

/// A DNS-SD service instance (RFC 6763).
///
/// A service instance is identified by
/// `<Instance>.<Service>.<Domain>`, for example:
///
/// ```text
/// Instance: "My Web Server"
/// Service:  "_http._tcp"
/// Domain:   "local"
/// Host:     "myhost.local."
/// Port:     8080
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceInstance {
    /// The user-friendly name (UTF-8, max 63 bytes after encoding).
    ///
    /// May contain dots and other punctuation (RFC 6763 §4.1.1).
    pub instance: String,

    /// The service type, e.g. `_http._tcp`.
    ///
    /// Must be in the form `_<name>._<proto>` where proto is `tcp` or `udp`.
    pub service: String,

    /// The DNS domain, typically `local` for mDNS.
    pub domain: String,

    /// The target hostname for the SRV record (e.g. `myhost.local.`).
    pub host: String,

    /// The TCP or UDP port number.
    pub port: u16,

    /// The SRV priority field (lower = preferred). Default 0.
    pub priority: u16,

    /// The SRV weight field. Default 0.
    pub weight: u16,

    /// The key/value pairs for the TXT record.
    pub text: Vec<TxtEntry>,
}

impl ServiceInstance {
    /// Returns the fully-qualified DNS name for this instance.
    ///
    /// Dots and backslashes in the instance portion are escaped per
    /// RFC 6763 §4.3: literal dots become `\.` and literal backslashes
    /// become `\\`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rtc_mdns::dnssd::ServiceInstance;
    ///
    /// let si = ServiceInstance {
    ///     instance: "My.Web".to_owned(),
    ///     service: "_http._tcp".to_owned(),
    ///     domain: "local".to_owned(),
    ///     ..Default::default()
    /// };
    /// assert_eq!(si.service_instance_name(), r"My\.Web._http._tcp.local.");
    /// ```
    pub fn service_instance_name(&self) -> String {
        let escaped = escape_instance_name(&self.instance);
        format!("{escaped}.{}.{}.", self.service, self.domain)
    }

    /// Returns the `<Service>.<Domain>` browsing name (e.g. `_http._tcp.local.`).
    pub fn service_name(&self) -> String {
        format!("{}.{}.", self.service, self.domain)
    }
}

/// Escapes dots and backslashes in an instance name for safe concatenation
/// into a DNS name string (RFC 6763 §4.3).
///
/// Literal dots become `\.` and literal backslashes become `\\`.
pub fn escape_instance_name(instance: &str) -> String {
    // Fast path: no escaping needed.
    if !instance.contains(['.', '\\']) {
        return instance.to_owned();
    }

    let mut buf = String::with_capacity(instance.len() + 4);
    for c in instance.chars() {
        match c {
            '.' => buf.push_str(r"\."),
            '\\' => buf.push_str(r"\\"),
            _ => buf.push(c),
        }
    }
    buf
}

/// Reverses the escaping applied by [`escape_instance_name`]:
/// `\.` becomes `.` and `\\` becomes `\`.
///
/// A trailing lone backslash is kept as-is, exactly as pion does.
pub fn unescape_instance_name(escaped: &str) -> String {
    if !escaped.contains('\\') {
        return escaped.to_owned();
    }

    // Backslash removal cannot split a UTF-8 sequence (`\` is ASCII and never
    // part of a multi-byte character), so the output of this loop over a
    // valid `&str` is always valid UTF-8 and the lossy conversion is exact.
    let src = escaped.as_bytes();
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\' && i + 1 < src.len() {
            i += 1;
            out.push(src[i]);
        } else {
            out.push(src[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits a string on dots that are NOT preceded by a backslash.
///
/// Escape sequences (`\.` and `\\`) are kept intact inside the labels.
pub fn split_escaped_dots(input: &str) -> Vec<String> {
    let src = input.as_bytes();
    let mut labels = Vec::new();
    let mut current = Vec::new();
    let mut i = 0;
    while i < src.len() {
        if src[i] == b'\\' && i + 1 < src.len() {
            // Escaped character: keep both the backslash and the next char.
            current.push(src[i]);
            i += 1;
            current.push(src[i]);
        } else if src[i] == b'.' {
            // Labels are valid UTF-8 (dots and backslashes are ASCII), so the
            // lossy conversion here is exact.
            labels.push(String::from_utf8_lossy(&current).into_owned());
            current.clear();
        } else {
            current.push(src[i]);
        }
        i += 1;
    }
    labels.push(String::from_utf8_lossy(&current).into_owned());
    labels
}

/// The components of a parsed service instance name.
///
/// Returned by [`parse_service_instance_name`].
pub type ParsedServiceInstanceName = (String, String, String);

/// Splits a fully-qualified DNS name into its instance, service, and domain
/// components.
///
/// The expected format is `<Instance>.<_name>.<_proto>.<Domain>.` — dots
/// within the instance portion must be escaped as `\.` (RFC 6763 §4.3).
/// The trailing dot is optional.
///
/// # Errors
///
/// Returns [`Error::ErrInvalidServiceName`] if the name has too few labels,
/// no `_name._proto` pair, or an empty component.
pub fn parse_service_instance_name(name: &str) -> Result<ParsedServiceInstanceName> {
    // Strip trailing dot.
    let name = name.strip_suffix('.').unwrap_or(name);

    // Split on unescaped dots. We need at least 4 labels:
    // <instance>, <_name>, <_proto>, <domain...>
    let labels = split_escaped_dots(name);
    if labels.len() < 4 {
        return Err(Error::ErrInvalidServiceName);
    }

    // The service is always the two labels starting with underscore.
    // The instance is everything before it, the domain is everything after.
    let mut service_idx: Option<usize> = None;
    for i in 1..labels.len() - 1 {
        if labels[i].starts_with('_') && labels[i + 1].starts_with('_') {
            service_idx = Some(i);
            break;
        }
    }
    let service_idx = match service_idx {
        Some(idx) if idx >= 1 && idx + 2 <= labels.len() => idx,
        _ => return Err(Error::ErrInvalidServiceName),
    };

    // Instance: rejoin labels before service_idx (unescaped).
    let instance = unescape_instance_name(&labels[..service_idx].join("."));

    let service = format!("{}.{}", labels[service_idx], labels[service_idx + 1]);
    let domain = labels[service_idx + 2..].join(".");

    if instance.is_empty() || service.is_empty() || domain.is_empty() {
        return Err(Error::ErrInvalidServiceName);
    }

    Ok((instance, service, domain))
}

/// Checks that a service string like `_http._tcp` follows the DNS-SD service
/// naming rules (RFC 6763 §7, RFC 6335):
///
/// - Format: `_<name>._<proto>` (proto must be `_tcp` or `_udp`)
/// - Name: 1-15 characters (not counting the underscore prefix)
/// - Name: letters, digits, hyphens only
/// - Name: must begin and end with a letter or digit
/// - Name: must not contain consecutive hyphens
/// - Name: must contain at least one letter
///
/// # Errors
///
/// Returns [`Error::ErrInvalidServiceName`] on any violation.
pub fn validate_service_name(service: &str) -> Result<()> {
    let (name_part, proto_part) = service
        .split_once('.')
        .ok_or(Error::ErrInvalidServiceName)?;

    validate_service_proto(proto_part)?;
    validate_service_label(name_part)
}

/// Checks that the protocol label is `_tcp` or `_udp`.
///
/// # Errors
///
/// Returns [`Error::ErrInvalidServiceName`] for any other value.
pub fn validate_service_proto(proto: &str) -> Result<()> {
    if proto != "_tcp" && proto != "_udp" {
        return Err(Error::ErrInvalidServiceName);
    }
    Ok(())
}

/// Checks the `_<name>` portion of a service name.
///
/// # Errors
///
/// Returns [`Error::ErrInvalidServiceName`] if the label does not start with
/// `_`, the name is empty or longer than 15 characters, does not begin and
/// end with a letter or digit, or contains an invalid character.
pub fn validate_service_label(label: &str) -> Result<()> {
    let name = label
        .strip_prefix('_')
        .ok_or(Error::ErrInvalidServiceName)?;

    if name.is_empty() || name.len() > 15 {
        return Err(Error::ErrInvalidServiceName);
    }

    // Must begin and end with letter or digit.
    let bytes = name.as_bytes();
    if !is_letter_or_digit(bytes[0]) || !is_letter_or_digit(bytes[bytes.len() - 1]) {
        return Err(Error::ErrInvalidServiceName);
    }

    validate_service_name_chars(name)
}

/// Checks individual characters in a service name: letters, digits, hyphens
/// only; no consecutive hyphens; at least one letter.
///
/// # Errors
///
/// Returns [`Error::ErrInvalidServiceName`] on any violation.
pub fn validate_service_name_chars(name: &str) -> Result<()> {
    let mut has_letter = false;
    let mut prev_hyphen = false;

    for &c in name.as_bytes() {
        if is_letter(c) {
            has_letter = true;
            prev_hyphen = false;
        } else if is_digit(c) {
            prev_hyphen = false;
        } else if c == b'-' {
            if prev_hyphen {
                return Err(Error::ErrInvalidServiceName); // consecutive hyphens
            }
            prev_hyphen = true;
        } else {
            return Err(Error::ErrInvalidServiceName); // invalid character
        }
    }

    if !has_letter {
        return Err(Error::ErrInvalidServiceName);
    }

    Ok(())
}

/// Checks that an instance name is valid per RFC 6763 §4.1.1:
///
/// - Must not be empty
/// - Must not exceed 63 bytes when UTF-8 encoded
/// - Must not contain ASCII control characters (0x00-0x1F, 0x7F)
///
/// # Errors
///
/// Returns the matching [`Error`] variant for each violation. (pion also
/// verifies UTF-8 validity here; a Rust `&str` is always valid UTF-8, so
/// that check is vacuous in this port.)
pub fn validate_instance_name(instance: &str) -> Result<()> {
    if instance.is_empty() {
        return Err(Error::ErrInstanceNameEmpty);
    }

    if instance.len() > MAX_INSTANCE_NAME_LEN {
        return Err(Error::ErrInstanceNameTooLong);
    }

    for &b in instance.as_bytes() {
        if b <= 0x1F || b == 0x7F {
            return Err(Error::ErrInstanceNameHasControl);
        }
    }

    Ok(())
}

fn is_letter(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_uppercase()
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

fn is_letter_or_digit(c: u8) -> bool {
    is_letter(c) || is_digit(c)
}
