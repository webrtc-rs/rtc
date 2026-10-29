//! DNS-SD TXT entries and DNS resource-record builders/parsers.
//!
//! Port of pion/mdns v2.2.2 `records.go`: the [`TxtEntry`] key/value model of
//! RFC 6763 §6, its string encoding/decoding rules, and the builders that
//! turn service data into PTR/SRV/TXT/A/AAAA [`Resource`] records (plus the
//! matching parsers). Class is always IN; pion never sets the cache-flush bit
//! on records it builds (PTR is a shared record, RFC 6762 §10.2), and neither
//! do we.

use std::collections::HashSet;
use std::net::IpAddr;

use shared::error::{Error, Result};

use crate::message::name::Name;
use crate::message::resource::a::AResource;
use crate::message::resource::aaaa::AaaaResource;
use crate::message::resource::ptr::PtrResource;
use crate::message::resource::srv::SrvResource;
use crate::message::resource::txt::TxtResource;
use crate::message::resource::{Resource, ResourceBody, ResourceHeader};
use crate::message::{DNSCLASS_INET, DnsType};

/// The recommended TTL for non-host-scoped records (browsing PTR, TXT) per
/// RFC 6762 §10: 75 minutes = 4500 seconds.
pub const BROWSE_TTL: u32 = 4500;

/// The maximum length of a single constituent string within a DNS TXT record
/// (RFC 1035 §3.3.14: 1-byte length prefix → max 255 bytes).
pub const MAX_TXT_STRING_LEN: usize = 255;

/// A single key=value pair in a DNS-SD TXT record (RFC 6763 §6).
///
/// The key is case-insensitive, printable US-ASCII (0x20-0x7E) excluding `=`
/// (0x3D). The value is opaque bytes (often UTF-8).
///
/// A `value` of `None` indicates a boolean attribute — the key is simply
/// present with no value. A `Some` of a zero-length vector represents a key
/// with an explicitly empty value (e.g. `PlugIns=`).
///
/// Prefer the [`new_txt_string`], [`new_txt_binary`] and [`new_txt_flag`]
/// constructors over a struct literal: they map the three RFC 6763 §6.4
/// cases to distinct calls and avoid the `None`-vs-empty footgun.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtEntry {
    /// The case-insensitive key (printable US-ASCII, no `=`).
    pub key: String,
    /// The opaque value: `None` = boolean attribute (present, no value),
    /// `Some` (possibly empty) = explicit value.
    pub value: Option<Vec<u8>>,
}

/// Creates a TXT entry with a key and string value, encoded on the wire as
/// `key=value`. An empty value yields `key=` (RFC 6763 §6.4).
pub fn new_txt_string(key: &str, value: &str) -> TxtEntry {
    TxtEntry {
        key: key.to_owned(),
        value: Some(value.as_bytes().to_vec()),
    }
}

/// Creates a TXT entry with a key and an opaque binary value (RFC 6763 §6.5),
/// encoded on the wire as `key=<bytes>`.
///
/// Go normalizes a nil value to an explicit empty value (`key=`); the Rust
/// equivalent is passing an empty slice. Use [`new_txt_flag`] for a boolean
/// attribute that carries no value at all.
pub fn new_txt_binary(key: &str, value: &[u8]) -> TxtEntry {
    TxtEntry {
        key: key.to_owned(),
        value: Some(value.to_vec()),
    }
}

/// Creates a boolean TXT attribute: a key that is present with no value,
/// encoded on the wire as just `key` (RFC 6763 §6.4).
pub fn new_txt_flag(key: &str) -> TxtEntry {
    TxtEntry {
        key: key.to_owned(),
        value: None,
    }
}

/// Checks a slice of TXT entries against the DNS-SD rules
/// (RFC 6763 §6.4, §6.7):
///
/// - each key must be non-empty, contain no `=`, and be printable US-ASCII;
/// - each encoded `key=value` (or bare `key`) string must not exceed 255 bytes;
/// - keys must be unique, compared case-insensitively.
///
/// # Errors
///
/// Returns the first violation encountered.
pub fn validate_txt_entries(entries: &[TxtEntry]) -> Result<()> {
    let mut seen = HashSet::with_capacity(entries.len());
    for entry in entries {
        validate_txt_key(&entry.key)?;

        // Encoded length: "key=value" (with '=') or "key" (boolean attribute).
        let encoded_len = entry.key.len()
            + match &entry.value {
                Some(value) => 1 + value.len(), // '=' separator + value bytes
                None => 0,
            };
        if encoded_len > MAX_TXT_STRING_LEN {
            return Err(Error::ErrTXTStringTooLong);
        }

        let lower = entry.key.to_lowercase();
        if !seen.insert(lower) {
            return Err(Error::ErrTXTDuplicateKey);
        }
    }

    Ok(())
}

/// Checks a single TXT key against RFC 6763 §6.4: it must be non-empty, must
/// not contain `=` (0x3D), and must consist solely of printable US-ASCII
/// characters (0x20-0x7E).
///
/// # Errors
///
/// Returns the matching [`Error`] variant for each violation.
pub fn validate_txt_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::ErrTXTKeyEmpty);
    }

    for &c in key.as_bytes() {
        if c == b'=' {
            return Err(Error::ErrTXTKeyHasEquals);
        }
        if !(0x20..=0x7E).contains(&c) {
            return Err(Error::ErrTXTKeyNotASCII);
        }
    }

    Ok(())
}

/// Converts key/value pairs into the wire-format strings for a DNS TXT
/// resource record. Each entry becomes `key=value` or just `key` (boolean
/// attribute).
///
/// An empty input slice returns a single empty string, which represents the
/// minimum valid TXT record (RFC 6763 §6.1).
///
/// # Errors
///
/// Returns an error if any single encoded string exceeds 255 bytes
/// (RFC 1035 §3.3.14) or a key is empty. Values must be valid UTF-8: the
/// crate's TXT wire type is string-based, so non-UTF-8 binary values are
/// rejected with [`Error::ErrTXTValueNotUtf8`] (a known divergence from
/// pion, whose Go strings hold arbitrary bytes).
pub fn encode_txt_record_strings(pairs: &[TxtEntry]) -> Result<Vec<String>> {
    if pairs.is_empty() {
        return Ok(vec![String::new()]);
    }

    let mut out = Vec::with_capacity(pairs.len());
    for kv in pairs {
        if kv.key.is_empty() {
            return Err(Error::ErrTXTKeyEmpty);
        }

        let s = match &kv.value {
            // Boolean attribute: key only, no '='.
            None => kv.key.clone(),
            // key=value (value may be empty).
            Some(value) => {
                let value =
                    String::from_utf8(value.clone()).map_err(|_| Error::ErrTXTValueNotUtf8)?;
                format!("{}={}", kv.key, value)
            }
        };

        if s.len() > MAX_TXT_STRING_LEN {
            return Err(Error::ErrTXTStringTooLong);
        }
        out.push(s);
    }

    Ok(out)
}

/// Parses wire-format TXT record strings back into key/value pairs.
///
/// Duplicate keys are deduplicated: only the first occurrence is kept
/// (RFC 6763 §6.4). Strings where the key is empty (i.e. starting with `=`)
/// are silently ignored (RFC 6763 §6.4). Empty strings are skipped.
pub fn decode_txt_record_strings(ss: &[String]) -> Vec<TxtEntry> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for s in ss {
        if s.is_empty() {
            continue;
        }

        let kv = match s.split_once('=') {
            // key=value (split on the first '=' only; the value may itself
            // contain '=').
            Some((key, value)) => TxtEntry {
                key: key.to_owned(),
                value: Some(value.as_bytes().to_vec()),
            },
            // Boolean attribute (no '=').
            None => TxtEntry {
                key: s.clone(),
                value: None,
            },
        };

        // Empty key → silently ignore (RFC 6763 §6.4).
        if kv.key.is_empty() {
            continue;
        }

        // Deduplicate: case-insensitive, keep first (RFC 6763 §6.4).
        if !seen.insert(kv.key.to_lowercase()) {
            continue;
        }

        out.push(kv);
    }

    out
}

/// Creates a PTR resource record.
///
/// `name` is the query name (e.g. `_http._tcp.local.`); `target` is what the
/// PTR points to (e.g. `My Web._http._tcp.local.`). TTL is typically
/// [`BROWSE_TTL`] (4500) for browsing PTRs (RFC 6762 §10).
pub(crate) fn build_ptr_resource(name: &str, target: &str, ttl: u32) -> Result<Resource> {
    let ptr = PtrResource {
        ptr: Name::new(target)?,
    };

    Ok(Resource {
        header: ResourceHeader {
            name: Name::new(name)?,
            typ: DnsType::Ptr,
            class: DNSCLASS_INET,
            ttl,
            length: 0,
        },
        body: Some(Box::new(ptr)),
    })
}

/// Creates an SRV resource record.
///
/// `name` is the service instance FQDN (e.g. `My Web._http._tcp.local.`);
/// `target` is the hostname (e.g. `myhost.local.`). TTL is typically the
/// 120-second response TTL for host-scoped records (RFC 6762 §10).
pub(crate) fn build_srv_resource(
    name: &str,
    target: &str,
    port: u16,
    priority: u16,
    weight: u16,
    ttl: u32,
) -> Result<Resource> {
    let srv = SrvResource {
        priority,
        weight,
        port,
        target: Name::new(target)?, // Not compressed as per RFC 2782.
    };

    Ok(Resource {
        header: ResourceHeader {
            name: Name::new(name)?,
            typ: DnsType::Srv,
            class: DNSCLASS_INET,
            ttl,
            length: 0,
        },
        body: Some(Box::new(srv)),
    })
}

/// Creates a TXT resource record.
///
/// `name` is the service instance FQDN; `txts` contains the pre-encoded TXT
/// strings (each at most 255 bytes). TTL is typically [`BROWSE_TTL`] for TXT
/// records (RFC 6762 §10).
pub(crate) fn build_txt_resource(name: &str, txts: Vec<String>, ttl: u32) -> Result<Resource> {
    let txt = TxtResource { txt: txts };

    Ok(Resource {
        header: ResourceHeader {
            name: Name::new(name)?,
            typ: DnsType::Txt,
            class: DNSCLASS_INET,
            ttl,
            length: 0,
        },
        body: Some(Box::new(txt)),
    })
}

/// Creates an A resource record for an IPv4 address.
///
/// TTL is typically the 120-second response TTL for host address records
/// (RFC 6762 §10).
///
/// # Errors
///
/// Returns [`Error::ErrNotIPv4Address`] if `addr` is an IPv6 address.
pub(crate) fn build_a_resource(name: &str, addr: IpAddr, ttl: u32) -> Result<Resource> {
    let a = AResource {
        a: match addr {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => return Err(Error::ErrNotIPv4Address),
        },
    };

    Ok(Resource {
        header: ResourceHeader {
            name: Name::new(name)?,
            typ: DnsType::A,
            class: DNSCLASS_INET,
            ttl,
            length: 0,
        },
        body: Some(Box::new(a)),
    })
}

/// Creates an AAAA resource record for an IPv6 address.
///
/// # Errors
///
/// Returns [`Error::ErrNotIPv6Address`] if `addr` is an IPv4 address.
pub(crate) fn build_aaaa_resource(name: &str, addr: IpAddr, ttl: u32) -> Result<Resource> {
    let aaaa = AaaaResource {
        aaaa: match addr {
            IpAddr::V6(v6) => v6.octets(),
            IpAddr::V4(_) => return Err(Error::ErrNotIPv6Address),
        },
    };

    Ok(Resource {
        header: ResourceHeader {
            name: Name::new(name)?,
            typ: DnsType::Aaaa,
            class: DNSCLASS_INET,
            ttl,
            length: 0,
        },
        body: Some(Box::new(aaaa)),
    })
}

/// The fields of an SRV resource record, as extracted by [`parse_srv_data`].
pub(crate) struct SrvData {
    /// The target hostname.
    pub target: String,
    /// The port.
    pub port: u16,
    /// The priority.
    pub priority: u16,
    /// The weight.
    pub weight: u16,
}

/// Extracts the target name string from a PTR resource body.
///
/// # Errors
///
/// Returns [`Error::ErrNotPTRResource`] if the body is not a PTR record.
pub(crate) fn parse_ptr_target(body: &dyn ResourceBody) -> Result<String> {
    body.as_any()
        .downcast_ref::<PtrResource>()
        .ok_or(Error::ErrNotPTRResource)
        .map(|ptr| ptr.ptr.to_string())
}

/// Extracts the target hostname, port, priority, and weight from an SRV
/// resource body.
///
/// # Errors
///
/// Returns [`Error::ErrNotSRVResource`] if the body is not an SRV record.
pub(crate) fn parse_srv_data(body: &dyn ResourceBody) -> Result<SrvData> {
    body.as_any()
        .downcast_ref::<SrvResource>()
        .ok_or(Error::ErrNotSRVResource)
        .map(|srv| SrvData {
            target: srv.target.to_string(),
            port: srv.port,
            priority: srv.priority,
            weight: srv.weight,
        })
}

/// Extracts the string slice from a TXT resource body.
///
/// # Errors
///
/// Returns [`Error::ErrNotTXTResource`] if the body is not a TXT record.
pub(crate) fn parse_txt_data(body: &dyn ResourceBody) -> Result<Vec<String>> {
    body.as_any()
        .downcast_ref::<TxtResource>()
        .ok_or(Error::ErrNotTXTResource)
        .map(|txt| txt.txt.clone())
}
