#[cfg(test)]
mod keyschedule_test;

use crypto::{HashAlgorithm as CryptoHashAlgorithm, HmacAlgorithm, RTCCrypto};

use shared::error::*;

/// The label prefix every DTLS 1.3 key-schedule label carries: where TLS 1.3 writes
/// `"tls13 "`, DTLS 1.3 writes `"dtls13"` ([RFC 9147 §5.9]).
///
/// [RFC 9147 §5.9]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.9
pub const DTLS13_PREFIX: &str = "dtls13";

/// The minimum length of a prefixed label, as `opaque label<7..255>` ([RFC 8446 §7.1]).
const LABEL_MIN_LENGTH: usize = 7;
/// The maximum length of a prefixed label, as `opaque label<7..255>` ([RFC 8446 §7.1]).
const LABEL_MAX_LENGTH: usize = 255;
/// The maximum length of a context, as `opaque context<0..255>` ([RFC 8446 §7.1]).
const CONTEXT_MAX_LENGTH: usize = 255;

/// The hash function a DTLS 1.3 key schedule runs on. pion's keyschedule takes a Go
/// `func() hash.Hash`; this enum is its typed counterpart, and `None` at the call sites below
/// is pion's nil hash, which every function rejects.
///
/// Only SHA-256 is named today — the hash of the `TLS_AES_128_GCM_SHA256` suites. More
/// variants join when the provider grows their HMAC and plain digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyscheduleHash {
    /// SHA-256, the hash of the `TLS_AES_128_GCM_SHA256` cipher suites.
    Sha256,
}

impl KeyscheduleHash {
    /// The HMAC algorithm of this hash, which the provider's HKDF runs on.
    fn hmac_algorithm(self) -> HmacAlgorithm {
        match self {
            Self::Sha256 => HmacAlgorithm::Sha256,
        }
    }

    /// The plain digest algorithm of this hash.
    fn digest_algorithm(self) -> CryptoHashAlgorithm {
        match self {
            Self::Sha256 => CryptoHashAlgorithm::Sha256,
        }
    }

    /// The digest length in bytes.
    fn size(self) -> usize {
        self.hmac_algorithm().output_len()
    }
}

/// Extracts a pseudorandom key: HKDF-Extract ([RFC 5869 §2.2]), `PRK = HMAC-Hash(salt, IKM)`,
/// as pion's `keyschedule.HkdfExtract`.
///
/// # Errors
///
/// [`Error::ErrHkdfMissingHashFunction`] when `hash` is `None`, as pion rejects a nil hash
/// function, or the provider error of the underlying HMAC.
///
/// [RFC 5869 §2.2]: https://datatracker.ietf.org/doc/html/rfc5869#section-2.2
pub fn hkdf_extract(
    crypto: &dyn RTCCrypto,
    hash: Option<KeyscheduleHash>,
    salt: &[u8],
    ikm: &[u8],
) -> Result<Vec<u8>> {
    let hash = hash.ok_or(Error::ErrHkdfMissingHashFunction)?;
    crypto
        .hkdf_extract(hash.hmac_algorithm(), salt, ikm)
        .map_err(super::crypto_error)
}

/// Derives a key: HKDF-Expand-Label ([RFC 8446 §7.1]) with the `dtls13` label prefix
/// ([RFC 9147 §5.9]), as pion's `keyschedule.HkdfExpandLabel`.
///
/// # Errors
///
/// [`Error::ErrHkdfMissingHashFunction`] when `hash` is `None`,
/// [`Error::ErrHkdfLabelTooSmall`] when the prefixed label is shorter than 7 bytes,
/// [`Error::ErrHkdfLabelTooBig`] when it is longer than 255 bytes,
/// [`Error::ErrHkdfContextTooBig`] when `context` is longer than 255 bytes,
/// [`Error::ErrHkdfLengthTooBig`] when `length` exceeds one expansion (`255 * HashLen`), or
/// the provider error of the underlying HMAC.
///
/// [RFC 8446 §7.1]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
/// [RFC 9147 §5.9]: https://datatracker.ietf.org/doc/html/rfc9147#section-5.9
pub fn hkdf_expand_label(
    crypto: &dyn RTCCrypto,
    hash: Option<KeyscheduleHash>,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>> {
    let hash = hash.ok_or(Error::ErrHkdfMissingHashFunction)?;

    let full_label = format!("{DTLS13_PREFIX}{label}");
    let full_label = full_label.as_bytes();

    // RFC 8446 section 7.1: opaque label<7..255>
    if full_label.len() < LABEL_MIN_LENGTH {
        return Err(Error::ErrHkdfLabelTooSmall);
    } else if full_label.len() > LABEL_MAX_LENGTH {
        return Err(Error::ErrHkdfLabelTooBig);
    }

    if context.len() > CONTEXT_MAX_LENGTH {
        return Err(Error::ErrHkdfContextTooBig);
    }

    // RFC 5869 section 2.3: the length of output keying material in octets is bounded by
    // 255*HashLen.
    if length > hash.size() * 255 {
        return Err(Error::ErrHkdfLengthTooBig);
    }

    let hkdf_label = hkdf_label(length as u16, full_label, context);
    crypto
        .hkdf_expand(hash.hmac_algorithm(), secret, &hkdf_label, length)
        .map_err(super::crypto_error)
}

/// Encodes the `HkdfLabel` structure of [RFC 8446 §7.1]: a `u16` length, a `u8`-prefixed
/// label, and a `u8`-prefixed context.
///
/// [RFC 8446 §7.1]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
pub(crate) fn hkdf_label(length: u16, label: &[u8], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 1 + label.len() + 1 + context.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

/// Derives a secret ([RFC 8446 §7.1]) from `secret` and the transcript hash, as pion's
/// `keyschedule.DeriveSecret`: an `hkdf_expand_label` whose context is the transcript hash
/// and whose length is the hash's size.
///
/// `transcript_hash` is the transcript digest, as pion's `transcriptHash.Sum(nil)` would
/// return; `None` stands for pion's nil hash — a fresh hash over an empty transcript.
///
/// # Errors
///
/// [`Error::ErrHkdfMissingHashFunction`] when `hash` is `None`, or any error of
/// [`hkdf_expand_label`].
///
/// [RFC 8446 §7.1]: https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
pub fn derive_secret(
    crypto: &dyn RTCCrypto,
    hash: Option<KeyscheduleHash>,
    secret: &[u8],
    label: &str,
    transcript_hash: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let hash = hash.ok_or(Error::ErrHkdfMissingHashFunction)?;

    // pion passes transcriptHash.Sum(nil) as the context and transcriptHash.Size() as the
    // length; a nil hash becomes a fresh one, so the context is the digest of the empty
    // transcript.
    let context = match transcript_hash {
        Some(transcript_hash) => transcript_hash.to_vec(),
        None => crypto
            .hash(hash.digest_algorithm(), &[])
            .map_err(super::crypto_error)?,
    };

    hkdf_expand_label(crypto, Some(hash), secret, label, &context, hash.size())
}
