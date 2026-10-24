#[cfg(test)]
mod signature_hash_algorithm_13_test;
#[cfg(test)]
mod signature_hash_algorithm_test;

use std::fmt;

use crate::crypto::*;
use shared::error::*;

// HashAlgorithm is used to indicate the hash algorithm used
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-18
// Supported hash hash algorithms
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// The hash algorithms that may be paired with a signature algorithm.
#[non_exhaustive]
pub enum HashAlgorithm {
    /// `MD2` (`0`).
    Md2 = 0, // Blacklisted
    /// `MD5` (`1`).
    Md5 = 1, // Blacklisted
    /// `SHA1` (`2`).
    Sha1 = 2, // Blacklisted
    /// `SHA224` (`3`).
    Sha224 = 3,
    /// `SHA256` (`4`).
    Sha256 = 4,
    /// `SHA384` (`5`).
    Sha384 = 5,
    /// `SHA512` (`6`).
    Sha512 = 6,
    /// `ED25519` (`8`).
    Ed25519 = 8,
    /// An algorithm this crate does not implement.
    Unsupported,
}

impl From<u8> for HashAlgorithm {
    fn from(val: u8) -> Self {
        match val {
            0 => HashAlgorithm::Md2,
            1 => HashAlgorithm::Md5,
            2 => HashAlgorithm::Sha1,
            3 => HashAlgorithm::Sha224,
            4 => HashAlgorithm::Sha256,
            5 => HashAlgorithm::Sha384,
            6 => HashAlgorithm::Sha512,
            8 => HashAlgorithm::Ed25519,
            _ => HashAlgorithm::Unsupported,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HashAlgorithm::Md2 => write!(f, "md2"),
            HashAlgorithm::Md5 => write!(f, "md5"), // [RFC3279]
            HashAlgorithm::Sha1 => write!(f, "sha-1"), // [RFC3279]
            HashAlgorithm::Sha224 => write!(f, "sha-224"), // [RFC4055]
            HashAlgorithm::Sha256 => write!(f, "sha-256"), // [RFC4055]
            HashAlgorithm::Sha384 => write!(f, "sha-384"), // [RFC4055]
            HashAlgorithm::Sha512 => write!(f, "sha-512"), // [RFC4055]
            HashAlgorithm::Ed25519 => write!(f, "null"), // [RFC4055]
            _ => write!(f, "unknown or unsupported hash algorithm"),
        }
    }
}

impl HashAlgorithm {
    pub(crate) fn insecure(&self) -> bool {
        matches!(
            *self,
            HashAlgorithm::Md2 | HashAlgorithm::Md5 | HashAlgorithm::Sha1
        )
    }

    pub(crate) fn invalid(&self) -> bool {
        matches!(*self, HashAlgorithm::Md2)
    }
}

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// The signature algorithms this crate can verify and produce.
///
/// The TLS 1.2 algorithms are one-byte code points carried in the byte-split
/// `SignatureHashAlgorithm` pair. The RSA-PSS variants are full `u16` signature schemes
/// ([RFC 8446 §4.2.3]): they are negotiated whole in DTLS 1.3, are offered by
/// [`algorithms_13`], and cannot be encoded in the TLS 1.2 byte-split form.
///
/// [RFC 8446 §4.2.3]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.3
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// `ANONYMOUS` (`0`).
    Anonymous = 0,
    /// `RSA` (`1`).
    Rsa = 1,
    /// `ECDSA` (`3`).
    Ecdsa = 3,
    /// `ED25519` (`7`).
    Ed25519 = 7,
    /// `RSA_PSS_RSAE_SHA256` (`0x0804`): RSA-PSS with SHA-256 over a certificate carrying the
    /// standard `rsaEncryption` public-key OID. A TLS 1.3 signature scheme whose full `u16`
    /// value is carried whole in the hybrid encodings.
    RsaPssRsaeSha256 = 0x0804,
    /// `RSA_PSS_RSAE_SHA384` (`0x0805`).
    RsaPssRsaeSha384 = 0x0805,
    /// `RSA_PSS_RSAE_SHA512` (`0x0806`).
    RsaPssRsaeSha512 = 0x0806,
    /// `RSA_PSS_PSS_SHA256` (`0x0809`): RSA-PSS with SHA-256 over an `id-RSASSA-PSS`
    /// certificate. Parsed for interoperability, never offered — such certificates are
    /// virtually unused in the real world, as in pion.
    RsaPssPssSha256 = 0x0809,
    /// `RSA_PSS_PSS_SHA384` (`0x080a`).
    RsaPssPssSha384 = 0x080a,
    /// `RSA_PSS_PSS_SHA512` (`0x080b`).
    RsaPssPssSha512 = 0x080b,
    /// An algorithm this crate does not implement.
    Unsupported,
}

impl From<u8> for SignatureAlgorithm {
    fn from(val: u8) -> Self {
        match val {
            0 => SignatureAlgorithm::Anonymous,
            1 => SignatureAlgorithm::Rsa,
            3 => SignatureAlgorithm::Ecdsa,
            7 => SignatureAlgorithm::Ed25519,
            _ => SignatureAlgorithm::Unsupported,
        }
    }
}

impl SignatureAlgorithm {
    /// Returns `true` if the algorithm is an RSA-PSS signature scheme.
    ///
    /// The check is by specific value rather than the `0x0804`-`0x080b` range, because `0x0807`
    /// (Ed25519) and `0x0808` (Ed448) fall inside that range but are not PSS schemes.
    #[must_use]
    pub const fn is_pss(self) -> bool {
        matches!(
            self,
            Self::RsaPssRsaeSha256
                | Self::RsaPssRsaeSha384
                | Self::RsaPssRsaeSha512
                | Self::RsaPssPssSha256
                | Self::RsaPssPssSha384
                | Self::RsaPssPssSha512
        )
    }

    /// Returns `true` if the algorithm is a signature scheme this crate parses for wire-format
    /// interoperability but never negotiates: the `RSA_PSS_PSS` family, which needs certificates
    /// with the `id-RSASSA-PSS` OID that are effectively unused on the public Web PKI.
    #[must_use]
    pub const fn is_unsupported(self) -> bool {
        matches!(
            self,
            Self::RsaPssPssSha256 | Self::RsaPssPssSha384 | Self::RsaPssPssSha512
        )
    }

    /// The hash algorithm associated with an RSA-PSS signature scheme, or
    /// [`HashAlgorithm::Md2`] (this crate's `0` code point, pion's `hash.None`) when the
    /// algorithm is not an RSA-PSS scheme.
    #[must_use]
    pub const fn get_pss_hash(self) -> HashAlgorithm {
        match self {
            Self::RsaPssRsaeSha256 | Self::RsaPssPssSha256 => HashAlgorithm::Sha256,
            Self::RsaPssRsaeSha384 | Self::RsaPssPssSha384 => HashAlgorithm::Sha384,
            Self::RsaPssRsaeSha512 | Self::RsaPssPssSha512 => HashAlgorithm::Sha512,
            _ => HashAlgorithm::Md2,
        }
    }
}

/// Extracts the hash algorithm from an RSA-PSS signature-scheme value, handling the TLS 1.3 PSS
/// schemes. Returns [`HashAlgorithm::Md2`] (this crate's `0` code point, pion's `hash.None`) if
/// the scheme is not a recognized PSS scheme.
#[must_use]
pub const fn extract_hash_from_pss(pss_scheme: u16) -> HashAlgorithm {
    match pss_scheme {
        0x0804 | 0x0809 => HashAlgorithm::Sha256,
        0x0805 | 0x080a => HashAlgorithm::Sha384,
        0x0806 | 0x080b => HashAlgorithm::Sha512,
        _ => HashAlgorithm::Md2,
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// A signature and hash pair, as negotiated for certificate verification.
pub struct SignatureHashAlgorithm {
    /// The hash to digest the signed data with.
    pub hash: HashAlgorithm,
    /// The signature algorithm to apply.
    pub signature: SignatureAlgorithm,
}

impl SignatureHashAlgorithm {
    /// Decodes one signature-scheme code point ([RFC 8446] §4.2.3) into a pair, as pion's
    /// `signaturehash.Algorithm.Unmarshal` does. TLS 1.3 PSS schemes carry the full `u16` value in
    /// the signature half; every other scheme splits into a hash byte and a signature byte.
    ///
    /// # Errors
    ///
    /// [`Error::ErrInvalidSignatureAlgorithm`] or [`Error::ErrInvalidHashAlgorithm`] when the
    /// code point is not a recognized pair.
    pub(crate) fn from_scheme(scheme: u16) -> Result<Self> {
        let signature = match scheme {
            0x0804 => SignatureAlgorithm::RsaPssRsaeSha256,
            0x0805 => SignatureAlgorithm::RsaPssRsaeSha384,
            0x0806 => SignatureAlgorithm::RsaPssRsaeSha512,
            0x0809 => SignatureAlgorithm::RsaPssPssSha256,
            0x080a => SignatureAlgorithm::RsaPssPssSha384,
            0x080b => SignatureAlgorithm::RsaPssPssSha512,
            _ => {
                // TLS 1.2 style: hash (high byte) + signature (low byte).
                let signature: SignatureAlgorithm = ((scheme & 0xFF) as u8).into();
                if signature == SignatureAlgorithm::Unsupported {
                    return Err(Error::ErrInvalidSignatureAlgorithm);
                }
                let hash: HashAlgorithm = ((scheme >> 8) as u8).into();
                if hash == HashAlgorithm::Unsupported || hash.invalid() {
                    return Err(Error::ErrInvalidHashAlgorithm);
                }
                return Ok(Self { hash, signature });
            }
        };

        Ok(Self {
            hash: extract_hash_from_pss(scheme),
            signature,
        })
    }

    /// Encodes this pair the way pion's `signaturehash.Algorithm.Marshal` does: a TLS 1.3 PSS
    /// scheme writes the full signature-scheme `u16`; every other pair the hash byte then the
    /// signature byte.
    ///
    /// # Errors
    ///
    /// [`Error::ErrInvalidSignHashAlgorithm`] when either half cannot be encoded.
    pub(crate) fn scheme_bytes(&self) -> Result<[u8; 2]> {
        if self.signature.is_pss() {
            return Ok((self.signature as u16).to_be_bytes());
        }
        match (self.hash, self.signature) {
            (HashAlgorithm::Unsupported, _) | (_, SignatureAlgorithm::Unsupported) => {
                Err(Error::ErrInvalidSignHashAlgorithm)
            }
            (hash, signature) => Ok([hash as u8, signature as u8]),
        }
    }

    pub(crate) fn crypto_scheme(&self) -> Result<crypto::SignatureScheme> {
        match (self.signature, self.hash) {
            (SignatureAlgorithm::Ed25519, _) => Ok(crypto::SignatureScheme::Ed25519),
            (SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha256) => {
                Ok(crypto::SignatureScheme::EcdsaP256Sha256)
            }
            (SignatureAlgorithm::Ecdsa, HashAlgorithm::Sha384) => {
                Ok(crypto::SignatureScheme::EcdsaP384Sha384)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha1) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha1)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha256) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha256)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha384) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha384)
            }
            (SignatureAlgorithm::Rsa, HashAlgorithm::Sha512) => {
                Ok(crypto::SignatureScheme::RsaPkcs1Sha512)
            }
            _ => Err(Error::ErrKeySignatureVerifyUnimplemented),
        }
    }

    // is_compatible checks that given private key is compatible with the signature scheme.
    pub(crate) fn is_compatible(&self, private_key: &CryptoPrivateKey) -> bool {
        self.crypto_scheme()
            .is_ok_and(|scheme| private_key.signing_key.supports(scheme))
    }
}

pub(crate) fn default_signature_schemes() -> Vec<SignatureHashAlgorithm> {
    vec![
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Ed25519,
            signature: SignatureAlgorithm::Ed25519,
        },
    ]
}

/// Returns the signature algorithms compatible with DTLS 1.3 / TLS 1.3: pion's
/// `signaturehash.Algorithms13`. This includes the DTLS 1.3-specific RSA-PSS schemes in
/// addition to the DTLS 1.2 algorithms.
///
/// The order is the priority a future `select_signature_scheme_13` will negotiate with, and
/// follows the industry-standard ECDSA-first preference of OpenSSL, BoringSSL, Firefox and
/// Chrome.
///
/// Only the `RSA_PSS_RSAE` variants are offered, never `RSA_PSS_PSS`: certificates with the
/// `id-RSASSA-PSS` OID are virtually unused and not allowed by the CA/Browser Forum baseline
/// requirements, as in pion — which follows the pragmatic approach of Go's `crypto/tls` and
/// BoringSSL.
#[must_use]
pub fn algorithms_13() -> Vec<SignatureHashAlgorithm> {
    vec![
        // ECDSA schemes (modern, efficient — industry standard preference)
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Ecdsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Ecdsa,
        },
        // Ed25519
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Ed25519,
            signature: SignatureAlgorithm::Ed25519,
        },
        // RSA-PSS RSAE schemes (TLS 1.3 / DTLS 1.3 compatible with standard RSA certs)
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::RsaPssRsaeSha256,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::RsaPssRsaeSha384,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::RsaPssRsaeSha512,
        },
        // RSA PKCS#1 v1.5 schemes (backward compatibility with DTLS 1.2)
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha256,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha384,
            signature: SignatureAlgorithm::Rsa,
        },
        SignatureHashAlgorithm {
            hash: HashAlgorithm::Sha512,
            signature: SignatureAlgorithm::Rsa,
        },
    ]
}

// select Signature Scheme returns most preferred and compatible scheme.
pub(crate) fn select_signature_scheme(
    sigs: &[SignatureHashAlgorithm],
    private_key: &CryptoPrivateKey,
) -> Result<SignatureHashAlgorithm> {
    for ss in sigs {
        if ss.is_compatible(private_key) {
            return Ok(*ss);
        }
    }

    Err(Error::ErrNoAvailableSignatureSchemes)
}

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// A TLS signature scheme, which names a signature and hash together ([RFC 8446] §4.2.3).
#[non_exhaustive]
pub enum SignatureScheme {
    // RSASSA-PKCS1-v1_5 algorithms.
    /// `PKCS1_WITH_SHA256` (`0x0401`).
    Pkcs1WithSha256 = 0x0401,
    /// `PKCS1_WITH_SHA384` (`0x0501`).
    Pkcs1WithSha384 = 0x0501,
    /// `PKCS1_WITH_SHA512` (`0x0601`).
    Pkcs1WithSha512 = 0x0601,

    // RSASSA-PSS algorithms with public key OID rsaEncryption.
    /// `PSS_WITH_SHA256` (`0x0804`).
    PssWithSha256 = 0x0804,
    /// `PSS_WITH_SHA384` (`0x0805`).
    PssWithSha384 = 0x0805,
    /// `PSS_WITH_SHA512` (`0x0806`).
    PssWithSha512 = 0x0806,

    // ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
    /// `ECDSA_WITH_P256_AND_SHA256` (`0x0403`).
    EcdsaWithP256AndSha256 = 0x0403,
    /// `ECDSA_WITH_P384_AND_SHA384` (`0x0503`).
    EcdsaWithP384AndSha384 = 0x0503,
    /// `ECDSA_WITH_P521_AND_SHA512` (`0x0603`).
    EcdsaWithP521AndSha512 = 0x0603,

    // EdDSA algorithms.
    /// `ED25519` (`0x0807`).
    Ed25519 = 0x0807,

    // Legacy signature and hash algorithms for TLS 1.2.
    /// `PKCS1_WITH_SHA1` (`0x0201`).
    Pkcs1WithSha1 = 0x0201,
    /// `ECDSA_WITH_SHA1` (`0x0203`).
    EcdsaWithSha1 = 0x0203,
}

// parse_signature_schemes translates []tls.SignatureScheme to []signatureHashAlgorithm.
// It returns default signature scheme list if no SignatureScheme is passed.
pub(crate) fn parse_signature_schemes(
    sigs: &[u16],
    insecure_hashes: bool,
) -> Result<Vec<SignatureHashAlgorithm>> {
    if sigs.is_empty() {
        return Ok(default_signature_schemes());
    }

    let mut out = vec![];
    for ss in sigs {
        // Handles both TLS 1.2 byte-split encoding and TLS 1.3 PSS full-u16 schemes, as pion
        // does.
        let alg = SignatureHashAlgorithm::from_scheme(*ss)?;
        if alg.hash.insecure() && !insecure_hashes {
            continue;
        }
        out.push(alg);
    }

    if out.is_empty() {
        Err(Error::ErrNoAvailableSignatureSchemes)
    } else {
        Ok(out)
    }
}

// parse_certificate_signature_schemes translates []tls.SignatureScheme to
// []SignatureHashAlgorithm with the hybrid encoding `signature_algorithms_cert` uses: a known
// RSA-PSS code point carries its hash, everything else byte-splits. Unknown or (without
// `insecure_hashes`) insecure entries are skipped rather than rejected, as in pion.
pub(crate) fn parse_certificate_signature_schemes(
    sigs: &[u16],
    insecure_hashes: bool,
) -> Result<Vec<SignatureHashAlgorithm>> {
    let mut out = vec![];
    for ss in sigs {
        let Some(algorithm) =
            crate::extension::extension_signature_algorithms_cert::parse_signature_hash_algorithm(*ss)
        else {
            return Err(Error::ErrInvalidSignatureAlgorithm);
        };
        if algorithm.hash.insecure() && !insecure_hashes {
            continue;
        }
        out.push(algorithm);
    }

    if out.is_empty() {
        Err(Error::ErrNoAvailableSignatureSchemes)
    } else {
        Ok(out)
    }
}
