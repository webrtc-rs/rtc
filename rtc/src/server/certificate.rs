use dtls::crypto::{CryptoPrivateKey, CryptoPrivateKeyKind};
use rand::thread_rng;
use rand::Rng;
use rcgen::{CertificateParams, KeyPair};
use ring::rand::SystemRandom;
use ring::rsa;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shared::error::{Error, Result};
use std::ops::Add;
use std::time::{Duration, SystemTime};

/// DTLSFingerprint specifies the hash function algorithm and certificate
/// fingerprint as described in <https://tools.ietf.org/html/rfc4572>.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RTCDtlsFingerprint {
    /// Algorithm specifies one of the the hash function algorithms defined in
    /// the 'Hash function Textual Names' registry.
    pub algorithm: String,

    /// Value specifies the value of the certificate fingerprint in lowercase
    /// hex string as expressed utilizing the syntax of 'fingerprint' in
    /// <https://tools.ietf.org/html/rfc4572#section-5>.
    pub value: String,
}

impl TryFrom<&str> for RTCDtlsFingerprint {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let fields: Vec<&str> = value.split_whitespace().collect();
        if fields.len() == 2 {
            Ok(Self {
                algorithm: fields[0].to_string(),
                value: fields[1].to_string(),
            })
        } else {
            Err(Error::Other("invalid fingerprint".to_string()))
        }
    }
}

/// RTCCertificate represents a X.509 certificate used to authenticate WebRTC communications.
#[derive(Clone, Debug)]
pub struct RTCCertificate {
    /// DTLS certificate.
    pub dtls_certificate: dtls::crypto::Certificate,
    /// Timestamp after which this certificate is no longer valid.
    pub expires: SystemTime,
}

impl PartialEq for RTCCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.dtls_certificate == other.dtls_certificate
    }
}

impl RTCCertificate {
    /// Generates a new certificate from the given parameters.
    ///
    /// See [`rcgen::Certificate::from_params`].
    pub fn from_params(params: CertificateParams) -> Result<Self> {
        let not_after = params.not_after;
        let x509_cert = rcgen::Certificate::from_params(params)?;

        let key_pair = x509_cert.get_key_pair();
        let serialized_der = key_pair.serialize_der();

        let private_key = if key_pair.is_compatible(&rcgen::PKCS_ED25519) {
            CryptoPrivateKey {
                kind: CryptoPrivateKeyKind::Ed25519(
                    Ed25519KeyPair::from_pkcs8(&serialized_der)
                        .map_err(|e| Error::Other(e.to_string()))?,
                ),
                serialized_der,
            }
        } else if key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
            CryptoPrivateKey {
                kind: CryptoPrivateKeyKind::Ecdsa256(
                    EcdsaKeyPair::from_pkcs8(
                        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                        &serialized_der,
                        &SystemRandom::new(),
                    )
                    .map_err(|e| Error::Other(e.to_string()))?,
                ),
                serialized_der,
            }
        } else if key_pair.is_compatible(&rcgen::PKCS_RSA_SHA256) {
            CryptoPrivateKey {
                kind: CryptoPrivateKeyKind::Rsa256(
                    rsa::KeyPair::from_pkcs8(&serialized_der)
                        .map_err(|e| Error::Other(e.to_string()))?,
                ),
                serialized_der,
            }
        } else {
            return Err(Error::Other("Unsupported key_pair".to_owned()));
        };

        let expires = if cfg!(target_arch = "arm") {
            // Workaround for issue overflow when adding duration to instant on armv7
            // https://github.com/webrtc-rs/examples/issues/5 https://github.com/chronotope/chrono/issues/343
            SystemTime::now().add(Duration::from_secs(172800)) //60*60*48 or 2 days
        } else {
            not_after.into()
        };

        Ok(Self {
            dtls_certificate: dtls::crypto::Certificate {
                certificate: vec![CertificateDer::from(x509_cert.serialize_der()?)],
                private_key,
            },
            expires,
        })
    }

    /// Generates a new certificate with default [`CertificateParams`] using the given keypair.
    pub fn from_key_pair(key_pair: KeyPair) -> Result<Self> {
        let mut params = CertificateParams::new(vec![math_rand_alpha(16)]);

        if key_pair.is_compatible(&rcgen::PKCS_ED25519) {
            params.alg = &rcgen::PKCS_ED25519;
        } else if key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
            params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        } else if key_pair.is_compatible(&rcgen::PKCS_RSA_SHA256) {
            params.alg = &rcgen::PKCS_RSA_SHA256;
        } else {
            return Err(Error::Other("Unsupported key_pair".to_owned()));
        };
        params.key_pair = Some(key_pair);

        RTCCertificate::from_params(params)
    }

    /// Builds a [`RTCCertificate`] using the existing DTLS certificate.
    ///
    /// Use this method when you have a persistent certificate (i.e. you don't want to generate a
    /// new one for each DTLS connection).
    ///
    /// NOTE: ID used for statistics will be different as it's neither derived from the given
    /// certificate nor persisted along it when using serialize_pem.
    pub fn from_existing(dtls_certificate: dtls::crypto::Certificate, expires: SystemTime) -> Self {
        Self {
            dtls_certificate,
            expires,
        }
    }

    /// get_fingerprints returns a SHA-256 fingerprint of this certificate.
    ///
    /// TODO: return a fingerprint computed with the digest algorithm used in the certificate
    /// signature.
    pub fn get_fingerprints(&self) -> Vec<RTCDtlsFingerprint> {
        let mut fingerprints = Vec::new();

        for c in &self.dtls_certificate.certificate {
            let mut h = Sha256::new();
            h.update(c.as_ref());
            let hashed = h.finalize();
            let values: Vec<String> = hashed.iter().map(|x| format! {"{x:02x}"}).collect();

            fingerprints.push(RTCDtlsFingerprint {
                algorithm: "sha-256".to_owned(),
                value: values.join(":"),
            });
        }

        fingerprints
    }
}

const RUNES_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// math_rand_alpha generates a mathematical random alphabet sequence of the requested length.
fn math_rand_alpha(n: usize) -> String {
    let mut rng = thread_rng();

    let rand_string: String = (0..n)
        .map(|_| {
            let idx = rng.gen_range(0..RUNES_ALPHA.len());
            RUNES_ALPHA[idx] as char
        })
        .collect();

    rand_string
}
