//! X.509 certificate management for WebRTC DTLS authentication.
//!
//! This module provides certificate generation, serialization, and management functionality
//! required for securing WebRTC peer-to-peer connections via DTLS (Datagram Transport Layer Security).
//!
//! # Overview
//!
//! WebRTC uses DTLS to encrypt media and data channels. Each peer must have an X.509 certificate
//! to establish secure connections. This module handles:
//!
//! - **Certificate Generation** - Create self-signed certificates with various key types
//! - **Certificate Persistence** - Serialize/deserialize certificates in PEM format
//! - **Fingerprint Calculation** - Generate SHA-256 fingerprints for SDP signaling
//! - **Identity Management** - Maintain consistent identity across sessions
//!
//! # Certificate Types
//!
//! Three cryptographic algorithms are supported:
//!
//! | Algorithm | Performance | Security | Recommendation |
//! |-----------|-------------|----------|----------------|
//! | **ECDSA P-256** | Fast | Strong | ✅ Recommended for most cases |
//! | **Ed25519** | Fastest | Strongest | ✅ Best for security-critical apps |
//! | **RSA-2048** | Slow | Strong | ⚠️ Generation not available |
//!
//! # Examples
//!
//! ## Quick Start - Generate and Use Certificate
//!
//! ```
//! use rtc::peer_connection::RTCPeerConnectionBuilder;
//! use rtc::peer_connection::configuration::RTCConfigurationBuilder;
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate ECDSA certificate (recommended)
//! let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
//! let certificate = RTCCertificate::from_key_pair(key_pair)?;
//!
//! // Use in peer connection
//! let peer_connection = RTCPeerConnectionBuilder::new()
//!     .with_configuration(
//!         RTCConfigurationBuilder::new()
//!             .with_certificates(vec![certificate])
//!             .build()
//!     )
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Generate Certificate with Ed25519 (Highest Security)
//!
//! ```
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Ed25519 provides the best security with excellent performance
//! let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
//! let certificate = RTCCertificate::from_key_pair(key_pair)?;
//!
//! // Get fingerprint for SDP signaling
//! let fingerprints = certificate.get_fingerprints();
//! println!("Fingerprint: {}", fingerprints[0].value);
//! # Ok(())
//! # }
//! ```
//!
//! ## Persist Certificate Across Sessions
//!
//! ```no_run
//! # #[cfg(feature = "pem")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//! use std::fs;
//!
//! // First run: Generate and save certificate
//! let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
//! let certificate = RTCCertificate::from_key_pair(key_pair)?;
//! let pem_data = certificate.serialize_pem();
//! fs::write("my_cert.pem", pem_data)?;
//!
//! // Later runs: Load existing certificate
//! let pem_data = fs::read_to_string("my_cert.pem")?;
//! let certificate = RTCCertificate::from_pem(&pem_data)?;
//! // Same identity maintained across restarts!
//! # Ok(())
//! # }
//! ```
//!
//! ## Extract Fingerprints for SDP Signaling
//!
//! ```
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
//! let certificate = RTCCertificate::from_key_pair(key_pair)?;
//!
//! // Get fingerprints for SDP offer/answer
//! let fingerprints = certificate.get_fingerprints();
//! for fp in fingerprints {
//!     // Format for SDP: a=fingerprint:sha-256 XX:XX:XX:...
//!     println!("a=fingerprint:{} {}", fp.algorithm, fp.value);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Compare Certificate Algorithms
//!
//! ```
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//! use std::time::Instant;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // ECDSA P-256: Good balance of speed and security
//! let start = Instant::now();
//! let ecdsa_kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
//! let _ecdsa_cert = RTCCertificate::from_key_pair(ecdsa_kp)?;
//! println!("ECDSA generation: {:?}", start.elapsed());
//!
//! // Ed25519: Fastest and most secure
//! let start = Instant::now();
//! let ed_kp = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
//! let _ed_cert = RTCCertificate::from_key_pair(ed_kp)?;
//! println!("Ed25519 generation: {:?}", start.elapsed());
//! # Ok(())
//! # }
//! ```
//!
//! ## Using External Certificate
//!
//! ```no_run
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use std::time::{SystemTime, Duration};
//!
//! # fn example(dtls_cert: dtls::crypto::Certificate) -> Result<(), Box<dyn std::error::Error>> {
//! // Use certificate from hardware security module or external source
//! let expires = SystemTime::now() + Duration::from_secs(365 * 86400); // 1 year
//! let certificate = RTCCertificate::from_existing(dtls_cert, expires);
//!
//! // Certificate is ready to use in WebRTC connections
//! # Ok(())
//! # }
//! ```
//!
//! # Security Considerations
//!
//! ## Private Key Protection
//!
//! - **Never** transmit private keys over the network
//! - Store serialized certificates securely (encrypted storage recommended)
//! - Use appropriate file permissions when saving to disk (0600 on Unix)
//! - Consider using platform keystores for production applications
//!
//! ## Certificate Expiration
//!
//! - Default expiration is platform-dependent
//! - On ARM platforms, certificates expire after 48 hours (workaround for overflow bug)
//! - Check certificate validity before each connection
//! - Regenerate certificates before they expire
//!
//! ## Fingerprint Verification
//!
//! - Always verify remote fingerprints via trusted signaling channel
//! - Mismatched fingerprints indicate MITM attack - abort connection
//! - Use out-of-band verification for high-security scenarios
//!
//! # Feature Flags
//!
//! - `pem` - Enable PEM serialization/deserialization (enabled by default)
//!
//! # Specifications
//!
//! * [W3C RTCCertificate](https://w3c.github.io/webrtc-pc/#dom-rtccertificate)
//! * [MDN RTCCertificate](https://developer.mozilla.org/en-US/docs/Web/API/RTCCertificate)
//! * [RFC 5763 - DTLS-SRTP](https://tools.ietf.org/html/rfc5763)
//! * [RFC 8122 - WebRTC Security Architecture](https://tools.ietf.org/html/rfc8122)

use std::ops::Add;
use std::time::{Duration, SystemTime};

use dtls::crypto::{CryptoPrivateKey, CryptoPrivateKeyKind};
use rcgen::{CertificateParams, KeyPair};
use ring::rand::SystemRandom;
use ring::rsa;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair};
use sha2::{Digest, Sha256};

use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;

/// X.509 certificate used to authenticate WebRTC peer-to-peer communications.
///
/// RTCCertificate encapsulates a DTLS certificate and its associated private key,
/// providing secure identity verification during the WebRTC connection establishment
/// process. Certificates can be generated on-demand or loaded from persistent storage.
///
/// # Certificate Lifetime
///
/// Each certificate has an expiration time after which it becomes invalid for use
/// in WebRTC connections. The default lifetime depends on the platform.
///
/// # Supported Key Types
///
/// - **ECDSA P-256** with SHA-256 (recommended for performance)
/// - **Ed25519** (recommended for security)
/// - **RSA** with SHA-256 (key generation not available in this implementation)
///
/// # Examples
///
/// ## Generating a new certificate
///
/// ```
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rcgen::KeyPair;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate ECDSA P-256 key pair and certificate
/// let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
/// let certificate = RTCCertificate::from_key_pair(key_pair)?;
///
/// // Certificate is ready to use
/// let fingerprints = certificate.get_fingerprints();
/// println!("Certificate has {} fingerprint(s)", fingerprints.len());
/// # Ok(())
/// # }
/// ```
///
/// ## Generating with Ed25519
///
/// ```
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rcgen::KeyPair;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate Ed25519 key pair and certificate
/// let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
/// let certificate = RTCCertificate::from_key_pair(key_pair)?;
///
/// // Get fingerprints for SDP signaling
/// let fingerprints = certificate.get_fingerprints();
/// for fp in fingerprints {
///     println!("Fingerprint ({}):\n{}", fp.algorithm, fp.value);
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Persisting and loading certificates
///
/// ```
/// # #[cfg(feature = "pem")]
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rcgen::KeyPair;
/// # let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
/// # let certificate = RTCCertificate::from_key_pair(key_pair)?;
/// // Serialize certificate to PEM format (includes private key)
/// let pem_string = certificate.serialize_pem();
///
/// // Save to file or database...
/// // std::fs::write("cert.pem", &pem_string)?;
///
/// // Later, load the certificate back
/// let loaded_cert = RTCCertificate::from_pem(&pem_string)?;
/// assert_eq!(loaded_cert, certificate);
/// # Ok(())
/// # }
/// ```
///
/// ## Using with RTCConfiguration
///
/// ```no_run
/// # use rtc::peer_connection::RTCPeerConnectionBuilder;
/// # use rtc::peer_connection::configuration::RTCConfigurationBuilder;
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rcgen::KeyPair;
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate certificate
/// let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
/// let certificate = RTCCertificate::from_key_pair(key_pair)?;
///
/// // Configure peer connection with custom certificate
/// let peer_connection = RTCPeerConnectionBuilder::new()
///     .with_configuration(
///         RTCConfigurationBuilder::new()
///             .with_certificates(vec![certificate])
///             .build()
///     )
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// ## Specifications
///
/// * [MDN RTCCertificate](https://developer.mozilla.org/en-US/docs/Web/API/RTCCertificate)
/// * [W3C RTCCertificate](https://w3c.github.io/webrtc-pc/#dom-rtccertificate)
#[derive(Clone, Debug)]
pub struct RTCCertificate {
    /// DTLS certificate containing X.509 certificate chain and private key
    pub(crate) dtls_certificate: dtls::crypto::Certificate,

    /// Timestamp after which this certificate is no longer valid
    pub(crate) expires: SystemTime,
}

impl PartialEq for RTCCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.dtls_certificate == other.dtls_certificate
    }
}

impl RTCCertificate {
    /// Generates a new certificate from custom parameters.
    ///
    /// This is an internal method used to create certificates with specific configuration.
    /// Most users should use [`from_key_pair`](Self::from_key_pair) instead.
    ///
    /// # Parameters
    ///
    /// * `params` - Certificate parameters including validity period and subject
    /// * `key_pair` - The cryptographic key pair to use
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key pair type is not supported (must be Ed25519, ECDSA P-256, or RSA)
    /// - Certificate generation fails
    ///
    /// # Platform Notes
    ///
    /// On ARM architectures, certificate expiration is capped at 48 hours due to
    /// overflow issues with SystemTime arithmetic.
    fn from_params(params: CertificateParams, key_pair: KeyPair) -> Result<Self> {
        let not_after = params.not_after;

        let x509_cert = params.self_signed(&key_pair).unwrap();
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
                certificate: vec![x509_cert.der().to_owned()],
                private_key,
            },
            expires,
        })
    }

    /// Generates a new self-signed certificate with default parameters.
    ///
    /// Creates a certificate with a randomly generated common name and default
    /// validity period. This is the recommended method for generating certificates
    /// for WebRTC connections.
    ///
    /// # Parameters
    ///
    /// * `key_pair` - A cryptographic key pair. Must be one of:
    ///   - `rcgen::PKCS_ED25519` - Ed25519 (recommended for security)
    ///   - `rcgen::PKCS_ECDSA_P256_SHA256` - ECDSA P-256 (recommended for performance)
    ///   - `rcgen::PKCS_RSA_SHA256` - RSA (generation not available)
    ///
    /// # Errors
    ///
    /// Returns an error if the key pair type is not supported.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rcgen::KeyPair;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Generate ECDSA certificate
    /// let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    /// let certificate = RTCCertificate::from_key_pair(key_pair)?;
    ///
    /// // Certificate is ready to use in peer connection
    /// let fingerprints = certificate.get_fingerprints();
    /// println!("Generated certificate with {} fingerprint(s)", fingerprints.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_key_pair(key_pair: KeyPair) -> Result<Self> {
        if !(key_pair.is_compatible(&rcgen::PKCS_ED25519)
            || key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256)
            || key_pair.is_compatible(&rcgen::PKCS_RSA_SHA256))
        {
            return Err(Error::Other("Unsupported key_pair".to_owned()));
        }

        RTCCertificate::from_params(
            CertificateParams::new(vec![math_rand_alpha(16)]).unwrap(),
            key_pair,
        )
    }

    /// Parses a certificate from PEM format string.
    ///
    /// Reconstructs an RTCCertificate from its PEM serialization, including the
    /// private key. The PEM format must match the output of [`serialize_pem`](Self::serialize_pem).
    ///
    /// # Format
    ///
    /// The PEM string must contain two parts:
    /// 1. An "EXPIRES" block containing the expiration timestamp
    /// 2. The certificate and private key blocks
    ///
    /// # Parameters
    ///
    /// * `pem_str` - PEM-encoded certificate string
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The PEM string is malformed or empty
    /// - The EXPIRES block is missing or invalid
    /// - The certificate data cannot be parsed
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "pem")]
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rcgen::KeyPair;
    /// # let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    /// # let original = RTCCertificate::from_key_pair(key_pair)?;
    /// // Load certificate from PEM string
    /// # let pem_str = original.serialize_pem();
    /// let certificate = RTCCertificate::from_pem(&pem_str)?;
    ///
    /// // Certificate is ready to use
    /// let fingerprints = certificate.get_fingerprints();
    /// println!("Loaded certificate with {} fingerprint(s)", fingerprints.len());
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "pem")]
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let mut pem_blocks = pem_str.split("\n\n");
        let first_block = if let Some(b) = pem_blocks.next() {
            b
        } else {
            return Err(Error::InvalidPEM("empty PEM".into()));
        };
        let expires_pem =
            pem::parse(first_block).map_err(|e| Error::Other(format!("can't parse PEM: {e}")))?;
        if expires_pem.tag() != "EXPIRES" {
            return Err(Error::InvalidPEM(format!(
                "invalid tag (expected: 'EXPIRES', got '{}')",
                expires_pem.tag()
            )));
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&expires_pem.contents()[..8]);
        let expires = if let Some(e) =
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(u64::from_le_bytes(bytes)))
        {
            e
        } else {
            return Err(Error::InvalidPEM("failed to calculate SystemTime".into()));
        };
        let dtls_certificate =
            dtls::crypto::Certificate::from_pem(&pem_blocks.collect::<Vec<&str>>().join("\n\n"))?;
        Ok(RTCCertificate::from_existing(dtls_certificate, expires))
    }

    /// Creates an RTCCertificate from an existing DTLS certificate.
    ///
    /// Use this method when you have a pre-existing certificate (e.g., loaded from
    /// external storage) that you want to use in WebRTC connections. This is useful
    /// for maintaining persistent identity across application restarts.
    ///
    /// # Parameters
    ///
    /// * `dtls_certificate` - The DTLS certificate with private key
    /// * `expires` - When this certificate expires
    ///
    /// # Note
    ///
    /// The statistics ID will be newly generated and will differ from the original
    /// certificate if it was previously serialized. Statistics IDs are not persisted
    /// during serialization.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use std::time::{SystemTime, Duration};
    /// # fn example(
    /// #     dtls_cert: dtls::crypto::Certificate
    /// # ) -> Result<(), Box<dyn std::error::Error>> {
    /// // Use an externally managed certificate
    /// let expires = SystemTime::now() + Duration::from_secs(86400 * 30); // 30 days
    /// let certificate = RTCCertificate::from_existing(dtls_cert, expires);
    ///
    /// // Certificate is ready to use
    /// let fingerprints = certificate.get_fingerprints();
    /// println!("Certificate has {} fingerprint(s)", fingerprints.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_existing(dtls_certificate: dtls::crypto::Certificate, expires: SystemTime) -> Self {
        Self {
            dtls_certificate,
            expires,
        }
    }

    /// Serializes the certificate to PEM format including the private key.
    ///
    /// Produces a PEM-encoded string containing both the certificate and its private
    /// key in PKCS#8 format. The output can be safely stored and later loaded with
    /// `from_pem` (requires the `pem` feature).
    ///
    /// # Security Warning
    ///
    /// The serialized output contains the private key in plain text. Store it securely
    /// and never transmit it over insecure channels or include it in client-side code.
    ///
    /// # Format
    ///
    /// The output contains:
    /// 1. EXPIRES block - Certificate expiration timestamp
    /// 2. CERTIFICATE block - X.509 certificate in DER format
    /// 3. PRIVATE KEY block - Private key in PKCS#8 format
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "pem")]
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rcgen::KeyPair;
    /// # let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    /// # let certificate = RTCCertificate::from_key_pair(key_pair)?;
    /// // Serialize for storage
    /// let pem_string = certificate.serialize_pem();
    ///
    /// // Save to secure storage
    /// // std::fs::write("private/cert.pem", &pem_string)?;
    ///
    /// // Later, reload it
    /// let reloaded = RTCCertificate::from_pem(&pem_string)?;
    /// assert_eq!(certificate, reloaded);
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(any(doc, feature = "pem"))]
    pub fn serialize_pem(&self) -> String {
        // Encode `expires` as a PEM block.
        //
        // TODO: serialize as nanos when https://github.com/rust-lang/rust/issues/103332 is fixed.
        let expires_pem = pem::Pem::new(
            "EXPIRES".to_string(),
            self.expires
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("expires to be valid")
                .as_secs()
                .to_le_bytes()
                .to_vec(),
        );
        format!(
            "{}\n{}",
            pem::encode(&expires_pem),
            self.dtls_certificate.serialize_pem()
        )
    }

    /// Returns SHA-256 fingerprints of the certificate chain.
    ///
    /// Computes cryptographic fingerprints that uniquely identify this certificate.
    /// These fingerprints are used during the WebRTC handshake to verify the remote
    /// peer's identity and are typically exchanged via SDP signaling.
    ///
    /// # Format
    ///
    /// Each fingerprint is a colon-separated string of hexadecimal byte pairs:
    /// `"12:34:56:78:9A:BC:DE:F0:..."`
    ///
    /// # Returns
    ///
    /// A vector of fingerprints, one for each certificate in the chain. In most cases,
    /// this will contain a single fingerprint for the self-signed certificate.
    ///
    /// # Future Enhancement
    ///
    /// Currently always uses SHA-256. Future versions may use the digest algorithm
    /// from the certificate signature.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rcgen::KeyPair;
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    /// let certificate = RTCCertificate::from_key_pair(key_pair)?;
    ///
    /// // Get fingerprints for SDP
    /// let fingerprints = certificate.get_fingerprints();
    /// for fp in fingerprints {
    ///     println!("a=fingerprint:{} {}", fp.algorithm, fp.value);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_generate_certificate_rsa() -> Result<()> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256);
        assert!(key_pair.is_err(), "RcgenError::KeyGenerationUnavailable");

        Ok(())
    }

    #[test]
    fn test_generate_certificate_ecdsa() -> Result<()> {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let _cert = RTCCertificate::from_key_pair(kp)?;

        Ok(())
    }

    #[test]
    fn test_generate_certificate_eddsa() -> Result<()> {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let _cert = RTCCertificate::from_key_pair(kp)?;

        Ok(())
    }

    #[test]
    fn test_certificate_equal() -> Result<()> {
        let kp1 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert1 = RTCCertificate::from_key_pair(kp1)?;

        let kp2 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert2 = RTCCertificate::from_key_pair(kp2)?;

        assert_ne!(cert1, cert2);

        Ok(())
    }

    #[test]
    fn test_generate_certificate_expires() -> Result<()> {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = RTCCertificate::from_key_pair(kp)?;

        let now = SystemTime::now();
        assert!(cert.expires.duration_since(now).is_ok());

        Ok(())
    }

    #[cfg(feature = "pem")]
    #[test]
    fn test_certificate_serialize_pem_and_from_pem() -> Result<()> {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = RTCCertificate::from_key_pair(kp)?;

        let pem = cert.serialize_pem();
        let loaded_cert = RTCCertificate::from_pem(&pem)?;

        assert_eq!(loaded_cert, cert);

        Ok(())
    }
}
