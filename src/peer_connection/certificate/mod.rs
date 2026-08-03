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
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use rtc::peer_connection::certificate::RTCCertificate;
//! use rcgen::KeyPair;
//! use std::fs;
//!
//! // First run: Generate and save certificate
//! let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
//! let certificate = RTCCertificate::from_key_pair(key_pair)?;
//! let pem_data = certificate.serialize_pem()?;
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
//! # Specifications
//!
//! * [W3C RTCCertificate](https://w3c.github.io/webrtc-pc/#dom-rtccertificate)
//! * [MDN RTCCertificate](https://developer.mozilla.org/en-US/docs/Web/API/RTCCertificate)
//! * [RFC 5763 - DTLS-SRTP](https://tools.ietf.org/html/rfc5763)
//! * [RFC 8122 - WebRTC Security Architecture](https://tools.ietf.org/html/rfc8122)

use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crypto::{HashAlgorithm, PublicKeyEncoding, RTCCryptoProvider, SignatureScheme, SigningKey};
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use dtls::crypto::CryptoPrivateKey;
use rcgen::CertificateParams;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
use rcgen::KeyPair;
use rustls::pki_types::CertificateDer;

use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
use shared::error::{Error, Result};
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
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
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # use rtc::peer_connection::certificate::RTCCertificate;
/// # use rcgen::KeyPair;
/// # let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
/// # let certificate = RTCCertificate::from_key_pair(key_pair)?;
/// // Serialize certificate to PEM format (includes private key)
/// let pem_string = certificate.serialize_pem()?;
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
    pub dtls_certificate: dtls::crypto::Certificate,

    /// Timestamp after which this certificate is no longer valid
    pub expires: SystemTime,
}

impl PartialEq for RTCCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.dtls_certificate == other.dtls_certificate
    }
}

impl RTCCertificate {
    /// Generates a self-signed certificate with a provider-owned signing key.
    ///
    /// `params` controls X.509 formatting and validity while `provider` owns key generation and
    /// signing. This keeps certificate formatting independent from the primitive backend.
    pub fn generate(
        provider: Arc<dyn RTCCryptoProvider>,
        scheme: SignatureScheme,
        params: CertificateParams,
    ) -> Result<Self> {
        let signing_key = provider
            .crypto()
            .generate_signing_key(scheme)
            .map_err(crypto_error)?;
        Self::generate_from_signing_key(params, scheme, signing_key)
    }

    /// Imports a PKCS#8 private key through `provider` and associates it with an existing chain.
    pub fn from_pkcs8(
        provider: Arc<dyn RTCCryptoProvider>,
        scheme: SignatureScheme,
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key_der: &[u8],
        expires: SystemTime,
    ) -> Result<Self> {
        let signing_key = provider
            .crypto()
            .import_signing_key(scheme, private_key_der)
            .map_err(crypto_error)?;
        Ok(Self::from_signing_key(
            certificate_chain,
            signing_key,
            expires,
        ))
    }

    /// Builds a certificate around an application-owned signing key, including HSM/KMS keys.
    #[must_use]
    pub fn from_signing_key(
        certificate_chain: Vec<CertificateDer<'static>>,
        signing_key: Arc<dyn SigningKey>,
        expires: SystemTime,
    ) -> Self {
        Self {
            dtls_certificate: dtls::crypto::Certificate::from_signing_key(
                certificate_chain,
                signing_key,
            ),
            expires,
        }
    }

    fn generate_from_signing_key(
        params: CertificateParams,
        scheme: SignatureScheme,
        signing_key: Arc<dyn SigningKey>,
    ) -> Result<Self> {
        let not_after = params.not_after;
        let adapter = RcgenSigningKey::new(scheme, signing_key.clone())?;
        let x509_cert = params
            .self_signed(&adapter)
            .map_err(|error| Error::Other(error.to_string()))?;
        let expires = certificate_expiration(not_after);
        Ok(Self::from_signing_key(
            vec![x509_cert.der().to_owned()],
            signing_key,
            expires,
        ))
    }

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
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    fn from_params(
        params: CertificateParams,
        key_pair: KeyPair,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Result<Self> {
        let not_after = params.not_after;

        let x509_cert = params
            .self_signed(&key_pair)
            .map_err(|error| Error::Other(error.to_string()))?;
        let private_key = CryptoPrivateKey::from_key_pair_with_provider(&key_pair, provider)?;
        let expires = certificate_expiration(not_after);

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
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn from_key_pair(key_pair: KeyPair) -> Result<Self> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        Self::from_key_pair_with_provider(key_pair, provider)
    }

    /// Imports an `rcgen` key pair through an explicit provider compatibility adapter.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    pub fn from_key_pair_with_provider(
        key_pair: KeyPair,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Result<Self> {
        if !(key_pair.is_compatible(&rcgen::PKCS_ED25519)
            || key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256)
            || key_pair.is_compatible(&rcgen::PKCS_RSA_SHA256))
        {
            return Err(Error::Other("Unsupported key_pair".to_owned()));
        }

        RTCCertificate::from_params(
            CertificateParams::new(vec![math_rand_alpha(16)]).unwrap(),
            key_pair,
            provider,
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
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rcgen::KeyPair;
    /// # let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    /// # let original = RTCCertificate::from_key_pair(key_pair)?;
    /// // Load certificate from PEM string
    /// # let pem_str = original.serialize_pem()?;
    /// let certificate = RTCCertificate::from_pem(&pem_str)?;
    ///
    /// // Certificate is ready to use
    /// let fingerprints = certificate.get_fingerprints();
    /// println!("Loaded certificate with {} fingerprint(s)", fingerprints.len());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        Self::from_pem_with_provider(pem_str, provider)
    }

    /// Parses PEM and imports its private key through an explicit provider.
    pub fn from_pem_with_provider(
        pem_str: &str,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Result<Self> {
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
        let dtls_certificate = dtls::crypto::Certificate::from_pem_with_provider(
            &pem_blocks.collect::<Vec<&str>>().join("\n\n"),
            provider,
        )?;
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
    /// `from_pem`.
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
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use rtc::peer_connection::certificate::RTCCertificate;
    /// # use rcgen::KeyPair;
    /// # let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    /// # let certificate = RTCCertificate::from_key_pair(key_pair)?;
    /// // Serialize for storage
    /// let pem_string = certificate.serialize_pem()?;
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
    pub fn serialize_pem(&self) -> Result<String> {
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
        Ok(format!(
            "{}\n{}",
            pem::encode(&expires_pem),
            self.dtls_certificate.serialize_pem()?
        ))
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
        let provider = crypto::default_provider().expect("a default crypto provider is required");
        self.get_fingerprints_with_provider(provider)
            .expect("the default crypto provider supports SHA-256")
    }

    /// Returns SHA-256 fingerprints computed by an explicit crypto provider.
    pub fn get_fingerprints_with_provider(
        &self,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Result<Vec<RTCDtlsFingerprint>> {
        let mut fingerprints = Vec::new();

        for c in &self.dtls_certificate.certificate {
            let hashed = provider
                .crypto()
                .hash(HashAlgorithm::Sha256, c.as_ref())
                .map_err(crypto_error)?;
            let values: Vec<String> = hashed.iter().map(|x| format! {"{x:02x}"}).collect();

            fingerprints.push(RTCDtlsFingerprint {
                algorithm: "sha-256".to_owned(),
                value: values.join(":"),
            });
        }

        Ok(fingerprints)
    }
}

fn crypto_error(error: crypto::CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

fn certificate_expiration(not_after: impl Into<SystemTime>) -> SystemTime {
    if cfg!(target_arch = "arm") {
        // Workaround for issue overflow when adding duration to instant on armv7.
        SystemTime::now().add(Duration::from_secs(172800))
    } else {
        not_after.into()
    }
}

struct RcgenSigningKey {
    scheme: SignatureScheme,
    algorithm: &'static rcgen::SignatureAlgorithm,
    signing_key: Arc<dyn SigningKey>,
    public_key: Vec<u8>,
}

impl RcgenSigningKey {
    fn new(scheme: SignatureScheme, signing_key: Arc<dyn SigningKey>) -> Result<Self> {
        let algorithm = match scheme {
            SignatureScheme::Ed25519 => &rcgen::PKCS_ED25519,
            SignatureScheme::EcdsaP256Sha256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            SignatureScheme::EcdsaP384Sha384 => &rcgen::PKCS_ECDSA_P384_SHA384,
            SignatureScheme::RsaPkcs1Sha256 => &rcgen::PKCS_RSA_SHA256,
            SignatureScheme::RsaPkcs1Sha384 => &rcgen::PKCS_RSA_SHA384,
            SignatureScheme::RsaPkcs1Sha512 => &rcgen::PKCS_RSA_SHA512,
            _ => {
                return Err(Error::Crypto(format!(
                    "certificate generation does not support {scheme:?}"
                )));
            }
        };
        if !signing_key.supports(scheme) {
            return Err(Error::Crypto(format!(
                "signing key does not support {scheme:?}"
            )));
        }
        let public_key = signing_key.public_key();
        let public_key = match public_key.encoding {
            PublicKeyEncoding::SubjectPublicKeyInfoDer => {
                use x509_parser::prelude::FromDer;
                let (remaining, subject_public_key_info) =
                    x509_parser::x509::SubjectPublicKeyInfo::from_der(public_key.bytes)
                        .map_err(|error| Error::Other(error.to_string()))?;
                if !remaining.is_empty() {
                    return Err(Error::Other(
                        "trailing bytes in SubjectPublicKeyInfo".to_owned(),
                    ));
                }
                subject_public_key_info.subject_public_key.data.to_vec()
            }
            PublicKeyEncoding::EcUncompressedPoint
            | PublicKeyEncoding::Ed25519Raw
            | PublicKeyEncoding::RsaPkcs1Der => public_key.bytes.to_vec(),
            _ => {
                return Err(Error::Crypto(format!(
                    "certificate generation does not support public-key encoding {:?}",
                    public_key.encoding
                )));
            }
        };
        Ok(Self {
            scheme,
            algorithm,
            signing_key,
            public_key,
        })
    }
}

impl rcgen::PublicKeyData for RcgenSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm
    }
}

impl rcgen::SigningKey for RcgenSigningKey {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        self.signing_key
            .sign(self.scheme, message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[cfg(all(test, any(feature = "ring", feature = "aws-lc-rs")))]
mod test {
    use super::*;

    struct NonExportableSigningKey(Arc<dyn SigningKey>);

    impl SigningKey for NonExportableSigningKey {
        fn supports(&self, scheme: SignatureScheme) -> bool {
            self.0.supports(scheme)
        }

        fn public_key(&self) -> crypto::PublicKey<'_> {
            self.0.public_key()
        }

        fn sign(
            &self,
            scheme: SignatureScheme,
            message: &[u8],
        ) -> std::result::Result<Vec<u8>, crypto::CryptoError> {
            self.0.sign(scheme, message)
        }
    }

    fn provider_certificate(provider: Arc<dyn RTCCryptoProvider>) -> Result<RTCCertificate> {
        RTCCertificate::generate(
            provider,
            SignatureScheme::EcdsaP256Sha256,
            CertificateParams::new(vec!["webrtc.rs".to_owned()])?,
        )
    }

    #[test]
    fn test_generate_certificate_rsa() -> Result<()> {
        match KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256) {
            Ok(key_pair) => {
                let _certificate = RTCCertificate::from_key_pair(key_pair)?;
            }
            Err(rcgen::Error::KeyGenerationUnavailable) => {}
            Err(error) => return Err(Error::Other(error.to_string())),
        }

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

    #[test]
    fn test_certificate_serialize_pem_and_from_pem() -> Result<()> {
        let kp = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = RTCCertificate::from_key_pair(kp)?;

        let pem = cert.serialize_pem()?;
        let loaded_cert = RTCCertificate::from_pem(&pem)?;

        assert_eq!(loaded_cert, cert);

        Ok(())
    }

    #[cfg(feature = "ring")]
    #[test]
    fn ring_provider_generates_imports_and_fingerprints_certificates() -> Result<()> {
        provider_certificate_round_trip(Arc::new(crypto::providers::RingProvider::new()))
    }

    #[cfg(feature = "aws-lc-rs")]
    #[test]
    fn aws_provider_generates_imports_and_fingerprints_certificates() -> Result<()> {
        provider_certificate_round_trip(Arc::new(crypto::providers::AwsLcRsProvider::new()))
    }

    fn provider_certificate_round_trip(provider: Arc<dyn RTCCryptoProvider>) -> Result<()> {
        let certificate = provider_certificate(provider.clone())?;
        let fingerprints = certificate.get_fingerprints_with_provider(provider.clone())?;
        assert_eq!(fingerprints.len(), 1);
        assert_eq!(fingerprints[0].algorithm, "sha-256");

        let pem = certificate.serialize_pem()?;
        let imported = RTCCertificate::from_pem_with_provider(&pem, provider.clone())?;
        assert_eq!(imported, certificate);

        let private_key = certificate
            .dtls_certificate
            .private_key
            .signing_key
            .to_pkcs8_der()
            .map_err(crypto_error)?
            .expect("built-in generated keys are exportable");
        let imported = RTCCertificate::from_pkcs8(
            provider,
            SignatureScheme::EcdsaP256Sha256,
            certificate.dtls_certificate.certificate.clone(),
            private_key.as_ref(),
            certificate.expires,
        )?;
        assert_eq!(imported, certificate);
        Ok(())
    }

    #[test]
    fn non_exportable_signing_key_returns_an_explicit_pem_error() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let certificate = provider_certificate(provider)?;
        let signing_key = certificate.dtls_certificate.private_key.signing_key.clone();
        let certificate = RTCCertificate::from_signing_key(
            certificate.dtls_certificate.certificate,
            Arc::new(NonExportableSigningKey(signing_key)),
            certificate.expires,
        );

        let error = certificate.serialize_pem().unwrap_err();
        assert!(error.to_string().contains("not exportable"));
        Ok(())
    }
}
