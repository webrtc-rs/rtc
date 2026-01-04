use serde::{Deserialize, Serialize};

/// DTLS certificate fingerprint for authentication.
///
/// `RTCDtlsFingerprint` contains a cryptographic hash of a certificate that is
/// used to verify the identity of the remote peer during the DTLS handshake.
/// The fingerprint is exchanged in the SDP and must match the actual certificate
/// presented during the DTLS handshake.
///
/// # Security
///
/// The fingerprint allows WebRTC to verify that the DTLS certificate received
/// during the handshake matches the certificate that was signaled out-of-band
/// via SDP. This prevents man-in-the-middle attacks even if the signaling channel
/// is not encrypted.
///
/// # Common Hash Algorithms
///
/// - `sha-256` - Most commonly used, recommended
/// - `sha-384` - Higher security
/// - `sha-512` - Maximum security
/// - `sha-1` - Deprecated, should not be used
///
/// # Format
///
/// The fingerprint value is a colon-separated sequence of lowercase hexadecimal
/// bytes, for example: `"AB:CD:EF:01:23:45:67:89:..."`
///
/// # Examples
///
/// ## Creating a Fingerprint
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsFingerprint;
///
/// let fingerprint = RTCDtlsFingerprint {
///     algorithm: "sha-256".to_string(),
///     value: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89".to_string(),
/// };
///
/// println!("Fingerprint: {} {}", fingerprint.algorithm, fingerprint.value);
/// ```
///
/// ## Serialization for SDP
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsFingerprint;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let fingerprint = RTCDtlsFingerprint {
///     algorithm: "sha-256".to_string(),
///     value: "12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF".to_string(),
/// };
///
/// // Serialize to JSON for signaling
/// let json = serde_json::to_string(&fingerprint)?;
/// println!("Fingerprint JSON: {}", json);
/// # Ok(())
/// # }
/// ```
///
/// ## Verifying Algorithm Support
///
/// ```
/// use rtc::peer_connection::transport::RTCDtlsFingerprint;
///
/// fn is_secure_algorithm(fingerprint: &RTCDtlsFingerprint) -> bool {
///     matches!(
///         fingerprint.algorithm.as_str(),
///         "sha-256" | "sha-384" | "sha-512"
///     )
/// }
///
/// let fp = RTCDtlsFingerprint {
///     algorithm: "sha-256".to_string(),
///     value: "AB:CD:EF:01:...".to_string(),
/// };
///
/// assert!(is_secure_algorithm(&fp));
/// ```
///
/// # Specifications
///
/// - [RFC 4572] - Connection-Oriented Media Transport over TLS
/// - [RFC 8122] - Updates to RFC 4572
/// - [W3C RTCDtlsFingerprint]
///
/// [RFC 4572]: https://datatracker.ietf.org/doc/html/rfc4572
/// [RFC 8122]: https://datatracker.ietf.org/doc/html/rfc8122
/// [W3C RTCDtlsFingerprint]: https://w3c.github.io/webrtc-pc/#rtcdtlsfingerprint
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RTCDtlsFingerprint {
    /// Hash function algorithm name.
    ///
    /// Specifies one of the hash function algorithms defined in the
    /// 'Hash function Textual Names' registry, such as:
    ///
    /// - `"sha-256"` - Recommended
    /// - `"sha-384"` - Higher security
    /// - `"sha-512"` - Maximum security
    /// - `"sha-1"` - Deprecated, should not be used
    ///
    /// The algorithm name is case-insensitive but typically lowercase.
    pub algorithm: String,

    /// Certificate fingerprint value.
    ///
    /// The value of the certificate fingerprint as a lowercase hex string
    /// using the syntax specified in [RFC 4572 Section 5]. Each byte is
    /// represented as two hexadecimal digits, with bytes separated by colons.
    ///
    /// Example: `"AB:CD:EF:01:23:45:67:89:..."`
    ///
    /// The length depends on the hash algorithm:
    /// - SHA-256: 32 bytes (95 characters with colons)
    /// - SHA-384: 48 bytes (143 characters with colons)
    /// - SHA-512: 64 bytes (191 characters with colons)
    ///
    /// [RFC 4572 Section 5]: https://datatracker.ietf.org/doc/html/rfc4572#section-5
    pub value: String,
}
