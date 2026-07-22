//! Certificate statistics.
//!
//! This module contains the [`RTCCertificateStats`] type which provides
//! information about certificates used in the DTLS handshake.

use super::RTCStats;
use serde::{Deserialize, Serialize};

/// Statistics for a certificate used in DTLS.
///
/// This struct corresponds to the `RTCCertificateStats` dictionary in the
/// W3C WebRTC Statistics API. It provides information about certificates
/// used during the DTLS handshake.
///
/// # W3C Reference
///
/// See [RTCCertificateStats](https://www.w3.org/TR/webrtc-stats/#certificatestats-dict*)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCCertificateStats {
    /// Base statistics fields (timestamp, type, id).
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The fingerprint of the certificate.
    ///
    /// This is computed using the hash algorithm specified in
    /// `fingerprint_algorithm`. The format is a colon-separated
    /// hex string (e.g., "AB:CD:EF:...").
    pub fingerprint: String,

    /// The hash algorithm used to compute the fingerprint.
    ///
    /// Common values are "sha-256" or "sha-1".
    pub fingerprint_algorithm: String,

    /// The certificate in base64-encoded DER format.
    pub base64_certificate: String,

    /// The ID of the issuer certificate stats.
    ///
    /// For certificate chains, this references the parent certificate's
    /// statistics object. Empty if this is a root certificate.
    pub issuer_certificate_id: String,
}
