use super::RTCStats;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCCertificateStats {
    /// General Stats Fields
    #[serde(flatten)]
    pub stats: RTCStats,

    /// The certificate fingerprint.
    pub fingerprint: String,
    /// The hash algorithm used for the fingerprint (e.g., "sha-256").
    pub fingerprint_algorithm: String,
    /// The certificate in base64-encoded DER format.
    pub base64_certificate: String,
    /// ID of the issuer certificate stats (for certificate chains).
    pub issuer_certificate_id: String,
}
