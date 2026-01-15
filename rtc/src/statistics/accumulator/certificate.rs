//! Certificate statistics accumulator.

use crate::statistics::stats::certificate::RTCCertificateStats;
use crate::statistics::stats::{RTCStats, RTCStatsType};
use std::time::Instant;

/// Accumulated certificate statistics.
///
/// This struct holds static certificate information captured after
/// the DTLS handshake completes. The data doesn't change after creation.
#[derive(Debug, Default, Clone)]
pub struct CertificateStatsAccumulator {
    /// The certificate fingerprint.
    pub fingerprint: String,
    /// The hash algorithm used for the fingerprint (e.g., "sha-256").
    pub fingerprint_algorithm: String,
    /// The certificate in base64-encoded DER format.
    pub base64_certificate: String,
    /// ID of the issuer certificate stats (for certificate chains).
    pub issuer_certificate_id: String,
}

impl CertificateStatsAccumulator {
    /// Creates a snapshot of the accumulated stats at the given timestamp.
    pub fn snapshot(&self, now: Instant, id: &str) -> RTCCertificateStats {
        RTCCertificateStats {
            stats: RTCStats {
                timestamp: now,
                typ: RTCStatsType::Certificate,
                id: id.to_string(),
            },
            fingerprint: self.fingerprint.clone(),
            fingerprint_algorithm: self.fingerprint_algorithm.clone(),
            base64_certificate: self.base64_certificate.clone(),
            issuer_certificate_id: self.issuer_certificate_id.clone(),
        }
    }
}
