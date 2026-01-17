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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let acc = CertificateStatsAccumulator::default();
        assert_eq!(acc.fingerprint, "");
        assert_eq!(acc.fingerprint_algorithm, "");
        assert_eq!(acc.base64_certificate, "");
        assert_eq!(acc.issuer_certificate_id, "");
    }

    #[test]
    fn test_snapshot() {
        let now = Instant::now();
        let acc = CertificateStatsAccumulator {
            fingerprint: "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90".to_string(),
            fingerprint_algorithm: "sha-256".to_string(),
            base64_certificate: "MIIBkTCB+wIJAKHBfH...".to_string(),
            issuer_certificate_id: "".to_string(),
        };

        let stats = acc.snapshot(now, "RTCCertificate_local");

        assert_eq!(stats.stats.id, "RTCCertificate_local");
        assert_eq!(stats.stats.typ, RTCStatsType::Certificate);
        assert_eq!(stats.stats.timestamp, now);
        assert_eq!(
            stats.fingerprint,
            "AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90:AB:CD:EF:12:34:56:78:90"
        );
        assert_eq!(stats.fingerprint_algorithm, "sha-256");
        assert_eq!(stats.base64_certificate, "MIIBkTCB+wIJAKHBfH...");
        assert_eq!(stats.issuer_certificate_id, "");
    }

    #[test]
    fn test_snapshot_with_issuer() {
        let now = Instant::now();
        let acc = CertificateStatsAccumulator {
            fingerprint: "11:22:33:44:55:66:77:88".to_string(),
            fingerprint_algorithm: "sha-256".to_string(),
            base64_certificate: "MIIB...".to_string(),
            issuer_certificate_id: "RTCCertificate_issuer".to_string(),
        };

        let stats = acc.snapshot(now, "RTCCertificate_end_entity");

        assert_eq!(stats.issuer_certificate_id, "RTCCertificate_issuer");
    }

    #[test]
    fn test_clone() {
        let acc = CertificateStatsAccumulator {
            fingerprint: "AA:BB:CC:DD".to_string(),
            fingerprint_algorithm: "sha-256".to_string(),
            base64_certificate: "cert_data".to_string(),
            issuer_certificate_id: "".to_string(),
        };

        let cloned = acc.clone();

        assert_eq!(cloned.fingerprint, acc.fingerprint);
        assert_eq!(cloned.fingerprint_algorithm, acc.fingerprint_algorithm);
        assert_eq!(cloned.base64_certificate, acc.base64_certificate);
    }

    #[test]
    fn test_snapshot_json_serialization() {
        let now = Instant::now();
        let acc = CertificateStatsAccumulator {
            fingerprint: "AA:BB:CC:DD:EE:FF".to_string(),
            fingerprint_algorithm: "sha-256".to_string(),
            base64_certificate: "MIIBkTCB".to_string(),
            issuer_certificate_id: "".to_string(),
        };

        let stats = acc.snapshot(now, "RTCCertificate_1");

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("\"fingerprint\":\"AA:BB:CC:DD:EE:FF\""));
        assert!(json.contains("\"fingerprintAlgorithm\":\"sha-256\""));
        assert!(json.contains("\"base64Certificate\":\"MIIBkTCB\""));
        assert!(json.contains("\"type\":\"certificate\""));
    }
}
