use std::time::Instant;

pub struct RTCDtlsFingerprint {
    algorithm: String,
    value: String,
}

pub struct RTCCertificate {
    pub expires: Instant,
}

impl RTCCertificate {
    fn get_fingerprints(&self) -> Vec<RTCDtlsFingerprint> {
        vec![]
    }
}
