use std::time::Instant;

#[derive(Default, Debug, Clone)]
pub struct RTCDtlsFingerprint {
    algorithm: String,
    value: String,
}

//TODO: [Serializable]
#[derive(Debug, Clone)]
pub struct RTCCertificate {
    pub expires: Instant, // EpochTimeStamp
}

impl Default for RTCCertificate {
    fn default() -> Self {
        Self {
            expires: Instant::now(),
        }
    }
}

impl RTCCertificate {
    fn get_fingerprints(&self) -> Vec<RTCDtlsFingerprint> {
        vec![]
    }
}
