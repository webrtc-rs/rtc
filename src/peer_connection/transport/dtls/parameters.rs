use serde::{Deserialize, Serialize};

use super::fingerprint::*;
use super::role::*;

/// RTCDtlsParameters holds information relating to DTLS configuration.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTCDtlsParameters {
    /// Indicates the role of the DTLS transport in the handshake.
    pub role: RTCDtlsRole,
    /// DTLS certificate fingerprint for authentication.
    pub fingerprints: Vec<RTCDtlsFingerprint>,
}
