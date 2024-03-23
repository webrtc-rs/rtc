use serde::{Deserialize, Serialize};
use shared::error::{Error, Result};

/// DTLSFingerprint specifies the hash function algorithm and certificate
/// fingerprint as described in <https://tools.ietf.org/html/rfc4572>.
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RTCDtlsFingerprint {
    /// Algorithm specifies one of the the hash function algorithms defined in
    /// the 'Hash function Textual Names' registry.
    pub algorithm: String,

    /// Value specifies the value of the certificate fingerprint in lowercase
    /// hex string as expressed utilizing the syntax of 'fingerprint' in
    /// <https://tools.ietf.org/html/rfc4572#section-5>.
    pub value: String,
}

impl TryFrom<&str> for RTCDtlsFingerprint {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let fields: Vec<&str> = value.split_whitespace().collect();
        if fields.len() == 2 {
            Ok(Self {
                algorithm: fields[0].to_string(),
                value: fields[1].to_string(),
            })
        } else {
            Err(Error::Other("invalid fingerprint".to_string()))
        }
    }
}
