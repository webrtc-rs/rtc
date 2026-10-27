#[cfg(test)]
mod integrity_test;

use crate::attributes::*;
use crate::message::*;
use crypto::{CryptoError, HashAlgorithm, HmacAlgorithm, RTCCrypto, SecretVec};
use shared::error::*;
use std::fmt;

// separator for credentials.
pub(crate) const CREDENTIALS_SEP: &str = ":";

// MessageIntegrity represents MESSAGE-INTEGRITY attribute.
//
// add_to and Check methods are using zero-allocation version of hmac, see
// newHMAC function and internal/hmac/pool.go.
//
// RFC 5389 Section 15.4
#[derive(Clone)]
/// The `MESSAGE-INTEGRITY` key: an HMAC-SHA1 is computed over the message with it.
///
/// Built from a short-term password, or from a long-term username/realm/password triple.
pub struct MessageIntegrity<'a> {
    key: SecretVec,
    crypto: &'a dyn RTCCrypto,
}

fn crypto_error(error: CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

impl<'a> fmt::Display for MessageIntegrity<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESSAGE-INTEGRITY key: [REDACTED; {} bytes]",
            self.key.len()
        )
    }
}

impl<'a> Setter for MessageIntegrity<'a> {
    // add_to adds MESSAGE-INTEGRITY attribute to message.
    //
    // CPU costly, see BenchmarkMessageIntegrity_AddTo.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        for a in m.iter_attributes() {
            // Message should not contain FINGERPRINT attribute
            // before MESSAGE-INTEGRITY.
            if a.typ == ATTR_FINGERPRINT {
                return Err(Error::ErrFingerprintBeforeIntegrity);
            }
        }
        // The text used as input to HMAC is the STUN message,
        // including the header, up to and including the attribute preceding the
        // MESSAGE-INTEGRITY attribute.
        let length = m.length;
        // Adjusting m.Length to contain MESSAGE-INTEGRITY TLV.
        m.length += (MESSAGE_INTEGRITY_SIZE + ATTRIBUTE_HEADER_SIZE) as u32;
        m.write_length(); // writing length to m.Raw
        let mut value = [0_u8; MESSAGE_INTEGRITY_SIZE];
        // A STUN message is authenticated once, so the MAC is keyed here rather than held. On a
        // per-packet path the keyed object belongs in the surrounding state instead.
        let result = self
            .crypto
            .new_hmac(HmacAlgorithm::Sha1, self.key.as_ref())
            .and_then(|mut mac| mac.sign(&[&m.raw], &mut value));
        m.length = length; // changing m.Length back
        m.write_length();
        result.map_err(crypto_error)?;

        m.add(ATTR_MESSAGE_INTEGRITY, &value);

        Ok(())
    }
}

pub(crate) const MESSAGE_INTEGRITY_SIZE: usize = 20;

impl<'a> MessageIntegrity<'a> {
    /// Creates a raw-key integrity attribute with an explicit crypto provider.
    #[must_use]
    pub fn new_raw_integrity_with_provider(
        key: impl Into<Vec<u8>>,
        crypto: &'a dyn RTCCrypto,
    ) -> Self {
        Self {
            key: SecretVec::new(key.into()),
            crypto,
        }
    }

    /// Creates a short-term integrity attribute with an explicit crypto provider.
    #[must_use]
    pub fn new_short_term_integrity_with_provider(
        password: String,
        crypto: &'a dyn RTCCrypto,
    ) -> Self {
        Self::new_raw_integrity_with_provider(password.into_bytes(), crypto)
    }

    /// Creates a long-term integrity attribute with an explicit crypto provider.
    pub fn new_long_term_integrity_with_provider(
        username: String,
        realm: String,
        password: String,
        crypto: &'a dyn RTCCrypto,
    ) -> Result<Self> {
        let key = MessageIntegrity::long_term_integrity_key(username, realm, password, crypto)?;
        Ok(Self::new_raw_integrity_with_provider(key, crypto))
    }

    /// Creates a long-term integrity key with an explicit crypto provider.
    pub fn long_term_integrity_key(
        username: String,
        realm: String,
        password: String,
        crypto: &'a dyn RTCCrypto,
    ) -> Result<Vec<u8>> {
        let credentials = [username, realm, password].join(CREDENTIALS_SEP);
        let key = crypto
            .hash(HashAlgorithm::Md5, credentials.as_bytes())
            .map_err(crypto_error)?;
        if key.len() != 16 {
            return Err(Error::Crypto(format!(
                "provider returned an invalid MD5 digest length: {}",
                key.len()
            )));
        }
        Ok(key)
    }

    /// Check checks MESSAGE-INTEGRITY attribute.
    ///
    /// CPU costly, see BenchmarkMessageIntegrity_Check.
    pub fn check(m: &mut Message, key: &[u8], crypto: &dyn RTCCrypto) -> Result<()> {
        let v = m.get_value(ATTR_MESSAGE_INTEGRITY)?;

        // The HMAC covers the message as it was when MESSAGE-INTEGRITY was added, so the header
        // length is the size of the attributes up to and including MESSAGE-INTEGRITY. Attributes
        // after it (FINGERPRINT, or ones decode dropped) are not part of it.
        let mut covered = 0;
        for a in m.iter_attributes() {
            covered += ATTRIBUTE_HEADER_SIZE + nearest_padded_value_length(a.value.len());
            if a.typ == ATTR_MESSAGE_INTEGRITY {
                break;
            }
        }
        // start_of_hmac should be first byte of integrity attribute.
        let start_of_hmac = (MESSAGE_HEADER_SIZE + covered)
            .saturating_sub(ATTRIBUTE_HEADER_SIZE + MESSAGE_INTEGRITY_SIZE);

        // The MAC input is the raw message up to the integrity attribute with the header's length
        // field replaced by `covered`. Feeding it in three pieces avoids rewriting the message's
        // own header and restoring it afterwards.
        let (Some(head), Some(tail)) = (m.raw.get(..2), m.raw.get(4..start_of_hmac)) else {
            return Err(Error::ErrIntegrityMismatch);
        };
        let length = (covered as u16).to_be_bytes();
        let result = crypto
            .new_hmac(HmacAlgorithm::Sha1, key)
            .and_then(|mut mac| mac.verify(&[head, &length, tail], v));
        match result {
            Ok(()) => Ok(()),
            Err(CryptoError::AuthenticationFailed | CryptoError::InvalidTagLength { .. }) => {
                Err(Error::ErrIntegrityMismatch)
            }
            Err(error) => Err(crypto_error(error)),
        }
    }
}
