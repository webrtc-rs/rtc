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
        for a in &m.attributes.0 {
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
        let v = m.get(ATTR_MESSAGE_INTEGRITY)?;

        // Adjusting length in header to match m.Raw that was
        // used when computing HMAC.

        let length = m.length as usize;
        let mut after_integrity = false;
        let mut size_reduced = 0;

        for a in &m.attributes.0 {
            if after_integrity {
                size_reduced += nearest_padded_value_length(a.length as usize);
                size_reduced += ATTRIBUTE_HEADER_SIZE;
            }
            if a.typ == ATTR_MESSAGE_INTEGRITY {
                after_integrity = true;
            }
        }
        m.length -= size_reduced as u32;
        m.write_length();
        // start_of_hmac should be first byte of integrity attribute.
        let start_of_hmac = MESSAGE_HEADER_SIZE + m.length as usize
            - (ATTRIBUTE_HEADER_SIZE + MESSAGE_INTEGRITY_SIZE);
        let b = &m.raw[..start_of_hmac]; // data before integrity attribute
        let result = crypto
            .new_hmac(HmacAlgorithm::Sha1, key)
            .and_then(|mut mac| mac.verify(&[b], &v));
        m.length = length as u32;
        m.write_length(); // writing length back
        match result {
            Ok(()) => Ok(()),
            Err(CryptoError::AuthenticationFailed | CryptoError::InvalidTagLength { .. }) => {
                Err(Error::ErrIntegrityMismatch)
            }
            Err(error) => Err(crypto_error(error)),
        }
    }
}
