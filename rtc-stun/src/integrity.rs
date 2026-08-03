#[cfg(test)]
mod integrity_test;

use crate::attributes::*;
use crate::message::*;
use crypto::{CryptoError, HashAlgorithm, HmacAlgorithm, RTCCryptoProvider, SecretVec};
use shared::error::*;

use std::fmt;
use std::sync::Arc;

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
pub struct MessageIntegrity {
    key: SecretVec,
    provider: Arc<dyn RTCCryptoProvider>,
}

fn crypto_error(error: CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

impl fmt::Display for MessageIntegrity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MESSAGE-INTEGRITY key: [REDACTED; {} bytes]",
            self.key.len()
        )
    }
}

impl Setter for MessageIntegrity {
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
        let result = self.provider.crypto().hmac(
            HmacAlgorithm::Sha1,
            self.key.as_ref(),
            &[&m.raw],
            &mut value,
        );
        m.length = length; // changing m.Length back
        m.write_length();
        result.map_err(crypto_error)?;

        m.add(ATTR_MESSAGE_INTEGRITY, &value);

        Ok(())
    }
}

pub(crate) const MESSAGE_INTEGRITY_SIZE: usize = 20;

impl MessageIntegrity {
    /// Creates a raw-key integrity attribute with an explicit crypto provider.
    #[must_use]
    pub fn new_raw_integrity_with_provider(
        key: impl Into<Vec<u8>>,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Self {
        Self {
            key: SecretVec::new(key.into()),
            provider,
        }
    }

    /// Creates a short-term integrity attribute with an explicit crypto provider.
    #[must_use]
    pub fn new_short_term_integrity_with_provider(
        password: String,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Self {
        Self::new_raw_integrity_with_provider(password.into_bytes(), provider)
    }

    /// Creates a long-term integrity attribute with an explicit crypto provider.
    pub fn new_long_term_integrity_with_provider(
        username: String,
        realm: String,
        password: String,
        provider: Arc<dyn RTCCryptoProvider>,
    ) -> Result<Self> {
        let credentials = [username, realm, password].join(CREDENTIALS_SEP);
        let key = provider
            .crypto()
            .hash(HashAlgorithm::Md5, credentials.as_bytes())
            .map_err(crypto_error)?;
        if key.len() != 16 {
            return Err(Error::Crypto(format!(
                "provider returned an invalid MD5 digest length: {}",
                key.len()
            )));
        }
        Ok(Self::new_raw_integrity_with_provider(key, provider))
    }

    /// Creates a raw-key integrity attribute using the built-in default provider.
    ///
    /// This compatibility adapter resolves the default once during construction and panics when
    /// no built-in provider is enabled. New code should use
    /// [`Self::new_raw_integrity_with_provider`].
    #[must_use]
    pub fn new_raw_integrity(key: impl Into<Vec<u8>>) -> Self {
        Self::new_raw_integrity_with_provider(
            key,
            crypto::default_provider().expect("a default crypto provider is required"),
        )
    }

    /// Creates a long-term integrity attribute using the built-in default provider.
    ///
    /// Password, username, and realm must be SASL-prepared. This compatibility adapter resolves
    /// the default once during construction and panics when no built-in provider is enabled. New
    /// code should use [`Self::new_long_term_integrity_with_provider`].
    pub fn new_long_term_integrity(username: String, realm: String, password: String) -> Self {
        Self::new_long_term_integrity_with_provider(
            username,
            realm,
            password,
            crypto::default_provider().expect("a default crypto provider is required"),
        )
        .expect("the default crypto provider must support STUN long-term credentials")
    }

    /// Creates a short-term integrity attribute using the built-in default provider.
    ///
    /// Password must be SASL-prepared. This compatibility adapter resolves the default once during
    /// construction and panics when no built-in provider is enabled. New code should use
    /// [`Self::new_short_term_integrity_with_provider`].
    pub fn new_short_term_integrity(password: String) -> Self {
        Self::new_short_term_integrity_with_provider(
            password,
            crypto::default_provider().expect("a default crypto provider is required"),
        )
    }

    /// Check checks MESSAGE-INTEGRITY attribute.
    ///
    /// CPU costly, see BenchmarkMessageIntegrity_Check.
    pub fn check(&self, m: &mut Message) -> Result<()> {
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
        let result =
            self.provider
                .crypto()
                .verify_hmac(HmacAlgorithm::Sha1, self.key.as_ref(), &[b], &v);
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

impl Default for MessageIntegrity {
    fn default() -> Self {
        Self::new_raw_integrity(Vec::new())
    }
}
