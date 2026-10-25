use crypto::{HmacAlgorithm, SecretVec};
use shared::FiveTuple;
use shared::error::{Error, Result};
use stun::attributes::*;
use stun::error_code::*;
use stun::integrity::MessageIntegrity;
use stun::message::Message;
use stun::textattrs::TextAttribute;

use super::{Server, message};

pub(super) struct Identity {
    pub username: String,
    pub key: SecretVec,
}

impl Server {
    pub(super) fn authenticate(
        &self,
        now: std::time::Instant,
        tuple: FiveTuple,
        request: &mut Message,
    ) -> std::result::Result<Identity, (ErrorCode, Option<SecretVec>)> {
        if !request.contains(ATTR_MESSAGE_INTEGRITY) {
            return Err((CODE_UNAUTHORIZED, None));
        }
        let username =
            message::text(request, ATTR_USERNAME, 513).ok_or((CODE_BAD_REQUEST, None))?;
        let realm = message::text(request, ATTR_REALM, 763).ok_or((CODE_BAD_REQUEST, None))?;
        let nonce = message::text(request, ATTR_NONCE, 763).ok_or((CODE_BAD_REQUEST, None))?;
        if realm != self.config.realm {
            return Err((CODE_UNAUTHORIZED, None));
        }
        let credential = self
            .authenticator
            .credential_key(&username, &realm)
            .filter(|key| key.len() == 16)
            .ok_or((CODE_UNAUTHORIZED, None))?;
        let key = self
            .allocations
            .get(&tuple)
            .filter(|allocation| allocation.username == username)
            .map(|allocation| allocation.key.clone())
            .unwrap_or_else(|| SecretVec::new(credential));
        MessageIntegrity::check(request, key.as_ref(), self.crypto.crypto())
            .map_err(|_| (CODE_UNAUTHORIZED, None))?;
        if !self.verify_nonce(now, tuple, &nonce).unwrap_or(false) {
            return Err((CODE_STALE_NONCE, Some(key)));
        }
        Ok(Identity { username, key })
    }

    pub(super) fn nonce(&self, now: std::time::Instant, tuple: FiveTuple) -> Result<String> {
        let seconds = now.saturating_duration_since(self.epoch).as_secs();
        let mut mac = self
            .crypto
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, self.nonce_key.as_ref())
            .map_err(|error| Error::Crypto(error.to_string()))?;
        let tuple_bytes = format!(
            "{}|{}|{:?}",
            tuple.local_addr, tuple.peer_addr, tuple.transport_protocol
        );
        let mut tag = [0u8; 32];
        mac.sign(&[&seconds.to_be_bytes(), tuple_bytes.as_bytes()], &mut tag)
            .map_err(|error| Error::Crypto(error.to_string()))?;
        let suffix: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(format!("{seconds:016x}{suffix}"))
    }

    fn verify_nonce(&self, now: std::time::Instant, tuple: FiveTuple, value: &str) -> Result<bool> {
        if value.len() != 80 || !value.is_ascii() {
            return Ok(false);
        }
        let Ok(seconds) = u64::from_str_radix(&value[..16], 16) else {
            return Ok(false);
        };
        let age = now.saturating_duration_since(self.epoch).as_secs();
        if seconds > age || age - seconds >= self.config.nonce_lifetime.as_secs() {
            return Ok(false);
        }
        let mut tag = [0u8; 32];
        for (index, slot) in tag.iter_mut().enumerate() {
            let Ok(byte) = u8::from_str_radix(&value[16 + index * 2..18 + index * 2], 16) else {
                return Ok(false);
            };
            *slot = byte;
        }
        let tuple_bytes = format!(
            "{}|{}|{:?}",
            tuple.local_addr, tuple.peer_addr, tuple.transport_protocol
        );
        let mut mac = self
            .crypto
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, self.nonce_key.as_ref())
            .map_err(|error| Error::Crypto(error.to_string()))?;
        Ok(mac
            .verify(&[&seconds.to_be_bytes(), tuple_bytes.as_bytes()], &tag)
            .is_ok())
    }

    pub(super) fn add_challenge(
        &self,
        now: std::time::Instant,
        tuple: FiveTuple,
        response: &mut Message,
    ) -> Result<()> {
        TextAttribute::new(ATTR_REALM, self.config.realm.clone()).add_to(response)?;
        TextAttribute::new(ATTR_NONCE, self.nonce(now, tuple)?).add_to(response)?;
        Ok(())
    }
}

use stun::message::Setter;
