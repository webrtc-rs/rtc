use super::*;
use crate::key_derivation::SRTCP_INDEX_SIZE;
use shared::{error::Result, marshal::Unmarshal};

use bytes::BytesMut;

impl Context {
    /// DecryptRTCP decrypts a RTCP packet with an encrypted payload
    pub fn decrypt_rtcp(&mut self, encrypted: &[u8]) -> Result<BytesMut> {
        // A received SRTCP packet must be at least the minimum valid size for the
        // negotiated profile: the RTCP header through the SSRC (read at bytes
        // 4..8), the trailing SRTCP index, and the auth tag that `get_rtcp_index`
        // and the cipher read from the end (the HMAC tag for AES-CM, the AEAD tag
        // for GCM). A shorter packet from the network would otherwise index out
        // of bounds and panic (a remotely triggerable DoS). This is self-
        // contained: it does not rely on the individual ciphers' own guards.
        let min_len = 8
            + SRTCP_INDEX_SIZE
            + self.cipher.rtcp_auth_tag_len()
            + self.cipher.aead_auth_tag_len();
        if encrypted.len() < min_len {
            return Err(Error::ErrTooShortRtcp);
        }

        let mut buf = encrypted;
        rtcp::Header::unmarshal(&mut buf)?;

        let index = self.cipher.get_rtcp_index(encrypted);
        let ssrc = u32::from_be_bytes([encrypted[4], encrypted[5], encrypted[6], encrypted[7]]);

        // The SSRC comes from an unauthenticated header, so no state is created for one this
        // context has not seen until a packet for it authenticates; otherwise random SSRCs would
        // grow the context's memory without bound. See `decrypt_rtp`.
        if let Some(state) = self.srtcp_ssrc_states.get_mut(&ssrc)
            && let Some(replay_detector) = &mut state.replay_detector
            && !replay_detector.check(index as u64)
        {
            return Err(Error::SrtcpSsrcDuplicated(ssrc, index));
        }

        let dst = self.cipher.decrypt_rtcp(encrypted, index, ssrc)?;

        if let Some(replay_detector) = &mut self.get_srtcp_ssrc_state(ssrc).replay_detector {
            // A new SSRC's detector has not been asked about this packet yet.
            replay_detector.check(index as u64);
            replay_detector.accept();
        }

        Ok(dst)
    }

    /// EncryptRTCP marshals and encrypts an RTCP packet, writing to the dst buffer provided.
    /// If the dst buffer does not have the capacity to hold `len(plaintext) + 14` bytes, a new one will be allocated and returned.
    pub fn encrypt_rtcp(&mut self, decrypted: &[u8]) -> Result<BytesMut> {
        if decrypted.len() < 8 {
            return Err(Error::ErrTooShortRtcp);
        }

        let mut buf = decrypted;
        rtcp::Header::unmarshal(&mut buf)?;

        let ssrc = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);

        let index = {
            let state = self.get_srtcp_ssrc_state(ssrc);
            state.srtcp_index += 1;
            if state.srtcp_index > MAX_SRTCP_INDEX {
                state.srtcp_index = 0;
            }
            state.srtcp_index
        };

        self.cipher.encrypt_rtcp(decrypted, index, ssrc)
    }
}

#[cfg(test)]
mod unauthenticated_srtcp_test {
    use super::*;
    use crate::protection_profile::ProtectionProfile;

    /// SRTCP authentication is mandatory: a packet whose E bit is clear must still carry a valid
    /// tag, or anyone could inject RTCP (BYE, PLI, REMB) into a session.
    #[test]
    fn rejects_unencrypted_srtcp_with_a_forged_tag() {
        let provider = crypto::default_provider().unwrap();
        let key: Vec<u8> = (0..16).collect();
        let salt: Vec<u8> = (0..14).map(|i| 0x10 + i).collect();
        let mut ctx = Context::new(
            &key,
            &salt,
            ProtectionProfile::Aes128CmHmacSha1_80,
            None,
            None,
            provider.crypto(),
        )
        .unwrap();

        // RTCP BYE for SSRC 0xdeadbeef, then E = 0 | index 1 and ten bytes of made-up "tag".
        let mut forged = vec![0x80, 0xcb, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
        forged.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        forged.extend_from_slice(&[0xAA; 10]);
        assert!(
            ctx.decrypt_rtcp(&forged).is_err(),
            "forged SRTCP was accepted"
        );

        // A genuine packet protected with the same context still round-trips.
        let mut sender = Context::new(
            &key,
            &salt,
            ProtectionProfile::Aes128CmHmacSha1_80,
            None,
            None,
            provider.crypto(),
        )
        .unwrap();
        let plain = [0x80, 0xcb, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
        let protected = sender.encrypt_rtcp(&plain).unwrap();
        assert_eq!(&ctx.decrypt_rtcp(&protected).unwrap()[..], &plain[..]);

        // Clearing the E bit of a genuine packet changes the authenticated bytes: refused.
        let mut tampered = protected.to_vec();
        let n = tampered.len();
        tampered[n - 14] &= 0x7f;
        assert!(ctx.decrypt_rtcp(&tampered).is_err());
    }
}
