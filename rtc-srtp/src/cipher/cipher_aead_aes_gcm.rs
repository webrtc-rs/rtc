use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, Algorithm, LessSafeKey, Nonce, UnboundKey};

use super::{Cipher, Kdf};
use crate::key_derivation::*;
use crate::protection_profile::ProtectionProfile;
use shared::{
    error::{Error, Result},
    marshal::*,
};

pub const CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN: usize = 16;

const RTCP_ENCRYPTION_FLAG: u8 = 0x80;

/// AEAD Cipher based on AES.
///
/// The AES-GCM AEAD (both the AES block cipher and the GHASH universal hash) is
/// provided by `ring`, which ships hardware-accelerated single-pass assembly for
/// x86_64 (AES-NI + CLMUL) and aarch64 (ARMv8 AES + PMULL) with runtime feature
/// detection. That is materially faster than the pure-Rust RustCrypto `aes-gcm`,
/// whose two-pass (encrypt-then-GHASH) design and cfg-gated intrinsics leave it
/// on a software fallback in a default build. `ring` is already a workspace
/// dependency (DTLS handshake signatures, STUN integrity).
pub(crate) struct CipherAeadAesGcm {
    profile: ProtectionProfile,
    srtp_cipher: LessSafeKey,
    srtcp_cipher: LessSafeKey,
    srtp_session_salt: Vec<u8>,
    srtcp_session_salt: Vec<u8>,
}

impl Cipher for CipherAeadAesGcm {
    fn rtp_auth_tag_len(&self) -> usize {
        self.profile.rtp_auth_tag_len()
    }

    /// Get RTCP authenticated tag length.
    fn rtcp_auth_tag_len(&self) -> usize {
        self.profile.rtcp_auth_tag_len()
    }

    /// Get AEAD auth key length of the cipher.
    fn aead_auth_tag_len(&self) -> usize {
        self.profile.aead_auth_tag_len()
    }

    fn encrypt_rtp(&mut self, payload: &[u8], header: &rtp::Header, roc: u32) -> Result<BytesMut> {
        // Copy the whole packet once, then encrypt the payload region in place
        // with the header region as AAD and a detached tag appended afterwards.
        let header_len = header.marshal_size();
        let nonce = self.rtp_initialization_vector(header, roc);

        let mut writer = BytesMut::with_capacity(payload.len() + self.aead_auth_tag_len());
        writer.extend_from_slice(payload);

        let (aad, plaintext) = writer.split_at_mut(header_len);
        let tag = self
            .srtp_cipher
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad[..]),
                plaintext,
            )
            .map_err(|_| Error::Other("SRTP AES-GCM seal failed".to_string()))?;

        writer.extend_from_slice(tag.as_ref());
        Ok(writer)
    }

    fn decrypt_rtp(
        &mut self,
        ciphertext: &[u8],
        header: &rtp::Header,
        roc: u32,
    ) -> Result<BytesMut> {
        let tag_len = self.aead_auth_tag_len();
        if ciphertext.len() < tag_len {
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        let payload_offset = header.marshal_size();
        if ciphertext.len() < payload_offset + tag_len {
            // Too short to hold header + tag; the AEAD would reject it and the
            // slice split below would panic.
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        let nonce = self.rtp_initialization_vector(header, roc);

        // ring's `open_in_place` decrypts a contiguous ciphertext||tag region in
        // place and returns the plaintext slice; the header stays as AAD. Copy
        // the wire packet once, decrypt, then drop the trailing tag.
        let mut writer = BytesMut::with_capacity(ciphertext.len());
        writer.extend_from_slice(ciphertext);
        let final_len = writer.len() - tag_len;

        let (aad, ct_and_tag) = writer.split_at_mut(payload_offset);
        self.srtp_cipher
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad[..]),
                ct_and_tag,
            )
            .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;

        writer.truncate(final_len);
        Ok(writer)
    }

    fn encrypt_rtcp(
        &mut self,
        decrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
    ) -> Result<BytesMut> {
        let iv = self.rtcp_initialization_vector(srtcp_index, ssrc);
        let aad = self.rtcp_additional_authenticated_data(decrypted, srtcp_index);

        let mut writer =
            BytesMut::with_capacity(decrypted.len() + self.aead_auth_tag_len() + SRTCP_INDEX_SIZE);
        writer.extend_from_slice(decrypted);

        let tag = self
            .srtcp_cipher
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(iv),
                Aad::from(&aad[..]),
                &mut writer[8..],
            )
            .map_err(|_| Error::Other("SRTCP AES-GCM seal failed".to_string()))?;

        writer.extend_from_slice(tag.as_ref());
        writer.extend_from_slice(&aad[8..]);

        Ok(writer)
    }

    fn decrypt_rtcp(
        &mut self,
        encrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
    ) -> Result<BytesMut> {
        let tag_len = self.aead_auth_tag_len();
        if encrypted.len() < tag_len + SRTCP_INDEX_SIZE {
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        let nonce = self.rtcp_initialization_vector(srtcp_index, ssrc);
        let aad = self.rtcp_additional_authenticated_data(encrypted, srtcp_index);

        let tag_start = encrypted.len() - SRTCP_INDEX_SIZE - tag_len;
        if tag_start < 8 {
            // Too short to hold the SRTCP header + tag; the AEAD would reject it.
            return Err(Error::ErrFailedToVerifyAuthTag);
        }

        // Copy header(8) || ciphertext || tag (dropping the trailing ESRTCP index
        // word), decrypt the ciphertext+tag region in place, then drop the tag.
        let mut writer = BytesMut::with_capacity(tag_start + tag_len);
        writer.extend_from_slice(&encrypted[..tag_start + tag_len]);

        {
            let (_, ct_and_tag) = writer.split_at_mut(8);
            self.srtcp_cipher
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad[..]),
                    ct_and_tag,
                )
                .map_err(|_| Error::ErrFailedToVerifyAuthTag)?;
        }

        writer.truncate(tag_start);
        Ok(writer)
    }

    fn get_rtcp_index(&self, input: &[u8]) -> usize {
        let pos = input.len() - 4;
        let val = BigEndian::read_u32(&input[pos..]);

        (val & !((RTCP_ENCRYPTION_FLAG as u32) << 24)) as usize
    }
}

impl CipherAeadAesGcm {
    /// Create a new AEAD instance.
    pub(crate) fn new(
        profile: ProtectionProfile,
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<CipherAeadAesGcm> {
        let (algorithm, kdf): (&'static Algorithm, Kdf) = match profile {
            ProtectionProfile::AeadAes128Gcm => (&AES_128_GCM, aes_cm_key_derivation),
            // AES_256_GCM must use AES_256_CM_PRF as per https://datatracker.ietf.org/doc/html/rfc7714#section-11
            ProtectionProfile::AeadAes256Gcm => (&AES_256_GCM, aes_256_cm_key_derivation),
            _ => unreachable!(),
        };

        assert_eq!(
            profile.aead_auth_tag_len(),
            CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN
        );
        assert_eq!(profile.salt_len(), master_salt.len());

        let build_cipher = |label: u8| -> Result<LessSafeKey> {
            let session_key = kdf(label, master_key, master_salt, 0, master_key.len())?;
            let unbound = UnboundKey::new(algorithm, &session_key)
                .map_err(|_| Error::Other("invalid SRTP AES-GCM session key".to_string()))?;
            Ok(LessSafeKey::new(unbound))
        };

        let srtp_cipher = build_cipher(LABEL_SRTP_ENCRYPTION)?;
        let srtcp_cipher = build_cipher(LABEL_SRTCP_ENCRYPTION)?;

        let srtp_session_salt = kdf(
            LABEL_SRTP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;

        let srtcp_session_salt = kdf(
            LABEL_SRTCP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;

        Ok(CipherAeadAesGcm {
            profile,
            srtp_cipher,
            srtcp_cipher,
            srtp_session_salt,
            srtcp_session_salt,
        })
    }

    /// The 12-octet IV used by AES-GCM SRTP is formed by first concatenating
    /// 2 octets of zeroes, the 4-octet SSRC, the 4-octet rollover counter
    /// (ROC), and the 2-octet sequence number (SEQ).  The resulting 12-octet
    /// value is then XORed to the 12-octet salt to form the 12-octet IV.
    ///
    /// https://tools.ietf.org/html/rfc7714#section-8.1
    pub(crate) fn rtp_initialization_vector(&self, header: &rtp::Header, roc: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        BigEndian::write_u32(&mut iv[2..], header.ssrc);
        BigEndian::write_u32(&mut iv[6..], roc);
        BigEndian::write_u16(&mut iv[10..], header.sequence_number);

        for (i, v) in iv.iter_mut().enumerate() {
            *v ^= self.srtp_session_salt[i];
        }

        iv
    }

    /// The 12-octet IV used by AES-GCM SRTCP is formed by first
    /// concatenating 2 octets of zeroes, the 4-octet SSRC identifier,
    /// 2 octets of zeroes, a single "0" bit, and the 31-bit SRTCP index.
    /// The resulting 12-octet value is then XORed to the 12-octet salt to
    /// form the 12-octet IV.
    ///
    /// https://tools.ietf.org/html/rfc7714#section-9.1
    pub(crate) fn rtcp_initialization_vector(&self, srtcp_index: usize, ssrc: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];

        BigEndian::write_u32(&mut iv[2..], ssrc);
        BigEndian::write_u32(&mut iv[8..], srtcp_index as u32);

        for (i, v) in iv.iter_mut().enumerate() {
            *v ^= self.srtcp_session_salt[i];
        }

        iv
    }

    /// In an SRTCP packet, a 1-bit Encryption flag is prepended to the
    /// 31-bit SRTCP index to form a 32-bit value we shall call the
    /// "ESRTCP word"
    ///
    /// https://tools.ietf.org/html/rfc7714#section-17
    pub(crate) fn rtcp_additional_authenticated_data(
        &self,
        rtcp_packet: &[u8],
        srtcp_index: usize,
    ) -> [u8; 12] {
        let mut aad = [0u8; 12];

        aad[..8].copy_from_slice(&rtcp_packet[..8]);

        BigEndian::write_u32(&mut aad[8..], srtcp_index as u32);

        aad[8] |= RTCP_ENCRYPTION_FLAG;
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_aes_gcm_128() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let mut cipher = CipherAeadAesGcm::new(profile, &master_key, &master_salt).unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        let payload = vec![0u8; 100];
        let encrypted = cipher.encrypt_rtp(&payload, &header, 0).unwrap();

        let decrypted = cipher.decrypt_rtp(&encrypted, &header, 0).unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }

    /// Inputs long enough to pass the tag-length check but too short to hold
    /// header + tag must fail cleanly instead of panicking on a slice split.
    #[test]
    fn test_aead_aes_gcm_short_input_errors() {
        let profile = ProtectionProfile::AeadAes128Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let mut cipher = CipherAeadAesGcm::new(profile, &master_key, &master_salt).unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        // 20 bytes: >= the 16-byte tag, but < 12-byte header + 16-byte tag.
        assert!(cipher.decrypt_rtp(&[0u8; 20], &header, 0).is_err());

        // 24 bytes: >= tag + 4-byte SRTCP index, but < 8-byte SRTCP header
        // + tag + index.
        assert!(cipher.decrypt_rtcp(&[0u8; 24], 0, 0x12345678).is_err());
    }

    #[test]
    fn test_aead_aes_gcm_256() {
        let profile = ProtectionProfile::AeadAes256Gcm;
        let master_key = vec![0u8; profile.key_len()];
        let master_salt = vec![0u8; 12];

        let mut cipher = CipherAeadAesGcm::new(profile, &master_key, &master_salt).unwrap();

        let header = rtp::Header {
            ssrc: 0x12345678,
            ..Default::default()
        };

        let payload = vec![0u8; 100];
        let encrypted = cipher.encrypt_rtp(&payload, &header, 0).unwrap();

        let decrypted = cipher.decrypt_rtp(&encrypted, &header, 0).unwrap();
        assert_eq!(&decrypted[..], &payload[..]);
    }
}
