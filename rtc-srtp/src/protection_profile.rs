/// ProtectionProfile specifies Cipher and AuthTag details, similar to TLS cipher suite
#[derive(Default, Debug, Clone, Copy)]
#[repr(u8)]
pub enum ProtectionProfile {
    #[default]
    /// `SRTP_AES128_CM_HMAC_SHA1_80`: AES-128 counter mode with an 80-bit HMAC-SHA1 tag.
    ///
    /// The profile every WebRTC implementation supports.
    Aes128CmHmacSha1_80 = 0x0001,
    /// `SRTP_AES128_CM_HMAC_SHA1_32`: as above with a truncated 32-bit tag, trading
    /// authentication strength for 6 bytes per packet.
    Aes128CmHmacSha1_32 = 0x0002,
    /// `SRTP_AES256_CM_HMAC_SHA1_80`: AES-256 counter mode with an 80-bit HMAC-SHA1 tag.
    Aes256CmHmacSha1_80 = 0x0003,
    /// `SRTP_AES256_CM_HMAC_SHA1_32`: AES-256 counter mode with a 32-bit HMAC-SHA1 tag.
    Aes256CmHmacSha1_32 = 0x0004,
    /// `SRTP_AEAD_AES_128_GCM`: AES-128 in GCM, which authenticates as part of encryption
    /// rather than with a separate HMAC.
    AeadAes128Gcm = 0x0007,
    /// `SRTP_AEAD_AES_256_GCM`: AES-256 in GCM.
    AeadAes256Gcm = 0x0008,
}

impl ProtectionProfile {
    /// The master key length in bytes for this profile.
    pub fn key_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::AeadAes128Gcm => 16,
            ProtectionProfile::Aes256CmHmacSha1_32 | ProtectionProfile::Aes256CmHmacSha1_80 => 32,
            ProtectionProfile::AeadAes256Gcm => 32,
        }
    }

    /// The master salt length in bytes for this profile.
    pub fn salt_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32
            | ProtectionProfile::Aes256CmHmacSha1_80 => 14,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 12,
        }
    }

    /// The authentication tag length appended to each SRTP packet, in bytes.
    pub fn rtp_auth_tag_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80 | ProtectionProfile::Aes256CmHmacSha1_80 => 10,
            ProtectionProfile::Aes128CmHmacSha1_32 | ProtectionProfile::Aes256CmHmacSha1_32 => 4,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }

    /// The authentication tag length appended to each SRTCP packet, in bytes.
    pub fn rtcp_auth_tag_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => 10,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }

    /// The AEAD tag length in bytes, for the GCM profiles; `0` for the HMAC-SHA1 ones.
    pub fn aead_auth_tag_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => 0,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 16,
        }
    }

    /// The HMAC authentication key length in bytes; `0` for the AEAD profiles, which derive
    /// authentication from the cipher itself.
    pub fn auth_key_len(&self) -> usize {
        match *self {
            ProtectionProfile::Aes128CmHmacSha1_80
            | ProtectionProfile::Aes128CmHmacSha1_32
            | ProtectionProfile::Aes256CmHmacSha1_80
            | ProtectionProfile::Aes256CmHmacSha1_32 => 20,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }
}
