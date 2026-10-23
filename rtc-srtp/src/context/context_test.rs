use super::*;
use crate::key_derivation::*;

/// The built-in provider, for tests only. Library code never resolves a default: every public
/// constructor takes the provider from its caller.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

use bytes::Bytes;
use lazy_static::lazy_static;

const CIPHER_CONTEXT_ALGO: ProtectionProfile = ProtectionProfile::Aes128CmHmacSha1_80;
const DEFAULT_SSRC: u32 = 0;

#[test]
fn test_context_roc() -> Result<()> {
    let key_len = CIPHER_CONTEXT_ALGO.key_len();
    let salt_len = CIPHER_CONTEXT_ALGO.salt_len();

    let mut c = Context::new(
        &vec![0; key_len],
        &vec![0; salt_len],
        CIPHER_CONTEXT_ALGO,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    let roc = c.get_roc(123);
    assert!(roc.is_none(), "ROC must return None for unused SSRC");

    c.set_roc(123, 100);
    let roc = c.get_roc(123);
    if let Some(r) = roc {
        assert_eq!(r, 100, "ROC is set to 100, but returned {r}")
    } else {
        panic!("ROC must return value for used SSRC");
    }

    Ok(())
}

#[test]
fn test_context_index() -> Result<()> {
    let key_len = CIPHER_CONTEXT_ALGO.key_len();
    let salt_len = CIPHER_CONTEXT_ALGO.salt_len();

    let mut c = Context::new(
        &vec![0; key_len],
        &vec![0; salt_len],
        CIPHER_CONTEXT_ALGO,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    let index = c.get_index(123);
    assert!(index.is_none(), "Index must return None for unused SSRC");

    c.set_index(123, 100);
    let index = c.get_index(123);
    if let Some(i) = index {
        assert_eq!(i, 100, "Index is set to 100, but returned {i}");
    } else {
        panic!("Index must return true for used SSRC")
    }

    Ok(())
}

#[test]
fn test_key_len() -> Result<()> {
    let key_len = CIPHER_CONTEXT_ALGO.key_len();
    let salt_len = CIPHER_CONTEXT_ALGO.salt_len();

    let result = Context::new(
        &[],
        &vec![0; salt_len],
        CIPHER_CONTEXT_ALGO,
        None,
        None,
        test_crypto_provider().crypto(),
    );
    assert!(result.is_err(), "CreateContext accepted a 0 length key");

    let result = Context::new(
        &vec![0; key_len],
        &[],
        CIPHER_CONTEXT_ALGO,
        None,
        None,
        test_crypto_provider().crypto(),
    );
    assert!(result.is_err(), "CreateContext accepted a 0 length salt");

    let result = Context::new(
        &vec![0; key_len],
        &vec![0; salt_len],
        CIPHER_CONTEXT_ALGO,
        None,
        None,
        test_crypto_provider().crypto(),
    );
    assert!(
        result.is_ok(),
        "CreateContext failed with a valid length key and salt"
    );

    Ok(())
}

#[test]
fn test_valid_packet_counter() -> Result<()> {
    let master_key = vec![
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ];
    let master_salt = vec![
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ];

    let srtp_session_salt = aes_cm_key_derivation(
        crypto::default_provider()
            .map_err(|error| Error::Crypto(error.to_string()))?
            .crypto(),
        LABEL_SRTP_SALT,
        &master_key,
        &master_salt,
        0,
        master_salt.len(),
    )?;

    let s = SrtpSsrcState {
        ssrc: 4160032510,
        ..Default::default()
    };
    let expected_counter = [
        0xcf, 0x90, 0x1e, 0xa5, 0xda, 0xd3, 0x2c, 0x15, 0x00, 0xa2, 0x24, 0xae, 0xae, 0xaf, 0x00,
        0x00,
    ];
    let counter = generate_counter(32846, (s.index >> 16) as _, s.ssrc, &srtp_session_salt);
    assert_eq!(
        counter, expected_counter,
        "Session Key {counter:?} does not match expected {expected_counter:?}",
    );

    Ok(())
}

#[test]
fn test_rollover_count() -> Result<()> {
    let mut s = SrtpSsrcState::default();

    // Set initial seqnum
    let (roc, diff, ovf) = s.next_rollover_count(65530);
    assert_eq!(roc, 0, "Initial rolloverCounter must be 0");
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(65530, diff);

    // Invalid packets never update ROC
    s.next_rollover_count(0);
    s.next_rollover_count(0x4000);
    s.next_rollover_count(0x8000);
    s.next_rollover_count(0xFFFF);
    s.next_rollover_count(0);

    // We rolled over to 0
    let (roc, diff, ovf) = s.next_rollover_count(0);
    assert_eq!(roc, 1, "rolloverCounter was not updated after it crossed 0");
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(0, diff);

    let (roc, diff, ovf) = s.next_rollover_count(65530);
    assert_eq!(
        roc, 0,
        "rolloverCounter was not updated when it rolled back, failed to handle out of order"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(65530, diff);

    let (roc, diff, ovf) = s.next_rollover_count(5);
    assert_eq!(
        roc, 1,
        "rolloverCounter was not updated when it rolled over initial, to handle out of order"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(5, diff);

    let (_, diff, _) = s.next_rollover_count(6);
    s.update_rollover_count(6, diff);
    let (_, diff, _) = s.next_rollover_count(7);
    s.update_rollover_count(7, diff);
    let (roc, diff, _) = s.next_rollover_count(8);
    assert_eq!(
        roc, 1,
        "rolloverCounter was improperly updated for non-significant packets"
    );
    s.update_rollover_count(8, diff);

    // valid packets never update ROC
    let (roc, diff, ovf) = s.next_rollover_count(0x4000);
    assert_eq!(
        roc, 1,
        "rolloverCounter was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(0x4000, diff);
    let (roc, diff, ovf) = s.next_rollover_count(0x8000);
    assert_eq!(
        roc, 1,
        "rolloverCounter was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(0x8000, diff);
    let (roc, diff, ovf) = s.next_rollover_count(0xFFFF);
    assert_eq!(
        roc, 1,
        "rolloverCounter was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(0xFFFF, diff);
    let (roc, _, ovf) = s.next_rollover_count(0);
    assert_eq!(
        roc, 2,
        "rolloverCounter must be incremented after wrapping, got {roc}"
    );
    assert!(!ovf, "Should not overflow");

    Ok(())
}

#[test]
fn test_rollover_count_overflow() -> Result<()> {
    let mut s = SrtpSsrcState {
        index: (MAX_ROC as u64) << 16,
        ..Default::default()
    };
    s.update_rollover_count(0xFFFF, 0);
    let (_, _, ovf) = s.next_rollover_count(0);
    assert!(ovf, "Should overflow");

    Ok(())
}

#[test]
fn test_rollover_count_2() -> Result<()> {
    let mut s = SrtpSsrcState::default();

    let (roc, diff, ovf) = s.next_rollover_count(30123);
    assert_eq!(roc, 0, "Initial rolloverCounter must be 0");
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(30123, diff);

    // 62892 = 30123 + (1 << 15) + 1
    let (roc, diff, ovf) = s.next_rollover_count(62892);
    assert_eq!(roc, 0, "Initial rolloverCounter must be 0");
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(62892, diff);
    let (roc, diff, ovf) = s.next_rollover_count(204);
    assert_eq!(roc, 1, "rolloverCounter was not updated after it crossed 0");
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(62892, diff);
    let (roc, diff, ovf) = s.next_rollover_count(64535);
    assert_eq!(
        roc, 0,
        "rolloverCounter was not updated when it rolled back, failed to handle out of order"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(64535, diff);
    let (roc, diff, ovf) = s.next_rollover_count(205);
    assert_eq!(
        roc, 1,
        "rolloverCounter was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(205, diff);
    let (roc, diff, ovf) = s.next_rollover_count(1);
    assert_eq!(
        roc, 1,
        "rolloverCounter was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(1, diff);

    let (roc, diff, ovf) = s.next_rollover_count(64532);
    assert_eq!(
        roc, 0,
        "rolloverCounter was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(64532, diff);
    let (roc, diff, ovf) = s.next_rollover_count(64534);
    assert_eq!(
        roc, 0,
        "index was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(64534, diff);
    let (roc, diff, ovf) = s.next_rollover_count(64532);
    assert_eq!(
        roc, 0,
        "index was improperly updated for non-significant packets"
    );
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(64532, diff);
    let (roc, diff, ovf) = s.next_rollover_count(205);
    assert_eq!(roc, 1, "index was not updated after it crossed 0");
    assert!(!ovf, "Should not overflow");
    s.update_rollover_count(205, diff);

    Ok(())
}

lazy_static! {
    static ref MASTER_KEY_16_BYTES: Bytes = Bytes::from_static(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]);
    static ref MASTER_KEY_32_BYTES: Bytes = Bytes::from_static(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f
    ]);
    static ref MASTER_SALT_12_BYTES: Bytes = Bytes::from_static(&[
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
    ]);
    static ref MASTER_SALT_14_BYTES: Bytes = Bytes::from_static(&[
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad
    ]);
    static ref DECRYPTED_RTP_PACKET: Bytes = Bytes::from_static(&[
        0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    ]);
    static ref ENCRYPTED_AEAD_AES_128_GCM_RTP_PACKET: Bytes = Bytes::from_static(&[
        0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xc5, 0x00, 0x2e,
        0xde, 0x04, 0xcf, 0xdd, 0x2e, 0xb9, 0x11, 0x59, 0xe0, 0x88, 0x0a, 0xa0, 0x6e, 0xd2, 0x97,
        0x68, 0x26, 0xf7, 0x96, 0xb2, 0x01, 0xdf, 0x31, 0x31, 0xa1, 0x27, 0xe8, 0xa3, 0x92,
    ]);
    static ref ENCRYPTED_AES_256_CM_RTP_PACKET: Bytes = Bytes::from_static(&[
        0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xac, 0x3b, 0xca,
        0x88, 0x14, 0x37, 0x57, 0x83, 0x35, 0xc6, 0xd4, 0x57, 0xf1, 0xc3, 0x6b, 0xa7, 0x3d, 0x71,
        0x48, 0x63, 0x90, 0x9b, 0xbf, 0x15, 0xac, 0xec
    ]);
    static ref DECRYPTED_RTCP_PACKET: Bytes = Bytes::from_static(&[
        0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    ]);
    static ref ENCRYPTED_AEAD_AES_128_GCM_RTCP_PACKET: Bytes = Bytes::from_static(&[
        0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xc9, 0x8b, 0x8b, 0x5d, 0xf0, 0x39, 0x2a,
        0x55, 0x85, 0x2b, 0x6c, 0x21, 0xac, 0x8e, 0x70, 0x25, 0xc5, 0x2c, 0x6f, 0xbe, 0xa2, 0xb3,
        0xb4, 0x46, 0xea, 0x31, 0x12, 0x3b, 0xa8, 0x8c, 0xe6, 0x1e, 0x80, 0x00, 0x00, 0x01,
    ]);
    static ref ENCRYPTED_AES_256_CM_RTCP_PACKET: Bytes = Bytes::from_static(&[
        0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x97, 0x04, 0x31, 0xdc, 0x4a, 0xe6, 0xd2,
        0xaf, 0xd6, 0x54, 0xbf, 0x90, 0xf4, 0x35, 0x44, 0x9e, 0x80, 0x00, 0x00, 0x01, 0xbf, 0x18,
        0x18, 0x2d, 0xd1, 0x18, 0x81, 0x28, 0x78, 0xb1
    ]);
}

#[test]
fn test_encrypt_aead_aes_128_gcm_rtp() {
    let mut ctx = Context::new(
        &MASTER_KEY_16_BYTES,
        &MASTER_SALT_12_BYTES,
        ProtectionProfile::AeadAes128Gcm,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_encrypted_rtp_packet = ctx
        .encrypt_rtp(&DECRYPTED_RTP_PACKET)
        .expect("Error encrypting rtp payload");

    assert_eq!(
        gotten_encrypted_rtp_packet,
        *ENCRYPTED_AEAD_AES_128_GCM_RTP_PACKET
    )
}

#[test]
fn test_decrypt_aead_aes_128_gcm_rtp() {
    let mut ctx = Context::new(
        &MASTER_KEY_16_BYTES,
        &MASTER_SALT_12_BYTES,
        ProtectionProfile::AeadAes128Gcm,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_decrypted_rtp_packet = ctx
        .decrypt_rtp(&ENCRYPTED_AEAD_AES_128_GCM_RTP_PACKET)
        .expect("Error decrypting rtp payload");

    assert_eq!(gotten_decrypted_rtp_packet, *DECRYPTED_RTP_PACKET)
}

#[test]
fn test_encrypt_aead_aes_128_gcm_rtcp() {
    let mut ctx = Context::new(
        &MASTER_KEY_16_BYTES,
        &MASTER_SALT_12_BYTES,
        ProtectionProfile::AeadAes128Gcm,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_encrypted_rtcp_packet = ctx
        .encrypt_rtcp(&DECRYPTED_RTCP_PACKET)
        .expect("Error encrypting rtcp payload");

    assert_eq!(
        gotten_encrypted_rtcp_packet,
        *ENCRYPTED_AEAD_AES_128_GCM_RTCP_PACKET
    )
}

#[test]
fn test_decrypt_aead_aes_128_gcm_rtcp() {
    let mut ctx = Context::new(
        &MASTER_KEY_16_BYTES,
        &MASTER_SALT_12_BYTES,
        ProtectionProfile::AeadAes128Gcm,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_decrypted_rtcp_packet = ctx
        .decrypt_rtcp(&ENCRYPTED_AEAD_AES_128_GCM_RTCP_PACKET)
        .expect("Error decrypting rtcp payload");

    assert_eq!(gotten_decrypted_rtcp_packet, *DECRYPTED_RTCP_PACKET)
}

#[test]
fn test_encrypt_aes_256_cm_rtp() {
    let mut ctx = Context::new(
        &MASTER_KEY_32_BYTES,
        &MASTER_SALT_14_BYTES,
        ProtectionProfile::Aes256CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_encrypted_rtp_packet = ctx
        .encrypt_rtp(&DECRYPTED_RTP_PACKET)
        .expect("Error encrypting rtp payload");

    assert_eq!(
        gotten_encrypted_rtp_packet,
        *ENCRYPTED_AES_256_CM_RTP_PACKET
    )
}

#[test]
fn test_decrypt_aes_256_cm_rtp() {
    let mut ctx = Context::new(
        &MASTER_KEY_32_BYTES,
        &MASTER_SALT_14_BYTES,
        ProtectionProfile::Aes256CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_decrypted_rtp_packet = ctx
        .decrypt_rtp(&ENCRYPTED_AES_256_CM_RTP_PACKET)
        .expect("Error decrypting rtp payload");

    assert_eq!(gotten_decrypted_rtp_packet, *DECRYPTED_RTP_PACKET)
}

#[test]
fn test_encrypt_aes_256_cm_rtcp() {
    let mut ctx = Context::new(
        &MASTER_KEY_32_BYTES,
        &MASTER_SALT_14_BYTES,
        ProtectionProfile::Aes256CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_encrypted_rtcp_packet = ctx
        .encrypt_rtcp(&DECRYPTED_RTCP_PACKET)
        .expect("Error encrypting rtcp payload");

    assert_eq!(
        gotten_encrypted_rtcp_packet,
        *ENCRYPTED_AES_256_CM_RTCP_PACKET
    )
}

#[test]
fn test_decrypt_aes_256_cm_rtcp() {
    let mut ctx = Context::new(
        &MASTER_KEY_32_BYTES,
        &MASTER_SALT_14_BYTES,
        ProtectionProfile::Aes256CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )
    .expect("Error creating srtp context");

    let gotten_decrypted_rtcp_packet = ctx
        .decrypt_rtcp(&ENCRYPTED_AES_256_CM_RTCP_PACKET)
        .expect("Error decrypting rtcp payload");

    assert_eq!(gotten_decrypted_rtcp_packet, *DECRYPTED_RTCP_PACKET)
}

/// pion's `TestSrtpCipher`: the shared packet set (RTP for SSRC 0xcafebabe, RTCP likewise, both
/// at sequence number 0x1234 / SRTCP index 1) through every supported profile — encrypt and
/// decrypt, fresh and in place. pion's table also exercises NULL profiles and MKI variants;
/// those are the NULL-profile and MKI gaps, not covered here.
#[test]
fn test_srtp_cipher() -> Result<()> {
    use bytes::BytesMut;

    struct Case {
        profile: ProtectionProfile,
        encrypted_rtp: &'static [u8],
        encrypted_rtcp: &'static [u8],
    }

    let decrypted_rtp: &[u8] = &[
        0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    ];
    let decrypted_rtcp: &[u8] = &[
        0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    ];

    let cases = [
        Case {
            profile: ProtectionProfile::Aes128CmHmacSha1_32,
            encrypted_rtp: &[
                0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xe2, 0xd8,
                0xdf, 0x8f, 0x7a, 0x75, 0xd6, 0x88, 0xc3, 0x50, 0x2e, 0xee, 0xc2, 0xa9, 0x80, 0x66,
                0xcd, 0x7c, 0x0d, 0x09,
            ],
            encrypted_rtcp: &[
                0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x56, 0x74, 0xbf, 0x01, 0x81, 0x3d,
                0xc0, 0x62, 0xac, 0x1d, 0xf6, 0xf7, 0x5f, 0x77, 0xc6, 0x88, 0x80, 0x00, 0x00, 0x01,
                0x3d, 0xb7, 0xa1, 0x98, 0x37, 0xff, 0x64, 0xe5, 0xcb, 0xd2,
            ],
        },
        Case {
            profile: ProtectionProfile::Aes128CmHmacSha1_80,
            encrypted_rtp: &[
                0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xe2, 0xd8,
                0xdf, 0x8f, 0x7a, 0x75, 0xd6, 0x88, 0xc3, 0x50, 0x2e, 0xee, 0xc2, 0xa9, 0x80, 0x66,
                0xcd, 0x7c, 0x0d, 0x09, 0xca, 0x44, 0x32, 0xa5, 0x6e, 0x3d,
            ],
            encrypted_rtcp: &[
                0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x56, 0x74, 0xbf, 0x01, 0x81, 0x3d,
                0xc0, 0x62, 0xac, 0x1d, 0xf6, 0xf7, 0x5f, 0x77, 0xc6, 0x88, 0x80, 0x00, 0x00, 0x01,
                0x3d, 0xb7, 0xa1, 0x98, 0x37, 0xff, 0x64, 0xe5, 0xcb, 0xd2,
            ],
        },
        Case {
            profile: ProtectionProfile::Aes256CmHmacSha1_32,
            encrypted_rtp: &[
                0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xac, 0x3b,
                0xca, 0x88, 0x14, 0x37, 0x57, 0x83, 0x35, 0xc6, 0xd4, 0x57, 0xf1, 0xc3, 0x6b, 0xa7,
                0x3d, 0x71, 0x48, 0x63,
            ],
            encrypted_rtcp: &[
                0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x97, 0x04, 0x31, 0xdc, 0x4a, 0xe6,
                0xd2, 0xaf, 0xd6, 0x54, 0xbf, 0x90, 0xf4, 0x35, 0x44, 0x9e, 0x80, 0x00, 0x00, 0x01,
                0xbf, 0x18, 0x18, 0x2d, 0xd1, 0x18, 0x81, 0x28, 0x78, 0xb1,
            ],
        },
        Case {
            profile: ProtectionProfile::Aes256CmHmacSha1_80,
            encrypted_rtp: &[
                0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xac, 0x3b,
                0xca, 0x88, 0x14, 0x37, 0x57, 0x83, 0x35, 0xc6, 0xd4, 0x57, 0xf1, 0xc3, 0x6b, 0xa7,
                0x3d, 0x71, 0x48, 0x63, 0x90, 0x9b, 0xbf, 0x15, 0xac, 0xec,
            ],
            encrypted_rtcp: &[
                0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x97, 0x04, 0x31, 0xdc, 0x4a, 0xe6,
                0xd2, 0xaf, 0xd6, 0x54, 0xbf, 0x90, 0xf4, 0x35, 0x44, 0x9e, 0x80, 0x00, 0x00, 0x01,
                0xbf, 0x18, 0x18, 0x2d, 0xd1, 0x18, 0x81, 0x28, 0x78, 0xb1,
            ],
        },
        Case {
            profile: ProtectionProfile::AeadAes128Gcm,
            encrypted_rtp: &[
                0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xc5, 0x00,
                0x2e, 0xde, 0x04, 0xcf, 0xdd, 0x2e, 0xb9, 0x11, 0x59, 0xe0, 0x88, 0x0a, 0xa0, 0x6e,
                0xd2, 0x97, 0x68, 0x26, 0xf7, 0x96, 0xb2, 0x01, 0xdf, 0x31, 0x31, 0xa1, 0x27, 0xe8,
                0xa3, 0x92,
            ],
            encrypted_rtcp: &[
                0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xc9, 0x8b, 0x8b, 0x5d, 0xf0, 0x39,
                0x2a, 0x55, 0x85, 0x2b, 0x6c, 0x21, 0xac, 0x8e, 0x70, 0x25, 0xc5, 0x2c, 0x6f, 0xbe,
                0xa2, 0xb3, 0xb4, 0x46, 0xea, 0x31, 0x12, 0x3b, 0xa8, 0x8c, 0xe6, 0x1e, 0x80, 0x00,
                0x00, 0x01,
            ],
        },
        Case {
            profile: ProtectionProfile::AeadAes256Gcm,
            encrypted_rtp: &[
                0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xaf, 0x49,
                0x96, 0x8f, 0x7e, 0x9c, 0x43, 0xf8, 0x01, 0xdd, 0x0c, 0x84, 0x8b, 0x1e, 0xc9, 0xb0,
                0x29, 0xcd, 0xf8, 0x5c, 0xb7, 0x9a, 0x2f, 0x95, 0x60, 0xd4, 0x69, 0x75, 0x98, 0x50,
                0x77, 0x25,
            ],
            encrypted_rtcp: &[
                0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x98, 0x22, 0xba, 0x22, 0x96, 0x1c,
                0x31, 0x48, 0xe7, 0xb7, 0xec, 0x4f, 0x09, 0xf4, 0x26, 0xdc, 0xf6, 0xb5, 0x9a, 0x75,
                0xad, 0xec, 0x74, 0xfd, 0xb9, 0x51, 0xb6, 0x66, 0x84, 0x24, 0xd4, 0xe2, 0x80, 0x00,
                0x00, 0x01,
            ],
        },
    ];

    // pion's `createTestCiphers` keys every profile from the same material, sliced to size.
    let key_128: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let key_256: &[u8] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];
    let salt_14: &[u8] = &[
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad,
    ];
    let salt_12: &[u8] = &[
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
    ];

    for case in cases {
        let profile = case.profile;
        // pion's `createTestCiphers` keys every profile from the same material, sliced to size.
        let (master_key, master_salt): (&[u8], &[u8]) = match profile {
            ProtectionProfile::Aes128CmHmacSha1_32 | ProtectionProfile::Aes128CmHmacSha1_80 => {
                (key_128, salt_14)
            }
            ProtectionProfile::Aes256CmHmacSha1_32 | ProtectionProfile::Aes256CmHmacSha1_80 => {
                (key_256, salt_14)
            }
            ProtectionProfile::AeadAes128Gcm => (key_128, salt_12),
            ProtectionProfile::AeadAes256Gcm => (key_256, salt_12),
        };

        // Encrypt RTP, fresh allocation.
        let mut ctx = Context::new(
            master_key,
            master_salt,
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;
        let actual = ctx.encrypt_rtp(decrypted_rtp)?;
        assert_eq!(
            &actual[..],
            case.encrypted_rtp,
            "{profile:?}: EncryptRTP (new allocation)"
        );

        // Encrypt RTP, in place with the tag's worth of spare capacity.
        let mut ctx = Context::new(
            master_key,
            master_salt,
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;
        let mut buffer = BytesMut::with_capacity(decrypted_rtp.len() + ctx.rtp_overhead());
        buffer.extend_from_slice(decrypted_rtp);
        let before = buffer.as_ptr();
        ctx.encrypt_rtp_in_place(&mut buffer)?;
        assert_eq!(
            buffer.as_ptr(),
            before,
            "{profile:?}: EncryptRTP (same buffer) must not reallocate"
        );
        assert_eq!(
            &buffer[..],
            case.encrypted_rtp,
            "{profile:?}: EncryptRTP (same buffer)"
        );

        // Decrypt RTP.
        let mut ctx = Context::new(
            master_key,
            master_salt,
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;
        let actual = ctx.decrypt_rtp(case.encrypted_rtp)?;
        assert_eq!(&actual[..], decrypted_rtp, "{profile:?}: DecryptRTP");

        // Encrypt RTCP at index 1, as pion's SetIndex(0xcafebabe, 0) sets up.
        let mut ctx = Context::new(
            master_key,
            master_salt,
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;
        ctx.set_index(0xcafebabe, 0);
        let actual = ctx.encrypt_rtcp(decrypted_rtcp)?;
        assert_eq!(&actual[..], case.encrypted_rtcp, "{profile:?}: EncryptRTCP");

        // Decrypt RTCP.
        let mut ctx = Context::new(
            master_key,
            master_salt,
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;
        let actual = ctx.decrypt_rtcp(case.encrypted_rtcp)?;
        assert_eq!(&actual[..], decrypted_rtcp, "{profile:?}: DecryptRTCP");
    }

    Ok(())
}
