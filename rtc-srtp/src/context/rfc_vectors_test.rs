//! RFC known-answer vectors through the whole `Context` path, ported from pion's
//! `TestAesCiphersWithRfcTestVectors` (RFC 3711 appendix B.2 and RFC 6188 section 7.1) and
//! `TestAeadCiphersWithRfcTestVectors` (RFC 7714 sections 16 and 17).
//!
//! These vectors state the *session* key and salt directly, bypassing the RFC 3711 key
//! derivation [`Context::new`](super::Context::new) performs, so the ciphers are built with the
//! test-only `new_with_session_keys` and wrapped with the test-only
//! [`Context::new_with_cipher`](super::Context::new_with_cipher) — the same corner pion's test
//! suite reaches through `newSrtpCipher*WithDerivedKeys` and `createContextWithCipher`. The
//! derivation itself is verified against the RFC 3711 appendix B.3 and RFC 6188 section 7.2
//! values in `key_derivation.rs`.

use super::*;

fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 3711 appendix B.2 and RFC 6188 section 7.1: the packet is the RFC's (zero SSRC, zero
/// sequence number) header followed by an all-zero payload, so the SRTP payload *is* the AES-CM
/// keystream. The trailing HMAC tag is not part of the vectors and is not asserted.
#[test]
fn test_aes_ciphers_with_rfc_test_vectors() -> Result<()> {
    struct Case {
        profile: ProtectionProfile,
        session_key: &'static str,
        /// 14 octets: the RFC states the 16-octet salt form, whose last two octets are zero.
        session_salt: &'static str,
        keystream: &'static str,
    }

    let cases = [
        // AES-128-CM, RFC 3711 appendix B.2
        Case {
            profile: ProtectionProfile::Aes128CmHmacSha1_80,
            session_key: "2b7e151628aed2a6abf7158809cf4f3c",
            session_salt: "f0f1f2f3f4f5f6f7f8f9fafbfcfd",
            keystream: "e03ead0935c95e80e166b16dd92b4eb4
                        d23513162b02d0f72a43a2fe4a5f97ab
                        41e95b3bb0a2e8dd477901e4fca894c0",
        },
        // AES-256-CM, RFC 6188 section 7.1
        Case {
            profile: ProtectionProfile::Aes256CmHmacSha1_80,
            session_key: "57f82fe3613fd170a85ec93c40b1f0922ec4cb0dc025b58272147cc438944a98",
            session_salt: "f0f1f2f3f4f5f6f7f8f9fafbfcfd",
            keystream: "92bdd28a93c3f52511c677d08b5515a4
                        9da71b2378a854f67050756ded165bac
                        63c4868b7096d88421b563b8c94c9a31",
        },
    ];

    let provider = test_crypto_provider();
    for case in cases {
        let key = unhex(case.session_key);
        let salt = unhex(case.session_salt);
        let keystream = unhex(case.keystream);

        let cipher = CipherAesCmHmacSha1::new_with_session_keys(
            case.profile,
            &key,
            &key,
            &salt,
            &salt,
            provider.crypto(),
        )?;
        let mut ctx = Context::new_with_cipher(Box::new(cipher));

        // Header with zero SSRC and sequence number, as the RFCs specify, then a zero payload.
        let rtp_header = unhex("800f0000decafbad00000000");
        let mut packet = rtp_header.clone();
        packet.extend_from_slice(&vec![0u8; keystream.len()]);

        let encrypted = ctx.encrypt_rtp(&packet)?;

        assert_eq!(
            &encrypted[..rtp_header.len()],
            &rtp_header[..],
            "{:?}: header must not change",
            case.profile
        );
        assert_eq!(
            &encrypted[rtp_header.len()..rtp_header.len() + keystream.len()],
            &keystream[..],
            "{:?}: zero payload must come back as the RFC keystream",
            case.profile
        );
    }

    Ok(())
}

/// RFC 7714 sections 16 and 17: AES-GCM protection of the RFC's RTP and RTCP packets, with the
/// SRTCP index the RFC used (0x5d4) installed beforehand.
#[test]
fn test_aead_ciphers_with_rfc_test_vectors() -> Result<()> {
    struct Case {
        profile: ProtectionProfile,
        session_key: &'static str,
        session_salt: &'static str,
        decrypted_rtp: &'static str,
        encrypted_rtp: &'static str,
        decrypted_rtcp: &'static str,
        encrypted_rtcp: &'static str,
    }

    let cases = [
        // AES-128-GCM, RFC 7714 sections 16 and 17
        Case {
            profile: ProtectionProfile::AeadAes128Gcm,
            session_key: "000102030405060708090a0b0c0d0e0f",
            session_salt: "517569642070726f2071756f",
            decrypted_rtp: "8040f17b8041f8d35501a0b247616c6c
                            696120657374206f6d6e697320646976
                            69736120696e20706172746573207472
                            6573",
            encrypted_rtp: "8040f17b8041f8d35501a0b2f24de3a3
                            fb34de6cacba861c9d7e4bcabe633bd5
                            0d294e6f42a5f47a51c7d19b36de3adf
                            8833899d7f27beb16a9152cf765ee439
                            0cce",
            decrypted_rtcp: "81c8000d4d6172734e5450314e545032
                             525450200000042a0000e9304c756e61
                             deadbeefdeadbeefdeadbeefdeadbeef
                             deadbeef",
            encrypted_rtcp: "81c8000d4d61727363e94885dcdab67c
                             a727d7662f6b7e997ff5c0f76c06f32d
                             c676a5f1730d6fda4ce09b4686303ded
                             0bb9275bc84aa45896cf4d2fc5abf872
                             45d9eade800005d4",
        },
        // AES-256-GCM, RFC 7714 sections 16 and 17
        Case {
            profile: ProtectionProfile::AeadAes256Gcm,
            session_key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            session_salt: "517569642070726f2071756f",
            decrypted_rtp: "8040f17b8041f8d35501a0b247616c6c
                            696120657374206f6d6e697320646976
                            69736120696e20706172746573207472
                            6573",
            encrypted_rtp: "8040f17b8041f8d35501a0b232b1de78
                            a822fe12ef9f78fa332e33aab1801238
                            9a58e2f3b50b2a0276ffae0f1ba63799
                            b87b7aa3db36dfff d6b0f9bb7878d7a7
                            6c13",
            decrypted_rtcp: "81c8000d4d6172734e5450314e545032
                             525450200000042a0000e9304c756e61
                             deadbeefdeadbeefdeadbeefdeadbeef
                             deadbeef",
            encrypted_rtcp: "81c8000d4d617273d50ae4d1f5ce5d30
                             4ba297e47d470c282c3ece5dbffe0a50
                             a2eaa5c1110555be8415f658c61de047
                             6f1b6fad1d1eb30c4446839f57ff6f6c
                             b26ac3be800005d4",
        },
    ];

    let provider = test_crypto_provider();
    for case in cases {
        let key = unhex(case.session_key);
        let salt = unhex(case.session_salt);
        let decrypted_rtp = unhex(case.decrypted_rtp);
        let encrypted_rtp = unhex(case.encrypted_rtp);
        let decrypted_rtcp = unhex(case.decrypted_rtcp);
        let encrypted_rtcp = unhex(case.encrypted_rtcp);

        let make_context = || -> Result<Context> {
            let cipher = CipherAeadAesGcm::new_with_session_keys(
                case.profile,
                &key,
                &key,
                &salt,
                &salt,
                provider.crypto(),
            )?;
            Ok(Context::new_with_cipher(Box::new(cipher)))
        };

        // The RTCP packets were protected at SRTCP index 0x5d4; installing 0x5d3 makes the
        // context's next packet use it.
        let mut encrypt = make_context()?;
        encrypt.set_index(0x4d61_7273, 0x0000_05d3);
        let actual = encrypt.encrypt_rtp(&decrypted_rtp)?;
        assert_eq!(
            &actual[..],
            &encrypted_rtp[..],
            "{:?}: EncryptRTP",
            case.profile
        );

        let mut decrypt = make_context()?;
        decrypt.set_index(0x4d61_7273, 0x0000_05d3);
        let actual = decrypt.decrypt_rtp(&encrypted_rtp)?;
        assert_eq!(
            &actual[..],
            &decrypted_rtp[..],
            "{:?}: DecryptRTP",
            case.profile
        );

        let mut encrypt = make_context()?;
        encrypt.set_index(0x4d61_7273, 0x0000_05d3);
        let actual = encrypt.encrypt_rtcp(&decrypted_rtcp)?;
        assert_eq!(
            &actual[..],
            &encrypted_rtcp[..],
            "{:?}: EncryptRTCP",
            case.profile
        );

        let mut decrypt = make_context()?;
        decrypt.set_index(0x4d61_7273, 0x0000_05d3);
        let actual = decrypt.decrypt_rtcp(&encrypted_rtcp)?;
        assert_eq!(
            &actual[..],
            &decrypted_rtcp[..],
            "{:?}: DecryptRTCP",
            case.profile
        );
    }

    Ok(())
}
