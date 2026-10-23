use super::*;
use crate::key_derivation::*;

/// The built-in provider, for tests only. Library code never resolves a default: every public
/// constructor takes the provider from its caller.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

use bytes::{Buf, Bytes, BytesMut};
use lazy_static::lazy_static;

#[derive(Clone)]
pub struct RTCPTestCase {
    ssrc: u32,
    index: usize,
    encrypted: Bytes,
    decrypted: Bytes,
}

/// One of pion's `rtcpTestCases` entries: a profile with its key material and packets.
struct RTCPCaseSet {
    algo: ProtectionProfile,
    master_key: Bytes,
    master_salt: Bytes,
    packets: Vec<RTCPTestCase>,
}

// AES_128_CM_HMAC_SHA1_80 packets, pion's `rtcpTestCases` plus the two upper-index cases
// pion keeps in `TestRTCPMaxPackets`.
lazy_static! {
    static ref RTCP_TEST_MASTER_KEY: Bytes = Bytes::from_static(&[
        0xfd, 0xa6, 0x25, 0x95, 0xd7, 0xf6, 0x92, 0x6f, 0x7d, 0x9c, 0x02, 0x4c, 0xc9, 0x20, 0x9f,
        0x34
    ]);

    static ref RTCP_TEST_MASTER_SALT: Bytes = Bytes::from_static(&[
        0xa9, 0x65, 0x19, 0x85, 0x54, 0x0b, 0x47, 0xbe, 0x2f, 0x27, 0xa8, 0xb8, 0x81, 0x23
    ]);

    static ref RTCP_TEST_CASES: Vec<RTCPTestCase> = vec![
        RTCPTestCase {
            ssrc:      0x66ef91ff,
            index:     0,
            encrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0xcd, 0x34, 0xc5, 0x78, 0xb2, 0x8b,
                0xe1, 0x6b, 0xc5, 0x09, 0xd5, 0x77, 0xe4, 0xce, 0x5f, 0x20, 0x80, 0x21, 0xbd, 0x66,
                0x74, 0x65, 0xe9, 0x5f, 0x49, 0xe5, 0xf5, 0xc0, 0x68, 0x4e, 0xe5, 0x6a, 0x78, 0x07,
                0x75, 0x46, 0xed, 0x90, 0xf6, 0xdc, 0x9d, 0xef, 0x3b, 0xdf, 0xf2, 0x79, 0xa9, 0xd8,
                0x80, 0x00, 0x00, 0x01, 0x60, 0xc0, 0xae, 0xb5, 0x6f, 0x40, 0x88, 0x0e, 0x28, 0xba
            ]),
            decrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0xdf, 0x48, 0x80, 0xdd, 0x61, 0xa6,
                0x2e, 0xd3, 0xd8, 0xbc, 0xde, 0xbe, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x16, 0x04,
                0x81, 0xca, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0x01, 0x10, 0x52, 0x6e, 0x54, 0x35,
                0x43, 0x6d, 0x4a, 0x68, 0x7a, 0x79, 0x65, 0x74, 0x41, 0x78, 0x77, 0x2b, 0x00, 0x00
            ]),
        },
        RTCPTestCase{
            ssrc:      0x11111111,
            index:     0,
            encrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x17, 0x8c, 0x15, 0xf1, 0x4b, 0x11,
                0xda, 0xf5, 0x74, 0x53, 0x86, 0x2b, 0xc9, 0x07, 0x29, 0x40, 0xbf, 0x22, 0xf6, 0x46,
                0x11, 0xa4, 0xc1, 0x3a, 0xff, 0x5a, 0xbd, 0xd0, 0xf8, 0x8b, 0x38, 0xe4, 0x95, 0x38,
                0x5d, 0xcf, 0x1b, 0xf5, 0x27, 0x77, 0xfb, 0xdb, 0x3f, 0x10, 0x68, 0x99, 0xd8, 0xad,
                0x80, 0x00, 0x00, 0x01, 0x34, 0x3c, 0x2e, 0x83, 0x17, 0x13, 0x93, 0x69, 0xcf, 0xc0
            ]),
            decrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0xdf, 0x48, 0x80, 0xdd, 0x61, 0xa6,
                0x2e, 0xd3, 0xd8, 0xbc, 0xde, 0xbe, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x16, 0x04,
                0x81, 0xca, 0x00, 0x06, 0x66, 0xef, 0x91, 0xff, 0x01, 0x10, 0x52, 0x6e, 0x54, 0x35,
                0x43, 0x6d, 0x4a, 0x68, 0x7a, 0x79, 0x65, 0x74, 0x41, 0x78, 0x77, 0x2b, 0x00, 0x00
            ]),
        },
        RTCPTestCase{
            ssrc:      0x11111111,
            index:     0x7ffffffe, // Upper boundary of index
            encrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x17, 0x8c, 0x15, 0xf1, 0x4b, 0x11,
                0xda, 0xf5, 0x74, 0x53, 0x86, 0x2b, 0xc9, 0x07, 0x29, 0x40, 0xbf, 0x22, 0xf6, 0x46,
                0x11, 0xa4, 0xc1, 0x3a, 0xff, 0x5a, 0xbd, 0xd0, 0xf8, 0x8b, 0x38, 0xe4, 0x95, 0x38,
                0x5d, 0xcf, 0x1b, 0xf5, 0x27, 0x77, 0xfb, 0xdb, 0x3f, 0x10, 0x68, 0x99, 0xd8, 0xad,
                0xff, 0xff, 0xff, 0xff, 0x5a, 0x99, 0xce, 0xed, 0x9f, 0x2e, 0x4d, 0x9d, 0xfa, 0x97
            ]),
            decrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x0, 0x6, 0x11, 0x11, 0x11, 0x11, 0x4, 0x99, 0x47, 0x53, 0xc4, 0x1e,
                0xb9, 0xde, 0x52, 0xa3, 0x1d, 0x77, 0x2f, 0xff, 0xcc, 0x75, 0xbb, 0x6a, 0x29, 0xb8,
                0x1, 0xb7, 0x2e, 0x4b, 0x4e, 0xcb, 0xa4, 0x81, 0x2d, 0x46, 0x4, 0x5e, 0x86, 0x90,
                0x17, 0x4f, 0x4d, 0x78, 0x2f, 0x58, 0xb8, 0x67, 0x91, 0x89, 0xe3, 0x61, 0x1, 0x7d
            ]),
        },
        RTCPTestCase{
            ssrc:      0x11111111,
            index:     0x7fffffff, // Will be wrapped to 0
            encrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x17, 0x8c, 0x15, 0xf1, 0x4b, 0x11,
                0xda, 0xf5, 0x74, 0x53, 0x86, 0x2b, 0xc9, 0x07, 0x29, 0x40, 0xbf, 0x22, 0xf6, 0x46,
                0x11, 0xa4, 0xc1, 0x3a, 0xff, 0x5a, 0xbd, 0xd0, 0xf8, 0x8b, 0x38, 0xe4, 0x95, 0x38,
                0x5d, 0xcf, 0x1b, 0xf5, 0x27, 0x77, 0xfb, 0xdb, 0x3f, 0x10, 0x68, 0x99, 0xd8, 0xad,
                0x80, 0x00, 0x00, 0x00, 0x7d, 0x51, 0xf8, 0x0e, 0x56, 0x40, 0x72, 0x7b, 0x9e, 0x02
            ]),
            decrypted: Bytes::from_static(&[
                0x80, 0xc8, 0x0, 0x6, 0x11, 0x11, 0x11, 0x11, 0xda, 0xb5, 0xe0, 0x56, 0x9a, 0x4a,
                0x74, 0xed, 0x8a, 0x54, 0xc, 0xcf, 0xd5, 0x9, 0xb1, 0x40, 0x1, 0x42, 0xc3, 0x9a,
                0x76, 0x0, 0xa9, 0xd4, 0xf7, 0x29, 0x9e, 0x51, 0xfb, 0x3c, 0xc1, 0x74, 0x72, 0xf9,
                0x52, 0xb1, 0x92, 0x31, 0xca, 0x22, 0xab, 0x3e, 0xc5, 0x5f, 0x83, 0x34, 0xf0, 0x28
            ]),
        },
    ];
}

/// pion's `rtcpTestCases`, one set per protection profile, as the lifecycle tests run them.
fn rtcp_case_sets() -> Vec<RTCPCaseSet> {
    vec![
        RTCPCaseSet {
            algo: ProtectionProfile::Aes128CmHmacSha1_80,
            master_key: RTCP_TEST_MASTER_KEY.clone(),
            master_salt: RTCP_TEST_MASTER_SALT.clone(),
            packets: RTCP_TEST_CASES.to_vec(),
        },
        RTCPCaseSet {
            algo: ProtectionProfile::AeadAes128Gcm,
            master_key: Bytes::from_static(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ]),
            master_salt: Bytes::from_static(&[
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
            ]),
            packets: vec![RTCPTestCase {
                ssrc: 0xcafebabe,
                index: 0,
                encrypted: Bytes::from_static(&[
                    0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xc9, 0x8b, 0x8b, 0x5d, 0xf0,
                    0x39, 0x2a, 0x55, 0x85, 0x2b, 0x6c, 0x21, 0xac, 0x8e, 0x70, 0x25, 0xc5, 0x2c,
                    0x6f, 0xbe, 0xa2, 0xb3, 0xb4, 0x46, 0xea, 0x31, 0x12, 0x3b, 0xa8, 0x8c, 0xe6,
                    0x1e, 0x80, 0x00, 0x00, 0x01,
                ]),
                decrypted: Bytes::from_static(&[
                    0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab,
                    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                ]),
            }],
        },
    ]
}

#[test]
fn test_rtcp_lifecycle() -> Result<()> {
    // pion runs every case twice: with the default options and with SRTCP replay protection.
    for replay_protection in [false, true] {
        for case in rtcp_case_sets() {
            let mut encrypt_context = Context::new(
                &case.master_key,
                &case.master_salt,
                case.algo,
                None,
                replay_protection.then(|| srtcp_replay_protection(10)),
                test_crypto_provider().crypto(),
            )?;

            for test_case in &case.packets {
                // With replay protection on, a fresh context per packet: these cases reuse one
                // SSRC with wildly distant indexes, which a single window would (correctly)
                // refuse as too old. pion's own case set has one packet per SSRC.
                let mut decrypt_context = Context::new(
                    &case.master_key,
                    &case.master_salt,
                    case.algo,
                    None,
                    replay_protection.then(|| srtcp_replay_protection(10)),
                    test_crypto_provider().crypto(),
                )?;
                let decrypt_result = decrypt_context.decrypt_rtcp(&test_case.encrypted)?;
                assert_eq!(
                    decrypt_result, test_case.decrypted,
                    "RTCP failed to decrypt"
                );

                encrypt_context.set_index(test_case.ssrc, test_case.index);
                let encrypt_result = encrypt_context.encrypt_rtcp(&test_case.decrypted);
                if test_case.index >= 0x7fffffff {
                    // RFC 3711 section 9.2: once 2^31 packets have been protected with one
                    // key the session must rekey or end, not wrap the index back to 0 (as
                    // this context did before pion parity).
                    assert_eq!(
                        encrypt_result.err(),
                        Some(Error::ErrExceededMaxPackets),
                        "encrypting past the SRTCP index limit must be refused"
                    );
                } else {
                    assert_eq!(
                        encrypt_result?, test_case.encrypted,
                        "RTCP failed to encrypt"
                    );
                }
            }
        }
    }

    Ok(())
}

#[test]
fn test_rtcp_invalid_auth_tag() -> Result<()> {
    let auth_tag_len = ProtectionProfile::Aes128CmHmacSha1_80.rtcp_auth_tag_len();

    let mut decrypt_context = Context::new(
        &RTCP_TEST_MASTER_KEY,
        &RTCP_TEST_MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    let decrypt_result = decrypt_context.decrypt_rtcp(&RTCP_TEST_CASES[0].encrypted)?;
    assert_eq!(
        decrypt_result, RTCP_TEST_CASES[0].decrypted,
        "RTCP failed to decrypt"
    );

    // Zero out auth tag
    let mut rtcp_packet = BytesMut::new();
    rtcp_packet.extend_from_slice(&RTCP_TEST_CASES[0].encrypted);
    let rtcp_packet_len = rtcp_packet.len();
    rtcp_packet[rtcp_packet_len - auth_tag_len..].copy_from_slice(&vec![0; auth_tag_len]);
    let rtcp_packet = rtcp_packet.freeze();
    let decrypt_result = decrypt_context.decrypt_rtcp(&rtcp_packet);
    assert!(
        decrypt_result.is_err(),
        "Was able to decrypt RTCP packet with invalid Auth Tag"
    );

    Ok(())
}

#[test]
fn test_rtcp_replay_detector_separation() -> Result<()> {
    let mut decrypt_context = Context::new(
        &RTCP_TEST_MASTER_KEY,
        &RTCP_TEST_MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        Some(srtcp_replay_protection(10)),
        test_crypto_provider().crypto(),
    )?;

    let rtcp_packet1 = RTCP_TEST_CASES[0].encrypted.clone();
    let decrypt_result1 = decrypt_context.decrypt_rtcp(&rtcp_packet1)?;
    assert_eq!(
        decrypt_result1, RTCP_TEST_CASES[0].decrypted,
        "RTCP failed to decrypt"
    );

    let rtcp_packet2 = RTCP_TEST_CASES[1].encrypted.clone();
    let decrypt_result2 = decrypt_context.decrypt_rtcp(&rtcp_packet2)?;
    assert_eq!(
        decrypt_result2, RTCP_TEST_CASES[1].decrypted,
        "RTCP failed to decrypt"
    );

    let result = decrypt_context.decrypt_rtcp(&rtcp_packet1);
    assert!(
        result.is_err(),
        "Was able to decrypt duplicated RTCP packet"
    );

    let result = decrypt_context.decrypt_rtcp(&rtcp_packet2);
    assert!(
        result.is_err(),
        "Was able to decrypt duplicated RTCP packet"
    );

    Ok(())
}

fn get_rtcp_index(encrypted: &Bytes, auth_tag_len: usize) -> u32 {
    let tail_offset = encrypted.len() - (auth_tag_len + SRTCP_INDEX_SIZE);
    let reader = &mut encrypted.slice(tail_offset..tail_offset + SRTCP_INDEX_SIZE);
    //^(1 << 31)
    reader.get_u32() & 0x7FFFFFFF
}

#[test]
fn test_encrypt_rtcp_separation() -> Result<()> {
    let mut encrypt_context = Context::new(
        &RTCP_TEST_MASTER_KEY,
        &RTCP_TEST_MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    let auth_tag_len = ProtectionProfile::Aes128CmHmacSha1_80.rtcp_auth_tag_len();

    let mut decrypt_context = Context::new(
        &RTCP_TEST_MASTER_KEY,
        &RTCP_TEST_MASTER_SALT,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        Some(srtcp_replay_protection(10)),
        test_crypto_provider().crypto(),
    )?;

    let inputs = vec![
        RTCP_TEST_CASES[0].decrypted.clone(),
        RTCP_TEST_CASES[1].decrypted.clone(),
        RTCP_TEST_CASES[0].decrypted.clone(),
        RTCP_TEST_CASES[1].decrypted.clone(),
    ];
    let mut encrypted_rctps = vec![];

    for input in &inputs {
        let encrypted = encrypt_context.encrypt_rtcp(input)?;
        encrypted_rctps.push(encrypted);
    }

    for (i, expected_index) in [1, 1, 2, 2].iter().enumerate() {
        assert_eq!(
            *expected_index,
            get_rtcp_index(&encrypted_rctps[i].clone().freeze(), auth_tag_len),
            "RTCP index does not match"
        );
    }

    for (i, output) in encrypted_rctps.iter().enumerate() {
        let decrypted = decrypt_context.decrypt_rtcp(output)?;
        assert_eq!(inputs[i], decrypted);
    }

    Ok(())
}

/// Short SRTCP packets — anything below the minimum size (RTCP header through
/// the SSRC + trailing SRTCP index + auth tag) — must error, not panic. Before
/// the length guard, `get_rtcp_index` and the `encrypted[4..8]` SSRC read
/// indexed unconditionally, so a short packet from the network triggered an
/// index-out-of-bounds panic (a remotely triggerable DoS on the media path).
#[test]
fn test_rtcp_short_packet_errors() -> Result<()> {
    // Cover both cipher families end-to-end through `Context::decrypt_rtcp`.
    // AEAD-128-GCM takes a 12-byte salt vs 14 for AES-CM.
    let cases: [(ProtectionProfile, &[u8]); 2] = [
        (
            ProtectionProfile::Aes128CmHmacSha1_80,
            &RTCP_TEST_MASTER_SALT[..],
        ),
        (
            ProtectionProfile::AeadAes128Gcm,
            &RTCP_TEST_MASTER_SALT[..12],
        ),
    ];

    for (profile, salt) in cases {
        let mut ctx = Context::new(
            &RTCP_TEST_MASTER_KEY,
            salt,
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;

        // Slices of a real packet (its first 4 bytes are a valid RTCP header, so
        // the header parse succeeds and pre-fix execution reached the
        // out-of-bounds indexing). Every length below the minimum valid SRTCP
        // size for the profile must be rejected, not panic.
        let min_len =
            8 + SRTCP_INDEX_SIZE + profile.rtcp_auth_tag_len() + profile.aead_auth_tag_len();
        for len in 0..min_len {
            let short = RTCP_TEST_CASES[0].encrypted.slice(0..len);
            assert!(
                ctx.decrypt_rtcp(&short).is_err(),
                "decrypt_rtcp must reject a {len}-byte packet (profile min {min_len}), not panic"
            );
        }
    }

    Ok(())
}

/// pion's `buildTestContext`: the shared 16-byte key / 14-byte salt, sliced to what the profile
/// takes (pion's helper does the same, and is likewise only used with the 128-bit profiles).
fn build_test_context(profile: ProtectionProfile) -> Result<Context> {
    let master_key = [
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ];
    let master_salt = [
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ];

    Context::new(
        &master_key[..profile.key_len().min(master_key.len())],
        &master_salt[..profile.salt_len().min(master_salt.len())],
        profile,
        None,
        None,
        test_crypto_provider().crypto(),
    )
}

/// pion's `TestRTCPDecryptShortenedPacket`: every truncation of a real packet, from 1 byte up to
/// the full length minus one, must error (or at worst fail authentication) — never panic or
/// slice out of range. A fresh context per slice, as in pion.
#[test]
fn test_rtcp_decrypt_shortened_packet() -> Result<()> {
    for case in rtcp_case_sets() {
        let pkt = &case.packets[0];
        for i in 1..pkt.encrypted.len() - 1 {
            let packet = &pkt.encrypted[..i];
            let mut decrypt_context = Context::new(
                &case.master_key,
                &case.master_salt,
                case.algo,
                None,
                None,
                test_crypto_provider().crypto(),
            )?;
            assert!(
                decrypt_context.decrypt_rtcp(packet).is_err(),
                "{:?}: decrypt_rtcp must not accept a {}-byte packet",
                case.algo,
                i
            );
        }
    }

    Ok(())
}

/// pion's `TestRTCPMaxPackets`: the 2^31 SRTCP packet limit of RFC 3711 section 9.2. The index
/// 0x7fffffff is the last a key may protect; on the receive side a window sitting at that head
/// refuses a long-behind index as too old, and on the send side the next packet must be refused
/// rather than wrap the index back to 0.
#[test]
fn test_rtcp_max_packets() -> Result<()> {
    const SSRC: u32 = 0x1111_1111;

    /// One profile's pair: the last packet a key may protect (index 0x7fffffff), and a packet
    /// whose index lands far behind the window head once that limit has been reached.
    struct MaxPacketsCase {
        profile: ProtectionProfile,
        master_key: &'static [u8],
        master_salt: &'static [u8],
        at_limit: RTCPTestCase,
        wrapped_back: RTCPTestCase,
    }

    let cases = [
        MaxPacketsCase {
            profile: ProtectionProfile::AeadAes128Gcm,
            master_key: &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            master_salt: &[
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
            ],
            at_limit: RTCPTestCase {
                ssrc: SSRC,
                index: 0x7fffffff,
                encrypted: Bytes::from_static(&[
                    0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x02, 0xb6, 0xc1, 0x47, 0x92,
                    0xbe, 0xf0, 0xae, 0xd9, 0x40, 0xa5, 0x1c, 0xbe, 0xec, 0xaf, 0xfc, 0x7d, 0x86,
                    0x3b, 0xbb, 0x93, 0x0c, 0xb0, 0xd4, 0xea, 0x4a, 0x3c, 0x5b, 0xd1, 0xd5, 0x47,
                    0xb1, 0x1a, 0x61, 0xae, 0xa6, 0x1a, 0x0c, 0xb9, 0x14, 0xa5, 0x16, 0x08, 0xe4,
                    0xfb, 0x0d, 0x15, 0xba, 0x7f, 0x70, 0x2b, 0xb8, 0x99, 0x97, 0x91, 0xfd, 0x53,
                    0x03, 0xcd, 0x57, 0xbb, 0x8f, 0x93, 0xbe, 0xff, 0xff, 0xff, 0xff,
                ]),
                decrypted: Bytes::from_static(&[
                    0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x04, 0x99, 0x47, 0x53, 0xc4,
                    0x1e, 0xb9, 0xde, 0x52, 0xa3, 0x1d, 0x77, 0x2f, 0xff, 0xcc, 0x75, 0xbb, 0x6a,
                    0x29, 0xb8, 0x01, 0xb7, 0x2e, 0x4b, 0x4e, 0xcb, 0xa4, 0x81, 0x2d, 0x46, 0x04,
                    0x5e, 0x86, 0x90, 0x17, 0x4f, 0x4d, 0x78, 0x2f, 0x58, 0xb8, 0x67, 0x91, 0x89,
                    0xe3, 0x61, 0x01, 0x7d,
                ]),
            },
            wrapped_back: RTCPTestCase {
                ssrc: SSRC,
                index: 1,
                encrypted: Bytes::from_static(&[
                    0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x77, 0x47, 0x0c, 0x21, 0xc2,
                    0xcd, 0x33, 0xa7, 0x5a, 0x81, 0xb5, 0xb5, 0x8f, 0xe2, 0x34, 0x28, 0x11, 0xa8,
                    0xa3, 0x34, 0xf8, 0x9d, 0xfc, 0xd8, 0xcb, 0x87, 0xe2, 0x51, 0x8e, 0xae, 0xdb,
                    0xfd, 0x9d, 0xf1, 0xfa, 0x18, 0xe2, 0xdc, 0x0a, 0xd4, 0xe3, 0x06, 0x18, 0xff,
                    0xf7, 0x27, 0x92, 0x1f, 0x28, 0xcd, 0x3c, 0xf8, 0xa4, 0x0a, 0x2b, 0xbb, 0x5b,
                    0x1f, 0x4d, 0x1f, 0xef, 0x0e, 0xc4, 0x91, 0x80, 0x00, 0x00, 0x01,
                ]),
                decrypted: Bytes::from_static(&[
                    0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0xda, 0xb5, 0xe0, 0x56, 0x9a,
                    0x4a, 0x74, 0xed, 0x8a, 0x54, 0x0c, 0xcf, 0xd5, 0x09, 0xb1, 0x40, 0x01, 0x42,
                    0xc3, 0x9a, 0x76, 0x00, 0xa9, 0xd4, 0xf7, 0x29, 0x9e, 0x51, 0xfb, 0x3c, 0xc1,
                    0x74, 0x72, 0xf9, 0x52, 0xb1, 0x92, 0x31, 0xca, 0x22, 0xab, 0x3e, 0xc5, 0x5f,
                    0x83, 0x34, 0xf0, 0x28,
                ]),
            },
        },
        MaxPacketsCase {
            profile: ProtectionProfile::Aes128CmHmacSha1_80,
            master_key: &[
                0xfd, 0xa6, 0x25, 0x95, 0xd7, 0xf6, 0x92, 0x6f, 0x7d, 0x9c, 0x02, 0x4c, 0xc9, 0x20,
                0x9f, 0x34,
            ],
            master_salt: &[
                0xa9, 0x65, 0x19, 0x85, 0x54, 0x0b, 0x47, 0xbe, 0x2f, 0x27, 0xa8, 0xb8, 0x81, 0x23,
            ],
            at_limit: RTCPTestCase {
                ssrc: SSRC,
                index: 0x7fffffff,
                encrypted: RTCP_TEST_CASES[2].encrypted.clone(),
                decrypted: RTCP_TEST_CASES[2].decrypted.clone(),
            },
            wrapped_back: RTCPTestCase {
                ssrc: SSRC,
                index: 1,
                encrypted: Bytes::from_static(&[
                    0x80, 0xc8, 0x00, 0x06, 0x11, 0x11, 0x11, 0x11, 0x12, 0x71, 0x75, 0x7a, 0xb0,
                    0xfd, 0x80, 0xcb, 0x26, 0xbb, 0x54, 0x5a, 0x1c, 0x0e, 0x98, 0x09, 0xbe, 0x60,
                    0x23, 0xd8, 0xe6, 0x6e, 0x68, 0xe8, 0x6e, 0x9c, 0xb2, 0x7e, 0x02, 0xa7, 0xab,
                    0xfe, 0xb3, 0xf4, 0x4c, 0x13, 0xc3, 0xac, 0x97, 0x2c, 0x35, 0x91, 0xbb, 0x37,
                    0x9c, 0x86, 0x28, 0x85, 0x80, 0x00, 0x00, 0x01, 0x89, 0x76, 0x07, 0xca, 0xd9,
                    0xc4, 0xcb, 0xca, 0x66, 0xab,
                ]),
                decrypted: RTCP_TEST_CASES[3].decrypted.clone(),
            },
        },
    ];

    for case in cases {
        let profile = case.profile;
        let mut encrypt_context = Context::new(
            case.master_key,
            case.master_salt,
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;
        let mut decrypt_context = Context::new(
            case.master_key,
            case.master_salt,
            profile,
            None,
            Some(srtcp_replay_protection(10)),
            test_crypto_provider().crypto(),
        )?;

        // Upper boundary of the index.
        encrypt_context.set_index(SSRC, 0x7ffffffe);

        let decrypt_result = decrypt_context.decrypt_rtcp(&case.at_limit.encrypted)?;
        assert_eq!(
            decrypt_result, case.at_limit.decrypted,
            "{profile:?}: RTCP failed to decrypt"
        );

        let encrypt_result = encrypt_context.encrypt_rtcp(&case.at_limit.decrypted)?;
        assert_eq!(
            encrypt_result, case.at_limit.encrypted,
            "{profile:?}: RTCP failed to encrypt"
        );

        // Next packet exceeds the maximum packet count: the receive window refuses the
        // long-behind index, the send side refuses to wrap.
        assert!(matches!(
            decrypt_context.decrypt_rtcp(&case.wrapped_back.encrypted),
            Err(Error::SrtcpSsrcDuplicated(SSRC, 1))
        ));
        assert_eq!(
            encrypt_context
                .encrypt_rtcp(&case.wrapped_back.decrypted)
                .err(),
            Some(Error::ErrExceededMaxPackets),
            "{profile:?}: SRTCP index must not wrap past 2^31-1"
        );
    }

    Ok(())
}

/// pion's `TestRTCPReplayDetectorFactory`: a custom detector factory is invoked exactly once per
/// SSRC — here, once for the single SSRC of one decrypted packet.
#[test]
fn test_rtcp_replay_detector_factory() -> Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let case = &rtcp_case_sets()[1];
    let data = &case.packets[0];

    let count = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let factory: ContextOption = Box::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Box::<NoOpReplayDetector>::default()
    });

    let mut decrypt_context = Context::new(
        &case.master_key,
        &case.master_salt,
        case.algo,
        None,
        Some(factory),
        test_crypto_provider().crypto(),
    )?;

    decrypt_context.decrypt_rtcp(&data.encrypted)?;
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "the replay detector factory must run once per SSRC"
    );

    Ok(())
}

/// pion's `TestRTCPLegacyReplayDetector`: a detector that does not implement the two-phase
/// check/accept protocol must still catch replays. Our `ReplayDetector` trait is two-phase by
/// construction, so the "legacy detector" is simply the plain sliding window over the SRTCP
/// index, as pion's wraps `replaydetector.New` — and the context must refuse the replay.
#[test]
fn test_rtcp_legacy_replay_detector() -> Result<()> {
    let case = &rtcp_case_sets()[1];
    let data = &case.packets[0];

    let factory: ContextOption =
        Box::new(|| Box::new(SlidingWindowDetector::new(64, MAX_SRTCP_INDEX as u64)));
    let mut decrypt_context = Context::new(
        &case.master_key,
        &case.master_salt,
        case.algo,
        None,
        Some(factory),
        test_crypto_provider().crypto(),
    )?;

    decrypt_context.decrypt_rtcp(&data.encrypted)?;
    assert!(
        decrypt_context.decrypt_rtcp(&data.encrypted).is_err(),
        "the replayed packet must still be rejected"
    );

    Ok(())
}

/// pion's `TestDecryptInvalidSRTCP`: a crafted packet with a valid-looking shape must fail, not
/// panic.
#[test]
fn test_decrypt_invalid_srtcp() -> Result<()> {
    let key = [0x01; 16];
    let salt = [0x01; 14];
    let mut decrypt_context = Context::new(
        &key,
        &salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    let packet = [
        0x8f, 0x48, 0xff, 0xff, 0xec, 0x77, 0xb0, 0x43, 0xf9, 0x04, 0x51, 0xff, 0xfb, 0xdf,
    ];
    assert!(decrypt_context.decrypt_rtcp(&packet).is_err());

    Ok(())
}

/// pion's `TestEncryptInvalidRTCP`: a buffer too short to hold the 8-byte RTCP header through
/// the SSRC is refused.
#[test]
fn test_encrypt_invalid_rtcp() -> Result<()> {
    let key = [0x01; 16];
    let salt = [0x01; 14];
    let mut encrypt_context = Context::new(
        &key,
        &salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    let packet = [0xbb, 0xbb, 0x0a, 0x2f];
    assert!(encrypt_context.encrypt_rtcp(&packet).is_err());

    Ok(())
}

/// pion's `TestSRTCPFailedAuthDoesNotGrowSSRCMap`: a packet that fails authentication must not
/// leave per-SSRC state behind (the SSRC is read from an unauthenticated header).
#[test]
fn test_srtcp_failed_auth_does_not_grow_ssrc_map() -> Result<()> {
    for profile in [
        ProtectionProfile::Aes128CmHmacSha1_80,
        ProtectionProfile::AeadAes128Gcm,
    ] {
        let mut encrypt_context = build_test_context(profile)?;

        // All-zero key and salt: the authentication tag will never match.
        let mut decrypt_context = Context::new(
            &vec![0; profile.key_len()],
            &vec![0; profile.salt_len()],
            profile,
            None,
            None,
            test_crypto_provider().crypto(),
        )?;

        // RTCP PLI for media SSRC 0xdeadbeef, as pion marshals it.
        let mut pkt = vec![0x81, 0xce, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00];
        pkt.extend_from_slice(&0xdeadbeefu32.to_be_bytes());

        let encrypted = encrypt_context.encrypt_rtcp(&pkt)?;
        assert!(
            decrypt_context.decrypt_rtcp(&encrypted).is_err(),
            "{profile:?}: DecryptRTCP must fail when key does not match"
        );
        assert!(
            decrypt_context.srtcp_ssrc_states.is_empty(),
            "{profile:?}: SRTCP SSRC state map must not grow after failed authentication"
        );
    }

    Ok(())
}
