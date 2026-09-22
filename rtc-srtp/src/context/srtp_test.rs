use super::*;
use shared::marshal::*;

/// The built-in provider, for tests only. Library code never resolves a default: every public
/// constructor takes the provider from its caller.
fn test_crypto_provider() -> std::sync::Arc<dyn crypto::RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

use bytes::{Bytes, BytesMut};
use lazy_static::lazy_static;

struct RTPTestCase {
    sequence_number: u16,
    encrypted: Bytes,
}

lazy_static! {
    static ref RTP_TEST_CASE_DECRYPTED: Bytes = Bytes::from_static(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
    static ref RTP_TEST_CASES: Vec<RTPTestCase> = vec![
        RTPTestCase {
            sequence_number: 5000,
            encrypted: Bytes::from_static(&[
                0x6d, 0xd3, 0x7e, 0xd5, 0x99, 0xb7, 0x2d, 0x28, 0xb1, 0xf3, 0xa1, 0xf0, 0xc, 0xfb,
                0xfd, 0x8
            ]),
        },
        RTPTestCase {
            sequence_number: 5001,
            encrypted: Bytes::from_static(&[
                0xda, 0x47, 0xb, 0x2a, 0x74, 0x53, 0x65, 0xbd, 0x2f, 0xeb, 0xdc, 0x4b, 0x6d, 0x23,
                0xf3, 0xde
            ]),
        },
        RTPTestCase {
            sequence_number: 5002,
            encrypted: Bytes::from_static(&[
                0x6e, 0xa7, 0x69, 0x8d, 0x24, 0x6d, 0xdc, 0xbf, 0xec, 0x2, 0x1c, 0xd1, 0x60, 0x76,
                0xc1, 0x0e
            ]),
        },
        RTPTestCase {
            sequence_number: 5003,
            encrypted: Bytes::from_static(&[
                0x24, 0x7e, 0x96, 0xc8, 0x7d, 0x33, 0xa2, 0x92, 0x8d, 0x13, 0x8d, 0xe0, 0x76, 0x9f,
                0x08, 0xdc
            ]),
        },
        RTPTestCase {
            sequence_number: 5004,
            encrypted: Bytes::from_static(&[
                0x75, 0x43, 0x28, 0xe4, 0x3a, 0x77, 0x59, 0x9b, 0x2e, 0xdf, 0x7b, 0x12, 0x68, 0x0b,
                0x57, 0x49
            ]),
        },
        RTPTestCase{
            sequence_number: 65535, // upper boundary
            encrypted: Bytes::from_static(&[
                0xaf, 0xf7, 0xc2, 0x70, 0x37, 0x20, 0x83, 0x9c, 0x2c, 0x63, 0x85, 0x15, 0x0e, 0x44,
                0xca, 0x36
            ]),
        },
    ];
}

fn build_test_context() -> Result<Context> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let master_salt = Bytes::from_static(&[
        0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c,
    ]);

    Context::new(
        &master_key,
        &master_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )
}

#[test]
fn test_rtp_invalid_auth() -> Result<()> {
    let master_key = Bytes::from_static(&[
        0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28,
        0x89,
    ]);
    let invalid_salt = Bytes::from_static(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    let mut encrypt_context = build_test_context()?;
    let mut invalid_context = Context::new(
        &master_key,
        &invalid_salt,
        ProtectionProfile::Aes128CmHmacSha1_80,
        None,
        None,
        test_crypto_provider().crypto(),
    )?;

    for test_case in &*RTP_TEST_CASES {
        let pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };

        let pkt_raw = pkt.marshal()?;
        let out = encrypt_context.encrypt_rtp(&pkt_raw)?;

        let result = invalid_context.decrypt_rtp(&out);
        assert!(
            result.is_err(),
            "Managed to decrypt with incorrect salt for packet with SeqNum: {}",
            test_case.sequence_number
        );
    }

    Ok(())
}

#[test]
fn test_rtp_lifecyle() -> Result<()> {
    let mut encrypt_context = build_test_context()?;
    let mut decrypt_context = build_test_context()?;
    let auth_tag_len = ProtectionProfile::Aes128CmHmacSha1_80.rtp_auth_tag_len();

    for test_case in RTP_TEST_CASES.iter() {
        let decrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: RTP_TEST_CASE_DECRYPTED.clone(),
        };

        let decrypted_raw = decrypted_pkt.marshal()?;

        let encrypted_pkt = rtp::Packet {
            header: rtp::Header {
                sequence_number: test_case.sequence_number,
                ..Default::default()
            },
            payload: test_case.encrypted.clone(),
        };

        let encrypted_raw = encrypted_pkt.marshal()?;
        let actual_encrypted = encrypt_context.encrypt_rtp(&decrypted_raw)?;
        assert_eq!(
            actual_encrypted, encrypted_raw,
            "RTP packet with SeqNum invalid encryption: {}",
            test_case.sequence_number
        );

        let actual_decrypted = decrypt_context.decrypt_rtp(&encrypted_raw)?;
        assert_ne!(
            encrypted_raw[..encrypted_raw.len() - auth_tag_len].to_vec(),
            actual_decrypted,
            "DecryptRTP improperly encrypted in place"
        );

        assert_eq!(
            actual_decrypted, decrypted_raw,
            "RTP packet with SeqNum invalid decryption: {}",
            test_case.sequence_number,
        )
    }

    Ok(())
}

/// Both profile families, since each cipher has its own in-place implementation.
const PROFILES: [ProtectionProfile; 2] = [
    ProtectionProfile::Aes128CmHmacSha1_80,
    ProtectionProfile::AeadAes128Gcm,
];

fn keyed_context(profile: ProtectionProfile, salt: u8, replay_window: usize) -> Result<Context> {
    Context::new(
        &vec![0x5a; profile.key_len()],
        &vec![salt; profile.salt_len()],
        profile,
        Some(srtp_replay_protection(replay_window)),
        None,
        test_crypto_provider().crypto(),
    )
}

fn media_packet(ssrc: u32, sequence_number: u16) -> rtp::Packet {
    rtp::Packet {
        header: rtp::Header {
            version: 2,
            payload_type: 96,
            sequence_number,
            timestamp: sequence_number as u32 * 3000,
            ssrc,
            ..Default::default()
        },
        payload: Bytes::from_static(&[0xa5; 48]),
    }
}

/// A forged packet must not leave state behind for an SSRC the context has never
/// authenticated, or a stream of them with distinct SSRCs grows memory without bound.
#[test]
fn test_rejected_packets_for_unknown_ssrcs_leave_no_state() -> Result<()> {
    for profile in PROFILES {
        let mut sender = keyed_context(profile, 0x01, 64)?;
        let mut receiver = keyed_context(profile, 0x02, 64)?;

        for ssrc in 0..100 {
            let forged = sender.encrypt_rtp_packet(&media_packet(ssrc, 1))?;
            assert!(receiver.decrypt_rtp(&forged).is_err(), "{profile:?}");
            assert!(receiver.decrypt_rtp_packet(forged).is_err(), "{profile:?}");
        }

        assert!(
            receiver.srtp_ssrc_states.is_empty(),
            "{profile:?}: rejected packets created state for {} SSRCs",
            receiver.srtp_ssrc_states.len()
        );
    }
    Ok(())
}

/// Admission is deferred, not refused: the stream's first authentic packet still creates its
/// state, and replay protection starts from it.
#[test]
fn test_first_authentic_packet_after_a_forgery_creates_state() -> Result<()> {
    for profile in PROFILES {
        let mut sender = keyed_context(profile, 0x01, 64)?;
        let mut forger = keyed_context(profile, 0x02, 64)?;
        let mut receiver = keyed_context(profile, 0x01, 64)?;

        let forged = forger.encrypt_rtp_packet(&media_packet(7, 100))?;
        assert!(receiver.decrypt_rtp_packet(forged).is_err());
        assert_eq!(receiver.get_roc(7), None, "{profile:?}");

        let authentic = sender.encrypt_rtp_packet(&media_packet(7, 100))?;
        let decrypted = receiver.decrypt_rtp_packet(BytesMut::from(&authentic[..]))?;
        assert_eq!(decrypted, media_packet(7, 100), "{profile:?}");
        assert_eq!(receiver.get_roc(7), Some(0), "{profile:?}");

        assert!(
            matches!(
                receiver.decrypt_rtp_packet(authentic),
                Err(Error::SrtpSsrcDuplicated(7, 100))
            ),
            "{profile:?}: a replay of the first packet must be rejected"
        );
    }
    Ok(())
}

/// A forgery for a known stream must not advance its replay window or rollover counter.
#[test]
fn test_rejected_packet_does_not_disturb_a_known_stream() -> Result<()> {
    for profile in PROFILES {
        let mut sender = keyed_context(profile, 0x01, 64)?;
        let mut forger = keyed_context(profile, 0x02, 64)?;
        let mut receiver = keyed_context(profile, 0x01, 64)?;

        let first = sender.encrypt_rtp_packet(&media_packet(9, 65_000))?;
        receiver.decrypt_rtp_packet(first)?;

        // Far enough ahead to move the window, and across the wrap, were it accepted.
        let forged = forger.encrypt_rtp_packet(&media_packet(9, 200))?;
        assert!(receiver.decrypt_rtp_packet(forged).is_err());
        assert_eq!(receiver.get_roc(9), Some(0), "{profile:?}");

        let next = sender.encrypt_rtp_packet(&media_packet(9, 65_001))?;
        assert_eq!(
            receiver.decrypt_rtp_packet(next)?,
            media_packet(9, 65_001),
            "{profile:?}"
        );
    }
    Ok(())
}

/// The owned-buffer path must track rollover across the sequence-number wrap exactly as the
/// slice path does, on both sides.
#[test]
fn test_packet_apis_follow_rollover_across_the_wrap() -> Result<()> {
    for profile in PROFILES {
        let mut sender = keyed_context(profile, 0x01, 64)?;
        let mut receiver = keyed_context(profile, 0x01, 64)?;

        for sequence_number in (65_530..=u16::MAX).chain(0..5) {
            let packet = media_packet(3, sequence_number);
            let encrypted = sender.encrypt_rtp_packet(&packet)?;
            assert_eq!(
                receiver.decrypt_rtp_packet(encrypted)?,
                packet,
                "{profile:?}"
            );
        }
        assert_eq!(sender.get_roc(3), Some(1), "{profile:?}");
        assert_eq!(receiver.get_roc(3), Some(1), "{profile:?}");
    }
    Ok(())
}

/// `encrypt_rtp_packet` and `decrypt_rtp_packet` are the marshal-then-encrypt and
/// decrypt-then-unmarshal pairs fused; they must produce the same bytes and packets, including
/// for headers with CSRCs and extensions and for padded payloads.
#[test]
fn test_packet_apis_match_the_slice_apis() -> Result<()> {
    let mut with_extensions = media_packet(11, 40);
    with_extensions.header.csrc = vec![0x0102_0304, 0x0506_0708];
    with_extensions
        .header
        .set_extension(1, Bytes::from_static(b"mid"))?;
    with_extensions
        .header
        .set_extension(3, Bytes::from_static(&[0, 1, 2, 3, 4]))?;

    let mut padded = media_packet(12, 41);
    padded.header.padding = true;
    padded.payload = Bytes::from_static(&[0x11; 45]);

    for profile in PROFILES {
        for packet in [
            media_packet(10, 39),
            with_extensions.clone(),
            padded.clone(),
        ] {
            let mut by_slice = keyed_context(profile, 0x01, 64)?;
            let mut by_packet = keyed_context(profile, 0x01, 64)?;

            let expected = by_slice.encrypt_rtp(&packet.marshal()?)?;
            let encrypted = by_packet.encrypt_rtp_packet(&packet)?;
            assert_eq!(encrypted, expected, "{profile:?}");
            assert_eq!(
                encrypted.capacity(),
                encrypted.len(),
                "{profile:?}: the tag must fit in the buffer as allocated"
            );

            let mut by_slice = keyed_context(profile, 0x01, 64)?;
            let mut by_packet = keyed_context(profile, 0x01, 64)?;
            let expected = rtp::Packet::unmarshal(&mut by_slice.decrypt_rtp(&encrypted)?)?;
            let decrypted = by_packet.decrypt_rtp_packet(encrypted)?;
            assert_eq!(decrypted, expected, "{profile:?}");
            assert_eq!(decrypted.payload.len(), packet.payload.len(), "{profile:?}");
        }
    }
    Ok(())
}

#[test]
fn test_decrypt_rtp_packet_rejects_truncated_input() -> Result<()> {
    for profile in PROFILES {
        let mut sender = keyed_context(profile, 0x01, 64)?;
        let mut receiver = keyed_context(profile, 0x01, 64)?;
        let encrypted = sender.encrypt_rtp_packet(&media_packet(5, 1))?;

        for len in [0, 4, 12, 13, encrypted.len() - 1] {
            assert!(
                receiver
                    .decrypt_rtp_packet(BytesMut::from(&encrypted[..len]))
                    .is_err(),
                "{profile:?}: {len}-byte prefix"
            );
        }
        assert!(receiver.srtp_ssrc_states.is_empty(), "{profile:?}");
    }
    Ok(())
}

//TODO: BenchmarkEncryptRTP
//TODO: BenchmarkEncryptRTPInPlace
//TODO: BenchmarkDecryptRTP
