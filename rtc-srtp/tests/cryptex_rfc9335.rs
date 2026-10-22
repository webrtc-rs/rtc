//! RFC 9335 (Cryptex) Appendix A test vectors, and the behaviour around them, through the public
//! `Context` API. The vectors are the RFC's, shared with pion/srtp's `TestCryptexRFC`.

use bytes::BytesMut;
use rtc_srtp::context::Context;
use rtc_srtp::context::cryptex::CryptexMode;
use rtc_srtp::protection_profile::ProtectionProfile;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct Case {
    profile: ProtectionProfile,
    key: &'static str,
    salt: &'static str,
    /// (name, plain RTP, Cryptex-protected SRTP)
    vectors: &'static [(&'static str, &'static str, &'static str)],
}

const NAMES: [&str; 6] = [
    "one-byte extension",
    "two-byte extension",
    "one-byte extension and CSRCs",
    "two-byte extension and CSRCs",
    "empty one-byte extension and CSRCs",
    "empty two-byte extension and CSRCs",
];

static CASES: &[Case] = &[
    Case {
        profile: ProtectionProfile::Aes128CmHmacSha1_80,
        key: "e1f97a0d3e018be0d64fa32c06de4139",
        salt: "0ec675ad498afeebb6960b3aabe6",
        vectors: &[
            (
                "one_byte",
                "900f1235decafbadcafebabebede000151000200abababababababababababababababab",
                "900f1235decafbadcafebabec0de0001eb92365251c3e036f8de27e9c27ee3e0b4651d9fbc4218a70244522f34a5",
            ),
            (
                "two_byte",
                "900f1236decafbadcafebabe1000000105020002abababababababababababababababab",
                "900f1236decafbadcafebabec2de00014ed9cc4e6a712b3096c5ca77339d4204ce0d77396cab69585fbce38194a5",
            ),
            (
                "one_byte_csrc",
                "920f1238decafbadcafebabe0001e2400000b26ebede000151000200abababababababababababababababab",
                "920f1238decafbadcafebabe8bb6e12b5cff16ddc0de000192838c8c09e58393e1de3a9a74734d6745671338c3acf11da2df8423bee0",
            ),
            (
                "two_byte_csrc",
                "920f1239decafbadcafebabe0001e2400000b26e1000000105020002abababababababababababababababab",
                "920f1239decafbadcafebabef70e513eb90b9b25c2de0001bbed4848faa644665f3d7f34125914e9f4d0ae923c6f479b95a0f7b53133",
            ),
            (
                "empty_one_byte_csrc",
                "920f123adecafbadcafebabe0001e2400000b26ebede0000abababababababababababababababab",
                "920f123adecafbadcafebabe7130b6abfe2ab0e3c0de0000e3d9f64b25c9e74cb4cf8e43fb92e3781c2c0ceab6b3a499a14c",
            ),
            (
                "empty_two_byte_csrc",
                "920f123bdecafbadcafebabe0001e2400000b26e10000000abababababababababababababababab",
                "920f123bdecafbadcafebabecbf24c124330e1c8c2de0000599dd45bc9d687b603e8b59d771fd38e88b170e0cd31e125eabe",
            ),
        ],
    },
    Case {
        profile: ProtectionProfile::AeadAes128Gcm,
        key: "000102030405060708090a0b0c0d0e0f",
        salt: "a0a1a2a3a4a5a6a7a8a9aaab",
        vectors: &[
            (
                "one_byte",
                "900f1235decafbadcafebabebede000151000200abababababababababababababababab",
                "900f1235decafbadcafebabec0de000139972dc9572c4d99e8fc355de743fb2e94f9d8ff54e72f4193bbc5c74ffab0fa9fa0fbeb",
            ),
            (
                "two_byte",
                "900f1236decafbadcafebabe1000000105020002abababababababababababababababab",
                "900f1236decafbadcafebabec2de0001bb75a4c545cd1f413bdb7daa2b1e3263de313667c963249081b35a65f5cb6c88b394235f",
            ),
            (
                "one_byte_csrc",
                "920f1238decafbadcafebabe0001e2400000b26ebede000151000200abababababababababababababababab",
                "920f1238decafbadcafebabe63bbccc4a7f695c4c0de00018ad7c71fac70a80c92866b4c6ba98546ef913586e95ffaaffe956885bb0647a8bc094ac8",
            ),
            (
                "two_byte_csrc",
                "920f1239decafbadcafebabe0001e2400000b26e1000000105020002abababababababababababababababab",
                "920f1239decafbadcafebabe3680524f8d312b00c2de0001c78d120038422bc111a7187a18246f980c059cc6bc9df8b626394eca344e4b05d80fea83",
            ),
            (
                "empty_one_byte_csrc",
                "920f123adecafbadcafebabe0001e2400000b26ebede0000abababababababababababababababab",
                "920f123adecafbadcafebabe15b6bb4337906fffc0de0000b7b964537a2b03ab7ba5389ce93317126b5d974df30c6884dcb651c5e120c1da",
            ),
            (
                "empty_two_byte_csrc",
                "920f123bdecafbadcafebabe0001e2400000b26e10000000abababababababababababababababab",
                "920f123bdecafbadcafebabedcb38c9e48bf95f4c2de000061ee432cf920317076613258d3ce4236c06ac429681ad08413512dc98b5207d8",
            ),
        ],
    },
];

fn context(case: &Case, mode: CryptexMode) -> Context {
    let crypto = rtc_srtp::crypto::default_provider().expect("a built-in crypto provider");
    let mut ctx = Context::new(
        &unhex(case.key),
        &unhex(case.salt),
        case.profile,
        None,
        None,
        crypto.crypto(),
    )
    .unwrap();
    ctx.set_cryptex_mode(mode);
    ctx
}

#[test]
fn rfc9335_appendix_a_encrypt() {
    for case in CASES {
        for (name, plain, srtp) in case.vectors {
            let plain = unhex(plain);
            let want = unhex(srtp);

            // Into a fresh buffer, leaving the input alone.
            let got = context(case, CryptexMode::Enabled)
                .encrypt_rtp(&plain)
                .unwrap();
            assert_eq!(
                &got[..],
                &want[..],
                "{:?} / {name}: encrypt_rtp",
                case.profile
            );

            // In place, with spare room for the tag.
            let mut buf = BytesMut::with_capacity(plain.len() + 32);
            buf.extend_from_slice(&plain);
            context(case, CryptexMode::Enabled)
                .encrypt_rtp_in_place(&mut buf)
                .unwrap();
            assert_eq!(&buf[..], &want[..], "{:?} / {name}: in place", case.profile);
        }
    }
}

#[test]
fn rfc9335_appendix_a_decrypt() {
    for case in CASES {
        for (name, plain, srtp) in case.vectors {
            let want = unhex(plain);
            let encrypted = unhex(srtp);

            let got = context(case, CryptexMode::Enabled)
                .decrypt_rtp(&encrypted)
                .unwrap();
            assert_eq!(
                &got[..],
                &want[..],
                "{:?} / {name}: decrypt_rtp",
                case.profile
            );

            let mut buf = BytesMut::from(&encrypted[..]);
            context(case, CryptexMode::Enabled)
                .decrypt_rtp_in_place(&mut buf)
                .unwrap();
            assert_eq!(&buf[..], &want[..], "{:?} / {name}: in place", case.profile);

            // `Required` accepts what `Enabled` does.
            let got = context(case, CryptexMode::Required)
                .decrypt_rtp(&encrypted)
                .unwrap();
            assert_eq!(&got[..], &want[..], "{:?} / {name}: required", case.profile);
        }
    }
}

/// RFC 9335 §5.1: CSRCs but no extension block: an empty one-byte block is added so there is
/// something to carry the Cryptex marker. The empty-extension vectors are exactly that packet.
#[test]
fn csrcs_without_an_extension_block_get_an_empty_one() {
    for case in CASES {
        let (_, plain, srtp) = case.vectors[4];
        let mut p = unhex(plain);
        // Drop the (empty) extension block and clear the X bit.
        assert_eq!(&p[12 + 8..12 + 12], &[0xbe, 0xde, 0x00, 0x00]);
        p.drain(12 + 8..12 + 12);
        p[0] &= !0x10;

        let got = context(case, CryptexMode::Enabled).encrypt_rtp(&p).unwrap();
        assert_eq!(&got[..], &unhex(srtp)[..], "{:?}", case.profile);
    }
}

/// RFC 9335 §5.1: Cryptex cannot protect an extension block that is not RFC 8285.
#[test]
fn unsupported_header_extension_profile_is_refused() {
    let case = &CASES[0];
    // X bit set, profile 0x0001, no elements.
    let mut p = unhex("900f1235decafbadcafebabe");
    p[0] |= 0x10;
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    p.extend_from_slice(&[0xab; 8]);
    let err = context(case, CryptexMode::Enabled)
        .encrypt_rtp(&p)
        .unwrap_err();
    assert_eq!(err, shared::error::Error::ErrUnsupportedHeaderExtension);
}

#[test]
fn modes_decide_what_is_accepted() {
    let case = &CASES[0];
    let (_, plain, cryptex_srtp) = case.vectors[0];
    let plain = unhex(plain);

    // Protected without Cryptex: what a peer that did not negotiate it sends.
    let ordinary = context(case, CryptexMode::Disabled)
        .encrypt_rtp(&plain)
        .unwrap();
    assert_ne!(&ordinary[..], &unhex(cryptex_srtp)[..]);

    // Disabled refuses Cryptex packets; the other two modes read ordinary packets only if
    // they are not Required.
    assert_eq!(
        context(case, CryptexMode::Disabled)
            .decrypt_rtp(&unhex(cryptex_srtp))
            .unwrap_err(),
        shared::error::Error::ErrCryptexDisabled
    );
    assert_eq!(
        &context(case, CryptexMode::Enabled)
            .decrypt_rtp(&ordinary)
            .unwrap()[..],
        &plain[..]
    );
    assert_eq!(
        context(case, CryptexMode::Required)
            .decrypt_rtp(&ordinary)
            .unwrap_err(),
        shared::error::Error::ErrUnencryptedHeaderExtAndCsrcs
    );

    // A packet with neither extensions nor CSRCs is never a reason to refuse.
    let bare = unhex("800f1235decafbadcafebabeabababab");
    let protected = context(case, CryptexMode::Disabled)
        .encrypt_rtp(&bare)
        .unwrap();
    assert_eq!(
        &context(case, CryptexMode::Required)
            .decrypt_rtp(&protected)
            .unwrap()[..],
        &bare[..]
    );
}

#[test]
fn a_forged_cryptex_packet_is_rejected_and_left_alone() {
    for case in CASES {
        for (name, _, srtp) in case.vectors {
            let mut forged = unhex(srtp);
            let n = forged.len();
            forged[n - 1] ^= 0x01;
            let mut buf = BytesMut::from(&forged[..]);
            assert!(
                context(case, CryptexMode::Enabled)
                    .decrypt_rtp_in_place(&mut buf)
                    .is_err(),
                "{:?} / {name}",
                case.profile
            );
            if matches!(case.profile, ProtectionProfile::Aes128CmHmacSha1_80) {
                assert_eq!(
                    &buf[..],
                    &forged[..],
                    "{name}: a rejected packet is untouched"
                );
            }
        }
    }
}
