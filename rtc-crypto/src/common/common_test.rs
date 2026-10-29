//! CCM tests, ported from pion's `pkg/crypto/ccm` (`ccm_test.go`).
//!
//! pion's CCM is parameterized at runtime (`NewCCM(blk, M, len(nonce))`), so its tests run the
//! RFC 3610 vectors with 13-byte nonces and 8-, 10- and 14-byte tags. rtc-crypto's provider path
//! bakes the parameters into [`AeadAlgorithm`] — DTLS CCM uses a 12-byte nonce with an 8- or
//! 16-byte tag — so the vectors run through the same `ccm` crate primitive the provider wraps
//! ([`Ccm`]), at pion's parameters, with exactly the detached seal/open calls
//! [`CommonCcm`](super::CommonCcm) makes. Where pion's assertions survive the provider's fixed
//! parameters (bad nonce or tag lengths, over-long messages), they run through `new_ccm`.

use super::*;
use ccm::TagSize;
use ccm::consts::{U10, U13, U14};

/// pion's `aesKey1to12`.
const AES_KEY_1_TO_12: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
/// pion's `aesKey13to24`.
const AES_KEY_13_TO_24: &str = "d7828d13b2b0bdc325a76236df93cc6b";

/// pion's `mustHexDecode`.
fn must_hex_decode(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "pion's vectors hold whole bytes: {s:?}"
    );
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex digits"), 16)
                .expect("pion's vectors are valid hex")
        })
        .collect()
}

// AESKey: AES key
// CipherText: authenticated and encrypted output
// ClearHeaderOctets: input with X cleartext header octets
// Data: input with X cleartext header octets
// M: length(CBC-MAC)
// Nonce: nonce
//
// The hex strings are pion's, verbatim.
struct Vector {
    aes_key: &'static str,
    cipher_text: &'static str,
    clear_header_octets: usize,
    data: &'static str,
    m: usize,
    nonce: &'static str,
}

// Seal and open one vector, as pion's `seal`/`open` subtests do: the `ClearHeaderOctets` prefix
// is the additional data, the rest the plaintext. pion's `Seal`/`Open` carry the tag appended to
// the ciphertext, so the expected `CipherText` is payload ciphertext followed by the `M`-byte
// tag.
fn seal_and_open_vector<M>(vector: &Vector, index: usize)
where
    M: ArraySize + TagSize,
{
    let key = must_hex_decode(vector.aes_key);
    let data = must_hex_decode(vector.data);
    let cipher_text = must_hex_decode(vector.cipher_text);
    let nonce = must_hex_decode(vector.nonce);
    let (header, plaintext) = data.split_at(vector.clear_header_octets);
    let sealed = &cipher_text[vector.clear_header_octets..];
    let (expected_ct, expected_tag) = sealed.split_at(sealed.len() - M::USIZE);

    let cipher = Ccm::<Aes128, M, U13>::new_from_slice(&key)
        .expect("could not initialize AES block cipher from key");
    let nonce: &Array<u8, U13> = nonce.as_slice().try_into().expect("13-byte nonce");

    // seal: pion's `Seal` returns the ciphertext with the tag appended.
    let mut dst = plaintext.to_vec();
    let tag = cipher
        .encrypt_inout_detached(nonce, header, dst.as_mut_slice().into())
        .expect("could not seal");
    dst.extend_from_slice(&tag);
    assert_eq!(
        dst.as_slice(),
        sealed,
        "packet vector #{index}: seal mismatch"
    );

    // open
    let tag: &Array<u8, M> = expected_tag.try_into().expect("M-byte tag");
    let mut buffer = expected_ct.to_vec();
    cipher
        .decrypt_inout_detached(nonce, header, buffer.as_mut_slice().into(), tag)
        .expect("could not open");
    assert_eq!(
        buffer.as_slice(),
        plaintext,
        "packet vector #{index}: open plaintext mismatch"
    );
}

// Port of pion `TestRFC3610Vectors`: the 24 vectors of RFC 3610 section 8.
#[test]
fn test_rfc3610_vectors() {
    let cases = [
        // Vectors 1-12
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "0001020304050607588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0",
            clear_header_octets: 8,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            m: 8,
            nonce: "00000003020100a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060772c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3ba091d56e10400916",
            clear_header_octets: 8,
            data: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            m: 8,
            nonce: "00000004030201a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060751b1e5f44a197d1da46b0f8e2d282ae871e838bb64da8596574adaa76fbd9fb0c5",
            clear_header_octets: 8,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            m: 8,
            nonce: "00000005040302a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060708090a0ba28c6865939a9a79faaa5c4c2a9d4a91cdac8c96c861b9c9e61ef1",
            clear_header_octets: 12,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            m: 8,
            nonce: "00000006050403a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060708090a0bdcf1fb7b5d9e23fb9d4e131253658ad86ebdca3e51e83f077d9c2d93",
            clear_header_octets: 12,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            m: 8,
            nonce: "00000007060504a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060708090a0b6fc1b011f006568b5171a42d953d469b2570a4bd87405a0443ac91cb94",
            clear_header_octets: 12,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            m: 8,
            nonce: "00000008070605a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "00010203040506070135d1b2c95f41d5d1d4fec185d166b8094e999dfed96c048c56602c97acbb7490",
            clear_header_octets: 8,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            m: 10,
            nonce: "00000009080706a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "00010203040506077b75399ac0831dd2f0bbd75879a2fd8f6cae6b6cd9b7db24c17b4433f434963f34b4",
            clear_header_octets: 8,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            m: 10,
            nonce: "0000000a090807a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060782531a60cc24945a4b8279181ab5c84df21ce7f9b73f42e197ea9c07e56b5eb17e5f4e",
            clear_header_octets: 8,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            m: 10,
            nonce: "0000000b0a0908a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060708090a0b07342594157785152b074098330abb141b947b566aa9406b4d999988dd",
            clear_header_octets: 12,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
            m: 10,
            nonce: "0000000c0b0a09a0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060708090a0b676bb20380b0e301e8ab79590a396da78b834934f53aa2e9107a8b6c022c",
            clear_header_octets: 12,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            m: 10,
            nonce: "0000000d0c0b0aa0a1a2a3a4a5",
        },
        Vector {
            aes_key: AES_KEY_1_TO_12,
            cipher_text: "000102030405060708090a0bc0ffa0d6f05bdb67f24d43a4338d2aa4bed7b20e43cd1aa31662e7ad65d6db",
            clear_header_octets: 12,
            data: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            m: 10,
            nonce: "0000000e0d0c0ba0a1a2a3a4a5",
        },
        // Vectors 13-24
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "0be1a88bace018b14cb97f86a2a4689a877947ab8091ef5386a6ffbdd080f8e78cf7cb0cddd7b3",
            clear_header_octets: 8,
            data: "0be1a88bace018b108e8cf97d820ea258460e96ad9cf5289054d895ceac47c",
            m: 8,
            nonce: "00412b4ea9cdbe3c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "63018f76dc8a1bcb4ccb1e7ca981befaa0726c55d378061298c85c92814abc33c52ee81d7d77c08a",
            clear_header_octets: 8,
            data: "63018f76dc8a1bcb9020ea6f91bdd85afa0039ba4baff9bfb79c7028949cd0ec",
            m: 8,
            nonce: "0033568ef7b2633c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "aa6cfa36cae86b40b1d23a2220ddc0ac900d9aa03c61fcf4a559a4417767089708a776796edb723506",
            clear_header_octets: 8,
            data: "aa6cfa36cae86b40b916e0eacc1c00d7dcec68ec0b3bbb1a02de8a2d1aa346132e",
            m: 8,
            nonce: "00103fe41336713c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "d0d0735c531e1becf049c24414d253c3967b70609b7cbb7c499160283245269a6f49975bcadeaf",
            clear_header_octets: 12,
            data: "d0d0735c531e1becf049c24412daac5630efa5396f770ce1a66b21f7b2101c",
            m: 8,
            nonce: "00764c63b8058e3c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "77b60f011c03e1525899bcae5545ff1a085ee2efbf52b2e04bee1e2336c73e3f762c0c7744fe7e3c",
            clear_header_octets: 12,
            data: "77b60f011c03e1525899bcaee88b6a46c78d63e52eb8c546efb5de6f75e9cc0d",
            m: 8,
            nonce: "00f8b678094e3b3c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "cd9044d2b71fdb8120ea60c0009769ecabdf48625594c59251e6035722675e04c847099e5ae0704551",
            clear_header_octets: 12,
            data: "cd9044d2b71fdb8120ea60c06435acbafb11a82e2f071d7ca4a5ebd93a803ba87f",
            m: 8,
            nonce: "00d560912d3f703c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "d85bc7e69f944fb8bc218daa947427b6db386a99ac1aef23ade0b52939cb6a637cf9bec2408897c6ba",
            clear_header_octets: 8,
            data: "d85bc7e69f944fb88a19b950bcf71a018e5e6701c91787659809d67dbedd18",
            m: 10,
            nonce: "0042fff8f1951c3c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "74a0ebc9069f5b375810e6fd25874022e80361a478e3e9cf484ab04f447efff6f0a477cc2fc9bf548944",
            clear_header_octets: 8,
            data: "74a0ebc9069f5b371761433c37c5a35fc1f39f406302eb907c6163be38c98437",
            m: 10,
            nonce: "00920f40e56cdc3c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "44a3aa3aae6475caf2beed7bc5098e83feb5b31608f8e29c38819a89c8e776f1544d4151a4ed3a8b87b9ce",
            clear_header_octets: 8,
            data: "44a3aa3aae6475caa434a8e58500c6e41530538862d686ea9e81301b5ae4226bfa",
            m: 10,
            nonce: "0027ca0c7120bc3c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "ec46bb63b02520c33c49fd7031d750a09da3ed7fddd49a2032aabf17ec8ebf7d22c8088c666be5c197",
            clear_header_octets: 12,
            data: "ec46bb63b02520c33c49fd70b96b49e21d621741632875db7f6c9243d2d7c2",
            m: 10,
            nonce: "005b8ccbcd9af83c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "47a65ac78b3d594227e85e71e882f1dbd38ce3eda7c23f04dd65071eb41342acdf7e00dccec7ae52987d",
            clear_header_octets: 12,
            data: "47a65ac78b3d594227e85e71e2fcfbb880442c731bf95167c8ffd7895e337076",
            m: 10,
            nonce: "003ebe94044b9a3c9696766cfa",
        },
        Vector {
            aes_key: AES_KEY_13_TO_24,
            cipher_text: "6e37a6ef546d955d34ab6059f32905b88a641b04b9c9ffb58cc390900f3da12ab16dce9e82efa16da62059",
            clear_header_octets: 12,
            data: "6e37a6ef546d955d34ab6059abf21c0b02feb88f856df4a37381bce3cc128517d4",
            m: 10,
            nonce: "008d493b30ae8b3c9696766cfa",
        },
    ];

    assert_eq!(cases.len(), 24);

    for (index, case) in cases.iter().enumerate() {
        match case.m {
            8 => seal_and_open_vector::<U8>(case, index + 1),
            10 => seal_and_open_vector::<U10>(case, index + 1),
            m => panic!("packet vector #{}: unexpected M {m}", index + 1),
        }
    }
}

// Port of pion `TestNewCCMError`: pion's `NewCCM` rejects an invalid nonce length or tag size at
// construction. rtc-crypto's `new_ccm` bakes both into the [`AeadAlgorithm`] (a 12-byte nonce; an
// 8- or 16-byte tag), so the same four invalid values are rejected when the cipher is used — the
// guarantees pion gets from the constructor, checked at the boundary `new_ccm` controls.
#[test]
fn test_new_ccm_error() -> Result<(), CryptoError> {
    let key = must_hex_decode(AES_KEY_1_TO_12);
    let mut aead = new_ccm(AeadAlgorithm::Aes128Ccm8, &key)?;
    let mut plaintext = vec![0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    let mut tag = vec![0u8; 8];
    let nonce = [0u8; CCM_NONCE_LEN];

    // ShortNonceLength: pion's 6 bytes.
    let short_nonce = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5];
    assert_eq!(
        aead.seal_in_place(&short_nonce, b"", &mut plaintext, &mut tag),
        Err(CryptoError::InvalidNonceLength {
            expected: CCM_NONCE_LEN,
            actual: short_nonce.len(),
        })
    );

    // LongNonceLength: pion's 14 bytes.
    let long_nonce = must_hex_decode("0001020304050607080910111213");
    assert_eq!(
        aead.seal_in_place(&long_nonce, b"", &mut plaintext, &mut tag),
        Err(CryptoError::InvalidNonceLength {
            expected: CCM_NONCE_LEN,
            actual: long_nonce.len(),
        })
    );

    // ShortTag: pion's 3 bytes.
    let mut short_tag = vec![0u8; 3];
    assert_eq!(
        aead.seal_in_place(&nonce, b"", &mut plaintext, &mut short_tag),
        Err(CryptoError::InvalidTagLength {
            expected: 8,
            actual: short_tag.len(),
        })
    );

    // LongTag: pion's 17 bytes.
    let mut long_tag = vec![0u8; 17];
    assert_eq!(
        aead.seal_in_place(&nonce, b"", &mut plaintext, &mut long_tag),
        Err(CryptoError::InvalidTagLength {
            expected: 8,
            actual: long_tag.len(),
        })
    );

    Ok(())
}

// Port of pion `TestSealError`, through the provider path:
//
// * InvalidNonceLength — pion seals a 13-byte-nonce CCM with a 12-byte nonce; the provider's CCM
//   is built for a 12-byte nonce, so the mismatched direction is pion's 13-byte RFC 3610 nonce.
// * PlaintextTooLong — the message length is bounded by the nonce length (RFC 3610 section 5):
//   pion's 13-byte nonce caps a message at 65535 bytes, so its 100000-byte plaintext fails; the
//   provider's 12-byte nonce caps a message at 2^24-1, so the failing size scales accordingly.
#[test]
fn test_seal_error() -> Result<(), CryptoError> {
    let key = must_hex_decode(AES_KEY_1_TO_12);
    let mut aead = new_ccm(AeadAlgorithm::Aes128Ccm8, &key)?;

    // InvalidNonceLength: 13 bytes, pion's RFC 3610 vector-1 nonce.
    let nonce = must_hex_decode("00000003020100a0a1a2a3a4a5");
    let mut plaintext =
        must_hex_decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
    let mut tag = vec![0u8; 8];
    assert_eq!(
        aead.seal_in_place(&nonce, b"", &mut plaintext, &mut tag),
        Err(CryptoError::InvalidNonceLength {
            expected: CCM_NONCE_LEN,
            actual: nonce.len(),
        })
    );

    // PlaintextTooLong: one byte over the 2^24-1 limit of a 12-byte-nonce CCM.
    let nonce = [0u8; CCM_NONCE_LEN];
    let mut plaintext = vec![0u8; 1 << 24];
    let mut tag = vec![0u8; 8];
    assert!(
        aead.seal_in_place(&nonce, b"", &mut plaintext, &mut tag)
            .is_err(),
        "a plaintext above the CCM message limit must not seal"
    );

    Ok(())
}

// Port of pion `TestOpenError`, through the provider path:
//
// * CiphertextTooShort — pion's `Open` rejects a ciphertext shorter than the tag before
//   decrypting. The detached-tag provider API carries the tag separately, so there is no such
//   length to check; the 2 bytes pion opens cannot authenticate against any 8-byte tag, which is
//   the same outcome.
// * CiphertextTooLong — as in `test_seal_error`, the limit is 2^24-1 at the provider's 12-byte
//   nonce, against pion's 65535 at 13.
#[test]
fn test_open_error() -> Result<(), CryptoError> {
    let key = must_hex_decode(AES_KEY_1_TO_12);
    let mut aead = new_ccm(AeadAlgorithm::Aes128Ccm8, &key)?;

    // CiphertextTooShort: pion's 10-byte ciphertext minus the 8-byte clear header.
    let nonce = [0u8; CCM_NONCE_LEN];
    let mut ciphertext = vec![0u8; 10 - 8];
    let tag = vec![0u8; 8];
    assert!(
        aead.open_in_place(&nonce, b"", &mut ciphertext, &tag)
            .is_err(),
        "a ciphertext shorter than the tag must not open"
    );

    // CiphertextTooLong: one byte over the 2^24-1 limit of a 12-byte-nonce CCM.
    let mut ciphertext = vec![0u8; 1 << 24];
    assert!(
        aead.open_in_place(&nonce, b"", &mut ciphertext, &tag)
            .is_err(),
        "a ciphertext above the CCM message limit must not open"
    );

    Ok(())
}

// Port of pion `TestLongAdditionalData`: the encoding of the additional-data length on both
// sides of 0xff00 (RFC 3610 section 2.2, NIST SP 800-38C A.2.2). The 65536-byte case is Example 4
// of SP 800-38C Appendix C; the other two were computed with an independent AES-CCM
// implementation.
#[test]
fn test_long_additional_data() {
    let cases = [
        (
            0xfeff,
            "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72bd4d3d3b7bf1365b4577abeccac4",
        ),
        (
            0xff00,
            "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72107fb78c91dbb3c21cd810ce52a6",
        ),
        (
            0x10000,
            "69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b",
        ),
    ];

    let key = must_hex_decode("404142434445464748494a4b4c4d4e4f");
    let cipher = Ccm::<Aes128, U14, U13>::new_from_slice(&key)
        .expect("could not initialize AES block cipher from key");
    let nonce = must_hex_decode("101112131415161718191a1b1c");
    let nonce: &Array<u8, U13> = nonce.as_slice().try_into().expect("13-byte nonce");
    let plaintext =
        must_hex_decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

    for (adata_length, expected) in cases {
        let mut adata = vec![0u8; adata_length];
        for (i, byte) in adata.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let ciphertext = must_hex_decode(expected);

        // seal: pion's `Seal` returns the ciphertext with the tag appended.
        let mut sealed = plaintext.clone();
        let tag = cipher
            .encrypt_inout_detached(nonce, &adata, sealed.as_mut_slice().into())
            .expect("could not seal");
        sealed.extend_from_slice(&tag);
        assert_eq!(
            sealed.as_slice(),
            ciphertext.as_slice(),
            "additional data length {adata_length:#x}: seal mismatch"
        );

        // open
        let tag_len = ciphertext.len() - plaintext.len();
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - tag_len);
        let tag: &Array<u8, U14> = tag.try_into().expect("14-byte tag");
        let mut opened = ct.to_vec();
        cipher
            .decrypt_inout_detached(nonce, &adata, opened.as_mut_slice().into(), tag)
            .expect("could not open");
        assert_eq!(
            opened.as_slice(),
            plaintext.as_slice(),
            "additional data length {adata_length:#x}: open mismatch"
        );
    }
}
