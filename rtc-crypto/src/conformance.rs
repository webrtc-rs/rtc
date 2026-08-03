//! Reusable conformance assertions for built-in and application-provided crypto providers.

use crate::{
    AeadAlgorithm, BlockCipherAlgorithm, CbcAlgorithm, CryptoAlgorithm, CryptoError, HashAlgorithm,
    HmacAlgorithm, KeyExchangeAlgorithm, PublicKey, PublicKeyEncoding, RTCCrypto,
    RTCCryptoProvider, SignatureScheme, StreamCipherAlgorithm,
};

/// Exercises the complete initial RTC crypto contract implemented by the built-in providers.
///
/// This helper panics on a contract violation so provider authors can call it directly from a
/// normal `#[test]` function.
pub fn assert_provider(provider: &dyn RTCCryptoProvider) {
    assert_basic_capabilities(provider.crypto());
    assert_hashes_and_hmac(provider.crypto());
    assert_block_and_stream_ciphers(provider.crypto());
    assert_cbc(provider.crypto());
    assert_aead(provider.crypto());
    assert_key_exchange(provider.crypto());
    assert_signatures(provider.crypto());
    assert_random(provider);
}

fn assert_basic_capabilities(crypto: &dyn RTCCrypto) {
    let capabilities = [
        CryptoAlgorithm::Hash(HashAlgorithm::Md5),
        CryptoAlgorithm::Hash(HashAlgorithm::Sha256),
        CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1),
        CryptoAlgorithm::Hmac(HmacAlgorithm::Sha256),
        CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes128),
        CryptoAlgorithm::BlockCipher(BlockCipherAlgorithm::Aes256),
        CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes128Ctr),
        CryptoAlgorithm::StreamCipher(StreamCipherAlgorithm::Aes256Ctr),
        CryptoAlgorithm::Cbc(CbcAlgorithm::Aes256Cbc),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Gcm),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes256Gcm),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Ccm),
        CryptoAlgorithm::Aead(AeadAlgorithm::Aes128Ccm8),
        CryptoAlgorithm::Aead(AeadAlgorithm::ChaCha20Poly1305),
        CryptoAlgorithm::KeyExchange(KeyExchangeAlgorithm::P256),
        CryptoAlgorithm::KeyExchange(KeyExchangeAlgorithm::P384),
        CryptoAlgorithm::KeyExchange(KeyExchangeAlgorithm::X25519),
        CryptoAlgorithm::Signature(SignatureScheme::Ed25519),
        CryptoAlgorithm::Signature(SignatureScheme::EcdsaP256Sha256),
        CryptoAlgorithm::Signature(SignatureScheme::EcdsaP384Sha384),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha1),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha256),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha384),
        CryptoAlgorithm::Signature(SignatureScheme::RsaPkcs1Sha512),
        CryptoAlgorithm::SigningKeyGeneration(SignatureScheme::Ed25519),
        CryptoAlgorithm::SigningKeyGeneration(SignatureScheme::EcdsaP256Sha256),
        CryptoAlgorithm::SigningKeyImport(SignatureScheme::Ed25519),
        CryptoAlgorithm::SigningKeyImport(SignatureScheme::EcdsaP256Sha256),
        CryptoAlgorithm::SigningKeyImport(SignatureScheme::RsaPkcs1Sha256),
    ];
    for capability in capabilities {
        assert!(
            crypto.supports(capability),
            "missing capability: {capability:?}"
        );
    }
    assert!(!crypto.supports(CryptoAlgorithm::SigningKeyGeneration(
        SignatureScheme::RsaPkcs1Sha256
    )));
    assert!(matches!(
        crypto.generate_signing_key(SignatureScheme::RsaPkcs1Sha256),
        Err(CryptoError::UnsupportedAlgorithm(_))
    ));
    for scheme in [
        SignatureScheme::Ed25519,
        SignatureScheme::EcdsaP256Sha256,
        SignatureScheme::RsaPkcs1Sha256,
    ] {
        assert!(matches!(
            crypto.import_signing_key(scheme, b"not a PKCS#8 key"),
            Err(CryptoError::InvalidPrivateKey)
        ));
    }
}

/// Checks hash and HMAC known-answer vectors and their error contract.
pub fn assert_hashes_and_hmac(crypto: &dyn RTCCrypto) {
    // RFC 1321, FIPS 180-4, RFC 2202, and RFC 4231 known-answer vectors.
    assert_eq!(
        crypto.hash(HashAlgorithm::Md5, b"abc").unwrap(),
        bytes("900150983cd24fb0d6963f7d28e17f72")
    );
    assert_eq!(
        crypto.hash(HashAlgorithm::Sha256, b"abc").unwrap(),
        bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );

    let key = [0x0b; 20];
    let mut sha1 = [0; 20];
    let mut sha1_mac = crypto.new_hmac(HmacAlgorithm::Sha1, &key).unwrap();
    assert_eq!(sha1_mac.output_len(), 20);
    sha1_mac.sign(&[b"Hi ", b"There"], &mut sha1).unwrap();
    assert_eq!(
        sha1.as_slice(),
        bytes("b617318655057264e28bc0b6fb378c8ef146be00")
    );

    // A keyed MAC is reusable: the second message must not be affected by the first.
    let mut repeat = [0; 20];
    sha1_mac.sign(&[b"Hi ", b"There"], &mut repeat).unwrap();
    assert_eq!(repeat, sha1, "a Mac must produce the same tag when reused");

    let mut sha256 = [0; 32];
    let mut sha256_mac = crypto.new_hmac(HmacAlgorithm::Sha256, &key).unwrap();
    sha256_mac.sign(&[b"Hi ", b"There"], &mut sha256).unwrap();
    assert_eq!(
        sha256.as_slice(),
        bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );

    // Splitting the input across slices must not change the tag.
    let mut joined = [0; 32];
    sha256_mac.sign(&[b"Hi There"], &mut joined).unwrap();
    assert_eq!(joined, sha256, "slice boundaries must not affect the tag");

    sha256_mac.verify(&[b"Hi There"], &sha256).unwrap();
    let mut bad_tag = sha256;
    bad_tag[0] ^= 1;
    assert_eq!(
        sha256_mac.verify(&[b"Hi There"], &bad_tag),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(matches!(
        sha256_mac.sign(&[b"x"], &mut [0; 31]),
        Err(CryptoError::InvalidTagLength { .. })
    ));
}

/// Checks AES block and stream-cipher known-answer vectors and malformed inputs.
pub fn assert_block_and_stream_ciphers(crypto: &dyn RTCCrypto) {
    // FIPS 197 and NIST SP 800-38A known-answer vectors.
    let mut block = bytes("00112233445566778899aabbccddeeff");
    crypto
        .block_encrypt(
            BlockCipherAlgorithm::Aes128,
            &bytes("000102030405060708090a0b0c0d0e0f"),
            &mut block,
        )
        .unwrap();
    assert_eq!(block, bytes("69c4e0d86a7b0430d8cdb78070b4c55a"));

    let mut block = bytes("00112233445566778899aabbccddeeff");
    crypto
        .block_encrypt(
            BlockCipherAlgorithm::Aes256,
            &bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            &mut block,
        )
        .unwrap();
    assert_eq!(block, bytes("8ea2b7ca516745bfeafc49904b496089"));

    let key = bytes("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = bytes("6bc1bee22e409f96e93d7e117393172a");
    let mut encrypted = plaintext.clone();
    crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &key)
        .unwrap()
        .apply_keystream(&iv, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted, bytes("874d6191b620e3261bef6864990db6ce"));
    crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &key)
        .unwrap()
        .apply_keystream(&iv, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted, plaintext);

    let key = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let mut encrypted = plaintext.clone();
    crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes256Ctr, &key)
        .unwrap()
        .apply_keystream(&iv, &mut encrypted)
        .unwrap();
    assert_eq!(encrypted, bytes("601ec313775789a5b7a7f504bbf3d228"));

    assert!(matches!(
        crypto.block_encrypt(BlockCipherAlgorithm::Aes128, &[0; 15], &mut [0; 16]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        crypto.block_encrypt(BlockCipherAlgorithm::Aes128, &[0; 16], &mut [0; 15]),
        Err(CryptoError::OutputTooSmall { .. })
    ));
    assert!(matches!(
        crypto.new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &[0; 15]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    let mut stream = crypto
        .new_stream_cipher(StreamCipherAlgorithm::Aes128Ctr, &[0; 16])
        .unwrap();
    assert!(matches!(
        stream.apply_keystream(&[0; 15], &mut [0; 1]),
        Err(CryptoError::InvalidNonceLength { .. })
    ));
}

/// Checks AES-CBC known-answer vectors and malformed inputs.
pub fn assert_cbc(crypto: &dyn RTCCrypto) {
    // NIST SP 800-38A F.2.5.
    let key = bytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let iv = bytes("000102030405060708090a0b0c0d0e0f");
    let plaintext = bytes("6bc1bee22e409f96e93d7e117393172a");
    let mut blocks = plaintext.clone();
    let mut cipher = crypto.new_cbc(CbcAlgorithm::Aes256Cbc, &key).unwrap();
    assert_eq!(cipher.block_len(), 16);
    cipher.encrypt_blocks(&iv, &mut blocks).unwrap();
    assert_eq!(blocks, bytes("f58c4c04d6e5f1ba779eabfb5f7bfbd6"));
    cipher.decrypt_blocks(&iv, &mut blocks).unwrap();
    assert_eq!(blocks, plaintext);

    assert!(matches!(
        crypto.new_cbc(CbcAlgorithm::Aes256Cbc, &[0; 31]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        cipher.encrypt_blocks(&[0; 15], &mut [0; 16]),
        Err(CryptoError::InvalidNonceLength { .. })
    ));
    assert!(matches!(
        cipher.encrypt_blocks(&[0; 16], &mut []),
        Err(CryptoError::OutputTooSmall { .. })
    ));
    assert!(matches!(
        cipher.decrypt_blocks(&[0; 16], &mut [0; 15]),
        Err(CryptoError::OutputTooSmall { .. })
    ));
}

/// Checks AEAD known-answer vectors, round trips, authentication failures, and malformed sizes.
pub fn assert_aead(crypto: &dyn RTCCrypto) {
    // NIST SP 800-38D, NIST SP 800-38C, and RFC 8439 known-answer vectors.
    let mut gcm = crypto.new_aead(AeadAlgorithm::Aes128Gcm, &[0; 16]).unwrap();
    let mut block = vec![0; 16];
    let mut tag = vec![0; gcm.tag_len()];
    gcm.seal_in_place(&[0; 12], &[], &mut block, &mut tag)
        .unwrap();
    assert_eq!(block, bytes("0388dace60b6a392f328c2b971b2fe78"));
    assert_eq!(tag, bytes("ab6e47d42cec13bdf53a67b21257bddf"));
    gcm.open_in_place(&[0; 12], &[], &mut block, &tag).unwrap();
    assert_eq!(block, vec![0; 16]);

    let mut gcm = crypto.new_aead(AeadAlgorithm::Aes256Gcm, &[0; 32]).unwrap();
    let mut block = vec![0; 16];
    let mut tag = vec![0; gcm.tag_len()];
    gcm.seal_in_place(&[0; 12], &[], &mut block, &mut tag)
        .unwrap();
    assert_eq!(block, bytes("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(tag, bytes("d0d1c8a799996bf0265b98b5d48ab919"));

    let mut ccm8 = crypto
        .new_aead(
            AeadAlgorithm::Aes128Ccm8,
            &bytes("404142434445464748494a4b4c4d4e4f"),
        )
        .unwrap();
    let mut ccm8_buffer = bytes("202122232425262728292a2b2c2d2e2f3031323334353637");
    let mut ccm8_tag = vec![0; ccm8.tag_len()];
    ccm8.seal_in_place(
        &bytes("101112131415161718191a1b"),
        &bytes("000102030405060708090a0b0c0d0e0f10111213"),
        &mut ccm8_buffer,
        &mut ccm8_tag,
    )
    .unwrap();
    assert_eq!(
        ccm8_buffer,
        bytes("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5")
    );
    assert_eq!(ccm8_tag, bytes("484392fbc1b09951"));

    let mut chacha = crypto
        .new_aead(
            AeadAlgorithm::ChaCha20Poly1305,
            &bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        )
        .unwrap();
    let mut chacha_buffer = bytes(concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393",
        "a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f722074",
        "6865206675747572652c2073756e73637265656e20776f756c642062652069742e"
    ));
    let mut chacha_tag = vec![0; chacha.tag_len()];
    chacha
        .seal_in_place(
            &bytes("070000004041424344454647"),
            &bytes("50515253c0c1c2c3c4c5c6c7"),
            &mut chacha_buffer,
            &mut chacha_tag,
        )
        .unwrap();
    assert_eq!(
        chacha_buffer,
        bytes(concat!(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca967128",
            "2fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fa",
            "b324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        ))
    );
    assert_eq!(chacha_tag, bytes("1ae10b594f09e26a7e902ecbd0600691"));
    assert!(matches!(
        crypto.new_aead(AeadAlgorithm::Aes128Gcm, &[0; 15]),
        Err(CryptoError::InvalidKeyLength { .. })
    ));
    assert!(matches!(
        gcm.seal_in_place(&[0; 11], &[], &mut [], &mut [0; 16]),
        Err(CryptoError::InvalidNonceLength { .. })
    ));
    assert!(matches!(
        gcm.seal_in_place(&[0; 12], &[], &mut [], &mut [0; 15]),
        Err(CryptoError::InvalidTagLength { .. })
    ));

    let cases = [
        (AeadAlgorithm::Aes256Gcm, 32),
        (AeadAlgorithm::Aes128Ccm, 16),
        (AeadAlgorithm::Aes128Ccm8, 16),
        (AeadAlgorithm::ChaCha20Poly1305, 32),
    ];
    for (algorithm, key_len) in cases {
        let mut cipher = crypto.new_aead(algorithm, &vec![7; key_len]).unwrap();
        let plaintext = b"provider conformance".to_vec();
        let mut encrypted = plaintext.clone();
        let mut tag = vec![0; cipher.tag_len()];
        cipher
            .seal_in_place(&[3; 12], b"aad", &mut encrypted, &mut tag)
            .unwrap();
        assert_ne!(encrypted, plaintext);
        cipher
            .open_in_place(&[3; 12], b"aad", &mut encrypted, &tag)
            .unwrap();
        assert_eq!(encrypted, plaintext);

        let mut ciphertext = plaintext.clone();
        let mut valid_tag = vec![0; cipher.tag_len()];
        cipher
            .seal_in_place(&[3; 12], b"aad", &mut ciphertext, &mut valid_tag)
            .unwrap();

        let mut tampered = ciphertext.clone();
        tag[0] ^= 1;
        assert_eq!(
            cipher.open_in_place(&[3; 12], b"aad", &mut tampered, &tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut wrong_aad = ciphertext.clone();
        assert_eq!(
            cipher.open_in_place(&[3; 12], b"bad", &mut wrong_aad, &valid_tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut changed_ciphertext = ciphertext.clone();
        changed_ciphertext[0] ^= 1;
        assert_eq!(
            cipher.open_in_place(&[3; 12], b"aad", &mut changed_ciphertext, &valid_tag),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut wrong_key_cipher = crypto.new_aead(algorithm, &vec![8; key_len]).unwrap();
        assert_eq!(
            wrong_key_cipher.open_in_place(&[3; 12], b"aad", &mut ciphertext, &valid_tag),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}

/// Checks every supported one-shot key exchange and malformed peer keys.
pub fn assert_key_exchange(crypto: &dyn RTCCrypto) {
    for algorithm in [
        KeyExchangeAlgorithm::P256,
        KeyExchangeAlgorithm::P384,
        KeyExchangeAlgorithm::X25519,
    ] {
        let left = crypto.start_key_exchange(algorithm).unwrap();
        let right = crypto.start_key_exchange(algorithm).unwrap();
        assert_eq!(left.algorithm(), algorithm);
        let left_public = left.public_key().to_vec();
        let right_public = right.public_key().to_vec();
        let left_secret = left.complete(&right_public).unwrap();
        let right_secret = right.complete(&left_public).unwrap();
        assert_eq!(left_secret.as_ref(), right_secret.as_ref());
        assert!(!left_secret.is_empty());

        let invalid = crypto.start_key_exchange(algorithm).unwrap();
        assert!(matches!(
            invalid.complete(&[0; 1]),
            Err(CryptoError::InvalidPublicKey)
        ));
    }
}

/// Checks signing, verification, key import/export, and invalid signatures and encodings.
pub fn assert_signatures(crypto: &dyn RTCCrypto) {
    for scheme in [SignatureScheme::Ed25519, SignatureScheme::EcdsaP256Sha256] {
        let key = crypto.generate_signing_key(scheme).unwrap();
        let message = b"rtc-crypto provider conformance";
        let signature = key.sign(scheme, message).unwrap();
        crypto
            .verify_signature(scheme, key.public_key(), message, &signature)
            .unwrap();
        assert_eq!(
            crypto.verify_signature(scheme, key.public_key(), b"changed", &signature),
            Err(CryptoError::InvalidSignature)
        );

        let exported = key.to_pkcs8_der().unwrap().unwrap();
        let imported = crypto
            .import_signing_key(scheme, exported.as_ref())
            .unwrap();
        let imported_signature = imported.sign(scheme, message).unwrap();
        crypto
            .verify_signature(scheme, imported.public_key(), message, &imported_signature)
            .unwrap();
        assert!(matches!(
            imported.sign(SignatureScheme::RsaPkcs1Sha256, message),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }

    assert_eq!(
        crypto.verify_signature(
            SignatureScheme::Ed25519,
            PublicKey {
                encoding: PublicKeyEncoding::SubjectPublicKeyInfoDer,
                bytes: &[0; 32],
            },
            b"message",
            &[0; 64],
        ),
        Err(CryptoError::InvalidPublicKey)
    );

    assert_verification_only_schemes(crypto);
}

fn assert_verification_only_schemes(crypto: &dyn RTCCrypto) {
    let message = b"rtc-crypto verification vector";
    let p384_public_key = bytes(concat!(
        "04c298b589fdd33f544610d13c277e0c703b2e3a72c0dfa2a81725e761614bd8c4",
        "cb80ecf40bba853f37aec2f4e13c7b5d05e7be9231d651bd1dc2848050bcd19858",
        "e448d27bf2418b350626a1f241c4914795c404aa35afab97e15e202296244a"
    ));
    let p384_signature = bytes(concat!(
        "306502302c6f36a6a01282982213b037f73ec8f935e1fcf4dc63035824c2bcb6",
        "aaa378f716d15f63df23e85d60f7d5e46c028ad1023100877055a3a8849e179",
        "ad94da98dc5125f1e78852cf9017795087b90751b99985b989786d2a537f84b08cdf7243820c313"
    ));
    crypto
        .verify_signature(
            SignatureScheme::EcdsaP384Sha384,
            PublicKey {
                encoding: PublicKeyEncoding::EcUncompressedPoint,
                bytes: &p384_public_key,
            },
            message,
            &p384_signature,
        )
        .unwrap();

    let rsa_public_key = bytes(
        "3082010a0282010100b0f8c4868ce9bcd4d11632162c0376bb09dce2facadaa27a6d4ad01b217c0a29e036b1bfd0052254ec3d349383019d8fd2d5c895ac6790bcc6c4dfca7c26bbcf570ee3bdff70826f80e8254776d8e73b431e2bece3d7d515edd23ada88e2c7136ac796685df8a40ed38ce59eaefc2509e1b277a0363938eb8e998a3f9fd6f2ed011b969e48d89d76508904961f8d83756466eff0f1fd5e4621e8ff083fd0d6aa87b31e560c185a1862059ba0fa95f8125ac96bfc7e051c3996587dc1271bb3ebf49303314ee888ccc8441de13a59b0646d9375dfbcbd66c1435398e164bc4672fd63a2eef162a7c1ac7ddb3e9cdb68cfeacff01f036a557477b45172593727f50203010001",
    );
    let rsa_vectors = [
        (
            SignatureScheme::RsaPkcs1Sha1,
            "967636ce08cc1923f2b6fa792d2a7cd6521f4a793adb4a0f94cfc6543e483d5383a6b36dbcef3a5cfd5cc12c333ebc6a22f2d452cac61a352111247e26f5e13595f0b78a9e94be1ff7eb4ab60ef48fff3a0e8c1a70ea041f63413c7dc4a5219d2ddb8349058ce1b7d2c02eb98f285d589f858a18f6473a1d3af47de653d520ceba6825e1a1bd5a0065ef0e4d9ac5929bc1cc3ffab014081224db7e7787c67f1580913fb98a870c1355c86a33770d17f654f24dccd781f3bf8a7de29e00198a99dd2bf1a1298630da433982ae63cbf71c265abebdd003c1c2ee870f7f8ea96c465dedb158a1e2e5048763d308a69eefc91424ad0795e8320fa0e753673f657a45",
        ),
        (
            SignatureScheme::RsaPkcs1Sha256,
            "19b21fd70c4dacec4c3cc6f6aac961e4ea0fb9b5d0ee3862cc35b60849388f2f461ab4697c59c25abb251f88b1de312ced6861ed90152c911356dff768cc4eafdadaa2f8d6b5d70c630d2739f1178fe5cbaff62cee343a20bb38404d35c58d247befa486dd5a3c69affdad5bdecaab876799dd297bd9cc4700e099b92d18d8ad78b64f570e4a398b0b8e9baf9a1b01aaa873b23b7c381917f3383482b7780e0e11e734409fc18daacb0428082789f791af2c4a79d5c75cde45c201e46ae347ab7624e0137940945e174dfab59888892c25b8e10abee1a72f2f31fb3f0e8840db490ba752e1df966979f267756767c88ea0d7909145f379811412f68465e08fd2",
        ),
        (
            SignatureScheme::RsaPkcs1Sha384,
            "0095d1ef58850cbf09dd1219a8678d7fa3f8c490a4a35feb19f50d85991caf659131dc90c52f14466c429a099a53e1d5f321a49065e85f250b85e08158ee46328515acee03bd215d610ec2335e1cbd1525058b950fb8ecb5d073f9fc474613c830c1111868efc3554c2ec62d9efd4694db281a6b3e48ed68d934278f5ba9a6fb19e8d648baa6b5f48d126def83986166ed05d710d5cdccd457092649b08d5e54c5ccfe42786852c98113b78291e3e2ced51ff3ed51ddef8cb81d311a2983cc6c93f0bb583537c067c6afc63e8e4a9d15635882b14d189a217d9588a469ac1899e3adeafdd276150b1023d7b64fea94b50a9ba22cc47c0d8d6ca4faf6b23f76d0",
        ),
        (
            SignatureScheme::RsaPkcs1Sha512,
            "7373b3eaf66ba56bda1ae85a466c2f0321d15c37ce293642f6b69fddbea0e6f4dfa76dd0ba274afaabf71ba9d85198c0e75af95af6c64cb9bb304ea1ea3c04e653649891af78145b823d3ed1179fdbdc4edbedcf1eb3201b44a9a40930bf005da1bbe138dfac2d272364a991fcadcfba9093e889fa03f153771fdd51525ffae16cb2155eac8f6da49b602ae8fb34a5a131693459cacbc5adbc9b6002473732a7e205c2150bd25afe850c29845054e17d56a028d81f293b1dc634ba11a6790aa478f0f36bcc64787e356384ae90ef83c5226183afca64c9ac28c83ca803e01ff801f1ee12c806005d9f5d3562afae08e358722ca606d46d500d43901256625fc4",
        ),
    ];
    for (scheme, signature) in rsa_vectors {
        crypto
            .verify_signature(
                scheme,
                PublicKey {
                    encoding: PublicKeyEncoding::RsaPkcs1Der,
                    bytes: &rsa_public_key,
                },
                message,
                &bytes(signature),
            )
            .unwrap();
    }
}

/// Checks that a provider's secure random source returns fresh output.
pub fn assert_random(provider: &dyn RTCCryptoProvider) {
    let mut first = [0; 32];
    let mut second = [0; 32];
    provider.random().fill(&mut first).unwrap();
    provider.random().fill(&mut second).unwrap();
    assert_ne!(first, second);
}

/// Checks the default unsupported-operation behavior required for partial providers.
pub fn assert_unsupported_hash(crypto: &dyn RTCCrypto) {
    assert!(!crypto.supports(CryptoAlgorithm::Hash(HashAlgorithm::Sha256)));
    assert_eq!(
        crypto.hash(HashAlgorithm::Sha256, b"input"),
        Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hash(
            HashAlgorithm::Sha256
        )))
    );
}

/// Checks the provider-neutral failure returned by a deliberately failing random source.
pub fn assert_random_failure(random: &dyn crate::RTCRandom) {
    assert_eq!(random.fill(&mut [0; 1]), Err(CryptoError::RandomnessFailed));
}

fn bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid hexadecimal test vector"),
    }
}
