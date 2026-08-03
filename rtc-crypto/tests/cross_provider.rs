#![cfg(all(feature = "ring", feature = "aws-lc-rs"))]

use rtc_crypto::providers::{AwsLcRsProvider, RingProvider};
use rtc_crypto::{
    AeadAlgorithm, CbcAlgorithm, KeyExchangeAlgorithm, RTCCrypto, RTCCryptoProvider,
    SignatureScheme, StreamCipherAlgorithm,
};

fn providers() -> (RingProvider, AwsLcRsProvider) {
    (RingProvider::new(), AwsLcRsProvider::new())
}

#[test]
fn symmetric_ciphertext_is_interoperable() {
    let (ring, aws) = providers();
    cross_symmetric(ring.crypto(), aws.crypto());
    cross_symmetric(aws.crypto(), ring.crypto());
}

fn cross_symmetric(sealer: &dyn RTCCrypto, opener: &dyn RTCCrypto) {
    for (algorithm, key_len) in [
        (AeadAlgorithm::Aes128Gcm, 16),
        (AeadAlgorithm::Aes256Gcm, 32),
        (AeadAlgorithm::Aes128Ccm, 16),
        (AeadAlgorithm::Aes128Ccm8, 16),
        (AeadAlgorithm::ChaCha20Poly1305, 32),
    ] {
        let key = vec![0x23; key_len];
        let plaintext = b"cross-provider authenticated encryption".to_vec();
        let mut buffer = plaintext.clone();
        let mut sealer = sealer.new_aead(algorithm, &key).unwrap();
        let mut tag = vec![0; sealer.tag_len()];
        sealer
            .seal_in_place(&[0x45; 12], b"rtc", &mut buffer, &mut tag)
            .unwrap();
        opener
            .new_aead(algorithm, &key)
            .unwrap()
            .open_in_place(&[0x45; 12], b"rtc", &mut buffer, &tag)
            .unwrap();
        assert_eq!(buffer, plaintext);
    }

    for (algorithm, key_len) in [
        (StreamCipherAlgorithm::Aes128Ctr, 16),
        (StreamCipherAlgorithm::Aes256Ctr, 32),
    ] {
        let key = vec![0x34; key_len];
        let plaintext = b"cross-provider stream cipher".to_vec();
        let mut buffer = plaintext.clone();
        sealer
            .new_stream_cipher(algorithm, &key)
            .unwrap()
            .apply_keystream(&[0x56; 16], &mut buffer)
            .unwrap();
        opener
            .new_stream_cipher(algorithm, &key)
            .unwrap()
            .apply_keystream(&[0x56; 16], &mut buffer)
            .unwrap();
        assert_eq!(buffer, plaintext);
    }

    let key = [0x67; 32];
    let iv = [0x78; 16];
    let plaintext = [0x89; 32];
    let mut blocks = plaintext;
    sealer
        .new_cbc(CbcAlgorithm::Aes256Cbc, &key)
        .unwrap()
        .encrypt_blocks(&iv, &mut blocks)
        .unwrap();
    opener
        .new_cbc(CbcAlgorithm::Aes256Cbc, &key)
        .unwrap()
        .decrypt_blocks(&iv, &mut blocks)
        .unwrap();
    assert_eq!(blocks, plaintext);
}

#[test]
fn key_exchange_is_interoperable() {
    let (ring, aws) = providers();
    for algorithm in [
        KeyExchangeAlgorithm::P256,
        KeyExchangeAlgorithm::P384,
        KeyExchangeAlgorithm::X25519,
    ] {
        let left = ring.crypto().start_key_exchange(algorithm).unwrap();
        let right = aws.crypto().start_key_exchange(algorithm).unwrap();
        let left_public = left.public_key().to_vec();
        let right_public = right.public_key().to_vec();
        let left_secret = left.complete(&right_public).unwrap();
        let right_secret = right.complete(&left_public).unwrap();
        assert_eq!(left_secret.as_ref(), right_secret.as_ref());
    }
}

#[test]
fn generated_and_imported_signatures_are_interoperable() {
    let (ring, aws) = providers();
    cross_signatures(ring.crypto(), aws.crypto());
    cross_signatures(aws.crypto(), ring.crypto());

    let rsa_der = pem::parse(include_str!("data/rsa-2048.pkcs8.pem"))
        .unwrap()
        .into_contents();
    let ring_key = ring
        .crypto()
        .import_signing_key(SignatureScheme::RsaPkcs1Sha256, &rsa_der)
        .unwrap();
    let aws_key = aws
        .crypto()
        .import_signing_key(SignatureScheme::RsaPkcs1Sha256, &rsa_der)
        .unwrap();
    let message = b"cross-provider RSA";
    let ring_signature = ring_key
        .sign(SignatureScheme::RsaPkcs1Sha256, message)
        .unwrap();
    aws.crypto()
        .verify_signature(
            SignatureScheme::RsaPkcs1Sha256,
            ring_key.public_key(),
            message,
            &ring_signature,
        )
        .unwrap();
    let aws_signature = aws_key
        .sign(SignatureScheme::RsaPkcs1Sha256, message)
        .unwrap();
    ring.crypto()
        .verify_signature(
            SignatureScheme::RsaPkcs1Sha256,
            aws_key.public_key(),
            message,
            &aws_signature,
        )
        .unwrap();
}

fn cross_signatures(generator: &dyn RTCCrypto, verifier: &dyn RTCCrypto) {
    for scheme in [SignatureScheme::Ed25519, SignatureScheme::EcdsaP256Sha256] {
        let generated = generator.generate_signing_key(scheme).unwrap();
        let message = b"cross-provider signature";
        let signature = generated.sign(scheme, message).unwrap();
        verifier
            .verify_signature(scheme, generated.public_key(), message, &signature)
            .unwrap();

        let exported = generated.to_pkcs8_der().unwrap().unwrap();
        let imported = verifier
            .import_signing_key(scheme, exported.as_ref())
            .unwrap();
        let signature = imported.sign(scheme, message).unwrap();
        generator
            .verify_signature(scheme, imported.public_key(), message, &signature)
            .unwrap();
    }
}

#[test]
fn ring_remains_the_default_when_both_backends_are_enabled() {
    assert_eq!(rtc_crypto::default_provider().unwrap().name(), "ring");

    let providers: Vec<Box<dyn RTCCryptoProvider>> = vec![
        Box::new(RingProvider::new()),
        Box::new(AwsLcRsProvider::new()),
    ];
    assert_eq!(providers[0].name(), "ring");
    assert_eq!(providers[1].name(), "aws-lc-rs");
}
