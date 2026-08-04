use super::*;
use crate::attributes::ATTR_SOFTWARE;
use crate::fingerprint::FINGERPRINT;
use crate::message::TransactionId;
use crate::textattrs::TextAttribute;
use crypto::{
    CryptoAlgorithm, CryptoError, HashAlgorithm, HmacAlgorithm, RTCCrypto, RTCCryptoProvider,
    RTCRandom, constant_time_eq,
};
use std::sync::Arc;

struct TestProvider {
    crypto: TestCrypto,
    random: TestRandom,
}

struct TestCrypto;

struct TestRandom;

impl RTCCryptoProvider for TestProvider {
    fn name(&self) -> &'static str {
        "test"
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        &self.crypto
    }

    fn random(&self) -> &dyn RTCRandom {
        &self.random
    }
}

impl RTCRandom for TestRandom {
    fn fill(&self, output: &mut [u8]) -> std::result::Result<(), CryptoError> {
        output.fill(0x42);
        Ok(())
    }
}

impl RTCCrypto for TestCrypto {
    fn supports(&self, algorithm: CryptoAlgorithm) -> bool {
        matches!(
            algorithm,
            CryptoAlgorithm::Hash(HashAlgorithm::Md5) | CryptoAlgorithm::Hmac(HmacAlgorithm::Sha1)
        )
    }

    fn hash(
        &self,
        algorithm: HashAlgorithm,
        data: &[u8],
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        if algorithm != HashAlgorithm::Md5 {
            return Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hash(
                algorithm,
            )));
        }
        let mut output = vec![0_u8; 16];
        let output_len = output.len();
        for (index, byte) in data.iter().enumerate() {
            output[index % output_len] ^= byte;
        }
        Ok(output)
    }

    fn new_hmac(
        &self,
        algorithm: HmacAlgorithm,
        key: &[u8],
    ) -> std::result::Result<Box<dyn crypto::Mac>, CryptoError> {
        if algorithm != HmacAlgorithm::Sha1 {
            return Err(CryptoError::UnsupportedAlgorithm(CryptoAlgorithm::Hmac(
                algorithm,
            )));
        }
        Ok(Box::new(TestMac {
            key: key.to_vec(),
            output_len: algorithm.output_len(),
        }))
    }
}

/// A deliberately fake MAC: an XOR fold, not HMAC-SHA1. It exists to prove the custom-provider
/// path is honoured, so tests asserting RFC 5389 vectors must use `builtin_provider()` instead.
struct TestMac {
    key: Vec<u8>,
    output_len: usize,
}

impl crypto::Mac for TestMac {
    fn output_len(&self) -> usize {
        self.output_len
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> std::result::Result<(), CryptoError> {
        if output.len() != self.output_len {
            return Err(CryptoError::InvalidTagLength {
                expected: self.output_len,
                actual: output.len(),
            });
        }
        output.fill(0);
        for (index, byte) in self
            .key
            .iter()
            .chain(input.iter().flat_map(|part| part.iter()))
            .enumerate()
        {
            output[index % self.output_len] ^= byte;
        }
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> std::result::Result<(), CryptoError> {
        if expected.len() != self.output_len {
            return Err(CryptoError::InvalidTagLength {
                expected: self.output_len,
                actual: expected.len(),
            });
        }
        let mut actual = vec![0_u8; self.output_len];
        self.sign(input, &mut actual)?;
        if constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

fn test_provider() -> Arc<dyn RTCCryptoProvider> {
    Arc::new(TestProvider {
        crypto: TestCrypto,
        random: TestRandom,
    })
}

/// A real built-in provider. Tests asserting RFC 5389 key/tag vectors need genuine MD5 and
/// HMAC-SHA1, not the `TestProvider` stand-in above.
fn builtin_provider() -> Arc<dyn RTCCryptoProvider> {
    crypto::default_provider().expect("a built-in crypto provider must be enabled for tests")
}

#[test]
fn explicit_custom_provider_round_trip_and_truncated_tag_rejection() -> Result<()> {
    let integrity = MessageIntegrity::new_long_term_integrity_with_provider(
        "user".to_owned(),
        "realm".to_owned(),
        "password".to_owned(),
        test_provider(),
    )?;
    let mut message = Message::new();
    message.write_header();
    integrity.add_to(&mut message)?;
    integrity.check(&mut message)?;

    let attribute = message
        .attributes
        .0
        .iter_mut()
        .find(|attribute| attribute.typ == ATTR_MESSAGE_INTEGRITY)
        .expect("MESSAGE-INTEGRITY attribute");
    attribute.value.pop();
    attribute.length -= 1;
    assert_eq!(
        integrity.check(&mut message),
        Err(Error::ErrIntegrityMismatch)
    );

    Ok(())
}

#[test]
fn test_message_integrity_add_to_simple() -> Result<()> {
    {
        let i = MessageIntegrity::new_long_term_integrity_with_provider(
            "user".to_owned(),
            "realm".to_owned(),
            "passsss".to_owned(),
            builtin_provider(),
        )?;
        let expected = vec![
            104, 228, 91, 113, 61, 154, 222, 34, 101, 61, 181, 146, 177, 90, 4, 29,
        ];
        assert_eq!(i.key.as_ref(), expected, "{}", Error::ErrIntegrityMismatch);
    }

    let i = MessageIntegrity::new_long_term_integrity_with_provider(
        "user".to_owned(),
        "realm".to_owned(),
        "pass".to_owned(),
        builtin_provider(),
    )?;
    let expected = vec![
        0x84, 0x93, 0xfb, 0xc5, 0x3b, 0xa5, 0x82, 0xfb, 0x4c, 0x04, 0x4c, 0x45, 0x6b, 0xdc, 0x40,
        0xeb,
    ];
    assert_eq!(i.key.as_ref(), expected, "{}", Error::ErrIntegrityMismatch);

    //"Check"
    {
        let mut m = Message::new();
        m.write_header();
        i.add_to(&mut m)?;
        let a = TextAttribute {
            attr: ATTR_SOFTWARE,
            text: "software".to_owned(),
        };
        a.add_to(&mut m)?;
        m.write_header();

        let mut d_m = Message::new();
        d_m.raw = m.raw.clone();
        d_m.decode()?;
        i.check(&mut d_m)?;

        d_m.raw[24] += 12; // HMAC now invalid
        d_m.decode()?;
        let result = i.check(&mut d_m);
        assert!(result.is_err(), "should be invalid");
    }

    Ok(())
}

#[test]
fn test_message_integrity_with_fingerprint() -> Result<()> {
    let mut m = Message::new();
    m.transaction_id = TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0]);
    m.write_header();
    let a = TextAttribute {
        attr: ATTR_SOFTWARE,
        text: "software".to_owned(),
    };
    a.add_to(&mut m)?;

    let i = MessageIntegrity::new_short_term_integrity_with_provider(
        "pwd".to_owned(),
        builtin_provider(),
    );
    assert_eq!(
        i.to_string(),
        "MESSAGE-INTEGRITY key: [REDACTED; 3 bytes]",
        "bad string {i}"
    );
    let result = i.check(&mut m);
    assert!(result.is_err(), "should error");

    i.add_to(&mut m)?;
    FINGERPRINT.add_to(&mut m)?;
    i.check(&mut m)?;
    m.raw[24] = 33;
    m.decode()?;
    let result = i.check(&mut m);
    assert!(result.is_err(), "mismatch expected");

    Ok(())
}

#[test]
fn test_message_integrity() -> Result<()> {
    let mut m = Message::new();
    let i = MessageIntegrity::new_short_term_integrity_with_provider(
        "password".to_owned(),
        builtin_provider(),
    );
    m.write_header();
    i.add_to(&mut m)?;
    m.get(ATTR_MESSAGE_INTEGRITY)?;
    Ok(())
}

#[test]
fn test_message_integrity_before_fingerprint() -> Result<()> {
    let mut m = Message::new();
    m.write_header();
    FINGERPRINT.add_to(&mut m)?;
    let i = MessageIntegrity::new_short_term_integrity_with_provider(
        "password".to_owned(),
        builtin_provider(),
    );
    let result = i.add_to(&mut m);
    assert!(result.is_err(), "should error");

    Ok(())
}
