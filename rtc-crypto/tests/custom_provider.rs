use rtc_crypto::{CryptoAlgorithm, CryptoError, RTCCrypto, RTCCryptoProvider, RTCRandom};

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
use rtc_crypto::default_provider;

struct CustomProvider {
    crypto: CustomCrypto,
    random: CustomRandom,
}

struct CustomCrypto;

impl RTCCrypto for CustomCrypto {
    fn supports(&self, _algorithm: CryptoAlgorithm) -> bool {
        false
    }
}

struct CustomRandom;

impl RTCRandom for CustomRandom {
    fn fill(&self, output: &mut [u8]) -> Result<(), CryptoError> {
        output.fill(0x5a);
        Ok(())
    }
}

#[cfg(feature = "test-support")]
struct FailingRandom;

#[cfg(feature = "test-support")]
impl RTCRandom for FailingRandom {
    fn fill(&self, _output: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::RandomnessFailed)
    }
}

impl RTCCryptoProvider for CustomProvider {
    fn name(&self) -> &'static str {
        "application-provider"
    }

    fn crypto(&self) -> &dyn RTCCrypto {
        &self.crypto
    }

    fn random(&self) -> &dyn RTCRandom {
        &self.random
    }
}

#[test]
fn downstream_provider_requires_no_registration_or_backend_types() {
    let provider: &dyn RTCCryptoProvider = &CustomProvider {
        crypto: CustomCrypto,
        random: CustomRandom,
    };
    assert_eq!(provider.name(), "application-provider");
    let mut output = [0; 4];
    provider.random().fill(&mut output).unwrap();
    assert_eq!(output, [0x5a; 4]);
    #[cfg(feature = "test-support")]
    {
        rtc_crypto::conformance::assert_unsupported_hash(provider.crypto());
        rtc_crypto::conformance::assert_random_failure(&FailingRandom);
    }
}

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
#[test]
fn no_builtin_provider_is_a_normal_error() {
    assert!(matches!(
        default_provider(),
        Err(CryptoError::NoDefaultProvider)
    ));
}
