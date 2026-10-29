use super::*;

// Port of pion `pkg/crypto/elliptic` `TestString`.
#[test]
fn test_elliptic_string() {
    let tests = [
        (NamedCurve::X25519, "X25519"),
        (NamedCurve::P256, "P-256"),
        (NamedCurve::P384, "P-384"),
        // pion spells the raw value of an unknown curve in hex; `Curve(0)` becomes "0x0".
        (NamedCurve::Unsupported, "0x0"),
    ];

    for (curve, expected) in tests {
        assert_eq!(curve.to_string(), expected, "Curve({curve:?}).String()");
    }
}

// Port of pion `pkg/crypto/elliptic` `TestGenerateKeypair_InvalidCurve`: a curve this crate does
// not implement cannot produce a keypair. pion's `PreMasterSecret` surfaces the same
// `errInvalidNamedCurve` from `toECDH`; here the check runs when the keypair is generated, which
// is the only way this crate builds one.
#[test]
fn test_generate_keypair_invalid_curve() -> Result<()> {
    let provider = crypto::default_provider().map_err(|e| Error::Crypto(e.to_string()))?;

    let invalid = NamedCurve::from(0); // not a supported curve
    assert!(matches!(
        invalid.generate_keypair_with_crypto(provider.crypto()),
        Err(Error::ErrInvalidNamedCurve)
    ));

    Ok(())
}

// Port of pion `pkg/crypto/elliptic` `TestToECDH_InvalidCurve`: mapping an unknown curve to the
// underlying key-agreement algorithm fails with `errInvalidNamedCurve`. This crate's
// `crypto_algorithm` is the `toECDH` counterpart.
#[test]
fn test_to_ecdh_invalid_curve() {
    let invalid = NamedCurve::from(0xFFFF);
    assert!(matches!(
        invalid.crypto_algorithm(),
        Err(Error::ErrInvalidNamedCurve)
    ));
}

// A crypto provider whose key-agreement generation always fails, standing in for pion's
// `failingReader`: pion swaps `crypto/rand.Reader` for a reader that always errors, forcing
// `ecdh.GenerateKey` to fail. The built-in providers draw keypair randomness inside
// `start_key_exchange` — the provider's RNG trait is not consulted — so the failure is injected
// at that call instead, which is the same error path a failed RNG draw takes in a real provider.
struct FailingKeyExchangeCrypto;

impl crypto::RTCCrypto for FailingKeyExchangeCrypto {
    fn supports(&self, algorithm: crypto::CryptoAlgorithm) -> bool {
        matches!(algorithm, crypto::CryptoAlgorithm::KeyExchange(_))
    }

    fn start_key_exchange(
        &self,
        _algorithm: crypto::KeyExchangeAlgorithm,
    ) -> std::result::Result<Box<dyn crypto::ActiveKeyExchange>, crypto::CryptoError> {
        Err(crypto::CryptoError::RandomnessFailed)
    }
}

// Port of pion `pkg/crypto/elliptic` `TestGenerateKeypair_RandFailure`: a failure of the
// randomness behind keypair generation surfaces as an error from `GenerateKeypair` rather than a
// panic.
#[test]
fn test_generate_keypair_rand_failure() {
    let result = NamedCurve::P256.generate_keypair_with_crypto(&FailingKeyExchangeCrypto);
    assert!(
        matches!(result, Err(Error::Crypto(_))),
        "GenerateKeypair must surface the failed key generation"
    );
}
