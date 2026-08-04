use super::*;
use shared::error::Result;

struct IncompleteProvider;

impl crypto::RTCCryptoProvider for IncompleteProvider {
    fn name(&self) -> &'static str {
        "incomplete"
    }

    fn crypto(&self) -> &dyn crypto::RTCCrypto {
        self
    }

    fn random(&self) -> &dyn crypto::RTCRandom {
        self
    }
}

impl crypto::RTCCrypto for IncompleteProvider {
    fn supports(&self, _algorithm: crypto::CryptoAlgorithm) -> bool {
        false
    }
}

impl crypto::RTCRandom for IncompleteProvider {
    fn fill(&self, _output: &mut [u8]) -> std::result::Result<(), crypto::CryptoError> {
        Err(crypto::CryptoError::RandomnessFailed)
    }
}

#[derive(Debug)]
struct MockSigner;

impl crypto::SigningKey for MockSigner {
    fn supports(&self, _scheme: crypto::SignatureScheme) -> bool {
        true
    }

    fn public_key(&self) -> crypto::PublicKey<'_> {
        crypto::PublicKey {
            encoding: crypto::PublicKeyEncoding::SubjectPublicKeyInfoDer,
            bytes: &[],
        }
    }

    fn sign(
        &self,
        _scheme: crypto::SignatureScheme,
        _message: &[u8],
    ) -> std::result::Result<Vec<u8>, crypto::CryptoError> {
        Ok(vec![])
    }
}

#[test]
fn test_config_accepts_external_signing_key() -> Result<()> {
    let cert = Certificate {
        certificate: vec![],
        private_key: CryptoPrivateKey::from_signing_key(std::sync::Arc::new(MockSigner)),
    };

    let handshake = ConfigBuilder::default()
        .with_crypto_provider(crypto::default_provider().map_err(crypto_error)?)
        .with_certificates(vec![cert])
        .build(false, None)?;

    assert!(
        handshake.local_certificates[0]
            .private_key
            .signing_key
            .supports(crypto::SignatureScheme::EcdsaP256Sha256)
    );

    Ok(())
}

#[test]
fn test_config_rejects_incomplete_provider() {
    let result = ConfigBuilder::default()
        .with_crypto_provider(Arc::new(IncompleteProvider))
        .build(true, None);

    assert!(matches!(result, Err(Error::ErrNoAvailableCipherSuites)));
}

#[cfg(feature = "ring")]
#[test]
fn test_config_accepts_ring_provider() -> Result<()> {
    let handshake = ConfigBuilder::default()
        .with_crypto_provider(Arc::new(crypto::providers::RingProvider::new()))
        .build(true, None)?;

    assert_eq!(handshake.provider().name(), "ring");
    Ok(())
}

#[cfg(feature = "aws-lc-rs")]
#[test]
fn test_config_accepts_aws_lc_rs_provider() -> Result<()> {
    let handshake = ConfigBuilder::default()
        .with_crypto_provider(Arc::new(crypto::providers::AwsLcRsProvider::new()))
        .build(true, None)?;

    assert_eq!(handshake.provider().name(), "aws-lc-rs");
    Ok(())
}
