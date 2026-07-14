use super::*;
use shared::error::Result;

#[derive(Debug)]
struct MockSigner;

impl CustomSigner for MockSigner {
    fn sign(&self, _message: &[u8]) -> std::result::Result<Vec<u8>, String> {
        Ok(vec![])
    }

    fn clone_box(&self) -> Box<dyn CustomSigner> {
        Box::new(MockSigner)
    }
}

#[test]
fn test_config_accepts_custom_signer() -> Result<()> {
    let cert = Certificate {
        certificate: vec![],
        private_key: CryptoPrivateKey {
            kind: CryptoPrivateKeyKind::Custom(Box::new(MockSigner)),
            serialized_der: vec![],
        },
    };

    let handshake = ConfigBuilder::default()
        .with_certificates(vec![cert])
        .build(false, None)?;

    assert!(matches!(
        handshake.local_certificates[0].private_key.kind,
        CryptoPrivateKeyKind::Custom(_)
    ));

    Ok(())
}
