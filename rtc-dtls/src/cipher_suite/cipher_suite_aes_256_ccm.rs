use super::*;
use crate::client_certificate_type::ClientCertificateType;
use crate::crypto::crypto_ccm::{CryptoCcm, CryptoCcmTagLen};
use crate::prf::*;

/// The shared AES-256-CCM implementation, parameterized over the key exchange and signature.
///
/// As in pion, only the truncated 8-byte-tag variant is offered (`TLS_PSK_WITH_AES_256_CCM_8`,
/// RFC 6655), so the PRF key length is fixed at 32 bytes and the tag length stays configurable.
pub struct CipherSuiteAes256Ccm {
    ccm: Option<CryptoCcm>,
    client_certificate_type: ClientCertificateType,
    id: CipherSuiteId,
    psk: bool,
    crypto_ccm_tag_len: CryptoCcmTagLen,
}

impl CipherSuiteAes256Ccm {
    const PRF_MAC_LEN: usize = 0;
    const PRF_KEY_LEN: usize = 32;
    const PRF_IV_LEN: usize = 4;

    /// Builds an uninitialized AES-256-CCM suite; keys are installed later via `init`.
    pub fn new(
        client_certificate_type: ClientCertificateType,
        id: CipherSuiteId,
        psk: bool,
        crypto_ccm_tag_len: CryptoCcmTagLen,
    ) -> Self {
        CipherSuiteAes256Ccm {
            ccm: None,
            client_certificate_type,
            id,
            psk,
            crypto_ccm_tag_len,
        }
    }
}

impl CipherSuite for CipherSuiteAes256Ccm {
    fn to_string(&self) -> String {
        format!("{}", self.id)
    }

    fn id(&self) -> CipherSuiteId {
        self.id
    }

    fn certificate_type(&self) -> ClientCertificateType {
        self.client_certificate_type
    }

    fn hash_func(&self) -> CipherSuiteHash {
        CipherSuiteHash::Sha256
    }

    fn is_psk(&self) -> bool {
        self.psk
    }

    fn is_initialized(&self) -> bool {
        self.ccm.is_some()
    }

    fn init(
        &mut self,
        provider: Arc<dyn RTCCryptoProvider>,
        master_secret: &[u8],
        client_random: &[u8],
        server_random: &[u8],
        is_client: bool,
    ) -> Result<()> {
        let keys = prf_encryption_keys(
            provider.crypto(),
            master_secret,
            client_random,
            server_random,
            EncryptionKeyLengths {
                mac: CipherSuiteAes256Ccm::PRF_MAC_LEN,
                key: CipherSuiteAes256Ccm::PRF_KEY_LEN,
                iv: CipherSuiteAes256Ccm::PRF_IV_LEN,
            },
            self.hash_func(),
        )?;

        if is_client {
            self.ccm = Some(CryptoCcm::new(
                provider,
                &self.crypto_ccm_tag_len,
                &keys.client_write_key,
                &keys.client_write_iv,
                &keys.server_write_key,
                &keys.server_write_iv,
            )?);
        } else {
            self.ccm = Some(CryptoCcm::new(
                provider,
                &self.crypto_ccm_tag_len,
                &keys.server_write_key,
                &keys.server_write_iv,
                &keys.client_write_key,
                &keys.client_write_iv,
            )?);
        }

        Ok(())
    }

    fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let ccm = self.ccm.as_mut().ok_or(Error::Other(
            "CipherSuite has not been initialized, unable to encrypt".to_owned(),
        ))?;
        ccm.encrypt(pkt_rlh, raw)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let ccm = self.ccm.as_mut().ok_or(Error::Other(
            "CipherSuite has not been initialized, unable to decrypt".to_owned(),
        ))?;
        ccm.decrypt(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_certificate_type::ClientCertificateType;
    use crate::content::ContentType;
    use crate::record_layer::record_layer_header::{
        PROTOCOL_VERSION1_2, RECORD_LAYER_HEADER_SIZE, RecordLayerHeader,
    };

    const MASTER_SECRET: &[u8] = &[0x42; 48];
    const CLIENT_RANDOM: &[u8] = &[0x11; 32];
    const SERVER_RANDOM: &[u8] = &[0x22; 32];

    /// The client and server suites of `TLS_PSK_WITH_AES_256_CCM_8`, keyed with the same material.
    fn suite_pair() -> (Box<dyn CipherSuite>, Box<dyn CipherSuite>) {
        let mut client = cipher_suite_for_id(CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8).unwrap();
        let mut server = cipher_suite_for_id(CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8).unwrap();
        let provider = crypto::default_provider().unwrap();
        client
            .init(
                provider.clone(),
                MASTER_SECRET,
                CLIENT_RANDOM,
                SERVER_RANDOM,
                true,
            )
            .unwrap();
        server
            .init(provider, MASTER_SECRET, CLIENT_RANDOM, SERVER_RANDOM, false)
            .unwrap();
        (client, server)
    }

    fn record() -> (RecordLayerHeader, Vec<u8>) {
        let payload = b"aes-256-ccm-8 psk record";
        let header = RecordLayerHeader {
            content_type: ContentType::ApplicationData,
            protocol_version: PROTOCOL_VERSION1_2,
            epoch: 1,
            sequence_number: 7,
            content_len: payload.len() as u16,
        };
        let mut raw = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + payload.len());
        header.marshal(&mut raw).unwrap();
        raw.extend_from_slice(payload);
        (header, raw)
    }

    #[test]
    fn suite_metadata_is_tls_psk_with_aes_256_ccm_8() {
        let suite = new_cipher_suite_tls_psk_with_aes_256_ccm8();
        assert_eq!(suite.id(), CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8);
        assert_eq!(suite.to_string(), "TLS_PSK_WITH_AES_256_CCM_8");
        assert!(suite.is_psk());
        assert_eq!(suite.certificate_type(), ClientCertificateType::Unsupported);
        assert!(!suite.is_initialized());
    }

    #[test]
    fn roundtrip_and_tampered_record_is_rejected() {
        let (mut client, mut server) = suite_pair();
        assert!(client.is_initialized() && server.is_initialized());

        let (header, raw) = record();
        let encrypted = client.encrypt(&header, &raw).unwrap();
        // header + explicit nonce (8) + ciphertext + 8-byte tag
        assert_eq!(
            encrypted.len(),
            RECORD_LAYER_HEADER_SIZE + 8 + raw.len() - RECORD_LAYER_HEADER_SIZE + 8
        );

        let decrypted = server.decrypt(&encrypted).unwrap();
        assert_eq!(
            &decrypted[RECORD_LAYER_HEADER_SIZE..],
            &raw[RECORD_LAYER_HEADER_SIZE..]
        );

        let mut tampered = encrypted.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(server.decrypt(&tampered).is_err());
    }

    #[test]
    fn a_full_tag_aes_256_key_combination_is_refused() {
        let provider = crypto::default_provider().unwrap();
        let err = CryptoCcm::new(
            provider,
            &CryptoCcmTagLen::CryptoCcmTagLength,
            &[0x55; 32],
            &[0x66; 4],
            &[0x77; 32],
            &[0x88; 4],
        );
        assert!(err.is_err());
    }
}
