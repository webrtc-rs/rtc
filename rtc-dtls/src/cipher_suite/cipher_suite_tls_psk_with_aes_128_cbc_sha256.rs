use super::*;
use crate::crypto::crypto_cbc::{CryptoCbc, CryptoCbcSuite};
use crate::prf::*;

/// The `TLS_PSK_WITH_AES_128_CBC_SHA256` implementation (RFC 5487): AES-128-CBC records with an
/// HMAC-SHA-256 MAC, for pre-shared-key handshakes.
///
/// Unlike the certificate-based AES-256-CBC suite, whose MAC is HMAC-SHA-1, this suite derives a
/// 32-byte MAC key per direction and uses SHA-256 both for the PRF and the record MAC.
#[derive(Default)]
pub struct CipherSuiteTlsPskWithAes128CbcSha256 {
    cbc: Option<CryptoCbc>,
}

impl CipherSuiteTlsPskWithAes128CbcSha256 {
    const PRF_MAC_LEN: usize = 32;
    const PRF_KEY_LEN: usize = 16;
    const PRF_IV_LEN: usize = 16;
}

impl CipherSuite for CipherSuiteTlsPskWithAes128CbcSha256 {
    fn to_string(&self) -> String {
        "TLS_PSK_WITH_AES_128_CBC_SHA256".to_owned()
    }

    fn id(&self) -> CipherSuiteId {
        CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256
    }

    fn certificate_type(&self) -> ClientCertificateType {
        ClientCertificateType::Unsupported
    }

    fn hash_func(&self) -> CipherSuiteHash {
        CipherSuiteHash::Sha256
    }

    fn is_psk(&self) -> bool {
        true
    }

    fn is_initialized(&self) -> bool {
        self.cbc.is_some()
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
                mac: CipherSuiteTlsPskWithAes128CbcSha256::PRF_MAC_LEN,
                key: CipherSuiteTlsPskWithAes128CbcSha256::PRF_KEY_LEN,
                iv: CipherSuiteTlsPskWithAes128CbcSha256::PRF_IV_LEN,
            },
            self.hash_func(),
        )?;

        if is_client {
            self.cbc = Some(CryptoCbc::new(
                provider,
                CryptoCbcSuite::Aes128CbcSha256,
                &keys.client_write_key,
                &keys.client_mac_key,
                &keys.server_write_key,
                &keys.server_mac_key,
            )?);
        } else {
            self.cbc = Some(CryptoCbc::new(
                provider,
                CryptoCbcSuite::Aes128CbcSha256,
                &keys.server_write_key,
                &keys.server_mac_key,
                &keys.client_write_key,
                &keys.client_mac_key,
            )?);
        }

        Ok(())
    }

    fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let cbc = self.cbc.as_mut().ok_or(Error::Other(
            "CipherSuite has not been initialized, unable to encrypt".to_owned(),
        ))?;
        cbc.encrypt(pkt_rlh, raw)
    }

    fn decrypt(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let cbc = self.cbc.as_mut().ok_or(Error::Other(
            "CipherSuite has not been initialized, unable to decrypt".to_owned(),
        ))?;
        cbc.decrypt(input)
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

    /// The client and server suites of `TLS_PSK_WITH_AES_128_CBC_SHA256`, keyed with the same
    /// material.
    fn suite_pair() -> (Box<dyn CipherSuite>, Box<dyn CipherSuite>) {
        let mut client =
            cipher_suite_for_id(CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256).unwrap();
        let mut server =
            cipher_suite_for_id(CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256).unwrap();
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
        let payload = b"aes-128-cbc-sha256 psk record";
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
    fn suite_metadata_is_tls_psk_with_aes_128_cbc_sha256() {
        let suite = CipherSuiteTlsPskWithAes128CbcSha256::default();
        assert_eq!(suite.id(), CipherSuiteId::Tls_Psk_With_Aes_128_Cbc_Sha256);
        assert_eq!(suite.to_string(), "TLS_PSK_WITH_AES_128_CBC_SHA256");
        assert!(suite.is_psk());
        assert_eq!(suite.certificate_type(), ClientCertificateType::Unsupported);
        assert!(!suite.is_initialized());
    }

    #[test]
    fn roundtrip_and_tampered_records_are_rejected() {
        let (mut client, mut server) = suite_pair();
        assert!(client.is_initialized() && server.is_initialized());

        let (header, raw) = record();
        let encrypted = client.encrypt(&header, &raw).unwrap();
        // header + IV + whole blocks covering payload + 32-byte MAC + padding
        assert_eq!(
            (encrypted.len() - RECORD_LAYER_HEADER_SIZE) % 16,
            0,
            "CBC body is a whole number of blocks"
        );

        let decrypted = server.decrypt(&encrypted).unwrap();
        assert_eq!(
            &decrypted[RECORD_LAYER_HEADER_SIZE..],
            &raw[RECORD_LAYER_HEADER_SIZE..]
        );

        // Tampering the record IV (first body byte) scrambles the first plaintext block and the
        // MAC check fails.
        let mut bad_iv = encrypted.clone();
        bad_iv[RECORD_LAYER_HEADER_SIZE] ^= 1;
        assert!(server.decrypt(&bad_iv).is_err());

        // Tampering the last ciphertext block (the padding) fails the padding/MAC check.
        let mut bad_tail = encrypted.clone();
        let last = bad_tail.len() - 1;
        bad_tail[last] ^= 1;
        assert!(server.decrypt(&bad_tail).is_err());
    }
}
