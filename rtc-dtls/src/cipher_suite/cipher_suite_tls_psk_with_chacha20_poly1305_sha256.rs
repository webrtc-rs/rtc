use crate::cipher_suite::cipher_suite_chacha20_poly1305_sha256::CipherSuiteChaCha20Poly1305Sha256;

/// Builds a `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256` cipher suite.
pub fn new_cipher_suite_tls_psk_with_chacha20_poly1305_sha256() -> CipherSuiteChaCha20Poly1305Sha256
{
    CipherSuiteChaCha20Poly1305Sha256::new_psk()
}

#[cfg(test)]
mod tests {
    use super::new_cipher_suite_tls_psk_with_chacha20_poly1305_sha256;
    use crate::cipher_suite::{CipherSuite, CipherSuiteId, cipher_suite_for_id};
    use crate::client_certificate_type::ClientCertificateType;
    use crate::content::ContentType;
    use crate::record_layer::record_layer_header::{
        PROTOCOL_VERSION1_2, RECORD_LAYER_HEADER_SIZE, RecordLayerHeader,
    };

    const MASTER_SECRET: &[u8] = &[0x42; 48];
    const CLIENT_RANDOM: &[u8] = &[0x11; 32];
    const SERVER_RANDOM: &[u8] = &[0x22; 32];

    /// The client and server suites of `TLS_PSK_WITH_CHACHA20_POLY1305_SHA256`, keyed with the
    /// same material.
    fn suite_pair() -> (Box<dyn CipherSuite>, Box<dyn CipherSuite>) {
        let mut client =
            cipher_suite_for_id(CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256).unwrap();
        let mut server =
            cipher_suite_for_id(CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256).unwrap();
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
        let payload = b"chacha20-poly1305 psk record";
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
    fn suite_metadata_is_tls_psk_with_chacha20_poly1305_sha256() {
        let suite = new_cipher_suite_tls_psk_with_chacha20_poly1305_sha256();
        assert_eq!(
            suite.id(),
            CipherSuiteId::Tls_Psk_With_ChaCha20_Poly1305_Sha256
        );
        assert_eq!(suite.to_string(), "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256");
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
        // header + ciphertext + 16-byte tag, with no explicit nonce on the wire
        assert_eq!(encrypted.len(), raw.len() + 16);

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
}
