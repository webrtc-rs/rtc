use super::*;
use crate::cipher_suite::cipher_suite_aes_256_ccm::CipherSuiteAes256Ccm;
use crate::crypto::crypto_ccm::CryptoCcmTagLen;

/// Builds a `TLS_PSK_WITH_AES_256_CCM_8` cipher suite.
pub fn new_cipher_suite_tls_psk_with_aes_256_ccm8() -> CipherSuiteAes256Ccm {
    CipherSuiteAes256Ccm::new(
        ClientCertificateType::Unsupported,
        CipherSuiteId::Tls_Psk_With_Aes_256_Ccm_8,
        true,
        CryptoCcmTagLen::CryptoCcm8TagLength,
    )
}
