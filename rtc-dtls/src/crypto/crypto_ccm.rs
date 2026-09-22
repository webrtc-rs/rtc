// AES-CCM (Counter with CBC-MAC)
// Alternative to GCM mode.
// Available in OpenSSL as of TLS 1.3 (2018), but disabled by default.
// Two AES computations per block, thus expected to be somewhat slower than AES-GCM.
// RFC 6655 year 2012 https://tools.ietf.org/html/rfc6655
// Much lower adoption, probably because it came after GCM and offer no significant benefit.

// https://github.com/RustCrypto/AEADs
// https://docs.rs/ccm/0.3.0/ccm/ Or https://crates.io/crates/aes-ccm?

use std::sync::Arc;

use bytes::BytesMut;

use crypto::{AeadAlgorithm, AeadCipher, RTCCryptoProvider};

use super::*;
use crate::content::*;
use crate::record_layer::record_layer_header::*;
use shared::error::*;

const CRYPTO_CCM_NONCE_LENGTH: usize = 12;
const CRYPTO_CCM_EXPLICIT_NONCE_LENGTH: usize = 8;
const CRYPTO_CCM_MAX_TAG_LENGTH: usize = 16;
/// Most bytes AES-CCM adds to a record: the explicit nonce and a full-length tag.
pub const CRYPTO_CCM_OVERHEAD: usize = CRYPTO_CCM_EXPLICIT_NONCE_LENGTH + CRYPTO_CCM_MAX_TAG_LENGTH;

#[derive(Clone)]
/// The authentication tag length a CCM suite uses.
pub enum CryptoCcmTagLen {
    /// An 8-byte tag, as the `_CCM_8` suites use.
    CryptoCcm8TagLength,
    /// The full 16-byte tag.
    CryptoCcmTagLength,
}

/// AES-CCM authenticated encryption for DTLS records, holding the per-direction keys.
pub struct CryptoCcm {
    provider: Arc<dyn RTCCryptoProvider>,
    local_ccm: Box<dyn AeadCipher>,
    remote_ccm: Box<dyn AeadCipher>,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
}

impl CryptoCcm {
    /// Builds the cipher from the local and remote keys and salts.
    pub fn new(
        provider: Arc<dyn RTCCryptoProvider>,
        tag_len: &CryptoCcmTagLen,
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Result<Self> {
        let algorithm = match tag_len {
            CryptoCcmTagLen::CryptoCcmTagLength => AeadAlgorithm::Aes128Ccm,
            CryptoCcmTagLen::CryptoCcm8TagLength => AeadAlgorithm::Aes128Ccm8,
        };
        let local_ccm = provider
            .crypto()
            .new_aead(algorithm, local_key)
            .map_err(crypto_error)?;
        let remote_ccm = provider
            .crypto()
            .new_aead(algorithm, remote_key)
            .map_err(crypto_error)?;
        Ok(CryptoCcm {
            provider,
            local_ccm,
            local_write_iv: local_write_iv.to_vec(),
            remote_ccm,
            remote_write_iv: remote_write_iv.to_vec(),
        })
    }

    /// Protects one record, returning header plus ciphertext.
    ///
    /// # Errors
    ///
    /// Fails if the cipher rejects the input.
    pub fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let mut r = Vec::with_capacity(raw.len() + CRYPTO_CCM_OVERHEAD);
        r.extend_from_slice(&raw[..RECORD_LAYER_HEADER_SIZE]);
        r.extend_from_slice(&[0; CRYPTO_CCM_EXPLICIT_NONCE_LENGTH]);
        r.extend_from_slice(&raw[RECORD_LAYER_HEADER_SIZE..]);
        self.seal(pkt_rlh, &mut r)?;
        Ok(r)
    }

    /// Protects the record in `raw` (header followed by plaintext) in place, leaving header plus
    /// ciphertext. Reserve [`CRYPTO_CCM_OVERHEAD`] spare bytes to avoid a reallocation.
    ///
    /// # Errors
    ///
    /// Fails if the cipher rejects the input.
    pub fn encrypt_in_place(
        &mut self,
        pkt_rlh: &RecordLayerHeader,
        raw: &mut BytesMut,
    ) -> Result<()> {
        // Open the gap for the explicit nonce between header and payload.
        let len = raw.len();
        raw.reserve(CRYPTO_CCM_EXPLICIT_NONCE_LENGTH + self.local_ccm.tag_len());
        raw.resize(len + CRYPTO_CCM_EXPLICIT_NONCE_LENGTH, 0);
        raw.copy_within(
            RECORD_LAYER_HEADER_SIZE..len,
            RECORD_LAYER_HEADER_SIZE + CRYPTO_CCM_EXPLICIT_NONCE_LENGTH,
        );
        self.seal(pkt_rlh, raw)
    }

    // Seals `r`, laid out as header, explicit-nonce gap and payload, then appends the tag and
    // patches the header's length.
    fn seal(&mut self, pkt_rlh: &RecordLayerHeader, r: &mut impl RecordBuf) -> Result<()> {
        let payload_start = RECORD_LAYER_HEADER_SIZE + CRYPTO_CCM_EXPLICIT_NONCE_LENGTH;
        let payload_len = r.len() - payload_start;

        let mut nonce = [0u8; CRYPTO_CCM_NONCE_LENGTH];
        nonce[..4].copy_from_slice(&self.local_write_iv[..4]);
        self.provider
            .random()
            .fill(&mut nonce[4..])
            .map_err(crypto_error)?;
        r[RECORD_LAYER_HEADER_SIZE..payload_start].copy_from_slice(&nonce[4..]);

        let additional_data = generate_aead_additional_data(pkt_rlh, payload_len);

        let mut tag = [0; CRYPTO_CCM_MAX_TAG_LENGTH];
        let tag = &mut tag[..self.local_ccm.tag_len()];
        self.local_ccm
            .seal_in_place(&nonce, &additional_data, &mut r[payload_start..], tag)
            .map_err(crypto_error)?;
        r.extend(&*tag);

        // Update recordLayer size to include explicit nonce
        let r_len = (r.len() - RECORD_LAYER_HEADER_SIZE) as u16;
        r[RECORD_LAYER_HEADER_SIZE - 2..RECORD_LAYER_HEADER_SIZE]
            .copy_from_slice(&r_len.to_be_bytes());

        Ok(())
    }

    /// Unprotects one record.
    ///
    /// # Errors
    ///
    /// Fails if authentication fails or the record is too short.
    pub fn decrypt(&mut self, r: &[u8]) -> Result<Vec<u8>> {
        let Some((h, nonce, ciphertext_len)) = self.open_params(r)? else {
            return Ok(r.to_vec());
        };
        let additional_data = generate_aead_additional_data(&h, ciphertext_len);

        let ciphertext_start = RECORD_LAYER_HEADER_SIZE + CRYPTO_CCM_EXPLICIT_NONCE_LENGTH;
        let (ciphertext, tag) = r[ciphertext_start..].split_at(ciphertext_len);
        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + ciphertext_len);
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(ciphertext);
        self.remote_ccm
            .open_in_place(
                &nonce,
                &additional_data,
                &mut d[RECORD_LAYER_HEADER_SIZE..],
                tag,
            )
            .map_err(authentication_error)?;

        Ok(d)
    }

    /// Unprotects the record in `r` in place, leaving the header followed by the plaintext, as
    /// [`Self::decrypt`] returns it.
    ///
    /// # Errors
    ///
    /// Fails if authentication fails or the record is too short; `r` is then unspecified.
    pub fn decrypt_in_place(&mut self, r: &mut BytesMut) -> Result<()> {
        let Some((h, nonce, ciphertext_len)) = self.open_params(r)? else {
            return Ok(());
        };
        let additional_data = generate_aead_additional_data(&h, ciphertext_len);

        let ciphertext_start = RECORD_LAYER_HEADER_SIZE + CRYPTO_CCM_EXPLICIT_NONCE_LENGTH;
        let (ciphertext, tag) = r[ciphertext_start..].split_at_mut(ciphertext_len);
        self.remote_ccm
            .open_in_place(&nonce, &additional_data, ciphertext, tag)
            .map_err(authentication_error)?;

        strip_decrypted_record(r, CRYPTO_CCM_EXPLICIT_NONCE_LENGTH, ciphertext_len);
        Ok(())
    }

    // Checks a received record's length and returns its header, nonce and ciphertext length,
    // or `None` for a ChangeCipherSpec record, which is not encrypted.
    fn open_params(
        &self,
        r: &[u8],
    ) -> Result<Option<(RecordLayerHeader, [u8; CRYPTO_CCM_NONCE_LENGTH], usize)>> {
        let h = RecordLayerHeader::unmarshal(&mut &r[..])?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(None);
        }

        let ciphertext_start = RECORD_LAYER_HEADER_SIZE + CRYPTO_CCM_EXPLICIT_NONCE_LENGTH;
        if r.len() <= ciphertext_start {
            return Err(Error::ErrNotEnoughRoomForNonce);
        }

        let mut nonce = [0; CRYPTO_CCM_NONCE_LENGTH];
        nonce[..4].copy_from_slice(&self.remote_write_iv[..4]);
        nonce[4..].copy_from_slice(&r[RECORD_LAYER_HEADER_SIZE..ciphertext_start]);

        let out_len = r.len() - ciphertext_start;
        let tag_len = self.remote_ccm.tag_len();
        if out_len < tag_len {
            return Err(Error::ErrInvalidMac);
        }

        Ok(Some((h, nonce, out_len - tag_len)))
    }
}
