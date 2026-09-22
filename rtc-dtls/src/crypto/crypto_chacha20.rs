use std::sync::Arc;

use bytes::BytesMut;

use crypto::{AeadAlgorithm, AeadCipher, RTCCryptoProvider};

use super::*;
use crate::content::*;
use crate::record_layer::record_layer_header::*; // what about Aes256Gcm?

const CRYPTO_CHACHA20_TAG_LENGTH: usize = 16;
/// Bytes ChaCha20-Poly1305 adds to a record: the tag.
pub const CRYPTO_CHACHA20_OVERHEAD: usize = CRYPTO_CHACHA20_TAG_LENGTH;
const CRYPTO_CHACHA20_NONCE_LENGTH: usize = 12;

// State needed to handle encrypted input/output
/// ChaCha20-Poly1305 authenticated encryption for DTLS records, holding the per-direction keys.
pub struct CryptoChaCha20 {
    local_cc: Box<dyn AeadCipher>,
    remote_cc: Box<dyn AeadCipher>,
    local_write_iv: Vec<u8>,
    remote_write_iv: Vec<u8>,
}

fn noncegen(nonce: &mut [u8], epoch: u16, seqnum: u64) {
    let epoch: u64 = epoch.into();
    let seqnum = (seqnum & 0xFFFFFFFFFFFF) | (epoch << 48);
    for i in 0..8 {
        nonce[i + 4] ^= ((seqnum >> (8 * (7 - i))) & 0xFF) as u8;
    }
}

impl CryptoChaCha20 {
    /// Builds the cipher from the local and remote keys and salts.
    pub fn new(
        provider: Arc<dyn RTCCryptoProvider>,
        local_key: &[u8],
        local_write_iv: &[u8],
        remote_key: &[u8],
        remote_write_iv: &[u8],
    ) -> Result<Self> {
        let local_cc = provider
            .crypto()
            .new_aead(AeadAlgorithm::ChaCha20Poly1305, local_key)
            .map_err(crypto_error)?;
        let remote_cc = provider
            .crypto()
            .new_aead(AeadAlgorithm::ChaCha20Poly1305, remote_key)
            .map_err(crypto_error)?;
        Ok(CryptoChaCha20 {
            local_cc,
            local_write_iv: local_write_iv.to_vec(),
            remote_cc,
            remote_write_iv: remote_write_iv.to_vec(),
        })
    }

    /// Protects one record, returning header plus ciphertext.
    ///
    /// # Errors
    ///
    /// Fails if the cipher rejects the input.
    pub fn encrypt(&mut self, pkt_rlh: &RecordLayerHeader, raw: &[u8]) -> Result<Vec<u8>> {
        let mut r = Vec::with_capacity(raw.len() + CRYPTO_CHACHA20_TAG_LENGTH);
        r.extend_from_slice(raw);
        self.seal(pkt_rlh, &mut r)?;
        Ok(r)
    }

    /// Protects the record in `raw` (header followed by plaintext) in place, leaving header plus
    /// ciphertext. Reserve [`CRYPTO_CHACHA20_OVERHEAD`] spare bytes to avoid a reallocation.
    ///
    /// # Errors
    ///
    /// Fails if the cipher rejects the input.
    pub fn encrypt_in_place(
        &mut self,
        pkt_rlh: &RecordLayerHeader,
        raw: &mut BytesMut,
    ) -> Result<()> {
        raw.reserve(CRYPTO_CHACHA20_TAG_LENGTH);
        self.seal(pkt_rlh, raw)
    }

    // Seals the payload after the header of `r`, then appends the tag and patches the header's
    // length.
    fn seal(&mut self, pkt_rlh: &RecordLayerHeader, r: &mut impl RecordBuf) -> Result<()> {
        let payload_len = r.len() - RECORD_LAYER_HEADER_SIZE;

        let mut nonce = [0u8; CRYPTO_CHACHA20_NONCE_LENGTH];
        nonce[..CRYPTO_CHACHA20_NONCE_LENGTH]
            .copy_from_slice(&self.local_write_iv[..CRYPTO_CHACHA20_NONCE_LENGTH]);

        noncegen(&mut nonce[..], pkt_rlh.epoch, pkt_rlh.sequence_number);
        let additional_data = generate_aead_additional_data(pkt_rlh, payload_len);

        let mut tag = [0; CRYPTO_CHACHA20_TAG_LENGTH];
        self.local_cc
            .seal_in_place(
                &nonce,
                &additional_data,
                &mut r[RECORD_LAYER_HEADER_SIZE..],
                &mut tag,
            )
            .map_err(crypto_error)?;
        r.extend(&tag);

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

        let (ciphertext, tag) = r[RECORD_LAYER_HEADER_SIZE..].split_at(ciphertext_len);
        let mut d = Vec::with_capacity(RECORD_LAYER_HEADER_SIZE + ciphertext_len);
        d.extend_from_slice(&r[..RECORD_LAYER_HEADER_SIZE]);
        d.extend_from_slice(ciphertext);
        self.remote_cc
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

        let (ciphertext, tag) = r[RECORD_LAYER_HEADER_SIZE..].split_at_mut(ciphertext_len);
        self.remote_cc
            .open_in_place(&nonce, &additional_data, ciphertext, tag)
            .map_err(authentication_error)?;

        strip_decrypted_record(r, 0, ciphertext_len);
        Ok(())
    }

    // Checks a received record's length and returns its header, nonce and ciphertext length,
    // or `None` for a ChangeCipherSpec record, which is not encrypted.
    fn open_params(
        &self,
        r: &[u8],
    ) -> Result<Option<(RecordLayerHeader, [u8; CRYPTO_CHACHA20_NONCE_LENGTH], usize)>> {
        let h = RecordLayerHeader::unmarshal(&mut &r[..])?;
        if h.content_type == ContentType::ChangeCipherSpec {
            // Nothing to encrypt with ChangeCipherSpec
            return Ok(None);
        }

        let mut nonce = [0; CRYPTO_CHACHA20_NONCE_LENGTH];
        nonce.copy_from_slice(&self.remote_write_iv[..]);

        noncegen(&mut nonce[..], h.epoch, h.sequence_number);
        let out_len = r.len() - RECORD_LAYER_HEADER_SIZE;
        if out_len < CRYPTO_CHACHA20_TAG_LENGTH {
            return Err(Error::ErrInvalidMac);
        }

        Ok(Some((h, nonce, out_len - CRYPTO_CHACHA20_TAG_LENGTH)))
    }
}
