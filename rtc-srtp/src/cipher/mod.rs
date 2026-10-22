pub mod cipher_aead_aes_gcm;
pub mod cipher_aes_cm_hmac_sha1;

use bytes::BytesMut;
use crypto::{CryptoError, RTCCrypto};

use shared::error::{Error, Result};

type Kdf = fn(&dyn RTCCrypto, u8, &[u8], &[u8], usize, usize) -> Result<Vec<u8>>;

pub(crate) fn crypto_error(error: CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

///NOTE: Auth tag and AEAD auth tag are placed at the different position in SRTCP
///
///In non-AEAD cipher, the authentication tag is placed *after* the ESRTCP word
///(Encrypted-flag and SRTCP index).
///
///> AES_128_CM_HMAC_SHA1_80
///> | RTCP Header | Encrypted payload |E| SRTCP Index | Auth tag |
///>                                   ^               |----------|
///>                                   |                ^
///>                                   |                authTagLen=10
///>                                   aeadAuthTagLen=0
///
///In AEAD cipher, the AEAD authentication tag is embedded in the ciphertext.
///It is *before* the ESRTCP word (Encrypted-flag and SRTCP index).
///
///> AEAD_AES_128_GCM
///> | RTCP Header | Encrypted payload | AEAD auth tag |E| SRTCP Index |
///>                                   |---------------|               ^
///>                                    ^                              authTagLen=0
///>                                    aeadAuthTagLen=16
///
///See https://tools.ietf.org/html/rfc7714 for the full specifications.
///
/// Cipher represents a implementation of one
/// of the SRTP Specific ciphers.
pub(crate) trait Cipher: Send {
    /// Get RTP authenticated tag length.
    fn rtp_auth_tag_len(&self) -> usize;

    /// Get RTCP authenticated tag length.
    fn rtcp_auth_tag_len(&self) -> usize;

    /// Get AEAD auth key length of the cipher.
    fn aead_auth_tag_len(&self) -> usize;

    /// Retrieved RTCP index.
    fn get_rtcp_index(&self, input: &[u8]) -> usize;

    /// Protects, in place, the RTP packet that occupies `buf[start..]`: encrypts its payload and
    /// appends the authentication tag, so `buf[start..]` becomes the SRTP packet.
    ///
    /// On error the contents of `buf[start..]` are unspecified; callers that must preserve the
    /// buffer truncate it back to `start`.
    fn encrypt_rtp_in_place(
        &mut self,
        buf: &mut BytesMut,
        start: usize,
        header: &rtp::header::HeaderSummary,
        roc: u32,
    ) -> Result<()>;

    /// Verifies and decrypts, in place, the SRTP packet that occupies `buf[start..]`, removing
    /// the authentication tag, so `buf[start..]` becomes the plain RTP packet.
    ///
    /// Authentication is checked before anything is decrypted, so a forged packet leaves the
    /// buffer as it was (AES-GCM is the exception: its contents are unspecified on failure).
    fn decrypt_rtp_in_place(
        &mut self,
        buf: &mut BytesMut,
        start: usize,
        header: &rtp::header::HeaderSummary,
        roc: u32,
    ) -> Result<()>;

    /// Encrypt an RTP packet, appending the protected packet to `dst`.
    ///
    /// On error `dst` is left as it was.
    fn encrypt_rtp_into(
        &mut self,
        dst: &mut BytesMut,
        payload: &[u8],
        header: &rtp::header::HeaderSummary,
        roc: u32,
    ) -> Result<()> {
        let start = dst.len();
        dst.reserve(payload.len() + self.rtp_auth_tag_len().max(self.aead_auth_tag_len()));
        dst.extend_from_slice(payload);
        let result = self.encrypt_rtp_in_place(dst, start, header, roc);
        if result.is_err() {
            dst.truncate(start);
        }
        result
    }

    /// Decrypt an SRTP packet, appending the plain packet to `dst`.
    ///
    /// On error `dst` is left as it was.
    fn decrypt_rtp_into(
        &mut self,
        dst: &mut BytesMut,
        payload: &[u8],
        header: &rtp::header::HeaderSummary,
        roc: u32,
    ) -> Result<()> {
        let start = dst.len();
        dst.reserve(payload.len());
        dst.extend_from_slice(payload);
        let result = self.decrypt_rtp_in_place(dst, start, header, roc);
        if result.is_err() {
            dst.truncate(start);
        }
        result
    }

    /// Encrypt an RTP packet into a new buffer.
    fn encrypt_rtp(
        &mut self,
        payload: &[u8],
        header: &rtp::header::HeaderSummary,
        roc: u32,
    ) -> Result<BytesMut> {
        let mut dst = BytesMut::with_capacity(
            payload.len() + self.rtp_auth_tag_len().max(self.aead_auth_tag_len()),
        );
        self.encrypt_rtp_into(&mut dst, payload, header, roc)?;
        Ok(dst)
    }

    /// Decrypt an SRTP packet into a new buffer.
    fn decrypt_rtp(
        &mut self,
        payload: &[u8],
        header: &rtp::header::HeaderSummary,
        roc: u32,
    ) -> Result<BytesMut> {
        let mut dst = BytesMut::with_capacity(payload.len());
        self.decrypt_rtp_into(&mut dst, payload, header, roc)?;
        Ok(dst)
    }

    /// Encrypt RTCP payload.
    fn encrypt_rtcp(&mut self, payload: &[u8], srtcp_index: usize, ssrc: u32) -> Result<BytesMut>;

    /// Decrypt RTCP payload.
    fn decrypt_rtcp(&mut self, payload: &[u8], srtcp_index: usize, ssrc: u32) -> Result<BytesMut>;
}
