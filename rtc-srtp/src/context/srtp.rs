use super::*;
use shared::error::{Error, Result};

use bytes::BytesMut;

use super::cryptex::{self, CryptexMode};
use crate::cipher::Cipher;

/// Pairs an already-parsed header with its true length on the wire in `packet`.
fn summarize(packet: &[u8], header: &rtp::Header) -> Result<rtp::header::HeaderSummary> {
    Ok(rtp::header::HeaderSummary {
        marker: header.marker,
        payload_type: header.payload_type,
        sequence_number: header.sequence_number,
        timestamp: header.timestamp,
        ssrc: header.ssrc,
        header_len: rtp::Header::wire_len(packet)?,
    })
}

impl Context {
    /// Decrypts an SRTP packet whose header has already been parsed.
    ///
    /// Saves re-parsing when the caller needed the header to route the packet. The header must
    /// be the one belonging to `encrypted`.
    ///
    /// # Errors
    ///
    /// Fails if authentication fails, if the packet is a replay, or if it is too short to hold
    /// the profile's auth tag.
    pub fn decrypt_rtp_with_header(
        &mut self,
        encrypted: &[u8],
        header: &rtp::Header,
    ) -> Result<BytesMut> {
        let summary = summarize(encrypted, header)?;
        let mut dst = BytesMut::with_capacity(encrypted.len());
        let mode = self.cryptex_mode;
        self.decrypt_rtp_summary(encrypted.len(), &summary, |cipher, roc| {
            decrypt_into(cipher, mode, &mut dst, encrypted, &summary, roc)
        })?;
        Ok(dst)
    }

    /// Runs `decrypt` on the cipher with the rollover counter this packet needs, wrapped in the
    /// bookkeeping every received packet needs: the length check, replay detection, and — only
    /// once `decrypt` has authenticated the packet — recording it.
    fn decrypt_rtp_summary(
        &mut self,
        packet_len: usize,
        header: &rtp::header::HeaderSummary,
        decrypt: impl FnOnce(&mut dyn Cipher, u32) -> Result<()>,
    ) -> Result<()> {
        let auth_tag_len = self.cipher.rtp_auth_tag_len();
        if packet_len < header.header_len + auth_tag_len {
            return Err(Error::ErrTooShortRtp);
        }

        let ssrc = header.ssrc;
        let sequence_number = header.sequence_number;

        // An SSRC this context has not seen has no state yet, and none is created until a packet
        // for it authenticates: the SSRC is read from an unauthenticated header, so allocating
        // per-SSRC state (a replay window, a map slot) before the tag is checked would let anyone
        // grow this context's memory without bound by spraying random SSRCs.
        let (roc, diff) = match self.srtp_ssrc_states.get_mut(&ssrc) {
            Some(state) => {
                let (roc, diff, _) = state.next_rollover_count(sequence_number);
                if let Some(replay_detector) = &mut state.replay_detector
                    && !replay_detector.check(sequence_number as u64)
                {
                    return Err(Error::SrtpSsrcDuplicated(ssrc, sequence_number));
                }
                (roc, diff)
            }
            None => (0, 0),
        };

        decrypt(self.cipher.as_mut(), roc)?;

        let state = self.get_srtp_ssrc_state(ssrc);
        if let Some(replay_detector) = &mut state.replay_detector {
            // A new SSRC's detector has not been asked about this packet yet.
            replay_detector.check(sequence_number as u64);
            replay_detector.accept();
        }
        state.update_rollover_count(sequence_number, diff);
        Ok(())
    }

    /// DecryptRTP decrypts a RTP packet with an encrypted payload
    pub fn decrypt_rtp(&mut self, encrypted: &[u8]) -> Result<BytesMut> {
        let mut dst = BytesMut::with_capacity(encrypted.len());
        self.decrypt_rtp_into(&mut dst, encrypted)?;
        Ok(dst)
    }

    /// Decrypts an SRTP packet, appending the plain RTP packet to `dst`.
    ///
    /// For a send or receive loop that reuses one buffer: reserve once, decrypt into it, then
    /// `split()` off each packet, so steady state allocates nothing per packet. On error `dst`
    /// is unchanged.
    ///
    /// # Errors
    ///
    /// As [`Context::decrypt_rtp`].
    pub fn decrypt_rtp_into(&mut self, dst: &mut BytesMut, encrypted: &[u8]) -> Result<()> {
        let header = rtp::Header::peek(encrypted)?;
        let mode = self.cryptex_mode;
        self.decrypt_rtp_summary(encrypted.len(), &header, |cipher, roc| {
            decrypt_into(cipher, mode, dst, encrypted, &header, roc)
        })
    }

    /// Decrypts, in place, the SRTP packet in `packet`: on success it holds the plain RTP packet,
    /// its authentication tag removed.
    ///
    /// The cheapest way to unprotect a packet you own: no allocation and no copy, since the
    /// payload is decrypted where it arrived. A packet that fails authentication, or is a replay,
    /// is left untouched (AES-GCM profiles may leave the contents of a rejected packet
    /// unspecified).
    ///
    /// # Errors
    ///
    /// As [`Context::decrypt_rtp`].
    pub fn decrypt_rtp_in_place(&mut self, packet: &mut BytesMut) -> Result<()> {
        let header = rtp::Header::peek(packet)?;
        let mode = self.cryptex_mode;
        self.decrypt_rtp_summary(packet.len(), &header, |cipher, roc| {
            cryptex::decrypt_in_place(cipher, mode, packet, 0, &header, roc)
        })
    }

    /// Encrypts an RTP payload, using an already-parsed header.
    ///
    /// Saves re-parsing when the caller has just built the header. Returns the full protected
    /// packet, header included.
    ///
    /// # Errors
    ///
    /// Fails if the SRTP context has no key for this SSRC or the cipher rejects the input.
    pub fn encrypt_rtp_with_header(
        &mut self,
        plaintext: &[u8],
        header: &rtp::Header,
    ) -> Result<BytesMut> {
        let summary = summarize(plaintext, header)?;
        let mut dst = BytesMut::with_capacity(plaintext.len() + self.rtp_overhead() + 4);
        let cryptex = self.cryptex_mode != CryptexMode::Disabled;
        self.encrypt_rtp_summary(&summary, |cipher, roc| {
            encrypt_into(cipher, cryptex, &mut dst, plaintext, &summary, roc)
        })?;
        Ok(dst)
    }

    /// Runs `encrypt` on the cipher with the rollover counter this packet needs, and advances the
    /// stream's index once it has succeeded.
    fn encrypt_rtp_summary(
        &mut self,
        header: &rtp::header::HeaderSummary,
        encrypt: impl FnOnce(&mut dyn Cipher, u32) -> Result<()>,
    ) -> Result<()> {
        let sequence_number = header.sequence_number;
        let new_replay_detector = &self.new_srtp_replay_detector;
        let state = self
            .srtp_ssrc_states
            .entry(header.ssrc)
            .or_insert_with(|| SrtpSsrcState {
                ssrc: header.ssrc,
                replay_detector: Some(new_replay_detector()),
                ..Default::default()
            });
        let (roc, diff, ovf) = state.next_rollover_count(sequence_number);
        if ovf {
            // ... when 2^48 SRTP packets or 2^31 SRTCP packets have been secured with the same key
            // (whichever occurs before), the key management MUST be called to provide new master key(s)
            // (previously stored and used keys MUST NOT be used again), or the session MUST be terminated.
            // https://www.rfc-editor.org/rfc/rfc3711#section-9.2
            return Err(Error::ErrExceededMaxPackets);
        }

        encrypt(self.cipher.as_mut(), roc)?;

        state.update_rollover_count(sequence_number, diff);
        Ok(())
    }

    /// EncryptRTP marshals and encrypts an RTP packet, writing to the dst buffer provided.
    /// If the dst buffer does not have the capacity to hold `len(plaintext) + 10` bytes, a new one will be allocated and returned.
    pub fn encrypt_rtp(&mut self, plaintext: &[u8]) -> Result<BytesMut> {
        let mut dst = BytesMut::with_capacity(plaintext.len() + self.rtp_overhead());
        self.encrypt_rtp_into(&mut dst, plaintext)?;
        Ok(dst)
    }

    /// Encrypts an RTP packet, appending the protected packet to `dst`.
    ///
    /// For a send loop that reuses one buffer: reserve once, encrypt into it, then `split()` off
    /// each packet, so steady state allocates nothing per packet. On error `dst` is unchanged.
    ///
    /// # Errors
    ///
    /// As [`Context::encrypt_rtp`].
    pub fn encrypt_rtp_into(&mut self, dst: &mut BytesMut, plaintext: &[u8]) -> Result<()> {
        let header = rtp::Header::peek(plaintext)?;
        let cryptex = self.cryptex_mode != CryptexMode::Disabled;
        self.encrypt_rtp_summary(&header, |cipher, roc| {
            encrypt_into(cipher, cryptex, dst, plaintext, &header, roc)
        })
    }

    /// Encrypts, in place, the RTP packet in `packet`: on success it holds the SRTP packet, the
    /// authentication tag appended.
    ///
    /// The cheapest way to protect a packet you have just marshalled: the payload is encrypted
    /// where it lies, with no second buffer and no copy. Reserve [`rtp_overhead`](Self::rtp_overhead)
    /// spare bytes in `packet` when allocating it and the tag is appended without reallocating.
    /// If it fails the contents of `packet` are unspecified.
    ///
    /// # Errors
    ///
    /// As [`Context::encrypt_rtp`].
    pub fn encrypt_rtp_in_place(&mut self, packet: &mut BytesMut) -> Result<()> {
        let header = rtp::Header::peek(packet)?;
        let cryptex = self.cryptex_mode != CryptexMode::Disabled;
        self.encrypt_rtp_summary(&header, |cipher, roc| {
            if cryptex {
                cryptex::encrypt_in_place(cipher, packet, 0, &header, roc)
            } else {
                cipher.encrypt_rtp_in_place(packet, 0, &header, roc)
            }
        })
    }

    /// How many bytes protecting an RTP packet adds: the authentication tag.
    pub fn rtp_overhead(&self) -> usize {
        self.cipher
            .rtp_auth_tag_len()
            .max(self.cipher.aead_auth_tag_len())
    }
}

/// [`Cipher::decrypt_rtp_into`], going through Cryptex when it is in play.
fn decrypt_into(
    cipher: &mut dyn Cipher,
    mode: CryptexMode,
    dst: &mut BytesMut,
    encrypted: &[u8],
    summary: &rtp::header::HeaderSummary,
    roc: u32,
) -> Result<()> {
    if mode == CryptexMode::Disabled && !cryptex_packet_possible(encrypted) {
        return cipher.decrypt_rtp_into(dst, encrypted, summary, roc);
    }
    cryptex::decrypt_into(cipher, mode, dst, encrypted, summary, roc)
}

/// [`Cipher::encrypt_rtp_into`], going through Cryptex when it is on.
fn encrypt_into(
    cipher: &mut dyn Cipher,
    cryptex: bool,
    dst: &mut BytesMut,
    plaintext: &[u8],
    summary: &rtp::header::HeaderSummary,
    roc: u32,
) -> Result<()> {
    if cryptex {
        cryptex::encrypt_into(cipher, dst, plaintext, summary, roc)
    } else {
        cipher.encrypt_rtp_into(dst, plaintext, summary, roc)
    }
}

/// Whether a packet could be Cryptex-protected: it has a header extension block. The only
/// packets a disabled context must look at.
fn cryptex_packet_possible(packet: &[u8]) -> bool {
    packet.first().is_some_and(|b| b & 0x10 != 0)
}
