use super::*;
use shared::{
    error::{Error, Result},
    marshal::{Marshal, MarshalSize, Unmarshal},
};

use bytes::{Buf, BytesMut};

impl Context {
    /// Runs `decrypt` under the replay and rollover state of `header`'s SSRC, committing that
    /// state only once the packet has authenticated.
    ///
    /// An SSRC this context has not yet authenticated a packet for is checked against fresh
    /// state that is kept only if `decrypt` succeeds. Creating it up front, as a lookup that
    /// inserts would, lets every forged packet with a new SSRC leave a map entry and a replay
    /// detector behind: memory an attacker controls, proportional to packets sent.
    fn decrypt_rtp_under_state<T>(
        &mut self,
        header: &rtp::Header,
        decrypt: impl FnOnce(&mut dyn Cipher, u32) -> Result<T>,
    ) -> Result<T> {
        let (ssrc, sequence_number) = (header.ssrc, header.sequence_number);
        let mut unknown = None;
        let state = match self.srtp_ssrc_states.get_mut(&ssrc) {
            Some(state) => state,
            None => unknown.insert(SrtpSsrcState {
                ssrc,
                replay_detector: Some((self.new_srtp_replay_detector)()),
                ..Default::default()
            }),
        };

        let (roc, diff, _) = state.next_rollover_count(sequence_number);
        if let Some(replay_detector) = &mut state.replay_detector
            && !replay_detector.check(sequence_number as u64)
        {
            return Err(Error::SrtpSsrcDuplicated(ssrc, sequence_number));
        }

        let decrypted = decrypt(self.cipher.as_mut(), roc)?;

        if let Some(replay_detector) = &mut state.replay_detector {
            replay_detector.accept();
        }
        state.update_rollover_count(sequence_number, diff);
        if let Some(state) = unknown {
            self.srtp_ssrc_states.insert(ssrc, state);
        }

        Ok(decrypted)
    }

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
        let auth_tag_len = self.cipher.rtp_auth_tag_len();
        if encrypted.len() < header.marshal_size() + auth_tag_len {
            return Err(Error::ErrTooShortRtp);
        }

        self.decrypt_rtp_under_state(header, |cipher, roc| {
            cipher.decrypt_rtp(encrypted, header, roc)
        })
    }

    /// DecryptRTP decrypts a RTP packet with an encrypted payload
    pub fn decrypt_rtp(&mut self, encrypted: &[u8]) -> Result<BytesMut> {
        let mut buf = encrypted;
        let header = rtp::Header::unmarshal(&mut buf)?;
        self.decrypt_rtp_with_header(encrypted, &header)
    }

    /// Decrypts an SRTP packet in its own buffer and returns it parsed.
    ///
    /// Equivalent to [`decrypt_rtp`](Self::decrypt_rtp) followed by `rtp::Packet::unmarshal`,
    /// without either of their costs: the payload is decrypted where it lies rather than copied
    /// to a new buffer first, and the header is parsed once rather than once per call. The
    /// returned payload shares `encrypted`'s allocation.
    ///
    /// # Errors
    ///
    /// As [`decrypt_rtp`](Self::decrypt_rtp), plus `rtp::Packet::unmarshal`'s padding errors.
    /// On error the buffer is dropped, so a packet that fails authentication is never exposed.
    pub fn decrypt_rtp_packet(&mut self, mut encrypted: BytesMut) -> Result<rtp::Packet> {
        let mut buf = &encrypted[..];
        let header = rtp::Header::unmarshal(&mut buf)?;
        let payload_offset = encrypted.len() - buf.remaining();

        let auth_tag_len = self.cipher.rtp_auth_tag_len();
        if encrypted.len() < header.marshal_size() + auth_tag_len {
            return Err(Error::ErrTooShortRtp);
        }

        self.decrypt_rtp_under_state(&header, |cipher, roc| {
            cipher.decrypt_rtp_in_place(&mut encrypted, &header, roc)
        })?;

        // What `rtp::Packet::unmarshal` does with the bytes after the header, including its
        // treatment of padding. The payload offset is the parsed header's length, as it would
        // be for a re-parse: decryption leaves the header bytes untouched.
        if encrypted.len() < payload_offset {
            return Err(Error::ErrShortPacket);
        }
        encrypted.advance(payload_offset);
        if header.padding {
            let padding_len = match encrypted.last() {
                Some(&padding_len) if padding_len as usize <= encrypted.len() => padding_len,
                _ => return Err(Error::ErrShortPacket),
            };
            encrypted.truncate(encrypted.len() - padding_len as usize);
        }

        Ok(rtp::Packet {
            header,
            payload: encrypted.freeze(),
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
        self.encrypt_rtp_under_state(header, |cipher, roc| {
            cipher.encrypt_rtp(plaintext, header, roc)
        })
    }

    /// Marshals an RTP packet and encrypts it in the same buffer.
    ///
    /// Equivalent to marshalling `packet` and passing the bytes to
    /// [`encrypt_rtp_with_header`](Self::encrypt_rtp_with_header), with one allocation instead
    /// of two: the buffer is sized for the auth tag up front and encrypted where it was
    /// marshalled.
    ///
    /// # Errors
    ///
    /// As [`encrypt_rtp_with_header`](Self::encrypt_rtp_with_header), plus any marshalling
    /// error.
    pub fn encrypt_rtp_packet(&mut self, packet: &rtp::Packet) -> Result<BytesMut> {
        let len = packet.marshal_size();
        let mut buf = BytesMut::with_capacity(
            len + self.cipher.rtp_auth_tag_len() + self.cipher.aead_auth_tag_len(),
        );
        buf.resize(len, 0);
        let written = packet.marshal_to(&mut buf)?;
        if written != len {
            return Err(Error::Other(format!(
                "marshal_to output size {written}, but expect {len}"
            )));
        }

        self.encrypt_rtp_under_state(&packet.header, |cipher, roc| {
            cipher.encrypt_rtp_in_place(&mut buf, &packet.header, roc)
        })?;
        Ok(buf)
    }

    /// Runs `encrypt` with the rollover counter for `header`, then advances it.
    fn encrypt_rtp_under_state<T>(
        &mut self,
        header: &rtp::Header,
        encrypt: impl FnOnce(&mut dyn Cipher, u32) -> Result<T>,
    ) -> Result<T> {
        let (roc, diff, ovf) = self
            .get_srtp_ssrc_state(header.ssrc)
            .next_rollover_count(header.sequence_number);
        if ovf {
            // ... when 2^48 SRTP packets or 2^31 SRTCP packets have been secured with the same key
            // (whichever occurs before), the key management MUST be called to provide new master key(s)
            // (previously stored and used keys MUST NOT be used again), or the session MUST be terminated.
            // https://www.rfc-editor.org/rfc/rfc3711#section-9.2
            return Err(Error::ErrExceededMaxPackets);
        }

        let encrypted = encrypt(self.cipher.as_mut(), roc)?;

        self.get_srtp_ssrc_state(header.ssrc)
            .update_rollover_count(header.sequence_number, diff);

        Ok(encrypted)
    }

    /// EncryptRTP marshals and encrypts an RTP packet, writing to the dst buffer provided.
    /// If the dst buffer does not have the capacity to hold `len(plaintext) + 10` bytes, a new one will be allocated and returned.
    pub fn encrypt_rtp(&mut self, plaintext: &[u8]) -> Result<BytesMut> {
        let mut buf = plaintext;
        let header = rtp::Header::unmarshal(&mut buf)?;
        self.encrypt_rtp_with_header(plaintext, &header)
    }
}
