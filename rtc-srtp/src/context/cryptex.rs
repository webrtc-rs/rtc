//! Cryptex ([RFC 9335]): encrypting the RTP header extensions and CSRCs, which SRTP leaves in the
//! clear.
//!
//! The ciphers protect everything after a header of `header_len` bytes. To make the CSRCs and the
//! extension block part of what is protected, they are first moved so that the four bytes that
//! introduce the extension block (profile and length, which must stay readable) sit directly after
//! the fixed header; the packet is then protected as though that were all the header; and finally
//! the CSRCs are moved back in front of the extension header, so what goes on the wire has the
//! ordinary RTP layout. Unprotecting does the same in reverse.
//!
//! [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335

use bytes::BytesMut;
use rtp::header::{
    CRYPTEX_PROFILE_ONE_BYTE, CRYPTEX_PROFILE_TWO_BYTE, EXTENSION_PROFILE_ONE_BYTE,
    EXTENSION_PROFILE_TWO_BYTE, HeaderSummary,
};
use shared::error::{Error, Result};

use crate::cipher::Cipher;

/// Whether an SRTP context uses Cryptex.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CryptexMode {
    /// Cryptex is not used. A packet that arrives Cryptex-protected is refused.
    #[default]
    Disabled,
    /// Packets are sent Cryptex-protected, and both protected and unprotected packets are
    /// accepted.
    Enabled,
    /// As [`Enabled`](Self::Enabled), but a received packet that has header extensions or CSRCs
    /// and is not Cryptex-protected is refused.
    Required,
}

const FIXED_HEADER: usize = 12;
const EXT_HEADER: usize = 4;
/// What the ciphers treat as the header once a packet has been rearranged.
const REARRANGED_HEADER: usize = FIXED_HEADER + EXT_HEADER;

fn csrc_bytes(first: u8) -> usize {
    (first & 0x0f) as usize * 4
}

fn has_extension(first: u8) -> bool {
    first & 0x10 != 0
}

/// The extension profile of a packet that has an extension block, if it is all there.
fn extension_profile(p: &[u8]) -> Option<u16> {
    let at = FIXED_HEADER + csrc_bytes(*p.first()?);
    let bytes = p.get(at..at + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Whether the packet in `p` carries a Cryptex extension block.
fn is_cryptex(p: &[u8]) -> bool {
    p.len() >= FIXED_HEADER
        && has_extension(p[0])
        && matches!(
            extension_profile(p),
            Some(CRYPTEX_PROFILE_ONE_BYTE | CRYPTEX_PROFILE_TWO_BYTE)
        )
}

/// Moves the four-byte extension header in front of the CSRCs.
fn move_extension_header_before_csrcs(p: &mut [u8], csrc_len: usize) {
    if csrc_len == 0 {
        return;
    }
    let mut ext = [0u8; EXT_HEADER];
    ext.copy_from_slice(&p[FIXED_HEADER + csrc_len..FIXED_HEADER + csrc_len + EXT_HEADER]);
    p.copy_within(
        FIXED_HEADER..FIXED_HEADER + csrc_len,
        FIXED_HEADER + EXT_HEADER,
    );
    p[FIXED_HEADER..FIXED_HEADER + EXT_HEADER].copy_from_slice(&ext);
}

/// Undoes [`move_extension_header_before_csrcs`].
fn move_csrcs_before_extension_header(p: &mut [u8], csrc_len: usize) {
    if csrc_len == 0 {
        return;
    }
    let mut ext = [0u8; EXT_HEADER];
    ext.copy_from_slice(&p[FIXED_HEADER..FIXED_HEADER + EXT_HEADER]);
    p.copy_within(
        FIXED_HEADER + EXT_HEADER..FIXED_HEADER + EXT_HEADER + csrc_len,
        FIXED_HEADER,
    );
    p[FIXED_HEADER + csrc_len..FIXED_HEADER + csrc_len + EXT_HEADER].copy_from_slice(&ext);
}

/// Protects, in place, the RTP packet at `buf[start..]` with Cryptex.
///
/// A packet with neither CSRCs nor extensions has nothing to hide and is protected as usual. One
/// with CSRCs but no extension block gets an empty one (RFC 9335 §5.1), so there is a block for
/// the CSRCs to be encrypted with.
pub(crate) fn encrypt_in_place(
    cipher: &mut dyn Cipher,
    buf: &mut BytesMut,
    start: usize,
    summary: &HeaderSummary,
    roc: u32,
) -> Result<()> {
    if buf.len() < start + FIXED_HEADER {
        return Err(Error::ErrTooShortRtp);
    }
    let first = buf[start];
    let csrc_len = csrc_bytes(first);
    if !has_extension(first) && csrc_len == 0 {
        return cipher.encrypt_rtp_in_place(buf, start, summary, roc);
    }

    let at = start + FIXED_HEADER + csrc_len;
    if !has_extension(first) {
        if buf.len() < at {
            return Err(Error::ErrTooShortRtp);
        }
        let old_len = buf.len();
        buf.resize(old_len + EXT_HEADER, 0);
        buf.copy_within(at..old_len, at + EXT_HEADER);
        buf[at..at + 2].copy_from_slice(&EXTENSION_PROFILE_ONE_BYTE.to_be_bytes());
        buf[at + 2..at + 4].copy_from_slice(&[0, 0]);
        buf[start] |= 0x10;
    }

    let profile = extension_profile(&buf[start..]).ok_or(Error::ErrTooShortRtp)?;
    let cryptex_profile = match profile {
        EXTENSION_PROFILE_ONE_BYTE => CRYPTEX_PROFILE_ONE_BYTE,
        EXTENSION_PROFILE_TWO_BYTE => CRYPTEX_PROFILE_TWO_BYTE,
        // RFC 9335 §5.1: only RFC 8285 extensions can be protected this way.
        _ => return Err(Error::ErrUnsupportedHeaderExtension),
    };

    let packet = &mut buf[start..];
    if packet.len() < FIXED_HEADER + csrc_len + EXT_HEADER {
        return Err(Error::ErrTooShortRtp);
    }
    move_extension_header_before_csrcs(packet, csrc_len);
    packet[FIXED_HEADER..FIXED_HEADER + 2].copy_from_slice(&cryptex_profile.to_be_bytes());

    let mut rearranged = *summary;
    rearranged.header_len = REARRANGED_HEADER;
    if cipher.authenticates_wire_layout() {
        // The keystream runs over the rearranged packet; the MAC covers the packet as sent.
        cipher.apply_rtp_keystream(&mut buf[start..], &rearranged, roc)?;
        move_csrcs_before_extension_header(&mut buf[start..], csrc_len);
        return cipher.append_rtp_auth_tag(buf, start, roc);
    }
    cipher.encrypt_rtp_in_place(buf, start, &rearranged, roc)?;

    move_csrcs_before_extension_header(&mut buf[start..], csrc_len);
    Ok(())
}

/// Unprotects, in place, the SRTP packet at `buf[start..]`, which may or may not be
/// Cryptex-protected, depending on `mode`.
pub(crate) fn decrypt_in_place(
    cipher: &mut dyn Cipher,
    mode: CryptexMode,
    buf: &mut BytesMut,
    start: usize,
    summary: &HeaderSummary,
    roc: u32,
) -> Result<()> {
    let packet = &buf[start..];
    let protected = is_cryptex(packet);
    match mode {
        CryptexMode::Disabled if protected => return Err(Error::ErrCryptexDisabled),
        CryptexMode::Required
            if !protected
                && packet.len() >= FIXED_HEADER
                && (has_extension(packet[0]) || csrc_bytes(packet[0]) > 0) =>
        {
            return Err(Error::ErrUnencryptedHeaderExtAndCsrcs);
        }
        _ => {}
    }
    if !protected {
        return cipher.decrypt_rtp_in_place(buf, start, summary, roc);
    }

    let csrc_len = csrc_bytes(buf[start]);
    let profile = extension_profile(&buf[start..]).ok_or(Error::ErrTooShortRtp)?;
    let mut rearranged = *summary;
    rearranged.header_len = REARRANGED_HEADER;

    if cipher.authenticates_wire_layout() {
        // The MAC covers the packet as it was sent, so it is checked before anything moves.
        cipher.verify_and_strip_rtp_auth_tag(buf, start, roc)?;
        move_extension_header_before_csrcs(&mut buf[start..], csrc_len);
        cipher.apply_rtp_keystream(&mut buf[start..], &rearranged, roc)?;
    } else {
        move_extension_header_before_csrcs(&mut buf[start..], csrc_len);
        if let Err(e) = cipher.decrypt_rtp_in_place(buf, start, &rearranged, roc) {
            // A rejected packet is left as it arrived.
            move_csrcs_before_extension_header(&mut buf[start..], csrc_len);
            return Err(e);
        }
    }

    let packet = &mut buf[start..];
    move_csrcs_before_extension_header(packet, csrc_len);
    let plain = if profile == CRYPTEX_PROFILE_ONE_BYTE {
        EXTENSION_PROFILE_ONE_BYTE
    } else {
        EXTENSION_PROFILE_TWO_BYTE
    };
    let at = FIXED_HEADER + csrc_len;
    packet[at..at + 2].copy_from_slice(&plain.to_be_bytes());
    Ok(())
}

/// [`encrypt_in_place`] after copying `payload` onto the end of `dst`; on error `dst` is as it was.
pub(crate) fn encrypt_into(
    cipher: &mut dyn Cipher,
    dst: &mut BytesMut,
    payload: &[u8],
    summary: &HeaderSummary,
    roc: u32,
) -> Result<()> {
    let start = dst.len();
    dst.reserve(payload.len() + EXT_HEADER + 32);
    dst.extend_from_slice(payload);
    let result = encrypt_in_place(cipher, dst, start, summary, roc);
    if result.is_err() {
        dst.truncate(start);
    }
    result
}

/// [`decrypt_in_place`] after copying `payload` onto the end of `dst`; on error `dst` is as it was.
pub(crate) fn decrypt_into(
    cipher: &mut dyn Cipher,
    mode: CryptexMode,
    dst: &mut BytesMut,
    payload: &[u8],
    summary: &HeaderSummary,
    roc: u32,
) -> Result<()> {
    let start = dst.len();
    dst.reserve(payload.len());
    dst.extend_from_slice(payload);
    let result = decrypt_in_place(cipher, mode, dst, start, summary, roc);
    if result.is_err() {
        dst.truncate(start);
    }
    result
}
