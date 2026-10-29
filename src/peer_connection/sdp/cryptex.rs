//! Negotiating Cryptex ([RFC 9335]) from session descriptions.
//!
//! `a=cryptex` says its sender can *receive* RTP whose header extensions and CSRCs are encrypted.
//! So the peer's description decides whether this side may *send* that way, and this side's own
//! description decides what it still has to accept.
//!
//! [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335

use crate::peer_connection::configuration::RTCRtpHeaderEncryptionPolicy;
use crate::peer_connection::sdp::get_mid_value;
use sdp::description::media::MediaDescription;
use sdp::description::session::{ATTR_KEY_CRYPTEX, ATTR_KEY_GROUP, SessionDescription};
use shared::error::{Error, Result};
use srtp::context::cryptex::CryptexMode;

const MEDIA_SECTION_APPLICATION: &str = "application";

fn is_cryptex_set(media: &MediaDescription) -> bool {
    media.has_attribute(ATTR_KEY_CRYPTEX)
}

/// The mids listed in `a=group:BUNDLE`, in order. The first is the BUNDLE tag, whose media section
/// carries the TRANSPORT-category attributes (RFC 9143 §7.1.3) shared by every section in the
/// group, whether or not a section repeats them.
pub(crate) fn bundle_group_mids(desc: &SessionDescription) -> Vec<&str> {
    desc.attribute(ATTR_KEY_GROUP)
        .filter(|g| g.contains("BUNDLE"))
        .map(|g| g.split(' ').skip(1).collect())
        .unwrap_or_default()
}

/// The media section the BUNDLE group is tagged with.
pub(crate) fn bundle_tag_media(desc: &SessionDescription) -> Option<&MediaDescription> {
    let tag = *bundle_group_mids(desc).first()?;
    desc.media_descriptions
        .iter()
        .find(|m| get_mid_value(m) == Some(tag))
}

/// Whether `media` counts as active, whether it carries RTP (rather than a data channel), and
/// whether Cryptex applies to it.
///
/// A section without its own `a=cryptex` still inherits it from the BUNDLE tag section (RFC 9143
/// §7.1.3: TRANSPORT attributes apply to the whole group however many sections repeat them).
pub(crate) fn media_section_cryptex_state(
    media: &MediaDescription,
    bundle_tag: Option<&MediaDescription>,
    bundle_mids: &[&str],
) -> (bool, bool, bool) {
    // RFC 9143 §6/§7.2: a zero-port m-line with a=bundle-only asks to join the BUNDLE group, it
    // is not a rejection.
    if media.media_name.port.value == 0 && !media.has_attribute("bundle-only") {
        return (false, false, false);
    }
    if media.media_name.media == MEDIA_SECTION_APPLICATION {
        return (true, false, false);
    }

    let mut has_cryptex = is_cryptex_set(media);
    if !has_cryptex
        && let Some(tag) = bundle_tag
        && get_mid_value(media).is_some_and(|mid| bundle_mids.contains(&mid))
    {
        has_cryptex = is_cryptex_set(tag);
    }
    (true, true, has_cryptex)
}

/// Whether Cryptex is negotiated for any, and for every, active RTP media section of `desc`.
pub(crate) fn cryptex_negotiated_in_sdp(desc: &SessionDescription) -> (bool, bool) {
    if desc.has_attribute(ATTR_KEY_CRYPTEX) {
        return (true, true);
    }

    let tag = bundle_tag_media(desc);
    let mids = bundle_group_mids(desc);

    let (mut any, mut all) = (false, true);
    let (mut have_media, mut have_rtp) = (false, false);
    for media in &desc.media_descriptions {
        let (active, is_rtp, has_cryptex) = media_section_cryptex_state(media, tag, &mids);
        if !active {
            continue;
        }
        have_media = true;
        if !is_rtp {
            continue;
        }
        have_rtp = true;
        any |= has_cryptex;
        all &= has_cryptex;
    }

    if !have_media {
        return (false, false);
    }
    if !have_rtp {
        // Only non-RTP sections (data channels): Cryptex does not apply, which is vacuously
        // "negotiated for all RTP media" so a Require policy does not reject a data-only session.
        return (false, true);
    }
    (any, all)
}

/// The Cryptex mode `desc` implies under `policy`.
///
/// # Errors
///
/// Fails if only some of the RTP sections negotiate Cryptex (it is connection-wide here), or if the
/// policy is [`Require`](RTCRtpHeaderEncryptionPolicy::Require) and they do not all.
pub(crate) fn cryptex_mode_from_sdp(
    policy: RTCRtpHeaderEncryptionPolicy,
    desc: &SessionDescription,
) -> Result<CryptexMode> {
    let (any, all) = cryptex_negotiated_in_sdp(desc);

    if policy.enabled() && any && !all {
        return Err(Error::ErrRtpHeaderEncryptionMixedModeNotSupported);
    }

    Ok(match policy {
        RTCRtpHeaderEncryptionPolicy::Disable => CryptexMode::Disabled,
        RTCRtpHeaderEncryptionPolicy::Unspecified | RTCRtpHeaderEncryptionPolicy::Negotiate => {
            if any {
                CryptexMode::Enabled
            } else {
                CryptexMode::Disabled
            }
        }
        RTCRtpHeaderEncryptionPolicy::Require => {
            if !all {
                return Err(Error::ErrRtpHeaderEncryptionRequired);
            } else if any {
                CryptexMode::Required
            } else {
                // Data-only description without session-level Cryptex.
                CryptexMode::Disabled
            }
        }
    })
}
