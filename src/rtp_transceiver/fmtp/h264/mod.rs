#[cfg(test)]
mod h264_test;

use super::*;
use crate::rtp_transceiver::h264::H264ProfileLevelId;

fn profile_level_id_matches(a: &str, b: &str) -> bool {
    matches!(
        (H264ProfileLevelId::parse(a), H264ProfileLevelId::parse(b)),
        (Some(a), Some(b)) if a.is_same_profile(b)
    )
}

#[derive(Debug, PartialEq)]
pub(crate) struct H264Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

// RFC 6184 8.2.2: each endpoint advertises its own receive level when both
// permit asymmetry; otherwise the answer must select the lower level.
fn receive_level(local: &str, remote: &str) -> Option<H264ProfileLevelId> {
    let local_fmtp = parse("video/H264", local);
    let remote_fmtp = parse("video/H264", remote);
    if !local_fmtp.match_fmtp(&*remote_fmtp) {
        return None;
    }
    let local = H264ProfileLevelId::parse(local_fmtp.parameter("profile-level-id")?)?;
    let remote = H264ProfileLevelId::parse(remote_fmtp.parameter("profile-level-id")?)?;
    let asymmetric = local_fmtp
        .parameter("level-asymmetry-allowed")
        .map(String::as_str)
        == Some("1")
        && remote_fmtp
            .parameter("level-asymmetry-allowed")
            .map(String::as_str)
            == Some("1");
    Some(if asymmetric || local.is_level_at_most(remote) {
        local
    } else {
        local.with_level(remote)
    })
}

pub(crate) fn answer_fmtp(local: &str, remote: &str) -> Option<String> {
    let profile = receive_level(local, remote)?;
    Some(
        local
            .split(';')
            .map(|part| {
                if part
                    .trim()
                    .split_once('=')
                    .is_some_and(|(key, _)| key.eq_ignore_ascii_case("profile-level-id"))
                {
                    format!("profile-level-id={profile}")
                } else {
                    part.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(";"),
    )
}

impl Fmtp for H264Fmtp {
    fn mime_type(&self) -> &str {
        "video/h264"
    }

    /// Match returns true if h and b are compatible fmtp descriptions
    /// Based on RFC6184 Section 8.2.2:
    ///   The parameters identifying a media format configuration for H.264
    ///   are profile-level-id and packetization-mode.  These media format
    ///   configuration parameters (except for the level part of profile-
    ///   level-id) MUST be used symmetrically; that is, the answerer MUST
    ///   either maintain all configuration parameters or remove the media
    ///   format (payload type) completely if one or more of the parameter
    ///   values are not supported.
    ///     Informative note: The requirement for symmetric use does not
    ///     apply for the level part of profile-level-id and does not apply
    ///     for the other stream properties and capability parameters.
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        if let Some(c) = f.as_any().downcast_ref::<H264Fmtp>() {
            // test packetization-mode
            let hpmode = match self.parameters.get("packetization-mode") {
                Some(s) => s,
                None => return false,
            };
            let cpmode = match c.parameters.get("packetization-mode") {
                Some(s) => s,
                None => return false,
            };

            if hpmode != cpmode {
                return false;
            }

            // test profile-level-id
            let hplid = match self.parameters.get("profile-level-id") {
                Some(s) => s,
                None => return false,
            };
            let cplid = match c.parameters.get("profile-level-id") {
                Some(s) => s,
                None => return false,
            };

            if !profile_level_id_matches(hplid, cplid) {
                return false;
            }

            true
        } else {
            false
        }
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<H264Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
