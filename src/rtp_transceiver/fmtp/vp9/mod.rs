#[cfg(test)]
mod vp9_test;

use super::*;

#[derive(Debug, PartialEq)]
pub(crate) struct Vp9Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

impl Fmtp for Vp9Fmtp {
    fn mime_type(&self) -> &str {
        "video/vp9"
    }

    /// RTP Payload Format for VP9 Video (draft-ietf-payload-vp9-16): if no profile-id is
    /// present, Profile 0 MUST be inferred.
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        let Some(c) = f.as_any().downcast_ref::<Vp9Fmtp>() else {
            return false;
        };
        let profile = |p: &Vp9Fmtp| p.parameters.get("profile-id").cloned();
        profile(self).unwrap_or_else(|| "0".to_owned())
            == profile(c).unwrap_or_else(|| "0".to_owned())
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<Vp9Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
