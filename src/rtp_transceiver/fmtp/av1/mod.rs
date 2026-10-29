#[cfg(test)]
mod av1_test;

use super::*;

#[derive(Debug, PartialEq)]
pub(crate) struct Av1Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

impl Fmtp for Av1Fmtp {
    fn mime_type(&self) -> &str {
        "video/av1"
    }

    /// RTP Payload Format For AV1 (v1.0): if the profile parameter is not present, it MUST be
    /// inferred to be 0 ("Main" profile).
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        let Some(c) = f.as_any().downcast_ref::<Av1Fmtp>() else {
            return false;
        };
        let profile = |p: &Av1Fmtp| p.parameters.get("profile").cloned();
        profile(self).unwrap_or_else(|| "0".to_owned())
            == profile(c).unwrap_or_else(|| "0".to_owned())
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<Av1Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
