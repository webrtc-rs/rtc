#[cfg(test)]
mod h265_test;

use unicase::UniCase;

use super::*;

#[derive(Debug, PartialEq)]
pub(crate) struct H265Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

impl H265Fmtp {
    fn parameter_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.parameters.get(key).map_or(default, String::as_str)
    }
}

impl Fmtp for H265Fmtp {
    fn mime_type(&self) -> &str {
        "video/h265"
    }

    /// Match returns true if the two describe compatible H.265 media formats.
    /// draft-ietf-avtcore-hevc-webrtc-09 section 2.1 defines profile-id, tier-flag and tx-mode
    /// as the media format parameters for WebRTC.
    ///
    /// level-id is intentionally not compared, as W3C WebRTC candidate correction 52 requires:
    /// RFC 7798 section 7.2.2 permits an answer to lower it, so treating it as symmetric would
    /// reject a valid offer/answer exchange.
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        let Some(c) = f.as_any().downcast_ref::<H265Fmtp>() else {
            return false;
        };
        [("profile-id", "1"), ("tier-flag", "0"), ("tx-mode", "SRST")]
            .iter()
            .all(|(key, default)| {
                UniCase::new(self.parameter_or(key, default))
                    == UniCase::new(c.parameter_or(key, default))
            })
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<H265Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
