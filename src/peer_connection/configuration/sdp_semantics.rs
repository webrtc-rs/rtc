use std::fmt;

use serde::{Deserialize, Serialize};

/// SDP semantics determining the style of SDP offers and answers.
///
/// **Note:** This library only supports Unified Plan. Plan B is deprecated and
/// should not be used for new applications.
///
/// # Unified Plan vs Plan B
///
/// - **Unified Plan** - Modern standard (Chrome 72+, Firefox, Safari)
///   - One m= line per track
///   - Better simulcast support
///   - Simpler transcoding
///
/// - **Plan B** - Legacy format (deprecated)
///   - Multiple tracks per m= line
///   - Used by older Chrome versions
///   - Not recommended for new development
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::RTCSdpSemantics;
///
/// // This library only supports Unified Plan
/// let semantics = RTCSdpSemantics::UnifiedPlan;
/// assert_eq!(semantics.to_string(), "unified-plan");
/// ```
///
/// ## Specifications
///
/// * [Unified Plan](https://tools.ietf.org/html/draft-roach-mmusic-unified-plan-00)
/// * [Plan B (deprecated)](https://tools.ietf.org/html/draft-uberti-rtcweb-plan-00)
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum RTCSdpSemantics {
    /// Unspecified - not a valid semantic
    Unspecified = 0,

    /// Unified Plan - modern SDP format (default and recommended).
    ///
    /// Uses one m= line per media track, which provides:
    /// - Better support for simulcast
    /// - Easier transcoding
    /// - Clearer SDP structure
    ///
    /// This is the default in Chrome 72+, Firefox, and Safari.
    #[serde(rename = "unified-plan")]
    #[default]
    UnifiedPlan = 1,

    /// Plan B - legacy SDP format (deprecated, do not use).
    ///
    /// Uses one m= line per media type with multiple SSRCs. This format
    /// is deprecated and should not be used in new applications.
    #[serde(rename = "plan-b")]
    PlanB = 2,

    /// Unified Plan with Plan B fallback (not recommended).
    ///
    /// Prefers Unified Plan but will respond to Plan B offers with Plan B answers.
    /// This is not recommended for new applications.
    #[serde(rename = "unified-plan-with-fallback")]
    UnifiedPlanWithFallback = 3,
}

const SDP_SEMANTICS_UNIFIED_PLAN_WITH_FALLBACK: &str = "unified-plan-with-fallback";
const SDP_SEMANTICS_UNIFIED_PLAN: &str = "unified-plan";
const SDP_SEMANTICS_PLAN_B: &str = "plan-b";

impl From<&str> for RTCSdpSemantics {
    fn from(raw: &str) -> Self {
        match raw {
            SDP_SEMANTICS_UNIFIED_PLAN_WITH_FALLBACK => RTCSdpSemantics::UnifiedPlanWithFallback,
            SDP_SEMANTICS_UNIFIED_PLAN => RTCSdpSemantics::UnifiedPlan,
            SDP_SEMANTICS_PLAN_B => RTCSdpSemantics::PlanB,
            _ => RTCSdpSemantics::Unspecified,
        }
    }
}

impl fmt::Display for RTCSdpSemantics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCSdpSemantics::UnifiedPlanWithFallback => SDP_SEMANTICS_UNIFIED_PLAN_WITH_FALLBACK,
            RTCSdpSemantics::UnifiedPlan => SDP_SEMANTICS_UNIFIED_PLAN,
            RTCSdpSemantics::PlanB => SDP_SEMANTICS_PLAN_B,
            RTCSdpSemantics::Unspecified => crate::peer_connection::configuration::UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use sdp::description::media::MediaDescription;
    use sdp::description::session::{ATTR_KEY_SSRC, SessionDescription};

    use super::*;

    #[test]
    fn test_sdp_semantics_string() {
        let tests = vec![
            (RTCSdpSemantics::Unspecified, "Unspecified"),
            (
                RTCSdpSemantics::UnifiedPlanWithFallback,
                "unified-plan-with-fallback",
            ),
            (RTCSdpSemantics::PlanB, "plan-b"),
            (RTCSdpSemantics::UnifiedPlan, "unified-plan"),
        ];

        for (value, expected_string) in tests {
            assert_eq!(value.to_string(), expected_string);
        }
    }

    // The following tests are for non-standard SDP semantics
    // (i.e. not unified-unified)
    fn get_md_names(sdp: &SessionDescription) -> Vec<String> {
        sdp.media_descriptions
            .iter()
            .map(|md| md.media_name.media.clone())
            .collect()
    }

    fn extract_ssrc_list(md: &MediaDescription) -> Vec<String> {
        let mut ssrcs = HashSet::new();
        for attr in &md.attributes {
            if attr.key == ATTR_KEY_SSRC {
                if let Some(value) = &attr.value {
                    let fields: Vec<&str> = value.split_whitespace().collect();
                    if let Some(ssrc) = fields.first() {
                        ssrcs.insert(*ssrc);
                    }
                }
            }
        }
        ssrcs
            .into_iter()
            .map(|ssrc| ssrc.to_owned())
            .collect::<Vec<String>>()
    }
}
