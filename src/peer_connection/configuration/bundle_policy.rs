use std::fmt;

use serde::{Deserialize, Serialize};

/// Media bundling policy for ICE candidate gathering and transport usage.
///
/// Bundle policy determines how media tracks are multiplexed onto ICE transports
/// when the remote endpoint may or may not support bundling. Bundling multiple
/// media streams onto a single transport reduces overhead and improves performance.
///
/// # Recommendations
///
/// - **MaxBundle** - Recommended for modern WebRTC (Chrome/Firefox/Safari all support it)
/// - **Balanced** - Good fallback for legacy compatibility
/// - **MaxCompat** - Only use if connecting to very old implementations
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCBundlePolicy};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Recommended: Use max-bundle for best performance
/// let config = RTCConfigurationBuilder::new()
///     .with_bundle_policy(RTCBundlePolicy::MaxBundle)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Specifications
///
/// * [W3C RTCBundlePolicy](https://w3c.github.io/webrtc-pc/#rtcbundlepolicy-enum)
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub enum RTCBundlePolicy {
    /// Unspecified - not a valid policy, used as default value
    #[default]
    Unspecified = 0,

    /// Gather ICE candidates for each media type (audio, video, data).
    ///
    /// If the remote endpoint is not bundle-aware, negotiate only one audio
    /// and one video track on separate transports. This provides a balance
    /// between compatibility and efficiency.
    ///
    /// **Use when:** Connecting to peers that may not support bundling
    #[serde(rename = "balanced")]
    Balanced = 1,

    /// Gather ICE candidates for each track individually.
    ///
    /// If the remote endpoint is not bundle-aware, negotiate all media tracks
    /// on separate transports. This maximizes compatibility at the cost of
    /// performance and resource usage.
    ///
    /// **Use when:** Maximum compatibility with legacy systems is required
    #[serde(rename = "max-compat")]
    MaxCompat = 2,

    /// Gather ICE candidates for only one track (recommended).
    ///
    /// All media is bundled onto a single transport. If the remote endpoint
    /// is not bundle-aware, only negotiate one media track. This provides
    /// the best performance by minimizing overhead.
    ///
    /// **Use when:** Connecting to modern WebRTC implementations (recommended)
    #[serde(rename = "max-bundle")]
    MaxBundle = 3,
}

/// This is done this way because of a linter.
const BUNDLE_POLICY_BALANCED_STR: &str = "balanced";
const BUNDLE_POLICY_MAX_COMPAT_STR: &str = "max-compat";
const BUNDLE_POLICY_MAX_BUNDLE_STR: &str = "max-bundle";

impl From<&str> for RTCBundlePolicy {
    /// NewSchemeType defines a procedure for creating a new SchemeType from a raw
    /// string naming the scheme type.
    fn from(raw: &str) -> Self {
        match raw {
            BUNDLE_POLICY_BALANCED_STR => RTCBundlePolicy::Balanced,
            BUNDLE_POLICY_MAX_COMPAT_STR => RTCBundlePolicy::MaxCompat,
            BUNDLE_POLICY_MAX_BUNDLE_STR => RTCBundlePolicy::MaxBundle,
            _ => RTCBundlePolicy::Unspecified,
        }
    }
}

impl fmt::Display for RTCBundlePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCBundlePolicy::Balanced => write!(f, "{BUNDLE_POLICY_BALANCED_STR}"),
            RTCBundlePolicy::MaxCompat => write!(f, "{BUNDLE_POLICY_MAX_COMPAT_STR}"),
            RTCBundlePolicy::MaxBundle => write!(f, "{BUNDLE_POLICY_MAX_BUNDLE_STR}"),
            _ => write!(
                f,
                "{}",
                crate::peer_connection::configuration::UNSPECIFIED_STR
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_bundle_policy() {
        let tests = vec![
            ("Unspecified", RTCBundlePolicy::Unspecified),
            ("balanced", RTCBundlePolicy::Balanced),
            ("max-compat", RTCBundlePolicy::MaxCompat),
            ("max-bundle", RTCBundlePolicy::MaxBundle),
        ];

        for (policy_string, expected_policy) in tests {
            assert_eq!(RTCBundlePolicy::from(policy_string), expected_policy);
        }
    }

    #[test]
    fn test_bundle_policy_string() {
        let tests = vec![
            (RTCBundlePolicy::Unspecified, "Unspecified"),
            (RTCBundlePolicy::Balanced, "balanced"),
            (RTCBundlePolicy::MaxCompat, "max-compat"),
            (RTCBundlePolicy::MaxBundle, "max-bundle"),
        ];

        for (policy, expected_string) in tests {
            assert_eq!(policy.to_string(), expected_string);
        }
    }
}
