use serde::{Deserialize, Serialize};

/// ICEParameters includes the ICE username fragment
/// and password and other ICE-related parameters.
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCIceParameters
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtciceparameters
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTCIceParameters {
    /// The ICE username fragment used for authentication.
    pub username_fragment: String,
    /// The ICE password used for authentication.
    pub password: String,
    /// Whether the remote peer is running in ICE Lite mode.
    pub ice_lite: bool,
}
