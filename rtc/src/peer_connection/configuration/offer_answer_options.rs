/// Options for creating SDP answers.
///
/// Controls various aspects of the answer creation process, particularly
/// voice activity detection settings.
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::RTCAnswerOptions;
///
/// let options = RTCAnswerOptions {
///     voice_activity_detection: true,
/// };
/// ```
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct RTCAnswerOptions {
    /// Enable voice activity detection (VAD) for audio tracks.
    ///
    /// When enabled, silence detection can be used to reduce bandwidth
    /// by not transmitting during silent periods. This can save bandwidth
    /// but may affect audio quality perception.
    ///
    /// **Default:** `false`
    pub voice_activity_detection: bool,
}

/// Options for creating SDP offers.
///
/// Controls various aspects of the offer creation process, particularly
/// ICE restart behavior.
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::RTCOfferOptions;
///
/// // Create offer with ICE restart
/// let options = RTCOfferOptions {
///     ice_restart: true,
/// };
/// ```
///
/// ## Specifications
///
/// * [W3C RTCOfferOptions](https://w3c.github.io/webrtc-pc/#dictionary-rtcofferoptions-members)
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone)]
pub struct RTCOfferOptions {
    /// Force ICE restart with new credentials.
    ///
    /// When `true`, the generated offer will contain new ICE credentials,
    /// forcing the ICE agent to restart the gathering process. This is useful
    /// when network conditions change or to recover from connection failures.
    ///
    /// **Use when:**
    /// - Network conditions have changed (WiFi to cellular, VPN changes)
    /// - Connection has failed and needs recovery
    /// - Switching between networks
    ///
    /// **Default:** `false`
    pub ice_restart: bool,
}
