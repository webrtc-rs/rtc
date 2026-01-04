//! MediaStreamTrack Supported Constraints
//!
//! This module defines which constraints are supported by the user agent.
//!
//! # Specification
//!
//! See [MediaDevices.getSupportedConstraints()](https://www.w3.org/TR/mediacapture-streams/#dom-mediadevices-getsupportedconstraints).

/// Describes which constraints are supported by the user agent.
///
/// `MediaTrackSupportConstraints` indicates which constrainable properties
/// are understood by the user agent. This allows applications to detect
/// which constraints can be used before attempting to apply them.
///
/// Each field is `true` if the corresponding constraint is supported,
/// `false` otherwise.
///
/// # Specification
///
/// See [MediaTrackSupportedConstraints](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksupportedconstraints)
/// in the W3C Media Capture and Streams specification.
#[derive(Default, Debug, Clone)]
pub struct MediaTrackSupportConstraints {
    /// Whether the `width` constraint is supported.
    width: bool,

    /// Whether the `height` constraint is supported.
    height: bool,

    /// Whether the `aspectRatio` constraint is supported.
    aspect_ratio: bool,

    /// Whether the `frameRate` constraint is supported.
    frame_rate: bool,

    /// Whether the `facingMode` constraint is supported.
    facing_mode: bool,

    /// Whether the `resizeMode` constraint is supported.
    resize_mode: bool,

    /// Whether the `sampleRate` constraint is supported.
    sample_rate: bool,

    /// Whether the `sampleSize` constraint is supported.
    sample_size: bool,

    /// Whether the `echoCancellation` constraint is supported.
    echo_cancellation: bool,

    /// Whether the `autoGainControl` constraint is supported.
    auto_gain_control: bool,

    /// Whether the `noiseSuppression` constraint is supported.
    noise_suppression: bool,

    /// Whether the `latency` constraint is supported.
    latency: bool,

    /// Whether the `channelCount` constraint is supported.
    channel_count: bool,

    /// Whether the `deviceId` constraint is supported.
    device_id: bool,

    /// Whether the `groupId` constraint is supported.
    group_id: bool,

    /// Whether the `backgroundBlur` constraint is supported.
    background_blur: bool,
}
