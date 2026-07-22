//! MediaStreamTrack Settings
//!
//! This module defines the actual settings currently in effect for a
//! [`MediaStreamTrack`](super::MediaStreamTrack).
//!
//! Settings represent the current configuration values of a track, which may
//! differ from requested constraints based on hardware limitations and system
//! conditions.
//!
//! # Specification
//!
//! See [MediaStreamTrack.getSettings()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-getsettings).

/// Represents the actual settings of a media track.
///
/// `MediaTrackSettings` contains the current values of all constrainable properties
/// of a track. These values reflect what the track is actually producing, which may
/// differ from what was requested via constraints.
///
/// # Specification
///
/// See [MediaTrackSettings](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings)
/// in the W3C Media Capture and Streams specification.
///
/// # Examples
///
/// ```
/// use rtc::media_stream::MediaStreamTrack;
///
/// # fn example(track: MediaStreamTrack) {
/// let settings = track.get_settings();
/// // Inspect actual track settings
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct MediaTrackSettings {
    /// Actual video width in pixels.
    ///
    /// # Specification
    ///
    /// See [width](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-width).
    width: u32,

    /// Actual video height in pixels.
    ///
    /// # Specification
    ///
    /// See [height](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-height).
    height: u32,

    /// Actual aspect ratio (width/height).
    ///
    /// # Specification
    ///
    /// See [aspectRatio](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-aspectratio).
    aspect_ratio: f64,

    /// Actual frame rate in frames per second.
    ///
    /// # Specification
    ///
    /// See [frameRate](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-framerate).
    frame_rate: f64,

    /// Actual camera facing mode.
    ///
    /// Values: "user", "environment", "left", "right".
    ///
    /// # Specification
    ///
    /// See [facingMode](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-facingmode).
    facing_mode: String,

    /// Actual resize mode.
    ///
    /// Values: "none", "crop-and-scale".
    ///
    /// # Specification
    ///
    /// See [resizeMode](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-resizemode).
    resize_mode: String,

    /// Actual audio sample rate in Hz.
    ///
    /// # Specification
    ///
    /// See [sampleRate](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-samplerate).
    sample_rate: u32,

    /// Actual audio sample size in bits.
    ///
    /// # Specification
    ///
    /// See [sampleSize](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-samplesize).
    sample_size: u32,

    /// Whether echo cancellation is currently enabled.
    ///
    /// # Specification
    ///
    /// See [echoCancellation](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-echocancellation).
    echo_cancellation: bool,

    /// Whether automatic gain control is currently enabled.
    ///
    /// # Specification
    ///
    /// See [autoGainControl](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-autogaincontrol).
    auto_gain_control: bool,

    /// Whether noise suppression is currently enabled.
    ///
    /// # Specification
    ///
    /// See [noiseSuppression](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-noisesuppression).
    noise_suppression: bool,

    /// Actual latency in seconds.
    ///
    /// Represents the delay between capture and availability for processing.
    ///
    /// # Specification
    ///
    /// See [latency](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-latency).
    latency: f64,

    /// Actual audio channel count.
    ///
    /// # Specification
    ///
    /// See [channelCount](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-channelcount).
    channel_count: u32,

    /// Device identifier.
    ///
    /// # Specification
    ///
    /// See [deviceId](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-deviceid).
    device_id: String,

    /// Group identifier.
    ///
    /// # Specification
    ///
    /// See [groupId](https://www.w3.org/TR/mediacapture-streams/#dom-mediatracksettings-groupid).
    group_id: String,

    /// Whether background blur is currently enabled.
    background_blur: bool,
}
