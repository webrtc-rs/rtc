//! MediaStreamTrack Capabilities
//!
//! This module defines the capabilities that a [`MediaStreamTrack`](super::MediaStreamTrack)
//! can support, representing the inherent properties of the track's underlying source.
//!
//! Capabilities describe what a track *can* do, such as supported resolution ranges,
//! frame rates, audio features, etc., as determined by the hardware or media source.
//!
//! # Specification
//!
//! See [MediaStreamTrack.getCapabilities()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-getcapabilities).

use std::collections::HashSet;

/// Represents a range of numeric values with minimum and maximum bounds.
///
/// Used to express the range of supported values for capabilities like
/// width, height, frame rate, sample rate, etc.
///
/// # Specification
///
/// See [CapabilityRange](https://www.w3.org/TR/mediacapture-streams/#dfn-capabilityrange).
#[derive(Default, Debug, Clone)]
pub(crate) struct Range<T> {
    /// Maximum supported value.
    pub(crate) max: T,
    /// Minimum supported value.
    pub(crate) min: T,
}

/// Describes the capabilities of a media stream track.
///
/// `MediaTrackCapabilities` represents the inherent properties and supported
/// values of a track's underlying source. These are determined by the
/// hardware capabilities and cannot be changed by the application.
///
/// For video tracks, capabilities include supported resolutions, frame rates,
/// and facing modes. For audio tracks, they include sample rates, channel counts,
/// and audio processing features.
///
/// # Specification
///
/// See [MediaTrackCapabilities](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities)
/// in the W3C Media Capture and Streams specification.
///
/// # Examples
///
/// ```
/// use rtc::media_stream::MediaTrackCapabilities;
///
/// # fn example(track: rtc::media_stream::MediaStreamTrack) {
/// let capabilities = track.get_capabilities();
/// // Inspect what the track source supports
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct MediaTrackCapabilities {
    /// Supported video width range in pixels.
    ///
    /// # Specification
    ///
    /// See [width](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-width).
    width: Range<u32>,

    /// Supported video height range in pixels.
    ///
    /// # Specification
    ///
    /// See [height](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-height).
    height: Range<u32>,

    /// Supported aspect ratio range.
    ///
    /// Aspect ratio is the ratio of width to height (e.g., 16/9 ≈ 1.778).
    ///
    /// # Specification
    ///
    /// See [aspectRatio](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-aspectratio).
    aspect_ratio: Range<f64>,

    /// Supported frame rate range in frames per second.
    ///
    /// # Specification
    ///
    /// See [frameRate](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-framerate).
    frame_rate: Range<f64>,

    /// Supported camera facing modes.
    ///
    /// Values may include "user" (front-facing), "environment" (back-facing),
    /// "left", or "right".
    ///
    /// # Specification
    ///
    /// See [facingMode](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-facingmode).
    facing_mode: Vec<String>,

    /// Supported resize modes for video.
    ///
    /// Values may include "none" or "crop-and-scale".
    ///
    /// # Specification
    ///
    /// See [resizeMode](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-resizemode).
    resize_mode: Vec<String>,

    /// Supported audio sample rate range in samples per second (Hz).
    ///
    /// Common values include 8000, 16000, 44100, 48000 Hz.
    ///
    /// # Specification
    ///
    /// See [sampleRate](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-samplerate).
    sample_rate: Range<u32>,

    /// Supported audio sample size range in bits.
    ///
    /// Common values include 8, 16, 24, 32 bits.
    ///
    /// # Specification
    ///
    /// See [sampleSize](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-samplesize).
    sample_size: Range<u32>,

    /// Supported echo cancellation states.
    ///
    /// Contains `true` if echo cancellation is supported, `false` if it's not,
    /// or both if it can be enabled or disabled.
    ///
    /// # Specification
    ///
    /// See [echoCancellation](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-echocancellation).
    echo_cancellation: HashSet<bool>,

    /// Supported automatic gain control states.
    ///
    /// Contains `true` if AGC is supported, `false` if it's not,
    /// or both if it can be enabled or disabled.
    ///
    /// # Specification
    ///
    /// See [autoGainControl](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-autogaincontrol).
    auto_gain_control: HashSet<bool>,

    /// Supported noise suppression states.
    ///
    /// Contains `true` if noise suppression is supported, `false` if it's not,
    /// or both if it can be enabled or disabled.
    ///
    /// # Specification
    ///
    /// See [noiseSuppression](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-noisesuppression).
    noise_suppression: HashSet<bool>,

    /// Supported latency range in seconds.
    ///
    /// Represents the delay between capture and availability for processing.
    ///
    /// # Specification
    ///
    /// See [latency](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-latency).
    latency: Range<f64>,

    /// Supported audio channel count range.
    ///
    /// Common values include 1 (mono), 2 (stereo), or more for surround sound.
    ///
    /// # Specification
    ///
    /// See [channelCount](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-channelcount).
    channel_count: Range<u32>,

    /// Device identifier string.
    ///
    /// # Specification
    ///
    /// See [deviceId](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-deviceid).
    device_id: String,

    /// Group identifier for related devices.
    ///
    /// Devices that belong to the same physical hardware share the same group ID.
    ///
    /// # Specification
    ///
    /// See [groupId](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackcapabilities-groupid).
    group_id: String,

    /// Supported background blur states.
    ///
    /// Contains `true` if background blur is supported, `false` if it's not,
    /// or both if it can be enabled or disabled.
    background_blur: HashSet<bool>,
}
