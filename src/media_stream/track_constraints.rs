//! MediaStreamTrack Constraints
//!
//! This module defines constraints that can be applied to a [`MediaStreamTrack`](super::MediaStreamTrack)
//! to control its behavior and output characteristics.
//!
//! Constraints allow applications to specify required, ideal, or acceptable values
//! for track properties. The user agent attempts to satisfy these constraints based
//! on hardware capabilities and system conditions.
//!
//! # Specification
//!
//! See [MediaStreamTrack.applyConstraints()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-applyconstraints).

/// Represents a range of numeric values with constraints.
///
/// Used to specify acceptable ranges and ideal/exact values for constrainable
/// properties like width, height, frame rate, etc.
///
/// # Specification
///
/// See [ConstrainULongRange](https://www.w3.org/TR/mediacapture-streams/#dom-constrainulongrange)
/// and related constraint range types.
#[derive(Default, Debug, Clone)]
pub(crate) struct ConstrainRange<T> {
    /// Maximum acceptable value.
    pub(crate) max: T,
    /// Minimum acceptable value.
    pub(crate) min: T,
    /// Exact required value. If set, only this value is acceptable.
    pub(crate) exact: T,
    /// Ideal target value. The user agent will try to get as close as possible.
    pub(crate) ideal: T,
}

/// Represents a constraint that can be either a single value or a range.
///
/// # Specification
///
/// See [Constrainable properties](https://www.w3.org/TR/mediacapture-streams/#constrainable-properties).
#[derive(Debug, Clone)]
pub(crate) enum Constrain<T> {
    /// A single value constraint.
    Value(T),
    /// A range-based constraint with min, max, exact, and ideal values.
    Range(ConstrainRange<T>),
}

/// A set of constraints for a media track.
///
/// `MediaTrackConstraintSet` defines constraints for various track properties.
/// These constraints guide the user agent in configuring the track to meet
/// application requirements.
///
/// # Specification
///
/// See [MediaTrackConstraintSet](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackconstraintset)
/// in the W3C Media Capture and Streams specification.
#[derive(Debug, Clone)]
pub struct MediaTrackConstraintSet {
    /// Video width constraint in pixels.
    ///
    /// # Specification
    ///
    /// See [width](https://www.w3.org/TR/mediacapture-streams/#def-constraint-width).
    width: Constrain<u32>,

    /// Video height constraint in pixels.
    ///
    /// # Specification
    ///
    /// See [height](https://www.w3.org/TR/mediacapture-streams/#def-constraint-height).
    height: Constrain<u32>,

    /// Aspect ratio constraint (width/height).
    ///
    /// # Specification
    ///
    /// See [aspectRatio](https://www.w3.org/TR/mediacapture-streams/#def-constraint-aspectRatio).
    aspect_ratio: Constrain<f64>,

    /// Frame rate constraint in frames per second.
    ///
    /// # Specification
    ///
    /// See [frameRate](https://www.w3.org/TR/mediacapture-streams/#def-constraint-frameRate).
    frame_rate: Constrain<f64>,

    /// Camera facing mode constraint.
    ///
    /// Values: "user" (front), "environment" (back), "left", "right".
    ///
    /// # Specification
    ///
    /// See [facingMode](https://www.w3.org/TR/mediacapture-streams/#def-constraint-facingMode).
    facing_mode: Constrain<String>,

    /// Resize mode constraint for video processing.
    ///
    /// Values: "none", "crop-and-scale".
    ///
    /// # Specification
    ///
    /// See [resizeMode](https://www.w3.org/TR/mediacapture-streams/#def-constraint-resizeMode).
    resize_mode: Constrain<String>,

    /// Audio sample rate constraint in Hz.
    ///
    /// # Specification
    ///
    /// See [sampleRate](https://www.w3.org/TR/mediacapture-streams/#def-constraint-sampleRate).
    sample_rate: Constrain<u32>,

    /// Audio sample size constraint in bits.
    ///
    /// # Specification
    ///
    /// See [sampleSize](https://www.w3.org/TR/mediacapture-streams/#def-constraint-sampleSize).
    sample_size: Constrain<u32>,

    /// Echo cancellation constraint.
    ///
    /// # Specification
    ///
    /// See [echoCancellation](https://www.w3.org/TR/mediacapture-streams/#def-constraint-echoCancellation).
    echo_cancellation: Constrain<bool>,

    /// Automatic gain control constraint.
    ///
    /// # Specification
    ///
    /// See [autoGainControl](https://www.w3.org/TR/mediacapture-streams/#def-constraint-autoGainControl).
    auto_gain_control: Constrain<bool>,

    /// Noise suppression constraint.
    ///
    /// # Specification
    ///
    /// See [noiseSuppression](https://www.w3.org/TR/mediacapture-streams/#def-constraint-noiseSuppression).
    noise_suppression: Constrain<bool>,

    /// Latency constraint in seconds.
    ///
    /// # Specification
    ///
    /// See [latency](https://www.w3.org/TR/mediacapture-streams/#def-constraint-latency).
    latency: Constrain<f64>,

    /// Audio channel count constraint.
    ///
    /// # Specification
    ///
    /// See [channelCount](https://www.w3.org/TR/mediacapture-streams/#def-constraint-channelCount).
    channel_count: Constrain<u32>,

    /// Device identifier constraint.
    ///
    /// # Specification
    ///
    /// See [deviceId](https://www.w3.org/TR/mediacapture-streams/#def-constraint-deviceId).
    device_id: Constrain<String>,

    /// Group identifier constraint.
    ///
    /// # Specification
    ///
    /// See [groupId](https://www.w3.org/TR/mediacapture-streams/#def-constraint-groupId).
    group_id: Constrain<String>,

    /// Background blur constraint.
    background_blur: Constrain<bool>,
}

impl Default for MediaTrackConstraintSet {
    fn default() -> Self {
        Self {
            width: Constrain::Value(0),
            height: Constrain::Value(0),
            aspect_ratio: Constrain::Value(0.0),
            frame_rate: Constrain::Value(0.0),
            facing_mode: Constrain::Value("".to_string()),
            resize_mode: Constrain::Value("".to_string()),
            sample_rate: Constrain::Value(0),
            sample_size: Constrain::Value(0),
            echo_cancellation: Constrain::Value(false),
            auto_gain_control: Constrain::Value(false),
            noise_suppression: Constrain::Value(false),
            latency: Constrain::Value(0.0),
            channel_count: Constrain::Value(0),
            device_id: Constrain::Value("".to_string()),
            group_id: Constrain::Value("".to_string()),
            background_blur: Constrain::Value(false),
        }
    }
}

/// Constraints to apply to a media track.
///
/// `MediaTrackConstraints` consists of a basic constraint set and an optional
/// list of advanced constraint sets. The user agent will try to satisfy the
/// basic constraints and as many advanced constraints as possible.
///
/// # Specification
///
/// See [MediaTrackConstraints](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackconstraints)
/// in the W3C Media Capture and Streams specification.
///
/// # Examples
///
/// ```
/// use rtc::media_stream::MediaTrackConstraints;
/// use rtc::media_stream::MediaStreamTrack;
///
/// # fn example(mut track: MediaStreamTrack) {
/// // Create constraints
/// let constraints = MediaTrackConstraints::default();
///
/// // Apply to track
/// track.apply_constraints(Some(constraints));
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct MediaTrackConstraints {
    /// Basic constraint set that should be satisfied if possible.
    ///
    /// # Specification
    ///
    /// See [MediaTrackConstraints](https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackconstraints).
    basic: MediaTrackConstraintSet,

    /// Advanced constraint sets applied in order.
    ///
    /// The user agent will try to satisfy as many of these as possible,
    /// in the order they are specified.
    ///
    /// # Specification
    ///
    /// See [advanced](https://www.w3.org/TR/mediacapture-streams/#dfn-advanced).
    advanced: Vec<MediaTrackConstraintSet>,
}
