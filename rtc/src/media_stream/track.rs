//! MediaStreamTrack API
//!
//! This module implements the `MediaStreamTrack` interface as defined in the
//! [W3C Media Capture and Streams specification](https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack).
//!
//! A [`MediaStreamTrack`] represents a single media track within a media stream, such as
//! an audio track from a microphone or a video track from a camera. Each track has properties
//! like enabled/disabled state, mute status, and lifecycle state (live or ended).
//!
//! # Examples
//!
//! ## Creating a video track
//!
//! ```
//! use rtc::media_stream::MediaStreamTrack;
//! use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
//! use rtc::peer_connection::configuration::media_engine::MIME_TYPE_VP8;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let codec = RTCRtpCodec {
//!     mime_type: MIME_TYPE_VP8.to_string(),
//!     clock_rate: 90000,
//!     channels: 0,
//!     sdp_fmtp_line: String::new(),
//!     rtcp_feedback: vec![],
//! };
//!
//! let video_track = MediaStreamTrack::new(
//!     "stream-123".to_string(),
//!     "track-456".to_string(),
//!     "Front Camera".to_string(),
//!     RtpCodecKind::Video,
//!     None, // rid (for simulcast)
//!     789012, // SSRC
//!     codec,
//! );
//!
//! assert_eq!(video_track.kind(), RtpCodecKind::Video);
//! assert_eq!(video_track.label(), "Front Camera");
//! assert!(video_track.enabled());
//! # Ok(())
//! # }
//! ```
//!
//! ## Controlling track state
//!
//! ```
//! # use rtc::media_stream::MediaStreamTrack;
//! # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
//! # fn example(mut track: MediaStreamTrack) {
//! // Disable the track temporarily
//! track.set_enabled(false);
//! assert!(!track.enabled());
//!
//! // Re-enable the track
//! track.set_enabled(true);
//! assert!(track.enabled());
//!
//! // Stop the track permanently
//! track.stop();
//! # }
//! ```
//!
//! # Specifications
//!
//! - [W3C MediaStreamTrack](https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack)
//! - [MDN MediaStreamTrack](https://developer.mozilla.org/en-US/docs/Web/API/MediaStreamTrack)

use crate::media_stream::MediaStreamId;
use crate::media_stream::track_capabilities::MediaTrackCapabilities;
use crate::media_stream::track_constraints::MediaTrackConstraints;
use crate::media_stream::track_settings::MediaTrackSettings;
use crate::media_stream::track_state::MediaStreamTrackState;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};

/// Unique identifier for a media stream track.
///
/// As defined in [MediaStreamTrack.id](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-id).
pub type MediaStreamTrackId = String;

/// Represents a single media track within a media stream.
///
/// A `MediaStreamTrack` represents an audio or video track from a media source.
/// Each track has a unique identifier, a label (human-readable name), a kind
/// (audio or video), and various state attributes.
///
/// The track can be enabled/disabled, muted/unmuted, and has a lifecycle state
/// that progresses from "live" to "ended". Once ended, a track cannot be restarted.
///
/// # Specification
///
/// See [MediaStreamTrack](https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack)
/// in the W3C Media Capture and Streams specification.
///
/// # Examples
///
/// ```
/// use rtc::media_stream::MediaStreamTrack;
/// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let track = MediaStreamTrack::new(
///     "stream-id".to_string(),
///     "track-id".to_string(),
///     "Microphone".to_string(),
///     RtpCodecKind::Audio,
///     None,
///     12345,
///     RTCRtpCodec::default(),
/// );
///
/// assert_eq!(track.kind(), RtpCodecKind::Audio);
/// assert_eq!(track.label(), "Microphone");
/// assert!(track.enabled());
/// assert!(!track.muted());
/// # Ok(())
/// # }
/// ```
#[derive(Default, Debug, Clone)]
pub struct MediaStreamTrack {
    stream_id: MediaStreamId,
    track_id: MediaStreamTrackId,
    label: String,
    kind: RtpCodecKind,
    rid: Option<String>,
    ssrc: SSRC,
    codec: RTCRtpCodec,

    muted: bool,
    enabled: bool,
    ready_state: MediaStreamTrackState,
    restrictable: bool,
    capabilities: MediaTrackCapabilities,
    constraints: MediaTrackConstraints,
    settings: MediaTrackSettings,
}

impl MediaStreamTrack {
    /// Creates a new media stream track.
    ///
    /// # Parameters
    ///
    /// * `stream_id` - The ID of the [`MediaStream`](crate::media_stream::MediaStream) this track belongs to
    /// * `track_id` - A unique identifier for this track (typically a UUID)
    /// * `label` - A human-readable label for the track (e.g., "Built-in Microphone")
    /// * `kind` - The kind of media: [`Audio`](RtpCodecKind::Audio) or [`Video`](RtpCodecKind::Video)
    /// * `rid` - Optional RTP stream ID for simulcast or SVC
    /// * `ssrc` - The synchronization source identifier for RTP
    /// * `codec` - The RTP codec configuration for this track
    ///
    /// # Returns
    ///
    /// A new `MediaStreamTrack` initialized with the provided parameters. The track
    /// starts in the "live" state, enabled, and unmuted.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack](https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack).
    ///
    /// # Examples
    ///
    /// ```
    /// use rtc::media_stream::MediaStreamTrack;
    /// use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// use rtc::peer_connection::configuration::media_engine::MIME_TYPE_OPUS;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let codec = RTCRtpCodec {
    ///     mime_type: MIME_TYPE_OPUS.to_string(),
    ///     clock_rate: 48000,
    ///     channels: 2,
    ///     sdp_fmtp_line: String::new(),
    ///     rtcp_feedback: vec![],
    /// };
    ///
    /// let audio_track = MediaStreamTrack::new(
    ///     "my-stream".to_string(),
    ///     "audio-1".to_string(),
    ///     "Built-in Microphone".to_string(),
    ///     RtpCodecKind::Audio,
    ///     None,
    ///     123456,
    ///     codec,
    /// );
    ///
    /// assert_eq!(audio_track.track_id(), "audio-1");
    /// assert_eq!(audio_track.label(), "Built-in Microphone");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        stream_id: MediaStreamId,
        track_id: MediaStreamTrackId,
        label: String,
        kind: RtpCodecKind,
        rid: Option<String>,
        ssrc: SSRC,
        codec: RTCRtpCodec,
    ) -> Self {
        Self {
            stream_id,
            track_id,
            label,
            rid,
            ssrc,
            kind,
            codec,

            muted: false,
            enabled: true,
            ready_state: MediaStreamTrackState::Live,
            restrictable: false,

            ..Default::default()
        }
    }

    /// Returns the stream ID this track belongs to.
    ///
    /// # Specification
    ///
    /// Related to [MediaStream.id](https://www.w3.org/TR/mediacapture-streams/#dom-mediastream-id).
    pub fn stream_id(&self) -> &MediaStreamId {
        &self.stream_id
    }

    /// Returns the unique identifier of this track.
    ///
    /// The identifier is a 36-character Universally Unique Identifier (UUID)
    /// assigned when the track is created and remains constant throughout
    /// the track's lifetime.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.id](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-id).
    pub fn track_id(&self) -> &MediaStreamTrackId {
        &self.track_id
    }

    /// Returns the human-readable label of this track.
    ///
    /// The label is a user-agent assigned string that identifies the track source.
    /// For example, "Internal Microphone" or "FaceTime HD Camera".
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.label](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-label).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(track: MediaStreamTrack) {
    /// println!("Track label: {}", track.label());
    /// # }
    /// ```
    pub fn label(&self) -> &String {
        &self.label
    }

    /// Returns the kind of media this track represents.
    ///
    /// Returns either [`RtpCodecKind::Audio`] for audio tracks or
    /// [`RtpCodecKind::Video`] for video tracks.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.kind](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-kind).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(track: MediaStreamTrack) {
    /// match track.kind() {
    ///     RtpCodecKind::Audio => println!("This is an audio track"),
    ///     RtpCodecKind::Video => println!("This is a video track"),
    ///     _ => {},
    /// }
    /// # }
    /// ```
    pub fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    /// Returns the RTP stream ID (rid) if this track is part of a simulcast or SVC configuration.
    ///
    /// The rid (restriction identifier) is used to identify different encodings of the
    /// same media source in simulcast scenarios.
    ///
    /// # Returns
    ///
    /// Returns `Some(&str)` if a rid is set, or `None` for non-simulcast tracks.
    ///
    /// # Specification
    ///
    /// See [RFC 8851 - RTP Payload Format Restrictions](https://www.rfc-editor.org/rfc/rfc8851.html).
    pub fn rid(&self) -> Option<&str> {
        self.rid.as_deref()
    }

    /// Returns the Synchronization Source (SSRC) identifier for this track.
    ///
    /// The SSRC is a 32-bit identifier used in RTP to distinguish different
    /// media sources within a session.
    ///
    /// # Specification
    ///
    /// See [RFC 3550 - RTP: A Transport Protocol for Real-Time Applications](https://www.rfc-editor.org/rfc/rfc3550.html#section-5.1).
    pub fn ssrc(&self) -> SSRC {
        self.ssrc
    }

    /// Returns the RTP codec configuration for this track.
    ///
    /// The codec defines the media encoding format, clock rate, channels, and
    /// other codec-specific parameters.
    pub fn codec(&self) -> &RTCRtpCodec {
        &self.codec
    }

    /// Returns whether this track is enabled.
    ///
    /// When a track is disabled, it produces silence (for audio) or black frames (for video),
    /// but remains live and connected. This is useful for temporarily stopping media flow
    /// without tearing down the connection.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.enabled](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-enabled).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(track: MediaStreamTrack) {
    /// if track.enabled() {
    ///     println!("Track is producing media");
    /// } else {
    ///     println!("Track is disabled");
    /// }
    /// # }
    /// ```
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Sets whether this track is enabled.
    ///
    /// Disabling a track causes it to produce silence (audio) or black frames (video).
    /// This is reversible - enabling the track again resumes normal media flow.
    ///
    /// # Parameters
    ///
    /// * `enabled` - `true` to enable the track, `false` to disable it
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.enabled](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-enabled).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(mut track: MediaStreamTrack) {
    /// // Temporarily disable the track
    /// track.set_enabled(false);
    ///
    /// // Later, re-enable it
    /// track.set_enabled(true);
    /// # }
    /// ```
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns whether this track is muted.
    ///
    /// A muted track is unable to provide media data due to technical limitations,
    /// such as hardware issues or permission denials. Unlike [`enabled`](Self::enabled),
    /// which is under application control, muting is controlled by the user agent or system.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.muted](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-muted).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(track: MediaStreamTrack) {
    /// if track.muted() {
    ///     println!("Track is muted by the system");
    /// }
    /// # }
    /// ```
    pub fn muted(&self) -> bool {
        self.muted
    }

    /// Permanently stops this track.
    ///
    /// Stopping a track ends its media source and transitions the track to the "ended" state.
    /// Once stopped, a track cannot be restarted. The track will no longer produce media,
    /// and resources associated with it are released.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.stop()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-stop).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(mut track: MediaStreamTrack) {
    /// // Stop the track when done
    /// track.stop();
    ///
    /// // Track is now permanently ended
    /// # }
    /// ```
    pub fn stop(&mut self) {
        self.ready_state = MediaStreamTrackState::Ended;
    }

    /// Returns the capabilities of this track.
    ///
    /// Capabilities represent the inherent properties of the track's source, such as
    /// supported resolutions, frame rates, sample rates, etc. These are determined by
    /// the underlying hardware or media source.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.getCapabilities()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-getcapabilities).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(track: MediaStreamTrack) {
    /// let capabilities = track.get_capabilities();
    /// // Inspect supported capabilities
    /// # }
    /// ```
    pub fn get_capabilities(&self) -> &MediaTrackCapabilities {
        &self.capabilities
    }

    /// Returns the currently applied constraints for this track.
    ///
    /// Constraints define the allowed ranges or exact values for various track properties.
    /// They are applied using [`apply_constraints()`](Self::apply_constraints).
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.getConstraints()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-getconstraints).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(track: MediaStreamTrack) {
    /// let constraints = track.get_constraints();
    /// // Examine current constraints
    /// # }
    /// ```
    pub fn get_constraints(&self) -> &MediaTrackConstraints {
        &self.constraints
    }

    /// Returns the actual settings currently in effect for this track.
    ///
    /// Settings represent the current values of track properties like resolution,
    /// frame rate, sample rate, etc. These may differ from requested constraints
    /// based on hardware limitations or system conditions.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.getSettings()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-getsettings).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(track: MediaStreamTrack) {
    /// let settings = track.get_settings();
    /// // Check actual track settings
    /// # }
    /// ```
    pub fn get_settings(&self) -> &MediaTrackSettings {
        &self.settings
    }

    /// Applies constraints to this track.
    ///
    /// Constraints allow the application to specify desired values or ranges for
    /// track properties like resolution, frame rate, etc. The user agent will
    /// attempt to satisfy these constraints, but may not be able to meet all of them
    /// depending on hardware capabilities and system conditions.
    ///
    /// If the track is in the "ended" state, this method has no effect.
    ///
    /// # Parameters
    ///
    /// * `constraints` - Optional constraints to apply. Pass `None` to remove all constraints.
    ///
    /// # Specification
    ///
    /// See [MediaStreamTrack.applyConstraints()](https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-applyconstraints).
    ///
    /// # Examples
    ///
    /// ```
    /// # use rtc::media_stream::MediaStreamTrack;
    /// # use rtc::media_stream::MediaTrackConstraints;
    /// # use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RtpCodecKind};
    /// # fn example(mut track: MediaStreamTrack) {
    /// // Apply new constraints
    /// let constraints = MediaTrackConstraints::default();
    /// track.apply_constraints(Some(constraints));
    ///
    /// // Remove all constraints
    /// track.apply_constraints(None);
    /// # }
    /// ```
    pub fn apply_constraints(&mut self, constraints: Option<MediaTrackConstraints>) {
        if self.ready_state == MediaStreamTrackState::Ended {
            return;
        }

        if let Some(constraints) = constraints {
            //TODO: https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-applyconstraints
            self.constraints = constraints;
        }
    }

    /// Sets the codec for this track (internal use only).
    ///
    /// # Parameters
    ///
    /// * `codec` - The new RTP codec configuration
    pub(crate) fn set_codec(&mut self, codec: RTCRtpCodec) {
        self.codec = codec;
    }
}
