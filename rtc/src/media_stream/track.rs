use crate::media_stream::MediaStreamId;
use crate::media_stream::track_capabilities::MediaTrackCapabilities;
use crate::media_stream::track_constraints::MediaTrackConstraints;
use crate::media_stream::track_settings::MediaTrackSettings;
use crate::media_stream::track_state::MediaStreamTrackState;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{RTCRtpCodec, RtpCodecKind};

pub type MediaStreamTrackId = String;

/// Represents a single media track within a stream.
///
/// A `MediaStreamTrack` represents a media source such as audio or video. It contains
/// information about the codec, SSRC, and other parameters needed to send or receive media.
///
/// # Specification
///
/// See [MediaStreamTrack](https://www.w3.org/TR/mediacapture-streams/#mediastreamtrack)
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
    /// # Arguments
    ///
    /// * `stream_id` - The ID of the stream this track belongs to
    /// * `track_id` - A unique identifier for this track
    /// * `label` - A human-readable label for the track
    /// * `kind` - The kind of media (audio or video)
    /// * `rid` - Optional RTP stream ID (used for simulcast)
    /// * `ssrc` - The synchronization source identifier
    /// * `codec` - The RTP codec information
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

    pub fn stream_id(&self) -> &MediaStreamId {
        &self.stream_id
    }

    pub fn track_id(&self) -> &MediaStreamTrackId {
        &self.track_id
    }

    pub fn label(&self) -> &String {
        &self.label
    }

    pub fn kind(&self) -> RtpCodecKind {
        self.kind
    }
    pub fn rid(&self) -> Option<&str> {
        self.rid.as_deref()
    }

    pub fn ssrc(&self) -> SSRC {
        self.ssrc
    }

    pub fn codec(&self) -> &RTCRtpCodec {
        &self.codec
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn muted(&self) -> bool {
        self.muted
    }

    pub fn stop(&mut self) {
        self.ready_state = MediaStreamTrackState::Ended;
    }

    pub fn get_capabilities(&self) -> &MediaTrackCapabilities {
        &self.capabilities
    }

    pub fn get_constraints(&self) -> &MediaTrackConstraints {
        &self.constraints
    }

    pub fn get_settings(&self) -> &MediaTrackSettings {
        &self.settings
    }

    pub fn apply_constraints(&mut self, constraints: Option<MediaTrackConstraints>) {
        if self.ready_state == MediaStreamTrackState::Ended {
            return;
        }

        if let Some(constraints) = constraints {
            //TODO: https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack-applyconstraints
            self.constraints = constraints;
        }
    }

    pub(crate) fn set_codec(&mut self, codec: RTCRtpCodec) {
        self.codec = codec;
    }
}
