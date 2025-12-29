use crate::media_stream::track_capabilities::MediaTrackCapabilities;
use crate::media_stream::track_constraints::MediaTrackConstraints;
use crate::media_stream::track_settings::MediaTrackSettings;
use crate::media_stream::track_state::MediaStreamTrackState;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RTPCodecType;

pub type TrackId = String;

/// TrackStreams maintains a mapping of RTP/RTCP streams to a specific track
/// a RTPReceiver may contain multiple streams if we are dealing with Simulcast
#[derive(Default, Debug, Clone)]
pub struct MediaStreamTrack {
    id: TrackId,
    kind: RTPCodecType,
    label: String,
    muted: bool,
    enabled: bool,
    ready_state: MediaStreamTrackState,
    restrictable: bool,

    capabilities: MediaTrackCapabilities,
    constraints: MediaTrackConstraints,
    settings: MediaTrackSettings,
}

impl MediaStreamTrack {
    pub fn new(id: TrackId, kind: RTPCodecType, label: String, muted: bool) -> Self {
        Self {
            id,
            kind,
            label,
            muted,
            enabled: true,
            ready_state: MediaStreamTrackState::Live,
            restrictable: false,

            ..Default::default()
        }
    }

    pub fn kind(&self) -> RTPCodecType {
        self.kind
    }

    pub fn id(&self) -> &TrackId {
        &self.id
    }

    pub fn label(&self) -> &String {
        &self.label
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
}
