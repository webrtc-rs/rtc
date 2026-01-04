pub mod track;
pub mod track_capabilities;
pub mod track_constraints;
pub mod track_settings;
pub mod track_state;
pub mod track_supported_constraints;

use crate::media_stream::track::{MediaStreamTrack, MediaStreamTrackId};
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use std::collections::HashMap;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <https://www.w3.org/TR/mediacapture-streams/#stream-api>
////////////////////////////////////////////////////////////////////////////////////////////////////
pub type MediaStreamId = String;
#[derive(Default, Debug, Clone)]
pub struct MediaStream {
    stream_id: MediaStreamId,
    tracks: HashMap<MediaStreamTrackId, MediaStreamTrack>,
    active: bool,
}

impl MediaStream {
    pub fn new(stream_id: MediaStreamId, tracks: Vec<MediaStreamTrack>) -> Self {
        Self {
            stream_id,
            tracks: tracks
                .into_iter()
                .map(|track| (track.stream_id().to_string(), track))
                .collect(),
            active: true,
        }
    }

    pub fn stream_id(&self) -> &MediaStreamId {
        &self.stream_id
    }

    pub fn active(&self) -> bool {
        self.active
    }

    pub fn get_audio_tracks(&self) -> impl Iterator<Item = &MediaStreamTrack> {
        self.tracks
            .values()
            .filter(|track| track.kind() == RtpCodecKind::Audio)
    }

    pub fn get_audio_tracks_mut(&mut self) -> impl Iterator<Item = &mut MediaStreamTrack> {
        self.tracks
            .values_mut()
            .filter(|track| track.kind() == RtpCodecKind::Audio)
    }

    pub fn get_video_tracks(&self) -> impl Iterator<Item = &MediaStreamTrack> {
        self.tracks
            .values()
            .filter(|track| track.kind() == RtpCodecKind::Video)
    }

    pub fn get_video_tracks_mut(&mut self) -> impl Iterator<Item = &mut MediaStreamTrack> {
        self.tracks
            .values_mut()
            .filter(|track| track.kind() == RtpCodecKind::Video)
    }

    pub fn get_tracks(&self) -> impl Iterator<Item = &MediaStreamTrack> {
        self.tracks.values()
    }

    pub fn get_tracks_mut(&mut self) -> impl Iterator<Item = &mut MediaStreamTrack> {
        self.tracks.values_mut()
    }

    pub fn get_track_by_id(&self, track_id: &MediaStreamTrackId) -> Option<&MediaStreamTrack> {
        self.tracks.get(track_id)
    }

    pub fn get_track_by_id_mut(
        &mut self,
        track_id: &MediaStreamTrackId,
    ) -> Option<&mut MediaStreamTrack> {
        self.tracks.get_mut(track_id)
    }

    pub fn add_track(&mut self, track: MediaStreamTrack) {
        self.tracks.insert(track.track_id().to_string(), track);
    }

    pub fn remove_track(&mut self, track_id: &MediaStreamTrackId) -> Option<MediaStreamTrack> {
        self.tracks.remove(track_id)
    }
}
