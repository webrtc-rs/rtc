pub mod track;
pub mod track_capabilities;
pub mod track_constraints;
pub mod track_local;
pub mod track_remote;
pub mod track_settings;
pub mod track_state;
pub mod track_supported_constraints;

use crate::media_stream::track::{MediaStreamTrack, MediaStreamTrackId};
use crate::media_stream::track_local::TrackLocal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
use crate::rtp_transceiver::SSRC;
use interceptor::stream_info::StreamInfo;
use std::collections::HashMap;
use track_remote::*;

pub(crate) const RTP_OUTBOUND_MTU: usize = 1200;
pub(crate) const RTP_PAYLOAD_TYPE_BITMASK: u8 = 0x7F;

#[derive(Debug, Clone)]
pub(crate) struct TrackStream {
    pub(crate) stream_info: Option<StreamInfo>,
}

/// TrackStreams maintains a mapping of RTP/RTCP streams to a specific track
/// a RTPReceiver may contain multiple streams if we are dealing with Simulcast
#[derive(Debug, Clone)]
pub(crate) struct TrackStreams {
    pub(crate) track: TrackRemote,
    pub(crate) stream: TrackStream,
    pub(crate) repair_stream: TrackStream,
}

/// TrackDetails represents any media source that can be represented in a SDP
/// This isn't keyed by SSRC because it also needs to support rid based sources
#[derive(Default, Debug, Clone)]
pub(crate) struct TrackDetails {
    pub(crate) mid: String,
    pub(crate) kind: RtpCodecKind,
    pub(crate) stream_id: String,
    pub(crate) id: String,
    pub(crate) ssrcs: Vec<SSRC>,
    pub(crate) repair_ssrc: SSRC,
    pub(crate) rids: Vec<String>,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct TrackEncoding {
    pub(crate) track: TrackLocal,
    //pub(crate) srtp_stream: Arc<SrtpWriterFuture>,
    //pub(crate) rtcp_interceptor: Arc<dyn RTCPReader + Send + Sync>,
    pub(crate) stream_info: StreamInfo,
    //pub(crate) context: TrackLocalContext,
    pub(crate) ssrc: SSRC,

    pub(crate) rtx: Option<RtxEncoding>,
}

#[derive(Default, Debug, Clone)]
pub(crate) struct RtxEncoding {
    //pub(crate) srtp_stream: Arc<SrtpWriterFuture>,
    //pub(crate) rtcp_interceptor: Arc<dyn RTCPReader + Send + Sync>,
    pub(crate) stream_info: StreamInfo,

    pub(crate) ssrc: SSRC,
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// https://www.w3.org/TR/mediacapture-streams/#stream-api
////////////////////////////////////////////////////////////////////////////////////////////////////
pub type MediaStreamId = String;
#[derive(Default, Debug, Clone)]
pub struct MediaStream {
    id: MediaStreamId,
    tracks: HashMap<MediaStreamTrackId, MediaStreamTrack>,
    active: bool,
}

impl MediaStream {
    pub fn new(id: MediaStreamId, tracks: Vec<MediaStreamTrack>) -> Self {
        Self {
            id,
            tracks: tracks
                .into_iter()
                .map(|track| (track.id().to_string(), track))
                .collect(),
            active: true,
        }
    }

    pub fn id(&self) -> &MediaStreamId {
        &self.id
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
        self.tracks.insert(track.id().to_string(), track);
    }

    pub fn remove_track(&mut self, track_id: &MediaStreamTrackId) -> Option<MediaStreamTrack> {
        self.tracks.remove(track_id)
    }
}
