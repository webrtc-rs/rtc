//! Track event types.
//!
//! Events related to incoming media tracks from the remote peer.

use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrackId;
use crate::rtp_transceiver::{RTCRtpReceiverId, RtpStreamId};

/// Initialization data for a track event.
///
/// Contains IDs needed to access the track, receiver, transceiver, and
/// associated media streams when a track is opened.
///
/// # Fields
///
/// - `receiver_id` - ID of the RTP receiver handling this track
/// - `track_id` - ID of the media stream track
/// - `stream_ids` - IDs of media streams this track belongs to
/// - `transceiver_id` - ID of the transceiver managing this track
///
/// # Examples
///
/// ## Accessing track components
///
/// ```ignore
/// // Note: Accessing receiver/transceiver requires &mut RTCPeerConnection
/// use rtc::peer_connection::RTCPeerConnection;
/// use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
///
/// fn handle_event(mut peer_connection: RTCPeerConnection, event: RTCPeerConnectionEvent) {
///     match event {
///         RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) => {
///             // Access the receiver
///             if let Some(receiver) = peer_connection.rtp_receiver(init.receiver_id) {
///                 // Get receiver parameters
///                 let params = receiver.get_parameters();
///                 println!("Codecs: {:?}", params.codecs);
///             }
///             
///             // Print associated stream IDs
///             println!("Stream IDs: {:?}", init.stream_ids);
///         }
///         _ => {}
///     }
/// }
/// ```
#[allow(clippy::enum_variant_names)]
#[derive(Default, Debug, Clone)]
pub struct RTCTrackEventInit {
    /// ID of the RTP receiver handling this track.
    ///
    /// Use this with `peer_connection.rtp_receiver()` to access the receiver.
    pub receiver_id: RTCRtpReceiverId,

    /// ID of the media stream track.
    ///
    /// This uniquely identifies the track within the peer connection.
    pub track_id: MediaStreamTrackId,

    /// IDs of media streams this track belongs to.
    ///
    /// A track can be associated with multiple media streams.
    /// These correspond to the msid attribute in the SDP.
    pub stream_ids: Vec<MediaStreamId>,

    /// ID of the RTP stream in simulcast.
    ///
    /// This uniquely identifies the stream within the receiver.
    pub rid: Option<RtpStreamId>,
}

/// Events related to incoming media tracks.
///
/// These events track the lifecycle of media tracks received from the remote peer.
/// Applications should handle these events to access incoming audio/video streams
/// and read RTP/RTCP packets.
///
/// # Lifecycle
///
/// 1. `OnOpen` - Track is ready, contains initialization data
/// 2. `OnError` - An error occurred with the track
/// 3. `OnClosing` - Track is starting to close
/// 4. `OnClose` - Track is fully closed
///
/// # Examples
///
/// ## Handling track lifecycle
///
/// ```
/// use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnTrack(track_event) => {
///         match track_event {
///             RTCTrackEvent::OnOpen(init) => {
///                 println!("Track opened: {:?}", init.track_id);
///                 // Start reading RTP packets
///             }
///             RTCTrackEvent::OnError(track_id) => {
///                 eprintln!("Track error: {:?}", track_id);
///             }
///             RTCTrackEvent::OnClose(track_id) => {
///                 println!("Track closed: {:?}", track_id);
///                 // Clean up resources
///             }
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// ## Reading media from track (conceptual)
///
/// ```ignore
/// // Note: poll_read() is part of sans-I/O design
/// use rtc::peer_connection::RTCPeerConnection;
/// use rtc::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
/// use rtc::peer_connection::message::RTCMessage;
///
/// fn handle_events(mut peer_connection: RTCPeerConnection) {
///     // Poll events
///     while let Some(event) = peer_connection.poll_event() {
///         if let RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) = event {
///             println!("Track opened, ready to receive media");
///         }
///     }
///
///     // Poll incoming media
///     while let Some(message) = peer_connection.poll_read() {
///         match message {
///             RTCMessage::RtpPacket(track_id, rtp) => {
///                 println!("RTP packet from track {:?}: {} bytes", track_id, rtp.payload.len());
///             }
///             RTCMessage::RtcpPacket(receiver_id, rtcp) => {
///                 println!("RTCP packet: {:?}", rtcp);
///             }
///             _ => {}
///         }
///     }
/// }
/// ```
///
/// # Specification
///
/// See [RTCTrackEvent](https://www.w3.org/TR/webrtc/#rtctrackevent)
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone)]
pub enum RTCTrackEvent {
    /// Track has opened and is ready to receive media.
    ///
    /// This variant contains initialization data with IDs to access
    /// the track, receiver, transceiver, and associated streams.
    OnOpen(RTCTrackEventInit),

    /// An error occurred with the track.
    ///
    /// The track may still be usable depending on the error type.
    OnError(MediaStreamTrackId),

    /// Track is starting to close.
    ///
    /// The track is transitioning to the closing state.
    OnClosing(MediaStreamTrackId),

    /// Track has closed.
    ///
    /// The track is no longer usable and resources should be cleaned up.
    OnClose(MediaStreamTrackId),
}

impl Default for RTCTrackEvent {
    fn default() -> Self {
        Self::OnOpen(Default::default())
    }
}
