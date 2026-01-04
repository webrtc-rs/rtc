//! ICE candidate event types.
//!
//! Contains ICE candidate information emitted during candidate gathering.

use crate::peer_connection::transport::ice::candidate::RTCIceCandidate;

/// ICE candidate event.
///
/// This event is fired when a new ICE candidate is discovered during the
/// gathering process. The candidate should be sent to the remote peer
/// via the signaling channel.
///
/// # Fields
///
/// - `candidate` - The discovered ICE candidate
/// - `url` - The STUN/TURN URL used to discover this candidate (if applicable)
///
/// # Candidate Types
///
/// - **Host** - Local network interface address
/// - **Server Reflexive (srflx)** - Public address discovered via STUN
/// - **Peer Reflexive (prflx)** - Address discovered during connectivity checks
/// - **Relay** - Address allocated on TURN server
///
/// # Examples
///
/// ## Sending candidates to remote peer
///
/// ```
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
///         // Send candidate to remote peer via signaling channel
///         println!("Send candidate: {}", ice_event.candidate.address);
///         
///         // Also send the URL if needed
///         if !ice_event.url.is_empty() {
///             println!("Gathered from URL: {}", ice_event.url);
///         }
///         
///         // Signal candidate to remote peer
///         // signal_candidate(&ice_event.candidate).await;
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// ## Filtering candidates by type
///
/// ```
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
/// use rtc::peer_connection::transport::RTCIceCandidateType;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnIceCandidateEvent(ice_event) => {
///         // Only send relay candidates (for privacy)
///         if ice_event.candidate.typ == RTCIceCandidateType::Relay {
///             println!("Sending relay candidate: {}", ice_event.candidate.address);
///             // signal_candidate(&ice_event.candidate).await;
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// # Specification
///
/// See [RTCPeerConnectionIceEvent](https://www.w3.org/TR/webrtc/#rtcpeerconnectioniceevent)
#[derive(Default, Clone, Debug)]
pub struct RTCPeerConnectionIceEvent {
    /// The ICE candidate that was gathered.
    ///
    /// Contains all information about the candidate including address, port,
    /// protocol, priority, and type.
    pub candidate: RTCIceCandidate,

    /// The STUN or TURN URL used to gather this candidate.
    ///
    /// This is the URL from the ICE server configuration that was used
    /// to discover this candidate. May be empty for host candidates.
    pub url: String,
}
