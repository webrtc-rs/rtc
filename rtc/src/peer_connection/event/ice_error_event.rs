//! ICE error event types.
//!
//! Contains error information emitted when ICE candidate gathering fails.

/// ICE candidate gathering error event.
///
/// This event provides detailed information about errors that occur during
/// ICE candidate gathering, such as STUN/TURN server failures, network issues,
/// or permission problems.
///
/// # Fields
///
/// - `address` - Host candidate's related address (may be empty)
/// - `port` - Host candidate's related port
/// - `url` - STUN or TURN URL that caused the error
/// - `error_code` - Numeric error code
/// - `error_text` - Human-readable error description
///
/// # Common Error Codes
///
/// - `701` - STUN/TURN server unreachable
/// - `702` - TURN authentication failed
/// - `703` - TURN allocation failed
/// - `710` - Network permission denied
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::event::RTCPeerConnectionEvent;
///
/// # fn handle_event(event: RTCPeerConnectionEvent) {
/// match event {
///     RTCPeerConnectionEvent::OnIceCandidateErrorEvent(error) => {
///         eprintln!(
///             "ICE gathering error {}: {} (URL: {})",
///             error.error_code, error.error_text, error.url
///         );
///         
///         // Handle specific error codes
///         match error.error_code {
///             701 => eprintln!("STUN/TURN server unreachable"),
///             702 => eprintln!("TURN authentication failed - check credentials"),
///             _ => {}
///         }
///     }
///     _ => {}
/// }
/// # }
/// ```
///
/// # Specification
///
/// See [RTCPeerConnectionIceErrorEvent](https://www.w3.org/TR/webrtc/#rtcpeerconnectioniceerrorevent)
#[derive(Default, Clone, Debug)]
pub struct RTCPeerConnectionIceErrorEvent {
    /// Host candidate's related address.
    ///
    /// The address from which the host ICE candidate was gathered (may be empty).
    pub address: String,

    /// Host candidate's related port.
    ///
    /// The port from which the host ICE candidate was gathered.
    pub port: u16,

    /// STUN or TURN URL that caused the error.
    ///
    /// The URL of the server that was being contacted when the error occurred.
    pub url: String,

    /// Numeric STUN error code.
    ///
    /// A numeric error code in the range 300-699 per RFC 5389.
    pub error_code: u16,

    /// Human-readable error description.
    ///
    /// Textual description of the error that occurred.
    pub error_text: String,
}
