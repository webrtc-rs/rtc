pub(crate) mod certificate;
pub(crate) mod configuration;
pub(crate) mod event;
pub(crate) mod ice;
pub(crate) mod message;
pub(crate) mod proto;
pub(crate) mod sdp;
pub(crate) mod state;

use crate::peer_connection::configuration::offer_answer_options::{
    RTCAnswerOptions, RTCOfferOptions,
};
use crate::peer_connection::configuration::RTCConfiguration;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::sdp::session_description::RTCSessionDescription;
use crate::peer_connection::state::ice_connection_state::RTCIceConnectionState;
use crate::peer_connection::state::ice_gathering_state::RTCIceGatheringState;
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use std::collections::VecDeque;

use crate::data_channel::init::RTCDataChannelInit;
use crate::data_channel::RTCDataChannel;
use crate::peer_connection::proto::PeerConnectionInternal;
use crate::transport::ice::candidate::RTCIceCandidateInit;
use shared::error::Result;

/// PeerConnection represents a WebRTC connection that establishes a
/// peer-to-peer communications with another PeerConnection instance in a
/// browser, or to another endpoint implementing the required protocols.
#[derive(Default, Clone)]
pub struct RTCPeerConnection {
    //////////////////////////////////////////////////
    // PeerConnection WebRTC Spec Interface Definition
    //////////////////////////////////////////////////
    configuration: RTCConfiguration,

    local_description: Option<RTCSessionDescription>,
    current_local_description: Option<RTCSessionDescription>,
    pending_local_description: Option<RTCSessionDescription>,
    remote_description: Option<RTCSessionDescription>,
    current_remote_description: Option<RTCSessionDescription>,
    pending_remote_description: Option<RTCSessionDescription>,

    signaling_state: RTCSignalingState,
    ice_gathering_state: RTCIceGatheringState,
    ice_connection_state: RTCIceConnectionState,
    connection_state: RTCPeerConnectionState,
    can_trickle_ice_candidates: bool,

    events: VecDeque<RTCPeerConnectionEvent>,

    //////////////////////////////////////////////////
    // PeerConnection Internal State Machine
    //////////////////////////////////////////////////
    pub(crate) internal: PeerConnectionInternal,
}

impl RTCPeerConnection {
    /// creates a PeerConnection with RTCConfiguration
    pub fn new(configuration: RTCConfiguration) -> Self {
        Self {
            configuration,
            ..Default::default()
        }
    }

    /// create_offer starts the PeerConnection and generates the localDescription
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-createoffer>
    pub fn create_offer(
        &mut self,
        _options: Option<RTCOfferOptions>,
    ) -> Result<RTCSessionDescription> {
        Ok(RTCSessionDescription::default())
    }

    /// create_answer starts the PeerConnection and generates the localDescription
    pub fn create_answer(
        &mut self,
        _options: Option<RTCAnswerOptions>,
    ) -> Result<RTCSessionDescription> {
        Ok(RTCSessionDescription::default())
    }

    /// set_local_description sets the SessionDescription of the local peer
    pub fn set_local_description(&mut self, _description: RTCSessionDescription) -> Result<()> {
        Ok(())
    }

    /// set_remote_description sets the SessionDescription of the remote peer
    pub fn set_remote_description(&mut self, _description: RTCSessionDescription) -> Result<()> {
        Ok(())
    }

    /// add_ice_candidate accepts an ICE candidate string and adds it
    /// to the existing set of candidates.
    pub fn add_ice_candidate(&mut self, _candidate: RTCIceCandidateInit) -> Result<()> {
        Ok(())
    }

    /// restart_ice restart ICE and triggers negotiation needed
    /// <https://w3c.github.io/webrtc-pc/#dom-rtcpeerconnection-restartice>
    pub fn restart_ice(&mut self) -> Result<()> {
        Ok(())
    }

    /// get_configuration returns a Configuration object representing the current
    /// configuration of this PeerConnection object. The returned object is a
    /// copy and direct mutation on it will not take effect until set_configuration
    /// has been called with Configuration passed as its only argument.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-getconfiguration>
    pub fn get_configuration(&self) -> RTCConfiguration {
        self.configuration.clone()
    }

    /// set_configuration updates the configuration of this PeerConnection object.
    pub fn set_configuration(&mut self, _configuration: RTCConfiguration) -> Result<()> {
        Ok(())
    }

    /// create_data_channel creates a new DataChannel object with the given label
    /// and optional DataChannelInit used to configure properties of the
    /// underlying channel such as data reliability.
    pub fn create_data_channel(
        &mut self,
        _label: &str,
        _options: Option<RTCDataChannelInit>,
    ) -> Result<RTCDataChannel<'_>> {
        Ok(RTCDataChannel {
            channel_id: Default::default(),
            peer_connection: self,
        })
    }
}
