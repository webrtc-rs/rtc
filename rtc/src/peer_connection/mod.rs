pub mod certificate;
pub mod configuration;
pub mod event;
pub mod message;
pub mod proto;
pub mod sdp;
pub mod state;

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
use std::collections::{HashMap, VecDeque};

use crate::data_channel::init::RTCDataChannelInit;
use crate::data_channel::parameters::DataChannelParameters;
use crate::data_channel::{internal::RTCDataChannelInternal, RTCDataChannel, RTCDataChannelId};
use crate::transport::ice::candidate::RTCIceCandidateInit;
use shared::error::{Error, Result};

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
    pub(crate) data_channels: HashMap<RTCDataChannelId, RTCDataChannelInternal>,
}

impl RTCPeerConnection {
    /// creates a PeerConnection with RTCConfiguration
    pub fn new(mut configuration: RTCConfiguration) -> Result<Self> {
        configuration.validate()?;

        Ok(Self {
            configuration,
            ..Default::default()
        })
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

    /// local_description returns PendingLocalDescription if it is not null and
    /// otherwise it returns CurrentLocalDescription. This property is used to
    /// determine if set_local_description has already been called.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-localdescription>
    pub fn local_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_local_description.is_some() {
            self.pending_local_description.as_ref()
        } else {
            self.current_local_description.as_ref()
        }
    }

    /// set_remote_description sets the SessionDescription of the remote peer
    pub fn set_remote_description(&mut self, _description: RTCSessionDescription) -> Result<()> {
        Ok(())
    }

    /// remote_description returns pending_remote_description if it is not null and
    /// otherwise it returns current_remote_description. This property is used to
    /// determine if setRemoteDescription has already been called.
    /// <https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-remotedescription>
    pub fn remote_description(&self) -> Option<&RTCSessionDescription> {
        if self.pending_remote_description.is_some() {
            self.pending_remote_description.as_ref()
        } else {
            self.current_remote_description.as_ref()
        }
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
        label: &str,
        options: Option<RTCDataChannelInit>,
    ) -> Result<RTCDataChannel<'_>> {
        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #2)
        if self.connection_state == RTCPeerConnectionState::Closed {
            return Err(Error::ErrConnectionClosed);
        }

        let mut params = DataChannelParameters {
            label: label.to_owned(),
            ..Default::default()
        };

        let mut id = {
            let mut id = rand::random::<u16>();
            while self.data_channels.contains_key(&id) {
                id = rand::random::<u16>();
            }
            id
        };

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #19)
        if let Some(options) = options {
            // Ordered indicates if data is allowed to be delivered out of order. The
            // default value of true, guarantees that data will be delivered in order.
            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #9)
            params.ordered = options.ordered;

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #7)
            params.max_packet_life_time = Some(options.max_packet_life_time);

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #8)
            params.max_retransmits = Some(options.max_retransmits);

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #10)
            params.protocol = options.protocol;

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #11)
            if params.protocol.len() > 65535 {
                return Err(Error::ErrProtocolTooLarge);
            }

            // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #12)
            params.negotiated = options.negotiated;

            if let Some(negotiated_id) = &params.negotiated {
                id = *negotiated_id;
            }
        }

        let data_channel = RTCDataChannelInternal::new(
            params,
            //TODO: &self.configuration.setting_engine,
        );

        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #16)
        if data_channel.max_packet_lifetime.is_some() && data_channel.max_retransmits.is_some() {
            return Err(Error::ErrRetransmitsOrPacketLifeTime);
        }

        self.data_channels.insert(id, data_channel);

        Ok(RTCDataChannel {
            id,
            peer_connection: self,
        })
    }

    pub fn data_channel(&mut self, id: RTCDataChannelId) -> Option<RTCDataChannel<'_>> {
        if self.data_channels.contains_key(&id) {
            Some(RTCDataChannel {
                id,
                peer_connection: self,
            })
        } else {
            None
        }
    }
}
