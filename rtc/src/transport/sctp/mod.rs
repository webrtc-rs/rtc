use crate::configuration::setting_engine::SctpMaxMessageSize;
use crate::transport::dtls::role::DTLSRole;
use crate::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::transport::sctp::state::RTCSctpTransportState;
use sctp::{Association, AssociationHandle};
use shared::error::Result;
use shared::TransportProtocol;
use std::collections::HashMap;

pub mod capabilities;
pub mod state;

const SCTP_MAX_CHANNELS: u16 = u16::MAX;

/// SCTPTransport provides details about the SCTP transport.
#[derive(Default)]
pub struct RTCSctpTransport {
    pub(crate) sctp_endpoint: Option<::sctp::Endpoint>,
    pub(crate) sctp_transport_config: Option<::sctp::TransportConfig>,
    pub(crate) sctp_associations: HashMap<AssociationHandle, Association>,

    // State represents the current state of the SCTP transport.
    pub(crate) state: RTCSctpTransportState,

    // SCTPTransportState doesn't have an enum to distinguish between New/Connecting
    // so we need a dedicated field
    pub(crate) is_started: bool,

    // max_message_size represents the maximum size of data that can be passed to
    // RTCDataChannel's send() method. The attribute MUST, on getting,
    // return the value of the [[MaxMessageSize]] slot.
    pub(crate) max_message_size: SctpMaxMessageSize,

    // max_channels represents the maximum amount of DataChannel's that can
    // be used simultaneously.
    pub(crate) max_channels: u16,

    pub(crate) internal_buffer: Vec<u8>,
}

impl RTCSctpTransport {
    pub(crate) fn new(max_message_size: SctpMaxMessageSize) -> Self {
        Self {
            sctp_endpoint: None,
            sctp_transport_config: None,
            sctp_associations: HashMap::new(),

            state: RTCSctpTransportState::Connecting,
            is_started: false,
            max_message_size,
            max_channels: SCTP_MAX_CHANNELS,
            internal_buffer: vec![],
        }
    }

    pub(crate) fn calc_message_size(remote_max_message_size: u32, can_send_size: u32) -> u32 {
        if remote_max_message_size == 0 && can_send_size == 0 {
            u32::MAX
        } else if remote_max_message_size == 0 {
            can_send_size
        } else if can_send_size == 0 || can_send_size > remote_max_message_size {
            remote_max_message_size
        } else {
            can_send_size
        }
    }

    pub(crate) fn max_channels(&self) -> u16 {
        self.max_channels
    }

    /// Start the SCTPTransport. Since both local and remote parties must mutually
    /// create an SCTPTransport, SCTP SO (Simultaneous Open) is used to establish
    /// a connection over SCTP.
    pub(crate) fn start(
        &mut self,
        dtls_role: DTLSRole,
        remote_caps: SCTPTransportCapabilities,
        local_port: u16,
        _remote_port: u16,
    ) -> Result<()> {
        if self.is_started {
            return Ok(());
        }
        self.is_started = true;

        let max_message_size = RTCSctpTransport::calc_message_size(
            remote_caps.max_message_size,
            self.max_message_size.as_usize() as u32,
        );
        self.internal_buffer.resize(max_message_size as usize, 0u8);

        let sctp_endpoint_config = ::sctp::EndpointConfig::default();
        let sctp_transport_config = ::sctp::TransportConfig::default()
            .with_max_message_size(max_message_size)
            .with_sctp_port(local_port);
        //TODO: add remote_port support

        if dtls_role == DTLSRole::Client {
            self.sctp_endpoint = Some(sctp::Endpoint::new(
                "127.0.0.1:0".parse()?, //local_addr doesn't matter
                TransportProtocol::UDP, // TransportProtocol doesn't matter
                sctp_endpoint_config.into(),
                None,
            ));
            self.sctp_transport_config = Some(sctp_transport_config);
        } else {
            self.sctp_endpoint = Some(::sctp::Endpoint::new(
                "127.0.0.1:0".parse()?, //local_addr doesn't matter
                TransportProtocol::UDP, // TransportProtocol doesn't matter
                sctp_endpoint_config.into(),
                Some(::sctp::ServerConfig::new(sctp_transport_config).into()),
            ));
        }

        Ok(())
    }
}
