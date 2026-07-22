use crate::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::sctp::capabilities::SCTPTransportCapabilities;
use crate::peer_connection::transport::sctp::state::RTCSctpTransportState;
use sctp::{Association, AssociationHandle};
use shared::error::Result;
use shared::{TransportContext, TransportProtocol};
use std::collections::HashMap;

pub(crate) mod capabilities;
pub(crate) mod state;

const SCTP_MAX_CHANNELS: u16 = u16::MAX;

/// SCTPTransport provides details about the SCTP transport.
#[derive(Default)]
pub(crate) struct RTCSctpTransport {
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

    // Optional override for the SCTP receive-buffer size (a_rwnd flow-control window),
    // in bytes. None uses the sctp crate default (INITIAL_RECV_BUF_SIZE, 1 MiB).
    pub(crate) max_receive_buffer_size: Option<u32>,

    // max_channels represents the maximum amount of DataChannel's that can
    // be used simultaneously.
    pub(crate) max_channels: u16,

    pub(crate) internal_buffer: Vec<u8>,
}

impl RTCSctpTransport {
    pub(crate) fn new(
        max_message_size: SctpMaxMessageSize,
        max_receive_buffer_size: Option<u32>,
    ) -> Self {
        Self {
            sctp_endpoint: None,
            sctp_transport_config: None,
            sctp_associations: HashMap::new(),

            state: RTCSctpTransportState::Connecting,
            is_started: false,
            max_message_size,
            max_receive_buffer_size,
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
        dtls_role: RTCDtlsRole,
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
        let mut sctp_transport_config = ::sctp::TransportConfig::default()
            .with_max_message_size(max_message_size)
            .with_sctp_port(local_port);
        if let Some(recv_buf) = self.max_receive_buffer_size {
            sctp_transport_config = sctp_transport_config.with_max_receive_buffer_size(recv_buf);
        }
        //TODO: add remote_port support

        if dtls_role == RTCDtlsRole::Client {
            self.sctp_endpoint = Some(sctp::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                sctp_endpoint_config.into(),
                None,
            ));
            self.sctp_transport_config = Some(sctp_transport_config);
        } else {
            self.sctp_endpoint = Some(::sctp::Endpoint::new(
                TransportContext::default().local_addr, // placeholder; rewritten per-transmit by the ICE handler
                TransportProtocol::UDP, // placeholder; rewritten per-transmit by the ICE handler
                sctp_endpoint_config.into(),
                Some(::sctp::ServerConfig::new(sctp_transport_config).into()),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Starting a Client transport stores the built TransportConfig on the struct, so we
    // can assert the configured (or default) receive-buffer size flowed through `start()`.
    #[test]
    fn start_applies_configured_receive_buffer_size() {
        let mut transport = RTCSctpTransport::new(SctpMaxMessageSize::default(), Some(200_000));
        transport
            .start(
                RTCDtlsRole::Client,
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        assert_eq!(
            transport
                .sctp_transport_config
                .expect("client transport config")
                .max_receive_buffer_size(),
            200_000
        );
    }

    #[test]
    fn start_without_override_uses_default_receive_buffer_size() {
        let mut transport = RTCSctpTransport::new(SctpMaxMessageSize::default(), None);
        transport
            .start(
                RTCDtlsRole::Client,
                SCTPTransportCapabilities {
                    max_message_size: 0,
                },
                5000,
                5000,
            )
            .expect("start");
        // `None` keeps the sctp crate default (INITIAL_RECV_BUF_SIZE = 1 MiB).
        assert_eq!(
            transport
                .sctp_transport_config
                .expect("client transport config")
                .max_receive_buffer_size(),
            1024 * 1024
        );
    }
}
