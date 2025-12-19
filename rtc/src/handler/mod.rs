pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod interceptor;
pub mod message;
pub(crate) mod sctp;
pub(crate) mod srtp;
pub(crate) mod stun;

/*
use crate::handler::datachannel::DataChannelHandler;
use crate::handler::dtls::DtlsHandler;
use crate::handler::interceptor::InterceptorHandler;
use crate::handler::sctp::SctpHandler;
use crate::handler::srtp::SrtpHandler;
*/
use crate::handler::demuxer::{DemuxerHandler, DemuxerHandlerContext};
use crate::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
use crate::handler::stun::{StunHandler, StunHandlerContext};
use crate::peer_connection::RTCPeerConnection;
use crate::transport::TransportStates;
use shared::error::Result;

#[derive(Default)]
pub(crate) struct PipelineContext {
    // Immutable Configs
    pub(crate) dtls_handshake_config: ::dtls::config::HandshakeConfig,
    pub(crate) sctp_endpoint_config: ::sctp::EndpointConfig,
    pub(crate) sctp_server_config: ::sctp::ServerConfig,

    // Shared states
    pub(crate) transport_states: TransportStates,

    // Handler contexts
    pub(crate) demuxer_handler_context: DemuxerHandlerContext,
    pub(crate) stun_handler_context: StunHandlerContext,
    pub(crate) endpoint_handler_context: EndpointHandlerContext,
}

impl RTCPeerConnection {
    pub(crate) fn build_pipeline(&mut self) -> Result<()> {
        // Create and store DTLS handshake config
        self.pipeline_context.dtls_handshake_config = ::dtls::config::ConfigBuilder::default()
            .with_certificates(
                self.dtls_transport
                    .certificates
                    .iter()
                    .map(|c| c.dtls_certificate.clone())
                    .collect(),
            )
            .with_srtp_protection_profiles(vec![(self.dtls_transport.srtp_protection_profile
                as u16)
                .into()])
            .with_extended_master_secret(::dtls::config::ExtendedMasterSecretType::Require)
            .build(false, None)?;

        // Store SCTP configs
        self.pipeline_context.sctp_endpoint_config = ::sctp::EndpointConfig::default();
        self.pipeline_context.sctp_server_config = ::sctp::ServerConfig::default();

        /*
         let sctp_max_message_size = self
             .get_configuration()
             .setting_engine
             .sctp_max_message_size
             .as_usize();

         // DTLS
         let dtls_handler = DtlsHandler::new();
         let sctp_handler = SctpHandler::new(sctp_max_message_size);
         let data_channel_handler = DataChannelHandler::new();
         // SRTP
         let srtp_handler = SrtpHandler::new();
         let interceptor_handler = InterceptorHandler::new();
        */

        Ok(())
    }

    pub(crate) fn get_endpoint_handler(&mut self) -> EndpointHandler<'_> {
        EndpointHandler::new(
            &self.pipeline_context.dtls_handshake_config,
            &self.pipeline_context.sctp_endpoint_config,
            &self.pipeline_context.sctp_server_config,
            &mut self.pipeline_context.transport_states,
            &mut self.pipeline_context.endpoint_handler_context,
        )
    }

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(&mut self.pipeline_context.demuxer_handler_context)
    }

    pub(crate) fn get_stun_handler(&mut self) -> StunHandler<'_> {
        StunHandler::new(&mut self.pipeline_context.stun_handler_context)
    }
}
