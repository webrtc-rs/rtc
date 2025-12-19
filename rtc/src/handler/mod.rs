pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod exception;
pub(crate) mod interceptor;
pub mod message;
pub(crate) mod sctp;
pub(crate) mod srtp;
pub(crate) mod stun;

use crate::handler::datachannel::DataChannelHandler;
use crate::handler::demuxer::DemuxerHandler;
use crate::handler::dtls::DtlsHandler;
use crate::handler::endpoint::EndpointHandler;
use crate::handler::exception::ExceptionHandler;
use crate::handler::interceptor::InterceptorHandler;
use crate::handler::sctp::SctpHandler;
use crate::handler::srtp::SrtpHandler;
use crate::handler::stun::StunHandler;
use crate::peer_connection::RTCPeerConnection;
use shared::error::Result;
use std::sync::Arc;

impl RTCPeerConnection {
    pub(crate) fn build_pipeline(&mut self) -> Result<()> {
        let sctp_max_message_size = self
            .get_configuration()
            .setting_engine
            .sctp_max_message_size
            .as_usize();

        let dtls_handshake_config = Arc::new(
            ::dtls::config::ConfigBuilder::default()
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
                .build(false, None)?,
        );
        let sctp_endpoint_config = Arc::new(::sctp::EndpointConfig::default());
        let sctp_server_config = Arc::new(::sctp::ServerConfig::default());

        // Handlers
        let demuxer_handler = DemuxerHandler::new();
        let stun_handler = StunHandler::new();
        // DTLS
        let dtls_handler = DtlsHandler::new();
        let sctp_handler = SctpHandler::new(
            /*local_addr, Rc::clone(&server_states)*/
            sctp_max_message_size,
        );
        let data_channel_handler = DataChannelHandler::new();
        // SRTP
        let srtp_handler = SrtpHandler::new(/*Rc::clone(&server_states)*/);
        let interceptor_handler = InterceptorHandler::new(/*Rc::clone(&server_states)*/);
        // Endpoint
        let endpoint_handler = EndpointHandler::new(
            dtls_handshake_config,
            sctp_endpoint_config,
            sctp_server_config,
            Arc::clone(&self.transport_states),
        );
        let exception_handler = ExceptionHandler::new();

        // Build transport pipeline
        self.transport_pipeline.add_back(demuxer_handler);
        self.transport_pipeline.add_back(stun_handler);
        // DTLS
        self.transport_pipeline.add_back(dtls_handler);
        self.transport_pipeline.add_back(sctp_handler);
        self.transport_pipeline.add_back(data_channel_handler);
        // SRTP
        self.transport_pipeline.add_back(srtp_handler);
        self.transport_pipeline.add_back(interceptor_handler);
        // Endpoint
        self.transport_pipeline.add_back(endpoint_handler);
        self.transport_pipeline.add_back(exception_handler);
        self.transport_pipeline.finalize();

        Ok(())
    }
}
