//TODO:pub(crate) mod datachannel;
pub(crate) mod demuxer;
//pub(crate) mod dtls;
pub(crate) mod endpoint;
//pub(crate) mod interceptor;
pub mod message;
//pub(crate) mod sctp;
//pub(crate) mod srtp;
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
use crate::handler::message::{RTCEvent, RTCMessage};
use crate::handler::stun::{StunHandler, StunHandlerContext};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::RTCPeerConnection;
use crate::transport::TransportStates;
use shared::error::Error;
use shared::TaggedBytesMut;
use std::time::Instant;

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

impl sansio::Protocol<TaggedBytesMut, RTCMessage, RTCEvent> for RTCPeerConnection {
    type Rout = RTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, _msg: TaggedBytesMut) -> std::result::Result<(), Self::Error> {
        todo!()
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        todo!()
    }

    fn handle_write(&mut self, _msg: RTCMessage) -> std::result::Result<(), Self::Error> {
        todo!()
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        todo!()
    }

    fn handle_event(&mut self, _evt: RTCEvent) -> std::result::Result<(), Self::Error> {
        todo!()
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        todo!()
    }

    fn handle_timeout(&mut self, _now: Instant) -> std::result::Result<(), Self::Error> {
        todo!()
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        todo!()
    }

    fn close(&mut self) -> std::result::Result<(), Self::Error> {
        todo!()
    }
}
