/*pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod exception;
pub(crate) mod interceptor;*/
pub mod message;
/*
pub(crate) mod sctp;
pub(crate) mod srtp;
pub(crate) mod stun;

use crate::handler::datachannel::DataChannelHandler;
use crate::handler::demuxer::DemuxerHandler;
use crate::handler::dtls::DtlsHandler;
use crate::handler::endpoint::EndpointHandler;
use crate::handler::exception::ExceptionHandler;
use crate::handler::interceptor::InterceptorHandler;
use crate::handler::message::TaggedRTCMessage;
use crate::handler::sctp::SctpHandler;
use crate::handler::srtp::SrtpHandler;
use crate::handler::stun::StunHandler;
use crate::peer_connection::RTCPeerConnection;
use shared::error::Result;
use shared::{Pipeline, TaggedBytesMut};

impl RTCPeerConnection {
    pub(crate) fn build_pipeline(&self) -> Result<Pipeline<TaggedBytesMut, TaggedRTCMessage>> {
        let pipeline: Pipeline<TaggedBytesMut, TaggedRTCMessage> = Pipeline::new();

        let demuxer_handler = DemuxerHandler::new();
        let stun_handler = StunHandler::new();

        let sctp_max_message_size = self
            .get_configuration()
            .setting_engine
            .sctp_max_message_size
            .as_usize();
        // DTLS
        let dtls_handler = DtlsHandler::new(/*local_addr, Rc::clone(&server_states)*/);
        let sctp_handler = SctpHandler::new(
            /*local_addr, Rc::clone(&server_states)*/
            sctp_max_message_size,
        );
        let data_channel_handler = DataChannelHandler::new();
        // SRTP
        let srtp_handler = SrtpHandler::new(/*Rc::clone(&server_states)*/);
        let interceptor_handler = InterceptorHandler::new(/*Rc::clone(&server_states)*/);
        // Endpoint
        let endpoint_handler = EndpointHandler::new(/*Rc::clone(&server_states)*/);
        let exception_handler = ExceptionHandler::new();

        pipeline.add_back(demuxer_handler);
        pipeline.add_back(stun_handler);
        // DTLS
        pipeline.add_back(dtls_handler);
        pipeline.add_back(sctp_handler);
        pipeline.add_back(data_channel_handler);
        // SRTP
        pipeline.add_back(srtp_handler);
        pipeline.add_back(interceptor_handler);
        // Endpoint
        pipeline.add_back(endpoint_handler);
        pipeline.add_back(exception_handler);

        Ok(pipeline)
    }
}
*/
