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
use crate::handler::message::{RTCEvent, RTCMessage, TaggedRTCMessage};
use crate::handler::stun::{StunHandler, StunHandlerContext};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::RTCPeerConnection;
use crate::transport::TransportStates;
use log::warn;
use shared::error::Error;
use shared::{TaggedBytesMut, TransportContext};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration

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

    // Pipeline
    pub(crate) read_outs: VecDeque<RTCMessage>,
    pub(crate) write_outs: VecDeque<RTCMessage>,
}

impl RTCPeerConnection {
    /*
     let sctp_max_message_size = self
         .get_configuration()
         .setting_engine
         .sctp_max_message_size
         .as_usize();
     // STUN
     let demuxer_handler = DemuxerHandler::new();
     let stun_handler = StunHandler::new();
     // DTLS
     let dtls_handler = DtlsHandler::new();
     let sctp_handler = SctpHandler::new(sctp_max_message_size);
     let data_channel_handler = DataChannelHandler::new();
     // SRTP
     let srtp_handler = SrtpHandler::new();
     let interceptor_handler = InterceptorHandler::new();
     // Endpoint
     let endpoint_handler = EndpointHandler::new();
    */

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(&mut self.pipeline_context.demuxer_handler_context)
    }

    pub(crate) fn get_stun_handler(&mut self) -> StunHandler<'_> {
        StunHandler::new(&mut self.pipeline_context.stun_handler_context)
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
}

impl sansio::Protocol<TaggedBytesMut, RTCMessage, RTCEvent> for RTCPeerConnection {
    type Rout = RTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<(), Self::Error> {
        let mut intermediate_routs = VecDeque::new();

        // Demuxer
        let mut demuxer_handler = self.get_demuxer_handler();
        demuxer_handler.handle_read(msg)?;

        while let Some(msg) = demuxer_handler.poll_read() {
            intermediate_routs.push_back(msg);
        }

        // STUN
        let mut stun_handler = self.get_stun_handler();
        while let Some(msg) = intermediate_routs.pop_front() {
            stun_handler.handle_read(msg)?;
        }

        while let Some(msg) = stun_handler.poll_read() {
            intermediate_routs.push_back(msg);
        }

        // DTLS
        //let dtls_handler = DtlsHandler::new();
        //let sctp_handler = SctpHandler::new(sctp_max_message_size);
        //let data_channel_handler = DataChannelHandler::new();
        // SRTP
        //let srtp_handler = SrtpHandler::new();
        //let interceptor_handler = InterceptorHandler::new();

        // Endpoint
        let mut endpoint_handler = self.get_endpoint_handler();
        while let Some(msg) = intermediate_routs.pop_front() {
            endpoint_handler.handle_read(msg)?;
        }

        while let Some(msg) = endpoint_handler.poll_read() {
            intermediate_routs.push_back(msg);
        }

        // Finally, put intermediate_routs into RTCPeerConnection's routs
        while let Some(msg) = intermediate_routs.pop_front() {
            self.pipeline_context.read_outs.push_back(msg.message);
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.pipeline_context.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: RTCMessage) -> Result<(), Self::Error> {
        self.pipeline_context.write_outs.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        let mut intermediate_wouts = VecDeque::new();
        while let Some(msg) = self.pipeline_context.write_outs.pop_front() {
            intermediate_wouts.push_back(TaggedRTCMessage {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: msg,
            });
        }

        // Reverse order as handle_read

        // Endpoint
        let mut endpoint_handler = self.get_endpoint_handler();
        while let Some(msg) = intermediate_wouts.pop_front() {
            if let Err(err) = endpoint_handler.handle_write(msg) {
                warn!("Error handling intermediate RTC message: {}", err);
            }
        }

        while let Some(msg) = endpoint_handler.poll_write() {
            intermediate_wouts.push_back(msg);
        }

        //let interceptor_handler = InterceptorHandler::new();
        //let srtp_handler = SrtpHandler::new();
        //let data_channel_handler = DataChannelHandler::new();

        //let sctp_handler = SctpHandler::new(sctp_max_message_size);
        //let dtls_handler = DtlsHandler::new();

        // STUN
        let mut stun_handler = self.get_stun_handler();
        while let Some(msg) = intermediate_wouts.pop_front() {
            if let Err(err) = stun_handler.handle_write(msg) {
                warn!("Error handling intermediate RTC message: {}", err);
            }
        }

        while let Some(msg) = stun_handler.poll_write() {
            intermediate_wouts.push_back(msg);
        }

        // Demuxer
        let mut demuxer_handler = self.get_demuxer_handler();
        while let Some(msg) = intermediate_wouts.pop_front() {
            if let Err(err) = demuxer_handler.handle_write(msg) {
                warn!("Error handling intermediate RTC message: {}", err);
            }
        }

        // Final poll demuxer handler write out to pipeline's write out
        demuxer_handler.poll_write()
    }

    fn handle_event(&mut self, evt: RTCEvent) -> Result<(), Self::Error> {
        // Endpoint
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_event(evt)
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.poll_event()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        // Demuxer
        let mut demuxer_handler = self.get_demuxer_handler();
        demuxer_handler.handle_timeout(now)?;

        // STUN
        let mut stun_handler = self.get_stun_handler();
        stun_handler.handle_timeout(now)?;

        // DTLS
        //let dtls_handler = DtlsHandler::new();
        //let sctp_handler = SctpHandler::new(sctp_max_message_size);
        //let data_channel_handler = DataChannelHandler::new();
        // SRTP
        //let srtp_handler = SrtpHandler::new();
        //let interceptor_handler = InterceptorHandler::new();

        // Endpoint
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_timeout(now)?;

        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        let mut eto: Option<Instant> = None;

        // Demuxer
        let mut demuxer_handler = self.get_demuxer_handler();
        if let Some(t) = demuxer_handler.poll_timeout() {
            if let Some(e) = eto {
                eto = Some(std::cmp::min(t, e));
            } else {
                eto = Some(t);
            }
        }

        // STUN
        let mut stun_handler = self.get_stun_handler();
        if let Some(t) = stun_handler.poll_timeout() {
            if let Some(e) = eto {
                eto = Some(std::cmp::min(t, e));
            } else {
                eto = Some(t);
            }
        }

        // DTLS
        //let dtls_handler = DtlsHandler::new();
        //let sctp_handler = SctpHandler::new(sctp_max_message_size);
        //let data_channel_handler = DataChannelHandler::new();
        // SRTP
        //let srtp_handler = SrtpHandler::new();
        //let interceptor_handler = InterceptorHandler::new();

        // Endpoint
        let mut endpoint_handler = self.get_endpoint_handler();
        if let Some(t) = endpoint_handler.poll_timeout() {
            if let Some(e) = eto {
                eto = Some(std::cmp::min(t, e));
            } else {
                eto = Some(t);
            }
        }

        eto
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        // Demuxer
        let mut demuxer_handler = self.get_demuxer_handler();
        demuxer_handler.close()?;

        // STUN
        let mut stun_handler = self.get_stun_handler();
        stun_handler.close()?;

        // DTLS
        //let dtls_handler = DtlsHandler::new();
        //let sctp_handler = SctpHandler::new(sctp_max_message_size);
        //let data_channel_handler = DataChannelHandler::new();
        // SRTP
        //let srtp_handler = SrtpHandler::new();
        //let interceptor_handler = InterceptorHandler::new();

        // Endpoint
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.close()?;

        Ok(())
    }
}
