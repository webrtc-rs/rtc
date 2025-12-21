pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod ice;
pub(crate) mod interceptor;
pub mod message;
pub(crate) mod sctp;
pub(crate) mod srtp;
pub(crate) mod stun;

use crate::handler::datachannel::{DataChannelHandler, DataChannelHandlerContext};
use crate::handler::demuxer::{DemuxerHandler, DemuxerHandlerContext};
use crate::handler::dtls::{DtlsHandler, DtlsHandlerContext};
use crate::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
use crate::handler::ice::{IceHandler, IceHandlerContext};
use crate::handler::interceptor::{InterceptorHandler, InterceptorHandlerContext};
use crate::handler::message::{RTCEvent, RTCMessage, TaggedRTCMessage};
use crate::handler::sctp::{SctpHandler, SctpHandlerContext};
use crate::handler::srtp::{SrtpHandler, SrtpHandlerContext};
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

/// Forward handler list - invokes callback with handler list
macro_rules! forward_handlers {
    ($callback:ident!($($args:tt)*)) => {
        $callback!(
            $($args)*,
            [
                get_demuxer_handler,
                get_stun_handler,
                get_ice_handler,
                get_dtls_handler,
                get_sctp_handler,
                get_datachannel_handler,
                get_srtp_handler,
                get_interceptor_handler,
                get_endpoint_handler
            ]
        )
    };
}

/// Reverse handler list - invokes callback with handler list
macro_rules! reverse_handlers {
    ($callback:ident!($($args:tt)*)) => {
        $callback!(
            $($args)*,
            [
                get_endpoint_handler,
                get_interceptor_handler,
                get_srtp_handler,
                get_datachannel_handler,
                get_sctp_handler,
                get_dtls_handler,
                get_ice_handler,
                get_stun_handler,
                get_demuxer_handler
            ]
        )
    };
}

/// Helper macro that processes a list of handlers with code blocks
macro_rules! process_handler_list {
    (call_macro: process_handler!($self:expr, $handler:ident, $code:block), [$($getter:ident),+]) => {{
        $(
            {
                let mut $handler = $self.$getter();
                $code
            }
        )+
    }};
}

/// Unified macro to iterate over handlers with code blocks
macro_rules! for_each_handler {
    // Forward order: execute code block for each handler
    (forward: $macro:ident!($($args:tt)*)) => {
        forward_handlers!(process_handler_list!(call_macro: $macro!($($args)*)))
    };

    // Reverse order: execute code block for each handler
    (reverse: $macro:ident!($($args:tt)*)) => {
        reverse_handlers!(process_handler_list!(call_macro: $macro!($($args)*)))
    };
}

#[derive(Default)]
pub(crate) struct PipelineContext {
    // Shared states
    pub(crate) transport_states: TransportStates,

    // Handler contexts
    pub(crate) demuxer_handler_context: DemuxerHandlerContext,
    pub(crate) stun_handler_context: StunHandlerContext,
    pub(crate) ice_handler_context: IceHandlerContext,
    pub(crate) dtls_handler_context: DtlsHandlerContext,
    pub(crate) sctp_handler_context: SctpHandlerContext,
    pub(crate) datachannel_handler_context: DataChannelHandlerContext,
    pub(crate) srtp_handler_context: SrtpHandlerContext,
    pub(crate) interceptor_handler_context: InterceptorHandlerContext,
    pub(crate) endpoint_handler_context: EndpointHandlerContext,

    // Pipeline
    pub(crate) read_outs: VecDeque<RTCMessage>,
    pub(crate) write_outs: VecDeque<RTCMessage>,
}

impl RTCPeerConnection {
    /*
     Pipeline Flow (Read Path):
     Raw Bytes -> Demuxer -> STUN -> ICE -> DTLS -> SCTP -> DataChannel -> SRTP -> Interceptor -> Endpoint -> Application

     Pipeline Flow (Write Path):
     Application -> Endpoint -> Interceptor -> SRTP -> DataChannel -> SCTP -> DTLS -> ICE -> STUN -> Demuxer -> Raw Bytes
    */

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(&mut self.pipeline_context.demuxer_handler_context)
    }

    pub(crate) fn get_stun_handler(&mut self) -> StunHandler<'_> {
        StunHandler::new(&mut self.pipeline_context.stun_handler_context)
    }

    pub(crate) fn get_ice_handler(&mut self) -> IceHandler<'_> {
        IceHandler::new(&mut self.pipeline_context.ice_handler_context)
    }

    pub(crate) fn get_dtls_handler(&mut self) -> DtlsHandler<'_> {
        DtlsHandler::new(&mut self.pipeline_context.dtls_handler_context)
    }

    pub(crate) fn get_sctp_handler(&mut self) -> SctpHandler<'_> {
        SctpHandler::new(&mut self.pipeline_context.sctp_handler_context)
    }

    pub(crate) fn get_datachannel_handler(&mut self) -> DataChannelHandler<'_> {
        DataChannelHandler::new(&mut self.pipeline_context.datachannel_handler_context)
    }

    pub(crate) fn get_srtp_handler(&mut self) -> SrtpHandler<'_> {
        SrtpHandler::new(&mut self.pipeline_context.srtp_handler_context)
    }

    pub(crate) fn get_interceptor_handler(&mut self) -> InterceptorHandler<'_> {
        InterceptorHandler::new(&mut self.pipeline_context.interceptor_handler_context)
    }

    pub(crate) fn get_endpoint_handler(&mut self) -> EndpointHandler<'_> {
        EndpointHandler::new(
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
        intermediate_routs.push_back(TaggedRTCMessage {
            now: msg.now,
            transport: msg.transport,
            message: RTCMessage::Raw(msg.message),
        });

        for_each_handler!(forward: process_handler!(self, handler, {
            while let Some(msg) = intermediate_routs.pop_front() {
                handler.handle_read(msg)?;
            }
            while let Some(msg) = handler.poll_read() {
                intermediate_routs.push_back(msg);
            }
        }));

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

        for_each_handler!(reverse: process_handler!(self, handler, {
            while let Some(msg) = intermediate_wouts.pop_front() {
                if let Err(err) = handler.handle_write(msg) {
                    warn!("{}.handle_write got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_write() {
                intermediate_wouts.push_back(msg);
            }
        }));

        // Final poll write out to pipeline's write out
        if let Some(msg) = intermediate_wouts.pop_front() {
            if let RTCMessage::Raw(message) = msg.message {
                return Some(TaggedBytesMut {
                    now: msg.now,
                    transport: msg.transport,
                    message,
                });
            }
        }
        None
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
        for_each_handler!(forward: process_handler!(self, handler, {
            handler.handle_timeout(now)?;
        }));
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        let mut eto: Option<Instant> = None;
        for_each_handler!(forward: process_handler!(self, handler, {
            if let Some(next) = handler.poll_timeout() {
                eto = Some(eto.map_or(next, |curr| std::cmp::min(curr, next)));
            }
        }));
        eto
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        for_each_handler!(forward: process_handler!(self, handler, {
            handler.close()?;
        }));

        /*
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #1)
        if self.internal.is_closed.load(Ordering::SeqCst) {
            return Ok(());
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #2)
        self.internal.is_closed.store(true, Ordering::SeqCst);

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #3)
        self.internal
            .signaling_state
            .store(RTCSignalingState::Closed as u8, Ordering::SeqCst);

        // Try closing everything and collect the errors
        // Shutdown strategy:
        // 1. All Conn close by closing their underlying Conn.
        // 2. A Mux stops this chain. It won't close the underlying
        //    Conn if one of the endpoints is closed down. To
        //    continue the chain the Mux has to be closed.
        let mut close_errs = vec![];

        if let Err(err) = self.interceptor.close().await {
            close_errs.push(Error::new(format!("interceptor: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #4)
        {
            let mut rtp_transceivers = self.internal.rtp_transceivers.lock().await;
            for t in &*rtp_transceivers {
                if let Err(err) = t.stop().await {
                    close_errs.push(Error::new(format!("rtp_transceivers: {err}")));
                }
            }
            rtp_transceivers.clear();
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #5)
        {
            let mut data_channels = self.internal.sctp_transport.data_channels.lock().await;
            for d in &*data_channels {
                if let Err(err) = d.close().await {
                    close_errs.push(Error::new(format!("data_channels: {err}")));
                }
            }
            data_channels.clear();
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #6)
        if let Err(err) = self.internal.sctp_transport.stop().await {
            close_errs.push(Error::new(format!("sctp_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #7)
        if let Err(err) = self.internal.dtls_transport.stop().await {
            close_errs.push(Error::new(format!("dtls_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #8, #9, #10)
        if let Err(err) = self.internal.ice_transport.stop().await {
            close_errs.push(Error::new(format!("ice_transport: {err}")));
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #11)
        RTCPeerConnection::update_connection_state(
            &self.internal.on_peer_connection_state_change_handler,
            &self.internal.is_closed,
            &self.internal.peer_connection_state,
            self.ice_connection_state(),
            self.internal.dtls_transport.state(),
        )
        .await;

        if let Err(err) = self.internal.ops.close().await {
            close_errs.push(Error::new(format!("ops: {err}")));
        }

        flatten_errs(close_errs)*/
        Ok(())
    }
}
