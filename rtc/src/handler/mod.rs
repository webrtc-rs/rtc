pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod ice;
pub(crate) mod interceptor;
pub mod message;
pub(crate) mod sctp;
pub(crate) mod srtp;

use crate::handler::datachannel::{DataChannelHandler, DataChannelHandlerContext};
use crate::handler::demuxer::{DemuxerHandler, DemuxerHandlerContext};
use crate::handler::dtls::{DtlsHandler, DtlsHandlerContext};
use crate::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
use crate::handler::ice::{IceHandler, IceHandlerContext};
use crate::handler::interceptor::{InterceptorHandler, InterceptorHandlerContext};
use crate::handler::message::{RTCEvent, RTCEventInternal, RTCMessage, TaggedRTCMessage};
use crate::handler::sctp::{SctpHandler, SctpHandlerContext};
use crate::handler::srtp::{SrtpHandler, SrtpHandlerContext};
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::RTCPeerConnection;
use log::warn;
use shared::error::Error;
use shared::TaggedBytesMut;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_TIMEOUT_DURATION: Duration = Duration::from_secs(86400); // 1 day duration

/// Forward handler list - invokes callback with handler list
macro_rules! forward_handlers {
    ($callback:ident!($($args:tt)*)) => {
        $callback!(
            $($args)*,
            [
                get_demuxer_handler,
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
    // Handler contexts
    pub(crate) demuxer_handler_context: DemuxerHandlerContext,
    pub(crate) ice_handler_context: IceHandlerContext,
    pub(crate) dtls_handler_context: DtlsHandlerContext,
    pub(crate) sctp_handler_context: SctpHandlerContext,
    pub(crate) datachannel_handler_context: DataChannelHandlerContext,
    pub(crate) srtp_handler_context: SrtpHandlerContext,
    pub(crate) interceptor_handler_context: InterceptorHandlerContext,
    pub(crate) endpoint_handler_context: EndpointHandlerContext,

    // Pipeline
    pub(crate) read_outs: VecDeque<RTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,
}

impl RTCPeerConnection {
    /*
     Pipeline Flow (Read Path):
     Raw Bytes -> Demuxer -> ICE -> DTLS -> SCTP -> DataChannel -> SRTP -> Interceptor -> Endpoint -> Application

     Pipeline Flow (Write Path):
     Application -> Endpoint -> Interceptor -> SRTP -> DataChannel -> SCTP -> DTLS -> ICE -> Demuxer -> Raw Bytes
    */

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(&mut self.pipeline_context.demuxer_handler_context)
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
        DataChannelHandler::new(
            &mut self.pipeline_context.datachannel_handler_context,
            &mut self.data_channels,
        )
    }

    pub(crate) fn get_srtp_handler(&mut self) -> SrtpHandler<'_> {
        SrtpHandler::new(&mut self.pipeline_context.srtp_handler_context)
    }

    pub(crate) fn get_interceptor_handler(&mut self) -> InterceptorHandler<'_> {
        InterceptorHandler::new(&mut self.pipeline_context.interceptor_handler_context)
    }

    pub(crate) fn get_endpoint_handler(&mut self) -> EndpointHandler<'_> {
        EndpointHandler::new(&mut self.pipeline_context.endpoint_handler_context)
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
                if let Err(err) = handler.handle_read(msg) {
                    warn!("{}.handle_read got error: {}", handler.name(), err);
                }
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
        // Only endpoint can handle user write message
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_write(TaggedRTCMessage {
            now: Instant::now(),
            transport: Default::default(),
            message: msg,
        })
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        let mut intermediate_wouts = VecDeque::new();

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
        while let Some(msg) = intermediate_wouts.pop_front() {
            if let RTCMessage::Raw(message) = msg.message {
                self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                    now: msg.now,
                    transport: msg.transport,
                    message,
                });
            }
        }

        self.pipeline_context.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: RTCEvent) -> Result<(), Self::Error> {
        // Only endpoint can handle user event
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_event(RTCEventInternal::RTCEvent(evt))
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        let mut intermediate_eouts = VecDeque::new();

        for_each_handler!(forward: process_handler!(self, handler, {
            while let Some(evt) = intermediate_eouts.pop_front() {
                if let Err(err) = handler.handle_event(evt) {
                    warn!("{}.handle_event got error: {}", handler.name(), err);
                }
            }
            while let Some(msg) = handler.poll_event() {
                intermediate_eouts.push_back(msg);
            }
        }));

        // Finally, put intermediate_eouts into RTCPeerConnection's eouts
        while let Some(RTCEventInternal::RTCPeerConnectionEvent(evt)) =
            intermediate_eouts.pop_front()
        {
            self.pipeline_context.event_outs.push_back(evt);
        }

        self.pipeline_context.event_outs.pop_front()
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

        Ok(())
    }
}
