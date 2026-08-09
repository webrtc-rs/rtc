pub(crate) mod datachannel;
pub(crate) mod demuxer;
pub(crate) mod dtls;
pub(crate) mod endpoint;
pub(crate) mod ice;
pub(crate) mod interceptor;
pub(crate) mod sctp;
pub(crate) mod srtp;

use crate::peer_connection::RTCPeerConnection;
use crate::peer_connection::event::RTCPeerConnectionEvent;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEvent};
use crate::peer_connection::handler::datachannel::{DataChannelHandler, DataChannelHandlerContext};
use crate::peer_connection::handler::demuxer::{DemuxerHandler, DemuxerHandlerContext};
use crate::peer_connection::handler::dtls::{DtlsHandler, DtlsHandlerContext};
use crate::peer_connection::handler::endpoint::{EndpointHandler, EndpointHandlerContext};
use crate::peer_connection::handler::ice::{IceHandler, IceHandlerContext};
use crate::peer_connection::handler::interceptor::{InterceptorHandler, InterceptorHandlerContext};
use crate::peer_connection::handler::sctp::{SctpHandler, SctpHandlerContext};
use crate::peer_connection::handler::srtp::{SrtpHandler, SrtpHandlerContext};
use crate::peer_connection::message::{
    RTCMessage, TaggedRTCMessage,
    internal::{
        ApplicationMessage, DTLSMessage, DataChannelEvent, RTCMessageInternal, RTPMessage,
        TaggedRTCMessageInternal,
    },
};
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::peer_connection::state::signaling_state::RTCSignalingState;
use crate::statistics::accumulator::RTCStatsAccumulator;
use ::interceptor::Interceptor;
use ::interceptor::Packet;
use log::warn;
use shared::TaggedBytesMut;
use shared::error::{Error, flatten_errs};
use std::collections::VecDeque;
use std::time::Instant;

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
    pub(crate) read_outs: VecDeque<TaggedRTCMessage>,
    pub(crate) write_outs: VecDeque<TaggedBytesMut>,
    pub(crate) event_outs: VecDeque<RTCPeerConnectionEvent>,

    // Statistics accumulator
    pub(crate) stats: RTCStatsAccumulator,

    /// How many of `read_outs` are `RTCMessage::DataChannelMessage`.
    ///
    /// The SCTP handler bounds its drain against this, and it must **not** be
    /// `read_outs.len()`: that queue also carries RTP and RTCP, which on a media connection
    /// dwarf the data-channel traffic. Using the total would let a video flood stop the SCTP
    /// handler draining its reassembly queues and throttle the peer's *data channels* — a
    /// connection whose data-channel consumer is perfectly healthy would be slowed down by
    /// unrelated media.
    ///
    /// Maintained incrementally rather than counted on demand because `get_sctp_handler` runs
    /// on the per-datagram path, where an O(len) scan of a media backlog is not free.
    ///
    /// Exactly two places may touch it, and they must stay mirror images: the push in
    /// `handle_read` and the pop in `poll_read`. Drift either way decays the bound into
    /// permanent throttling or none at all.
    pub(crate) data_channel_read_backlog: usize,
}

impl<I> RTCPeerConnection<I>
where
    I: Interceptor,
{
    /*
     Pipeline Flow (Read Path):
     Raw Bytes -> Demuxer -> ICE -> DTLS -> SCTP -> DataChannel -> SRTP -> Interceptor -> Endpoint -> Application

     Pipeline Flow (Write Path):
     Application -> Endpoint -> Interceptor -> SRTP -> DataChannel -> SCTP -> DTLS -> ICE -> Demuxer -> Raw Bytes
    */

    pub(crate) fn get_demuxer_handler(&mut self) -> DemuxerHandler<'_> {
        DemuxerHandler::new(
            &mut self.pipeline_context.demuxer_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_ice_handler(&mut self) -> IceHandler<'_> {
        IceHandler::new(
            &mut self.pipeline_context.ice_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_dtls_handler(&mut self) -> DtlsHandler<'_> {
        DtlsHandler::new(
            &mut self.pipeline_context.dtls_handler_context,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_sctp_handler(&mut self) -> SctpHandler<'_> {
        // The SCTP handler bounds how much it pulls out of the reassembly queues against what
        // the application has not yet consumed. That backlog lives here, not in the handler's
        // own `read_outs` — the pipeline empties that within a single `handle_read` — and it
        // counts *data-channel* messages only, so unrelated media cannot throttle SCTP.
        let downstream_backlog = self.pipeline_context.data_channel_read_backlog;
        SctpHandler::new(
            &mut self.pipeline_context.sctp_handler_context,
            downstream_backlog,
        )
    }

    pub(crate) fn get_datachannel_handler(&mut self) -> DataChannelHandler<'_> {
        DataChannelHandler::new(
            &mut self.pipeline_context.datachannel_handler_context,
            &mut self.data_channels,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_srtp_handler(&mut self) -> SrtpHandler<'_> {
        SrtpHandler::new(&mut self.pipeline_context.srtp_handler_context)
    }

    pub(crate) fn get_interceptor_handler(&mut self) -> InterceptorHandler<'_, I> {
        InterceptorHandler::new(
            &mut self.pipeline_context.interceptor_handler_context,
            &mut self.interceptor,
            &mut self.pipeline_context.stats,
        )
    }

    pub(crate) fn get_endpoint_handler(&mut self) -> EndpointHandler<'_, I> {
        EndpointHandler::new(
            &mut self.pipeline_context.endpoint_handler_context,
            &mut self.rtp_transceivers,
            &self.media_engine,
            &mut self.interceptor,
            &mut self.pipeline_context.stats,
        )
    }
}

impl<I> sansio::Protocol<TaggedBytesMut, TaggedRTCMessage, TaggedRTCEvent> for RTCPeerConnection<I>
where
    I: Interceptor,
{
    type Rout = TaggedRTCMessage;
    type Wout = TaggedBytesMut;
    type Eout = RTCPeerConnectionEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<(), Self::Error> {
        let mut intermediate_routs = VecDeque::new();
        intermediate_routs.push_back(TaggedRTCMessageInternal {
            now: msg.now,
            transport: msg.transport,
            message: RTCMessageInternal::Raw(msg.message),
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
            let rtc_message = match msg.message {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(application_message)) => {
                    if let DataChannelEvent::Message(data_channel_message) =
                        application_message.data_channel_event
                    {
                        Some(RTCMessage::DataChannelMessage(
                            application_message.data_channel_id,
                            data_channel_message,
                        ))
                    } else {
                        None
                    }
                }
                RTCMessageInternal::Rtp(RTPMessage::TrackPacket(track_packet)) => {
                    match track_packet.packet {
                        Packet::Rtp(packet) => {
                            Some(RTCMessage::RtpPacket(track_packet.track_id, packet))
                        }
                        Packet::Rtcp(packet) => {
                            Some(RTCMessage::RtcpPacket(track_packet.track_id, packet))
                        }
                        _ => None,
                    }
                }
                _ => None,
            };

            if let Some(rtc_message) = rtc_message {
                // The instant travels with the message: the application learns when the packet
                // was observed at the socket, not when it happened to drain it.
                if matches!(rtc_message, RTCMessage::DataChannelMessage(..)) {
                    self.pipeline_context.data_channel_read_backlog += 1;
                }
                self.pipeline_context.read_outs.push_back(TaggedRTCMessage {
                    now: msg.now,
                    message: rtc_message,
                });
            }
        }

        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        let msg = self.pipeline_context.read_outs.pop_front()?;
        if matches!(msg.message, RTCMessage::DataChannelMessage(..)) {
            debug_assert!(self.pipeline_context.data_channel_read_backlog > 0);
            self.pipeline_context.data_channel_read_backlog = self
                .pipeline_context
                .data_channel_read_backlog
                .saturating_sub(1);
        }
        Some(msg)
    }

    fn handle_write(&mut self, msg: TaggedRTCMessage) -> Result<(), Self::Error> {
        let now = msg.now;
        let rtc_message_internal = match msg.message {
            RTCMessage::DataChannelMessage(data_channel_id, data_channel_message) => {
                RTCMessageInternal::Dtls(DTLSMessage::DataChannel(ApplicationMessage {
                    data_channel_id,
                    data_channel_event: DataChannelEvent::Message(data_channel_message),
                }))
            }
            RTCMessage::RtpPacket(_track_id, rtp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtp(rtp_packet)))
            }
            RTCMessage::RtcpPacket(_track_id, rtcp_packet) => {
                RTCMessageInternal::Rtp(RTPMessage::Packet(Packet::Rtcp(rtcp_packet)))
            }
        };

        // Only endpoint can handle user write message
        let mut endpoint_handler = self.get_endpoint_handler();
        endpoint_handler.handle_write(TaggedRTCMessageInternal {
            now,
            transport: Default::default(),
            message: rtc_message_internal,
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
            if let RTCMessageInternal::Raw(message) = msg.message {
                self.pipeline_context.write_outs.push_back(TaggedBytesMut {
                    now: msg.now,
                    transport: msg.transport,
                    message,
                });
            }
        }

        self.pipeline_context.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEvent) -> Result<(), Self::Error> {
        // `RTCEvent` is `pub enum RTCEvent {}` — uninhabited, reserved for future use — so no
        // caller can construct one and this arm is unreachable. Diverging on the empty match
        // keeps that fact in the type system, and avoids inventing an instant to wrap the
        // event with when there is none to be had. C3-03 replaces this with `evt.now` once
        // the public channel carries a timestamp.
        match evt.event {}
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
        while let Some(evt_internal) = intermediate_eouts.pop_front() {
            match &evt_internal.event {
                RTCEventInternal::RTCPeerConnectionEvent(
                    RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(_),
                )
                | RTCEventInternal::DTLSHandshakeComplete(_, _) => {
                    self.update_connection_state(false);
                }
                _ => {}
            };

            if let RTCEventInternal::RTCPeerConnectionEvent(evt) = evt_internal.event {
                self.pipeline_context.event_outs.push_back(evt);
            }
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
        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #1)
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return Ok(());
        }

        // https://www.w3.org/TR/webrtc/#dom-rtcpeerconnection-close (step #3)
        self.signaling_state = RTCSignalingState::Closed;

        // Try closing everything and collect the errors
        // Shutdown strategy:
        // 1. All Conn close by closing their underlying Conn.
        // 2. A Mux stops this chain. It won't close the underlying
        //    Conn if one of the endpoints is closed down. To
        //    continue the chain the Mux has to be closed.
        for_each_handler!(forward: process_handler!(self, handler, {
            handler.close()?;
        }));

        let close_errs: Vec<Error> = vec![];

        /* TODO:
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
         */

        self.update_connection_state(true);

        flatten_errs(close_errs)
    }
}

#[cfg(test)]
mod handler_test {
    use super::*;
    use crate::data_channel::message::RTCDataChannelMessage;
    use crate::peer_connection::RTCPeerConnectionBuilder;
    use bytes::BytesMut;
    use sansio::Protocol;
    use std::time::Duration;

    /// `poll_read` must decrement `data_channel_read_backlog` for exactly the messages
    /// `handle_read` incremented it for, and no others.
    ///
    /// This is the pop half of the invariant the SCTP back-pressure bound rests on. If the
    /// two halves ever disagree the counter drifts, and the bound decays into either
    /// permanent throttling (count too high) or none at all (count too low). A pop that
    /// decremented for media would underflow — `-= 1` on `0` panics in debug builds — which
    /// is what this would catch.
    #[test]
    fn poll_read_decrements_the_backlog_for_data_channel_messages_only() {
        let base = Instant::now();
        let mut pc = RTCPeerConnectionBuilder::new()
            .build(base)
            .expect("build peer connection");

        // Stand in for what `handle_read` would have queued: media outnumbering data, which
        // is the shape that made `read_outs.len()` the wrong signal in the first place.
        let mut expected_backlog = 0usize;
        for i in 0..10 {
            let message = if i % 5 == 0 {
                expected_backlog += 1;
                RTCMessage::DataChannelMessage(0, RTCDataChannelMessage::default())
            } else {
                RTCMessage::RtpPacket(Default::default(), ::rtp::packet::Packet::default())
            };
            pc.pipeline_context
                .read_outs
                .push_back(TaggedRTCMessage { now: base, message });
        }
        pc.pipeline_context.data_channel_read_backlog = expected_backlog;
        assert_eq!(expected_backlog, 2, "fixture sanity");

        let mut drained = 0;
        while pc.poll_read().is_some() {
            drained += 1;
        }

        assert_eq!(drained, 10, "every message must be handed over");
        assert_eq!(
            pc.pipeline_context.data_channel_read_backlog, 0,
            "a fully drained pipeline must report no data-channel backlog, or SCTP stays \
             throttled forever"
        );
    }

    /// The instant the application supplies on `handle_write` is the one the core stamps the
    /// resulting internal message with — not a reading the core took for itself. Before C3-03
    /// the public `Win` was a bare `RTCMessage`, so this entry point had no time source and
    /// stamped `Instant::now()`.
    #[test]
    fn handle_write_stamps_from_the_caller_not_the_clock() {
        let base = Instant::now();
        let t = |secs| base + Duration::from_secs(secs);

        let mut pc = RTCPeerConnectionBuilder::new()
            .build(t(0))
            .expect("a default peer connection builds");

        pc.handle_write(TaggedRTCMessage {
            now: t(5),
            message: RTCMessage::DataChannelMessage(
                1,
                RTCDataChannelMessage {
                    is_string: true,
                    data: BytesMut::from(&b"hello"[..]),
                },
            ),
        })
        .expect("handle_write queues the message");

        let queued = pc
            .pipeline_context
            .endpoint_handler_context
            .write_outs
            .front()
            .expect("the message reaches the endpoint handler");

        assert_eq!(
            queued.now,
            t(5),
            "the internal message carries the caller's instant, not an ambient reading"
        );
        assert_ne!(queued.now, t(0), "and not the construction instant either");
    }
}
