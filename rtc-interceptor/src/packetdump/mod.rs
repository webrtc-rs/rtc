//! Dumping the packets that pass through.
//!
//! pion's `interceptor/pkg/packetdump` logs every RTP and RTCP packet a connection sends or
//! receives, with filters, pluggable formatters and a place for the output to go. This is that,
//! shaped for the belt: one [`PacketDump`] interceptor sees both directions — inbound on the read
//! walk, outbound on the write walk — and forwards every packet unchanged.
//!
//! A dumped line is produced only for packets the filter accepts: the filter runs first, so a
//! rejected packet costs neither a format nor an allocation. An empty RTCP carrier
//! ([`Packet::Rtcp(vec![])`](crate::Packet::Rtcp)) holds attributes, not packets, and dumps
//! nothing.
//!
//! # Example
//!
//! ```
//! use rtc_interceptor::{PacketDumpBuilder, Registry, Slot};
//!
//! let chain = Registry::new()
//!     .with(Slot::PacketDump, PacketDumpBuilder::new().build())
//!     .build();
//! # let _ = chain;
//! ```

#[cfg(test)]
mod packetdump_test;

use std::collections::VecDeque;
use std::time::Instant;

use sansio::Protocol;
use shared::error::Error;

use crate::packet::{Packet, TaggedPacket};
use crate::{Interceptor, StreamInfo};

/// Where dumped lines go.
///
/// The sink is called once per accepted packet, with the formatted line (which owns its trailing
/// newline, as pion's formatters do). Implement this to write to a file, a channel or a test
/// recorder; the default is [`LogSink`].
pub trait PacketDumpSink: Send + Sync {
    /// Writes one formatted line.
    fn write(&mut self, line: &str);
}

/// The default sink: each line at DEBUG level through the `log` crate.
#[derive(Default, Debug, Clone, Copy)]
pub struct LogSink;

impl PacketDumpSink for LogSink {
    fn write(&mut self, line: &str) {
        log::debug!("{line}");
    }
}

/// Decides whether an RTP packet is dumped. `true` dumps it.
pub type RtpFilter = Box<dyn Fn(&rtp::Packet) -> bool + Send + Sync>;
/// Decides whether an RTCP packet is dumped, called once per packet of a compound. `true`
/// dumps it.
pub type RtcpFilter = Box<dyn Fn(&dyn rtcp::Packet) -> bool + Send + Sync>;
/// Formats an RTP packet into the line the sink writes. The line owns its trailing newline.
pub type RtpFormatter = Box<dyn Fn(&rtp::Packet) -> String + Send + Sync>;
/// Formats an RTCP packet into the line the sink writes. The line owns its trailing newline.
pub type RtcpFormatter = Box<dyn Fn(&dyn rtcp::Packet) -> String + Send + Sync>;

/// Builds a [`PacketDump`].
///
/// Everything is optional: with no configuration every RTP and RTCP packet in both directions is
/// formatted like pion formats it and written to the [`LogSink`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::PacketDumpBuilder;
/// use std::sync::{Arc, Mutex};
///
/// // A sink that keeps the lines, so a test (or an application) can read them back.
/// #[derive(Clone, Default)]
/// struct Recorder(Arc<Mutex<Vec<String>>>);
/// impl rtc_interceptor::PacketDumpSink for Recorder {
///     fn write(&mut self, line: &str) {
///         self.0.lock().unwrap().push(line.to_owned());
///     }
/// }
///
/// let recorder = Recorder::default();
/// let dumper = PacketDumpBuilder::new()
///     .rtp_filter(|_| true)
///     .sink(Box::new(recorder.clone()))
///     .build();
/// # let _ = dumper;
/// ```
pub struct PacketDumpBuilder {
    rtp_filter: Option<RtpFilter>,
    rtcp_filter: Option<RtcpFilter>,
    rtp_formatter: Option<RtpFormatter>,
    rtcp_formatter: Option<RtcpFormatter>,
    sink: Option<Box<dyn PacketDumpSink>>,
}

impl Default for PacketDumpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketDumpBuilder {
    /// A builder that dumps everything, like pion's defaults.
    pub fn new() -> Self {
        Self {
            rtp_filter: None,
            rtcp_filter: None,
            rtp_formatter: None,
            rtcp_formatter: None,
            sink: None,
        }
    }

    /// Dumps only the RTP packets `filter` accepts. Without this, every RTP packet is dumped.
    pub fn rtp_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&rtp::Packet) -> bool + Send + Sync + 'static,
    {
        self.rtp_filter = Some(Box::new(filter));
        self
    }

    /// Dumps only the RTCP packets `filter` accepts, called once per packet of a compound.
    /// Without this, every RTCP packet is dumped.
    pub fn rtcp_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&dyn rtcp::Packet) -> bool + Send + Sync + 'static,
    {
        self.rtcp_filter = Some(Box::new(filter));
        self
    }

    /// Formats RTP packets with `formatter` instead of the default, which is the packet's
    /// `Display` plus a newline, as pion's default formatter writes it.
    pub fn rtp_formatter<F>(mut self, formatter: F) -> Self
    where
        F: Fn(&rtp::Packet) -> String + Send + Sync + 'static,
    {
        self.rtp_formatter = Some(Box::new(formatter));
        self
    }

    /// Formats RTCP packets with `formatter` instead of the default, which is the packet's
    /// `Display` plus a newline, as pion's default formatter writes it.
    pub fn rtcp_formatter<F>(mut self, formatter: F) -> Self
    where
        F: Fn(&dyn rtcp::Packet) -> String + Send + Sync + 'static,
    {
        self.rtcp_formatter = Some(Box::new(formatter));
        self
    }

    /// Writes the lines to `sink` instead of the [`LogSink`].
    pub fn sink(mut self, sink: Box<dyn PacketDumpSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Builds the interceptor.
    pub fn build(self) -> PacketDump {
        PacketDump {
            read_queue: VecDeque::new(),
            write_queue: VecDeque::new(),
            rtp_filter: self.rtp_filter,
            rtcp_filter: self.rtcp_filter,
            rtp_formatter: self.rtp_formatter,
            rtcp_formatter: self.rtcp_formatter,
            sink: self.sink.unwrap_or_else(|| Box::new(LogSink)),
        }
    }
}

/// Dumps every RTP and RTCP packet that passes through, in both directions, and forwards
/// everything unchanged.
///
/// Sitting at [`Slot::PacketDump`](crate::Slot::PacketDump) — the wire-most slot — it sees
/// what really leaves and arrives: a departing packet reaches it last, after pacing and
/// transport-wide numbering, and an arriving one reaches it first, before anything rebuilds or
/// re-stamps it. The dump is an observation only; the forwarded packet is the same packet, not a
/// copy.
pub struct PacketDump {
    read_queue: VecDeque<TaggedPacket>,
    write_queue: VecDeque<TaggedPacket>,
    rtp_filter: Option<RtpFilter>,
    rtcp_filter: Option<RtcpFilter>,
    rtp_formatter: Option<RtpFormatter>,
    rtcp_formatter: Option<RtcpFormatter>,
    sink: Box<dyn PacketDumpSink>,
}

impl PacketDump {
    /// Formats and writes the packets the filters accept. The filter runs first: a rejected
    /// packet is never formatted, never allocated for.
    fn dump(&mut self, packet: &Packet) {
        match packet {
            Packet::Rtp(rtp) => {
                if let Some(filter) = &self.rtp_filter
                    && !filter(rtp)
                {
                    return;
                }
                let line = match &self.rtp_formatter {
                    Some(formatter) => formatter(rtp),
                    None => format!("{rtp}\n"),
                };
                self.sink.write(&line);
            }
            Packet::Rtcp(pkts) => {
                for pkt in pkts {
                    if let Some(filter) = &self.rtcp_filter
                        && !filter(pkt.as_ref())
                    {
                        continue;
                    }
                    let line = match &self.rtcp_formatter {
                        Some(formatter) => formatter(pkt.as_ref()),
                        None => format!("{pkt}\n"),
                    };
                    self.sink.write(&line);
                }
            }
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for PacketDump {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.dump(&msg.message.packet);
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.dump(&msg.message.packet);
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }
}

impl Interceptor for PacketDump {
    fn bind_local_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}
