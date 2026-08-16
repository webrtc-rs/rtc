//! Emits RFC 8888 congestion control feedback for the streams being received.

use super::recorder::CcFeedbackRecorder;
use crate::stream_info::StreamInfo;
use crate::{Interceptor, Packet, TaggedPacket, interceptor};
use rtcp::transport_feedbacks::cc_feedback_report::Ecn;
use shared::TransportContext;
use shared::error::Error;
use shared::time::SystemInstant;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

/// How often feedback is sent when no interval is configured.
pub const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);

/// Byte budget for one report, chosen to sit inside a conservative path MTU.
pub const DEFAULT_MAX_REPORT_SIZE: usize = 1200;

/// Builder for [`Rfc8888Interceptor`].
///
/// # Example
///
/// ```
/// use rtc_interceptor::{Registry, Rfc8888Builder};
/// use std::time::Duration;
///
/// let chain = Registry::new()
///     .with(Rfc8888Builder::new().with_interval(Duration::from_millis(50)).build())
///     .build();
/// ```
pub struct Rfc8888Builder<P> {
    interval: Duration,
    max_report_size: usize,
    sender_ssrc: u32,
    _phantom: PhantomData<P>,
}

impl<P> Default for Rfc8888Builder<P> {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            max_report_size: DEFAULT_MAX_REPORT_SIZE,
            sender_ssrc: 0,
            _phantom: PhantomData,
        }
    }
}

impl<P> Rfc8888Builder<P> {
    /// Create a builder with the default interval and report size.
    pub fn new() -> Self {
        Self::default()
    }

    /// How often feedback is sent.
    ///
    /// Congestion control wants this often — the estimate is only as fresh as the feedback
    /// driving it — traded against the RTCP bandwidth it costs.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Byte budget for one report.
    ///
    /// A report larger than the path MTU is fragmented or dropped, and feedback that does not
    /// arrive is worth nothing, so a report describes fewer packets rather than growing.
    pub fn with_max_report_size(mut self, max_report_size: usize) -> Self {
        self.max_report_size = max_report_size;
        self
    }

    /// The SSRC these reports are sent from.
    pub fn with_sender_ssrc(mut self, sender_ssrc: u32) -> Self {
        self.sender_ssrc = sender_ssrc;
        self
    }

    /// Build the interceptor factory function.
    pub fn build(self) -> impl FnOnce(P) -> Rfc8888Interceptor<P> {
        move |inner| {
            Rfc8888Interceptor::new(inner, self.interval, self.max_report_size, self.sender_ssrc)
        }
    }
}

/// Reports when each packet of each bound remote stream arrived ([RFC 8888]).
///
/// # Differences from upstream
///
/// `pion/interceptor` injects a `SenderTicker` and a `SenderNow` so its tests can control time.
/// Sans-I/O needs neither: every instant arrives as a parameter, so the tests drive the clock by
/// passing one. Both are dropped.
///
/// Upstream's `Recorder` also never sets its sender SSRC, so every report it builds claims to come
/// from SSRC 0. Here it is configured.
///
/// [RFC 8888]: https://www.rfc-editor.org/rfc/rfc8888
#[derive(Interceptor)]
pub struct Rfc8888Interceptor<P> {
    #[next]
    inner: P,
    interval: Duration,
    max_report_size: usize,
    sender_ssrc: u32,
    recorder: CcFeedbackRecorder,
    /// Remote streams being reported on.
    streams: HashSet<u32>,
    next_timeout: Option<Instant>,
    /// Wall-clock reference, captured from the first instant handed over, so a monotonic `Instant`
    /// can be turned into the NTP timestamp a report carries.
    epoch: Option<SystemInstant>,
    write_queue: VecDeque<TaggedPacket>,
}

impl<P> Rfc8888Interceptor<P> {
    fn new(inner: P, interval: Duration, max_report_size: usize, sender_ssrc: u32) -> Self {
        Self {
            inner,
            interval,
            max_report_size,
            sender_ssrc,
            recorder: CcFeedbackRecorder::new(),
            streams: HashSet::new(),
            next_timeout: None,
            epoch: None,
            write_queue: VecDeque::new(),
        }
    }

    /// The middle 32 bits of the NTP timestamp for `now`, which is what a report carries.
    fn report_timestamp(&mut self, now: Instant) -> u32 {
        let epoch = self.epoch.get_or_insert_with(|| SystemInstant::now(now));
        (epoch.ntp(now) >> 16) as u32
    }

    /// Arm the interval from the first instant this interceptor is given.
    fn arm(&mut self, now: Instant) {
        if self.next_timeout.is_none() && !self.streams.is_empty() && !self.interval.is_zero() {
            self.next_timeout = Some(now + self.interval);
        }
    }
}

#[interceptor]
impl<P: Interceptor> Rfc8888Interceptor<P> {
    #[overrides]
    fn bind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.insert(info.ssrc);
        self.inner.bind_remote_stream(info);
    }

    #[overrides]
    fn unbind_remote_stream(&mut self, info: &StreamInfo) {
        self.streams.remove(&info.ssrc);
        self.recorder.remove_stream(info.ssrc);
        if self.streams.is_empty() {
            self.next_timeout = None;
        }
        self.inner.unbind_remote_stream(info);
    }

    #[overrides]
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(rtp_packet) = &msg.message
            && self.streams.contains(&rtp_packet.header.ssrc)
        {
            // ECN lives in the IP header, which a sans-I/O interceptor never sees. Until the
            // transport surfaces it, every packet is reported as Not-ECT — which is what an
            // endpoint without ECN support would report anyway.
            self.recorder.add_packet(
                msg.now,
                rtp_packet.header.ssrc,
                rtp_packet.header.sequence_number,
                Ecn::NotEct,
            );
            self.arm(msg.now);
        }
        self.inner.handle_read(msg)
    }

    #[overrides]
    fn handle_timeout(&mut self, now: Self::Time) -> Result<(), Self::Error> {
        self.arm(now);

        if let Some(next_timeout) = self.next_timeout
            && now >= next_timeout
        {
            self.next_timeout = Some(now + self.interval);

            if !self.recorder.is_empty() {
                let report_timestamp = self.report_timestamp(now);
                let report = self.recorder.build_report(
                    now,
                    self.sender_ssrc,
                    report_timestamp,
                    self.max_report_size,
                );
                if !report.report_blocks.is_empty() {
                    self.write_queue.push_back(TaggedPacket {
                        now,
                        transport: TransportContext::default(),
                        message: Packet::Rtcp(vec![Box::new(report)]),
                    });
                }
            }
        }

        self.inner.handle_timeout(now)
    }

    #[overrides]
    fn poll_timeout(&mut self) -> Option<Self::Time> {
        match (self.next_timeout, self.inner.poll_timeout()) {
            (Some(mine), Some(theirs)) => Some(mine.min(theirs)),
            (mine, theirs) => mine.or(theirs),
        }
    }

    #[overrides]
    fn poll_write(&mut self) -> Option<Self::Wout> {
        // A generated report is terminal (chain contract rule 1): complete when built, with
        // nothing below to transform it.
        if let Some(packet) = self.write_queue.pop_front() {
            return Some(packet);
        }
        self.inner.poll_write()
    }
}
