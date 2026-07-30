#![warn(rust_2018_idioms)]
#![warn(missing_docs)]
#![allow(dead_code)]

//! Media samples and container I/O.
//!
//! The bridge between encoded media and RTP: a codec-agnostic [`Sample`] type, and readers
//! and writers for the container formats the examples and tests use.
//!
//! # Structure
//!
//! * [`Sample`] — one encoded unit of media (a video frame, an audio frame) with its
//!   duration, timestamp and packet metadata. Hand these to a sample-based local track and
//!   the RTP packetizer does the rest.
//! * [`io`] — the [`Writer`](io::Writer) trait plus concrete readers and writers for IVF
//!   (VP8/VP9), Ogg (Opus) and H.264/H.265 Annex B — [`IVFReader`](io::ivf_reader::IVFReader),
//!   [`OggReader`](io::ogg_reader::OggReader) and friends — enough to play media from disk or
//!   record it to disk. [`SampleBuilder`](io::sample_builder::SampleBuilder) goes the other
//!   way, reassembling inbound RTP into [`Sample`]s.
//! * [`audio`], [`video`] — per-codec helpers, including audio buffering and frame
//!   inspection.
//!
//! Most applications do not depend on this crate directly — the
//! [`rtc`](https://docs.rs/rtc) crate re-exports it as `rtc::media`.

/// Audio sample types and multi-channel buffers.
pub mod audio;
/// Container readers and writers, plus RTP sample reassembly.
pub mod io;
/// Video frame helpers.
pub mod video;

use bytes::Bytes;
use shared::time::SystemInstant;
use std::time::Duration;

/// A Sample contains encoded media and timing information
#[derive(Debug)]
pub struct Sample {
    /// The assembled data in the sample, as a bitstream.
    ///
    /// The format is Codec dependant, but is always a bitstream format
    /// rather than the packetized format used when carried over RTP.
    ///
    /// See: [`rtp::packetizer::Depacketizer`] and implementations of it for more details.
    pub data: Bytes,

    /// The wallclock time when this sample was generated.
    pub timestamp: SystemInstant,

    /// The duration of this sample
    pub duration: Duration,

    /// The RTP packet timestamp of this sample.
    ///
    /// For all RTP packets that contributed to a single sample the timestamp is the same.
    pub packet_timestamp: u32,

    /// The number of packets that were dropped prior to building this sample.
    ///
    /// Packets being dropped doesn't necessarily indicate something wrong, e.g., packets are sometimes
    /// dropped because they aren't relevant for sample building.
    pub prev_dropped_packets: u16,

    /// The number of packets that were identified as padding prior to building this sample.
    ///
    /// Some implementations, notably libWebRTC, send padding packets to keep the send rate steady.
    /// These packets don't carry media and aren't useful for building samples.
    ///
    /// This field can be combined with [`Sample::prev_dropped_packets`] to determine if any
    /// dropped packets are likely to have detrimental impact on the steadiness of the RTP stream.
    ///
    /// ## Example adjustment
    ///
    /// ```rust
    /// # use bytes::Bytes;
    /// # use std::time::{SystemTime, Duration};
    /// # use rtc_media::Sample;
    /// use shared::time::SystemInstant;
    /// # let sample = Sample {
    /// #   data: Bytes::new(),
    /// #   timestamp: SystemInstant::now(),
    /// #   duration: Duration::from_secs(0),
    /// #   packet_timestamp: 0,
    /// #   prev_dropped_packets: 10,
    /// #   prev_padding_packets: 15
    /// # };
    /// #
    /// let adjusted_dropped =
    /// sample.prev_dropped_packets.saturating_sub(sample.prev_padding_packets);
    /// ```
    pub prev_padding_packets: u16,
}

impl Default for Sample {
    fn default() -> Self {
        Sample {
            data: Bytes::new(),
            timestamp: SystemInstant::now(),
            duration: Duration::from_secs(0),
            packet_timestamp: 0,
            prev_dropped_packets: 0,
            prev_padding_packets: 0,
        }
    }
}

impl PartialEq for Sample {
    fn eq(&self, other: &Self) -> bool {
        let mut equal: bool = true;
        if self.data != other.data {
            equal = false;
        }
        if self.timestamp.duration_since_unix_epoch().as_secs()
            != other.timestamp.duration_since_unix_epoch().as_secs()
        {
            equal = false;
        }
        if self.duration != other.duration {
            equal = false;
        }
        if self.packet_timestamp != other.packet_timestamp {
            equal = false;
        }
        if self.prev_dropped_packets != other.prev_dropped_packets {
            equal = false;
        }
        if self.prev_padding_packets != other.prev_padding_packets {
            equal = false;
        }

        equal
    }
}
