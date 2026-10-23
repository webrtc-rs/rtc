#[cfg(test)]
mod ogg_writer_test;

use std::io::{Seek, SeekFrom, Write};

use bytes::Bytes;
use rtp::packetizer::Depacketizer;

use crate::io::Writer;
use crate::io::ogg_reader::{
    COMMENT_PAGE_SIGNATURE, DEFAULT_PRE_SKIP, ID_PAGE_SIGNATURE, PAGE_HEADER_SIGNATURE,
    PAGE_HEADER_SIZE, PAGE_HEADER_TYPE_BEGINNING_OF_STREAM,
    PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM, PAGE_HEADER_TYPE_END_OF_STREAM,
    generate_checksum_table,
};
use shared::error::{Error, Result};

/// Page header flag: this page continues a packet from the previous page (lacing
/// continuation), used when one Opus packet spans several pages.
pub const PAGE_HEADER_TYPE_CONTINUATION_OF_PACKET: u8 = 0x01;
/// The Opus granule-position clock is always 48 kHz, regardless of the original
/// input sample rate ([RFC 7845] § 4.2).
///
/// [RFC 7845]: https://datatracker.ietf.org/doc/html/rfc7845#section-4.2
pub const OPUS_GRANULE_SAMPLE_RATE: u32 = 48_000;
/// The most samples one Opus packet may cover: 120 ms at the 48 kHz granule rate.
const MAX_OPUS_PACKET_SAMPLES: u64 = OPUS_GRANULE_SAMPLE_RATE as u64 * 120 / 1000;
/// The maximum number of lacing values one Ogg page's segment table may hold.
const MAX_OGG_PAGE_SEGMENTS: usize = 255;
/// The granule position written on pages that do not end a packet
/// (`-1` in the Ogg framing, [RFC 3533] § 6).
///
/// [RFC 3533]: https://datatracker.ietf.org/doc/html/rfc3533#section-6
const NO_GRANULE_POSITION: u64 = u64::MAX;
/// The largest length a Vorbis-comment field may claim on the wire: `u32::MAX`.
const MAX_UINT32_LENGTH: u64 = u32::MAX as u64;
/// The default sample rate written into the `OpusHead`.
const DEFAULT_SAMPLE_RATE: u32 = 48_000;
/// The default channel count: stereo.
const DEFAULT_CHANNEL_COUNT: u16 = 2;
/// The vendor string written into the `OpusTags` page.
const DEFAULT_VENDOR: &str = "WebRTC.rs";

/// An `OpusTags` key-value pair (a Vorbis comment).
///
/// The name may use only printable ASCII except `=`, and the pair marshals as
/// `NAME=value`, per the [Vorbis comment header].
///
/// [Vorbis comment header]: https://www.xiph.org/vorbis/doc/v-comment.html
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserComment {
    /// The tag name, such as `TITLE` or `ARTIST`.
    pub comment: String,
    /// The tag value.
    pub value: String,
}

impl UserComment {
    /// Builds a comment from a name and a value.
    pub fn new(comment: impl Into<String>, value: impl Into<String>) -> Self {
        UserComment {
            comment: comment.into(),
            value: value.into(),
        }
    }
}

/// The `OpusTags` page metadata: the encoder vendor plus user comments
/// ([RFC 7845] § 5.2).
///
/// [RFC 7845]: https://datatracker.ietf.org/doc/html/rfc7845#section-5.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpusTags {
    /// The encoder that produced the stream.
    pub vendor: String,
    /// Metadata tags.
    pub user_comments: Vec<UserComment>,
}

impl Default for OpusTags {
    fn default() -> Self {
        OpusTags {
            vendor: DEFAULT_VENDOR.to_owned(),
            user_comments: vec![],
        }
    }
}

impl OpusTags {
    /// The length the marshalled comment header would occupy, in bytes.
    ///
    /// Mirrors pion's `validateOpusTagsHeaderLen` accounting exactly (it is what
    /// bounds the header before any allocation).
    fn header_len(&self) -> u64 {
        let mut len = COMMENT_PAGE_SIGNATURE.len() as u64 + 4 + self.vendor.len() as u64 + 4;
        for comment in &self.user_comments {
            len += 4 + comment.comment.len() as u64 + 1 + comment.value.len() as u64;
        }
        len
    }
}

/// A validated Opus channel mapping ([RFC 7845] § 5.1.1).
///
/// Family 0 is the implicit mono/stereo mapping (no table); families 1 (Vorbis
/// order), 2 (zero-order ambisonics, [RFC 8486]) and 255 (unspecified) carry an
/// explicit mapping table.
///
/// [RFC 7845]: https://datatracker.ietf.org/doc/html/rfc7845#section-5.1.1
/// [RFC 8486]: https://datatracker.ietf.org/doc/html/rfc8486
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMapping {
    family: u8,
    channel_count: u8,
    stream_count: u8,
    coupled_count: u8,
    mapping: Vec<u8>,
}

impl ChannelMapping {
    /// The family-0 mapping for one or two channels (pion's `defaultChannelMapping`).
    ///
    /// Any other count is invalid here: multichannel layouts need an explicit
    /// family through [`ChannelMapping::new`].
    pub fn default_for_channels(channel_count: u16) -> Result<Self> {
        match channel_count {
            1 => Ok(ChannelMapping {
                family: 0,
                channel_count: 1,
                stream_count: 1,
                coupled_count: 0,
                mapping: vec![],
            }),
            2 => Ok(ChannelMapping {
                family: 0,
                channel_count: 2,
                stream_count: 1,
                coupled_count: 1,
                mapping: vec![],
            }),
            _ => Err(Error::ErrInvalidChannelCount),
        }
    }

    /// A validated explicit channel mapping (pion's `validateChannelMapping`).
    ///
    /// Only single-stream mappings are accepted — one Opus packet per Ogg packet
    /// is all [`MultiTrackOggWriter`] writes — and the channel count is derived
    /// from `mapping.len()`.
    pub fn new(family: u8, stream_count: u8, coupled_count: u8, mapping: &[u8]) -> Result<Self> {
        validate_channel_mapping_family(family)?;
        validate_channel_mapping_layout(stream_count, coupled_count, mapping)?;
        validate_family_specific_channel_mapping(family, stream_count, coupled_count, mapping)?;

        Ok(ChannelMapping {
            family,
            channel_count: mapping.len() as u8,
            stream_count,
            coupled_count,
            mapping: mapping.to_vec(),
        })
    }

    /// The channel mapping family.
    pub fn family(&self) -> u8 {
        self.family
    }

    /// The channel count (the mapping-table length for non-zero families).
    pub fn channel_count(&self) -> u8 {
        self.channel_count
    }

    /// The number of decoded Opus streams.
    pub fn stream_count(&self) -> u8 {
        self.stream_count
    }

    /// How many of the streams are coupled stereo pairs.
    pub fn coupled_count(&self) -> u8 {
        self.coupled_count
    }

    /// The mapping table: which decoded channel feeds each output channel.
    pub fn mapping(&self) -> &[u8] {
        &self.mapping
    }
}

fn validate_channel_mapping_family(family: u8) -> Result<()> {
    match family {
        1 | 2 | 255 => Ok(()),
        _ => Err(Error::ErrInvalidChannelMap),
    }
}

fn validate_channel_mapping_layout(
    stream_count: u8,
    coupled_count: u8,
    mapping: &[u8],
) -> Result<()> {
    if mapping.is_empty() || mapping.len() > u8::MAX as usize {
        return Err(Error::ErrInvalidChannelCount);
    }
    if stream_count != 1 {
        return Err(Error::ErrInvalidChannelMap);
    }
    if coupled_count > stream_count {
        return Err(Error::ErrInvalidChannelMap);
    }

    let decoded_channels = stream_count as usize + coupled_count as usize;
    if mapping
        .iter()
        .any(|&channel| channel != u8::MAX && channel as usize >= decoded_channels)
    {
        return Err(Error::ErrInvalidChannelMap);
    }
    Ok(())
}

fn validate_family_specific_channel_mapping(
    family: u8,
    stream_count: u8,
    coupled_count: u8,
    mapping: &[u8],
) -> Result<()> {
    match family {
        1 => validate_vorbis_channel_mapping(stream_count, coupled_count, mapping),
        2 => {
            if mapping.len() != 1 || stream_count != 1 || coupled_count != 0 || mapping[0] != 0 {
                return Err(Error::ErrInvalidChannelMap);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_vorbis_channel_mapping(
    stream_count: u8,
    coupled_count: u8,
    mapping: &[u8],
) -> Result<()> {
    let (want_streams, want_coupled, want_mapping): (u8, u8, &[u8]) = match mapping.len() {
        1 => (1, 0, &[0]),
        2 => (1, 1, &[0, 1]),
        _ => return Err(Error::ErrInvalidChannelMap),
    };
    if stream_count != want_streams || coupled_count != want_coupled || mapping != want_mapping {
        return Err(Error::ErrInvalidChannelMap);
    }
    Ok(())
}

/// Options for one logical stream (track) of a [`MultiTrackOggWriter`]:
/// pion's `TrackOption`s, where every `None` inherits the writer's default.
#[derive(Default)]
pub struct TrackOptions {
    serial: Option<u32>,
    sample_rate: Option<u32>,
    channel_count: Option<u16>,
    channel_mapping: Option<(u8, u8, u8, Vec<u8>)>,
    vendor: Option<String>,
    user_comments: Vec<UserComment>,
}

impl TrackOptions {
    /// Options with everything inherited from the writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Ogg bitstream serial number (pion's `WithSerial`).
    pub fn with_serial(mut self, serial: u32) -> Self {
        self.serial = Some(serial);
        self
    }

    /// Overrides the track's sample rate (pion's `WithSampleRate`).
    pub fn with_sample_rate(mut self, sample_rate: u32) -> Self {
        self.sample_rate = Some(sample_rate);
        self
    }

    /// Overrides the track's channel count with the family-0 mapping for it
    /// (pion's `WithChannelCount`).
    pub fn with_channel_count(mut self, channel_count: u16) -> Self {
        self.channel_count = Some(channel_count);
        self
    }

    /// Sets an explicit channel mapping for the track (pion's `WithChannelMapping`).
    pub fn with_channel_mapping(
        mut self,
        family: u8,
        stream_count: u8,
        coupled_count: u8,
        mapping: Vec<u8>,
    ) -> Self {
        self.channel_mapping = Some((family, stream_count, coupled_count, mapping));
        self
    }

    /// Overrides the track's `OpusTags` vendor (pion's `WithVendor`).
    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    /// Appends user comments to the track's inherited tags (pion's `WithUserComments`).
    pub fn with_user_comments(mut self, comments: Vec<UserComment>) -> Self {
        self.user_comments.extend(comments);
        self
    }
}

/// One logical Opus stream's write state (pion's `oggTrack`).
#[derive(Debug)]
struct TrackState {
    sample_rate: u32,
    channel_mapping: ChannelMapping,
    serial: u32,
    opus_tags: OpusTags,
    page_index: u32,
    previous_granule_position: u64,
    /// Close-time EOS-rewrite bookkeeping; only maintained on seekable outputs.
    last_payload: Bytes,
    last_granule_position: u64,
    last_page_index: u32,
    last_page_offset: u64,
    last_page_header_type: u8,
    last_page_written: bool,
}

impl TrackState {
    fn new(
        sample_rate: u32,
        channel_mapping: ChannelMapping,
        serial: u32,
        opus_tags: OpusTags,
    ) -> Self {
        TrackState {
            sample_rate,
            channel_mapping,
            serial,
            opus_tags,
            page_index: 0,
            previous_granule_position: 0,
            last_payload: Bytes::new(),
            last_granule_position: 0,
            last_page_index: 0,
            last_page_offset: 0,
            last_page_header_type: 0,
            last_page_written: false,
        }
    }
}

/// One marshalled Ogg page, plus the framing facts close-time rewrites need.
struct OggPage {
    data: Vec<u8>,
    payload: Bytes,
    header_type: u8,
    granule_pos: u64,
    page_index: u32,
}

/// `OggWriter` takes RTP packets carrying Opus and writes a single-track Ogg
/// stream to an append-only output (pion's `OggWriter` built with `NewWith`).
///
/// Because a non-seekable output cannot have already-written pages rewritten,
/// [`close`](OggWriter::close) only flushes: the final page keeps its original
/// header type and no end-of-stream page is appended (duplicating the last
/// payload, as the pre-4.x writers did, corrupts the stream — decoders replay
/// the packet). Use [`SeekableOggWriter`] over a seekable output to get a
/// proper end-of-stream mark.
pub struct OggWriter<W: Write> {
    stream: W,
    checksum_table: [u32; 256],
    track: TrackState,
    closed: bool,
}

impl<W: Write> OggWriter<W> {
    /// Initializes a new single-track OGG Opus writer over an append-only output.
    ///
    /// `channel_count` may only be 1 or 2 (the family-0 mappings); multichannel
    /// layouts need the explicit families of [`MultiTrackOggWriter`]. The
    /// `OpusHead` and `OpusTags` pages are written immediately.
    pub fn new(writer: W, sample_rate: u32, channel_count: u16) -> Result<Self> {
        let channel_mapping = ChannelMapping::default_for_channels(channel_count)?;
        let mut w = OggWriter {
            stream: writer,
            checksum_table: generate_checksum_table(),
            track: TrackState::new(
                sample_rate,
                channel_mapping,
                rand::random::<u32>(),
                OpusTags::default(),
            ),
            closed: false,
        };
        w.write_track_headers()?;
        Ok(w)
    }

    /// Writes one RTP packet's Opus payload as the next page of the stream.
    pub fn write_rtp(&mut self, packet: &rtp::Packet) -> Result<()> {
        if self.closed {
            return Err(Error::ErrFileNotOpened);
        }
        write_rtp(
            &mut self.stream,
            &self.checksum_table,
            &mut self.track,
            packet,
            None,
        )
    }

    /// Flushes the output. Rewriting pages in place is impossible on an
    /// append-only stream, so no end-of-stream mark is added.
    pub fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.closed = true;
            self.stream.flush()?;
        }
        Ok(())
    }

    /// Recovers the underlying output.
    pub fn into_inner(self) -> W {
        self.stream
    }

    fn write_track_headers(&mut self) -> Result<()> {
        write_track_headers(
            &mut self.stream,
            &self.checksum_table,
            &mut self.track,
            None,
        )
    }
}

impl<W: Write> Writer for OggWriter<W> {
    fn write_rtp(&mut self, pkt: &rtp::Packet) -> Result<()> {
        OggWriter::write_rtp(self, pkt)
    }

    fn close(&mut self) -> Result<()> {
        OggWriter::close(self)
    }
}

/// `SeekableOggWriter` is the single-track writer over an output that can seek
/// (pion's `OggWriter` built with `New` over a file): closing rewrites the last
/// page in place with the end-of-stream flag set, exactly as pion's
/// `markTrackEndOfStream` does.
pub struct SeekableOggWriter<W: Write + Seek> {
    stream: W,
    checksum_table: [u32; 256],
    track: TrackState,
    closed: bool,
}

impl<W: Write + Seek> SeekableOggWriter<W> {
    /// Initializes a new single-track OGG Opus writer over a seekable output.
    ///
    /// The `OpusHead` and `OpusTags` pages are written immediately.
    pub fn new(writer: W, sample_rate: u32, channel_count: u16) -> Result<Self> {
        let channel_mapping = ChannelMapping::default_for_channels(channel_count)?;
        let mut w = SeekableOggWriter {
            stream: writer,
            checksum_table: generate_checksum_table(),
            track: TrackState::new(
                sample_rate,
                channel_mapping,
                rand::random::<u32>(),
                OpusTags::default(),
            ),
            closed: false,
        };
        let offset = w.stream.stream_position()?;
        write_track_id_header(&mut w.stream, &w.checksum_table, &mut w.track, Some(offset))?;
        let offset = w.stream.stream_position()?;
        write_track_comment_header(&mut w.stream, &w.checksum_table, &mut w.track, Some(offset))?;
        Ok(w)
    }

    /// Writes one RTP packet's Opus payload as the next page of the stream.
    pub fn write_rtp(&mut self, packet: &rtp::Packet) -> Result<()> {
        if self.closed {
            return Err(Error::ErrFileNotOpened);
        }
        let offset = self.stream.stream_position()?;
        write_rtp(
            &mut self.stream,
            &self.checksum_table,
            &mut self.track,
            packet,
            Some(offset),
        )
    }

    /// Rewrites the last page with the end-of-stream flag, then flushes.
    pub fn close(&mut self) -> Result<()> {
        if !self.closed {
            self.closed = true;
            mark_track_end_of_stream(&mut self.stream, &self.checksum_table, &mut self.track)?;
            self.stream.flush()?;
        }
        Ok(())
    }

    /// Recovers the underlying output.
    pub fn into_inner(self) -> W {
        self.stream
    }
}

impl<W: Write + Seek> Writer for SeekableOggWriter<W> {
    fn write_rtp(&mut self, pkt: &rtp::Packet) -> Result<()> {
        SeekableOggWriter::write_rtp(self, pkt)
    }

    fn close(&mut self) -> Result<()> {
        SeekableOggWriter::close(self)
    }
}

/// `MultiTrackOggWriter` multiplexes several logical Opus streams — one per RTP
/// SSRC — into one Ogg container (pion's `Writer` without `WithSeekableOutput`).
///
/// Tracks are registered with [`new_track`](MultiTrackOggWriter::new_track)
/// before the first packet is written; each track's `OpusHead`/`OpusTags` pages
/// are then written lazily, on the first packet that will actually be written.
/// [`write_rtp`](MultiTrackOggWriter::write_rtp) routes by the packet's SSRC.
/// Because an append-only output cannot have pages rewritten, closing appends an
/// empty end-of-stream page per track (pion's `writeNilEndOfStreamPage`); use
/// [`SeekableMultiTrackOggWriter`] for in-place last-page EOS rewrites.
pub struct MultiTrackOggWriter<W: Write> {
    stream: W,
    checksum_table: [u32; 256],
    sample_rate: u32,
    channel_mapping: ChannelMapping,
    opus_tags: OpusTags,
    /// Insertion-ordered tracks keyed by SSRC (pion's `tracks` map + `trackOrder`).
    tracks: Vec<(u32, TrackState)>,
    started: bool,
    closed: bool,
}

impl<W: Write> MultiTrackOggWriter<W> {
    /// A multi-track writer with pion's defaults: 48 kHz, stereo family 0.
    pub fn new(writer: W) -> Self {
        MultiTrackOggWriter {
            stream: writer,
            checksum_table: generate_checksum_table(),
            sample_rate: DEFAULT_SAMPLE_RATE,
            channel_mapping: ChannelMapping::default_for_channels(DEFAULT_CHANNEL_COUNT)
                .expect("2 is a valid family-0 channel count"),
            opus_tags: OpusTags::default(),
            tracks: vec![],
            started: false,
            closed: false,
        }
    }

    /// Sets the default sample rate for tracks that do not override it.
    pub fn with_sample_rate(mut self, sample_rate: u32) -> Self {
        self.sample_rate = sample_rate;
        self
    }

    /// Sets the default channel count (family-0 mapping) for tracks that do not
    /// override it; only 1 and 2 are valid.
    pub fn with_channel_count(mut self, channel_count: u16) -> Result<Self> {
        self.channel_mapping = ChannelMapping::default_for_channels(channel_count)?;
        Ok(self)
    }

    /// Sets the default explicit channel mapping for tracks that do not override it.
    pub fn with_channel_mapping(
        mut self,
        family: u8,
        stream_count: u8,
        coupled_count: u8,
        mapping: &[u8],
    ) -> Result<Self> {
        self.channel_mapping = ChannelMapping::new(family, stream_count, coupled_count, mapping)?;
        Ok(self)
    }

    /// Sets the default `OpusTags` vendor for tracks that do not override it.
    pub fn with_vendor(mut self, vendor: &str) -> Result<Self> {
        apply_vendor(&mut self.opus_tags, vendor)?;
        Ok(self)
    }

    /// Appends user comments to the default `OpusTags`.
    pub fn with_user_comments(mut self, comments: &[UserComment]) -> Result<Self> {
        apply_user_comments(&mut self.opus_tags, comments)?;
        Ok(self)
    }

    /// Registers a logical Opus stream for `ssrc` (pion's `NewTrack`).
    ///
    /// Fails after the first packet has been written, on a duplicate SSRC, on a
    /// serial already in use, and on invalid per-track options.
    pub fn new_track(&mut self, ssrc: u32, opts: TrackOptions) -> Result<()> {
        if self.closed {
            return Err(Error::ErrOutputNotOpened);
        }
        if self.started {
            return Err(Error::ErrTracksStarted);
        }
        if self.tracks.iter().any(|(ssrc_, _)| *ssrc_ == ssrc) {
            return Err(Error::ErrDuplicateTrackSSRC);
        }

        let mut sample_rate = self.sample_rate;
        let mut channel_mapping = self.channel_mapping.clone();
        if let Some(count) = opts.channel_count {
            channel_mapping = ChannelMapping::default_for_channels(count)?;
        }
        if let Some((family, stream_count, coupled_count, mapping)) = opts.channel_mapping {
            channel_mapping = ChannelMapping::new(family, stream_count, coupled_count, &mapping)?;
        }
        let mut opus_tags = self.opus_tags.clone();
        if let Some(vendor) = opts.vendor {
            apply_vendor(&mut opus_tags, &vendor)?;
        }
        apply_user_comments(&mut opus_tags, &opts.user_comments)?;
        validate_opus_tags(&opus_tags)?;

        let serial = match opts.serial {
            Some(serial) => {
                if self.tracks.iter().any(|(_, track)| track.serial == serial) {
                    return Err(Error::ErrDuplicateTrackSerial);
                }
                serial
            }
            None => self.allocate_serial(),
        };

        if let Some(rate) = opts.sample_rate {
            sample_rate = rate;
        }

        self.tracks.push((
            ssrc,
            TrackState::new(sample_rate, channel_mapping, serial, opus_tags),
        ));
        Ok(())
    }

    /// Writes one RTP packet into the track registered for its SSRC.
    ///
    /// A packet whose SSRC has no track is rejected, and nothing is written: the
    /// writer does not start (and tracks can still be added) until a packet will
    /// actually be written.
    pub fn write_rtp(&mut self, packet: &rtp::Packet) -> Result<()> {
        if self.closed {
            return Err(Error::ErrOutputNotOpened);
        }
        let index = self
            .tracks
            .iter()
            .position(|(ssrc, _)| *ssrc == packet.header.ssrc)
            .ok_or(Error::ErrPacketSSRCMismatch)?;

        let payload = opus_payload_from_packet(packet)?;
        let Some(payload) = payload else {
            return Ok(());
        };
        self.start()?;
        let (_, track) = &mut self.tracks[index];
        write_opus_payload(
            &mut self.stream,
            &self.checksum_table,
            track,
            &payload,
            None,
        )
    }

    /// Appends an empty end-of-stream page for every track, then flushes.
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.start()?;
        for (_, track) in &mut self.tracks {
            write_nil_end_of_stream_page(&mut self.stream, &self.checksum_table, track)?;
        }
        self.stream.flush()?;
        Ok(())
    }

    /// Recovers the underlying output.
    pub fn into_inner(self) -> W {
        self.stream
    }

    /// Whether the track headers have been written (pion's `started`).
    pub fn is_started(&self) -> bool {
        self.started
    }

    fn start(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }
        for (_, track) in &mut self.tracks {
            write_track_id_header(&mut self.stream, &self.checksum_table, track, None)?;
        }
        for (_, track) in &mut self.tracks {
            write_track_comment_header(&mut self.stream, &self.checksum_table, track, None)?;
        }
        self.started = true;
        Ok(())
    }

    fn allocate_serial(&self) -> u32 {
        let mut serial = rand::random::<u32>();
        while self.tracks.iter().any(|(_, track)| track.serial == serial) {
            serial = rand::random::<u32>();
        }
        serial
    }
}

impl<W: Write> Writer for MultiTrackOggWriter<W> {
    fn write_rtp(&mut self, pkt: &rtp::Packet) -> Result<()> {
        MultiTrackOggWriter::write_rtp(self, pkt)
    }

    fn close(&mut self) -> Result<()> {
        MultiTrackOggWriter::close(self)
    }
}

/// `SeekableMultiTrackOggWriter` is the multi-track writer over an output that
/// can seek (pion's `Writer` with `WithSeekableOutput`): closing rewrites each
/// track's last page in place with the end-of-stream flag.
pub struct SeekableMultiTrackOggWriter<W: Write + Seek> {
    stream: W,
    checksum_table: [u32; 256],
    sample_rate: u32,
    channel_mapping: ChannelMapping,
    opus_tags: OpusTags,
    tracks: Vec<(u32, TrackState)>,
    started: bool,
    closed: bool,
}

impl<W: Write + Seek> SeekableMultiTrackOggWriter<W> {
    /// A multi-track writer with pion's defaults: 48 kHz, stereo family 0.
    pub fn new(writer: W) -> Self {
        SeekableMultiTrackOggWriter {
            stream: writer,
            checksum_table: generate_checksum_table(),
            sample_rate: DEFAULT_SAMPLE_RATE,
            channel_mapping: ChannelMapping::default_for_channels(DEFAULT_CHANNEL_COUNT)
                .expect("2 is a valid family-0 channel count"),
            opus_tags: OpusTags::default(),
            tracks: vec![],
            started: false,
            closed: false,
        }
    }

    /// Sets the default sample rate for tracks that do not override it.
    pub fn with_sample_rate(mut self, sample_rate: u32) -> Self {
        self.sample_rate = sample_rate;
        self
    }

    /// Sets the default channel count (family-0 mapping); only 1 and 2 are valid.
    pub fn with_channel_count(mut self, channel_count: u16) -> Result<Self> {
        self.channel_mapping = ChannelMapping::default_for_channels(channel_count)?;
        Ok(self)
    }

    /// Sets the default explicit channel mapping.
    pub fn with_channel_mapping(
        mut self,
        family: u8,
        stream_count: u8,
        coupled_count: u8,
        mapping: &[u8],
    ) -> Result<Self> {
        self.channel_mapping = ChannelMapping::new(family, stream_count, coupled_count, mapping)?;
        Ok(self)
    }

    /// Sets the default `OpusTags` vendor.
    pub fn with_vendor(mut self, vendor: &str) -> Result<Self> {
        apply_vendor(&mut self.opus_tags, vendor)?;
        Ok(self)
    }

    /// Appends user comments to the default `OpusTags`.
    pub fn with_user_comments(mut self, comments: &[UserComment]) -> Result<Self> {
        apply_user_comments(&mut self.opus_tags, comments)?;
        Ok(self)
    }

    /// Registers a logical Opus stream for `ssrc` (pion's `NewTrack`).
    pub fn new_track(&mut self, ssrc: u32, opts: TrackOptions) -> Result<()> {
        if self.closed {
            return Err(Error::ErrOutputNotOpened);
        }
        if self.started {
            return Err(Error::ErrTracksStarted);
        }
        if self.tracks.iter().any(|(ssrc_, _)| *ssrc_ == ssrc) {
            return Err(Error::ErrDuplicateTrackSSRC);
        }

        let mut sample_rate = self.sample_rate;
        let mut channel_mapping = self.channel_mapping.clone();
        if let Some(count) = opts.channel_count {
            channel_mapping = ChannelMapping::default_for_channels(count)?;
        }
        if let Some((family, stream_count, coupled_count, mapping)) = opts.channel_mapping {
            channel_mapping = ChannelMapping::new(family, stream_count, coupled_count, &mapping)?;
        }
        let mut opus_tags = self.opus_tags.clone();
        if let Some(vendor) = opts.vendor {
            apply_vendor(&mut opus_tags, &vendor)?;
        }
        apply_user_comments(&mut opus_tags, &opts.user_comments)?;
        validate_opus_tags(&opus_tags)?;

        let serial = match opts.serial {
            Some(serial) => {
                if self.tracks.iter().any(|(_, track)| track.serial == serial) {
                    return Err(Error::ErrDuplicateTrackSerial);
                }
                serial
            }
            None => self.allocate_serial(),
        };

        if let Some(rate) = opts.sample_rate {
            sample_rate = rate;
        }

        self.tracks.push((
            ssrc,
            TrackState::new(sample_rate, channel_mapping, serial, opus_tags),
        ));
        Ok(())
    }

    /// Writes one RTP packet into the track registered for its SSRC.
    pub fn write_rtp(&mut self, packet: &rtp::Packet) -> Result<()> {
        if self.closed {
            return Err(Error::ErrOutputNotOpened);
        }
        let index = self
            .tracks
            .iter()
            .position(|(ssrc, _)| *ssrc == packet.header.ssrc)
            .ok_or(Error::ErrPacketSSRCMismatch)?;

        let payload = opus_payload_from_packet(packet)?;
        let Some(payload) = payload else {
            return Ok(());
        };
        self.start()?;
        let (_, track) = &mut self.tracks[index];
        let offset = self.stream.stream_position()?;
        write_opus_payload(
            &mut self.stream,
            &self.checksum_table,
            track,
            &payload,
            Some(offset),
        )
    }

    /// Rewrites each track's last page with the end-of-stream flag, then
    /// flushes. Every track is attempted even when an earlier rewrite fails
    /// (pion's `errors.Join` semantics).
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.start()?;
        let mut first_err = None;
        for (_, track) in &mut self.tracks {
            if let Err(err) =
                mark_track_end_of_stream(&mut self.stream, &self.checksum_table, track)
            {
                first_err = first_err.or(Some(err));
            }
        }
        self.stream.flush()?;
        first_err.map_or(Ok(()), Err)
    }

    /// Recovers the underlying output.
    pub fn into_inner(self) -> W {
        self.stream
    }

    /// Whether the track headers have been written (pion's `started`).
    pub fn is_started(&self) -> bool {
        self.started
    }

    fn start(&mut self) -> Result<()> {
        if self.started {
            return Ok(());
        }
        for (_, track) in &mut self.tracks {
            let offset = self.stream.stream_position()?;
            write_track_id_header(&mut self.stream, &self.checksum_table, track, Some(offset))?;
        }
        for (_, track) in &mut self.tracks {
            let offset = self.stream.stream_position()?;
            write_track_comment_header(
                &mut self.stream,
                &self.checksum_table,
                track,
                Some(offset),
            )?;
        }
        self.started = true;
        Ok(())
    }

    fn allocate_serial(&self) -> u32 {
        let mut serial = rand::random::<u32>();
        while self.tracks.iter().any(|(_, track)| track.serial == serial) {
            serial = rand::random::<u32>();
        }
        serial
    }
}

// ---------------------------------------------------------------------------
// Page construction (pion's factored functions; tests exercise these directly).
// ---------------------------------------------------------------------------

fn write_track_headers<W: Write>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
    rewrite_at: RewriteAt,
) -> Result<()> {
    write_track_id_header(stream, checksum_table, track, rewrite_at)?;
    write_track_comment_header(stream, checksum_table, track, rewrite_at)
}

fn write_track_id_header<W: Write>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
    rewrite_at: RewriteAt,
) -> Result<()> {
    let payload = Bytes::from(build_id_header(track));
    write_page(
        stream,
        checksum_table,
        track,
        &payload,
        PAGE_HEADER_TYPE_BEGINNING_OF_STREAM,
        0,
        rewrite_at,
    )
}

fn write_track_comment_header<W: Write>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
    rewrite_at: RewriteAt,
) -> Result<()> {
    let payload = Bytes::from(build_comment_header(&track.opus_tags));
    write_page(
        stream,
        checksum_table,
        track,
        &payload,
        PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM,
        0,
        rewrite_at,
    )
}

fn build_id_header(track: &TrackState) -> Vec<u8> {
    let mapping = &track.channel_mapping;
    let mut header = Vec::with_capacity(ID_PAGE_SIGNATURE.len() + 11 + mapping.mapping.len());
    header.extend_from_slice(ID_PAGE_SIGNATURE); // Magic Signature 'OpusHead'
    header.push(1); // Version
    header.push(mapping.channel_count); // Channel count
    header.extend_from_slice(&DEFAULT_PRE_SKIP.to_le_bytes()); // pre-skip
    header.extend_from_slice(&track.sample_rate.to_le_bytes()); // original sample rate
    header.extend_from_slice(&0u16.to_le_bytes()); // output gain
    header.push(mapping.family); // channel mapping family
    if mapping.family != 0 {
        header.push(mapping.stream_count);
        header.push(mapping.coupled_count);
        header.extend_from_slice(&mapping.mapping);
    }
    header
}

fn build_comment_header(opus_tags: &OpusTags) -> Vec<u8> {
    let mut header = Vec::with_capacity(opus_tags.header_len() as usize);
    header.extend_from_slice(COMMENT_PAGE_SIGNATURE); // Magic Signature 'OpusTags'
    header.extend_from_slice(&(opus_tags.vendor.len() as u32).to_le_bytes());
    header.extend_from_slice(opus_tags.vendor.as_bytes());
    header.extend_from_slice(&(opus_tags.user_comments.len() as u32).to_le_bytes());
    for comment in &opus_tags.user_comments {
        let len = comment.comment.len() + 1 + comment.value.len();
        header.extend_from_slice(&(len as u32).to_le_bytes());
        header.extend_from_slice(comment.comment.as_bytes());
        header.push(b'=');
        header.extend_from_slice(comment.value.as_bytes());
    }
    header
}

/// pion's `writeRTP`: extract the Opus payload, then advance the granule
/// position by the packet's Opus duration and write the page(s).
fn write_rtp<W: Write>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
    packet: &rtp::Packet,
    rewrite_at: RewriteAt,
) -> Result<()> {
    let payload = opus_payload_from_packet(packet)?;
    let Some(payload) = payload else {
        return Ok(());
    };
    write_opus_payload(stream, checksum_table, track, &payload, rewrite_at)
}

/// pion's `opusPayloadFromPacket`: `None` means "nothing to write".
fn opus_payload_from_packet(packet: &rtp::Packet) -> Result<Option<Bytes>> {
    if packet.payload.is_empty() {
        return Ok(None);
    }

    let mut opus_packet = rtp::codec::opus::OpusPacket;
    Ok(Some(opus_packet.depacketize(&packet.payload)?))
}

fn write_opus_payload<W: Write>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
    payload: &Bytes,
    rewrite_at: RewriteAt,
) -> Result<()> {
    let sample_count = opus_packet_sample_count(payload)?;
    track.previous_granule_position += sample_count;

    write_page(
        stream,
        checksum_table,
        track,
        payload,
        PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM,
        track.previous_granule_position,
        rewrite_at,
    )
}

/// Where a page write lands, pion's `pageRewriter` distinction: `None` is an
/// append-only output (no offsets, no close-time rewrites); `Some(offset)` is
/// a seekable output writing this payload at `offset`, which is where the
/// last page of the payload can later be rewritten with the EOS flag.
type RewriteAt = Option<u64>;

/// pion's `writePage`: split the payload into lacing-bounded pages, write them,
/// and on a seekable output remember where the last one landed.
fn write_page<W: Write>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
    payload: &Bytes,
    header_type: u8,
    granule_pos: u64,
    rewrite_at: RewriteAt,
) -> Result<()> {
    let pages = create_pages_for_serial(
        checksum_table,
        payload,
        header_type,
        granule_pos,
        track.serial,
        track.page_index,
    );

    let mut offset = rewrite_at;
    for (i, page) in pages.iter().enumerate() {
        stream.write_all(&page.data)?;
        if let Some(offset) = offset.as_mut() {
            if i == pages.len() - 1 {
                track.last_payload = page.payload.clone();
                track.last_granule_position = page.granule_pos;
                track.last_page_index = page.page_index;
                track.last_page_header_type = page.header_type;
                track.last_page_offset = *offset;
                track.last_page_written = true;
            }
            *offset += page.data.len() as u64;
        }
    }
    track.page_index += pages.len() as u32;

    Ok(())
}

/// pion's `createPagesForSerial`: fill pages with at most 255 lacing values
/// each; a page that does not end the packet carries no granule position.
fn create_pages_for_serial(
    checksum_table: &[u32; 256],
    payload: &Bytes,
    header_type: u8,
    granule_pos: u64,
    serial: u32,
    page_index: u32,
) -> Vec<OggPage> {
    let mut pages = vec![];
    let mut payload_offset = 0usize;
    let mut remaining_payload = payload.len();
    let mut first_page = true;
    let mut page_index = page_index;

    loop {
        let mut segment_table: Vec<u8> = Vec::with_capacity(MAX_OGG_PAGE_SEGMENTS);
        let mut page_payload_size = 0usize;
        let mut packet_complete = false;
        while segment_table.len() < MAX_OGG_PAGE_SEGMENTS {
            if remaining_payload >= 255 {
                segment_table.push(255);
                page_payload_size += 255;
                remaining_payload -= 255;
                continue;
            }
            segment_table.push(remaining_payload as u8);
            page_payload_size += remaining_payload;
            remaining_payload = 0;
            packet_complete = true;
            break;
        }

        let page_payload = payload.slice(payload_offset..payload_offset + page_payload_size);
        let page_header_type = packet_page_header_type(header_type, first_page, packet_complete);
        let page_granule_pos = if packet_complete {
            granule_pos
        } else {
            NO_GRANULE_POSITION
        };

        pages.push(OggPage {
            data: create_page_for_serial_with_segments(
                checksum_table,
                &page_payload,
                &segment_table,
                page_header_type,
                page_granule_pos,
                serial,
                page_index,
            ),
            payload: page_payload,
            header_type: page_header_type,
            granule_pos: page_granule_pos,
            page_index,
        });

        payload_offset += page_payload_size;
        page_index += 1;
        first_page = false;
        if packet_complete {
            break;
        }
    }

    pages
}

/// pion's `packetPageHeaderType`: the first page keeps the requested type
/// (minus EOS when the packet continues), later pages are packet
/// continuations, and only the terminating page may carry EOS.
fn packet_page_header_type(header_type: u8, first_page: bool, packet_complete: bool) -> u8 {
    if first_page {
        if packet_complete {
            return header_type;
        }
        return header_type & !PAGE_HEADER_TYPE_END_OF_STREAM;
    }

    let mut t = PAGE_HEADER_TYPE_CONTINUATION_OF_PACKET;
    if packet_complete {
        t |= header_type & PAGE_HEADER_TYPE_END_OF_STREAM;
    }
    t
}

/// pion's `createPageForSerial`: the concatenation of every page a payload
/// spans — what a close-time rewrite re-marshals.
fn create_page_for_serial(
    checksum_table: &[u32; 256],
    payload: &Bytes,
    header_type: u8,
    granule_pos: u64,
    serial: u32,
    page_index: u32,
) -> Vec<u8> {
    let pages = create_pages_for_serial(
        checksum_table,
        payload,
        header_type,
        granule_pos,
        serial,
        page_index,
    );
    let page_size: usize = pages.iter().map(|page| page.data.len()).sum();
    let mut data = Vec::with_capacity(page_size);
    for page in pages {
        data.extend_from_slice(&page.data);
    }
    data
}

fn create_page_for_serial_with_segments(
    checksum_table: &[u32; 256],
    payload: &[u8],
    segment_table: &[u8],
    header_type: u8,
    granule_pos: u64,
    serial: u32,
    page_index: u32,
) -> Vec<u8> {
    let mut page = Vec::with_capacity(PAGE_HEADER_SIZE + segment_table.len() + payload.len());
    page.extend_from_slice(PAGE_HEADER_SIGNATURE); // 'OggS'
    page.push(0); // Version
    page.push(header_type); // 1 = continuation, 2 = bos, 4 = eos
    page.extend_from_slice(&granule_pos.to_le_bytes()); // granule position
    page.extend_from_slice(&serial.to_le_bytes()); // bitstream serial number
    page.extend_from_slice(&page_index.to_le_bytes()); // page sequence number
    page.extend_from_slice(&0u32.to_le_bytes()); // checksum reserve
    page.push(segment_table.len() as u8); // number of segments

    page.extend_from_slice(segment_table);
    page.extend_from_slice(payload);

    let mut checksum = 0u32;
    for v in &page {
        checksum = (checksum << 8) ^ checksum_table[(((checksum >> 24) as u8) ^ v) as usize];
    }
    page[22..26].copy_from_slice(&checksum.to_le_bytes());

    page
}

/// pion's `markTrackEndOfStream`: rewrite the track's last page in place with
/// the end-of-stream flag set.
fn mark_track_end_of_stream<W: Write + Seek>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
) -> Result<()> {
    if !track.last_page_written {
        return Ok(());
    }

    let data = create_page_for_serial(
        checksum_table,
        &track.last_payload,
        track.last_page_header_type | PAGE_HEADER_TYPE_END_OF_STREAM,
        track.last_granule_position,
        track.serial,
        track.last_page_index,
    );
    stream.seek(SeekFrom::Start(track.last_page_offset))?;
    stream.write_all(&data)?;

    Ok(())
}

/// pion's `writeNilEndOfStreamPage`: append an empty EOS page when the last
/// page cannot be rewritten.
fn write_nil_end_of_stream_page<W: Write>(
    stream: &mut W,
    checksum_table: &[u32; 256],
    track: &mut TrackState,
) -> Result<()> {
    if track.page_index == 0 {
        return Ok(());
    }

    let data = create_page_for_serial_with_segments(
        checksum_table,
        &[],
        &[],
        PAGE_HEADER_TYPE_END_OF_STREAM,
        track.previous_granule_position,
        track.serial,
        track.page_index,
    );
    stream.write_all(&data)?;
    track.page_index += 1;

    Ok(())
}

/// The duration of an Opus packet in samples at the 48 kHz granule rate
/// (pion's `opusPacketSampleCount`), from the TOC byte and frame count.
pub fn opus_packet_sample_count(payload: &Bytes) -> Result<u64> {
    if payload.is_empty() {
        return Err(Error::ErrInvalidOpusPacket);
    }

    let frame_count = opus_packet_frame_count(payload)?;
    let sample_count = opus_samples_per_frame(payload[0]) as u64 * frame_count as u64;
    if sample_count > MAX_OPUS_PACKET_SAMPLES {
        return Err(Error::ErrInvalidOpusPacket);
    }

    Ok(sample_count)
}

fn opus_packet_frame_count(payload: &Bytes) -> Result<u8> {
    match payload[0] & 0x03 {
        0 => Ok(1),
        1 | 2 => Ok(2),
        3 => {
            if payload.len() < 2 {
                return Err(Error::ErrInvalidOpusPacket);
            }
            let frame_count = payload[1] & 0x3f;
            if frame_count == 0 {
                return Err(Error::ErrInvalidOpusPacket);
            }
            Ok(frame_count)
        }
        _ => Err(Error::ErrInvalidOpusPacket),
    }
}

fn opus_samples_per_frame(toc: u8) -> u32 {
    if toc & 0x80 != 0 {
        // CELT: 2.5/5/10/20 ms
        return (OPUS_GRANULE_SAMPLE_RATE << ((toc >> 3) & 0x03)) / 400;
    }
    if toc & 0x60 == 0x60 {
        // Hybrid: 10 or 20 ms
        if toc & 0x08 != 0 {
            return OPUS_GRANULE_SAMPLE_RATE / 50;
        }
        return OPUS_GRANULE_SAMPLE_RATE / 100;
    }

    // SILK: 10/20/40/60 ms
    let frame_size = (toc >> 3) & 0x03;
    if frame_size == 3 {
        return OPUS_GRANULE_SAMPLE_RATE * 60 / 1000;
    }
    (OPUS_GRANULE_SAMPLE_RATE << frame_size) / 100
}

// ---------------------------------------------------------------------------
// OpusTags validation (pion's validate* functions).
// ---------------------------------------------------------------------------

fn apply_vendor(opus_tags: &mut OpusTags, vendor: &str) -> Result<()> {
    validate_opus_tag_string(vendor)?;
    opus_tags.vendor = vendor.to_owned();
    Ok(())
}

fn apply_user_comments(opus_tags: &mut OpusTags, comments: &[UserComment]) -> Result<()> {
    validate_user_comments(comments)?;
    opus_tags.user_comments.extend_from_slice(comments);
    Ok(())
}

fn validate_opus_tags(opus_tags: &OpusTags) -> Result<()> {
    validate_opus_tags_with_max_header_len(opus_tags, u64::MAX)
}

/// pion's `validateOpusTagsWithMaxHeaderLen`: bounds the marshalled comment
/// header against `max_header_len` before anything is built.
fn validate_opus_tags_with_max_header_len(opus_tags: &OpusTags, max_header_len: u64) -> Result<()> {
    validate_opus_tag_string(&opus_tags.vendor)?;
    if opus_tags.user_comments.len() as u64 > MAX_UINT32_LENGTH {
        return Err(Error::ErrInvalidOpusTags);
    }
    validate_user_comments(&opus_tags.user_comments)?;

    let header_len = COMMENT_PAGE_SIGNATURE.len() as u64 + 4 + opus_tags.vendor.len() as u64 + 4;
    if header_len > max_header_len {
        return Err(Error::ErrInvalidOpusTags);
    }

    let mut header_len = header_len;
    for comment in &opus_tags.user_comments {
        let user_comment_len = comment.comment.len() as u64 + 1 + comment.value.len() as u64;
        let comment_field_len = 4 + user_comment_len;
        if comment_field_len > max_header_len - header_len {
            return Err(Error::ErrInvalidOpusTags);
        }
        header_len += comment_field_len;
    }

    Ok(())
}

fn validate_user_comments(comments: &[UserComment]) -> Result<()> {
    for comment in comments {
        validate_user_comment(comment)?;
    }
    Ok(())
}

fn validate_user_comment(comment: &UserComment) -> Result<()> {
    if !is_valid_comment_name(&comment.comment) {
        return Err(Error::ErrInvalidOpusTags);
    }
    validate_opus_tag_string(&comment.value)?;
    if comment.comment.len() as u64 + 1 + comment.value.len() as u64 > MAX_UINT32_LENGTH {
        return Err(Error::ErrInvalidOpusTags);
    }
    Ok(())
}

fn validate_opus_tag_string(value: &str) -> Result<()> {
    // Rust `String`s are UTF-8 by construction; only the wire length is bounded.
    if value.len() as u64 > MAX_UINT32_LENGTH {
        return Err(Error::ErrInvalidOpusTags);
    }
    Ok(())
}

fn is_valid_comment_name(comment: &str) -> bool {
    if comment.is_empty() {
        return false;
    }
    comment
        .as_bytes()
        .iter()
        .all(|&b| (0x20..=0x7d).contains(&b) && b != b'=')
}
