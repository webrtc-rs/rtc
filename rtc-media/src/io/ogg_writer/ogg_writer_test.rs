use std::cell::RefCell;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::rc::Rc;

use bytes::Bytes;

use super::*;
use crate::io::ogg_reader::{self, OggHeaderType, OggReader, parse_opus_tags};

// ---------------------------------------------------------------------------
// Test doubles and helpers (pion's test scaffolding).
// ---------------------------------------------------------------------------

/// An in-memory output that can be inspected while a writer owns it, standing
/// in for pion's `bytes.Buffer`/files: writes land at the cursor (so close-time
/// rewrites overwrite in place) and a cloned handle still sees the bytes.
#[derive(Default, Clone)]
struct SharedBuf {
    data: Rc<RefCell<Vec<u8>>>,
    pos: Rc<std::cell::Cell<u64>>,
    seek_calls: Rc<std::cell::Cell<usize>>,
    fail_seek: bool,
}

impl SharedBuf {
    fn new() -> Self {
        Self::default()
    }

    fn failing_seek() -> Self {
        SharedBuf {
            fail_seek: true,
            ..Self::default()
        }
    }

    fn contents(&self) -> Vec<u8> {
        self.data.borrow().clone()
    }

    fn is_empty(&self) -> bool {
        self.data.borrow().is_empty()
    }

    fn seek_calls(&self) -> usize {
        self.seek_calls.get()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut data = self.data.borrow_mut();
        let pos = self.pos.get() as usize;
        if pos + buf.len() > data.len() {
            data.resize(pos + buf.len(), 0);
        }
        data[pos..pos + buf.len()].copy_from_slice(buf);
        self.pos.set((pos + buf.len()) as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for SharedBuf {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.seek_calls.set(self.seek_calls.get() + 1);
        if self.fail_seek {
            return Err(io::Error::other("unexpected seek"));
        }
        let len = self.data.borrow().len() as i64;
        let current = self.pos.get() as i64;
        let target = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::Current(delta) => current + delta,
            SeekFrom::End(delta) => len + delta,
        };
        let target = target
            .try_into()
            .map_err(|_| io::Error::other("negative seek"))?;
        self.pos.set(target);
        Ok(target)
    }
}

/// A seekable output whose close-time rewrites fail (pion's `rewriteFailingCloser`
/// / O_APPEND file): position queries and appends succeed, but seeking back to
/// rewrite an already-written page is refused.
#[derive(Default)]
struct FailingRewriter {
    data: Vec<u8>,
    rewrite_seeks: usize,
}

impl Write for FailingRewriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for FailingRewriter {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Current(0) => Ok(self.data.len() as u64),
            SeekFrom::Start(offset) => {
                if offset < self.data.len() as u64 {
                    self.rewrite_seeks += 1;
                    return Err(io::Error::other("rewrite failed"));
                }
                Ok(offset)
            }
            _ => Err(io::Error::other("unexpected seek")),
        }
    }
}

struct RawOggPage {
    header: Vec<u8>,
    segment_table: Vec<u8>,
    payload: Vec<u8>,
}

/// pion's `parseRawOggPages`.
fn parse_raw_ogg_pages(data: &[u8]) -> Vec<RawOggPage> {
    let mut pages = vec![];
    let mut offset = 0usize;
    while offset < data.len() {
        assert!(
            offset + PAGE_HEADER_SIZE <= data.len(),
            "short Ogg page header at offset {offset}"
        );
        let header = data[offset..offset + PAGE_HEADER_SIZE].to_vec();
        let segment_count = header[26] as usize;
        let segment_table_offset = offset + PAGE_HEADER_SIZE;
        let payload_offset = segment_table_offset + segment_count;
        assert!(
            payload_offset <= data.len(),
            "short Ogg segment table at offset {segment_table_offset}"
        );
        let segment_table = data[segment_table_offset..payload_offset].to_vec();
        let payload_size: usize = segment_table.iter().map(|&s| s as usize).sum();
        let next_offset = payload_offset + payload_size;
        assert!(
            next_offset <= data.len(),
            "short Ogg page payload at offset {payload_offset}"
        );
        pages.push(RawOggPage {
            header,
            segment_table,
            payload: data[payload_offset..next_offset].to_vec(),
        });
        offset = next_offset;
    }
    pages
}

fn valid_opus_packet_for_test(timestamp: u32, ssrc: u32) -> rtp::Packet {
    opus_rtp_packet_for_test(
        timestamp,
        ssrc,
        Bytes::from_static(&[0x98, 0x36, 0xbe, 0x88, 0x9e]),
    )
}

fn opus_rtp_packet_for_test(timestamp: u32, ssrc: u32, payload: Bytes) -> rtp::Packet {
    let mut packet = rtp::Packet {
        header: rtp::Header {
            marker: true,
            extension: true,
            extension_profile: 1,
            version: 2,
            payload_type: 111,
            sequence_number: 27023,
            timestamp,
            ssrc,
            csrc: vec![],
            padding: false,
            extensions: vec![],
            extensions_padding: 0,
            padding_size: 0,
        },
        payload,
    };
    packet
        .header
        .set_extension(0, Bytes::from_static(&[0xFF, 0xFF, 0xFF, 0xFF]))
        .expect("set extension");
    packet
}

fn first_opus_head_for_test(data: &[u8]) -> ogg_reader::OggHeader {
    let (_, header) =
        OggReader::new(Cursor::new(data.to_vec()), true).expect("parse first OpusHead");
    header
}

fn audio_granule_positions(data: &[u8]) -> Vec<u64> {
    let mut reader = OggReader::new_with_options(Cursor::new(data.to_vec()), true);
    let mut granules = vec![];
    while let Ok((payload, page_header)) = reader.parse_next_page() {
        if page_header.opus_header_type(&payload).is_none() {
            granules.push(page_header.granule_position);
        }
    }
    granules
}

fn opus_tags_by_serial(data: &[u8]) -> std::collections::HashMap<u32, ogg_reader::OpusTags> {
    let mut reader = OggReader::new_with_options(Cursor::new(data.to_vec()), true);
    let mut tags = std::collections::HashMap::new();
    loop {
        match reader.parse_next_page() {
            Ok((payload, page_header)) => {
                if page_header.opus_header_type(&payload) != Some(OggHeaderType::OpusTags) {
                    continue;
                }
                if let Ok(parsed) = parse_opus_tags(&payload) {
                    tags.insert(page_header.serial, parsed);
                }
            }
            Err(_) => break,
        }
    }
    tags
}

// ---------------------------------------------------------------------------
// Ported tests.
// ---------------------------------------------------------------------------

// pion TestOggWriter_AddPacketAndClose. Rust has no nil packets, so pion's
// nil-packet and nil-stream arms drop out; the closed-writer and empty-payload
// arms carry the behaviour.
#[test]
fn test_ogg_writer_add_packet_and_close() -> Result<()> {
    let valid_packet = valid_opus_packet_for_test(3653407706, 476325762);

    // Writing after close fails; closing again is fine.
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.close()?;
    assert!(matches!(
        writer.write_rtp(&valid_packet),
        Err(Error::ErrFileNotOpened)
    ));
    writer.close()?;

    // An empty payload is skipped, not an error.
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&rtp::Packet::default())?;
    writer.close()?;

    // A valid packet writes and closes cleanly.
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&valid_packet)?;
    writer.close()?;
    Ok(())
}

// pion TestOggWriter_EmptyPayload.
#[test]
fn test_ogg_writer_empty_payload() -> Result<()> {
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&rtp::Packet {
        payload: Bytes::new(),
        ..rtp::Packet::default()
    })
}

// pion TestOggWriter_RejectsUnsupportedChannelCount. pion's file constructor
// arm ("the file must not be created") has no Rust counterpart — the Rust API
// takes an io::Write — so the observable rule is the constructor error itself.
#[test]
fn test_ogg_writer_rejects_unsupported_channel_count() {
    for channel_count in [0u16, 3, 9, 256, 65535] {
        assert!(
            matches!(
                OggWriter::new(SharedBuf::new(), 48000, channel_count),
                Err(Error::ErrInvalidChannelCount)
            ),
            "single-track writer rejects {channel_count}"
        );
        assert!(
            matches!(
                SeekableOggWriter::new(SharedBuf::new(), 48000, channel_count),
                Err(Error::ErrInvalidChannelCount)
            ),
            "seekable single-track writer rejects {channel_count}"
        );
        assert!(
            matches!(
                MultiTrackOggWriter::new(SharedBuf::new()).with_channel_count(channel_count),
                Err(Error::ErrInvalidChannelCount)
            ),
            "multi-track writer default rejects {channel_count}"
        );

        let mut writer = MultiTrackOggWriter::new(SharedBuf::new());
        assert!(
            matches!(
                writer.new_track(1111, TrackOptions::new().with_channel_count(channel_count)),
                Err(Error::ErrInvalidChannelCount)
            ),
            "track option rejects {channel_count}"
        );
    }

    // Sanity: the multi-track writer itself is fine without the option.
    let mut writer = MultiTrackOggWriter::new(SharedBuf::new());
    writer
        .new_track(1111, TrackOptions::new())
        .expect("default track options are valid");
}

// pion TestOggWriter_ChannelMappingFamily0Defaults.
#[test]
fn test_ogg_writer_channel_mapping_family_0_defaults() -> Result<()> {
    for channels in [1u16, 2] {
        let buffer = SharedBuf::new();
        let writer = OggWriter::new(buffer.clone(), 48000, channels)?;
        drop(writer);

        let header = first_opus_head_for_test(&buffer.contents());
        assert_eq!(channels as u8, header.channels);
        assert_eq!(0, header.channel_map);
        assert_eq!(0, header.stream_count);
        assert_eq!(0, header.coupled_count);
        assert!(header.channel_mapping.is_empty());
    }
    Ok(())
}

// pion TestOggWriter_ExplicitChannelMappings.
#[test]
fn test_ogg_writer_explicit_channel_mappings() -> Result<()> {
    let cases = [
        (1u8, 1u8, 0u8, vec![0u8]),   // family-1 mono
        (1, 1, 1, vec![0, 1]),        // family-1 stereo
        (2, 1, 0, vec![0]),           // family-2 zero-order ambisonics
        (255, 1, 1, vec![0, 255, 1]), // family-255
        (255, 1, 1, vec![0]),         // fewer output channels than decoded
    ];

    for (family, streams, coupled, channel_map) in cases {
        let buffer = SharedBuf::new();
        let mut writer = MultiTrackOggWriter::new(buffer.clone());
        writer.new_track(
            1111,
            TrackOptions::new().with_channel_mapping(family, streams, coupled, channel_map.clone()),
        )?;
        writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;

        let header = first_opus_head_for_test(&buffer.contents());
        assert_eq!(family, header.channel_map);
        assert_eq!(channel_map.len() as u8, header.channels);
        assert_eq!(streams, header.stream_count);
        assert_eq!(coupled, header.coupled_count);
        assert_eq!(channel_map, header.channel_mapping);
    }
    Ok(())
}

// pion TestOggWriter_ExplicitChannelMappingOverridesWriterDefaultChannelCount.
#[test]
fn test_ogg_writer_explicit_channel_mapping_overrides_writer_default_channel_count() -> Result<()> {
    let channel_map = vec![0u8, 255, 1];
    let buffer = SharedBuf::new();
    let mut writer = MultiTrackOggWriter::new(buffer.clone()).with_channel_count(1)?;
    writer.new_track(
        1111,
        TrackOptions::new().with_channel_mapping(255, 1, 1, channel_map.clone()),
    )?;
    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;

    let header = first_opus_head_for_test(&buffer.contents());
    assert_eq!(255, header.channel_map);
    assert_eq!(channel_map.len() as u8, header.channels);
    assert_eq!(1, header.stream_count);
    assert_eq!(1, header.coupled_count);
    assert_eq!(channel_map, header.channel_mapping);
    Ok(())
}

// pion TestOggWriter_RejectsInvalidChannelMappings, for both the writer default
// and a per-track option.
#[test]
fn test_ogg_writer_rejects_invalid_channel_mappings() {
    let cases = [
        (0u8, 1u8, 1u8, vec![0u8, 1], Error::ErrInvalidChannelMap), // family 0
        (3, 1, 1, vec![0, 1], Error::ErrInvalidChannelMap),         // unknown family
        (4, 1, 1, vec![0, 1], Error::ErrInvalidChannelMap),         // unknown family
        (1, 1, 1, vec![], Error::ErrInvalidChannelCount),           // empty mapping
        (1, 0, 0, vec![0], Error::ErrInvalidChannelMap),            // zero streams
        (255, 2, 0, vec![0, 1], Error::ErrInvalidChannelMap),       // multiple streams
        (1, 1, 2, vec![0, 1, 2], Error::ErrInvalidChannelMap),      // too many coupled
        (1, 1, 1, vec![0, 2], Error::ErrInvalidChannelMap),         // entry out of range
        (1, 1, 1, vec![0, 1, 1], Error::ErrInvalidChannelMap),      // f1 bad channel count
        (1, 1, 1, vec![1, 0], Error::ErrInvalidChannelMap),         // f1 non-vorbis order
        (2, 1, 1, vec![0, 1], Error::ErrInvalidChannelMap),         // f2 bad channel count
    ];

    for (family, streams, coupled, mapping, want_err) in cases {
        assert!(
            matches!(
                MultiTrackOggWriter::new(SharedBuf::new()).with_channel_mapping(
                    family,
                    streams,
                    coupled,
                    &mapping
                ),
                Err(e) if e == want_err
            ),
            "writer default rejects family {family} mapping {mapping:?}"
        );

        let mut writer = MultiTrackOggWriter::new(SharedBuf::new());
        assert!(
            matches!(
                writer.new_track(
                    1111,
                    TrackOptions::new().with_channel_mapping(family, streams, coupled, mapping.clone())
                ),
                Err(e) if e == want_err
            ),
            "track option rejects family {family} mapping {mapping:?}"
        );
    }
}

// pion TestOggWriter_NewCloseWithoutRTPPreservesHeaders (the file-backed,
// seekable writer): closing without packets rewrites the comment page with the
// end-of-stream flag, and the headers stay parseable.
#[test]
fn test_ogg_writer_new_close_without_rtp_preserves_headers() -> Result<()> {
    let buffer = SharedBuf::new();
    let mut writer = SeekableOggWriter::new(buffer.clone(), 48000, 2)?;
    writer.close()?;

    let (mut reader, _) = OggReader::new(Cursor::new(buffer.contents()), true)?;
    let (payload, page_header) = reader.parse_next_page()?;
    assert_eq!(
        Some(OggHeaderType::OpusTags),
        page_header.opus_header_type(&payload)
    );
    Ok(())
}

// pion TestOggWriter_LargePayload.
#[test]
fn test_ogg_writer_large_payload() -> Result<()> {
    let raw_pkt = Bytes::from_iter(std::iter::repeat_n(0x45u8, 1000));
    let packet = opus_rtp_packet_for_test(3653407706, 476325762, raw_pkt.clone());

    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&packet)?;

    let data = create_page_for_serial(
        &writer.checksum_table,
        &raw_pkt,
        PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM,
        0,
        writer.track.serial,
        1,
    );
    assert_eq!(4, data[26]);
    Ok(())
}

// pion TestOggWriter_BoundaryPayloadSplitsTerminatingLace: a payload of
// exactly 255 * 255 bytes fills the segment table without a terminating lace,
// so an empty continuation page ends the packet.
#[test]
fn test_ogg_writer_boundary_payload_splits_terminating_lace() -> Result<()> {
    let payload = Bytes::from_iter(std::iter::repeat_n(0x45u8, 65_025));
    let mapping = ChannelMapping::default_for_channels(2)?;
    let mut track = TrackState::new(48000, mapping, 0x0102_0304, OpusTags::default());
    track.page_index = 7;
    let buffer = SharedBuf::new();

    let mut stream = buffer.clone();
    write_page(
        &mut stream,
        &generate_checksum_table(),
        &mut track,
        &payload,
        PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM,
        960,
        None,
    )?;
    assert_eq!(9, track.page_index);

    let pages = parse_raw_ogg_pages(&buffer.contents());
    assert_eq!(2, pages.len());

    assert_eq!(PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM, pages[0].header[5]);
    assert_eq!(
        NO_GRANULE_POSITION,
        u64::from_le_bytes(pages[0].header[6..14].try_into().unwrap())
    );
    assert_eq!(
        7u32,
        u32::from_le_bytes(pages[0].header[18..22].try_into().unwrap())
    );
    assert_eq!(MAX_OGG_PAGE_SEGMENTS as u8, pages[0].header[26]);
    assert_eq!(vec![255u8; MAX_OGG_PAGE_SEGMENTS], pages[0].segment_table);
    assert_eq!(65_025, pages[0].payload.len());

    assert_eq!(PAGE_HEADER_TYPE_CONTINUATION_OF_PACKET, pages[1].header[5]);
    assert_eq!(
        960u64,
        u64::from_le_bytes(pages[1].header[6..14].try_into().unwrap())
    );
    assert_eq!(
        8u32,
        u32::from_le_bytes(pages[1].header[18..22].try_into().unwrap())
    );
    assert_eq!(1, pages[1].header[26]);
    assert_eq!(vec![0u8], pages[1].segment_table);
    assert!(pages[1].payload.is_empty());
    Ok(())
}

// pion TestOggWriter_BoundaryPayloadCloseMarksEmptyContinuationPageEOS: with a
// seekable output, closing rewrites that empty continuation page with EOS.
#[test]
fn test_ogg_writer_boundary_payload_close_marks_empty_continuation_page_eos() -> Result<()> {
    let buffer = SharedBuf::new();
    let mut writer = SeekableOggWriter::new(buffer.clone(), 48000, 2)?;

    let payload = Bytes::from_iter(std::iter::repeat_n(0x45u8, 65_025));
    let ssrc = 1000;
    let packet = opus_rtp_packet_for_test(1000, ssrc, payload);
    // The single-track writer does not gate on the RTP SSRC; the packet's own
    // SSRC stands in for pion's writer.track.serial usage.
    writer.write_rtp(&packet)?;
    writer.close()?;

    let pages = parse_raw_ogg_pages(&buffer.contents());
    assert_eq!(4, pages.len());

    assert_eq!(
        PAGE_HEADER_TYPE_CONTINUATION_OF_PACKET | PAGE_HEADER_TYPE_END_OF_STREAM,
        pages[3].header[5]
    );
    assert_eq!(vec![0u8], pages[3].segment_table);
    assert!(pages[3].payload.is_empty());
    Ok(())
}

// pion TestOggWriter_CloseClosesFileAfterEOSRewriteFailure, on an output
// whose rewrites fail (pion uses an O_APPEND file, where WriteAt fails).
#[test]
fn test_ogg_writer_close_reports_eos_rewrite_failure() -> Result<()> {
    let mut writer = SeekableOggWriter::new(FailingRewriter::default(), 48000, 2)?;
    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;

    assert!(writer.close().is_err());
    assert_eq!(1, writer.stream.rewrite_seeks);
    Ok(())
}

// pion TestOggWriter_OpusPacketSampleCount.
#[test]
fn test_ogg_writer_opus_packet_sample_count() {
    let cases = [
        (&[0x18u8][..], Some(2880u64)),  // silk 60ms
        (&[0x60][..], Some(480)),        // hybrid 10ms
        (&[0x68][..], Some(960)),        // hybrid 20ms
        (&[0x80][..], Some(120)),        // celt 2.5ms
        (&[0x98][..], Some(960)),        // celt 20ms one frame
        (&[0x99][..], Some(1920)),       // code 1 two frames
        (&[0x9a][..], Some(1920)),       // code 2 two frames
        (&[0x9b, 0x03][..], Some(2880)), // code 3 frame count
        (&[0x1b, 0x02][..], Some(5760)), // maximum packet duration
        (&[0x9b][..], None),             // missing code 3 count
        (&[0x9b, 0x00][..], None),       // zero code 3 frame count
        (&[0x1b, 0x03][..], None),       // over maximum packet duration
    ];

    for (payload, want) in cases {
        let got = opus_packet_sample_count(&Bytes::copy_from_slice(payload));
        match want {
            Some(want) => assert_eq!(Ok(want), got, "payload {payload:?}"),
            None => assert!(
                matches!(got, Err(Error::ErrInvalidOpusPacket)),
                "payload {payload:?} must be rejected"
            ),
        }
    }
}

// pion TestOggWriter_GranulePositionUsesOpusDuration: the granule position
// advances by each packet's Opus duration, not by RTP timestamp deltas.
#[test]
fn test_ogg_writer_granule_position_uses_opus_duration() -> Result<()> {
    let buffer = SharedBuf::new();
    let mut writer = OggWriter::new(buffer.clone(), 48000, 2)?;

    writer.write_rtp(&opus_rtp_packet_for_test(
        1000,
        1111,
        Bytes::from_static(&[0x98]),
    ))?;
    writer.write_rtp(&opus_rtp_packet_for_test(
        3880,
        1111,
        Bytes::from_static(&[0x98]),
    ))?;
    writer.write_rtp(&opus_rtp_packet_for_test(
        4840,
        1111,
        Bytes::from_static(&[0x9b, 0x02]),
    ))?;

    assert_eq!(
        vec![960, 1920, 3840],
        audio_granule_positions(&buffer.contents())
    );
    Ok(())
}

// pion TestOggWriter_NewWriterRequiresOutput is Go-nil-specific: Rust's writer
// types own a non-optional output, so there is nothing to reject.

// pion TestOggWriter_NewWriter.
#[test]
fn test_ogg_writer_new_writer() -> Result<()> {
    let buffer = SharedBuf::new();
    let serial1 = 0x0102_0304u32;
    let serial2 = 0x0506_0708u32;

    let mut writer = MultiTrackOggWriter::new(buffer.clone())
        .with_sample_rate(48000)
        .with_channel_count(2)?;
    writer.new_track(
        1111,
        TrackOptions::new()
            .with_serial(serial1)
            .with_channel_count(1),
    )?;
    writer.new_track(
        2222,
        TrackOptions::new()
            .with_serial(serial2)
            .with_sample_rate(16000),
    )?;

    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;
    writer.write_rtp(&valid_opus_packet_for_test(2000, 2222))?;

    #[derive(PartialEq, Debug)]
    enum PageKind {
        OpusHead,
        OpusTags,
        Audio,
    }
    let mut page_order: Vec<(PageKind, u32)> = vec![];
    let mut opus_head_sample_rates = std::collections::HashMap::new();
    let mut opus_head_channel_counts = std::collections::HashMap::new();
    let mut audio_granules = vec![];

    let mut reader = OggReader::new_with_options(Cursor::new(buffer.contents()), true);
    loop {
        let (payload, page_header) = match reader.parse_next_page() {
            Ok(page) => page,
            Err(_) => break,
        };
        match page_header.opus_header_type(&payload) {
            Some(OggHeaderType::OpusHead) => {
                page_order.push((PageKind::OpusHead, page_header.serial));
                opus_head_sample_rates.insert(
                    page_header.serial,
                    u32::from_le_bytes(payload[12..16].try_into().unwrap()),
                );
                opus_head_channel_counts.insert(page_header.serial, payload[9]);
            }
            Some(OggHeaderType::OpusTags) => {
                page_order.push((PageKind::OpusTags, page_header.serial));
            }
            None => {
                page_order.push((PageKind::Audio, page_header.serial));
                audio_granules.push(page_header.granule_position);
            }
        }
    }

    assert_eq!(
        vec![
            (PageKind::OpusHead, serial1),
            (PageKind::OpusHead, serial2),
            (PageKind::OpusTags, serial1),
            (PageKind::OpusTags, serial2),
            (PageKind::Audio, serial1),
            (PageKind::Audio, serial2),
        ],
        page_order
    );
    assert_eq!(Some(&48000), opus_head_sample_rates.get(&serial1));
    assert_eq!(Some(&16000), opus_head_sample_rates.get(&serial2));
    assert_eq!(Some(&1u8), opus_head_channel_counts.get(&serial1));
    assert_eq!(Some(&2u8), opus_head_channel_counts.get(&serial2));
    assert_eq!(vec![960, 960], audio_granules);
    Ok(())
}

// pion TestOggWriter_NewWriterWritesOpusTags.
#[test]
fn test_ogg_writer_new_writer_writes_opus_tags() -> Result<()> {
    let buffer = SharedBuf::new();
    let serial1 = 0x0102_0304u32;
    let serial2 = 0x0506_0708u32;

    let mut writer = MultiTrackOggWriter::new(buffer.clone())
        .with_vendor("pion-test-suite")?
        .with_user_comments(&[UserComment::new("ENCODER", "pion-oggwriter")])?;
    writer.new_track(
        1111,
        TrackOptions::new()
            .with_serial(serial1)
            .with_user_comments(vec![
                UserComment::new("ARTIST", "Julia"),
                UserComment::new("TITLE", "First Track"),
            ]),
    )?;
    writer.new_track(
        2222,
        TrackOptions::new()
            .with_serial(serial2)
            .with_vendor("track-two-vendor")
            .with_user_comments(vec![
                UserComment::new("ARTIST", "Jade Bob"),
                UserComment::new("ALBUM", "Fanta"),
            ]),
    )?;

    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;
    writer.write_rtp(&valid_opus_packet_for_test(2000, 2222))?;

    let tags = opus_tags_by_serial(&buffer.contents());
    let track1 = tags.get(&serial1).expect("track 1 tags");
    assert_eq!("pion-test-suite", track1.vendor);
    assert_eq!(
        vec![
            ogg_reader::UserComment {
                comment: "ENCODER".to_owned(),
                value: "pion-oggwriter".to_owned(),
            },
            ogg_reader::UserComment {
                comment: "ARTIST".to_owned(),
                value: "Julia".to_owned(),
            },
            ogg_reader::UserComment {
                comment: "TITLE".to_owned(),
                value: "First Track".to_owned(),
            },
        ],
        track1.user_comments
    );

    let track2 = tags.get(&serial2).expect("track 2 tags");
    assert_eq!("track-two-vendor", track2.vendor);
    assert_eq!(
        vec![
            ogg_reader::UserComment {
                comment: "ENCODER".to_owned(),
                value: "pion-oggwriter".to_owned(),
            },
            ogg_reader::UserComment {
                comment: "ARTIST".to_owned(),
                value: "Jade Bob".to_owned(),
            },
            ogg_reader::UserComment {
                comment: "ALBUM".to_owned(),
                value: "Fanta".to_owned(),
            },
        ],
        track2.user_comments
    );
    Ok(())
}

// pion TestOggWriter_RejectsInvalidOpusTags. Rust strings are UTF-8 by
// construction, so the invalid-UTF-8 arms cannot be expressed; the name rules
// and the propagation points port.
#[test]
fn test_ogg_writer_rejects_invalid_opus_tags() {
    let bad_options = [
        // empty user comment name
        TrackOptions::new().with_user_comments(vec![UserComment::new("", "Alice")]),
        // user comment name with equals
        TrackOptions::new().with_user_comments(vec![UserComment::new("ART=IST", "Alice")]),
        // user comment name with a control character
        TrackOptions::new().with_user_comments(vec![UserComment::new("ART\u{1}IST", "Alice")]),
    ];

    for option in bad_options {
        assert!(
            matches!(
                MultiTrackOggWriter::new(SharedBuf::new())
                    .with_user_comments(option.user_comments.as_slice()),
                Err(Error::ErrInvalidOpusTags)
            ),
            "writer default rejects {:?}",
            option.user_comments
        );

        let mut writer = MultiTrackOggWriter::new(SharedBuf::new());
        assert!(
            matches!(
                writer.new_track(1111, option),
                Err(Error::ErrInvalidOpusTags)
            ),
            "track option must reject the invalid comment"
        );
    }
}

// pion TestOggWriter_RejectsOpusTagsHeaderLongerThanMaxInt.
#[test]
fn test_ogg_writer_rejects_opus_tags_header_longer_than_max_int() {
    let opus_tags = OpusTags {
        vendor: "pion".to_owned(),
        user_comments: vec![
            UserComment::new("TITLE", "A long enough title"),
            UserComment::new("ARTIST", "Pion"),
        ],
    };
    let header_len = opus_tags.header_len();

    assert!(validate_opus_tags_with_max_header_len(&opus_tags, header_len).is_ok());
    assert!(matches!(
        validate_opus_tags_with_max_header_len(&opus_tags, header_len - 1),
        Err(Error::ErrInvalidOpusTags)
    ));
}

// pion TestOggWriter_NewWriterAcceptsZeroSerial.
#[test]
fn test_ogg_writer_new_writer_accepts_zero_serial() -> Result<()> {
    let buffer = SharedBuf::new();
    let mut writer = MultiTrackOggWriter::new(buffer.clone())
        .with_sample_rate(48000)
        .with_channel_count(2)?;
    writer.new_track(1111, TrackOptions::new().with_serial(0))?;
    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;

    let mut reader = OggReader::new_with_options(Cursor::new(buffer.contents()), true);
    let mut serials = vec![];
    loop {
        match reader.parse_next_page() {
            Ok((_, page_header)) => serials.push(page_header.serial),
            Err(_) => break,
        }
    }
    assert_eq!(vec![0, 0, 0], serials);
    Ok(())
}

// pion TestOggWriter_MultiTrackRejectsDuplicateTrackSSRC.
#[test]
fn test_ogg_writer_multi_track_rejects_duplicate_track_ssrc() -> Result<()> {
    let mut writer = MultiTrackOggWriter::new(SharedBuf::new())
        .with_sample_rate(48000)
        .with_channel_count(2)?;

    writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;
    assert!(matches!(
        writer.new_track(1111, TrackOptions::new().with_serial(0x0506_0708)),
        Err(Error::ErrDuplicateTrackSSRC)
    ));
    Ok(())
}

// pion TestOggWriter_MultiTrackRejectsPacketSSRCMismatch.
#[test]
fn test_ogg_writer_multi_track_rejects_packet_ssrc_mismatch() -> Result<()> {
    let buffer = SharedBuf::new();
    let mut writer = MultiTrackOggWriter::new(buffer.clone())
        .with_sample_rate(48000)
        .with_channel_count(2)?;

    writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;

    assert!(matches!(
        writer.write_rtp(&valid_opus_packet_for_test(1000, 2222)),
        Err(Error::ErrPacketSSRCMismatch)
    ));
    assert!(!writer.is_started());
    assert!(buffer.is_empty());

    // The failed packet did not consume the track slot.
    writer.new_track(2222, TrackOptions::new().with_serial(0x0506_0708))?;
    Ok(())
}

// pion TestOggWriter_MultiTrackDoesNotStartUntilPacketWillBeWritten. The
// nil-packet arm is Go-specific; nil/empty payloads and SSRC mismatches port.
#[test]
fn test_ogg_writer_multi_track_does_not_start_until_packet_will_be_written() -> Result<()> {
    let cases: [(&str, rtp::Packet, Option<Error>); 3] = [
        (
            "empty payload",
            rtp::Packet {
                header: rtp::Header {
                    ssrc: 1111,
                    ..rtp::Header::default()
                },
                payload: Bytes::new(),
            },
            None,
        ),
        (
            "wrong ssrc",
            valid_opus_packet_for_test(1000, 2222),
            Some(Error::ErrPacketSSRCMismatch),
        ),
        (
            "unregistered ssrc",
            valid_opus_packet_for_test(1000, 3333),
            Some(Error::ErrPacketSSRCMismatch),
        ),
    ];

    for (name, packet, want_err) in cases {
        let buffer = SharedBuf::new();
        let mut writer = MultiTrackOggWriter::new(buffer.clone())
            .with_sample_rate(48000)
            .with_channel_count(2)?;
        writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;

        let result = writer.write_rtp(&packet);
        match want_err {
            None => assert!(result.is_ok(), "{name}"),
            Some(want) => assert!(matches!(result, Err(e) if e == want), "{name}"),
        }
        assert!(!writer.is_started(), "{name}: writer must not start");
        assert!(buffer.is_empty(), "{name}: nothing may be written");

        // Tracks can still be added, and a real packet starts the writer.
        writer.new_track(2222, TrackOptions::new().with_serial(0x0506_0708))?;
        writer.write_rtp(&valid_opus_packet_for_test(2000, 2222))?;
        assert!(writer.is_started(), "{name}");
        assert!(!buffer.is_empty(), "{name}");
    }
    Ok(())
}

// pion TestOggWriter_MultiTrackRejectsDuplicateTrackSerial.
#[test]
fn test_ogg_writer_multi_track_rejects_duplicate_track_serial() -> Result<()> {
    let mut writer = MultiTrackOggWriter::new(SharedBuf::new())
        .with_sample_rate(48000)
        .with_channel_count(2)?;

    writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;
    assert!(matches!(
        writer.new_track(2222, TrackOptions::new().with_serial(0x0102_0304)),
        Err(Error::ErrDuplicateTrackSerial)
    ));
    Ok(())
}

// pion TestOggWriter_MultiTrackRejectsDuplicateZeroTrackSerial.
#[test]
fn test_ogg_writer_multi_track_rejects_duplicate_zero_track_serial() -> Result<()> {
    let mut writer = MultiTrackOggWriter::new(SharedBuf::new())
        .with_sample_rate(48000)
        .with_channel_count(2)?;

    writer.new_track(1111, TrackOptions::new().with_serial(0))?;
    assert!(matches!(
        writer.new_track(2222, TrackOptions::new().with_serial(0)),
        Err(Error::ErrDuplicateTrackSerial)
    ));
    Ok(())
}

// pion TestOggWriter_MultiTrackRejectsTrackCreationAfterWrite.
#[test]
fn test_ogg_writer_multi_track_rejects_track_creation_after_write() -> Result<()> {
    let mut writer = MultiTrackOggWriter::new(SharedBuf::new())
        .with_sample_rate(48000)
        .with_channel_count(2)?;

    writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;
    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;

    assert!(matches!(
        writer.new_track(2222, TrackOptions::new().with_serial(0x0506_0708)),
        Err(Error::ErrTracksStarted)
    ));
    Ok(())
}

// pion TestOggWriter_NewWriterDoesNotSeekWithoutOption: an append-only output
// is never seeked, not even at close. (pion also asserts the output was
// closed; Rust's writers only flush, so the close-tracking arm is Go-specific.)
#[test]
fn test_ogg_writer_new_writer_does_not_seek_without_option() -> Result<()> {
    let output = SharedBuf::new();
    let mut writer = MultiTrackOggWriter::new(output.clone())
        .with_sample_rate(48000)
        .with_channel_count(2)?;
    writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;

    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;
    writer.close()?;
    assert_eq!(0, output.seek_calls());
    Ok(())
}

// pion TestOggWriter_NewWriterFinalizesUnseekableOutputWithEOS.
#[test]
fn test_ogg_writer_new_writer_finalizes_unseekable_output_with_eos() -> Result<()> {
    let output = SharedBuf::new();
    let serial1 = 0x0102_0304u32;
    let serial2 = 0x0506_0708u32;

    let mut writer = MultiTrackOggWriter::new(output.clone())
        .with_sample_rate(48000)
        .with_channel_count(2)?;
    writer.new_track(1111, TrackOptions::new().with_serial(serial1))?;
    writer.new_track(2222, TrackOptions::new().with_serial(serial2))?;

    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;
    writer.write_rtp(&valid_opus_packet_for_test(2000, 2222))?;
    writer.close()?;

    let pages = parse_raw_ogg_pages(&output.contents());
    assert_eq!(8, pages.len());

    let mut eos_pages = std::collections::HashMap::new();
    for page in &pages {
        if page.header[5] & PAGE_HEADER_TYPE_END_OF_STREAM != 0 {
            eos_pages.insert(
                u32::from_le_bytes(page.header[14..18].try_into().unwrap()),
                page,
            );
        }
    }
    assert_eq!(2, eos_pages.len());
    for serial in [serial1, serial2] {
        let page = eos_pages.get(&serial).expect("EOS page");
        assert_eq!(PAGE_HEADER_TYPE_END_OF_STREAM, page.header[5]);
        assert_eq!(
            960u64,
            u64::from_le_bytes(page.header[6..14].try_into().unwrap())
        );
        assert!(page.segment_table.is_empty());
        assert!(page.payload.is_empty());
    }
    assert_eq!(0, output.seek_calls());
    Ok(())
}

// pion TestOggWriter_NewWriterCloseWithoutRTPFinalizesUnseekableOutputWithEOS.
#[test]
fn test_ogg_writer_new_writer_close_without_rtp_finalizes_unseekable_output_with_eos() -> Result<()>
{
    let buffer = SharedBuf::new();
    let serial = 0x0102_0304u32;

    let mut writer = MultiTrackOggWriter::new(buffer.clone())
        .with_sample_rate(48000)
        .with_channel_count(2)?;
    writer.new_track(1111, TrackOptions::new().with_serial(serial))?;
    writer.close()?;

    let pages = parse_raw_ogg_pages(&buffer.contents());
    assert_eq!(3, pages.len());

    assert_eq!(PAGE_HEADER_TYPE_BEGINNING_OF_STREAM, pages[0].header[5]);
    assert_eq!(PAGE_HEADER_TYPE_CONTINUATION_OF_STREAM, pages[1].header[5]);
    assert_eq!(PAGE_HEADER_TYPE_END_OF_STREAM, pages[2].header[5]);
    assert_eq!(
        serial,
        u32::from_le_bytes(pages[2].header[14..18].try_into().unwrap())
    );
    assert_eq!(
        2u32,
        u32::from_le_bytes(pages[2].header[18..22].try_into().unwrap())
    );
    assert_eq!(
        0u64,
        u64::from_le_bytes(pages[2].header[6..14].try_into().unwrap())
    );
    assert!(pages[2].segment_table.is_empty());
    assert!(pages[2].payload.is_empty());
    Ok(())
}

// pion TestOggWriter_NewWriterCloseClosesOutputAfterStartFailure: closing a
// never-started seekable writer writes the headers, and the failing seek
// surfaces.
#[test]
fn test_ogg_writer_new_writer_close_closes_output_after_start_failure() -> Result<()> {
    let output = SharedBuf::failing_seek();

    let mut writer = SeekableMultiTrackOggWriter::new(output.clone())
        .with_sample_rate(48000)
        .with_channel_count(2)?;
    writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;

    assert!(writer.close().is_err());
    assert!(output.seek_calls() > 0);
    Ok(())
}

// pion TestOggWriter_NewWriterCloseClosesOutputAfterEOSRewriteFailure: every
// track's rewrite is attempted even when they fail (pion's errors.Join), and
// the failure surfaces.
#[test]
fn test_ogg_writer_new_writer_close_closes_output_after_eos_rewrite_failure() -> Result<()> {
    let mut writer = SeekableMultiTrackOggWriter::new(FailingRewriter::default())
        .with_sample_rate(48000)
        .with_channel_count(2)?;
    writer.new_track(1111, TrackOptions::new().with_serial(0x0102_0304))?;
    writer.new_track(2222, TrackOptions::new().with_serial(0x0506_0708))?;

    writer.write_rtp(&valid_opus_packet_for_test(1000, 1111))?;
    writer.write_rtp(&valid_opus_packet_for_test(2000, 2222))?;

    assert!(writer.close().is_err());
    // Both tracks were attempted, as in pion (writeAtCalls == 2).
    assert_eq!(2, writer.stream.rewrite_seeks);
    Ok(())
}

// pion TestOggWriter_NewWithPreservesLegacyStreamMode: the append-only writer
// has no seekable half, so close is just a flush.
#[test]
fn test_ogg_writer_new_with_preserves_legacy_stream_mode() -> Result<()> {
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.close()
}

// pion TestOggWriter_NewWithDoesNotRetainLastPayload.
#[test]
fn test_ogg_writer_new_with_does_not_retain_last_payload() -> Result<()> {
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    assert!(writer.track.last_payload.is_empty());
    assert!(!writer.track.last_page_written);

    writer.write_rtp(&valid_opus_packet_for_test(1000, 0x1234_5678))?;
    assert!(writer.track.last_payload.is_empty());
    assert!(!writer.track.last_page_written);
    assert_eq!(0, writer.track.last_granule_position);
    assert_eq!(0, writer.track.last_page_index);
    assert_eq!(0, writer.track.last_page_offset);
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy local tests kept for the segment-table arithmetic (they predate the
// pion port and pin the same lacing rules byte-for-byte).
// ---------------------------------------------------------------------------

fn legacy_packet(payload: Bytes) -> rtp::Packet {
    opus_rtp_packet_for_test(3653407706, 476325762, payload)
}

#[test]
fn test_ogg_writer_add_packet() -> Result<()> {
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&legacy_packet(Bytes::from_iter(std::iter::repeat_n(
        0x45, 235,
    ))))?;

    let data = writer.into_inner().contents();
    assert_eq!([1u8, 235], data[126..128], "one segment of 235 bytes");
    Ok(())
}

#[test]
fn test_ogg_writer_add_packet_of_255() -> Result<()> {
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&legacy_packet(Bytes::from_iter(std::iter::repeat_n(
        0x45, 255,
    ))))?;

    let data = writer.into_inner().contents();
    // A packet of exactly 255 bytes terminates with a zero lace (pion's
    // createPagesForSerial): [255, 0], not the pre-4.x single 255.
    assert_eq!([2u8, 255, 0], data[126..129]);
    Ok(())
}

#[test]
fn test_ogg_writer_add_large_packet() -> Result<()> {
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&legacy_packet(Bytes::from_iter(std::iter::repeat_n(
        0x45, 1000,
    ))))?;

    let data = writer.into_inner().contents();
    assert_eq!(
        [4u8, 255, 255, 255, 235],
        data[126..131],
        "four segments: 255, 255, 255 and 235"
    );
    Ok(())
}

#[test]
fn test_ogg_writer_add_large_packet_with_multiple_of_255() -> Result<()> {
    let mut writer = OggWriter::new(SharedBuf::new(), 48000, 2)?;
    writer.write_rtp(&legacy_packet(Bytes::from_iter(std::iter::repeat_n(
        0x45,
        255 * 4,
    ))))?;

    let data = writer.into_inner().contents();
    // 4 * 255 bytes fill four laces, and the packet still needs its
    // terminating zero lace.
    assert_eq!([5u8, 255, 255, 255, 255, 0], data[126..132]);
    Ok(())
}

// A payload that needs more than 255 lacing values once produced a segment
// count that overflowed `u8` (0) and a remainder computed from it; now the
// packet spans multiple pages (pion's page splitting).
#[test]
fn test_ogg_writer_payload_larger_than_one_page() -> Result<()> {
    let payload = Bytes::from_iter(std::iter::repeat_n(0x45, 255 * 255 + 10));
    let buffer = SharedBuf::new();
    let mut writer = OggWriter::new(buffer.clone(), 48000, 2)?;
    writer.write_rtp(&legacy_packet(payload.clone()))?;
    writer.close()?;

    let pages = parse_raw_ogg_pages(&buffer.contents());
    assert_eq!(4, pages.len(), "id, comment, full page, terminating page");
    assert_eq!(MAX_OGG_PAGE_SEGMENTS as u8, pages[2].header[26]);
    assert_eq!(vec![255u8; MAX_OGG_PAGE_SEGMENTS], pages[2].segment_table);
    assert_eq!(65_025, pages[2].payload.len());
    assert_eq!(PAGE_HEADER_TYPE_CONTINUATION_OF_PACKET, pages[3].header[5]);
    assert_eq!(1, pages[3].header[26]);
    assert_eq!(vec![10u8], pages[3].segment_table);
    assert_eq!(10, pages[3].payload.len());
    Ok(())
}

// Round-trip: the writer's pages parse back through the reader, and the
// audio payload survives byte-for-byte. `OggReader::new` consumes the
// OpusHead page, so the first `parse_next_page` is the OpusTags page.
#[test]
fn test_ogg_writer_round_trips_through_the_reader() -> Result<()> {
    let buffer = SharedBuf::new();
    let mut writer = OggWriter::new(buffer.clone(), 48000, 2)?;
    let payload = Bytes::from_static(&[0x98, 0x36, 0xbe, 0x88, 0x9e]);
    writer.write_rtp(&opus_rtp_packet_for_test(1000, 1, payload.clone()))?;
    writer.close()?;

    let (mut reader, header) = OggReader::new(Cursor::new(buffer.contents()), true)?;
    assert_eq!(2, header.channels);
    let (comment, _) = reader.parse_next_page()?; // OpusTags (OpusHead was consumed by new)
    assert_eq!(COMMENT_PAGE_SIGNATURE, &comment[..8]);
    let (audio, _) = reader.parse_next_page()?;
    assert_eq!(&payload[..], &audio[..]);
    assert!(reader.parse_next_page().is_err(), "EOF after the packet");
    Ok(())
}
