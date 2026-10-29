use super::{chunk_header::*, chunk_type::*, *};
use crate::util::sna32lt;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::borrow::Cow;
use std::fmt;

/// This chunk is used by the data sender to inform the data receiver to adjust its cumulative
/// received TSN when user message interleaving ([RFC 8260]) was negotiated. It replaces
/// FORWARD-TSN, whose 16-bit stream sequence numbers cannot name an I-DATA message.
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 194  |  Flags = 0x00 |        Length = Variable      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      New Cumulative TSN                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Stream Identifier    |       Reserved            |U| |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Message Identifier                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               /
/// /                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// [RFC 8260]: https://www.rfc-editor.org/rfc/rfc8260.html#section-2.3.1
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChunkIForwardTsn {
    /// The new cumulative TSN: the receiver treats every missing TSN up to it as received.
    pub(crate) new_cumulative_tsn: u32,
    pub(crate) streams: Vec<ChunkIForwardTsnStream>,
}

pub(crate) const I_FORWARD_TSN_ENTRY_LENGTH: usize = 8;
/// Most (stream, ordered/unordered) entries one chunk can carry.
pub(crate) const MAX_I_FORWARD_TSN_STREAMS: usize =
    ((1 << 16) - 1 - CHUNK_HEADER_SIZE - super::chunk_forward_tsn::NEW_CUMULATIVE_TSN_LENGTH)
        / I_FORWARD_TSN_ENTRY_LENGTH;

/// One skipped stream: every message of it up to and including `message_identifier` is
/// abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChunkIForwardTsnStream {
    pub(crate) identifier: u16,
    pub(crate) unordered: bool,
    pub(crate) message_identifier: u32,
}

impl ChunkIForwardTsnStream {
    fn unmarshal(raw: &[u8]) -> Result<Self> {
        if raw.len() < I_FORWARD_TSN_ENTRY_LENGTH {
            return Err(Error::ErrChunkTooShort);
        }
        let mut reader = raw;
        let identifier = reader.get_u16();
        let flags = reader.get_u16();
        let message_identifier = reader.get_u32();
        Ok(Self {
            identifier,
            unordered: flags & 0x1 != 0,
            message_identifier,
        })
    }

    fn marshal_to(&self, writer: &mut BytesMut) {
        writer.put_u16(self.identifier);
        writer.put_u16(u16::from(self.unordered));
        writer.put_u32(self.message_identifier);
    }
}

/// Collapses duplicate (stream, unordered) entries, keeping the largest message identifier and
/// the position of the first occurrence.
pub(crate) fn normalize_i_forward_tsn_streams(
    streams: &[ChunkIForwardTsnStream],
) -> Cow<'_, [ChunkIForwardTsnStream]> {
    if streams.len() < 2 {
        return Cow::Borrowed(streams);
    }
    let has_duplicate = if streams.len() <= 32 {
        streams.iter().enumerate().any(|(i, a)| {
            streams[..i]
                .iter()
                .any(|b| (a.identifier, a.unordered) == (b.identifier, b.unordered))
        })
    } else {
        let mut seen = rustc_hash::FxHashSet::default();
        streams
            .iter()
            .any(|s| !seen.insert((s.identifier, s.unordered)))
    };
    if !has_duplicate {
        return Cow::Borrowed(streams);
    }

    let mut normalized: Vec<ChunkIForwardTsnStream> = Vec::with_capacity(streams.len());
    let mut index = rustc_hash::FxHashMap::default();
    for s in streams {
        match index.get(&(s.identifier, s.unordered)) {
            Some(&i) => {
                let kept: &mut ChunkIForwardTsnStream = &mut normalized[i];
                if sna32lt(kept.message_identifier, s.message_identifier) {
                    kept.message_identifier = s.message_identifier;
                }
            }
            None => {
                index.insert((s.identifier, s.unordered), normalized.len());
                normalized.push(*s);
            }
        }
    }
    Cow::Owned(normalized)
}

impl fmt::Display for ChunkIForwardTsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = vec![self.header().to_string()];
        res.push(format!("New Cumulative TSN: {}", self.new_cumulative_tsn));
        for s in &self.streams {
            res.push(format!(
                " - si={} mid={} unordered={}",
                s.identifier, s.message_identifier, s.unordered
            ));
        }
        write!(f, "{}", res.join("\n"))
    }
}

impl Chunk for ChunkIForwardTsn {
    fn header(&self) -> ChunkHeader {
        ChunkHeader {
            typ: CT_IFORWARD_TSN,
            flags: 0,
            value_length: self.value_length() as u16,
        }
    }

    fn unmarshal(buf: &Bytes) -> Result<Self> {
        let header = ChunkHeader::unmarshal(buf)?;

        if header.typ != CT_IFORWARD_TSN {
            return Err(Error::ErrChunkTypeNotIForwardTsn);
        }

        let value_length = header.value_length();
        if value_length < super::chunk_forward_tsn::NEW_CUMULATIVE_TSN_LENGTH {
            return Err(Error::ErrChunkTooShort);
        }
        let value = &buf[CHUNK_HEADER_SIZE..CHUNK_HEADER_SIZE + value_length];

        let mut reader = value;
        let new_cumulative_tsn = reader.get_u32();

        let stream_bytes = reader.len();
        if !stream_bytes.is_multiple_of(I_FORWARD_TSN_ENTRY_LENGTH) {
            return Err(Error::ErrIForwardTsnChunkInvalidLength);
        }
        let stream_count = stream_bytes / I_FORWARD_TSN_ENTRY_LENGTH;
        if stream_count > MAX_I_FORWARD_TSN_STREAMS {
            return Err(Error::ErrIForwardTsnTooManyStreams);
        }

        let mut streams = Vec::with_capacity(stream_count);
        for entry in reader.as_chunks::<I_FORWARD_TSN_ENTRY_LENGTH>().0 {
            streams.push(ChunkIForwardTsnStream::unmarshal(entry)?);
        }

        Ok(ChunkIForwardTsn {
            new_cumulative_tsn,
            streams: normalize_i_forward_tsn_streams(&streams).into_owned(),
        })
    }

    fn marshal_to(&self, writer: &mut BytesMut) -> Result<usize> {
        self.check()?;
        let streams = normalize_i_forward_tsn_streams(&self.streams);

        ChunkHeader {
            typ: CT_IFORWARD_TSN,
            flags: 0,
            value_length: (super::chunk_forward_tsn::NEW_CUMULATIVE_TSN_LENGTH
                + streams.len() * I_FORWARD_TSN_ENTRY_LENGTH) as u16,
        }
        .marshal_to(writer)?;

        writer.put_u32(self.new_cumulative_tsn);
        for s in streams.iter() {
            s.marshal_to(writer);
        }

        Ok(writer.len())
    }

    fn check(&self) -> Result<()> {
        if normalize_i_forward_tsn_streams(&self.streams).len() > MAX_I_FORWARD_TSN_STREAMS {
            return Err(Error::ErrIForwardTsnTooManyStreams);
        }
        Ok(())
    }

    fn value_length(&self) -> usize {
        super::chunk_forward_tsn::NEW_CUMULATIVE_TSN_LENGTH
            + normalize_i_forward_tsn_streams(&self.streams).len() * I_FORWARD_TSN_ENTRY_LENGTH
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use shared::error::Error;

    fn entry(identifier: u16, unordered: bool, message_identifier: u32) -> ChunkIForwardTsnStream {
        ChunkIForwardTsnStream {
            identifier,
            unordered,
            message_identifier,
        }
    }

    fn distinct_streams(count: usize) -> Vec<ChunkIForwardTsnStream> {
        (0..count)
            .map(|i| entry(i as u16, false, i as u32))
            .collect()
    }

    #[test]
    fn test_chunk_i_forward_tsn_success() -> Result<()> {
        // pion: TestChunkIForwardTSN_Success
        let tests: Vec<Vec<u8>> = vec![
            vec![0xc2, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3],
            vec![
                0xc2, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5,
            ],
            vec![
                0xc2, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5,
                0x0, 0x6, 0x0, 0x1, 0x0, 0x0, 0x0, 0x7, 0x0, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x9,
                0x0, 0xa, 0x0, 0x1, 0x0, 0x0, 0x0, 0xb, 0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x0, 0xd,
                0x0, 0xe, 0x0, 0x1, 0x0, 0x0, 0x0, 0xf, 0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x0, 0x11,
            ],
        ];
        for (i, binary) in tests.into_iter().enumerate() {
            let binary = Bytes::from(binary);
            let actual = ChunkIForwardTsn::unmarshal(&binary)?;
            let b = actual.marshal()?;
            assert_eq!(binary, b, "test {i} not equal");
        }
        Ok(())
    }

    #[test]
    fn test_chunk_i_forward_tsn_unmarshal_normalizes_duplicate_streams() -> Result<()> {
        // pion: TestChunkIForwardTSNUnmarshal_NormalizesDuplicateStreams
        let raw = Bytes::from_static(&[
            0xc2, 0x0, 0x0, 0x18, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0,
            0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5,
        ]);
        let actual = ChunkIForwardTsn::unmarshal(&raw)?;
        assert_eq!(vec![entry(4, true, 5)], actual.streams);
        Ok(())
    }

    #[test]
    fn test_chunk_i_forward_tsn_unmarshal_failure() {
        // pion: TestChunkIForwardTSNUnmarshal_Failure
        let tests: Vec<(&str, Vec<u8>)> = vec![
            ("chunk header to short", vec![0xc2]),
            ("missing New Cumulative TSN", vec![0xc2, 0x0, 0x0, 0x4]),
            (
                "missing stream info",
                vec![0xc2, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x1],
            ),
        ];
        for (name, binary) in tests {
            let result = ChunkIForwardTsn::unmarshal(&Bytes::from(binary));
            assert!(result.is_err(), "expected unmarshal '{name}' to fail");
        }
    }

    #[test]
    fn test_chunk_i_forward_tsn_unmarshal_failure_does_not_keep_partial_streams() {
        // pion: TestChunkIForwardTSNUnmarshal_FailureDoesNotKeepPartialStreams. Unmarshal here
        // returns a new chunk or an error, so no partially filled chunk can be observed; the
        // test pins the error (a stream list that is not a whole number of entries).
        let raw = Bytes::from_static(&[
            0xc2, 0x0, 0x0, 0x12, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x0,
            0x6,
        ]);
        assert_eq!(
            Err(Error::ErrIForwardTsnChunkInvalidLength),
            ChunkIForwardTsn::unmarshal(&raw)
        );
    }

    #[test]
    fn test_chunk_i_forward_tsn_check() {
        // pion: TestChunkIForwardTSNCheck
        struct Case {
            name: &'static str,
            chunk: ChunkIForwardTsn,
            want_err: Option<Error>,
            want: Option<Vec<ChunkIForwardTsnStream>>,
        }
        let cases = vec![
            Case {
                name: "valid with ordered and unordered forwards for same stream",
                chunk: ChunkIForwardTsn {
                    new_cumulative_tsn: 1,
                    streams: vec![entry(1, false, 2), entry(1, true, 3)],
                },
                want_err: None,
                want: None,
            },
            Case {
                name: "zero new cumulative tsn",
                chunk: ChunkIForwardTsn {
                    new_cumulative_tsn: 0,
                    streams: vec![entry(1, false, 2)],
                },
                want_err: None,
                want: None,
            },
            Case {
                name: "too many streams",
                chunk: ChunkIForwardTsn {
                    new_cumulative_tsn: 1,
                    streams: distinct_streams(MAX_I_FORWARD_TSN_STREAMS + 1),
                },
                want_err: Some(Error::ErrIForwardTsnTooManyStreams),
                want: None,
            },
            Case {
                name: "duplicate ordered stream forward keeps largest mid",
                chunk: ChunkIForwardTsn {
                    new_cumulative_tsn: 1,
                    streams: vec![entry(1, false, 2), entry(1, false, 3)],
                },
                want_err: None,
                want: Some(vec![entry(1, false, 3)]),
            },
            Case {
                name: "duplicate unordered stream forward keeps largest mid",
                chunk: ChunkIForwardTsn {
                    new_cumulative_tsn: 1,
                    streams: vec![entry(1, true, 2), entry(1, true, 3)],
                },
                want_err: None,
                want: Some(vec![entry(1, true, 3)]),
            },
        ];
        for c in cases {
            assert_eq!(c.want_err, c.chunk.check().err(), "{}", c.name);
            if let Some(want) = c.want {
                assert_eq!(
                    want,
                    normalize_i_forward_tsn_streams(&c.chunk.streams).into_owned(),
                    "{}",
                    c.name
                );
            }
        }
    }

    #[test]
    fn test_chunk_i_forward_tsn_marshal_normalizes_duplicate_streams() -> Result<()> {
        // pion: TestChunkIForwardTSNMarshal_NormalizesDuplicateStreams
        let b = ChunkIForwardTsn {
            new_cumulative_tsn: 1,
            streams: vec![entry(1, false, 2), entry(1, false, 3)],
        }
        .marshal()?;
        assert_eq!(
            &[
                0xc2u8, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3
            ][..],
            &b[..]
        );
        Ok(())
    }

    #[test]
    fn test_chunk_i_forward_tsn_marshal_zero_cumulative_tsn() {
        // pion: TestChunkIForwardTSNMarshal_ZeroCumulativeTSN
        assert!(
            ChunkIForwardTsn {
                new_cumulative_tsn: 0,
                streams: vec![entry(1, false, 2)],
            }
            .marshal()
            .is_ok()
        );
    }

    #[test]
    fn the_largest_chunk_round_trips_and_one_more_stream_is_refused() -> Result<()> {
        let chunk = ChunkIForwardTsn {
            new_cumulative_tsn: 7,
            streams: distinct_streams(MAX_I_FORWARD_TSN_STREAMS),
        };
        let raw = chunk.marshal()?;
        assert!(raw.len() <= u16::MAX as usize);
        assert_eq!(chunk, ChunkIForwardTsn::unmarshal(&raw)?);

        let too_many = ChunkIForwardTsn {
            new_cumulative_tsn: 7,
            streams: distinct_streams(MAX_I_FORWARD_TSN_STREAMS + 1),
        };
        assert_eq!(Err(Error::ErrIForwardTsnTooManyStreams), too_many.marshal());
        Ok(())
    }
}
