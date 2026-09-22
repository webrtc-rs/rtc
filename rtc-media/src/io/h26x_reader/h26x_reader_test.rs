use super::*;
use std::io::{self, Cursor};

/// The byte-at-a-time reader `next_nal` replaced, kept as the reference the bulk scanner must
/// match. Its read buffer is copied too, so a change to [`ReadBuffer`] cannot move both sides.
mod byte_wise {
    use super::*;

    struct ReadBuffer {
        buffer: Box<[u8]>,
        read_end: usize,
        filled_end: usize,
    }

    impl ReadBuffer {
        fn new(capacity: usize) -> ReadBuffer {
            Self {
                buffer: vec![0u8; capacity].into_boxed_slice(),
                read_end: 0,
                filled_end: 0,
            }
        }

        fn in_buffer(&self) -> usize {
            self.filled_end - self.read_end
        }

        fn consume(&mut self, consume: usize) -> &[u8] {
            let result = &self.buffer[self.read_end..][..consume];
            self.read_end += consume;
            result
        }

        fn fill_buffer(&mut self, reader: &mut impl Read) -> Result<()> {
            self.read_end = 0;
            self.filled_end = reader.read(&mut self.buffer)?;
            Ok(())
        }
    }

    pub(super) struct Reader<R: Read> {
        pub(super) reader: R,
        is_hevc: bool,
        buffer: ReadBuffer,
        nal_prefix_parsed: bool,
        count_of_consecutive_zero_bytes: usize,
        nal_buffer: BytesMut,
        /// Set where the original subtracted past zero (a usize underflow, which panics).
        pub(super) underflowed: bool,
    }

    impl<R: Read> Reader<R> {
        pub(super) fn new(reader: R, capacity: usize, is_hevc: bool) -> Self {
            Self {
                reader,
                is_hevc,
                nal_prefix_parsed: false,
                buffer: ReadBuffer::new(capacity),
                count_of_consecutive_zero_bytes: 0,
                nal_buffer: BytesMut::new(),
                underflowed: false,
            }
        }

        fn read4(&mut self) -> Result<([u8; 4], usize)> {
            let mut result = [0u8; 4];
            let mut result_filled = 0;
            loop {
                let in_buffer = self.buffer.in_buffer();

                if in_buffer + result_filled >= 4 {
                    let consume = 4 - result_filled;
                    result[result_filled..].copy_from_slice(self.buffer.consume(consume));
                    return Ok((result, 4));
                }

                result[result_filled..][..in_buffer]
                    .copy_from_slice(self.buffer.consume(in_buffer));
                result_filled += in_buffer;

                self.buffer.fill_buffer(&mut self.reader)?;

                if self.buffer.in_buffer() == 0 {
                    return Ok((result, result_filled));
                }
            }
        }

        fn read1(&mut self) -> Result<Option<u8>> {
            if self.buffer.in_buffer() == 0 {
                self.buffer.fill_buffer(&mut self.reader)?;

                if self.buffer.in_buffer() == 0 {
                    return Ok(None);
                }
            }

            Ok(Some(self.buffer.consume(1)[0]))
        }

        fn not_a_stream(&self) -> Error {
            if self.is_hevc {
                Error::ErrDataIsNotH265Stream
            } else {
                Error::ErrDataIsNotH264Stream
            }
        }

        fn bit_stream_starts_with_prefix(&mut self) -> Result<usize> {
            let (prefix_buffer, n) = self.read4()?;

            if n == 0 {
                return Err(Error::ErrIoEOF);
            }

            if n < 3 {
                return Err(self.not_a_stream());
            }

            let nal_prefix3bytes_found = NAL_PREFIX_3BYTES[..] == prefix_buffer[..3];
            if n == 3 {
                if nal_prefix3bytes_found {
                    return Err(Error::ErrIoEOF);
                }
                return Err(self.not_a_stream());
            }

            if nal_prefix3bytes_found {
                self.nal_buffer.put_u8(prefix_buffer[3]);
                return Ok(3);
            }

            if NAL_PREFIX_4BYTES[..] == prefix_buffer {
                Ok(4)
            } else {
                Err(self.not_a_stream())
            }
        }

        pub(super) fn next_nal(&mut self) -> Result<H26xNAL> {
            if !self.nal_prefix_parsed {
                self.bit_stream_starts_with_prefix()?;
                self.nal_prefix_parsed = true;
            }

            loop {
                let Some(read_byte) = self.read1()? else {
                    break;
                };

                let nal_found = self.process_byte(read_byte);
                if self.underflowed {
                    return Err(Error::ErrIoEOF);
                }
                if nal_found {
                    if self.is_hevc {
                        if !self.nal_buffer.is_empty() {
                            let nal_unit_type =
                                H265NalUnitType::from((self.nal_buffer[0] & 0x7E) >> 1);
                            if nal_unit_type == H265NalUnitType::PrefixSEI
                                || nal_unit_type == H265NalUnitType::SuffixSEI
                            {
                                self.nal_buffer.clear();
                                continue;
                            } else {
                                break;
                            }
                        }
                    } else {
                        let nal_unit_type = H264NalUnitType::from(self.nal_buffer[0] & 0x1F);
                        if nal_unit_type == H264NalUnitType::SEI {
                            self.nal_buffer.clear();
                            continue;
                        } else {
                            break;
                        }
                    }
                }

                self.nal_buffer.put_u8(read_byte);
            }

            if self.nal_buffer.is_empty() {
                return Err(Error::ErrIoEOF);
            }

            if self.is_hevc {
                let mut nal = H265NAL::new(self.nal_buffer.split());
                nal.parse_header();
                Ok(H26xNAL::H265(nal))
            } else {
                let mut nal = H264NAL::new(self.nal_buffer.split());
                nal.parse_header();
                Ok(H26xNAL::H264(nal))
            }
        }

        fn process_byte(&mut self, read_byte: u8) -> bool {
            let mut nal_found = false;

            match read_byte {
                0 => {
                    self.count_of_consecutive_zero_bytes += 1;
                }
                1 => {
                    if self.count_of_consecutive_zero_bytes >= 2 {
                        let count_of_consecutive_zero_bytes_in_prefix =
                            if self.count_of_consecutive_zero_bytes > 2 {
                                3
                            } else {
                                2
                            };
                        // The original subtracted directly and panicked on underflow.
                        let Some(nal_unit_length) = self
                            .nal_buffer
                            .len()
                            .checked_sub(count_of_consecutive_zero_bytes_in_prefix)
                        else {
                            self.underflowed = true;
                            return false;
                        };
                        if nal_unit_length > 0 {
                            let _ = self.nal_buffer.split_off(nal_unit_length);
                            nal_found = true;
                        }
                    }
                    self.count_of_consecutive_zero_bytes = 0;
                }
                _ => {
                    self.count_of_consecutive_zero_bytes = 0;
                }
            }

            nal_found
        }
    }
}

/// One `next_nal` result, flattened so the two readers' results compare with `==`.
#[derive(Debug, PartialEq)]
enum Outcome {
    H264 {
        data: Vec<u8>,
        picture_order_count: u32,
        forbidden_zero_bit: bool,
        ref_idc: u8,
        unit_type: H264NalUnitType,
    },
    H265 {
        data: Vec<u8>,
        forbidden_zero_bit: bool,
        unit_type: H265NalUnitType,
        nuh_layer_id: u8,
        nuh_temporal_id_plus1: u8,
    },
    Error(String),
}

impl From<Result<H26xNAL>> for Outcome {
    fn from(result: Result<H26xNAL>) -> Self {
        match result {
            Ok(H26xNAL::H264(nal)) => Outcome::H264 {
                data: nal.data.to_vec(),
                picture_order_count: nal.picture_order_count,
                forbidden_zero_bit: nal.forbidden_zero_bit,
                ref_idc: nal.ref_idc,
                unit_type: nal.unit_type,
            },
            Ok(H26xNAL::H265(nal)) => Outcome::H265 {
                data: nal.data.to_vec(),
                forbidden_zero_bit: nal.forbidden_zero_bit,
                unit_type: nal.unit_type,
                nuh_layer_id: nal.nuh_layer_id,
                nuh_temporal_id_plus1: nal.nuh_temporal_id_plus1,
            },
            Err(err) => Outcome::Error(format!("{err:?}")),
        }
    }
}

/// xorshift64: deterministic test data without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// A byte biased towards the values start codes are made of.
    fn biased_byte(&mut self) -> u8 {
        match self.below(8) {
            0..=2 => 0,
            3 => 1,
            _ => self.next() as u8,
        }
    }
}

/// A reader that hands out the stream in irregular pieces, and optionally pauses (returns
/// `Ok(0)` mid-stream, which the H26x reader takes as end of stream until it reads again) or
/// fails once at chosen offsets. Two copies with the same seed behave identically as long as
/// they see the same sequence of calls.
struct IrregularReader {
    data: Vec<u8>,
    position: usize,
    rng: Rng,
    max_chunk: usize,
    /// Offsets, in descending order, at which the next call returns `Ok(0)` once.
    pauses: Vec<usize>,
    /// Offsets, in descending order, at which the next call fails once.
    failures: Vec<usize>,
}

impl IrregularReader {
    fn new(data: Vec<u8>, seed: u64, max_chunk: usize, interrupt: bool) -> Self {
        let mut rng = Rng(seed);
        let mut pauses = vec![];
        let mut failures = vec![];
        if interrupt && !data.is_empty() {
            for _ in 0..rng.below(4) {
                pauses.push(rng.below(data.len()));
            }
            for _ in 0..rng.below(3) {
                failures.push(rng.below(data.len()));
            }
        }
        pauses.sort_unstable_by(|a, b| b.cmp(a));
        failures.sort_unstable_by(|a, b| b.cmp(a));
        Self {
            data,
            position: 0,
            rng,
            max_chunk,
            pauses,
            failures,
        }
    }

    fn done(&self) -> bool {
        self.position == self.data.len() && self.pauses.is_empty() && self.failures.is_empty()
    }
}

impl Read for IrregularReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.failures.last().is_some_and(|&at| at <= self.position) {
            self.failures.pop();
            return Err(io::Error::other("injected failure"));
        }
        if self.pauses.last().is_some_and(|&at| at <= self.position) {
            self.pauses.pop();
            return Ok(0);
        }
        let remaining = self.data.len() - self.position;
        let n = remaining
            .min(buf.len())
            .min(1 + self.rng.below(self.max_chunk));
        buf[..n].copy_from_slice(&self.data[self.position..][..n]);
        self.position += n;
        Ok(n)
    }
}

/// Reads `stream` to the end with both readers and asserts every result matches. Returns
/// whether the comparison ran to the end, which it does unless the byte-wise reader reaches
/// the underflow the original panicked on.
fn assert_matches_byte_wise(
    stream: &[u8],
    capacity: usize,
    is_hevc: bool,
    seed: u64,
    max_chunk: usize,
    interrupt: bool,
) -> bool {
    let new_source = IrregularReader::new(stream.to_vec(), seed, max_chunk, interrupt);
    let old_source = IrregularReader::new(stream.to_vec(), seed, max_chunk, interrupt);
    let mut actual = H26xReader::new(new_source, capacity, is_hevc);
    let mut expected = byte_wise::Reader::new(old_source, capacity, is_hevc);

    for call in 0.. {
        assert!(call < 100_000, "reader did not finish");
        let expected_outcome = Outcome::from(expected.next_nal());
        if expected.underflowed {
            return false;
        }
        let actual_outcome = Outcome::from(actual.next_nal());
        assert_eq!(
            actual_outcome, expected_outcome,
            "call {call}, capacity {capacity}, hevc {is_hevc}, seed {seed:#x}, \
             max_chunk {max_chunk}, interrupt {interrupt}, stream {stream:02x?}"
        );
        assert_eq!(actual.reader.position, expected.reader.position);
        if actual_outcome == Outcome::Error(format!("{:?}", Error::ErrIoEOF))
            && actual.reader.done()
        {
            // Once the source is exhausted, end of stream is final.
            let again = Outcome::from(actual.next_nal());
            assert_eq!(again, Outcome::from(expected.next_nal()));
            assert_eq!(again, actual_outcome);
            return true;
        }
    }
    unreachable!()
}

/// A random Annex B stream: an optional (sometimes malformed) leading prefix, then NAL units
/// with random headers, including SEI, separated by zero runs of varying length. Bodies and
/// separators lean towards `00` and `01` so near-miss and overlapping start codes are common.
fn random_stream(rng: &mut Rng, is_hevc: bool) -> Vec<u8> {
    let mut stream = match rng.below(12) {
        0 => vec![],
        1 => (0..rng.below(4)).map(|_| rng.biased_byte()).collect(),
        2..=6 => vec![0, 0, 0, 1],
        _ => vec![0, 0, 1],
    };
    for _ in 0..rng.below(12) {
        match rng.below(8) {
            0 => {}
            1 if is_hevc => {
                // Prefix SEI, suffix SEI or VPS.
                stream.extend_from_slice(&[[39u8, 40, 32][rng.below(3)] << 1, 1]);
            }
            1 => {
                // SEI, IDR slice or SPS.
                stream.push([6u8, 0x65, 0x67][rng.below(3)]);
            }
            _ => stream.push(rng.next() as u8),
        }
        let body = match rng.below(6) {
            0 => 0,
            1 => rng.below(4),
            2..=4 => rng.below(64),
            _ => rng.below(2_000),
        };
        let random_body = rng.below(3) == 0;
        for _ in 0..body {
            stream.push(if random_body {
                rng.next() as u8
            } else {
                rng.biased_byte()
            });
        }
        match rng.below(10) {
            0 => stream.extend(std::iter::repeat_n(0, rng.below(40))),
            1 => stream.push(1),
            2 => stream.extend_from_slice(&[0, 1]),
            _ => {
                stream.extend(std::iter::repeat_n(0, 2 + rng.below(5)));
                stream.push(1);
            }
        }
    }
    stream
}

const CAPACITIES: [usize; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 13, 64, 4096];

#[test]
fn test_h26x_reader_matches_byte_wise_reader() {
    let mut rng = Rng(0x243f_6a88_85a3_08d3);
    let mut completed = 0;
    for stream_index in 0..300 {
        let is_hevc = stream_index % 2 == 1;
        let stream = random_stream(&mut rng, is_hevc);
        for capacity in CAPACITIES {
            let seed = rng.next() | 1;
            for (max_chunk, interrupt) in [
                (capacity, false),
                (1 + rng.below(capacity), false),
                (1 + rng.below(capacity), true),
            ] {
                completed += usize::from(assert_matches_byte_wise(
                    &stream, capacity, is_hevc, seed, max_chunk, interrupt,
                ));
            }
        }
    }
    // Only interrupted runs can stop early; most must run to the end.
    assert!(completed > 300 * CAPACITIES.len() * 2, "{completed}");
}

#[test]
fn test_h26x_reader_matches_byte_wise_reader_on_dense_start_code_bytes() {
    // Streams drawn only from {00, 01, 06, 4e, 65}: every byte is part of a start code, a
    // near miss, an SEI header or a slice header.
    let mut rng = Rng(0x1319_8a2e_0370_7344);
    for stream_index in 0..400 {
        let is_hevc = stream_index % 2 == 1;
        let len = rng.below(if stream_index % 5 == 0 { 600 } else { 40 });
        let mut stream: Vec<u8> = (0..len)
            .map(|_| [0, 0, 0, 1, 1, 6, 0x4e, 0x65][rng.below(8)])
            .collect();
        if rng.below(3) != 0 {
            let prefix: &[u8] = if rng.below(2) == 0 {
                &[0, 0, 1]
            } else {
                &[0, 0, 0, 1]
            };
            stream.splice(0..0, prefix.iter().copied());
        }
        for capacity in CAPACITIES {
            let seed = rng.next() | 1;
            assert_matches_byte_wise(&stream, capacity, is_hevc, seed, capacity, false);
            assert_matches_byte_wise(
                &stream,
                capacity,
                is_hevc,
                seed,
                1 + rng.below(capacity),
                true,
            );
        }
    }
}

#[test]
fn test_h26x_reader_matches_byte_wise_reader_on_short_streams() {
    // Every stream of up to 8 bytes over {00, 01, 06} behind a four-byte prefix, so start codes
    // land at every offset and straddle every refill of a small buffer.
    for length in 0..=8u32 {
        for value in 0..3usize.pow(length) {
            let mut value = value;
            let mut stream = vec![0, 0, 0, 1];
            stream.extend((0..length).map(|_| {
                let b = [0, 1, 6][value % 3];
                value /= 3;
                b
            }));
            for capacity in [1, 2, 3, 5, 64] {
                for is_hevc in [false, true] {
                    assert_matches_byte_wise(&stream, capacity, is_hevc, 1, capacity, false);
                }
            }
        }
    }
}

#[test]
fn test_h26x_reader_matches_byte_wise_reader_on_long_zero_runs() {
    for zeros in [2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 63, 64, 65, 1000] {
        for capacity in CAPACITIES {
            for is_hevc in [false, true] {
                let mut stream = vec![0, 0, 0, 1, 0x65, 0xaa];
                stream.extend(std::iter::repeat_n(0, zeros));
                stream.extend_from_slice(&[1, 0x41, 0xbb]);
                stream.extend(std::iter::repeat_n(0, zeros));
                assert_matches_byte_wise(&stream, capacity, is_hevc, 7, capacity, false);
                assert_matches_byte_wise(&stream, capacity, is_hevc, 7, 3, false);
            }
        }
    }
}

fn read_all(stream: &[u8], capacity: usize, is_hevc: bool) -> Vec<Result<Vec<u8>>> {
    let mut reader = H26xReader::new(Cursor::new(stream.to_vec()), capacity, is_hevc);
    let mut out = vec![];
    loop {
        match reader.next_nal() {
            Ok(nal) => out.push(Ok(nal.data().to_vec())),
            Err(Error::ErrIoEOF) => return out,
            Err(err) => out.push(Err(err)),
        }
        assert!(out.len() < 1000);
    }
}

#[test]
fn test_h26x_reader_h264() {
    let stream = [
        0, 0, 0, 1, 0x67, 0x42, 0xc0, 0x1f, // SPS
        0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80, // PPS
        0, 0, 1, 0x06, 0x05, 0xff, // SEI, dropped
        0, 0, 1, 0x65, 0x88, 0x84, 0x00, 0x00, 0x03, 0x01, // IDR slice
    ];
    for capacity in [1, 2, 3, 4, 7, 1024] {
        let mut reader = H26xReader::new(Cursor::new(&stream[..]), capacity, false);
        let mut units = vec![];
        loop {
            match reader.next_nal() {
                Ok(H26xNAL::H264(nal)) => units.push((nal.unit_type, nal.ref_idc, nal.data)),
                Ok(H26xNAL::H265(_)) => panic!("H.265 unit from an H.264 reader"),
                Err(Error::ErrIoEOF) => break,
                Err(err) => panic!("{err}"),
            }
        }
        assert_eq!(
            units,
            vec![
                (H264NalUnitType::SPS, 3, BytesMut::from(&stream[4..8])),
                (H264NalUnitType::PPS, 3, BytesMut::from(&stream[12..16])),
                (
                    H264NalUnitType::CodedSliceIdr,
                    3,
                    BytesMut::from(&stream[25..]),
                ),
            ],
            "capacity {capacity}"
        );
    }
}

#[test]
fn test_h26x_reader_h265() {
    let stream = [
        0, 0, 0, 1, 0x40, 0x01, 0x0c, 0x01, // VPS
        0, 0, 0, 1, 0x4e, 0x01, 0x05, // prefix SEI, dropped
        0, 0, 1, 0x26, 0x01, 0xaf, 0x00, 0x00, 0x03, 0x02, // IDR slice
        0, 0, 1, 0x50, 0x01, 0x07, // suffix SEI, dropped
        0, 0, 1, 0x02, 0x01, 0xd0, // trailing picture
    ];
    for capacity in [1, 2, 3, 4, 7, 1024] {
        let mut reader = H26xReader::new(Cursor::new(&stream[..]), capacity, true);
        let mut units = vec![];
        loop {
            match reader.next_nal() {
                Ok(H26xNAL::H265(nal)) => {
                    units.push((nal.unit_type, nal.nuh_temporal_id_plus1, nal.data))
                }
                Ok(H26xNAL::H264(_)) => panic!("H.264 unit from an H.265 reader"),
                Err(Error::ErrIoEOF) => break,
                Err(err) => panic!("{err}"),
            }
        }
        assert_eq!(
            units,
            vec![
                (H265NalUnitType::VPS, 1, BytesMut::from(&stream[4..8])),
                (H265NalUnitType::Idr, 1, BytesMut::from(&stream[18..25])),
                (H265NalUnitType::TrailR, 1, BytesMut::from(&stream[34..])),
            ],
            "capacity {capacity}"
        );
    }
}

#[test]
fn test_h26x_reader_start_code_edge_cases() {
    for capacity in [1, 2, 3, 4, 5, 1024] {
        // Only three zeros belong to a start code: the rest stay on the end of the previous
        // unit. The last unit keeps its trailing zeros too.
        assert_eq!(
            read_all(
                &[0, 0, 0, 1, 0x65, 0, 0, 0, 0, 0, 1, 0x41, 0, 0],
                capacity,
                false
            ),
            vec![Ok(vec![0x65, 0, 0]), Ok(vec![0x41, 0, 0])],
        );
        // A start code with nothing before it is kept as data: the zeros and its `01` begin
        // the next unit.
        assert_eq!(
            read_all(&[0, 0, 0, 1, 0, 0, 1, 0x65, 0, 0, 1, 0x41], capacity, false),
            vec![Ok(vec![0, 0, 1, 0x65]), Ok(vec![0x41])],
        );
        // After a three-byte prefix the next byte is taken as data without being counted as a
        // zero, so `00 00 01 00 00 01` does not end an empty unit.
        assert_eq!(
            read_all(&[0, 0, 1, 0, 0, 1, 0x65, 0, 0, 1, 0x41], capacity, false),
            vec![Ok(vec![0, 0, 1, 0x65]), Ok(vec![0x41])],
        );
        // A trailing SEI is returned rather than dropped: only a start code drops one.
        assert_eq!(
            read_all(&[0, 0, 0, 1, 0x65, 0, 0, 1, 0x06, 0x05], capacity, false),
            vec![Ok(vec![0x65]), Ok(vec![0x06, 0x05])],
        );
        // Not an Annex B stream. Each failed prefix check consumes four bytes, and the next
        // call checks the bytes after them.
        assert_eq!(
            read_all(&[0, 1, 0, 1, 0x65], capacity, false),
            vec![
                Err(Error::ErrDataIsNotH264Stream),
                Err(Error::ErrDataIsNotH264Stream)
            ],
        );
    }
}
