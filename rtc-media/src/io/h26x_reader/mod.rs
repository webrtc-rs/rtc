#[cfg(test)]
mod h26x_reader_test;

use bytes::{BufMut, BytesMut};
use shared::error::{Error, Result};
use std::fmt;
use std::io::Read;

const NAL_PREFIX_3BYTES: [u8; 3] = [0, 0, 1];
const NAL_PREFIX_4BYTES: [u8; 4] = [0, 0, 0, 1];

/// Wrapper class around reading buffer
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

    #[inline]
    fn in_buffer(&self) -> usize {
        self.filled_end - self.read_end
    }

    fn consume(&mut self, consume: usize) -> &[u8] {
        debug_assert!(self.read_end + consume <= self.filled_end);
        let result = &self.buffer[self.read_end..][..consume];
        self.read_end += consume;
        result
    }

    pub(crate) fn fill_buffer(&mut self, reader: &mut impl Read) -> Result<()> {
        debug_assert_eq!(self.read_end, self.filled_end);

        self.read_end = 0;
        self.filled_end = reader.read(&mut self.buffer)?;

        Ok(())
    }
}

/// H264NalUnitType is the type of a NAL
/// Enums for H264NalUnitType
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum H264NalUnitType {
    /// Unspecified
    #[default]
    Unspecified = 0,
    /// Coded slice of a non-IDR picture
    CodedSliceNonIdr = 1,
    /// Coded slice data partition A
    CodedSliceDataPartitionA = 2,
    /// Coded slice data partition B
    CodedSliceDataPartitionB = 3,
    /// Coded slice data partition C
    CodedSliceDataPartitionC = 4,
    /// Coded slice of an IDR picture
    CodedSliceIdr = 5,
    /// Supplemental enhancement information (SEI)
    SEI = 6,
    /// Sequence parameter set
    SPS = 7,
    /// Picture parameter set
    PPS = 8,
    /// Access unit delimiter
    AUD = 9,
    /// End of sequence
    EndOfSequence = 10,
    /// End of stream
    EndOfStream = 11,
    /// Filler data
    Filler = 12,
    /// Sequence parameter set extension
    SpsExt = 13,
    /// Coded slice of an auxiliary coded picture without partitioning
    CodedSliceAux = 19,
    ///Reserved
    Reserved,
    // 14..18                                            // Reserved
    // 20..23                                            // Reserved
    // 24..31                                            // Unspecified
}

impl fmt::Display for H264NalUnitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            H264NalUnitType::Unspecified => "Unspecified",
            H264NalUnitType::CodedSliceNonIdr => "CodedSliceNonIdr",
            H264NalUnitType::CodedSliceDataPartitionA => "CodedSliceDataPartitionA",
            H264NalUnitType::CodedSliceDataPartitionB => "CodedSliceDataPartitionB",
            H264NalUnitType::CodedSliceDataPartitionC => "CodedSliceDataPartitionC",
            H264NalUnitType::CodedSliceIdr => "CodedSliceIdr",
            H264NalUnitType::SEI => "SEI",
            H264NalUnitType::SPS => "SPS",
            H264NalUnitType::PPS => "PPS",
            H264NalUnitType::AUD => "AUD",
            H264NalUnitType::EndOfSequence => "EndOfSequence",
            H264NalUnitType::EndOfStream => "EndOfStream",
            H264NalUnitType::Filler => "Filler",
            H264NalUnitType::SpsExt => "SpsExt",
            H264NalUnitType::CodedSliceAux => "NalUnitTypeCodedSliceAux",
            _ => "Reserved",
        };
        write!(f, "{}({})", s, *self as u8)
    }
}

impl From<u8> for H264NalUnitType {
    fn from(v: u8) -> Self {
        match v {
            0 => H264NalUnitType::Unspecified,
            1 => H264NalUnitType::CodedSliceNonIdr,
            2 => H264NalUnitType::CodedSliceDataPartitionA,
            3 => H264NalUnitType::CodedSliceDataPartitionB,
            4 => H264NalUnitType::CodedSliceDataPartitionC,
            5 => H264NalUnitType::CodedSliceIdr,
            6 => H264NalUnitType::SEI,
            7 => H264NalUnitType::SPS,
            8 => H264NalUnitType::PPS,
            9 => H264NalUnitType::AUD,
            10 => H264NalUnitType::EndOfSequence,
            11 => H264NalUnitType::EndOfStream,
            12 => H264NalUnitType::Filler,
            13 => H264NalUnitType::SpsExt,
            19 => H264NalUnitType::CodedSliceAux,
            _ => H264NalUnitType::Reserved,
        }
    }
}

/// NAL H.264 Network Abstraction Layer
pub struct H264NAL {
    pub picture_order_count: u32,

    /// NAL header
    pub forbidden_zero_bit: bool,
    pub ref_idc: u8,
    pub unit_type: H264NalUnitType,

    /// header byte + rbsp
    pub data: BytesMut,
}

impl H264NAL {
    pub fn new(data: BytesMut) -> Self {
        H264NAL {
            picture_order_count: 0,
            forbidden_zero_bit: false,
            ref_idc: 0,
            unit_type: H264NalUnitType::Unspecified,
            data,
        }
    }

    pub fn parse_header(&mut self) {
        let first_byte = self.data[0];
        self.forbidden_zero_bit = ((first_byte & 0x80) >> 7) == 1; // 0x80 = 0b10000000
        self.ref_idc = (first_byte & 0x60) >> 5; // 0x60 = 0b01100000
        self.unit_type = H264NalUnitType::from(first_byte & 0x1F); // 0x1F = 0b00011111
    }
}

/// H265NalUnitType is the type of a NAL unit in H.265/HEVC
/// Based on ITU-T H.265 (04/2013) Table 7-1
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub enum H265NalUnitType {
    /// Coded slice of a non-TSA, non-STSA trailing picture
    #[default]
    TrailN = 0,
    /// Coded slice of a non-TSA, non-STSA trailing picture
    TrailR = 1,
    /// Coded slice of a TSA picture
    TsaN = 2,
    /// Coded slice of a TSA picture
    TsaR = 3,
    /// Coded slice of a STSA picture
    StsaN = 4,
    /// Coded slice of a STSA picture
    StsaR = 5,
    /// Coded slice of a RADL picture
    RadlN = 6,
    /// Coded slice of a RADL picture
    RadlR = 7,
    /// Coded slice of a RASL picture
    RaslN = 8,
    /// Coded slice of a RASL picture
    RaslR = 9,
    /// Coded slice of a BLA picture
    BlaN = 16,
    /// Coded slice of a BLA picture
    BlaR = 17,
    /// Coded slice of a BLA picture
    BlaRadl = 18,
    /// Coded slice of an IDR picture
    Idr = 19,
    /// Coded slice of an IDR picture
    IdrNlp = 20,
    /// Coded slice of a CRA picture
    Cra = 21,
    /// Video Parameter Set
    VPS = 32,
    /// Sequence Parameter Set
    SPS = 33,
    /// Picture Parameter Set
    PPS = 34,
    /// Access Unit Delimiter
    AUD = 35,
    /// End of Sequence
    EOS = 36,
    /// End of Bitstream
    EOB = 37,
    /// Filler Data
    FD = 38,
    /// Supplemental Enhancement Information
    PrefixSEI = 39,
    /// Supplemental Enhancement Information
    SuffixSEI = 40,
    /// Reserved
    Reserved,
}

impl fmt::Display for H265NalUnitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            H265NalUnitType::TrailN => "TrailN",
            H265NalUnitType::TrailR => "TrailR",
            H265NalUnitType::TsaN => "TsaN",
            H265NalUnitType::TsaR => "TsaR",
            H265NalUnitType::StsaN => "StsaN",
            H265NalUnitType::StsaR => "StsaR",
            H265NalUnitType::RadlN => "RadlN",
            H265NalUnitType::RadlR => "RadlR",
            H265NalUnitType::RaslN => "RaslN",
            H265NalUnitType::RaslR => "RaslR",
            H265NalUnitType::BlaN => "BlaN",
            H265NalUnitType::BlaR => "BlaR",
            H265NalUnitType::BlaRadl => "BlaRadl",
            H265NalUnitType::Idr => "Idr",
            H265NalUnitType::IdrNlp => "IdrNlp",
            H265NalUnitType::Cra => "Cra",
            H265NalUnitType::VPS => "VPS",
            H265NalUnitType::SPS => "SPS",
            H265NalUnitType::PPS => "PPS",
            H265NalUnitType::AUD => "AUD",
            H265NalUnitType::EOS => "EOS",
            H265NalUnitType::EOB => "EOB",
            H265NalUnitType::FD => "FD",
            H265NalUnitType::PrefixSEI => "PrefixSEI",
            H265NalUnitType::SuffixSEI => "SuffixSEI",
            _ => "Reserved",
        };
        write!(f, "{}({})", s, *self as u8)
    }
}

impl From<u8> for H265NalUnitType {
    fn from(v: u8) -> Self {
        match v {
            0 => H265NalUnitType::TrailN,
            1 => H265NalUnitType::TrailR,
            2 => H265NalUnitType::TsaN,
            3 => H265NalUnitType::TsaR,
            4 => H265NalUnitType::StsaN,
            5 => H265NalUnitType::StsaR,
            6 => H265NalUnitType::RadlN,
            7 => H265NalUnitType::RadlR,
            8 => H265NalUnitType::RaslN,
            9 => H265NalUnitType::RaslR,
            16 => H265NalUnitType::BlaN,
            17 => H265NalUnitType::BlaR,
            18 => H265NalUnitType::BlaRadl,
            19 => H265NalUnitType::Idr,
            20 => H265NalUnitType::IdrNlp,
            21 => H265NalUnitType::Cra,
            32 => H265NalUnitType::VPS,
            33 => H265NalUnitType::SPS,
            34 => H265NalUnitType::PPS,
            35 => H265NalUnitType::AUD,
            36 => H265NalUnitType::EOS,
            37 => H265NalUnitType::EOB,
            38 => H265NalUnitType::FD,
            39 => H265NalUnitType::PrefixSEI,
            40 => H265NalUnitType::SuffixSEI,
            _ => H265NalUnitType::Reserved,
        }
    }
}

/// NAL H.265/HEVC Network Abstraction Layer
/// H.265 uses a 2-byte NAL unit header
pub struct H265NAL {
    /// NAL header (2 bytes for H.265)
    pub forbidden_zero_bit: bool,
    pub unit_type: H265NalUnitType,
    pub nuh_layer_id: u8,
    pub nuh_temporal_id_plus1: u8,

    /// NAL unit header (2 bytes) + rbsp
    pub data: BytesMut,
}

impl H265NAL {
    pub fn new(data: BytesMut) -> Self {
        H265NAL {
            forbidden_zero_bit: false,
            unit_type: H265NalUnitType::TrailN,
            nuh_layer_id: 0,
            nuh_temporal_id_plus1: 0,
            data,
        }
    }

    pub fn parse_header(&mut self) {
        if self.data.len() < 2 {
            return;
        }

        // H.265 NAL unit header is 2 bytes
        // First byte: forbidden_zero_bit (1 bit) + nal_unit_type (6 bits) + nuh_layer_id (1 bit, MSB)
        // Second byte: nuh_layer_id (5 bits, LSB) + nuh_temporal_id_plus1 (3 bits)

        let first_byte = self.data[0];
        let second_byte = self.data[1];

        self.forbidden_zero_bit = ((first_byte & 0x80) >> 7) == 1; // bit 0
        let nal_unit_type = (first_byte & 0x7E) >> 1; // bits 1-6
        self.unit_type = H265NalUnitType::from(nal_unit_type);

        let nuh_layer_id_msb = (first_byte & 0x01) << 5; // bit 7 (MSB of layer_id)
        let nuh_layer_id_lsb = (second_byte & 0xF8) >> 3; // bits 8-12 (LSB of layer_id)
        self.nuh_layer_id = nuh_layer_id_msb | nuh_layer_id_lsb;

        self.nuh_temporal_id_plus1 = second_byte & 0x07; // bits 13-15
    }
}

/// H26xNAL represents either an H264 or H265 NAL unit
pub enum H26xNAL {
    H264(H264NAL),
    H265(H265NAL),
}

impl H26xNAL {
    pub fn data(&self) -> &BytesMut {
        match self {
            H26xNAL::H264(nal) => &nal.data,
            H26xNAL::H265(nal) => &nal.data,
        }
    }
}

/// H26xReader reads data from stream and constructs H264 or H265 NAL units
/// based on the is_hevc flag
pub struct H26xReader<R: Read> {
    reader: R,
    is_hevc: bool,
    // reading buffers
    buffer: ReadBuffer,
    // for reading
    nal_prefix_parsed: bool,
    count_of_consecutive_zero_bytes: usize,
    nal_buffer: BytesMut,
}

impl<R: Read> H26xReader<R> {
    /// new creates new `H26xReader` with `capacity` sized read buffer.
    /// is_hevc: true for H265, false for H264
    pub fn new(reader: R, capacity: usize, is_hevc: bool) -> H26xReader<R> {
        H26xReader {
            reader,
            is_hevc,
            nal_prefix_parsed: false,
            buffer: ReadBuffer::new(capacity),
            count_of_consecutive_zero_bytes: 0,
            nal_buffer: BytesMut::new(),
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

            result[result_filled..][..in_buffer].copy_from_slice(self.buffer.consume(in_buffer));
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

    fn bit_stream_starts_with_prefix(&mut self) -> Result<usize> {
        let (prefix_buffer, n) = self.read4()?;

        if n == 0 {
            return Err(Error::ErrIoEOF);
        }

        if n < 3 {
            return Err(if self.is_hevc {
                Error::ErrDataIsNotH265Stream
            } else {
                Error::ErrDataIsNotH264Stream
            });
        }

        let nal_prefix3bytes_found = NAL_PREFIX_3BYTES[..] == prefix_buffer[..3];
        if n == 3 {
            if nal_prefix3bytes_found {
                return Err(Error::ErrIoEOF);
            }
            return Err(if self.is_hevc {
                Error::ErrDataIsNotH265Stream
            } else {
                Error::ErrDataIsNotH264Stream
            });
        }

        // n == 4
        if nal_prefix3bytes_found {
            self.nal_buffer.put_u8(prefix_buffer[3]);
            return Ok(3);
        }

        let nal_prefix4bytes_found = NAL_PREFIX_4BYTES[..] == prefix_buffer;
        if nal_prefix4bytes_found {
            Ok(4)
        } else {
            Err(if self.is_hevc {
                Error::ErrDataIsNotH265Stream
            } else {
                Error::ErrDataIsNotH264Stream
            })
        }
    }

    /// next_nal reads from stream and returns then next NAL,
    /// and an error if there is incomplete frame data.
    /// Returns all nil values when no more NALs are available.
    pub fn next_nal(&mut self) -> Result<H26xNAL> {
        if !self.nal_prefix_parsed {
            self.bit_stream_starts_with_prefix()?;
            self.nal_prefix_parsed = true;
        }

        loop {
            let Some(read_byte) = self.read1()? else {
                break;
            };

            let nal_found = self.process_byte(read_byte);
            if nal_found {
                if self.is_hevc {
                    // H.265 NAL unit type is in the first byte, bits 1-6
                    if self.nal_buffer.len() >= 1 {
                        let nal_unit_type = H265NalUnitType::from((self.nal_buffer[0] & 0x7E) >> 1);
                        // Skip SEI NAL units
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
                    // H.264 NAL unit type is in the first byte, bits 3-7
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
                    let nal_unit_length =
                        self.nal_buffer.len() - count_of_consecutive_zero_bytes_in_prefix;
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
