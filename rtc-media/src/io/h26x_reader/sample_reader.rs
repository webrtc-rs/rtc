use bytes::{Bytes, BytesMut};
use shared::error::{Error, Result};
use std::io::Read;

use super::{H26xNAL, H26xReader, H264NalUnitType, H265NalUnitType};

const ANNEXB_START_CODE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H26xSample {
    pub data: Bytes,
    pub timed: bool,
}

pub struct H26xSampleReader<R: Read> {
    reader: H26xReader<R>,
    is_hevc: bool,
    pending_hevc_nals: Vec<BytesMut>,
}

impl<R: Read> H26xSampleReader<R> {
    pub fn new(reader: R, capacity: usize, is_hevc: bool) -> Self {
        Self {
            reader: H26xReader::new(reader, capacity, is_hevc),
            is_hevc,
            pending_hevc_nals: vec![],
        }
    }

    pub fn next_sample(&mut self) -> Result<H26xSample> {
        loop {
            let nal = match self.reader.next_nal() {
                Ok(nal) => nal,
                Err(Error::ErrIoEOF) if self.is_hevc && !self.pending_hevc_nals.is_empty() => {
                    let data = build_hevc_access_unit(&mut self.pending_hevc_nals, None);
                    return Ok(H26xSample { data, timed: false });
                }
                Err(err) => return Err(err),
            };

            let timed = !should_skip_timing(&nal);
            if self.is_hevc && should_buffer_with_next_hevc_vcl(&nal) {
                self.pending_hevc_nals.push(nal.data().clone());
                continue;
            }

            let data = if self.is_hevc && !self.pending_hevc_nals.is_empty() {
                build_hevc_access_unit(&mut self.pending_hevc_nals, Some(nal.data()))
            } else {
                nal.data().clone().freeze()
            };

            return Ok(H26xSample { data, timed });
        }
    }
}

fn should_skip_timing(nal: &H26xNAL) -> bool {
    match nal {
        H26xNAL::H264(nal) => {
            matches!(
                nal.unit_type,
                H264NalUnitType::SPS
                    | H264NalUnitType::PPS
                    | H264NalUnitType::SEI
                    | H264NalUnitType::AUD
            )
        }
        H26xNAL::H265(nal) => {
            matches!(
                nal.unit_type,
                H265NalUnitType::VPS
                    | H265NalUnitType::SPS
                    | H265NalUnitType::PPS
                    | H265NalUnitType::PrefixSEI
                    | H265NalUnitType::SuffixSEI
                    | H265NalUnitType::AUD
            )
        }
    }
}

fn should_buffer_with_next_hevc_vcl(nal: &H26xNAL) -> bool {
    matches!(
        nal,
        H26xNAL::H265(nal)
            if matches!(
                nal.unit_type,
                H265NalUnitType::VPS
                    | H265NalUnitType::SPS
                    | H265NalUnitType::PPS
                    | H265NalUnitType::PrefixSEI
                    | H265NalUnitType::SuffixSEI
                    | H265NalUnitType::AUD
            )
    )
}

fn build_hevc_access_unit(
    buffered_nals: &mut Vec<BytesMut>,
    current_nal: Option<&BytesMut>,
) -> Bytes {
    let total_len = buffered_nals
        .iter()
        .map(|nal| ANNEXB_START_CODE.len() + nal.len())
        .sum::<usize>()
        + current_nal.map_or(0, |nal| ANNEXB_START_CODE.len() + nal.len());
    let mut access_unit = BytesMut::with_capacity(total_len);

    for nal in buffered_nals.drain(..) {
        access_unit.extend_from_slice(&ANNEXB_START_CODE);
        access_unit.extend_from_slice(&nal);
    }
    if let Some(current_nal) = current_nal {
        access_unit.extend_from_slice(&ANNEXB_START_CODE);
        access_unit.extend_from_slice(current_nal);
    }

    access_unit.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn h265_sample_reader_groups_parameter_sets_with_following_vcl() -> Result<()> {
        let stream = vec![
            0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x01, //
            0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x02, //
            0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0x03, //
            0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xaa, //
        ];
        let mut reader = H26xSampleReader::new(Cursor::new(stream), 1024, true);

        let sample = reader.next_sample()?;

        assert!(sample.timed);
        assert_eq!(
            sample.data,
            Bytes::from_static(&[
                0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x01, //
                0x00, 0x00, 0x00, 0x01, 0x42, 0x01, 0x02, //
                0x00, 0x00, 0x00, 0x01, 0x44, 0x01, 0x03, //
                0x00, 0x00, 0x00, 0x01, 0x28, 0x01, 0xaa, //
            ])
        );
        assert!(matches!(reader.next_sample(), Err(Error::ErrIoEOF)));

        Ok(())
    }

    #[test]
    fn h264_sample_reader_keeps_parameter_sets_separate_and_untimed() -> Result<()> {
        let stream = vec![
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1f, //
            0x00, 0x00, 0x00, 0x01, 0x68, 0xce, 0x06, 0xe2, //
            0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, //
        ];
        let mut reader = H26xSampleReader::new(Cursor::new(stream), 1024, false);

        let sps = reader.next_sample()?;
        assert!(!sps.timed);
        assert_eq!(sps.data, Bytes::from_static(&[0x67, 0x42, 0x00, 0x1f]));

        let pps = reader.next_sample()?;
        assert!(!pps.timed);
        assert_eq!(pps.data, Bytes::from_static(&[0x68, 0xce, 0x06, 0xe2]));

        let idr = reader.next_sample()?;
        assert!(idr.timed);
        assert_eq!(idr.data, Bytes::from_static(&[0x65, 0x88, 0x84, 0x21]));

        Ok(())
    }
}
