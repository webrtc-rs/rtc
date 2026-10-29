#![no_main]

//! The Ogg reader must reject, never panic on, arbitrary bytes — through every
//! page of a stream, with and without checksum verification.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rtc_media::io::ogg_reader::{OggHeaderType, OggReader};

fuzz_target!(|data: &[u8]| {
    // The first byte decides whether checksums are verified, so both the
    // checksum path (CRC table walks over attacker-sized segment tables) and
    // the lenient path run.
    let Some((&do_checksum, _rest)) = data.split_first() else {
        return;
    };
    let do_checksum = do_checksum & 1 == 1;

    let mut reader = OggReader::new_with_options(Cursor::new(data), do_checksum);
    while let Ok((payload, page_header)) = reader.parse_next_page() {
        // Classification must be panic-free on every payload shape too.
        let _ = page_header.opus_header_type(&payload);
        let _ = page_header.is_beginning_of_stream();
        let _ = page_header.is_end_of_stream();
        if page_header.opus_header_type(&payload) == Some(OggHeaderType::OpusHead) {
            let _ = rtc_media::io::ogg_reader::parse_opus_head(&payload);
        }
    }
});
