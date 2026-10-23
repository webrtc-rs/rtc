#![no_main]

//! The OpusHead parser must reject, never panic on, arbitrary bytes —
//! including lengths that would slice out of range for every channel-mapping
//! family (pion's `ParseOpusHead` no-panic tests, fed continuously).

use libfuzzer_sys::fuzz_target;
use rtc_media::io::ogg_reader::parse_opus_head;

fuzz_target!(|data: &[u8]| {
    let _ = parse_opus_head(data);
});
