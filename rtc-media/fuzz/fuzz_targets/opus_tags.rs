#![no_main]

//! The OpusTags parser must reject, never panic on, arbitrary bytes — the
//! comment count and per-comment lengths are attacker-controlled u32s.

use libfuzzer_sys::fuzz_target;
use rtc_media::io::ogg_reader::parse_opus_tags;

fuzz_target!(|data: &[u8]| {
    let _ = parse_opus_tags(data);
});
