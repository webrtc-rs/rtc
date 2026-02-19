#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::source_description::SourceDescriptionChunk;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = SourceDescriptionChunk::unmarshal(&mut buf);
});
