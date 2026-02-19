#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::chunk_chunk_forward_tsn_stream_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = chunk_chunk_forward_tsn_stream_unmarshal(data);
});
