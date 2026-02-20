#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::packet_partial_decode_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = packet_partial_decode_unmarshal(data);
});
