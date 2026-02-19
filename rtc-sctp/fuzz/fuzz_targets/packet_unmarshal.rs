#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::packet_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = packet_unmarshal(data);
});
