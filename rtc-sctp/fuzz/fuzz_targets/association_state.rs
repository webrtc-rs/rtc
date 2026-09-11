#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    rtc_sctp::fuzzing::association_state(input, std::time::Instant::now());
});
