#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::chunk_error_cause_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = chunk_error_cause_unmarshal(data);
});
