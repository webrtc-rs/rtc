#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::param_param_header_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = param_param_header_unmarshal(data);
});
