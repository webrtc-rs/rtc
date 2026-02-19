#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_sctp::fuzzing::param_param_unknown_unmarshal;

fuzz_target!(|data: &[u8]| {
    let _ = param_param_unknown_unmarshal(data);
});
