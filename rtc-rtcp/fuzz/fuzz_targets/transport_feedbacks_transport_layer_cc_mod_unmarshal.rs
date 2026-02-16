#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::transport_feedbacks::transport_layer_cc::RunLengthChunk;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = RunLengthChunk::unmarshal(&mut buf);
});
