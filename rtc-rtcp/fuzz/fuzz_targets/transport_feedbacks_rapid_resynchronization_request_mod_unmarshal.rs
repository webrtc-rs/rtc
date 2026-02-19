#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::transport_feedbacks::rapid_resynchronization_request::RapidResynchronizationRequest;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = RapidResynchronizationRequest::unmarshal(&mut buf);
});
