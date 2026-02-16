#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::payload_feedbacks::slice_loss_indication::SliceLossIndication;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = SliceLossIndication::unmarshal(&mut buf);
});
