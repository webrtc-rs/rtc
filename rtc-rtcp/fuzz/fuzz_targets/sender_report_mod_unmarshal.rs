#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::sender_report::SenderReport;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = SenderReport::unmarshal(&mut buf);
});
