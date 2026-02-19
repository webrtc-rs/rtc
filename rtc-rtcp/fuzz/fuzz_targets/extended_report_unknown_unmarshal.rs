#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::extended_report::UnknownReportBlock;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = UnknownReportBlock::unmarshal(&mut buf);
});
