#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::extended_report::PacketReceiptTimesReportBlock;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = PacketReceiptTimesReportBlock::unmarshal(&mut buf);
});
