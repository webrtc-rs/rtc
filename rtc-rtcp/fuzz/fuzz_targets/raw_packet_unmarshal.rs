#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::raw_packet::RawPacket;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = RawPacket::unmarshal(&mut buf);
});
