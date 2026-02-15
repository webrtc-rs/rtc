#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtp::packet::Packet;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = Packet::unmarshal(&mut buf);
});
