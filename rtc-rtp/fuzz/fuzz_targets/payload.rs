#![no_main]

//! Payloaders must terminate, without panicking or exhausting memory, for any frame at any MTU
//! (pion's H.265 payloader hangs and allocates without bound at an MTU of 3; libFuzzer's
//! timeout and RSS limit are what catch that class of bug here).

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc_rtp::codec::av1::Av1Payloader;
use rtc_rtp::codec::h264::H264Payloader;
use rtc_rtp::codec::h265::HevcPayloader;
use rtc_rtp::codec::opus::OpusPayloader;
use rtc_rtp::codec::vp8::Vp8Payloader;
use rtc_rtp::codec::vp9::Vp9Payloader;
use rtc_rtp::packetizer::Payloader;

fuzz_target!(|data: &[u8]| {
    let Some((mtu, frame)) = data.split_first_chunk::<2>() else {
        return;
    };
    // 1..=1500 covers the interesting range, tiny MTUs included.
    let mtu = u16::from_be_bytes(*mtu) as usize % 1500 + 1;
    let frame = Bytes::copy_from_slice(frame);

    let mut payloaders: Vec<Box<dyn Payloader>> = vec![
        Box::new(Vp8Payloader::default()),
        Box::new(Vp9Payloader::default()),
        Box::new(H264Payloader::default()),
        Box::new(HevcPayloader::default()),
        Box::new(Av1Payloader::default()),
        Box::new(OpusPayloader),
    ];
    for payloader in &mut payloaders {
        let _ = payloader.payload(mtu, &frame);
    }
});
