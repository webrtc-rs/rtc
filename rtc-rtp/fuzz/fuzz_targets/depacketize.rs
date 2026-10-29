#![no_main]

//! Every depacketizer must reject, not panic on, any payload; and a depacketizer fed a whole
//! stream of arbitrary payloads (state carried between calls) must stay panic-free too.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use rtc_rtp::codec::av1::Av1Depacketizer;
use rtc_rtp::codec::h264::H264Packet;
use rtc_rtp::codec::h265::H265Depacketizer;
use rtc_rtp::codec::h266::H266Depacketizer;
use rtc_rtp::codec::opus::OpusPacket;
use rtc_rtp::codec::vp8::Vp8Packet;
use rtc_rtp::codec::vp9::Vp9Packet;
use rtc_rtp::packetizer::Depacketizer;

fn drive(depacketizer: &mut dyn Depacketizer, chunks: &[Bytes]) {
    for chunk in chunks {
        let _ = depacketizer.depacketize(chunk);
        let _ = depacketizer.is_partition_head(chunk);
        let _ = depacketizer.is_partition_tail(true, chunk);
        let _ = depacketizer.is_partition_tail(false, chunk);
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks how the input is cut into consecutive payloads (a stream), so state
    // that survives between packets (fragment reassembly) is exercised.
    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let cut = (cut as usize % 8) + 1;
    let chunks: Vec<Bytes> = rest
        .chunks(rest.len().div_ceil(cut).max(1))
        .map(Bytes::copy_from_slice)
        .collect();

    drive(&mut Vp8Packet::default(), &chunks);
    drive(&mut Vp9Packet::default(), &chunks);
    drive(&mut H264Packet::default(), &chunks);
    drive(&mut H265Depacketizer::default(), &chunks);
    drive(&mut H266Depacketizer::default(), &chunks);
    drive(&mut Av1Depacketizer::default(), &chunks);
    drive(&mut OpusPacket, &chunks);
});
