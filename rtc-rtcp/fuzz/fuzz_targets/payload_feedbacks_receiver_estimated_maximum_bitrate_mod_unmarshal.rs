#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_rtcp::payload_feedbacks::receiver_estimated_maximum_bitrate::ReceiverEstimatedMaximumBitrate;
use rtc_shared::marshal::Unmarshal;

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let _ = ReceiverEstimatedMaximumBitrate::unmarshal(&mut buf);
});
