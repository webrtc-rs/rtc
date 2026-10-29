#![no_main]

//! ChannelData: whatever `parse` and `decode` accept, `encode` writes back so that both read the
//! same channel and payload again.

use libfuzzer_sys::fuzz_target;
use rtc_turn::proto::chandata::ChannelData;

fuzz_target!(|data: &[u8]| {
    let _ = ChannelData::is_channel_data(data);
    let parsed = ChannelData::parse(data);

    let mut decoded = ChannelData {
        raw: data.to_vec(),
        ..Default::default()
    };
    // `decode` and `parse` are one parser.
    assert_eq!(decoded.decode().is_ok(), parsed.is_ok());
    let Ok((number, payload)) = parsed else {
        return;
    };
    assert_eq!(decoded.number, number);
    assert_eq!(decoded.data, payload);

    decoded.encode();
    let (again_number, again_payload) = ChannelData::parse(&decoded.raw).unwrap();
    assert_eq!(again_number, number);
    assert_eq!(again_payload, payload);
    assert_eq!(decoded.raw.len() % 4, 0, "encoded ChannelData is padded");
});
