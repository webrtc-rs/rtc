#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::state::State;

fuzz_target!(|data: &[u8]| {
    let mut state = State::default();
    let _ = state.unmarshal_binary(data);
});
