#![no_main]
use libfuzzer_sys::fuzz_target;
use rtc_dtls::state::State;

fuzz_target!(|data: &[u8]| {
    // A resumed session's state is loaded from storage the application controls, but it is
    // still parsed input: it must be refused, never panic.
    for is_client in [true, false] {
        let provider = rtc_crypto::default_provider().expect("a built-in provider is enabled");
        let mut state = State::new(provider, is_client);
        let _ = state.unmarshal_binary(data);
    }
});
