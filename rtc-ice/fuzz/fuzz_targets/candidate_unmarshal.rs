#![no_main]

//! Candidate lines: a line that parses must marshal to a line that parses to the same candidate.

use libfuzzer_sys::fuzz_target;
use rtc_ice::candidate::unmarshal_candidate;

fuzz_target!(|line: &str| {
    if let Ok(candidate) = unmarshal_candidate(line) {
        let again = unmarshal_candidate(&candidate.marshal())
            .expect("a candidate's own marshalling parses");
        assert_eq!(candidate.marshal(), again.marshal());
        assert_eq!(candidate.priority(), again.priority());
    }
});
