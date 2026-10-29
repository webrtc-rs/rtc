#![no_main]

//! DCEP messages arrive on an SCTP stream before the peer is authenticated to do anything else:
//! parsing must never panic, and what parses must re-marshal to something that parses equal.

use libfuzzer_sys::fuzz_target;
use rtc_datachannel::message::Message;
use rtc_shared::marshal::{Marshal, MarshalSize, Unmarshal};

fuzz_target!(|data: &[u8]| {
    let mut buf = data;
    let Ok(message) = Message::unmarshal(&mut buf) else {
        return;
    };
    let Ok(bytes) = message.marshal() else {
        return;
    };
    assert_eq!(bytes.len(), message.marshal_size());
    let mut again = &bytes[..];
    let reparsed = Message::unmarshal(&mut again).expect("our own output must parse");
    assert_eq!(reparsed, message);
});
