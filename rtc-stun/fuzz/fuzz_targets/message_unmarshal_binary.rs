#![no_main]

use libfuzzer_sys::fuzz_target;
use rtc_stun::attributes::ATTR_SOFTWARE;
use rtc_stun::message::Message;
use rtc_stun::textattrs::TextAttribute;
use rtc_stun::xoraddr::XorMappedAddress;

fuzz_target!(|data: &[u8]| {
    let mut m = Message::new();
    m.build(&[
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "software".to_owned())),
        Box::new(XorMappedAddress {
            ip: "213.1.223.5".parse().unwrap(),
            port: 0,
        }),
    ])
    .unwrap();

    let _ = m.unmarshal_binary(data);
});
