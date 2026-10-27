#![no_main]

//! A STUN message decoded from arbitrary bytes, and every TURN attribute read from it.

use libfuzzer_sys::fuzz_target;
use rtc_turn::proto::channum::ChannelNumber;
use rtc_turn::proto::connid::ConnectionId;
use rtc_turn::proto::data::Data;
use rtc_turn::proto::dontfrag::DontFragmentAttr;
use rtc_turn::proto::evenport::EvenPort;
use rtc_turn::proto::lifetime::Lifetime;
use rtc_turn::proto::peeraddr::PeerAddress;
use rtc_turn::proto::relayaddr::RelayedAddress;
use rtc_turn::proto::reqfamily::RequestedAddressFamily;
use rtc_turn::proto::reqtrans::RequestedTransport;
use rtc_turn::proto::rsrvtoken::ReservationToken;
use stun::message::{Getter, Message};

fuzz_target!(|data: &[u8]| {
    let mut m = Message {
        raw: data.to_vec(),
        ..Default::default()
    };
    if m.decode().is_err() {
        return;
    }
    let _ = ChannelNumber::default().get_from(&m);
    let _ = ConnectionId::default().get_from(&m);
    let _ = Data::default().get_from(&m);
    let _ = DontFragmentAttr.get_from(&m);
    let _ = EvenPort::default().get_from(&m);
    let _ = Lifetime::default().get_from(&m);
    let _ = PeerAddress::default().get_from(&m);
    let _ = RelayedAddress::default().get_from(&m);
    let _ = RequestedAddressFamily::default().get_from(&m);
    let _ = RequestedTransport::default().get_from(&m);
    let _ = ReservationToken::default().get_from(&m);
});
