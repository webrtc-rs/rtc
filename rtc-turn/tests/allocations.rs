//! pion/turn's `NoAlloc` tests, ported and widened: once warm, adding a TURN attribute to a reused
//! message, reading one back, and encoding or decoding ChannelData must not allocate.
//!
//! The counting allocator is process-global and the default harness runs the tests of one binary on
//! parallel threads, so every test takes `SERIALIZE` for its whole body, and this has to be its own
//! integration-test binary.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rtc_turn::proto::PROTO_UDP;
use rtc_turn::proto::chandata::ChannelData;
use rtc_turn::proto::channum::{ChannelNumber, MIN_CHANNEL_NUMBER};
use rtc_turn::proto::data::Data;
use rtc_turn::proto::evenport::EvenPort;
use rtc_turn::proto::lifetime::Lifetime;
use rtc_turn::proto::reqfamily::REQUESTED_FAMILY_IPV6;
use rtc_turn::proto::reqtrans::RequestedTransport;
use stun::message::{Getter, Message, Setter};

struct Counting;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { std::alloc::System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { std::alloc::System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { std::alloc::System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Counting = Counting;

static SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// How many allocations `f` makes per call, once it has run a few times to warm its buffers.
fn allocations_per_call(mut f: impl FnMut()) -> usize {
    for _ in 0..8 {
        f();
    }
    let before = ALLOCS.load(Ordering::Relaxed);
    const RUNS: usize = 1000;
    for _ in 0..RUNS {
        f();
    }
    (ALLOCS.load(Ordering::Relaxed) - before) / RUNS
}

#[test]
fn adding_a_turn_attribute_to_a_reused_message_does_not_allocate() {
    let _serialized = SERIALIZE.lock().unwrap();
    let setters: Vec<(&str, Box<dyn Setter>)> = vec![
        (
            "CHANNEL-NUMBER",
            Box::new(ChannelNumber(MIN_CHANNEL_NUMBER + 1)),
        ),
        ("LIFETIME", Box::new(Lifetime(Duration::from_secs(60)))),
        ("DATA", Box::new(Data(vec![7; 100]))),
        ("EVEN-PORT", Box::new(EvenPort::new(true))),
        (
            "REQUESTED-TRANSPORT",
            Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            }),
        ),
        ("REQUESTED-ADDRESS-FAMILY", Box::new(REQUESTED_FAMILY_IPV6)),
    ];
    for (name, setter) in &setters {
        let mut m = Message::new();
        let n = allocations_per_call(|| {
            setter.add_to(&mut m).unwrap();
            m.reset();
        });
        assert_eq!(
            n, 0,
            "{name}: add_to + reset allocates {n} time(s) per call"
        );
    }
}

#[test]
fn reading_a_turn_attribute_does_not_allocate() {
    let _serialized = SERIALIZE.lock().unwrap();
    let mut m = Message::new();
    ChannelNumber(MIN_CHANNEL_NUMBER + 1)
        .add_to(&mut m)
        .unwrap();
    Lifetime(Duration::from_secs(60)).add_to(&mut m).unwrap();
    EvenPort::new(true).add_to(&mut m).unwrap();
    RequestedTransport {
        protocol: PROTO_UDP,
    }
    .add_to(&mut m)
    .unwrap();

    let mut number = ChannelNumber::default();
    let mut lifetime = Lifetime::default();
    let mut even = EvenPort::default();
    let mut transport = RequestedTransport::default();
    let n = allocations_per_call(|| {
        number.get_from(&m).unwrap();
        lifetime.get_from(&m).unwrap();
        even.get_from(&m).unwrap();
        transport.get_from(&m).unwrap();
    });
    assert_eq!(n, 0);
    assert_eq!(number, ChannelNumber(MIN_CHANNEL_NUMBER + 1));
    assert_eq!(lifetime, Lifetime(Duration::from_secs(60)));
}

#[test]
fn channel_data_parse_never_allocates_and_encode_decode_do_not_once_warm() {
    let _serialized = SERIALIZE.lock().unwrap();
    let mut encoded = ChannelData {
        data: vec![1, 2, 3, 4, 5],
        number: ChannelNumber(MIN_CHANNEL_NUMBER + 1),
        raw: vec![],
    };
    encoded.encode();
    let wire = encoded.raw.clone();

    let n = allocations_per_call(|| {
        let (number, payload) = ChannelData::parse(&wire).unwrap();
        std::hint::black_box((number, payload));
    });
    assert_eq!(n, 0, "parse borrows");

    let mut d = ChannelData {
        data: vec![1, 2, 3, 4, 5],
        number: ChannelNumber(MIN_CHANNEL_NUMBER + 1),
        raw: vec![],
    };
    let n = allocations_per_call(|| {
        d.encode();
    });
    assert_eq!(n, 0, "encode reuses raw");

    let mut decoded = ChannelData::default();
    let n = allocations_per_call(|| {
        decoded.reset();
        decoded.raw.extend_from_slice(&wire);
        decoded.decode().unwrap();
    });
    assert_eq!(n, 0, "decode reuses data");
    assert_eq!(decoded.data, [1, 2, 3, 4, 5]);
}
