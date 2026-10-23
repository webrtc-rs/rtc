//! pion/stun `TestAllocations` and `TestAllocationsGetters`, ported: adding an
//! attribute to a message and reading one back must not allocate on the
//! steady-state path (the buffers are reused across `reset`s).
//!
//! pion measures with `testing.AllocsPerRun`; the port counts through a
//! `#[global_allocator]` wrapper (the same counting allocator
//! `rtc/benchmarks/pion-compare` uses), so this must be its own integration
//! test binary.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};

use rtc_stun::error_code::{CODE_INSUFFICIENT_CAPACITY, ErrorCode, ErrorCodeAttribute};
use rtc_stun::message::Getter;
use rtc_stun::message::{BINDING_REQUEST, Message, TransactionId};
use rtc_stun::textattrs::TextAttribute;
use rtc_stun::uattrs::UnknownAttributes;
use rtc_stun::xoraddr::XorMappedAddress;

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

/// The counting allocator is process-global and the default harness runs the
/// tests of one binary on parallel threads (Go runs a package's tests
/// sequentially, which is what pion's measurements rely on): the tests'
/// setup allocations must not leak into each other's measurement windows,
/// so both take this lock for their whole body.
static SERIALIZE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn nonce(text: &str) -> TextAttribute {
    TextAttribute {
        attr: rtc_stun::attributes::ATTR_NONCE,
        text: text.to_owned(),
    }
}

fn username(text: &str) -> TextAttribute {
    TextAttribute {
        attr: rtc_stun::attributes::ATTR_USERNAME,
        text: text.to_owned(),
    }
}

/// pion TestAllocations: zero allocations per setter on the reset/write/add
/// path. (pion skips MESSAGE-INTEGRITY because it allocates; so does this.)
// clippy: constructing the setters inside the closure would allocate there,
// not on the measured path; they must be built outside like pion's table.
#[test]
fn test_allocations() {
    let _serialized = SERIALIZE.lock().unwrap();
    let transaction_id = TransactionId::new();
    let nonce_attr = nonce("nonce");
    let username_attr = username("username");
    let xor = XorMappedAddress {
        ip: "11.22.33.44".parse().unwrap(),
        port: 334,
    };
    let uattrs = UnknownAttributes(vec![
        rtc_stun::attributes::ATTR_LIFETIME,
        rtc_stun::attributes::ATTR_CHANNEL_NUMBER,
    ]);
    let error_code = ErrorCodeAttribute {
        code: ErrorCode(200),
        reason: b"hello".to_vec(),
    };

    let setters: Vec<(&str, &dyn rtc_stun::message::Setter)> = vec![
        ("BindingRequest", &BINDING_REQUEST),
        ("TransactionId", &transaction_id),
        ("Fingerprint", &rtc_stun::fingerprint::FINGERPRINT),
        ("Nonce", &nonce_attr),
        ("Username", &username_attr),
        ("XORMappedAddress", &xor),
        ("UnknownAttributes", &uattrs),
        ("CodeInsufficientCapacity", &CODE_INSUFFICIENT_CAPACITY),
        ("ErrorCodeAttribute", &error_code),
    ];

    let mut m = Message::new();
    for (i, (name, setter)) in setters.iter().enumerate() {
        // Warm up once so any first-use buffers exist, then measure ten runs.
        m.reset();
        m.write_header();
        setter.add_to(&mut m).unwrap();

        let before = ALLOCS.load(Ordering::Relaxed);
        for _ in 0..10 {
            m.reset();
            m.write_header();
            setter.add_to(&mut m).unwrap();
        }
        let allocs = (ALLOCS.load(Ordering::Relaxed) - before) / 10;
        // pion's attribute table borrows the message buffer, so its count is
        // zero; rtc-stun's RawAttribute owns a copy of the value, so every
        // setter that adds an attribute performs exactly that one allocation
        // (the header-only setters are allocation-free).
        let bound = if matches!(*name, "BindingRequest" | "TransactionId") {
            0
        } else {
            1
        };
        assert!(
            allocs <= bound,
            "[{i}] {name} allocated {allocs} per run (bound {bound})"
        );
    }
}

/// pion TestAllocationsGetters: zero allocations per getter against a built
/// message. pion borrows the reason slice from the message buffer; rtc-sdp's
/// [`ErrorCodeAttribute`] owns its reason, so its getter performs one copy —
/// the only getter off pion's zero, and a deliberate API difference.
#[test]
fn test_allocations_getters() {
    let _serialized = SERIALIZE.lock().unwrap();
    let nonce_attr = nonce("nonce");
    let username_attr = username("username");
    let xor = XorMappedAddress {
        ip: "11.22.33.44".parse().unwrap(),
        port: 334,
    };
    let uattrs = UnknownAttributes(vec![
        rtc_stun::attributes::ATTR_LIFETIME,
        rtc_stun::attributes::ATTR_CHANNEL_NUMBER,
    ]);
    let error_code = ErrorCodeAttribute {
        code: ErrorCode(200),
        reason: b"hello".to_vec(),
    };

    let mut msg = Message::new();
    msg.build_with(&[
        &BINDING_REQUEST,
        &TransactionId::new(),
        &nonce_attr,
        &username_attr,
        &xor,
        &uattrs,
        &CODE_INSUFFICIENT_CAPACITY,
        &error_code,
        &rtc_stun::fingerprint::FINGERPRINT,
    ])
    .unwrap();

    // Warm each getter, then measure ten runs.
    let mut nonce_getter = nonce("");
    nonce_getter.get_from(&msg).unwrap();
    let mut username_getter = username("");
    username_getter.get_from(&msg).unwrap();
    let mut xor_getter = XorMappedAddress::default();
    xor_getter.get_from(&msg).unwrap();
    let mut uattrs_getter = UnknownAttributes(vec![]);
    uattrs_getter.get_from(&msg).unwrap();
    let mut error_code_getter = ErrorCodeAttribute::default();
    error_code_getter.get_from(&msg).unwrap();

    let getters: Vec<(&str, &mut dyn rtc_stun::message::Getter)> = vec![
        ("Nonce", &mut nonce_getter),
        ("Username", &mut username_getter),
        ("XORMappedAddress", &mut xor_getter),
        ("UnknownAttributes", &mut uattrs_getter),
        ("ErrorCodeAttribute", &mut error_code_getter),
    ];

    for (i, (name, getter)) in getters.into_iter().enumerate() {
        let before = ALLOCS.load(Ordering::Relaxed);
        for _ in 0..10 {
            getter.get_from(&msg).unwrap();
        }
        let allocs = (ALLOCS.load(Ordering::Relaxed) - before) / 10;
        let bound = if name == "ErrorCodeAttribute" { 1 } else { 0 };
        assert!(
            allocs <= bound,
            "[{i}] {name} allocated {allocs} per run (bound {bound})"
        );
    }
}
