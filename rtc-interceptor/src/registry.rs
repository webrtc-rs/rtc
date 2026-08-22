//! Building a chain.

use crate::chain::Chain;
use crate::noop::NoopInterceptor;
use crate::{BoxedInterceptor, Interceptor};
use log::warn;
use std::collections::BTreeMap;

/// Where an interceptor belongs in the chain, measured by **distance from the wire**.
///
/// This is the chain contract's ordering table expressed as data, so that one place decides it and
/// a test can check a builder against it. The doc comments carry that table's indices; the gaps are
/// slots nothing fills yet.
///
/// Read walks the list forwards and write walks it in reverse, so a smaller slot is closer to the
/// network in both directions.
#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
#[repr(usize)]
pub enum Slot {
    /// Congestion control: send history and feedback ingest.
    ///
    /// The only position that sees every byte that leaves, because nothing exits the chain except
    /// through the interceptors ahead of it. Named here so an estimator of your own has a
    /// landmark.
    CongestionControl = 1_000,
    /// `TwccSenderInterceptor` — assigns the transport-wide sequence number the send history keys on.
    TwccSender = 2_000,
    /// `PacerInterceptor` — gates departures. Everything that generates a packet sits above it, so
    /// retransmissions, FEC repair and generated RTCP are all metered.
    Pacer = 3_000,
    /// `NackResponderInterceptor` — buffers sent RTP; its retransmissions still reach 3_000, 2_000, 1_000.
    NackResponder = 4_000,
    /// `FlexFec03SendInterceptor` — its repair packets still reach everything below.
    FecEncoder = 5_000,
    /// `FlexFec03ReceiveInterceptor` — recovery before anything inspects sequence numbers.
    FecDecoder = 6_000,
    /// `NackGeneratorInterceptor` — loss detected from arrivals, not from released packets.
    NackGenerator = 7_000,
    /// `TwccReceiverInterceptor` — records arrivals and reports them to the remote sender's
    /// congestion controller. An arrival recorder, so it precedes the jitter buffer.
    TwccReceiver = 8_000,
    /// `Rfc8888Interceptor` — the same job as [`Slot::TwccReceiver`] in a different format, and
    /// registering both double-counts, so a chain carries one or the other.
    Rfc8888 = 9_000,
    /// `ReceiverReportInterceptor` — RFC 3550 reception quality, not congestion-control feedback.
    /// Still an arrival recorder, so it precedes the jitter buffer.
    ReceiverReport = 10_000,
    /// `SenderReportInterceptor` — a generator with no read-side ordering constraint.
    SenderReport = 11_000,
    /// `IntervalPliInterceptor` — a generator with no read-side ordering constraint.
    IntervalPli = 12_000,
    /// `JitterBufferInterceptor` — delays and re-stamps, so every arrival recorder precedes it.
    ///
    /// A recorder below this would report local playout instants to the remote as arrival times,
    /// and the remote's congestion controller would read this endpoint's buffering depth as network
    /// delay variation.
    JitterBuffer = 13_000,
    /// Anywhere else, for an interceptor this crate knows nothing about.
    ///
    /// The named slots are spaced a thousand apart so that one of your own fits between any two of
    /// them without renumbering anything: `Slot::from(6_500)` sits after the FEC decoder and before
    /// the NACK generator. Reach it through [`From<usize>`](#impl-From<usize>-for-Slot) rather than
    /// by naming the variant, so the spelling stays the same if this gains a richer representation.
    Custom(usize),
}

impl Slot {
    /// Where this sits, as a distance from the wire.
    ///
    /// The named slots are the thousands; a custom one is whatever it was built from.
    pub const fn slot(self) -> usize {
        match self {
            Self::CongestionControl => 1_000,
            Self::TwccSender => 2_000,
            Self::Pacer => 3_000,
            Self::NackResponder => 4_000,
            Self::FecEncoder => 5_000,
            Self::FecDecoder => 6_000,
            Self::NackGenerator => 7_000,
            Self::TwccReceiver => 8_000,
            Self::Rfc8888 => 9_000,
            Self::ReceiverReport => 10_000,
            Self::SenderReport => 11_000,
            Self::IntervalPli => 12_000,
            Self::JitterBuffer => 13_000,
            Self::Custom(position) => position,
        }
    }
}

/// A position of your own. See [`Slot::Custom`].
impl From<usize> for Slot {
    fn from(position: usize) -> Self {
        Self::Custom(position)
    }
}

impl From<Slot> for usize {
    fn from(slot: Slot) -> Self {
        slot.slot()
    }
}

// Equality and ordering are both by position, and they are written out rather than derived because
// deriving them would disagree with each other. A derived `PartialEq` compares variants, so
// `Slot::from(2_000) != Slot::TwccSender` even though both name the same distance from the wire; a
// derived `Ord` compares *declaration* order, so `Slot::Custom(1_500)` would sort after
// `JitterBuffer` rather than between `CongestionControl` and `TwccSender` — which is the whole
// point of allowing a custom one. Two values that compare `Equal` must also be `==`, and a sort by
// slot must put a custom position where its number says, so both come from [`Slot::slot`].
impl PartialEq for Slot {
    fn eq(&self, other: &Self) -> bool {
        self.slot() == other.slot()
    }
}

impl Eq for Slot {}

impl PartialOrd for Slot {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Slot {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.slot().cmp(&other.slot())
    }
}

impl std::hash::Hash for Slot {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.slot().hash(state);
    }
}

/// Collects interceptors and assembles them into a [`Chain`].
///
/// # Order
///
/// Every interceptor is added at a [`Slot`], and [`build`](Self::build) sorts by it. A slot is a
/// **distance from the wire**: the smallest is closest to the network, the largest closest to the
/// application. Read walks that order, write walks it in reverse, so one list serves both
/// directions and "closest to the wire" means one thing rather than opposite things per direction.
///
/// ```text
/// Registry::new()
///     .with(Slot::TwccSender, a)     // 2_000: closest to the wire
///     .with(Slot::NackGenerator, b)  // 7_000
///     .with(Slot::JitterBuffer, c)   // 13_000: closest to the application
///     .build()
///
/// read:   a → b → c → application
/// write:  application → c → b → a → wire
/// ```
///
/// Declaring the position rather than relying on call order is what makes the helpers in
/// `rtc` composable: `configure_twcc` places interceptors at 2_000 and 8_000, `configure_nack` at
/// 4_000 and 7_000, and the two interleave correctly however the caller sequences them. With order taken
/// from insertion, calling them in either sequence produced a chain that was wrong in a different
/// way each time, and nothing caught it — the nested registry that preceded this added *innermost*
/// first, so `register_default_interceptors` assembled TWCC receiver → RTCP reports → NACK
/// generator, the reverse of what the chain contract documented.
///
/// A slot holds one interceptor. Two of your own go at two custom positions — the named slots are
/// spaced a thousand apart so there is room between any two of them.
///
/// # Example
///
/// ```
/// use rtc_interceptor::{NackGeneratorBuilder, Registry, Slot, TwccSenderBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::TwccSender, TwccSenderBuilder::new().build())        // closest to the wire
///     .with(Slot::NackGenerator, NackGeneratorBuilder::new().build())  // sees arrivals after it
///     .build();                                                        // terminus appended here
/// # let _ = chain;
/// ```
#[derive(Default)]
pub struct Registry {
    interceptors: BTreeMap<Slot, BoxedInterceptor>,
    /// What each interceptor is called, keyed the same way as `interceptors`.
    ///
    /// Kept beside the chain rather than asked of it: `Interceptor` is a trait object by the time
    /// it is stored, and a trait object cannot say what it used to be. Recording the name at the
    /// one moment the concrete type is still in hand is the only way to have it later, which is
    /// also why [`with`](Self::with) takes a concrete interceptor rather than a boxed one.
    names: BTreeMap<Slot, String>,
}

/// A type's name without its module paths — `TwccSenderInterceptor`, not
/// `rtc_interceptor::twcc::sender::TwccSenderInterceptor`.
///
/// Every path is shortened, not just the outermost one, so a congestion controller reads as
/// `CongestionControlInterceptor<Gcc>`. Splitting the whole string on its last `::` would be
/// simpler and wrong: on a generic type that separator sits inside the *argument*, and
/// `CongestionControlInterceptor<rtc_interceptor::cc::estimator::ConstantBitrate>` comes back as
/// `ConstantBitrate>` — the interceptor's own name gone, and a stray bracket left behind.
///
/// The generic argument is kept because it is often the only thing telling two interceptors apart:
/// which estimator a congestion controller carries is the interesting half of its name.
fn short_type_name<T: ?Sized>() -> String {
    let full = std::any::type_name::<T>();
    let mut out = String::with_capacity(full.len());
    let mut segment = String::new();

    let flush = |segment: &mut String, out: &mut String| {
        out.push_str(segment.rsplit("::").next().unwrap_or(segment));
        segment.clear();
    };

    for ch in full.chars() {
        // A path segment runs until punctuation that cannot appear in one: `<`, `>`, `,`, a space.
        if ch.is_alphanumeric() || ch == '_' || ch == ':' {
            segment.push(ch);
        } else {
            flush(&mut segment, &mut out);
            out.push(ch);
        }
    }
    flush(&mut segment, &mut out);

    out
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an interceptor at `slot`.
    ///
    /// Call order does not matter: the slot decides the position. A slot holds one interceptor, so
    /// adding a second at the same position replaces the first and says so in the log.
    pub fn with<T: Interceptor + 'static>(mut self, slot: Slot, interceptor: T) -> Self {
        let name = short_type_name::<T>();

        // One interceptor per slot: the map key is the position. Replacing rather than stacking is
        // what a map gives, and it is announced rather than done quietly — an interceptor that
        // vanished because something else claimed its slot is the kind of fault that shows up much
        // later as "the chain does not do what I configured".
        if let Some(displaced) = self.names.insert(slot, name.clone()) {
            warn!("{slot:?} already held {displaced}; {name} replaced it");
        }
        self.interceptors.insert(slot, Box::new(interceptor));
        self
    }

    /// What this registry holds, wire-to-application: each interceptor's slot and its type name,
    /// in the order [`build`](Self::build) will compose them.
    ///
    /// Present so a caller assembling a chain from several helpers can assert what it got. Each
    /// helper places interceptors at its own landmarks and none of them sees the whole, so the
    /// composition is precisely the thing no single helper can check.
    pub fn slots(&self) -> Vec<(Slot, String)> {
        // Already wire-to-application: a `BTreeMap` iterates in key order, and `Slot` orders by
        // position. This is the order `build` will compose them in, for the same reason.
        self.names
            .iter()
            .map(|(slot, name)| (*slot, name.clone()))
            .collect()
    }

    /// Assemble the interceptor chain.
    ///
    /// [`NoopInterceptor`] is appended last, so every chain ends the inbound RTCP path. That is a
    /// property of a chain rather than something a caller opts into: left out, an application would
    /// get a stream of control traffic it never asked for, and the omission would look like working
    /// code.
    ///
    /// What gets past it is decided per packet, by an interceptor attaching
    /// [`Attribute::DeliverToApplication`](crate::Attribute::DeliverToApplication) to the ones it
    /// vouches for — the component that knows which packets an application can act on is the one
    /// that makes the call, rather than a switch here that could only say "all of it or none".
    pub fn build(self) -> impl Interceptor {
        // No sort: a `BTreeMap` is already in key order, and `Slot` orders by distance from the
        // wire, which is the order the chain runs in.
        let mut interceptors: Vec<BoxedInterceptor> = self.interceptors.into_values().collect();

        interceptors.push(Box::new(NoopInterceptor::new()));

        Chain::new(interceptors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StreamInfo;
    use crate::{AttributedPacket, Packet, TaggedPacket};
    use sansio::Protocol;
    use shared::TransportContext;
    use shared::error::Error;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<&'static str>>>);

    struct Marker {
        name: &'static str,
        log: Log,
        read_queue: VecDeque<TaggedPacket>,
        write_queue: VecDeque<TaggedPacket>,
    }

    impl Marker {
        fn new(name: &'static str, log: Log) -> Self {
            Self {
                name,
                log,
                read_queue: VecDeque::new(),
                write_queue: VecDeque::new(),
            }
        }
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for Marker {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.log.0.lock().unwrap().push(self.name);
            self.read_queue.push_back(msg);
            Ok(())
        }

        fn poll_read(&mut self) -> Option<Self::Rout> {
            self.read_queue.pop_front()
        }

        fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.log.0.lock().unwrap().push(self.name);
            self.write_queue.push_back(msg);
            Ok(())
        }

        fn poll_write(&mut self) -> Option<Self::Wout> {
            self.write_queue.pop_front()
        }

        fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_timeout(&mut self) -> Option<Self::Time> {
            None
        }
    }

    impl Interceptor for Marker {
        fn bind_local_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
        fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
    }

    fn packet() -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet::default())),
        }
    }

    fn chain(log: &Log) -> impl Interceptor {
        Registry::new()
            .with(Slot::TwccSender, Marker::new("wire", log.clone()))
            .with(Slot::NackGenerator, Marker::new("middle", log.clone()))
            .with(Slot::JitterBuffer, Marker::new("app", log.clone()))
            .build()
    }

    /// Slots decide the order, not the sequence of calls. Adding application-most first must
    /// compose the same chain as adding wire-most first — the property the helpers in `rtc` rely
    /// on to be callable in any sequence.
    #[test]
    fn call_order_does_not_decide_chain_order() {
        let log = Log::default();
        let mut chain = Registry::new()
            .with(Slot::JitterBuffer, Marker::new("app", log.clone()))
            .with(Slot::TwccSender, Marker::new("wire", log.clone()))
            .with(Slot::NackGenerator, Marker::new("middle", log.clone()))
            .build();

        chain.handle_read(packet()).unwrap();
        while chain.poll_read().is_some() {}

        assert_eq!(vec!["wire", "middle", "app"], *log.0.lock().unwrap());
    }

    /// A slot holds one interceptor: adding a second at the same position replaces the first
    /// rather than stacking with it. Two of your own go at two custom positions, which is what the
    /// thousand-apart spacing leaves room for.
    #[test]
    fn a_slot_holds_one_interceptor() {
        let log = Log::default();
        let mut chain = Registry::new()
            .with(Slot::NackGenerator, Marker::new("first", log.clone()))
            .with(Slot::NackGenerator, Marker::new("second", log.clone()))
            .build();

        chain.handle_read(packet()).unwrap();
        while chain.poll_read().is_some() {}

        assert_eq!(
            vec!["second"],
            *log.0.lock().unwrap(),
            "the later one claimed the slot; the earlier one is not in the chain"
        );
    }

    /// Read runs the list forwards: the first interceptor added is closest to the wire.
    #[test]
    fn read_runs_in_the_order_stages_were_added() {
        let log = Log::default();
        let mut chain = chain(&log);

        chain.handle_read(packet()).unwrap();
        while chain.poll_read().is_some() {}

        assert_eq!(vec!["wire", "middle", "app"], *log.0.lock().unwrap());
    }

    /// Write runs it backwards, so the same list describes both directions.
    #[test]
    fn write_runs_in_reverse() {
        let log = Log::default();
        let mut chain = chain(&log);

        chain.handle_write(packet()).unwrap();
        while chain.poll_write().is_some() {}

        assert_eq!(vec!["app", "middle", "wire"], *log.0.lock().unwrap());
    }

    /// Ending the inbound RTCP path is a property of every chain, not something a caller adds.
    #[test]
    fn a_registry_with_nothing_added_still_has_the_terminus() {
        let mut chain = Registry::new().build();

        chain
            .handle_read(TaggedPacket {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![])),
            })
            .unwrap();
        assert!(
            chain.poll_read().is_none(),
            "inbound RTCP stops before the application"
        );
    }

    /// The terminus goes last, so every interceptor sees inbound RTCP before it is dropped.
    #[test]
    fn the_terminus_is_application_most() {
        let log = Log::default();
        let mut chain = Registry::new()
            .with(Slot::TwccSender, Marker::new("wire", log.clone()))
            .build();

        chain
            .handle_read(TaggedPacket {
                now: Instant::now(),
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![])),
            })
            .unwrap();

        assert_eq!(
            vec!["wire"],
            *log.0.lock().unwrap(),
            "the stage saw the RTCP packet; the terminus dropped it afterwards"
        );
        assert!(chain.poll_read().is_none());
    }

    /// An application's own interceptor goes between two named slots, which is what the spacing is
    /// for: nothing has to be renumbered to make room.
    #[test]
    fn a_custom_slot_sits_where_its_number_says() {
        let log = Log::default();
        let mut chain = Registry::new()
            .with(Slot::FecDecoder, Marker::new("fec", log.clone()))
            .with(Slot::NackGenerator, Marker::new("nack", log.clone()))
            .with(Slot::from(6_500), Marker::new("mine", log.clone()))
            .build();

        chain.handle_read(packet()).unwrap();
        while chain.poll_read().is_some() {}

        assert_eq!(
            vec!["fec", "mine", "nack"],
            *log.0.lock().unwrap(),
            "6_500 belongs after the FEC decoder at 6_000 and before the NACK generator at 7_000"
        );
    }

    /// A custom slot naming a named slot's position *is* that slot. Equality and ordering both come
    /// from the position, and they have to agree: a pair that compares `Equal` must also be `==`,
    /// or a sort or a `BTreeMap` keyed on this behaves differently depending on which spelling the
    /// caller reached for.
    #[test]
    fn equality_and_ordering_both_follow_the_position() {
        assert_eq!(Slot::TwccSender, Slot::from(2_000));
        assert_eq!(
            std::cmp::Ordering::Equal,
            Slot::TwccSender.cmp(&Slot::from(2_000))
        );
        assert!(Slot::from(1_500) > Slot::CongestionControl);
        assert!(Slot::from(1_500) < Slot::TwccSender);
        assert!(
            Slot::from(20_000) > Slot::JitterBuffer,
            "a position past every named slot sorts past them, not by declaration order"
        );
    }

    /// The named slots keep the spacing the doc promises, so `Slot::from` has room to aim at.
    #[test]
    fn the_named_slots_are_spaced_by_a_thousand() {
        let named = [
            Slot::CongestionControl,
            Slot::TwccSender,
            Slot::Pacer,
            Slot::NackResponder,
            Slot::FecEncoder,
            Slot::FecDecoder,
            Slot::NackGenerator,
            Slot::TwccReceiver,
            Slot::Rfc8888,
            Slot::ReceiverReport,
            Slot::SenderReport,
            Slot::IntervalPli,
            Slot::JitterBuffer,
        ];

        for pair in named.windows(2) {
            assert_eq!(
                1_000,
                pair[1].slot() - pair[0].slot(),
                "{:?} and {:?} must stay a thousand apart",
                pair[0],
                pair[1]
            );
        }
    }

    /// A registry records what each interceptor is called, which a chain of trait objects could not
    /// tell you afterwards. It is what makes a composed chain inspectable — several helpers each
    /// place interceptors at their own landmarks, and this is the only view of the result.
    #[test]
    fn slots_carry_the_interceptor_names() {
        let log = Log::default();
        let registry = Registry::new()
            .with(Slot::JitterBuffer, Marker::new("app", log.clone()))
            .with(Slot::TwccSender, crate::TwccSenderBuilder::new().build());

        assert_eq!(
            vec![
                (Slot::TwccSender, "TwccSenderInterceptor".to_owned()),
                (Slot::JitterBuffer, "Marker".to_owned()),
            ],
            registry.slots(),
            "names come back with their slots, sorted wire-to-application"
        );
    }

    /// The module path is dropped: a name is for reading, and the full path is mostly the crate's
    /// own directory layout.
    #[test]
    fn names_are_stripped_of_their_module_path() {
        let registry = Registry::new().with(
            Slot::CongestionControl,
            crate::CongestionControlBuilder::new(crate::ConstantBitrate::new(1_000_000.0)).build(),
        );

        let (_, name) = &registry.slots()[0];
        assert!(
            !name.contains("::"),
            "a module path leaked into the name: {name}"
        );
        assert_eq!(
            "CongestionControlInterceptor<ConstantBitrate>", name,
            "the generic argument is shortened too, and kept — it is what tells two \
             congestion controllers apart"
        );
    }
}
