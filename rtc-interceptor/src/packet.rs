use shared::TransportMessage;
use std::any::Any;
use std::sync::Arc;

/// RTP/RTCP Packet
///
/// An enum representing either an RTP or RTCP packet that can be processed
/// by interceptors in the chain.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Packet {
    /// RTP (Real-time Transport Protocol) packet containing media data
    Rtp(rtp::Packet),
    /// RTCP (RTP Control Protocol) packets for feedback and statistics
    Rtcp(Vec<Box<dyn rtcp::Packet>>),
}

/// A fact about a packet, attached by one interceptor and readable by the rest.
///
/// # Why it rides with the packet
///
/// Because it has to survive the journey. An interceptor that queues a packet and emits it later
/// puts it back on the belt *behind* itself, where every interceptor ahead sees it again — so what
/// was learned about that packet has to travel with it or be worked out twice. A side channel
/// cannot manage that: it has no way to say *which* packet it refers to once the packet has been
/// held, reordered or duplicated.
///
/// With `Ein`/`Eout` left as `()`, this is the only way information crosses interceptors.
///
/// # Cost
///
/// [`AttributedPacket`] holds a `Vec`, which does not allocate while empty — and most packets carry
/// nothing. Lookup is a linear scan of a handful of words, cheaper than hashing.
#[derive(Clone)]
#[non_exhaustive]
pub enum Attribute {
    /// Rebuilt by FEC rather than received: these bytes never arrived on the wire.
    ///
    /// A NACK generator that sees this must not ask for the packet again.
    RecoveredByFec,

    /// A retransmission answering a NACK, not a first transmission.
    ///
    /// Still new bytes on the wire, which is why a send history has to count it — counting it as
    /// an original tells a bandwidth estimator the path is carrying less than it is.
    Retransmission,

    /// Inbound RTCP an interceptor has decided the application should see.
    ///
    /// [`NoopInterceptor`](crate::NoopInterceptor) ends the inbound RTCP path unless the packet
    /// carries this, which makes forwarding a per-packet judgement by whichever interceptor is
    /// qualified to make it, rather than a chain-wide setting.
    DeliverToApplication,

    /// The congestion controller's estimate, in bits per second.
    ///
    /// Rides outbound so the pacer reads it on the way past. A bitrate is connection state rather
    /// than a property of the packet carrying it — it travels this way because with no event
    /// channel there is nowhere else for it to go.
    TargetBitrateChanged {
        /// The new target, in bits per second.
        bits_per_second: f64,
    },

    /// Ask the keyframe generator to send a Picture Loss Indication now.
    ForcePli {
        /// Which streams to request a keyframe for, or `None` for all of them.
        ssrcs: Option<Vec<u32>>,
    },

    /// Anything an application defines, so this enum is never a bottleneck on it.
    ///
    /// `Arc` rather than `Box` so an attributed packet stays cheap to clone — the NACK responder
    /// clones into its send buffer and the FEC encoder into its block, and neither should deep-copy
    /// an application's payload. Reached by type: [`AttributedPacket::custom`].
    Custom(Arc<dyn Any + Send + Sync>),
}

impl std::fmt::Debug for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RecoveredByFec => f.write_str("RecoveredByFec"),
            Self::Retransmission => f.write_str("Retransmission"),
            Self::DeliverToApplication => f.write_str("DeliverToApplication"),
            Self::TargetBitrateChanged { bits_per_second } => f
                .debug_struct("TargetBitrateChanged")
                .field("bits_per_second", bits_per_second)
                .finish(),
            Self::ForcePli { ssrcs } => f.debug_struct("ForcePli").field("ssrcs", ssrcs).finish(),
            // The payload is `dyn Any`, which is not `Debug`.
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

/// A packet together with what the interceptors have learned about it.
#[derive(Clone, Debug)]
pub struct AttributedPacket {
    /// What the interceptors have attached on the way, in the order they attached it.
    pub attributes: Vec<Attribute>,
    /// The packet itself.
    pub packet: Packet,
}

impl AttributedPacket {
    /// A packet with nothing attached.
    pub fn new(packet: Packet) -> Self {
        Self {
            attributes: Vec::new(),
            packet,
        }
    }
    /// Attach `attribute`, taking ownership — for building a packet in one expression.
    pub fn with(mut self, attribute: Attribute) -> Self {
        self.attributes.push(attribute);
        self
    }
    /// Attach `attribute`.
    ///
    /// Attaching the same one twice is allowed and means nothing extra; [`has`](Self::has) answers
    /// the only question anyone asks of it.
    pub fn add(&mut self, attribute: Attribute) -> &mut Self {
        self.attributes.push(attribute);
        self
    }

    /// Whether this packet carries `attribute`.
    ///
    /// Compares by variant, not by value, so `has(&Attribute::TargetBitrateChanged { .. })` finds
    /// one whatever the rate is, and [`Attribute::Custom`] never satisfies a query for a built-in.
    pub fn has(&self, attribute: &Attribute) -> bool {
        let wanted = std::mem::discriminant(attribute);
        self.attributes
            .iter()
            .any(|held| std::mem::discriminant(held) == wanted)
    }

    /// The first attribute matching `attribute`'s variant, for reading a value out of it.
    pub fn get(&self, attribute: &Attribute) -> Option<&Attribute> {
        let wanted = std::mem::discriminant(attribute);
        self.attributes
            .iter()
            .find(|held| std::mem::discriminant(*held) == wanted)
    }

    /// The first [`Attribute::Custom`] payload of type `T`, if this packet carries one.
    pub fn custom<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.attributes
            .iter()
            .find_map(|attribute| match attribute {
                Attribute::Custom(value) => value.downcast_ref::<T>(),
                _ => None,
            })
    }
}

impl From<Packet> for AttributedPacket {
    fn from(packet: Packet) -> Self {
        Self::new(packet)
    }
}

/// Tagged packet with transport metadata.
///
/// A [`TransportMessage`] wrapping a [`Packet`], which includes transport-level
/// context such as source/destination addresses and protocol information.
/// This is the primary message type passed through interceptor chains.
pub type TaggedPacket = TransportMessage<AttributedPacket>;
