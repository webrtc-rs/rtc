#![allow(dead_code)]

use std::io;
use std::net;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    #[error("buffer: full")]
    ErrBufferFull,
    #[error("buffer: closed")]
    ErrBufferClosed,
    #[error("buffer: short")]
    ErrBufferShort,
    #[error("packet too big")]
    ErrPacketTooBig,
    #[error("i/o timeout")]
    ErrTimeout,
    #[error("udp: listener closed")]
    ErrClosedListener,
    #[error("udp: listen queue exceeded")]
    ErrListenQueueExceeded,
    #[error("udp: listener accept ch closed")]
    ErrClosedListenerAcceptCh,
    #[error("obs cannot be nil")]
    ErrObsCannotBeNil,
    #[error("se of closed network connection")]
    ErrUseClosedNetworkConn,
    #[error("addr is not a net.UDPAddr")]
    ErrAddrNotUdpAddr,
    #[error("something went wrong with locAddr")]
    ErrLocAddr,
    #[error("already closed")]
    ErrAlreadyClosed,
    #[error("no remAddr defined")]
    ErrNoRemAddr,
    #[error("address already in use")]
    ErrAddressAlreadyInUse,
    #[error("no such UDPConn")]
    ErrNoSuchUdpConn,
    #[error("cannot remove unspecified IP by the specified IP")]
    ErrCannotRemoveUnspecifiedIp,
    #[error("no address assigned")]
    ErrNoAddressAssigned,
    #[error("1:1 NAT requires more than one mapping")]
    ErrNatRequriesMapping,
    #[error("length mismtach between mappedIPs and localIPs")]
    ErrMismatchLengthIp,
    #[error("non-udp translation is not supported yet")]
    ErrNonUdpTranslationNotSupported,
    #[error("no associated local address")]
    ErrNoAssociatedLocalAddress,
    #[error("no NAT binding found")]
    ErrNoNatBindingFound,
    #[error("has no permission")]
    ErrHasNoPermission,
    #[error("host name must not be empty")]
    ErrHostnameEmpty,
    #[error("failed to parse IP address")]
    ErrFailedToParseIpaddr,
    #[error("no interface is available")]
    ErrNoInterface,
    #[error("not found")]
    ErrNotFound,
    #[error("unexpected network")]
    ErrUnexpectedNetwork,
    #[error("can't assign requested address")]
    ErrCantAssignRequestedAddr,
    #[error("unknown network")]
    ErrUnknownNetwork,
    #[error("no router linked")]
    ErrNoRouterLinked,
    #[error("invalid port number")]
    ErrInvalidPortNumber,
    #[error("unexpected type-switch failure")]
    ErrUnexpectedTypeSwitchFailure,
    #[error("bind failed")]
    ErrBindFailed,
    #[error("end port is less than the start")]
    ErrEndPortLessThanStart,
    #[error("port space exhausted")]
    ErrPortSpaceExhausted,
    #[error("vnet is not enabled")]
    ErrVnetDisabled,
    #[error("invalid local IP in static_ips")]
    ErrInvalidLocalIpInStaticIps,
    #[error("mapped in static_ips is beyond subnet")]
    ErrLocalIpBeyondStaticIpsSubset,
    #[error("all static_ips must have associated local IPs")]
    ErrLocalIpNoStaticsIpsAssociated,
    #[error("router already started")]
    ErrRouterAlreadyStarted,
    #[error("router already stopped")]
    ErrRouterAlreadyStopped,
    #[error("static IP is beyond subnet")]
    ErrStaticIpIsBeyondSubnet,
    #[error("address space exhausted")]
    ErrAddressSpaceExhausted,
    #[error("no IP address is assigned for eth0")]
    ErrNoIpaddrEth0,
    #[error("Invalid mask")]
    ErrInvalidMask,

    //ExportKeyingMaterial errors
    #[error("tls handshake is in progress")]
    HandshakeInProgress,
    #[error("context is not supported for export_keying_material")]
    ContextUnsupported,
    #[error("export_keying_material can not be used with a reserved label")]
    ReservedExportKeyingMaterial,
    #[error("no cipher suite for export_keying_material")]
    CipherSuiteUnset,
    #[error("export_keying_material hash: {0}")]
    Hash(String),
    #[error("mutex poison: {0}")]
    PoisonError(String),

    //RTCP errors
    /// Wrong marshal size.
    #[error("Wrong marshal size")]
    WrongMarshalSize,
    /// Packet lost exceeds maximum amount of packets
    /// that can possibly be lost.
    #[error("Invalid total lost count")]
    InvalidTotalLost,
    /// Packet contains an invalid header.
    #[error("Invalid header")]
    InvalidHeader,
    /// Packet contains empty compound.
    #[error("Empty compound packet")]
    EmptyCompound,
    /// Invalid first packet in compound packets. First packet
    /// should either be a SenderReport packet or ReceiverReport
    #[error("First packet in compound must be SR or RR")]
    BadFirstPacket,
    /// CNAME was not defined.
    #[error("Compound missing SourceDescription with CNAME")]
    MissingCname,
    /// Packet was defined before CNAME.
    #[error("Feedback packet seen before CNAME")]
    PacketBeforeCname,
    /// Too many reports.
    #[error("Too many reports")]
    TooManyReports,
    /// Too many chunks.
    #[error("Too many chunks")]
    TooManyChunks,
    /// Too many sources.
    #[error("too many sources")]
    TooManySources,
    /// Packet received is too short.
    #[error("Packet status chunk must be 2 bytes")]
    PacketTooShort,
    /// Buffer is too short.
    #[error("Buffer too short to be written")]
    BufferTooShort,
    /// Wrong packet type.
    #[error("Wrong packet type")]
    WrongType,
    /// SDES received is too long.
    #[error("SDES must be < 255 octets long")]
    SdesTextTooLong,
    /// SDES type is missing.
    #[error("SDES item missing type")]
    SdesMissingType,
    /// Reason is too long.
    #[error("Reason must be < 255 octets long")]
    ReasonTooLong,
    /// Invalid packet version.
    #[error("Invalid packet version")]
    BadVersion,
    /// Invalid padding value.
    #[error("Invalid padding value")]
    WrongPadding,
    /// Wrong feedback message type.
    #[error("Wrong feedback message type")]
    WrongFeedbackType,
    /// Wrong payload type.
    #[error("Wrong payload type")]
    WrongPayloadType,
    /// Header length is too small.
    #[error("Header length is too small")]
    HeaderTooSmall,
    /// Media ssrc was defined as zero.
    #[error("Media SSRC must be 0")]
    SsrcMustBeZero,
    /// Missing REMB identifier.
    #[error("Missing REMB identifier")]
    MissingRembIdentifier,
    /// SSRC number and length mismatches.
    #[error("SSRC num and length do not match")]
    SsrcNumAndLengthMismatch,
    /// Invalid size or start index.
    #[error("Invalid size or startIndex")]
    InvalidSizeOrStartIndex,
    /// Delta exceeds limit.
    #[error("Delta exceed limit")]
    DeltaExceedLimit,
    /// Packet status chunk is not 2 bytes.
    #[error("Packet status chunk must be 2 bytes")]
    PacketStatusChunkLength,
    #[error("Invalid bitrate")]
    InvalidBitrate,
    #[error("Wrong chunk type")]
    WrongChunkType,
    #[error("Struct contains unexpected member type")]
    BadStructMemberType,
    #[error("Cannot read into non-pointer")]
    BadReadParameter,

    //RTP errors
    #[error("RTP header size insufficient")]
    ErrHeaderSizeInsufficient,
    #[error("RTP header size insufficient for extension")]
    ErrHeaderSizeInsufficientForExtension,
    #[error("buffer too small")]
    ErrBufferTooSmall,
    #[error("extension not enabled")]
    ErrHeaderExtensionsNotEnabled,
    #[error("extension not found")]
    ErrHeaderExtensionNotFound,

    #[error("header extension id must be between 1 and 14 for RFC 5285 extensions")]
    ErrRfc8285oneByteHeaderIdrange,
    #[error("header extension payload must be 16bytes or less for RFC 5285 one byte extensions")]
    ErrRfc8285oneByteHeaderSize,

    #[error("header extension id must be between 1 and 255 for RFC 5285 extensions")]
    ErrRfc8285twoByteHeaderIdrange,
    #[error("header extension payload must be 255bytes or less for RFC 5285 two byte extensions")]
    ErrRfc8285twoByteHeaderSize,

    #[error("header extension id must be 0 for none RFC 5285 extensions")]
    ErrRfc3550headerIdrange,

    #[error("packet is not large enough")]
    ErrShortPacket,
    #[error("invalid nil packet")]
    ErrNilPacket,
    #[error("too many PDiff")]
    ErrTooManyPDiff,
    #[error("too many spatial layers")]
    ErrTooManySpatialLayers,
    #[error("NALU Type is unhandled")]
    ErrUnhandledNaluType,

    #[error("corrupted h265 packet")]
    ErrH265CorruptedPacket,
    #[error("invalid h265 packet type")]
    ErrInvalidH265PacketType,

    #[error("extension_payload must be in 32-bit words")]
    HeaderExtensionPayloadNot32BitWords,
    #[error("audio level overflow")]
    AudioLevelOverflow,
    #[error("payload is not large enough")]
    PayloadIsNotLargeEnough,
    #[error("STAP-A declared size({0}) is larger than buffer({1})")]
    StapASizeLargerThanBuffer(usize, usize),
    #[error("nalu type {0} is currently not handled")]
    NaluTypeIsNotHandled(u8),

    //SRTP
    #[error("duplicated packet")]
    ErrDuplicated,
    #[error("SRTP master key is not long enough")]
    ErrShortSrtpMasterKey,
    #[error("SRTP master salt is not long enough")]
    ErrShortSrtpMasterSalt,
    #[error("no such SRTP Profile")]
    ErrNoSuchSrtpProfile,
    #[error("indexOverKdr > 0 is not supported yet")]
    ErrNonZeroKdrNotSupported,
    #[error("exporter called with wrong label")]
    ErrExporterWrongLabel,
    #[error("no config provided")]
    ErrNoConfig,
    #[error("no conn provided")]
    ErrNoConn,
    #[error("failed to verify auth tag")]
    ErrFailedToVerifyAuthTag,
    #[error("packet is too short to be rtcp packet")]
    ErrTooShortRtcp,
    #[error("payload differs")]
    ErrPayloadDiffers,
    #[error("started channel used incorrectly, should only be closed")]
    ErrStartedChannelUsedIncorrectly,
    #[error("stream has not been inited, unable to close")]
    ErrStreamNotInited,
    #[error("stream is already closed")]
    ErrStreamAlreadyClosed,
    #[error("stream is already inited")]
    ErrStreamAlreadyInited,
    #[error("failed to cast child")]
    ErrFailedTypeAssertion,

    #[error("index_over_kdr > 0 is not supported yet")]
    UnsupportedIndexOverKdr,
    #[error("SRTP Master Key must be len {0}, got {1}")]
    SrtpMasterKeyLength(usize, usize),
    #[error("SRTP Salt must be len {0}, got {1}")]
    SrtpSaltLength(usize, usize),
    #[error("SyntaxError: {0}")]
    ExtMapParse(String),
    #[error("ssrc {0} not exist in srtp_ssrc_state")]
    SsrcMissingFromSrtp(u32),
    #[error("srtp ssrc={0} index={1}: duplicated")]
    SrtpSsrcDuplicated(u32, u16),
    #[error("srtcp ssrc={0} index={1}: duplicated")]
    SrtcpSsrcDuplicated(u32, usize),
    #[error("ssrc {0} not exist in srtcp_ssrc_state")]
    SsrcMissingFromSrtcp(u32),
    #[error("Stream with ssrc {0} exists")]
    StreamWithSsrcExists(u32),
    #[error("Session RTP/RTCP type must be same as input buffer")]
    SessionRtpRtcpTypeMismatch,
    #[error("Session EOF")]
    SessionEof,
    #[error("too short SRTP packet: only {0} bytes, expected > {1} bytes")]
    SrtpTooSmall(usize, usize),
    #[error("too short SRTCP packet: only {0} bytes, expected > {1} bytes")]
    SrtcpTooSmall(usize, usize),
    #[error("failed to verify rtp auth tag")]
    RtpFailedToVerifyAuthTag,
    #[error("failed to verify rtcp auth tag")]
    RtcpFailedToVerifyAuthTag,
    #[error("SessionSRTP has been closed")]
    SessionSrtpAlreadyClosed,
    #[error("this stream is not a RTPStream")]
    InvalidRtpStream,
    #[error("this stream is not a RTCPStream")]
    InvalidRtcpStream,

    //#[error("mpsc send: {0}")]
    //MpscSend(String),
    #[error("aes gcm: {0}")]
    AesGcm(#[from] aes_gcm::Error),

    //#[error("parse ipnet: {0}")]
    //ParseIpnet(#[from] ipnet::AddrParseError),
    #[error("parse ip: {0}")]
    ParseIp(#[from] net::AddrParseError),
    #[error("parse int: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("{0}")]
    Io(#[source] IoError),
    #[error("utf8: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("{0}")]
    Std(#[source] StdError),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn from_std<T>(error: T) -> Self
    where
        T: std::error::Error + Send + Sync + 'static,
    {
        Error::Std(StdError(Box::new(error)))
    }

    pub fn downcast_ref<T: std::error::Error + 'static>(&self) -> Option<&T> {
        if let Error::Std(s) = self {
            return s.0.downcast_ref();
        }

        None
    }
}

#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(IoError(e))
    }
}

/// An escape hatch to preserve stack traces when we don't know the error.
///
/// This crate exports some traits such as `Conn` and `Listener`. The trait functions
/// produce the local error `util::Error`. However when used in crates higher up the stack,
/// we are forced to handle errors that are local to that crate. For example we use
/// `Listener` the `dtls` crate and it needs to handle `dtls::Error`.
///
/// By using `util::Error::from_std` we can preserve the underlying error (and stack trace!).
#[derive(Debug, Error)]
#[error("{0}")]
pub struct StdError(pub Box<dyn std::error::Error + Send + Sync>);

impl PartialEq for StdError {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        Error::PoisonError(e.to_string())
    }
}
