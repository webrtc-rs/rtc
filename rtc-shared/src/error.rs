#![allow(dead_code)]

use std::io;
use std::net;
use std::net::SocketAddr;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;
use substring::Substring;
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
    #[error("Packet too short to be read")]
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
    #[error("Invalid block size")]
    InvalidBlockSize,

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

    #[error("payload is too small for OBU extension header")]
    ErrPayloadTooSmallForObuExtensionHeader,
    #[error("payload is too small for OBU payload size")]
    ErrPayloadTooSmallForObuPayloadSize,

    #[error("extension_payload must be in 32-bit words")]
    HeaderExtensionPayloadNot32BitWords,
    #[error("audio level overflow")]
    AudioLevelOverflow,
    #[error("playout delay overflow")]
    PlayoutDelayOverflow,
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
    #[error("packet is too short to be RTP packet")]
    ErrTooShortRtp,
    #[error("packet is too short to be RTCP packet")]
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
    #[error("exceeded the maximum number of packets")]
    ErrExceededMaxPackets,

    #[error("index_over_kdr > 0 is not supported yet")]
    UnsupportedIndexOverKdr,
    #[error("invalid master key length for aes_256_cm")]
    InvalidMasterKeyLength,
    #[error("invalid master salt length for aes_256_cm")]
    InvalidMasterSaltLength,
    #[error("out_len > 32 is not supported for aes_256_cm")]
    UnsupportedOutLength,
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
    #[error("too short auth tag: only {0} bytes, expected > {1} bytes")]
    RtcpInvalidLengthAuthTag(usize, usize),
    #[error("failed to verify rtcp auth tag")]
    RtcpFailedToVerifyAuthTag,
    #[error("SessionSRTP has been closed")]
    SessionSrtpAlreadyClosed,
    #[error("this stream is not a RTPStream")]
    InvalidRtpStream,
    #[error("this stream is not a RTCPStream")]
    InvalidRtcpStream,

    //STUN errors
    #[error("attribute not found")]
    ErrAttributeNotFound,
    #[error("transaction is stopped")]
    ErrTransactionStopped,
    #[error("transaction not exists")]
    ErrTransactionNotExists,
    #[error("transaction exists with same id")]
    ErrTransactionExists,
    #[error("agent is closed")]
    ErrAgentClosed,
    #[error("transaction is timed out")]
    ErrTransactionTimeOut,
    #[error("no default reason for ErrorCode")]
    ErrNoDefaultReason,
    #[error("unexpected EOF")]
    ErrUnexpectedEof,
    #[error("attribute size is invalid")]
    ErrAttributeSizeInvalid,
    #[error("attribute size overflow")]
    ErrAttributeSizeOverflow,
    #[error("attempt to decode to nil message")]
    ErrDecodeToNil,
    #[error("unexpected EOF: not enough bytes to read header")]
    ErrUnexpectedHeaderEof,
    #[error("integrity check failed")]
    ErrIntegrityMismatch,
    #[error("fingerprint check failed")]
    ErrFingerprintMismatch,
    #[error("FINGERPRINT before MESSAGE-INTEGRITY attribute")]
    ErrFingerprintBeforeIntegrity,
    #[error("bad UNKNOWN-ATTRIBUTES size")]
    ErrBadUnknownAttrsSize,
    #[error("invalid length of IP value")]
    ErrBadIpLength,
    #[error("no connection provided")]
    ErrNoConnection,
    #[error("client is closed")]
    ErrClientClosed,
    #[error("no agent is set")]
    ErrNoAgent,
    #[error("collector is closed")]
    ErrCollectorClosed,
    #[error("unsupported network")]
    ErrUnsupportedNetwork,
    #[error("invalid url")]
    ErrInvalidUrl,
    #[error("unknown scheme type")]
    ErrSchemeType,
    #[error("invalid hostname")]
    ErrHost,

    // TURN errors
    #[error("turn: RelayAddress must be valid IP to use RelayAddressGeneratorStatic")]
    ErrRelayAddressInvalid,
    #[error("turn: PacketConnConfigs and ConnConfigs are empty, unable to proceed")]
    ErrNoAvailableConns,
    #[error("turn: PacketConnConfig must have a non-nil Conn")]
    ErrConnUnset,
    #[error("turn: ListenerConfig must have a non-nil Listener")]
    ErrListenerUnset,
    #[error("turn: RelayAddressGenerator has invalid ListeningAddress")]
    ErrListeningAddressInvalid,
    #[error("turn: RelayAddressGenerator in RelayConfig is unset")]
    ErrRelayAddressGeneratorUnset,
    #[error("turn: max retries exceeded")]
    ErrMaxRetriesExceeded,
    #[error("turn: MaxPort must be not 0")]
    ErrMaxPortNotZero,
    #[error("turn: MaxPort must be not 0")]
    ErrMinPortNotZero,
    #[error("turn: MaxPort less than MinPort")]
    ErrMaxPortLessThanMinPort,
    #[error("turn: relay_conn cannot not be nil")]
    ErrNilConn,
    #[error("turn: TODO")]
    ErrTodo,
    #[error("turn: already listening")]
    ErrAlreadyListening,
    #[error("turn: Server failed to close")]
    ErrFailedToClose,
    #[error("turn: failed to retransmit transaction")]
    ErrFailedToRetransmitTransaction,
    #[error("all retransmissions failed")]
    ErrAllRetransmissionsFailed,
    #[error("no binding found for channel")]
    ErrChannelBindNotFound,
    #[error("STUN server address is not set for the client")]
    ErrStunserverAddressNotSet,
    #[error("only one Allocate() caller is allowed")]
    ErrOneAllocateOnly,
    #[error("already allocated")]
    ErrAlreadyAllocated,
    #[error("non-STUN message from STUN server")]
    ErrNonStunmessage,
    #[error("failed to decode STUN message")]
    ErrFailedToDecodeStun,
    #[error("unexpected STUN request message")]
    ErrUnexpectedStunrequestMessage,
    #[error("channel number not in [0x4000, 0x7FFF]")]
    ErrInvalidChannelNumber,
    #[error("channelData length != len(Data)")]
    ErrBadChannelDataLength,
    #[error("invalid value for requested family attribute")]
    ErrInvalidRequestedFamilyValue,
    #[error("fake error")]
    ErrFakeErr,
    #[error("use of closed network connection")]
    ErrClosed,
    #[error("addr is not a net.UDPAddr")]
    ErrUdpaddrCast,
    #[error("try-lock is already locked")]
    ErrDoubleLock,
    #[error("transaction closed")]
    ErrTransactionClosed,
    #[error("wait_for_result called on non-result transaction")]
    ErrWaitForResultOnNonResultTransaction,
    #[error("failed to build refresh request")]
    ErrFailedToBuildRefreshRequest,
    #[error("failed to refresh allocation")]
    ErrFailedToRefreshAllocation,
    #[error("failed to get lifetime from refresh response")]
    ErrFailedToGetLifetime,
    #[error("too short buffer")]
    ErrShortBuffer,
    #[error("unexpected response type")]
    ErrUnexpectedResponse,
    #[error("AllocatePacketConn must be set")]
    ErrAllocatePacketConnMustBeSet,
    #[error("AllocateConn must be set")]
    ErrAllocateConnMustBeSet,
    #[error("LeveledLogger must be set")]
    ErrLeveledLoggerMustBeSet,
    #[error("you cannot use the same channel number with different peer")]
    ErrSameChannelDifferentPeer,
    #[error("allocations must not be created with nil FivTuple")]
    ErrNilFiveTuple,
    #[error("allocations must not be created with nil FiveTuple.src_addr")]
    ErrNilFiveTupleSrcAddr,
    #[error("allocations must not be created with nil FiveTuple.dst_addr")]
    ErrNilFiveTupleDstAddr,
    #[error("allocations must not be created with nil turnSocket")]
    ErrNilTurnSocket,
    #[error("allocations must not be created with a lifetime of 0")]
    ErrLifetimeZero,
    #[error("allocation attempt created with duplicate FiveTuple")]
    ErrDupeFiveTuple,
    #[error("failed to cast net.Addr to *net.UDPAddr")]
    ErrFailedToCastUdpaddr,
    #[error("failed to generate nonce")]
    ErrFailedToGenerateNonce,
    #[error("failed to send error message")]
    ErrFailedToSendError,
    #[error("duplicated Nonce generated, discarding request")]
    ErrDuplicatedNonce,
    #[error("no such user exists")]
    ErrNoSuchUser,
    #[error("unexpected class")]
    ErrUnexpectedClass,
    #[error("unexpected method")]
    ErrUnexpectedMethod,
    #[error("failed to handle")]
    ErrFailedToHandle,
    #[error("unhandled STUN packet")]
    ErrUnhandledStunpacket,
    #[error("unable to handle ChannelData")]
    ErrUnableToHandleChannelData,
    #[error("failed to create stun message from packet")]
    ErrFailedToCreateStunpacket,
    #[error("failed to create channel data from packet")]
    ErrFailedToCreateChannelData,
    #[error("relay already allocated for 5-TUPLE")]
    ErrRelayAlreadyAllocatedForFiveTuple,
    #[error("RequestedTransport must be UDP")]
    ErrRequestedTransportMustBeUdp,
    #[error("no support for DONT-FRAGMENT")]
    ErrNoDontFragmentSupport,
    #[error("Request must not contain RESERVATION-TOKEN and EVEN-PORT")]
    ErrRequestWithReservationTokenAndEvenPort,
    #[error("no allocation found")]
    ErrNoAllocationFound,
    #[error("unable to handle send-indication, no permission added")]
    ErrNoPermission,
    #[error("packet write smaller than packet")]
    ErrShortWrite,
    #[error("no such channel bind")]
    ErrNoSuchChannelBind,
    #[error("failed writing to socket")]
    ErrFailedWriteSocket,

    // ICE errors
    /// Indicates an error with Unknown info.
    #[error("Unknown type")]
    ErrUnknownType,

    /// Indicates query arguments are provided in a STUN URL.
    #[error("queries not supported in stun address")]
    ErrStunQuery,

    /// Indicates an malformed query is provided.
    #[error("invalid query")]
    ErrInvalidQuery,

    /// Indicates malformed port is provided.
    #[error("url parse: invalid port number")]
    ErrPort,

    /// Indicates local username fragment insufficient bits are provided.
    /// Have to be at least 24 bits long.
    #[error("local username fragment is less than 24 bits long")]
    ErrLocalUfragInsufficientBits,

    /// Indicates local passoword insufficient bits are provided.
    /// Have to be at least 128 bits long.
    #[error("local password is less than 128 bits long")]
    ErrLocalPwdInsufficientBits,

    /// Indicates an unsupported transport type was provided.
    #[error("invalid transport protocol type")]
    ErrProtoType,

    /// Indicates agent does not have a valid candidate pair.
    #[error("no candidate pairs available")]
    ErrNoCandidatePairs,

    /// Indicates agent connection was canceled by the caller.
    #[error("connecting canceled by caller")]
    ErrCanceledByCaller,

    /// Indicates agent was started twice.
    #[error("attempted to start agent twice")]
    ErrMultipleStart,

    /// Indicates agent was started with an empty remote ufrag.
    #[error("remote ufrag is empty")]
    ErrRemoteUfragEmpty,

    /// Indicates agent was started with an empty remote pwd.
    #[error("remote pwd is empty")]
    ErrRemotePwdEmpty,

    /// Indicates agent was started without on_candidate.
    #[error("no on_candidate provided")]
    ErrNoOnCandidateHandler,

    /// Indicates GatherCandidates has been called multiple times.
    #[error("attempting to gather candidates during gathering state")]
    ErrMultipleGatherAttempted,

    /// Indicates agent was give TURN URL with an empty Username.
    #[error("username is empty")]
    ErrUsernameEmpty,

    /// Indicates agent was give TURN URL with an empty Password.
    #[error("password is empty")]
    ErrPasswordEmpty,

    /// Indicates we were unable to parse a candidate address.
    #[error("failed to parse address")]
    ErrAddressParseFailed,

    /// Indicates that non host candidates were selected for a lite agent.
    #[error("lite agents must only use host candidates")]
    ErrLiteUsingNonHostCandidates,

    /// Indicates that current ice agent supports Lite only
    #[error("lite support only")]
    ErrLiteSupportOnly,

    /// Indicates that one or more URL was provided to the agent but no host candidate required them.
    #[error("agent does not need URL with selected candidate types")]
    ErrUselessUrlsProvided,

    /// Indicates that the specified NAT1To1IPCandidateType is unsupported.
    #[error("unsupported 1:1 NAT IP candidate type")]
    ErrUnsupportedNat1to1IpCandidateType,

    /// Indicates that the given 1:1 NAT IP mapping is invalid.
    #[error("invalid 1:1 NAT IP mapping")]
    ErrInvalidNat1to1IpMapping,

    /// IPNotFound in NAT1To1IPMapping.
    #[error("external mapped IP not found")]
    ErrExternalMappedIpNotFound,

    /// Indicates that the mDNS gathering cannot be used along with 1:1 NAT IP mapping for host
    /// candidate.
    #[error("mDNS gathering cannot be used with 1:1 NAT IP mapping for host candidate")]
    ErrMulticastDnsWithNat1to1IpMapping,

    /// Indicates that 1:1 NAT IP mapping for host candidate is requested, but the host candidate
    /// type is disabled.
    #[error("1:1 NAT IP mapping for host candidate ineffective")]
    ErrIneffectiveNat1to1IpMappingHost,

    /// Indicates that 1:1 NAT IP mapping for srflx candidate is requested, but the srflx candidate
    /// type is disabled.
    #[error("1:1 NAT IP mapping for srflx candidate ineffective")]
    ErrIneffectiveNat1to1IpMappingSrflx,

    /// Indicates an invalid MulticastDNSHostName.
    #[error("invalid mDNS HostName, must end with .local and can only contain a single '.'")]
    ErrInvalidMulticastDnshostName,

    /// Indicates mdns is not supported.
    #[error("mdns is not supported")]
    ErrMulticastDnsNotSupported,

    /// Indicates Restart was called when Agent is in GatheringStateGathering.
    #[error("ICE Agent can not be restarted when gathering")]
    ErrRestartWhenGathering,

    /// Indicates a run operation was canceled by its individual done.
    #[error("run was canceled by done")]
    ErrRunCanceled,

    /// Initialized Indicates TCPMux is not initialized and that invalidTCPMux is used.
    #[error("TCPMux is not initialized")]
    ErrTcpMuxNotInitialized,

    /// Indicates we already have the connection with same remote addr.
    #[error("conn with same remote addr already exists")]
    ErrTcpRemoteAddrAlreadyExists,

    #[error("failed to send packet")]
    ErrSendPacket,
    #[error("attribute not long enough to be ICE candidate")]
    ErrAttributeTooShortIceCandidate,
    #[error("could not parse component")]
    ErrParseComponent,
    #[error("could not parse priority")]
    ErrParsePriority,
    #[error("could not parse port")]
    ErrParsePort,
    #[error("could not parse related addresses")]
    ErrParseRelatedAddr,
    #[error("could not parse type")]
    ErrParseType,
    #[error("unknown candidate type")]
    ErrUnknownCandidateType,
    #[error("failed to get XOR-MAPPED-ADDRESS response")]
    ErrGetXorMappedAddrResponse,
    #[error("connection with same remote address already exists")]
    ErrConnectionAddrAlreadyExist,
    #[error("error reading streaming packet")]
    ErrReadingStreamingPacket,
    #[error("error writing to")]
    ErrWriting,
    #[error("error closing connection")]
    ErrClosingConnection,
    #[error("unable to determine networkType")]
    ErrDetermineNetworkType,
    #[error("missing protocol scheme")]
    ErrMissingProtocolScheme,
    #[error("too many colons in address")]
    ErrTooManyColonsAddr,
    #[error("unexpected error trying to read")]
    ErrRead,
    #[error("unknown role")]
    ErrUnknownRole,
    #[error("username mismatch")]
    ErrMismatchUsername,
    #[error("the ICE conn can't write STUN messages")]
    ErrIceWriteStunMessage,
    #[error("url parse: relative URL without a base")]
    ErrUrlParse,
    #[error("Candidate IP could not be found")]
    ErrCandidateIpNotFound,

    // DTLS errors
    #[error("conn is closed")]
    ErrConnClosed,
    #[error("read/write timeout")]
    ErrDeadlineExceeded,
    #[error("context is not supported for export_keying_material")]
    ErrContextUnsupported,
    #[error("packet is too short")]
    ErrDtlspacketInvalidLength,
    #[error("handshake is in progress")]
    ErrHandshakeInProgress,
    #[error("invalid content type")]
    ErrInvalidContentType,
    #[error("invalid mac")]
    ErrInvalidMac,
    #[error("packet length and declared length do not match")]
    ErrInvalidPacketLength,
    #[error("export_keying_material can not be used with a reserved label")]
    ErrReservedExportKeyingMaterial,
    #[error("client sent certificate verify but we have no certificate to verify")]
    ErrCertificateVerifyNoCertificate,
    #[error("client+server do not support any shared cipher suites")]
    ErrCipherSuiteNoIntersection,
    #[error("server hello can not be created without a cipher suite")]
    ErrCipherSuiteUnset,
    #[error("client sent certificate but did not verify it")]
    ErrClientCertificateNotVerified,
    #[error("server required client verification, but got none")]
    ErrClientCertificateRequired,
    #[error("server responded with SRTP Profile we do not support")]
    ErrClientNoMatchingSrtpProfile,
    #[error("client required Extended Master Secret extension, but server does not support it")]
    ErrClientRequiredButNoServerEms,
    #[error("server hello can not be created without a compression method")]
    ErrCompressionMethodUnset,
    #[error("client+server cookie does not match")]
    ErrCookieMismatch,
    #[error("cookie must not be longer then 255 bytes")]
    ErrCookieTooLong,
    #[error("PSK Identity Hint provided but PSK is nil")]
    ErrIdentityNoPsk,
    #[error("no certificate provided")]
    ErrInvalidCertificate,
    #[error("cipher spec invalid")]
    ErrInvalidCipherSpec,
    #[error("invalid or unknown cipher suite")]
    ErrInvalidCipherSuite,
    #[error("unable to determine if ClientKeyExchange is a public key or PSK Identity")]
    ErrInvalidClientKeyExchange,
    #[error("invalid or unknown compression method")]
    ErrInvalidCompressionMethod,
    #[error("ECDSA signature contained zero or negative values")]
    ErrInvalidEcdsasignature,
    #[error("invalid or unknown elliptic curve type")]
    ErrInvalidEllipticCurveType,
    #[error("invalid extension type")]
    ErrInvalidExtensionType,
    #[error("invalid hash algorithm")]
    ErrInvalidHashAlgorithm,
    #[error("invalid named curve")]
    ErrInvalidNamedCurve,
    #[error("invalid private key type")]
    ErrInvalidPrivateKey,
    #[error("named curve and private key type does not match")]
    ErrNamedCurveAndPrivateKeyMismatch,
    #[error("invalid server name format")]
    ErrInvalidSniFormat,
    #[error("invalid signature algorithm")]
    ErrInvalidSignatureAlgorithm,
    #[error("expected and actual key signature do not match")]
    ErrKeySignatureMismatch,
    #[error("Conn can not be created with a nil nextConn")]
    ErrNilNextConn,
    #[error("connection can not be created, no CipherSuites satisfy this Config")]
    ErrNoAvailableCipherSuites,
    #[error("connection can not be created, no SignatureScheme satisfy this Config")]
    ErrNoAvailableSignatureSchemes,
    #[error("no certificates configured")]
    ErrNoCertificates,
    #[error("no config provided")]
    ErrNoConfigProvided,
    #[error("client requested zero or more elliptic curves that are not supported by the server")]
    ErrNoSupportedEllipticCurves,
    #[error("unsupported protocol version")]
    ErrUnsupportedProtocolVersion,
    #[error("Certificate and PSK provided")]
    ErrPskAndCertificate,
    #[error("PSK and PSK Identity Hint must both be set for client")]
    ErrPskAndIdentityMustBeSetForClient,
    #[error("SRTP support was requested but server did not respond with use_srtp extension")]
    ErrRequestedButNoSrtpExtension,
    #[error("Certificate is mandatory for server")]
    ErrServerMustHaveCertificate,
    #[error("client requested SRTP but we have no matching profiles")]
    ErrServerNoMatchingSrtpProfile,
    #[error(
        "server requires the Extended Master Secret extension, but the client does not support it"
    )]
    ErrServerRequiredButNoClientEms,
    #[error("expected and actual verify data does not match")]
    ErrVerifyDataMismatch,
    #[error("handshake message unset, unable to marshal")]
    ErrHandshakeMessageUnset,
    #[error("invalid flight number")]
    ErrInvalidFlight,
    #[error("unable to generate key signature, unimplemented")]
    ErrKeySignatureGenerateUnimplemented,
    #[error("unable to verify key signature, unimplemented")]
    ErrKeySignatureVerifyUnimplemented,
    #[error("data length and declared length do not match")]
    ErrLengthMismatch,
    #[error("buffer not long enough to contain nonce")]
    ErrNotEnoughRoomForNonce,
    #[error("feature has not been implemented yet")]
    ErrNotImplemented,
    #[error("sequence number overflow")]
    ErrSequenceNumberOverflow,
    #[error("unable to marshal fragmented handshakes")]
    ErrUnableToMarshalFragmented,
    #[error("invalid state machine transition")]
    ErrInvalidFsmTransition,
    #[error("ApplicationData with epoch of 0")]
    ErrApplicationDataEpochZero,
    #[error("unhandled contentType")]
    ErrUnhandledContextType,
    #[error("context canceled")]
    ErrContextCanceled,
    #[error("empty fragment")]
    ErrEmptyFragment,
    #[error("Alert is Fatal or Close Notify")]
    ErrAlertFatalOrClose,
    #[error(
        "Fragment buffer overflow. New size {new_size} is greater than specified max {max_size}"
    )]
    ErrFragmentBufferOverflow { new_size: usize, max_size: usize },
    #[error("Client transport is not set yet")]
    ErrClientTransportNotSet,

    /// The endpoint can no longer create new connections
    ///
    /// Indicates that a necessary component of the endpoint has been dropped or otherwise disabled.
    #[error("endpoint stopping")]
    EndpointStopping,
    /// The number of active connections on the local endpoint is at the limit
    ///
    /// Try using longer connection IDs.
    #[error("too many connections")]
    TooManyConnections,
    /// The domain name supplied was malformed
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),
    /// The remote [`SocketAddr`] supplied was malformed
    ///
    /// Examples include attempting to connect to port 0, or using an inappropriate address family.
    #[error("invalid remote address: {0}")]
    InvalidRemoteAddress(SocketAddr),
    /// No client configuration was set up
    #[error("no client config")]
    NoClientConfig,
    /// No server configuration was set up
    #[error("no server config")]
    NoServerConfig,

    //SCTP errors
    #[error("raw is too small for a SCTP chunk")]
    ErrChunkHeaderTooSmall,
    #[error("not enough data left in SCTP packet to satisfy requested length")]
    ErrChunkHeaderNotEnoughSpace,
    #[error("chunk PADDING is non-zero at offset")]
    ErrChunkHeaderPaddingNonZero,
    #[error("chunk has invalid length")]
    ErrChunkHeaderInvalidLength,

    #[error("ChunkType is not of type ABORT")]
    ErrChunkTypeNotAbort,
    #[error("failed build Abort Chunk")]
    ErrBuildAbortChunkFailed,
    #[error("ChunkType is not of type COOKIEACK")]
    ErrChunkTypeNotCookieAck,
    #[error("ChunkType is not of type COOKIEECHO")]
    ErrChunkTypeNotCookieEcho,
    #[error("ChunkType is not of type ctError")]
    ErrChunkTypeNotCt,
    #[error("failed build Error Chunk")]
    ErrBuildErrorChunkFailed,
    #[error("failed to marshal stream")]
    ErrMarshalStreamFailed,
    #[error("chunk too short")]
    ErrChunkTooShort,
    #[error("ChunkType is not of type ForwardTsn")]
    ErrChunkTypeNotForwardTsn,
    #[error("ChunkType is not of type HEARTBEAT")]
    ErrChunkTypeNotHeartbeat,
    #[error("ChunkType is not of type HEARTBEATACK")]
    ErrChunkTypeNotHeartbeatAck,
    #[error("heartbeat is not long enough to contain Heartbeat Info")]
    ErrHeartbeatNotLongEnoughInfo,
    #[error("failed to parse param type")]
    ErrParseParamTypeFailed,
    #[error("heartbeat should only have HEARTBEAT param")]
    ErrHeartbeatParam,
    #[error("failed unmarshalling param in Heartbeat Chunk")]
    ErrHeartbeatChunkUnmarshal,
    #[error("unimplemented")]
    ErrUnimplemented,
    #[error("heartbeat Ack must have one param")]
    ErrHeartbeatAckParams,
    #[error("heartbeat Ack must have one param, and it should be a HeartbeatInfo")]
    ErrHeartbeatAckNotHeartbeatInfo,
    #[error("unable to marshal parameter for Heartbeat Ack")]
    ErrHeartbeatAckMarshalParam,

    #[error("raw is too small for error cause")]
    ErrErrorCauseTooSmall,

    #[error("unhandled ParamType: {typ}")]
    ErrParamTypeUnhandled { typ: u16 },

    #[error("unexpected ParamType")]
    ErrParamTypeUnexpected,

    #[error("param header too short")]
    ErrParamHeaderTooShort,
    #[error("param self reported length is shorter than header length")]
    ErrParamHeaderSelfReportedLengthShorter,
    #[error("param self reported length is longer than header length")]
    ErrParamHeaderSelfReportedLengthLonger,
    #[error("failed to parse param type")]
    ErrParamHeaderParseFailed,

    #[error("packet to short")]
    ErrParamPacketTooShort,
    #[error("outgoing SSN reset request parameter too short")]
    ErrSsnResetRequestParamTooShort,
    #[error("reconfig response parameter too short")]
    ErrReconfigRespParamTooShort,
    #[error("invalid algorithm type")]
    ErrInvalidAlgorithmType,

    #[error("failed to parse param type")]
    ErrInitChunkParseParamTypeFailed,
    #[error("failed unmarshalling param in Init Chunk")]
    ErrInitChunkUnmarshalParam,
    #[error("unable to marshal parameter for INIT/INITACK")]
    ErrInitAckMarshalParam,

    #[error("ChunkType is not of type INIT")]
    ErrChunkTypeNotTypeInit,
    #[error("chunk Value isn't long enough for mandatory parameters exp")]
    ErrChunkValueNotLongEnough,
    #[error("ChunkType of type INIT flags must be all 0")]
    ErrChunkTypeInitFlagZero,
    #[error("failed to unmarshal INIT body")]
    ErrChunkTypeInitUnmarshalFailed,
    #[error("failed marshaling INIT common data")]
    ErrChunkTypeInitMarshalFailed,
    #[error("ChunkType of type INIT ACK InitiateTag must not be 0")]
    ErrChunkTypeInitInitiateTagZero,
    #[error("INIT ACK inbound stream request must be > 0")]
    ErrInitInboundStreamRequestZero,
    #[error("INIT ACK outbound stream request must be > 0")]
    ErrInitOutboundStreamRequestZero,
    #[error("INIT ACK Advertised Receiver Window Credit (a_rwnd) must be >= 1500")]
    ErrInitAdvertisedReceiver1500,

    #[error("packet is smaller than the header size")]
    ErrChunkPayloadSmall,
    #[error("ChunkType is not of type PayloadData")]
    ErrChunkTypeNotPayloadData,
    #[error("ChunkType is not of type Reconfig")]
    ErrChunkTypeNotReconfig,
    #[error("ChunkReconfig has invalid ParamA")]
    ErrChunkReconfigInvalidParamA,

    #[error("failed to parse param type")]
    ErrChunkParseParamTypeFailed,
    #[error("unable to marshal parameter A for reconfig")]
    ErrChunkMarshalParamAReconfigFailed,
    #[error("unable to marshal parameter B for reconfig")]
    ErrChunkMarshalParamBReconfigFailed,

    #[error("ChunkType is not of type SACK")]
    ErrChunkTypeNotSack,
    #[error("SACK Chunk size is not large enough to contain header")]
    ErrSackSizeNotLargeEnoughInfo,

    #[error("invalid chunk size")]
    ErrInvalidChunkSize,
    #[error("ChunkType is not of type SHUTDOWN")]
    ErrChunkTypeNotShutdown,

    #[error("ChunkType is not of type SHUTDOWN-ACK")]
    ErrChunkTypeNotShutdownAck,
    #[error("ChunkType is not of type SHUTDOWN-COMPLETE")]
    ErrChunkTypeNotShutdownComplete,

    #[error("raw is smaller than the minimum length for a SCTP packet")]
    ErrPacketRawTooSmall,
    #[error("unable to parse SCTP chunk, not enough data for complete header")]
    ErrParseSctpChunkNotEnoughData,
    #[error("failed to unmarshal, contains unknown chunk type")]
    ErrUnmarshalUnknownChunkType,
    #[error("checksum mismatch theirs")]
    ErrChecksumMismatch,

    #[error("unexpected chunk popped (unordered)")]
    ErrUnexpectedChuckPoppedUnordered,
    #[error("unexpected chunk popped (ordered)")]
    ErrUnexpectedChuckPoppedOrdered,
    #[error("unexpected q state (should've been selected)")]
    ErrUnexpectedQState,
    #[error("try again")]
    ErrTryAgain,

    #[error("abort chunk, with following errors: {0}")]
    ErrAbortChunk(String),
    #[error("shutdown called in non-Established state")]
    ErrShutdownNonEstablished,
    #[error("association closed before connecting")]
    ErrAssociationClosedBeforeConn,
    #[error("association init failed")]
    ErrAssociationInitFailed,
    #[error("association handshake closed")]
    ErrAssociationHandshakeClosed,
    #[error("silently discard")]
    ErrSilentlyDiscard,
    #[error("the init not stored to send")]
    ErrInitNotStoredToSend,
    #[error("cookieEcho not stored to send")]
    ErrCookieEchoNotStoredToSend,
    #[error("sctp packet must not have a source port of 0")]
    ErrSctpPacketSourcePortZero,
    #[error("sctp packet must not have a destination port of 0")]
    ErrSctpPacketDestinationPortZero,
    #[error("init chunk must not be bundled with any other chunk")]
    ErrInitChunkBundled,
    #[error("init chunk expects a verification tag of 0 on the packet when out-of-the-blue")]
    ErrInitChunkVerifyTagNotZero,
    #[error("todo: handle Init when in state")]
    ErrHandleInitState,
    #[error("no cookie in InitAck")]
    ErrInitAckNoCookie,
    #[error("there already exists a stream with identifier")]
    ErrStreamAlreadyExist,
    #[error("Failed to create a stream with identifier")]
    ErrStreamCreateFailed,
    #[error("unable to be popped from inflight queue TSN")]
    ErrInflightQueueTsnPop,
    #[error("requested non-existent TSN")]
    ErrTsnRequestNotExist,
    #[error("sending reset packet in non-Established state")]
    ErrResetPacketInStateNotExist,
    #[error("unexpected parameter type")]
    ErrParameterType,
    #[error("sending payload data in non-Established state")]
    ErrPayloadDataStateNotExist,
    #[error("unhandled chunk type")]
    ErrChunkTypeUnhandled,
    #[error("handshake failed (INIT ACK)")]
    ErrHandshakeInitAck,
    #[error("handshake failed (COOKIE ECHO)")]
    ErrHandshakeCookieEcho,

    #[error("outbound packet larger than maximum message size")]
    ErrOutboundPacketTooLarge,
    #[error("Stream closed")]
    ErrStreamClosed,
    #[error("Stream not existed")]
    ErrStreamNotExisted,
    #[error("Association not existed")]
    ErrAssociationNotExisted,
    #[error("Transport not existed")]
    ErrTransportNoExisted,
    #[error("Io EOF")]
    ErrEof,
    #[error("Invalid SystemTime")]
    ErrInvalidSystemTime,
    #[error("Net Conn read error")]
    ErrNetConnRead,
    #[error("Max Data Channel ID")]
    ErrMaxDataChannelID,

    //Data Channel
    #[error(
        "DataChannel message is not long enough to determine type: (expected: {expected}, actual: {actual})"
    )]
    UnexpectedEndOfBuffer { expected: usize, actual: usize },
    #[error("Unknown MessageType {0}")]
    InvalidMessageType(u8),
    #[error("Unknown ChannelType {0}")]
    InvalidChannelType(u8),
    #[error("Unknown PayloadProtocolIdentifier {0}")]
    InvalidPayloadProtocolIdentifier(u8),
    #[error("Unknow Protocol")]
    UnknownProtocol,

    //RTC
    /// ErrConnectionClosed indicates an operation executed after connection
    /// has already been closed.
    #[error("connection closed")]
    ErrConnectionClosed,

    /// ErrDataChannelClosed indicates an operation executed when the data
    /// channel is not (yet) open or closed.
    #[error("data channel closed")]
    ErrDataChannelClosed,

    /// ErrDataChannelNonExist indicates an operation executed when the data
    /// channel not existed.
    #[error("data channel not existed")]
    ErrDataChannelNotExisted,

    /// ErrCertificateExpired indicates that an x509 certificate has expired.
    #[error("x509Cert expired")]
    ErrCertificateExpired,

    /// ErrNoTurnCredentials indicates that a TURN server URL was provided
    /// without required credentials.
    #[error("turn server credentials required")]
    ErrNoTurnCredentials,

    /// ErrTurnCredentials indicates that provided TURN credentials are partial
    /// or malformed.
    #[error("invalid turn server credentials")]
    ErrTurnCredentials,

    /// ErrExistingTrack indicates that a track already exists.
    #[error("track already exists")]
    ErrExistingTrack,

    /// ErrPrivateKeyType indicates that a particular private key encryption
    /// chosen to generate a certificate is not supported.
    #[error("private key type not supported")]
    ErrPrivateKeyType,

    /// ErrModifyingPeerIdentity indicates that an attempt to modify
    /// PeerIdentity was made after PeerConnection has been initialized.
    #[error("peerIdentity cannot be modified")]
    ErrModifyingPeerIdentity,

    /// ErrModifyingCertificates indicates that an attempt to modify
    /// Certificates was made after PeerConnection has been initialized.
    #[error("certificates cannot be modified")]
    ErrModifyingCertificates,

    /// ErrNonCertificate indicates that there is no certificate
    #[error("no certificate")]
    ErrNonCertificate,

    /// ErrModifyingBundlePolicy indicates that an attempt to modify
    /// BundlePolicy was made after PeerConnection has been initialized.
    #[error("bundle policy cannot be modified")]
    ErrModifyingBundlePolicy,

    /// ErrModifyingRTCPMuxPolicy indicates that an attempt to modify
    /// RTCPMuxPolicy was made after PeerConnection has been initialized.
    #[error("rtcp mux policy cannot be modified")]
    ErrModifyingRTCPMuxPolicy,

    /// ErrModifyingICECandidatePoolSize indicates that an attempt to modify
    /// ICECandidatePoolSize was made after PeerConnection has been initialized.
    #[error("ice candidate pool size cannot be modified")]
    ErrModifyingICECandidatePoolSize,

    /// ErrStringSizeLimit indicates that the character size limit of string is
    /// exceeded. The limit is hardcoded to 65535 according to specifications.
    #[error("data channel label exceeds size limit")]
    ErrStringSizeLimit,

    /// ErrNegotiatedWithoutID indicates that an attempt to create a data channel
    /// was made while setting the negotiated option to true without providing
    /// the negotiated channel ID.
    #[error("negotiated set without channel id")]
    ErrNegotiatedWithoutID,

    /// ErrRetransmitsOrPacketLifeTime indicates that an attempt to create a data
    /// channel was made with both options max_packet_life_time and max_retransmits
    /// set together. Such configuration is not supported by the specification
    /// and is mutually exclusive.
    #[error("both max_packet_life_time and max_retransmits was set")]
    ErrRetransmitsOrPacketLifeTime,

    /// ErrCodecNotFound is returned when a codec search to the Media Engine fails
    #[error("codec not found")]
    ErrCodecNotFound,

    /// ErrNoRemoteDescription indicates that an operation was rejected because
    /// the remote description is not set
    #[error("remote description is not set")]
    ErrNoRemoteDescription,

    /// ErrIncorrectSDPSemantics indicates that the PeerConnection was configured to
    /// generate SDP Answers with different SDP Semantics than the received Offer
    #[error("offer SDP semantics does not match configuration")]
    ErrIncorrectSDPSemantics,

    /// ErrIncorrectSignalingState indicates that the signaling state of PeerConnection is not correct
    #[error("operation can not be run in current signaling state")]
    ErrIncorrectSignalingState,

    /// ErrProtocolTooLarge indicates that value given for a DataChannelInit protocol is
    /// longer then 65535 bytes
    #[error("protocol is larger then 65535 bytes")]
    ErrProtocolTooLarge,

    /// ErrSenderNotCreatedByConnection indicates remove_track was called with a RtpSender not created
    /// by this PeerConnection
    #[error("RtpSender not created by this PeerConnection")]
    ErrSenderNotCreatedByConnection,

    /// ErrSenderInitialTrackIdAlreadySet indicates a second call to
    /// RtpSender::set_initial_track_id which is not allowed.
    #[error("RtpSender's initial_track_id has already been set")]
    ErrSenderInitialTrackIdAlreadySet,

    /// ErrSessionDescriptionNoFingerprint indicates set_remote_description was called with a SessionDescription that has no
    /// fingerprint
    #[error("set_remote_description called with no fingerprint")]
    ErrSessionDescriptionNoFingerprint,

    /// ErrSessionDescriptionInvalidFingerprint indicates set_remote_description was called with a SessionDescription that
    /// has an invalid fingerprint
    #[error("set_remote_description called with an invalid fingerprint")]
    ErrSessionDescriptionInvalidFingerprint,

    /// ErrSessionDescriptionConflictingFingerprints indicates set_remote_description was called with a SessionDescription that
    /// has an conflicting fingerprints
    #[error("set_remote_description called with multiple conflicting fingerprint")]
    ErrSessionDescriptionConflictingFingerprints,

    /// ErrSessionDescriptionMissingIceUfrag indicates set_remote_description was called with a SessionDescription that
    /// is missing an ice-ufrag value
    #[error("set_remote_description called with no ice-ufrag")]
    ErrSessionDescriptionMissingIceUfrag,

    /// ErrSessionDescriptionMissingIcePwd indicates set_remote_description was called with a SessionDescription that
    /// is missing an ice-pwd value
    #[error("set_remote_description called with no ice-pwd")]
    ErrSessionDescriptionMissingIcePwd,

    /// ErrSessionDescriptionConflictingIceUfrag  indicates set_remote_description was called with a SessionDescription that
    /// contains multiple conflicting ice-ufrag values
    #[error("set_remote_description called with multiple conflicting ice-ufrag values")]
    ErrSessionDescriptionConflictingIceUfrag,

    /// ErrSessionDescriptionConflictingIcePwd indicates set_remote_description was called with a SessionDescription that
    /// contains multiple conflicting ice-pwd values
    #[error("set_remote_description called with multiple conflicting ice-pwd values")]
    ErrSessionDescriptionConflictingIcePwd,

    /// ErrNoSRTPProtectionProfile indicates that the DTLS handshake completed and no SRTP Protection Profile was chosen
    #[error("DTLS Handshake completed and no SRTP Protection Profile was chosen")]
    ErrNoSRTPProtectionProfile,

    /// ErrFailedToGenerateCertificateFingerprint indicates that we failed to generate the fingerprint used for comparing certificates
    #[error("failed to generate certificate fingerprint")]
    ErrFailedToGenerateCertificateFingerprint,

    /// ErrNoCodecsAvailable indicates that operation isn't possible because the MediaEngine has no codecs available
    #[error("operation failed no codecs are available")]
    ErrNoCodecsAvailable,

    /// ErrUnsupportedCodec indicates the remote peer doesn't support the requested codec
    #[error("unable to start track, codec is not supported by remote")]
    ErrUnsupportedCodec,

    /// ErrSenderWithNoCodecs indicates that a RTPSender was created without any codecs. To send media the MediaEngine needs at
    /// least one configured codec.
    #[error("unable to populate media section, RTPSender created with no codecs")]
    ErrSenderWithNoCodecs,

    /// ErrRTPSenderNewTrackHasIncorrectKind indicates that the new track is of a different kind than the previous/original
    #[error("new track must be of the same kind as previous")]
    ErrRTPSenderNewTrackHasIncorrectKind,

    /// ErrRTPSenderDataSent indicates that the sequence number transformer tries to be enabled after the data sending began
    #[error("Sequence number transformer must be enabled before sending data")]
    ErrRTPSenderDataSent,

    /// ErrRTPSenderSeqTransEnabled indicates that the sequence number transformer has been already enabled
    #[error("Sequence number transformer has been already enabled")]
    ErrRTPSenderSeqTransEnabled,

    /// ErrUnbindFailed indicates that a TrackLocal was not able to be unbind
    #[error("failed to unbind TrackLocal from PeerConnection")]
    ErrUnbindFailed,

    /// ErrNoPayloaderForCodec indicates that the requested codec does not have a payloader
    #[error("the requested codec does not have a payloader")]
    ErrNoPayloaderForCodec,

    /// ErrRegisterHeaderExtensionInvalidDirection indicates that a extension was registered with different
    /// directions for two different calls.
    #[error("a header extension must be registered with the same direction each time")]
    ErrRegisterHeaderExtensionInvalidDirection,

    /// ErrRegisterHeaderExtensionNoFreeID indicates that there was no extension ID available which
    /// in turn means that all 15 available id(1 through 14) have been used.
    #[error("no header extension ID was free to use(this means the maximum of 15 extensions have been registered)"
    )]
    ErrRegisterHeaderExtensionNoFreeID,

    /// ErrSimulcastProbeOverflow indicates that too many Simulcast probe streams are in flight and the requested SSRC was ignored
    #[error("simulcast probe limit has been reached, new SSRC has been discarded")]
    ErrSimulcastProbeOverflow,

    #[error("enable detaching by calling webrtc.DetachDataChannels()")]
    ErrDetachNotEnabled,
    #[error("datachannel not opened yet, try calling Detach from OnOpen")]
    ErrDetachBeforeOpened,
    #[error("the DTLS transport has not started yet")]
    ErrDtlsTransportNotStarted,
    #[error("failed extracting keys from DTLS for SRTP")]
    ErrDtlsKeyExtractionFailed,
    #[error("failed to start SRTP")]
    ErrFailedToStartSRTP,
    #[error("failed to start SRTCP")]
    ErrFailedToStartSRTCP,
    #[error("attempted to start DTLSTransport that is not in new state")]
    ErrInvalidDTLSStart,
    #[error("peer didn't provide certificate via DTLS")]
    ErrNoRemoteCertificate,
    #[error("identity provider is not implemented")]
    ErrIdentityProviderNotImplemented,
    #[error("remote certificate does not match any fingerprint")]
    ErrNoMatchingCertificateFingerprint,
    #[error("unsupported fingerprint algorithm")]
    ErrUnsupportedFingerprintAlgorithm,
    #[error("ICE connection not started")]
    ErrICEConnectionNotStarted,
    #[error("unknown candidate type")]
    ErrICECandidateTypeUnknown,
    #[error("cannot convert ice.CandidateType into webrtc.ICECandidateType, invalid type")]
    ErrICEInvalidConvertCandidateType,
    #[error("ICEAgent does not exist")]
    ErrICEAgentNotExist,
    #[error("unable to convert ICE candidates to ICECandidates")]
    ErrICECandidatesConversionFailed,
    #[error("unknown ICE Role")]
    ErrICERoleUnknown,
    #[error("unknown protocol")]
    ErrICEProtocolUnknown,
    #[error("gatherer not started")]
    ErrICEGathererNotStarted,
    #[error("unknown network type")]
    ErrNetworkTypeUnknown,
    #[error("new sdp does not match previous offer")]
    ErrSDPDoesNotMatchOffer,
    #[error("new sdp does not match previous answer")]
    ErrSDPDoesNotMatchAnswer,
    #[error("provided value is not a valid enum value of type SDPType")]
    ErrPeerConnSDPTypeInvalidValue,
    #[error("invalid state change op")]
    ErrPeerConnStateChangeInvalid,
    #[error("unhandled state change op")]
    ErrPeerConnStateChangeUnhandled,
    #[error("invalid SDP type supplied to SetLocalDescription()")]
    ErrPeerConnSDPTypeInvalidValueSetLocalDescription,
    #[error("remoteDescription contained media section without mid value")]
    ErrPeerConnRemoteDescriptionWithoutMidValue,
    #[error("remoteDescription has not been set yet")]
    ErrPeerConnRemoteDescriptionNil,
    #[error("localDescription has not been set yet")]
    ErrPeerConnLocalDescriptionNil,
    #[error("single media section has an explicit SSRC")]
    ErrPeerConnSingleMediaSectionHasExplicitSSRC,
    #[error("could not add transceiver for remote SSRC")]
    ErrPeerConnRemoteSSRCAddTransceiver,
    #[error("mid RTP Extensions required for Simulcast")]
    ErrPeerConnSimulcastMidRTPExtensionRequired,
    #[error("stream id RTP Extensions required for Simulcast")]
    ErrPeerConnSimulcastStreamIDRTPExtensionRequired,
    #[error("incoming SSRC failed Simulcast probing")]
    ErrPeerConnSimulcastIncomingSSRCFailed,
    #[error("failed collecting stats")]
    ErrPeerConnStatsCollectionFailed,
    #[error("add_transceiver_from_kind only accepts one RTPTransceiverInit")]
    ErrPeerConnAddTransceiverFromKindOnlyAcceptsOne,
    #[error("add_transceiver_from_track only accepts one RTPTransceiverInit")]
    ErrPeerConnAddTransceiverFromTrackOnlyAcceptsOne,
    #[error("add_transceiver_from_kind currently only supports recvonly")]
    ErrPeerConnAddTransceiverFromKindSupport,
    #[error("add_transceiver_from_track currently only supports sendonly and sendrecv")]
    ErrPeerConnAddTransceiverFromTrackSupport,
    #[error("TODO set_identity_provider")]
    ErrPeerConnSetIdentityProviderNotImplemented,
    #[error("write_rtcp failed to open write_stream")]
    ErrPeerConnWriteRTCPOpenWriteStream,
    #[error("cannot find transceiver with mid")]
    ErrPeerConnTransceiverMidNil,
    #[error("DTLSTransport must not be nil")]
    ErrRTPReceiverDTLSTransportNil,
    #[error("Receive has already been called")]
    ErrRTPReceiverReceiveAlreadyCalled,
    #[error("unable to find stream for Track with SSRC")]
    ErrRTPReceiverWithSSRCTrackStreamNotFound,
    #[error("no trackStreams found for SSRC")]
    ErrRTPReceiverForSSRCTrackStreamNotFound,
    #[error("no trackStreams found for RID")]
    ErrRTPReceiverForRIDTrackStreamNotFound,
    #[error("invalid RTP Receiver transition")]
    ErrRTPReceiverStateChangeInvalid,
    #[error("Track must not be nil")]
    ErrRTPSenderTrackNil,
    #[error("RTPSender must not be nil")]
    ErrRTPSenderNil,
    #[error("RTPReceiver must not be nil")]
    ErrRTPReceiverNil,
    #[error("DTLSTransport must not be nil")]
    ErrRTPSenderDTLSTransportNil,
    #[error("Send has already been called")]
    ErrRTPSenderSendAlreadyCalled,
    #[error("errRTPSenderTrackNil")]
    ErrRTPTransceiverCannotChangeMid,
    #[error("invalid state change in RTPTransceiver.setSending")]
    ErrRTPTransceiverSetSendingInvalidState,
    #[error("unsupported codec type by this transceiver")]
    ErrRTPTransceiverCodecUnsupported,
    #[error("DTLS not established")]
    ErrSCTPTransportDTLS,
    #[error("add_transceiver_sdp() called with 0 transceivers")]
    ErrSDPZeroTransceivers,
    #[error("invalid Media Section. Media + DataChannel both enabled")]
    ErrSDPMediaSectionMediaDataChanInvalid,
    #[error("invalid Media Section Track Index")]
    ErrSDPMediaSectionTrackInvalid,
    #[error("set_answering_dtlsrole must DTLSRoleClient or DTLSRoleServer")]
    ErrSettingEngineSetAnsweringDTLSRole,
    #[error("can't rollback from stable state")]
    ErrSignalingStateCannotRollback,
    #[error("invalid proposed signaling state transition: {0}")]
    ErrSignalingStateProposedTransitionInvalid(String),
    #[error("cannot convert to StatsICECandidatePairStateSucceeded invalid ice candidate state")]
    ErrStatsICECandidateStateInvalid,
    #[error("ICETransport can only be called in ICETransportStateNew")]
    ErrICETransportNotInNew,
    #[error("bad Certificate PEM format")]
    ErrCertificatePEMFormatError,
    #[error("SCTP is not established")]
    ErrSCTPNotEstablished,

    #[error("DataChannel is not opened")]
    ErrClosedPipe,
    #[error("Interceptor is not bind")]
    ErrInterceptorNotBind,
    #[error("excessive retries in CreateOffer")]
    ErrExcessiveRetries,

    #[error("not long enough to be a RTP Packet")]
    ErrRTPTooShort,

    /// SyntaxIdDirSplit indicates rid-syntax could not be parsed.
    #[error("RFC8851 mandates rid-syntax        = %s\"a=rid:\" rid-id SP rid-dir")]
    SimulcastRidParseErrorSyntaxIdDirSplit,
    /// UnknownDirection indicates rid-dir was not parsed. Should be "send" or "recv".
    #[error("RFC8851 mandates rid-dir           = %s\"send\" / %s\"recv\"")]
    SimulcastRidParseErrorUnknownDirection,

    //SDP
    #[error("codec not found")]
    CodecNotFound,
    #[error("missing whitespace")]
    MissingWhitespace,
    #[error("missing colon")]
    MissingColon,
    #[error("payload type not found")]
    PayloadTypeNotFound,
    #[error("SdpInvalidSyntax: {0}")]
    SdpInvalidSyntax(String),
    #[error("SdpInvalidValue: {0}")]
    SdpInvalidValue(String),
    #[error("sdp: empty time_descriptions")]
    SdpEmptyTimeDescription,
    #[error("parse extmap: {0}")]
    ParseExtMap(String),
    #[error("{} --> {} <-- {}", .s.substring(0,*.p), .s.substring(*.p, *.p+1), .s.substring(*.p+1, .s.len())
    )]
    SyntaxError { s: String, p: usize },

    //Third Party Error
    #[error("{0}")]
    Sec1(#[source] sec1::Error),
    #[error("{0}")]
    P256(#[source] P256Error),
    #[error("{0}")]
    RcGen(#[from] rcgen::Error),
    #[error("invalid PEM: {0}")]
    InvalidPEM(String),
    #[error("aes gcm: {0}")]
    AesGcm(#[from] aes_gcm::Error),
    #[error("parse ip: {0}")]
    ParseIp(#[from] net::AddrParseError),
    #[error("parse int: {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("{0}")]
    Io(#[source] IoError),
    #[error("url parse: {0}")]
    Url(#[from] url::ParseError),
    #[error("utf8: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("{0}")]
    Std(#[source] StdError),
    #[error("{0}")]
    Aes(#[from] aes::cipher::InvalidLength),

    //Other Errors
    #[error("Other RTCP Err: {0}")]
    OtherRtcpErr(String),
    #[error("Other RTP Err: {0}")]
    OtherRtpErr(String),
    #[error("Other SRTP Err: {0}")]
    OtherSrtpErr(String),
    #[error("Other STUN Err: {0}")]
    OtherStunErr(String),
    #[error("Other TURN Err: {0}")]
    OtherTurnErr(String),
    #[error("Other ICE Err: {0}")]
    OtherIceErr(String),
    #[error("Other DTLS Err: {0}")]
    OtherDtlsErr(String),
    #[error("Other SCTP Err: {0}")]
    OtherSctpErr(String),
    #[error("Other DataChannel Err: {0}")]
    OtherDataChannelErr(String),
    #[error("Other Interceptor Err: {0}")]
    OtherInterceptorErr(String),
    #[error("Other Media Err: {0}")]
    OtherMediaErr(String),
    #[error("Other mDNS Err: {0}")]
    OtherMdnsErr(String),
    #[error("Other SDP Err: {0}")]
    OtherSdpErr(String),
    #[error("Other PeerConnection Err: {0}")]
    OtherPeerConnectionErr(String),
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

impl From<sec1::Error> for Error {
    fn from(e: sec1::Error) -> Self {
        Error::Sec1(e)
    }
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct P256Error(#[source] p256::elliptic_curve::Error);

impl PartialEq for P256Error {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

impl From<p256::elliptic_curve::Error> for Error {
    fn from(e: p256::elliptic_curve::Error) -> Self {
        Error::P256(P256Error(e))
    }
}

impl From<SystemTimeError> for Error {
    fn from(e: SystemTimeError) -> Self {
        Error::Other(e.to_string())
    }
}

/// flatten_errs flattens multiple errors into one
pub fn flatten_errs(errs: Vec<impl Into<Error>>) -> Result<()> {
    if errs.is_empty() {
        Ok(())
    } else {
        let errs_strs: Vec<String> = errs.into_iter().map(|e| e.into().to_string()).collect();
        Err(Error::Other(errs_strs.join("\n")))
    }
}
