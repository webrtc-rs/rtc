#![allow(dead_code)]

use std::io;
use std::net;
use std::net::SocketAddr;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;
use substring::Substring;
use thiserror::Error;

/// A type alias for `std::result::Result` with this crate's [`enum@Error`] type.
pub type Result<T> = std::result::Result<T, Error>;

/// Unified error type for all WebRTC sub-protocols.
///
/// Aggregates errors from every layer of the WebRTC stack — buffers, RTP/RTCP,
/// SRTP, STUN, TURN, ICE, DTLS, SCTP, data channels, SDP, mDNS, and the
/// top-level peer connection — into a single enum so callers only need to
/// handle one error type.
///
/// The enum is `#[non_exhaustive]`: new variants may be added in future
/// releases without a semver-breaking change.
#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Buffer: full.
    #[error("buffer: full")]
    ErrBufferFull,
    /// Buffer: closed.
    #[error("buffer: closed")]
    ErrBufferClosed,
    /// Buffer: short.
    #[error("buffer: short")]
    ErrBufferShort,
    /// Packet too big.
    #[error("packet too big")]
    ErrPacketTooBig,
    /// I/O timeout.
    #[error("i/o timeout")]
    ErrTimeout,
    /// UDP: listener closed.
    #[error("udp: listener closed")]
    ErrClosedListener,
    /// UDP: listen queue exceeded.
    #[error("udp: listen queue exceeded")]
    ErrListenQueueExceeded,
    /// UDP: listener accept ch closed.
    #[error("udp: listener accept ch closed")]
    ErrClosedListenerAcceptCh,
    /// Obs cannot be nil.
    #[error("obs cannot be nil")]
    ErrObsCannotBeNil,
    /// Se of closed network connection.
    #[error("se of closed network connection")]
    ErrUseClosedNetworkConn,
    /// Addr is not a net.UDPAddr.
    #[error("addr is not a net.UDPAddr")]
    ErrAddrNotUdpAddr,
    /// Something went wrong with locAddr.
    #[error("something went wrong with locAddr")]
    ErrLocAddr,
    /// Already closed.
    #[error("already closed")]
    ErrAlreadyClosed,
    /// No remAddr defined.
    #[error("no remAddr defined")]
    ErrNoRemAddr,
    /// Address already in use.
    #[error("address already in use")]
    ErrAddressAlreadyInUse,
    /// No such UDPConn.
    #[error("no such UDPConn")]
    ErrNoSuchUdpConn,
    /// Cannot remove unspecified IP by the specified IP.
    #[error("cannot remove unspecified IP by the specified IP")]
    ErrCannotRemoveUnspecifiedIp,
    /// No address assigned.
    #[error("no address assigned")]
    ErrNoAddressAssigned,
    /// 1:1 NAT requires more than one mapping.
    #[error("1:1 NAT requires more than one mapping")]
    ErrNatRequriesMapping,
    /// Length mismtach between mappedIPs and localIPs.
    #[error("length mismtach between mappedIPs and localIPs")]
    ErrMismatchLengthIp,
    /// Non-udp translation is not supported yet.
    #[error("non-udp translation is not supported yet")]
    ErrNonUdpTranslationNotSupported,
    /// No associated local address.
    #[error("no associated local address")]
    ErrNoAssociatedLocalAddress,
    /// No NAT binding found.
    #[error("no NAT binding found")]
    ErrNoNatBindingFound,
    /// Has no permission.
    #[error("has no permission")]
    ErrHasNoPermission,
    /// Host name must not be empty.
    #[error("host name must not be empty")]
    ErrHostnameEmpty,
    /// Failed to parse IP address.
    #[error("failed to parse IP address")]
    ErrFailedToParseIpaddr,
    /// No interface is available.
    #[error("no interface is available")]
    ErrNoInterface,
    /// Not found.
    #[error("not found")]
    ErrNotFound,
    /// Unexpected network.
    #[error("unexpected network")]
    ErrUnexpectedNetwork,
    /// Can't assign requested address.
    #[error("can't assign requested address")]
    ErrCantAssignRequestedAddr,
    /// Unknown network.
    #[error("unknown network")]
    ErrUnknownNetwork,
    /// No router linked.
    #[error("no router linked")]
    ErrNoRouterLinked,
    /// Invalid port number.
    #[error("invalid port number")]
    ErrInvalidPortNumber,
    /// Unexpected type-switch failure.
    #[error("unexpected type-switch failure")]
    ErrUnexpectedTypeSwitchFailure,
    /// Bind failed.
    #[error("bind failed")]
    ErrBindFailed,
    /// End port is less than the start.
    #[error("end port is less than the start")]
    ErrEndPortLessThanStart,
    /// Port space exhausted.
    #[error("port space exhausted")]
    ErrPortSpaceExhausted,
    /// Vnet is not enabled.
    #[error("vnet is not enabled")]
    ErrVnetDisabled,
    /// Invalid local IP in static_ips.
    #[error("invalid local IP in static_ips")]
    ErrInvalidLocalIpInStaticIps,
    /// Mapped in static_ips is beyond subnet.
    #[error("mapped in static_ips is beyond subnet")]
    ErrLocalIpBeyondStaticIpsSubset,
    /// All static_ips must have associated local IPs.
    #[error("all static_ips must have associated local IPs")]
    ErrLocalIpNoStaticsIpsAssociated,
    /// Router already started.
    #[error("router already started")]
    ErrRouterAlreadyStarted,
    /// Router already stopped.
    #[error("router already stopped")]
    ErrRouterAlreadyStopped,
    /// Static IP is beyond subnet.
    #[error("static IP is beyond subnet")]
    ErrStaticIpIsBeyondSubnet,
    /// Address space exhausted.
    #[error("address space exhausted")]
    ErrAddressSpaceExhausted,
    /// No IP address is assigned for eth0.
    #[error("no IP address is assigned for eth0")]
    ErrNoIpaddrEth0,
    /// Invalid mask.
    #[error("Invalid mask")]
    ErrInvalidMask,

    //ExportKeyingMaterial errors
    /// TLS handshake is in progress.
    #[error("tls handshake is in progress")]
    HandshakeInProgress,
    /// Context is not supported for export_keying_material.
    #[error("context is not supported for export_keying_material")]
    ContextUnsupported,
    /// Export_keying_material can not be used with a reserved label.
    #[error("export_keying_material can not be used with a reserved label")]
    ReservedExportKeyingMaterial,
    /// No cipher suite for export_keying_material.
    #[error("no cipher suite for export_keying_material")]
    CipherSuiteUnset,
    /// Export_keying_material hash.
    #[error("export_keying_material hash: {0}")]
    Hash(String),
    /// Mutex poison.
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
    /// Invalid bitrate.
    #[error("Invalid bitrate")]
    InvalidBitrate,
    /// Wrong chunk type.
    #[error("Wrong chunk type")]
    WrongChunkType,
    /// Struct contains unexpected member type.
    #[error("Struct contains unexpected member type")]
    BadStructMemberType,
    /// Cannot read into non-pointer.
    #[error("Cannot read into non-pointer")]
    BadReadParameter,
    /// Invalid block size.
    #[error("Invalid block size")]
    InvalidBlockSize,

    //RTP errors
    /// RTP header size insufficient.
    #[error("RTP header size insufficient")]
    ErrHeaderSizeInsufficient,
    /// RTP header size insufficient for extension.
    #[error("RTP header size insufficient for extension")]
    ErrHeaderSizeInsufficientForExtension,
    /// Buffer too small.
    #[error("buffer too small")]
    ErrBufferTooSmall,
    /// Extension not enabled.
    #[error("extension not enabled")]
    ErrHeaderExtensionsNotEnabled,
    /// Extension not found.
    #[error("extension not found")]
    ErrHeaderExtensionNotFound,

    /// Header extension id must be between 1 and 14 for RFC 5285 extensions.
    #[error("header extension id must be between 1 and 14 for RFC 5285 extensions")]
    ErrRfc8285oneByteHeaderIdrange,
    /// Header extension payload must be 16bytes or less for RFC 5285 one byte extensions.
    #[error("header extension payload must be 16bytes or less for RFC 5285 one byte extensions")]
    ErrRfc8285oneByteHeaderSize,

    /// Header extension id must be between 1 and 255 for RFC 5285 extensions.
    #[error("header extension id must be between 1 and 255 for RFC 5285 extensions")]
    ErrRfc8285twoByteHeaderIdrange,
    /// Header extension payload must be 255bytes or less for RFC 5285 two byte extensions.
    #[error("header extension payload must be 255bytes or less for RFC 5285 two byte extensions")]
    ErrRfc8285twoByteHeaderSize,

    /// Header extension id must be 0 for none RFC 5285 extensions.
    #[error("header extension id must be 0 for none RFC 5285 extensions")]
    ErrRfc3550headerIdrange,

    /// Packet is not large enough.
    #[error("packet is not large enough")]
    ErrShortPacket,
    /// Invalid nil packet.
    #[error("invalid nil packet")]
    ErrNilPacket,
    /// Too many PDiff.
    #[error("too many PDiff")]
    ErrTooManyPDiff,
    /// Too many spatial layers.
    #[error("too many spatial layers")]
    ErrTooManySpatialLayers,
    /// NALU Type is unhandled.
    #[error("NALU Type is unhandled")]
    ErrUnhandledNaluType,

    /// Corrupted H265 packet.
    #[error("corrupted h265 packet")]
    ErrH265CorruptedPacket,
    /// Invalid H265 packet type.
    #[error("invalid h265 packet type")]
    ErrInvalidH265PacketType,

    /// Payload is too small for OBU extension header.
    #[error("payload is too small for OBU extension header")]
    ErrPayloadTooSmallForObuExtensionHeader,
    /// Payload is too small for OBU payload size.
    #[error("payload is too small for OBU payload size")]
    ErrPayloadTooSmallForObuPayloadSize,

    /// Extension_payload must be in 32-bit words.
    #[error("extension_payload must be in 32-bit words")]
    HeaderExtensionPayloadNot32BitWords,
    /// Audio level overflow.
    #[error("audio level overflow")]
    AudioLevelOverflow,
    /// Playout delay overflow.
    #[error("playout delay overflow")]
    PlayoutDelayOverflow,
    /// Payload is not large enough.
    #[error("payload is not large enough")]
    PayloadIsNotLargeEnough,
    /// STAP-A declared size is larger than buffer.
    #[error("STAP-A declared size({0}) is larger than buffer({1})")]
    StapASizeLargerThanBuffer(usize, usize),
    /// NALU type is currently not handled.
    #[error("nalu type {0} is currently not handled")]
    NaluTypeIsNotHandled(u8),

    //SRTP
    /// Duplicated packet.
    #[error("duplicated packet")]
    ErrDuplicated,
    /// SRTP master key is not long enough.
    #[error("SRTP master key is not long enough")]
    ErrShortSrtpMasterKey,
    /// SRTP master salt is not long enough.
    #[error("SRTP master salt is not long enough")]
    ErrShortSrtpMasterSalt,
    /// No such SRTP Profile.
    #[error("no such SRTP Profile")]
    ErrNoSuchSrtpProfile,
    /// IndexOverKdr > 0 is not supported yet.
    #[error("indexOverKdr > 0 is not supported yet")]
    ErrNonZeroKdrNotSupported,
    /// Exporter called with wrong label.
    #[error("exporter called with wrong label")]
    ErrExporterWrongLabel,
    /// No config provided.
    #[error("no config provided")]
    ErrNoConfig,
    /// No conn provided.
    #[error("no conn provided")]
    ErrNoConn,
    /// Failed to verify auth tag.
    #[error("failed to verify auth tag")]
    ErrFailedToVerifyAuthTag,
    /// Packet is too short to be RTP packet.
    #[error("packet is too short to be RTP packet")]
    ErrTooShortRtp,
    /// Packet is too short to be RTCP packet.
    #[error("packet is too short to be RTCP packet")]
    ErrTooShortRtcp,
    /// Payload differs.
    #[error("payload differs")]
    ErrPayloadDiffers,
    /// Started channel used incorrectly, should only be closed.
    #[error("started channel used incorrectly, should only be closed")]
    ErrStartedChannelUsedIncorrectly,
    /// Stream has not been inited, unable to close.
    #[error("stream has not been inited, unable to close")]
    ErrStreamNotInited,
    /// Stream is already closed.
    #[error("stream is already closed")]
    ErrStreamAlreadyClosed,
    /// Stream is already inited.
    #[error("stream is already inited")]
    ErrStreamAlreadyInited,
    /// Failed to cast child.
    #[error("failed to cast child")]
    ErrFailedTypeAssertion,
    /// Exceeded the maximum number of packets.
    #[error("exceeded the maximum number of packets")]
    ErrExceededMaxPackets,

    /// Index_over_kdr > 0 is not supported yet.
    #[error("index_over_kdr > 0 is not supported yet")]
    UnsupportedIndexOverKdr,
    /// Invalid master key length for AES_256_cm.
    #[error("invalid master key length for aes_256_cm")]
    InvalidMasterKeyLength,
    /// Invalid master salt length for AES_256_cm.
    #[error("invalid master salt length for aes_256_cm")]
    InvalidMasterSaltLength,
    /// Out_len > 32 is not supported for AES_256_cm.
    #[error("out_len > 32 is not supported for aes_256_cm")]
    UnsupportedOutLength,
    /// SRTP Master Key must be len , got.
    #[error("SRTP Master Key must be len {0}, got {1}")]
    SrtpMasterKeyLength(usize, usize),
    /// SRTP Salt must be len , got.
    #[error("SRTP Salt must be len {0}, got {1}")]
    SrtpSaltLength(usize, usize),
    /// SyntaxError.
    #[error("SyntaxError: {0}")]
    ExtMapParse(String),
    /// SSRC not exist in SRTP_SSRC_state.
    #[error("ssrc {0} not exist in srtp_ssrc_state")]
    SsrcMissingFromSrtp(u32),
    /// SRTP SSRC= index=: duplicated.
    #[error("srtp ssrc={0} index={1}: duplicated")]
    SrtpSsrcDuplicated(u32, u16),
    /// Srtcp SSRC= index=: duplicated.
    #[error("srtcp ssrc={0} index={1}: duplicated")]
    SrtcpSsrcDuplicated(u32, usize),
    /// SSRC not exist in srtcp_SSRC_state.
    #[error("ssrc {0} not exist in srtcp_ssrc_state")]
    SsrcMissingFromSrtcp(u32),
    /// Stream with SSRC exists.
    #[error("Stream with ssrc {0} exists")]
    StreamWithSsrcExists(u32),
    /// Session RTP/RTCP type must be same as input buffer.
    #[error("Session RTP/RTCP type must be same as input buffer")]
    SessionRtpRtcpTypeMismatch,
    /// Session EOF.
    #[error("Session EOF")]
    SessionEof,
    /// Too short SRTP packet: only bytes, expected > bytes.
    #[error("too short SRTP packet: only {0} bytes, expected > {1} bytes")]
    SrtpTooSmall(usize, usize),
    /// Too short SRTCP packet: only bytes, expected > bytes.
    #[error("too short SRTCP packet: only {0} bytes, expected > {1} bytes")]
    SrtcpTooSmall(usize, usize),
    /// Failed to verify RTP auth tag.
    #[error("failed to verify rtp auth tag")]
    RtpFailedToVerifyAuthTag,
    /// Too short auth tag: only bytes, expected > bytes.
    #[error("too short auth tag: only {0} bytes, expected > {1} bytes")]
    RtcpInvalidLengthAuthTag(usize, usize),
    /// Failed to verify RTCP auth tag.
    #[error("failed to verify rtcp auth tag")]
    RtcpFailedToVerifyAuthTag,
    /// SessionSRTP has been closed.
    #[error("SessionSRTP has been closed")]
    SessionSrtpAlreadyClosed,
    /// This stream is not a RTPStream.
    #[error("this stream is not a RTPStream")]
    InvalidRtpStream,
    /// This stream is not a RTCPStream.
    #[error("this stream is not a RTCPStream")]
    InvalidRtcpStream,

    //STUN errors
    /// Attribute not found.
    #[error("attribute not found")]
    ErrAttributeNotFound,
    /// Transaction is stopped.
    #[error("transaction is stopped")]
    ErrTransactionStopped,
    /// Transaction not exists.
    #[error("transaction not exists")]
    ErrTransactionNotExists,
    /// Transaction exists with same id.
    #[error("transaction exists with same id")]
    ErrTransactionExists,
    /// Agent is closed.
    #[error("agent is closed")]
    ErrAgentClosed,
    /// Transaction is timed out.
    #[error("transaction is timed out")]
    ErrTransactionTimeOut,
    /// No default reason for ErrorCode.
    #[error("no default reason for ErrorCode")]
    ErrNoDefaultReason,
    /// Unexpected EOF.
    #[error("unexpected EOF")]
    ErrUnexpectedEof,
    /// Attribute size is invalid.
    #[error("attribute size is invalid")]
    ErrAttributeSizeInvalid,
    /// Attribute size overflow.
    #[error("attribute size overflow")]
    ErrAttributeSizeOverflow,
    /// Attempt to decode to nil message.
    #[error("attempt to decode to nil message")]
    ErrDecodeToNil,
    /// Unexpected EOF: not enough bytes to read header.
    #[error("unexpected EOF: not enough bytes to read header")]
    ErrUnexpectedHeaderEof,
    /// Integrity check failed.
    #[error("integrity check failed")]
    ErrIntegrityMismatch,
    /// Fingerprint check failed.
    #[error("fingerprint check failed")]
    ErrFingerprintMismatch,
    /// FINGERPRINT before MESSAGE-INTEGRITY attribute.
    #[error("FINGERPRINT before MESSAGE-INTEGRITY attribute")]
    ErrFingerprintBeforeIntegrity,
    /// Bad UNKNOWN-ATTRIBUTES size.
    #[error("bad UNKNOWN-ATTRIBUTES size")]
    ErrBadUnknownAttrsSize,
    /// Invalid length of IP value.
    #[error("invalid length of IP value")]
    ErrBadIpLength,
    /// No connection provided.
    #[error("no connection provided")]
    ErrNoConnection,
    /// Client is closed.
    #[error("client is closed")]
    ErrClientClosed,
    /// No agent is set.
    #[error("no agent is set")]
    ErrNoAgent,
    /// Collector is closed.
    #[error("collector is closed")]
    ErrCollectorClosed,
    /// Unsupported network.
    #[error("unsupported network")]
    ErrUnsupportedNetwork,
    /// Invalid URL.
    #[error("invalid url")]
    ErrInvalidUrl,
    /// Unknown scheme type.
    #[error("unknown scheme type")]
    ErrSchemeType,
    /// Invalid hostname.
    #[error("invalid hostname")]
    ErrHost,

    // TURN errors
    /// TURN: RelayAddress must be valid IP to use RelayAddressGeneratorStatic.
    #[error("turn: RelayAddress must be valid IP to use RelayAddressGeneratorStatic")]
    ErrRelayAddressInvalid,
    /// TURN: PacketConnConfigs and ConnConfigs are empty, unable to proceed.
    #[error("turn: PacketConnConfigs and ConnConfigs are empty, unable to proceed")]
    ErrNoAvailableConns,
    /// TURN: PacketConnConfig must have a non-nil Conn.
    #[error("turn: PacketConnConfig must have a non-nil Conn")]
    ErrConnUnset,
    /// TURN: ListenerConfig must have a non-nil Listener.
    #[error("turn: ListenerConfig must have a non-nil Listener")]
    ErrListenerUnset,
    /// TURN: RelayAddressGenerator has invalid ListeningAddress.
    #[error("turn: RelayAddressGenerator has invalid ListeningAddress")]
    ErrListeningAddressInvalid,
    /// TURN: RelayAddressGenerator in RelayConfig is unset.
    #[error("turn: RelayAddressGenerator in RelayConfig is unset")]
    ErrRelayAddressGeneratorUnset,
    /// TURN: max retries exceeded.
    #[error("turn: max retries exceeded")]
    ErrMaxRetriesExceeded,
    /// TURN: MaxPort must be not 0.
    #[error("turn: MaxPort must be not 0")]
    ErrMaxPortNotZero,
    /// TURN: MaxPort must be not 0.
    #[error("turn: MaxPort must be not 0")]
    ErrMinPortNotZero,
    /// TURN: MaxPort less than MinPort.
    #[error("turn: MaxPort less than MinPort")]
    ErrMaxPortLessThanMinPort,
    /// TURN: relay_conn cannot not be nil.
    #[error("turn: relay_conn cannot not be nil")]
    ErrNilConn,
    /// TURN: TODO.
    #[error("turn: TODO")]
    ErrTodo,
    /// TURN: already listening.
    #[error("turn: already listening")]
    ErrAlreadyListening,
    /// TURN: Server failed to close.
    #[error("turn: Server failed to close")]
    ErrFailedToClose,
    /// TURN: failed to retransmit transaction.
    #[error("turn: failed to retransmit transaction")]
    ErrFailedToRetransmitTransaction,
    /// All retransmissions failed.
    #[error("all retransmissions failed")]
    ErrAllRetransmissionsFailed,
    /// No binding found for channel.
    #[error("no binding found for channel")]
    ErrChannelBindNotFound,
    /// STUN server address is not set for the client.
    #[error("STUN server address is not set for the client")]
    ErrStunserverAddressNotSet,
    /// Only one Allocate caller is allowed.
    #[error("only one Allocate() caller is allowed")]
    ErrOneAllocateOnly,
    /// Already allocated.
    #[error("already allocated")]
    ErrAlreadyAllocated,
    /// Non-STUN message from STUN server.
    #[error("non-STUN message from STUN server")]
    ErrNonStunmessage,
    /// Failed to decode STUN message.
    #[error("failed to decode STUN message")]
    ErrFailedToDecodeStun,
    /// Unexpected STUN request message.
    #[error("unexpected STUN request message")]
    ErrUnexpectedStunrequestMessage,
    /// Channel number not in [0x4000, 0x7FFF].
    #[error("channel number not in [0x4000, 0x7FFF]")]
    ErrInvalidChannelNumber,
    /// ChannelData length != len(Data).
    #[error("channelData length != len(Data)")]
    ErrBadChannelDataLength,
    /// Invalid value for requested family attribute.
    #[error("invalid value for requested family attribute")]
    ErrInvalidRequestedFamilyValue,
    /// Fake error.
    #[error("fake error")]
    ErrFakeErr,
    /// Use of closed network connection.
    #[error("use of closed network connection")]
    ErrClosed,
    /// Addr is not a net.UDPAddr.
    #[error("addr is not a net.UDPAddr")]
    ErrUdpaddrCast,
    /// Try-lock is already locked.
    #[error("try-lock is already locked")]
    ErrDoubleLock,
    /// Transaction closed.
    #[error("transaction closed")]
    ErrTransactionClosed,
    /// Wait_for_result called on non-result transaction.
    #[error("wait_for_result called on non-result transaction")]
    ErrWaitForResultOnNonResultTransaction,
    /// Failed to build refresh request.
    #[error("failed to build refresh request")]
    ErrFailedToBuildRefreshRequest,
    /// Failed to refresh allocation.
    #[error("failed to refresh allocation")]
    ErrFailedToRefreshAllocation,
    /// Failed to get lifetime from refresh response.
    #[error("failed to get lifetime from refresh response")]
    ErrFailedToGetLifetime,
    /// Too short buffer.
    #[error("too short buffer")]
    ErrShortBuffer,
    /// Unexpected response type.
    #[error("unexpected response type")]
    ErrUnexpectedResponse,
    /// AllocatePacketConn must be set.
    #[error("AllocatePacketConn must be set")]
    ErrAllocatePacketConnMustBeSet,
    /// AllocateConn must be set.
    #[error("AllocateConn must be set")]
    ErrAllocateConnMustBeSet,
    /// LeveledLogger must be set.
    #[error("LeveledLogger must be set")]
    ErrLeveledLoggerMustBeSet,
    /// You cannot use the same channel number with different peer.
    #[error("you cannot use the same channel number with different peer")]
    ErrSameChannelDifferentPeer,
    /// Allocations must not be created with nil FivTuple.
    #[error("allocations must not be created with nil FivTuple")]
    ErrNilFiveTuple,
    /// Allocations must not be created with nil FiveTuple.src_addr.
    #[error("allocations must not be created with nil FiveTuple.src_addr")]
    ErrNilFiveTupleSrcAddr,
    /// Allocations must not be created with nil FiveTuple.dst_addr.
    #[error("allocations must not be created with nil FiveTuple.dst_addr")]
    ErrNilFiveTupleDstAddr,
    /// Allocations must not be created with nil turnSocket.
    #[error("allocations must not be created with nil turnSocket")]
    ErrNilTurnSocket,
    /// Allocations must not be created with a lifetime of 0.
    #[error("allocations must not be created with a lifetime of 0")]
    ErrLifetimeZero,
    /// Allocation attempt created with duplicate FiveTuple.
    #[error("allocation attempt created with duplicate FiveTuple")]
    ErrDupeFiveTuple,
    /// Failed to cast net.Addr to *net.UDPAddr.
    #[error("failed to cast net.Addr to *net.UDPAddr")]
    ErrFailedToCastUdpaddr,
    /// Failed to generate nonce.
    #[error("failed to generate nonce")]
    ErrFailedToGenerateNonce,
    /// Failed to send error message.
    #[error("failed to send error message")]
    ErrFailedToSendError,
    /// Duplicated Nonce generated, discarding request.
    #[error("duplicated Nonce generated, discarding request")]
    ErrDuplicatedNonce,
    /// No such user exists.
    #[error("no such user exists")]
    ErrNoSuchUser,
    /// Unexpected class.
    #[error("unexpected class")]
    ErrUnexpectedClass,
    /// Unexpected method.
    #[error("unexpected method")]
    ErrUnexpectedMethod,
    /// Failed to handle.
    #[error("failed to handle")]
    ErrFailedToHandle,
    /// Unhandled STUN packet.
    #[error("unhandled STUN packet")]
    ErrUnhandledStunpacket,
    /// Unable to handle ChannelData.
    #[error("unable to handle ChannelData")]
    ErrUnableToHandleChannelData,
    /// Failed to create STUN message from packet.
    #[error("failed to create stun message from packet")]
    ErrFailedToCreateStunpacket,
    /// Failed to create channel data from packet.
    #[error("failed to create channel data from packet")]
    ErrFailedToCreateChannelData,
    /// Relay already allocated for 5-TUPLE.
    #[error("relay already allocated for 5-TUPLE")]
    ErrRelayAlreadyAllocatedForFiveTuple,
    /// RequestedTransport must be UDP.
    #[error("RequestedTransport must be UDP")]
    ErrRequestedTransportMustBeUdp,
    /// No support for DONT-FRAGMENT.
    #[error("no support for DONT-FRAGMENT")]
    ErrNoDontFragmentSupport,
    /// Request must not contain RESERVATION-TOKEN and EVEN-PORT.
    #[error("Request must not contain RESERVATION-TOKEN and EVEN-PORT")]
    ErrRequestWithReservationTokenAndEvenPort,
    /// No allocation found.
    #[error("no allocation found")]
    ErrNoAllocationFound,
    /// Unable to handle send-indication, no permission added.
    #[error("unable to handle send-indication, no permission added")]
    ErrNoPermission,
    /// Packet write smaller than packet.
    #[error("packet write smaller than packet")]
    ErrShortWrite,
    /// No such channel bind.
    #[error("no such channel bind")]
    ErrNoSuchChannelBind,
    /// Failed writing to socket.
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

    /// Failed to send packet.
    #[error("failed to send packet")]
    ErrSendPacket,
    /// Attribute not long enough to be ICE candidate.
    #[error("attribute not long enough to be ICE candidate")]
    ErrAttributeTooShortIceCandidate,
    /// Could not parse component.
    #[error("could not parse component")]
    ErrParseComponent,
    /// Could not parse priority.
    #[error("could not parse priority")]
    ErrParsePriority,
    /// Could not parse port.
    #[error("could not parse port")]
    ErrParsePort,
    /// Could not parse related addresses.
    #[error("could not parse related addresses")]
    ErrParseRelatedAddr,
    /// Could not parse type.
    #[error("could not parse type")]
    ErrParseType,
    /// Unknown candidate type.
    #[error("unknown candidate type")]
    ErrUnknownCandidateType,
    /// Failed to get XOR-MAPPED-ADDRESS response.
    #[error("failed to get XOR-MAPPED-ADDRESS response")]
    ErrGetXorMappedAddrResponse,
    /// Connection with same remote address already exists.
    #[error("connection with same remote address already exists")]
    ErrConnectionAddrAlreadyExist,
    /// Error reading streaming packet.
    #[error("error reading streaming packet")]
    ErrReadingStreamingPacket,
    /// Error writing to.
    #[error("error writing to")]
    ErrWriting,
    /// Error closing connection.
    #[error("error closing connection")]
    ErrClosingConnection,
    /// Unable to determine networkType.
    #[error("unable to determine networkType")]
    ErrDetermineNetworkType,
    /// Missing protocol scheme.
    #[error("missing protocol scheme")]
    ErrMissingProtocolScheme,
    /// Too many colons in address.
    #[error("too many colons in address")]
    ErrTooManyColonsAddr,
    /// Unexpected error trying to read.
    #[error("unexpected error trying to read")]
    ErrRead,
    /// Unknown role.
    #[error("unknown role")]
    ErrUnknownRole,
    /// Username mismatch.
    #[error("username mismatch")]
    ErrMismatchUsername,
    /// The ICE conn can't write STUN messages.
    #[error("the ICE conn can't write STUN messages")]
    ErrIceWriteStunMessage,
    /// URL parse: relative URL without a base.
    #[error("url parse: relative URL without a base")]
    ErrUrlParse,
    /// Candidate IP could not be found.
    #[error("Candidate IP could not be found")]
    ErrCandidateIpNotFound,

    // DTLS errors
    /// Conn is closed.
    #[error("conn is closed")]
    ErrConnClosed,
    /// Read/write timeout.
    #[error("read/write timeout")]
    ErrDeadlineExceeded,
    /// Context is not supported for export_keying_material.
    #[error("context is not supported for export_keying_material")]
    ErrContextUnsupported,
    /// Packet is too short.
    #[error("packet is too short")]
    ErrDtlspacketInvalidLength,
    /// Handshake is in progress.
    #[error("handshake is in progress")]
    ErrHandshakeInProgress,
    /// Invalid content type.
    #[error("invalid content type")]
    ErrInvalidContentType,
    /// Invalid mac.
    #[error("invalid mac")]
    ErrInvalidMac,
    /// Packet length and declared length do not match.
    #[error("packet length and declared length do not match")]
    ErrInvalidPacketLength,
    /// Export_keying_material can not be used with a reserved label.
    #[error("export_keying_material can not be used with a reserved label")]
    ErrReservedExportKeyingMaterial,
    /// Client sent certificate verify but we have no certificate to verify.
    #[error("client sent certificate verify but we have no certificate to verify")]
    ErrCertificateVerifyNoCertificate,
    /// Client+server do not support any shared cipher suites.
    #[error("client+server do not support any shared cipher suites")]
    ErrCipherSuiteNoIntersection,
    /// Server hello can not be created without a cipher suite.
    #[error("server hello can not be created without a cipher suite")]
    ErrCipherSuiteUnset,
    /// Client sent certificate but did not verify it.
    #[error("client sent certificate but did not verify it")]
    ErrClientCertificateNotVerified,
    /// Server required client verification, but got none.
    #[error("server required client verification, but got none")]
    ErrClientCertificateRequired,
    /// Server responded with SRTP Profile we do not support.
    #[error("server responded with SRTP Profile we do not support")]
    ErrClientNoMatchingSrtpProfile,
    /// Client required Extended Master Secret extension, but server does not support it.
    #[error("client required Extended Master Secret extension, but server does not support it")]
    ErrClientRequiredButNoServerEms,
    /// Server hello can not be created without a compression method.
    #[error("server hello can not be created without a compression method")]
    ErrCompressionMethodUnset,
    /// Client+server cookie does not match.
    #[error("client+server cookie does not match")]
    ErrCookieMismatch,
    /// Cookie must not be longer then 255 bytes.
    #[error("cookie must not be longer then 255 bytes")]
    ErrCookieTooLong,
    /// PSK Identity Hint provided but PSK is nil.
    #[error("PSK Identity Hint provided but PSK is nil")]
    ErrIdentityNoPsk,
    /// No certificate provided.
    #[error("no certificate provided")]
    ErrInvalidCertificate,
    /// Cipher spec invalid.
    #[error("cipher spec invalid")]
    ErrInvalidCipherSpec,
    /// Invalid or unknown cipher suite.
    #[error("invalid or unknown cipher suite")]
    ErrInvalidCipherSuite,
    /// Unable to determine if ClientKeyExchange is a public key or PSK Identity.
    #[error("unable to determine if ClientKeyExchange is a public key or PSK Identity")]
    ErrInvalidClientKeyExchange,
    /// Invalid or unknown compression method.
    #[error("invalid or unknown compression method")]
    ErrInvalidCompressionMethod,
    /// ECDSA signature contained zero or negative values.
    #[error("ECDSA signature contained zero or negative values")]
    ErrInvalidEcdsasignature,
    /// Invalid or unknown elliptic curve type.
    #[error("invalid or unknown elliptic curve type")]
    ErrInvalidEllipticCurveType,
    /// Invalid extension type.
    #[error("invalid extension type")]
    ErrInvalidExtensionType,
    /// Invalid hash algorithm.
    #[error("invalid hash algorithm")]
    ErrInvalidHashAlgorithm,
    /// Invalid named curve.
    #[error("invalid named curve")]
    ErrInvalidNamedCurve,
    /// Invalid private key type.
    #[error("invalid private key type")]
    ErrInvalidPrivateKey,
    /// Named curve and private key type does not match.
    #[error("named curve and private key type does not match")]
    ErrNamedCurveAndPrivateKeyMismatch,
    /// Invalid server name format.
    #[error("invalid server name format")]
    ErrInvalidSniFormat,
    /// Invalid signature algorithm.
    #[error("invalid signature algorithm")]
    ErrInvalidSignatureAlgorithm,
    /// Expected and actual key signature do not match.
    #[error("expected and actual key signature do not match")]
    ErrKeySignatureMismatch,
    /// Conn can not be created with a nil nextConn.
    #[error("Conn can not be created with a nil nextConn")]
    ErrNilNextConn,
    /// Connection can not be created, no CipherSuites satisfy this Config.
    #[error("connection can not be created, no CipherSuites satisfy this Config")]
    ErrNoAvailableCipherSuites,
    /// Connection can not be created, no SignatureScheme satisfy this Config.
    #[error("connection can not be created, no SignatureScheme satisfy this Config")]
    ErrNoAvailableSignatureSchemes,
    /// No certificates configured.
    #[error("no certificates configured")]
    ErrNoCertificates,
    /// No config provided.
    #[error("no config provided")]
    ErrNoConfigProvided,
    /// Client requested zero or more elliptic curves that are not supported by the server.
    #[error("client requested zero or more elliptic curves that are not supported by the server")]
    ErrNoSupportedEllipticCurves,
    /// Unsupported protocol version.
    #[error("unsupported protocol version")]
    ErrUnsupportedProtocolVersion,
    /// Certificate and PSK provided.
    #[error("Certificate and PSK provided")]
    ErrPskAndCertificate,
    /// PSK and PSK Identity Hint must both be set for client.
    #[error("PSK and PSK Identity Hint must both be set for client")]
    ErrPskAndIdentityMustBeSetForClient,
    /// SRTP support was requested but server did not respond with use_SRTP extension.
    #[error("SRTP support was requested but server did not respond with use_srtp extension")]
    ErrRequestedButNoSrtpExtension,
    /// Certificate is mandatory for server.
    #[error("Certificate is mandatory for server")]
    ErrServerMustHaveCertificate,
    /// Client requested SRTP but we have no matching profiles.
    #[error("client requested SRTP but we have no matching profiles")]
    ErrServerNoMatchingSrtpProfile,
    /// Server requires the Extended Master Secret extension, but the client does not support it.
    #[error(
        "server requires the Extended Master Secret extension, but the client does not support it"
    )]
    ErrServerRequiredButNoClientEms,
    /// Expected and actual verify data does not match.
    #[error("expected and actual verify data does not match")]
    ErrVerifyDataMismatch,
    /// Handshake message unset, unable to marshal.
    #[error("handshake message unset, unable to marshal")]
    ErrHandshakeMessageUnset,
    /// Invalid flight number.
    #[error("invalid flight number")]
    ErrInvalidFlight,
    /// Unable to generate key signature, unimplemented.
    #[error("unable to generate key signature, unimplemented")]
    ErrKeySignatureGenerateUnimplemented,
    /// Unable to verify key signature, unimplemented.
    #[error("unable to verify key signature, unimplemented")]
    ErrKeySignatureVerifyUnimplemented,
    /// Data length and declared length do not match.
    #[error("data length and declared length do not match")]
    ErrLengthMismatch,
    /// Buffer not long enough to contain nonce.
    #[error("buffer not long enough to contain nonce")]
    ErrNotEnoughRoomForNonce,
    /// Feature has not been implemented yet.
    #[error("feature has not been implemented yet")]
    ErrNotImplemented,
    /// Sequence number overflow.
    #[error("sequence number overflow")]
    ErrSequenceNumberOverflow,
    /// Unable to marshal fragmented handshakes.
    #[error("unable to marshal fragmented handshakes")]
    ErrUnableToMarshalFragmented,
    /// Invalid state machine transition.
    #[error("invalid state machine transition")]
    ErrInvalidFsmTransition,
    /// ApplicationData with epoch of 0.
    #[error("ApplicationData with epoch of 0")]
    ErrApplicationDataEpochZero,
    /// Unhandled contentType.
    #[error("unhandled contentType")]
    ErrUnhandledContextType,
    /// Context canceled.
    #[error("context canceled")]
    ErrContextCanceled,
    /// Empty fragment.
    #[error("empty fragment")]
    ErrEmptyFragment,
    /// Alert is Fatal or Close Notify.
    #[error("Alert is Fatal or Close Notify")]
    ErrAlertFatalOrClose,
    /// Fragment buffer overflow. New size is greater than specified max.
    #[error(
        "Fragment buffer overflow. New size {new_size} is greater than specified max {max_size}"
    )]
    ErrFragmentBufferOverflow {
        /// The size the buffer would have grown to.
        new_size: usize,
        /// The configured maximum.
        max_size: usize,
    },
    /// Client transport is not set yet.
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
    /// Raw is too small for a SCTP chunk.
    #[error("raw is too small for a SCTP chunk")]
    ErrChunkHeaderTooSmall,
    /// Not enough data left in SCTP packet to satisfy requested length.
    #[error("not enough data left in SCTP packet to satisfy requested length")]
    ErrChunkHeaderNotEnoughSpace,
    /// Chunk PADDING is non-zero at offset.
    #[error("chunk PADDING is non-zero at offset")]
    ErrChunkHeaderPaddingNonZero,
    /// Chunk has invalid length.
    #[error("chunk has invalid length")]
    ErrChunkHeaderInvalidLength,

    /// ChunkType is not of type ABORT.
    #[error("ChunkType is not of type ABORT")]
    ErrChunkTypeNotAbort,
    /// Failed build Abort Chunk.
    #[error("failed build Abort Chunk")]
    ErrBuildAbortChunkFailed,
    /// ChunkType is not of type COOKIEACK.
    #[error("ChunkType is not of type COOKIEACK")]
    ErrChunkTypeNotCookieAck,
    /// ChunkType is not of type COOKIEECHO.
    #[error("ChunkType is not of type COOKIEECHO")]
    ErrChunkTypeNotCookieEcho,
    /// ChunkType is not of type ctError.
    #[error("ChunkType is not of type ctError")]
    ErrChunkTypeNotCt,
    /// Failed build Error Chunk.
    #[error("failed build Error Chunk")]
    ErrBuildErrorChunkFailed,
    /// Failed to marshal stream.
    #[error("failed to marshal stream")]
    ErrMarshalStreamFailed,
    /// Chunk too short.
    #[error("chunk too short")]
    ErrChunkTooShort,
    /// ChunkType is not of type ForwardTsn.
    #[error("ChunkType is not of type ForwardTsn")]
    ErrChunkTypeNotForwardTsn,
    /// ChunkType is not of type HEARTBEAT.
    #[error("ChunkType is not of type HEARTBEAT")]
    ErrChunkTypeNotHeartbeat,
    /// ChunkType is not of type HEARTBEATACK.
    #[error("ChunkType is not of type HEARTBEATACK")]
    ErrChunkTypeNotHeartbeatAck,
    /// Heartbeat is not long enough to contain Heartbeat Info.
    #[error("heartbeat is not long enough to contain Heartbeat Info")]
    ErrHeartbeatNotLongEnoughInfo,
    /// Failed to parse param type.
    #[error("failed to parse param type")]
    ErrParseParamTypeFailed,
    /// Heartbeat should only have HEARTBEAT param.
    #[error("heartbeat should only have HEARTBEAT param")]
    ErrHeartbeatParam,
    /// Failed unmarshalling param in Heartbeat Chunk.
    #[error("failed unmarshalling param in Heartbeat Chunk")]
    ErrHeartbeatChunkUnmarshal,
    /// Unimplemented.
    #[error("unimplemented")]
    ErrUnimplemented,
    /// Heartbeat Ack must have one param.
    #[error("heartbeat Ack must have one param")]
    ErrHeartbeatAckParams,
    /// Heartbeat Ack must have one param, and it should be a HeartbeatInfo.
    #[error("heartbeat Ack must have one param, and it should be a HeartbeatInfo")]
    ErrHeartbeatAckNotHeartbeatInfo,
    /// Unable to marshal parameter for Heartbeat Ack.
    #[error("unable to marshal parameter for Heartbeat Ack")]
    ErrHeartbeatAckMarshalParam,

    /// Raw is too small for error cause.
    #[error("raw is too small for error cause")]
    ErrErrorCauseTooSmall,

    /// Unhandled ParamType.
    #[error("unhandled ParamType: {typ}")]
    ErrParamTypeUnhandled {
        /// The raw parameter type that was not recognised.
        typ: u16,
    },

    /// Unexpected ParamType.
    #[error("unexpected ParamType")]
    ErrParamTypeUnexpected,

    /// Param header too short.
    #[error("param header too short")]
    ErrParamHeaderTooShort,
    /// Param self reported length is shorter than header length.
    #[error("param self reported length is shorter than header length")]
    ErrParamHeaderSelfReportedLengthShorter,
    /// Param self reported length is longer than header length.
    #[error("param self reported length is longer than header length")]
    ErrParamHeaderSelfReportedLengthLonger,
    /// Failed to parse param type.
    #[error("failed to parse param type")]
    ErrParamHeaderParseFailed,

    /// Packet to short.
    #[error("packet to short")]
    ErrParamPacketTooShort,
    /// Outgoing SSN reset request parameter too short.
    #[error("outgoing SSN reset request parameter too short")]
    ErrSsnResetRequestParamTooShort,
    /// Failed unmarshalling SSN reset request parameter in RE-CONFIG chunk.
    #[error("failed unmarshalling SSN reset request parameter in RE-CONFIG chunk")]
    ErrUnmarshalSsnResetRequestParam,
    /// Reconfig response parameter too short.
    #[error("reconfig response parameter too short")]
    ErrReconfigRespParamTooShort,
    /// Failed unmarshalling re-configuration response parameter in RE-CONFIG chunk.
    #[error("failed unmarshalling re-configuration response parameter in RE-CONFIG chunk")]
    ErrUnmarshalReconfigRespParam,
    /// Invalid algorithm type.
    #[error("invalid algorithm type")]
    ErrInvalidAlgorithmType,

    /// Failed to parse param type.
    #[error("failed to parse param type")]
    ErrInitChunkParseParamTypeFailed,
    /// Failed unmarshalling param in Init Chunk.
    #[error("failed unmarshalling param in Init Chunk")]
    ErrInitChunkUnmarshalParam,
    /// Unable to marshal parameter for INIT/INITACK.
    #[error("unable to marshal parameter for INIT/INITACK")]
    ErrInitAckMarshalParam,

    /// ChunkType is not of type INIT.
    #[error("ChunkType is not of type INIT")]
    ErrChunkTypeNotTypeInit,
    /// Chunk Value isn't long enough for mandatory parameters exp.
    #[error("chunk Value isn't long enough for mandatory parameters exp")]
    ErrChunkValueNotLongEnough,
    /// ChunkType of type INIT flags must be all 0.
    #[error("ChunkType of type INIT flags must be all 0")]
    ErrChunkTypeInitFlagZero,
    /// Failed to unmarshal INIT body.
    #[error("failed to unmarshal INIT body")]
    ErrChunkTypeInitUnmarshalFailed,
    /// Failed marshaling INIT common data.
    #[error("failed marshaling INIT common data")]
    ErrChunkTypeInitMarshalFailed,
    /// ChunkType of type INIT ACK InitiateTag must not be 0.
    #[error("ChunkType of type INIT ACK InitiateTag must not be 0")]
    ErrChunkTypeInitInitiateTagZero,
    /// INIT ACK inbound stream request must be > 0.
    #[error("INIT ACK inbound stream request must be > 0")]
    ErrInitInboundStreamRequestZero,
    /// INIT ACK outbound stream request must be > 0.
    #[error("INIT ACK outbound stream request must be > 0")]
    ErrInitOutboundStreamRequestZero,
    /// INIT ACK Advertised Receiver Window Credit (a_rwnd) must be >= 1500.
    #[error("INIT ACK Advertised Receiver Window Credit (a_rwnd) must be >= 1500")]
    ErrInitAdvertisedReceiver1500,

    /// Packet is smaller than the header size.
    #[error("packet is smaller than the header size")]
    ErrChunkPayloadSmall,
    /// ChunkType is not of type PayloadData.
    #[error("ChunkType is not of type PayloadData")]
    ErrChunkTypeNotPayloadData,
    /// Failed unmarshalling payload data chunk.
    #[error("failed unmarshalling payload data chunk")]
    ErrChunkUnmarshalPayloadData,
    /// ChunkType is not of type Reconfig.
    #[error("ChunkType is not of type Reconfig")]
    ErrChunkTypeNotReconfig,
    /// ChunkReconfig has invalid ParamA.
    #[error("ChunkReconfig has invalid ParamA")]
    ErrChunkReconfigInvalidParamA,

    /// Failed to parse param type.
    #[error("failed to parse param type")]
    ErrChunkParseParamTypeFailed,
    /// Unable to marshal parameter A for reconfig.
    #[error("unable to marshal parameter A for reconfig")]
    ErrChunkMarshalParamAReconfigFailed,
    /// Unable to marshal parameter B for reconfig.
    #[error("unable to marshal parameter B for reconfig")]
    ErrChunkMarshalParamBReconfigFailed,

    /// ChunkType is not of type SACK.
    #[error("ChunkType is not of type SACK")]
    ErrChunkTypeNotSack,
    /// SACK Chunk size is not large enough to contain header.
    #[error("SACK Chunk size is not large enough to contain header")]
    ErrSackSizeNotLargeEnoughInfo,
    /// Failed unmarshalling SACK chunk.
    #[error("failed unmarshalling SACK chunk")]
    ErrChunkUnmarshalSack,

    /// Invalid chunk size.
    #[error("invalid chunk size")]
    ErrInvalidChunkSize,
    /// ChunkType is not of type SHUTDOWN.
    #[error("ChunkType is not of type SHUTDOWN")]
    ErrChunkTypeNotShutdown,
    /// Failed unmarshalling shutdown chunk.
    #[error("failed unmarshalling shutdown chunk")]
    ErrChunkUnmarshalShutdown,

    /// ChunkType is not of type SHUTDOWN-ACK.
    #[error("ChunkType is not of type SHUTDOWN-ACK")]
    ErrChunkTypeNotShutdownAck,
    /// ChunkType is not of type SHUTDOWN-COMPLETE.
    #[error("ChunkType is not of type SHUTDOWN-COMPLETE")]
    ErrChunkTypeNotShutdownComplete,

    /// Raw is smaller than the minimum length for a SCTP packet.
    #[error("raw is smaller than the minimum length for a SCTP packet")]
    ErrPacketRawTooSmall,
    /// Unable to parse SCTP chunk, not enough data for complete header.
    #[error("unable to parse SCTP chunk, not enough data for complete header")]
    ErrParseSctpChunkNotEnoughData,
    /// Failed to unmarshal, contains unknown chunk type.
    #[error("failed to unmarshal, contains unknown chunk type")]
    ErrUnmarshalUnknownChunkType,
    /// Checksum mismatch theirs.
    #[error("checksum mismatch theirs")]
    ErrChecksumMismatch,

    /// Unexpected chunk popped (unordered).
    #[error("unexpected chunk popped (unordered)")]
    ErrUnexpectedChuckPoppedUnordered,
    /// Unexpected chunk popped (ordered).
    #[error("unexpected chunk popped (ordered)")]
    ErrUnexpectedChuckPoppedOrdered,
    /// Unexpected q state (should've been selected).
    #[error("unexpected q state (should've been selected)")]
    ErrUnexpectedQState,
    /// Try again.
    #[error("try again")]
    ErrTryAgain,

    /// Abort chunk, with following errors.
    #[error("abort chunk, with following errors: {0}")]
    ErrAbortChunk(String),
    /// Shutdown called in non-Established state.
    #[error("shutdown called in non-Established state")]
    ErrShutdownNonEstablished,
    /// Association closed before connecting.
    #[error("association closed before connecting")]
    ErrAssociationClosedBeforeConn,
    /// Association init failed.
    #[error("association init failed")]
    ErrAssociationInitFailed,
    /// Association handshake closed.
    #[error("association handshake closed")]
    ErrAssociationHandshakeClosed,
    /// Silently discard.
    #[error("silently discard")]
    ErrSilentlyDiscard,
    /// The init not stored to send.
    #[error("the init not stored to send")]
    ErrInitNotStoredToSend,
    /// CookieEcho not stored to send.
    #[error("cookieEcho not stored to send")]
    ErrCookieEchoNotStoredToSend,
    /// SCTP packet must not have a source port of 0.
    #[error("sctp packet must not have a source port of 0")]
    ErrSctpPacketSourcePortZero,
    /// SCTP packet must not have a destination port of 0.
    #[error("sctp packet must not have a destination port of 0")]
    ErrSctpPacketDestinationPortZero,
    /// Init chunk must not be bundled with any other chunk.
    #[error("init chunk must not be bundled with any other chunk")]
    ErrInitChunkBundled,
    /// Init chunk expects a verification tag of 0 on the packet when out-of-the-blue.
    #[error("init chunk expects a verification tag of 0 on the packet when out-of-the-blue")]
    ErrInitChunkVerifyTagNotZero,
    /// Todo: handle Init when in state.
    #[error("todo: handle Init when in state")]
    ErrHandleInitState,
    /// No cookie in InitAck.
    #[error("no cookie in InitAck")]
    ErrInitAckNoCookie,
    /// There already exists a stream with identifier.
    #[error("there already exists a stream with identifier")]
    ErrStreamAlreadyExist,
    /// Failed to create a stream with identifier.
    #[error("Failed to create a stream with identifier")]
    ErrStreamCreateFailed,
    /// Unable to be popped from inflight queue TSN.
    #[error("unable to be popped from inflight queue TSN")]
    ErrInflightQueueTsnPop,
    /// Requested non-existent TSN.
    #[error("requested non-existent TSN")]
    ErrTsnRequestNotExist,
    /// Sending reset packet in non-Established state.
    #[error("sending reset packet in non-Established state")]
    ErrResetPacketInStateNotExist,
    /// Unexpected parameter type.
    #[error("unexpected parameter type")]
    ErrParameterType,
    /// Sending payload data in non-Established state.
    #[error("sending payload data in non-Established state")]
    ErrPayloadDataStateNotExist,
    /// Unhandled chunk type.
    #[error("unhandled chunk type")]
    ErrChunkTypeUnhandled,
    /// Handshake failed (INIT ACK).
    #[error("handshake failed (INIT ACK)")]
    ErrHandshakeInitAck,
    /// Handshake failed (COOKIE ECHO).
    #[error("handshake failed (COOKIE ECHO)")]
    ErrHandshakeCookieEcho,

    /// Outbound packet larger than maximum message size.
    #[error("outbound packet larger than maximum message size")]
    ErrOutboundPacketTooLarge,
    /// Stream closed.
    #[error("Stream closed")]
    ErrStreamClosed,
    /// Stream not existed.
    #[error("Stream not existed")]
    ErrStreamNotExisted,
    /// Association not existed.
    #[error("Association not existed")]
    ErrAssociationNotExisted,
    /// Transport not existed.
    #[error("Transport not existed")]
    ErrTransportNoExisted,
    /// Io EOF.
    #[error("Io EOF")]
    ErrEof,
    /// Invalid SystemTime.
    #[error("Invalid SystemTime")]
    ErrInvalidSystemTime,
    /// Net Conn read error.
    #[error("Net Conn read error")]
    ErrNetConnRead,
    /// Max Data Channel ID.
    #[error("Max Data Channel ID")]
    ErrMaxDataChannelID,

    //Data Channel
    /// DataChannel message is not long enough to determine type: (expected: , actual: ).
    #[error(
        "DataChannel message is not long enough to determine type: (expected: {expected}, actual: {actual})"
    )]
    UnexpectedEndOfBuffer {
        /// The number of bytes the parser required.
        expected: usize,
        /// The number of bytes actually available.
        actual: usize,
    },
    /// Unknown MessageType.
    #[error("Unknown MessageType {0}")]
    InvalidMessageType(u8),
    /// Unknown ChannelType.
    #[error("Unknown ChannelType {0}")]
    InvalidChannelType(u8),
    /// Unknown PayloadProtocolIdentifier.
    #[error("Unknown PayloadProtocolIdentifier {0}")]
    InvalidPayloadProtocolIdentifier(u8),
    /// Unknow Protocol.
    #[error("Unknow Protocol")]
    UnknownProtocol,

    //Media
    /// Stream is nil.
    #[error("stream is nil")]
    ErrNilStream,
    /// Incomplete frame header.
    #[error("incomplete frame header")]
    ErrIncompleteFrameHeader,
    /// Incomplete frame data.
    #[error("incomplete frame data")]
    ErrIncompleteFrameData,
    /// Incomplete file header.
    #[error("incomplete file header")]
    ErrIncompleteFileHeader,
    /// IVF signature mismatch.
    #[error("IVF signature mismatch")]
    ErrSignatureMismatch,
    /// IVF version unknown, parser may not parse correctly.
    #[error("IVF version unknown, parser may not parse correctly")]
    ErrUnknownIVFVersion,

    /// File not opened.
    #[error("file not opened")]
    ErrFileNotOpened,
    /// Invalid nil packet.
    #[error("invalid nil packet")]
    ErrInvalidNilPacket,

    /// Bad header signature.
    #[error("bad header signature")]
    ErrBadIDPageSignature,
    /// Wrong header, expected beginning of stream.
    #[error("wrong header, expected beginning of stream")]
    ErrBadIDPageType,
    /// Payload for id page must be 19 bytes.
    #[error("payload for id page must be 19 bytes")]
    ErrBadIDPageLength,
    /// Bad payload signature.
    #[error("bad payload signature")]
    ErrBadIDPagePayloadSignature,
    /// Not enough data for payload header.
    #[error("not enough data for payload header")]
    ErrShortPageHeader,
    /// Bad OpusTags signature.
    #[error("bad OpusTags signature")]
    ErrBadOpusTagsSignature,
    /// Unsupported channel mapping family.
    #[error("unsupported channel mapping family")]
    ErrUnsupportedChannelMappingFamily,

    /// Data is not a H264 bitstream.
    #[error("data is not a H264 bitstream")]
    ErrDataIsNotH264Stream,
    /// Data is not a H265 bitstream.
    #[error("data is not a H265 bitstream")]
    ErrDataIsNotH265Stream,
    /// Io EOF.
    #[error("Io EOF")]
    ErrIoEOF,

    // mDNS
    /// MDNS: port not support, only 5353 is supported.
    #[error("mDNS: port not support, only 5353 is supported")]
    ErrMDNSPortNotSupported,
    /// MDNS: connection is closed.
    #[error("mDNS: connection is closed")]
    ErrMDNSConnectionClosed,
    /// MDNS: query not found.
    #[error("mDNS: query not found")]
    ErrMDNSQueryNotFound,
    /// MDNS: parsing/packing of this type isn't available yet.
    #[error("mDNS: parsing/packing of this type isn't available yet")]
    ErrNotStarted,
    /// MDNS: parsing/packing of this section has completed.
    #[error("mDNS: parsing/packing of this section has completed")]
    ErrSectionDone,
    /// MDNS: parsing/packing of this section is header.
    #[error("mDNS: parsing/packing of this section is header")]
    ErrSectionHeader,
    /// MDNS: insufficient data for base length type.
    #[error("mDNS: insufficient data for base length type")]
    ErrBaseLen,
    /// MDNS: insufficient data for calculated length type.
    #[error("mDNS: insufficient data for calculated length type")]
    ErrCalcLen,
    /// MDNS: segment prefix is reserved.
    #[error("mDNS: segment prefix is reserved")]
    ErrReserved,
    /// MDNS: too many pointers (>10).
    #[error("mDNS: too many pointers (>10)")]
    ErrTooManyPtr,
    /// MDNS: invalid pointer.
    #[error("mDNS: invalid pointer")]
    ErrInvalidPtr,
    /// MDNS: nil resource body.
    #[error("mDNS: nil resource body")]
    ErrNilResourceBody,
    /// MDNS: insufficient data for resource body length.
    #[error("mDNS: insufficient data for resource body length")]
    ErrResourceLen,
    /// MDNS: segment length too long.
    #[error("mDNS: segment length too long")]
    ErrSegTooLong,
    /// MDNS: zero length segment.
    #[error("mDNS: zero length segment")]
    ErrZeroSegLen,
    /// MDNS: resource length too long.
    #[error("mDNS: resource length too long")]
    ErrResTooLong,
    /// MDNS: too many Questions to pack (>65535).
    #[error("mDNS: too many Questions to pack (>65535)")]
    ErrTooManyQuestions,
    /// MDNS: too many Answers to pack (>65535).
    #[error("mDNS: too many Answers to pack (>65535)")]
    ErrTooManyAnswers,
    /// MDNS: too many Authorities to pack (>65535).
    #[error("mDNS: too many Authorities to pack (>65535)")]
    ErrTooManyAuthorities,
    /// MDNS: too many Additionals to pack (>65535).
    #[error("mDNS: too many Additionals to pack (>65535)")]
    ErrTooManyAdditionals,
    /// MDNS: name is not in canonical format (it must end with a .).
    #[error("mDNS: name is not in canonical format (it must end with a .)")]
    ErrNonCanonicalName,
    /// MDNS: character string exceeds maximum length (255).
    #[error("mDNS: character string exceeds maximum length (255)")]
    ErrStringTooLong,
    /// MDNS: compressed name in SRV resource data.
    #[error("mDNS: compressed name in SRV resource data")]
    ErrCompressedSrv,
    /// MDNS: empty builder msg.
    #[error("mDNS: empty builder msg")]
    ErrEmptyBuilderMsg,

    //RTC
    /// ErrConnectionClosed indicates an operation executed after connection
    /// has already been closed.
    #[error("connection closed")]
    ErrConnectionClosed,

    /// ErrDataChannelClosed indicates an operation executed when the data
    /// channel is not (yet) open or closed.
    #[error("data channel closed")]
    ErrDataChannelClosed,

    /// ErrDataChannelNotOpen indicates a send was attempted on a data channel
    /// whose underlying SCTP stream has not been established yet — its
    /// `ready_state` is still `connecting`. Wait for the channel to open.
    #[error("data channel is not open yet")]
    ErrDataChannelNotOpen,

    /// ErrDataChannelNonExist indicates an operation executed when the data
    /// channel not existed.
    #[error("data channel not existed")]
    ErrDataChannelNotExisted,

    /// ErrSendBufferFull indicates that a data-channel send was rejected because
    /// the channel's outstanding send buffer exceeded the configured hard ceiling
    /// (back-pressure). Retry after the buffer drains (e.g. on OnBufferedAmountLow).
    #[error("data channel send buffer full")]
    ErrSendBufferFull,

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

    /// ErrExistingTrack indicates that a track already exists.
    #[error("track not existed")]
    ErrTrackNotExisted,

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

    /// Invalid state error.
    #[error("Invalid state error")]
    InvalidStateError,

    /// Invalid modification error.
    #[error("Invalid modification error")]
    InvalidModificationError,

    /// Range error.
    #[error("Range error {0}")]
    RangeError(String),

    /// ErrSenderWithNoCodecs indicates that a RTPSender was created without any codecs. To send media the MediaEngine needs at
    /// least one configured codec.
    #[error("unable to populate media section, RTPSender created with no codecs")]
    ErrSenderWithNoCodecs,

    /// ErrSenderWithNoSSRCs indicates that a RTPSender was created without any SSRRs. To send media the Sender needs at
    /// least one configured ssrc.
    #[error("unable to populate media section, RTPSender created with no ssrcs")]
    ErrSenderWithNoSSRCs,

    /// ErrRTPSenderNewTrackHasIncorrectKind indicates that the new track is of a different kind than the previous/original
    #[error("new track must be of the same kind as previous")]
    ErrRTPSenderNewTrackHasIncorrectKind,

    /// New track has incorrect envelope.
    #[error("new track has incorrect envelope")]
    ErrRTPSenderNewTrackHasIncorrectEnvelope,

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

    /// Invalid direction.
    #[error("invalid direction")]
    ErrInvalidDirection,

    /// ErrRegisterHeaderExtensionNoFreeID indicates that there was no extension ID available which
    /// in turn means that all 15 available id(1 through 14) have been used.
    #[error(
        "no header extension ID was free to use(this means the maximum of 15 extensions have been registered)"
    )]
    ErrRegisterHeaderExtensionNoFreeID,

    /// ErrSimulcastProbeOverflow indicates that too many Simulcast probe streams are in flight and the requested SSRC was ignored
    #[error("simulcast probe limit has been reached, new SSRC has been discarded")]
    ErrSimulcastProbeOverflow,

    /// Enable detaching by calling webrtc.DetachDataChannels.
    #[error("enable detaching by calling webrtc.DetachDataChannels()")]
    ErrDetachNotEnabled,
    /// Datachannel not opened yet, try calling Detach from OnOpen.
    #[error("datachannel not opened yet, try calling Detach from OnOpen")]
    ErrDetachBeforeOpened,
    /// The DTLS transport has not started yet.
    #[error("the DTLS transport has not started yet")]
    ErrDtlsTransportNotStarted,
    /// Failed extracting keys from DTLS for SRTP.
    #[error("failed extracting keys from DTLS for SRTP")]
    ErrDtlsKeyExtractionFailed,
    /// Failed to start SRTP.
    #[error("failed to start SRTP")]
    ErrFailedToStartSRTP,
    /// Failed to start SRTCP.
    #[error("failed to start SRTCP")]
    ErrFailedToStartSRTCP,
    /// Attempted to start DTLSTransport that is not in new state.
    #[error("attempted to start DTLSTransport that is not in new state")]
    ErrInvalidDTLSStart,
    /// Peer didn't provide certificate via DTLS.
    #[error("peer didn't provide certificate via DTLS")]
    ErrNoRemoteCertificate,
    /// Identity provider is not implemented.
    #[error("identity provider is not implemented")]
    ErrIdentityProviderNotImplemented,
    /// Remote certificate does not match any fingerprint.
    #[error("remote certificate does not match any fingerprint")]
    ErrNoMatchingCertificateFingerprint,
    /// Unsupported fingerprint algorithm.
    #[error("unsupported fingerprint algorithm")]
    ErrUnsupportedFingerprintAlgorithm,
    /// ICE connection not started.
    #[error("ICE connection not started")]
    ErrICEConnectionNotStarted,
    /// Unknown candidate type.
    #[error("unknown candidate type")]
    ErrICECandidateTypeUnknown,
    /// Cannot convert ICE.CandidateType into webrtc.ICECandidateType, invalid type.
    #[error("cannot convert ice.CandidateType into webrtc.ICECandidateType, invalid type")]
    ErrICEInvalidConvertCandidateType,
    /// ICEAgent does not exist.
    #[error("ICEAgent does not exist")]
    ErrICEAgentNotExist,
    /// Unable to convert ICE candidates to ICECandidates.
    #[error("unable to convert ICE candidates to ICECandidates")]
    ErrICECandidatesConversionFailed,
    /// Unknown ICE Role.
    #[error("unknown ICE Role")]
    ErrICERoleUnknown,
    /// Unknown protocol.
    #[error("unknown protocol")]
    ErrICEProtocolUnknown,
    /// Gatherer not started.
    #[error("gatherer not started")]
    ErrICEGathererNotStarted,
    /// Unknown network type.
    #[error("unknown network type")]
    ErrNetworkTypeUnknown,
    /// New SDP does not match previous offer.
    #[error("new sdp does not match previous offer")]
    ErrSDPDoesNotMatchOffer,
    /// New SDP does not match previous answer.
    #[error("new sdp does not match previous answer")]
    ErrSDPDoesNotMatchAnswer,
    /// Provided value is not a valid enum value of type SDPType.
    #[error("provided value is not a valid enum value of type SDPType")]
    ErrPeerConnSDPTypeInvalidValue,
    /// Invalid state change op.
    #[error("invalid state change op")]
    ErrPeerConnStateChangeInvalid,
    /// Unhandled state change op.
    #[error("unhandled state change op")]
    ErrPeerConnStateChangeUnhandled,
    /// Invalid SDP type supplied to SetLocalDescription.
    #[error("invalid SDP type supplied to SetLocalDescription()")]
    ErrPeerConnSDPTypeInvalidValueSetLocalDescription,
    /// RemoteDescription contained media section without mid value.
    #[error("remoteDescription contained media section without mid value")]
    ErrPeerConnRemoteDescriptionWithoutMidValue,
    /// LocalDescription contained media section without mid value.
    #[error("localDescription contained media section without mid value")]
    ErrPeerConnLocalDescriptionWithoutMidValue,
    /// RemoteDescription has not been set yet.
    #[error("remoteDescription has not been set yet")]
    ErrPeerConnRemoteDescriptionNil,
    /// LocalDescription has not been set yet.
    #[error("localDescription has not been set yet")]
    ErrPeerConnLocalDescriptionNil,
    /// Single media section has an explicit SSRC.
    #[error("single media section has an explicit SSRC")]
    ErrPeerConnSingleMediaSectionHasExplicitSSRC,
    /// Could not add transceiver for remote SSRC.
    #[error("could not add transceiver for remote SSRC")]
    ErrPeerConnRemoteSSRCAddTransceiver,
    /// Mid RTP Extensions required for Simulcast.
    #[error("mid RTP Extensions required for Simulcast")]
    ErrPeerConnSimulcastMidRTPExtensionRequired,
    /// Stream id RTP Extensions required for Simulcast.
    #[error("stream id RTP Extensions required for Simulcast")]
    ErrPeerConnSimulcastStreamIDRTPExtensionRequired,
    /// Incoming SSRC failed Simulcast probing.
    #[error("incoming SSRC failed Simulcast probing")]
    ErrPeerConnSimulcastIncomingSSRCFailed,
    /// Failed collecting stats.
    #[error("failed collecting stats")]
    ErrPeerConnStatsCollectionFailed,
    /// Add_transceiver_from_kind only accepts one RTPTransceiverInit.
    #[error("add_transceiver_from_kind only accepts one RTPTransceiverInit")]
    ErrPeerConnAddTransceiverFromKindOnlyAcceptsOne,
    /// Add_transceiver_from_track only accepts one RTPTransceiverInit.
    #[error("add_transceiver_from_track only accepts one RTPTransceiverInit")]
    ErrPeerConnAddTransceiverFromTrackOnlyAcceptsOne,
    /// Add_transceiver_from_kind currently only supports recvonly.
    #[error("add_transceiver_from_kind currently only supports recvonly")]
    ErrPeerConnAddTransceiverFromKindSupport,
    /// Add_transceiver_from_track currently only supports sendonly and sendrecv.
    #[error("add_transceiver_from_track currently only supports sendonly and sendrecv")]
    ErrPeerConnAddTransceiverFromTrackSupport,
    /// TODO set_identity_provider.
    #[error("TODO set_identity_provider")]
    ErrPeerConnSetIdentityProviderNotImplemented,
    /// Write_RTCP failed to open write_stream.
    #[error("write_rtcp failed to open write_stream")]
    ErrPeerConnWriteRTCPOpenWriteStream,
    /// Cannot find transceiver with mid.
    #[error("cannot find transceiver with mid")]
    ErrPeerConnTransceiverMidNil,
    /// DTLSTransport must not be nil.
    #[error("DTLSTransport must not be nil")]
    ErrRTPReceiverDTLSTransportNil,
    /// Receive has already been called.
    #[error("Receive has already been called")]
    ErrRTPReceiverReceiveAlreadyCalled,
    /// Unable to find stream for Track with SSRC.
    #[error("unable to find stream for Track with SSRC")]
    ErrRTPReceiverWithSSRCTrackStreamNotFound,
    /// No trackStreams found for SSRC.
    #[error("no trackStreams found for SSRC")]
    ErrRTPReceiverForSSRCTrackStreamNotFound,
    /// No trackStreams found for RID.
    #[error("no trackStreams found for RID")]
    ErrRTPReceiverForRIDTrackStreamNotFound,
    /// Invalid RTP Receiver transition.
    #[error("invalid RTP Receiver transition")]
    ErrRTPReceiverStateChangeInvalid,
    /// Track must not be nil.
    #[error("Track must not be nil")]
    ErrRTPSenderTrackNil,
    /// RTPSender not existed.
    #[error("RTPSender not existed")]
    ErrRTPSenderNotExisted,
    /// Sender Track has been removed or replaced to nil.
    #[error("Sender Track has been removed or replaced to nil")]
    ErrRTPSenderTrackRemoved,
    /// Sender cannot add encoding as rid is empty.
    #[error("Sender cannot add encoding as rid is empty")]
    ErrRTPSenderRidNil,
    /// Sender cannot add encoding as there is no base track.
    #[error("Sender cannot add encoding as there is no base track")]
    ErrRTPSenderNoBaseEncoding,
    /// Sender cannot add encoding as provided track does not match base track.
    #[error("Sender cannot add encoding as provided track does not match base track")]
    ErrRTPSenderBaseEncodingMismatch,
    /// Sender cannot encoding due to RID collision.
    #[error("Sender cannot encoding due to RID collision")]
    ErrRTPSenderRIDCollision,
    /// Sender does not have track for RID.
    #[error("Sender does not have track for RID")]
    ErrRTPSenderNoTrackForRID,
    /// RTPReceiver not existed.
    #[error("RTPReceiver not existed")]
    ErrRTPReceiverNotExisted,
    /// DTLSTransport must not be nil.
    #[error("DTLSTransport must not be nil")]
    ErrRTPSenderDTLSTransportNil,
    /// Send has already been called.
    #[error("Send has already been called")]
    ErrRTPSenderSendAlreadyCalled,
    /// RTPTransceiver not existed.
    #[error("RTPTransceiver not existed")]
    ErrRTPTransceiverNotExisted,
    /// ErrRTPSenderTrackNil.
    #[error("errRTPSenderTrackNil")]
    ErrRTPTransceiverCannotChangeMid,
    /// Invalid state change in RTPTransceiver.setSending.
    #[error("invalid state change in RTPTransceiver.setSending")]
    ErrRTPTransceiverSetSendingInvalidState,
    /// Unsupported codec type by this transceiver.
    #[error("unsupported codec type by this transceiver")]
    ErrRTPTransceiverCodecUnsupported,
    /// DTLS not established.
    #[error("DTLS not established")]
    ErrSCTPTransportDTLS,
    /// Add_transceiver_SDP called with 0 transceivers.
    #[error("add_transceiver_sdp() called with 0 transceivers")]
    ErrSDPZeroTransceivers,
    /// Invalid Media Section. Media + DataChannel both enabled.
    #[error("invalid Media Section. Media + DataChannel both enabled")]
    ErrSDPMediaSectionMediaDataChanInvalid,
    /// Invalid Media Section Track Index.
    #[error("invalid Media Section Track Index")]
    ErrSDPMediaSectionTrackInvalid,
    /// Set_answering_dtlsrole must DTLSRoleClient or DTLSRoleServer.
    #[error("set_answering_dtlsrole must DTLSRoleClient or DTLSRoleServer")]
    ErrSettingEngineSetAnsweringDTLSRole,
    /// Can't rollback from stable state.
    #[error("can't rollback from stable state")]
    ErrSignalingStateCannotRollback,
    /// Invalid proposed signaling state transition.
    #[error("invalid proposed signaling state transition: {0}")]
    ErrSignalingStateProposedTransitionInvalid(String),
    /// Cannot convert to StatsICECandidatePairStateSucceeded invalid ICE candidate state.
    #[error("cannot convert to StatsICECandidatePairStateSucceeded invalid ice candidate state")]
    ErrStatsICECandidateStateInvalid,
    /// ICETransport can only be called in ICETransportStateNew.
    #[error("ICETransport can only be called in ICETransportStateNew")]
    ErrICETransportNotInNew,
    /// Bad Certificate PEM format.
    #[error("bad Certificate PEM format")]
    ErrCertificatePEMFormatError,
    /// SCTP is not established.
    #[error("SCTP is not established")]
    ErrSCTPNotEstablished,

    /// DataChannel is not opened.
    #[error("DataChannel is not opened")]
    ErrClosedPipe,
    /// Interceptor is not bind.
    #[error("Interceptor is not bind")]
    ErrInterceptorNotBind,
    /// Excessive retries in CreateOffer.
    #[error("excessive retries in CreateOffer")]
    ErrExcessiveRetries,

    /// Not long enough to be a RTP Packet.
    #[error("not long enough to be a RTP Packet")]
    ErrRTPTooShort,

    /// SyntaxIdDirSplit indicates rid-syntax could not be parsed.
    #[error("RFC8851 mandates rid-syntax        = %s\"a=rid:\" rid-id SP rid-dir")]
    SimulcastRidParseErrorSyntaxIdDirSplit,
    /// UnknownDirection indicates rid-dir was not parsed. Should be "send" or "recv".
    #[error("RFC8851 mandates rid-dir           = %s\"send\" / %s\"recv\"")]
    SimulcastRidParseErrorUnknownDirection,

    //SDP
    /// Codec not found.
    #[error("codec not found")]
    CodecNotFound,
    /// Missing whitespace.
    #[error("missing whitespace")]
    MissingWhitespace,
    /// Missing colon.
    #[error("missing colon")]
    MissingColon,
    /// Payload type not found.
    #[error("payload type not found")]
    PayloadTypeNotFound,
    /// SdpInvalidSyntax.
    #[error("SdpInvalidSyntax: {0}")]
    SdpInvalidSyntax(String),
    /// SdpInvalidValue.
    #[error("SdpInvalidValue: {0}")]
    SdpInvalidValue(String),
    /// SDP: empty time_descriptions.
    #[error("sdp: empty time_descriptions")]
    SdpEmptyTimeDescription,
    /// Parse extmap.
    #[error("parse extmap: {0}")]
    ParseExtMap(String),
    /// A syntax error at a known offset in the input, rendered with the offending character marked.
    #[error("{} --> {} <-- {}", .s.substring(0,*.p), .s.substring(*.p, *.p+1), .s.substring(*.p+1, .s.len())
    )]
    SyntaxError {
        /// The input being parsed.
        s: String,
        /// The byte offset of the offending character in `s`.
        p: usize,
    },

    //Third Party Error
    /// An error from the `sec1` crate while handling EC key encodings.
    #[error("{0}")]
    Sec1(#[source] sec1::Error),
    /// An error from the `p256` crate during NIST P-256 elliptic-curve operations.
    #[error("{0}")]
    P256(#[source] P256Error),
    /// An error from the `rcgen` crate while generating a self-signed certificate.
    #[error("{0}")]
    RcGen(#[from] rcgen::Error),
    /// Invalid PEM.
    #[error("invalid PEM: {0}")]
    InvalidPEM(String),
    /// AES GCM.
    #[error("aes gcm: {0}")]
    AesGcm(#[from] aes_gcm::Error),
    /// Parse ip.
    #[error("parse ip: {0}")]
    ParseIp(#[from] net::AddrParseError),
    /// Parse int.
    #[error("parse int: {0}")]
    ParseInt(#[from] ParseIntError),
    /// An underlying I/O error.
    #[error("{0}")]
    Io(#[source] IoError),
    /// URL parse.
    #[error("url parse: {0}")]
    Url(#[from] url::ParseError),
    /// UTF-8.
    #[error("utf8: {0}")]
    Utf8(#[from] FromUtf8Error),
    /// An error from the standard library or another boxed source.
    #[error("{0}")]
    Std(#[source] StdError),
    /// An error from the `aes` crate during block-cipher setup.
    #[error("{0}")]
    Aes(#[from] aes::cipher::InvalidLength),

    //Other Errors
    /// Other RTCP Err.
    #[error("Other RTCP Err: {0}")]
    OtherRtcpErr(String),
    /// Other RTP Err.
    #[error("Other RTP Err: {0}")]
    OtherRtpErr(String),
    /// Other SRTP Err.
    #[error("Other SRTP Err: {0}")]
    OtherSrtpErr(String),
    /// Other STUN Err.
    #[error("Other STUN Err: {0}")]
    OtherStunErr(String),
    /// Other TURN Err.
    #[error("Other TURN Err: {0}")]
    OtherTurnErr(String),
    /// Other ICE Err.
    #[error("Other ICE Err: {0}")]
    OtherIceErr(String),
    /// Other DTLS Err.
    #[error("Other DTLS Err: {0}")]
    OtherDtlsErr(String),
    /// Other SCTP Err.
    #[error("Other SCTP Err: {0}")]
    OtherSctpErr(String),
    /// Other DataChannel Err.
    #[error("Other DataChannel Err: {0}")]
    OtherDataChannelErr(String),
    /// Other Interceptor Err.
    #[error("Other Interceptor Err: {0}")]
    OtherInterceptorErr(String),
    /// Other Media Err.
    #[error("Other Media Err: {0}")]
    OtherMediaErr(String),
    /// Other mDNS Err.
    #[error("Other mDNS Err: {0}")]
    OtherMdnsErr(String),
    /// Other SDP Err.
    #[error("Other SDP Err: {0}")]
    OtherSdpErr(String),
    /// Other PeerConnection Err.
    #[error("Other PeerConnection Err: {0}")]
    OtherPeerConnectionErr(String),
    #[error("{0}")]
    /// An error that does not fit any other variant, carrying a description.
    Other(String),
}

impl Error {
    /// Wraps any `std::error::Error` implementation as [`Error::Std`],
    /// preserving the original error and its stack trace.
    pub fn from_std<T>(error: T) -> Self
    where
        T: std::error::Error + Send + Sync + 'static,
    {
        Error::Std(StdError(Box::new(error)))
    }

    /// Attempts to downcast an [`Error::Std`] variant to a concrete error type.
    ///
    /// Returns `None` if this error is not `Error::Std` or if the inner error
    /// is not of type `T`.
    pub fn downcast_ref<T: std::error::Error + 'static>(&self) -> Option<&T> {
        if let Error::Std(s) = self {
            return s.0.downcast_ref();
        }

        None
    }
}

/// Wrapper around [`std::io::Error`] that implements [`PartialEq`].
///
/// `io::Error` does not implement `PartialEq`, which is required by the
/// top-level [`enum@Error`] enum. This newtype delegates equality to
/// [`io::ErrorKind`], so two `IoError` values are equal when their kinds match.
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

/// An escape hatch to preserve stack traces for errors whose concrete type is unknown.
///
/// Some traits exported by this crate (e.g. `Conn`, `Listener`) return `Error`.
/// When those traits are used in higher-level crates that have their own error
/// types, callers are forced to handle foreign errors. `StdError` boxes any
/// `std::error::Error` implementation and wraps it in `Error::Std`, preserving
/// the original error's message and — where supported — its stack trace.
///
/// Use [`Error::from_std`] to construct this variant.
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

/// Wrapper around [`p256::elliptic_curve::Error`] that implements [`PartialEq`].
///
/// `p256::elliptic_curve::Error` does not implement `PartialEq`, which is
/// required by the top-level [`enum@Error`] enum. This newtype always returns
/// `false` for equality comparisons, which is the safe conservative choice
/// for opaque cryptographic errors.
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

/// Flattens a list of errors into a single [`enum@Error`], joining their messages with newlines.
///
/// Returns `Ok(())` if `errs` is empty.
pub fn flatten_errs(errs: Vec<impl Into<Error>>) -> Result<()> {
    if errs.is_empty() {
        Ok(())
    } else {
        let errs_strs: Vec<String> = errs.into_iter().map(|e| e.into().to_string()).collect();
        Err(Error::Other(errs_strs.join("\n")))
    }
}
