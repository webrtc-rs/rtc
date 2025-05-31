pub(crate) const MAX_NUMERICNODE_LEN: usize = 48; // Max IPv6 string representation length
pub(crate) const MAX_NUMERICSERV_LEN: usize = 6; // Max port string representation length

pub(crate) const DEFAULT_SCTP_PORT: u16 = 5000; // SCTP port to use by default

pub(crate) const MAX_SCTP_STREAMS_COUNT: u16 = 1024; // Max number of negotiated SCTP streams
                                                     // RFC 8831 recommends 65535 but usrsctp needs a lot
                                                     // of memory, Chromium historically limits to 1024.

pub(crate) const DEFAULT_LOCAL_MAX_MESSAGE_SIZE: usize = 256 * 1024; // Default local max message size
pub(crate) const DEFAULT_REMOTE_MAX_MESSAGE_SIZE: usize = 65536; // Remote max message size if not in SDP

pub(crate) const DEFAULT_WS_MAX_MESSAGE_SIZE: usize = 256 * 1024; // Default max message size for WebSockets

pub(crate) const RECV_QUEUE_LIMIT: usize = 1024; // Max per-channel queue size (messages)

pub(crate) const MIN_THREADPOOL_SIZE: usize = 4; // Minimum number of threads in the global thread pool (>= 2)

pub(crate) const DEFAULT_MTU: usize = 1280; // defined in rtc.h
