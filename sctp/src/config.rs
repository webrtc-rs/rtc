use crate::util::{AssociationIdGenerator, RandomAssociationIdGenerator};

use crate::TimerConfig;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

/// MTU for inbound packet (from DTLS)
pub(crate) const RECEIVE_MTU: usize = 8192;
/// initial MTU for outgoing packets (to DTLS)
pub(crate) const INITIAL_MTU: u32 = 1228;
pub(crate) const INITIAL_RECV_BUF_SIZE: u32 = 1024 * 1024;
pub(crate) const COMMON_HEADER_SIZE: u32 = 12;
pub(crate) const DATA_CHUNK_HEADER_SIZE: u32 = 16;
pub(crate) const DEFAULT_MAX_MESSAGE_SIZE: u32 = 262144;

/// Config collects the arguments to create_association construction into
/// a single structure
#[derive(Debug)]
pub struct TransportConfig {
    sctp_port: u16,
    max_receive_buffer_size: u32,
    max_message_size: u32,
    max_num_outbound_streams: u16,
    max_num_inbound_streams: u16,
    timer_config: TimerConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            sctp_port: 5000,
            max_receive_buffer_size: INITIAL_RECV_BUF_SIZE,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_num_outbound_streams: u16::MAX,
            max_num_inbound_streams: u16::MAX,
            timer_config: TimerConfig::default(),
        }
    }
}

impl TransportConfig {
    pub fn with_sctp_port(mut self, value: u16) -> Self {
        self.sctp_port = value;
        self
    }

    pub fn with_max_receive_buffer_size(mut self, value: u32) -> Self {
        self.max_receive_buffer_size = value;
        self
    }

    pub fn with_max_message_size(mut self, value: u32) -> Self {
        self.max_message_size = value;
        self
    }

    pub fn with_max_num_outbound_streams(mut self, value: u16) -> Self {
        self.max_num_outbound_streams = value;
        self
    }

    pub fn with_max_num_inbound_streams(mut self, value: u16) -> Self {
        self.max_num_inbound_streams = value;
        self
    }

    pub fn with_timer_config(mut self, value: TimerConfig) -> Self {
        self.timer_config = value;
        self
    }

    pub fn sctp_port(&self) -> u16 {
        self.sctp_port
    }

    pub fn max_receive_buffer_size(&self) -> u32 {
        self.max_receive_buffer_size
    }

    pub fn max_message_size(&self) -> u32 {
        self.max_message_size
    }

    pub fn max_num_outbound_streams(&self) -> u16 {
        self.max_num_outbound_streams
    }

    pub fn max_num_inbound_streams(&self) -> u16 {
        self.max_num_inbound_streams
    }

    pub fn timer_config(&self) -> TimerConfig {
        self.timer_config
    }
}

/// Global configuration for the endpoint, affecting all associations
///
/// Default values should be suitable for most internet applications.
#[derive(Clone)]
pub struct EndpointConfig {
    pub(crate) max_payload_size: u32,

    /// AID generator factory
    ///
    /// Create a aid generator for local aid in Endpoint struct
    pub(crate) aid_generator_factory: Rc<dyn Fn() -> Box<dyn AssociationIdGenerator>>,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointConfig {
    /// Create a default config
    pub fn new() -> Self {
        let aid_factory: fn() -> Box<dyn AssociationIdGenerator> =
            || Box::<RandomAssociationIdGenerator>::default();
        Self {
            max_payload_size: INITIAL_MTU - (COMMON_HEADER_SIZE + DATA_CHUNK_HEADER_SIZE),
            aid_generator_factory: Rc::new(aid_factory),
        }
    }

    /// Supply a custom Association ID generator factory
    ///
    /// Called once by each `Endpoint` constructed from this configuration to obtain the AID
    /// generator which will be used to generate the AIDs used for incoming packets on all
    /// associations involving that  `Endpoint`. A custom AID generator allows applications to embed
    /// information in local association IDs, e.g. to support stateless packet-level load balancers.
    ///
    /// `EndpointConfig::new()` applies a default random AID generator factory. This functions
    /// accepts any customized AID generator to reset AID generator factory that implements
    /// the `AssociationIdGenerator` trait.
    pub fn aid_generator<F: Fn() -> Box<dyn AssociationIdGenerator> + 'static>(
        &mut self,
        factory: F,
    ) -> &mut Self {
        self.aid_generator_factory = Rc::new(factory);
        self
    }

    /// Maximum payload size accepted from peers.
    ///
    /// The default is suitable for typical internet applications. Applications which expect to run
    /// on networks supporting Ethernet jumbo frames or similar should set this appropriately.
    pub fn max_payload_size(&mut self, value: u32) -> &mut Self {
        self.max_payload_size = value;
        self
    }

    /// Get the current value of `max_payload_size`
    ///
    /// While most parameters don't need to be readable, this must be exposed to allow higher-level
    /// layers to determine how large a receive buffer to allocate to
    /// support an externally-defined `EndpointConfig`.
    ///
    /// While `get_` accessors are typically unidiomatic in Rust, we favor concision for setters,
    /// which will be used far more heavily.
    pub fn get_max_payload_size(&self) -> u32 {
        self.max_payload_size
    }
}

impl fmt::Debug for EndpointConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("EndpointConfig")
            .field("max_payload_size", &self.max_payload_size)
            .field("aid_generator_factory", &"[ elided ]")
            .finish()
    }
}

/// Parameters governing incoming associations
///
/// Default values should be suitable for most internet applications.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Transport configuration to use for incoming associations
    pub transport: Arc<TransportConfig>,

    /// Maximum number of concurrent associations
    pub(crate) concurrent_associations: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            transport: Arc::new(TransportConfig::default()),
            concurrent_associations: 100_000,
        }
    }
}

impl ServerConfig {
    /// Create a default config with a particular handshake token key
    pub fn new() -> Self {
        ServerConfig::default()
    }
}

/// Configuration for outgoing associations
///
/// Default values should be suitable for most internet applications.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Transport configuration to use
    pub transport: Arc<TransportConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            transport: Arc::new(TransportConfig::default()),
        }
    }
}

impl ClientConfig {
    /// Create a default config with a particular cryptographic config
    pub fn new() -> Self {
        ClientConfig::default()
    }
}
