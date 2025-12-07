#![warn(rust_2018_idioms)]
#![allow(dead_code)]

pub(crate) mod configs;
pub(crate) mod description;
pub(crate) mod endpoint;
pub(crate) mod handlers;
pub(crate) mod interceptors;
pub(crate) mod messages;
pub(crate) mod server;
pub(crate) mod session;
pub(crate) mod types;

pub use configs::{media_config::MediaConfig, server_config::ServerConfig};

pub use description::RTCSessionDescription;
pub use handlers::{
    datachannel::DataChannelHandler, demuxer::DemuxerHandler, dtls::DtlsHandler,
    exception::ExceptionHandler, gateway::GatewayHandler, interceptor::InterceptorHandler,
    sctp::SctpHandler, srtp::SrtpHandler, stun::StunHandler,
};
pub use server::{certificate::RTCCertificate, states::ServerStates};
