#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use rand::{rng, Rng};

pub(crate) mod peer_connection;
//TODO: pub(crate) mod statistics;
pub(crate) mod transport;

/*
pub(crate) mod configuration;
pub(crate) mod description;
pub(crate) mod endpoint;
pub(crate) mod handler;
pub(crate) mod interceptor;
pub(crate) mod messages;
pub(crate) mod session;
pub(crate) mod state;
pub(crate) mod types;

pub use configuration::{
    client_config::ClientConfig, media_config::MediaConfig, server_config::ServerConfig,
};

pub use description::RTCSessionDescription;
pub use handler::{
    datachannel::DataChannelHandler, demuxer::DemuxerHandler, dtls::DtlsHandler,
    exception::ExceptionHandler, gateway::GatewayHandler, interceptor::InterceptorHandler,
    sctp::SctpHandler, srtp::SrtpHandler, stun::StunHandler,
};
pub use state::{certificate::RTCCertificate, server_states::ServerStates};*/

pub(crate) const RUNES_ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub(crate) const UNSPECIFIED_STR: &str = "Unspecified";

/// Equal to UDP MTU
pub(crate) const RECEIVE_MTU: usize = 1460;

pub(crate) const SDP_ATTRIBUTE_RID: &str = "rid";
pub(crate) const SDP_ATTRIBUTE_SIMULCAST: &str = "simulcast";
pub(crate) const GENERATED_CERTIFICATE_ORIGIN: &str = "WebRTC";

/// math_rand_alpha generates a mathematical random alphabet sequence of the requested length.
pub(crate) fn math_rand_alpha(n: usize) -> String {
    let mut rng = rng();

    let rand_string: String = (0..n)
        .map(|_| {
            let idx = rng.random_range(0..RUNES_ALPHA.len());
            RUNES_ALPHA[idx] as char
        })
        .collect();

    rand_string
}
