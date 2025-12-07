use crate::configs::media_config::MediaConfig;
use crate::server::certificate::RTCCertificate;
use std::sync::Arc;
use std::time::Duration;

/// ServerConfig provides customized parameters for SFU server
pub struct ServerConfig {
    pub(crate) certificates: Vec<RTCCertificate>,
    pub(crate) dtls_handshake_config: Arc<dtls::config::HandshakeConfig>,
    pub(crate) sctp_endpoint_config: Arc<sctp::EndpointConfig>,
    pub(crate) sctp_server_config: Arc<sctp::ServerConfig>,
    pub(crate) media_config: MediaConfig,
    pub(crate) idle_timeout: Duration,
}

impl ServerConfig {
    /// create new server config
    pub fn new(certificates: Vec<RTCCertificate>) -> Self {
        Self {
            certificates,
            media_config: MediaConfig::default(),
            sctp_endpoint_config: Arc::new(sctp::EndpointConfig::default()),
            sctp_server_config: Arc::new(sctp::ServerConfig::default()),
            dtls_handshake_config: Arc::new(dtls::config::HandshakeConfig::default()),
            idle_timeout: Duration::from_secs(30),
        }
    }

    /// build with provided MediaConfig
    pub fn with_media_config(mut self, media_config: MediaConfig) -> Self {
        self.media_config = media_config;
        self
    }

    /// build with provided sctp::ServerConfig
    pub fn with_sctp_server_config(mut self, sctp_server_config: Arc<sctp::ServerConfig>) -> Self {
        self.sctp_server_config = sctp_server_config;
        self
    }

    /// build with provided sctp::EndpointConfig
    pub fn with_sctp_endpoint_config(
        mut self,
        sctp_endpoint_config: Arc<sctp::EndpointConfig>,
    ) -> Self {
        self.sctp_endpoint_config = sctp_endpoint_config;
        self
    }

    /// build with provided dtls::config::HandshakeConfig
    pub fn with_dtls_handshake_config(
        mut self,
        dtls_handshake_config: Arc<dtls::config::HandshakeConfig>,
    ) -> Self {
        self.dtls_handshake_config = dtls_handshake_config;
        self
    }

    /// build with idle timeout
    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }
}
