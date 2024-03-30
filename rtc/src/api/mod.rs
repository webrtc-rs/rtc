//TODO: #[cfg(test)]
//TODO: mod api_test;

//TODO: pub mod interceptor_registry;
pub mod media_engine;
pub mod setting_engine;

/*TODO: use interceptor::registry::Registry;
use interceptor::Interceptor;*/
use crate::peer_connection::configuration::RTCConfiguration;
use crate::peer_connection::RTCPeerConnection;
use media_engine::*;
use setting_engine::*;
use std::sync::Arc;

/*TODO:use crate::transports::data_channel::data_channel_parameters::DataChannelParameters;
use crate::transports::data_channel::RTCDataChannel;
use crate::transports::dtls_transport::RTCDtlsTransport;
use crate::transports::ice_transport::ice_gatherer::{RTCIceGatherOptions, RTCIceGatherer};
use crate::transports::ice_transport::RTCIceTransport;
use crate::peer_connection::certificate::RTCCertificate;
use crate::peer_connection::configuration::RTCConfiguration;
use crate::peer_connection::RTCPeerConnection;
use crate::rtp_transceiver::rtp_codec::RTPCodecType;
use crate::rtp_transceiver::rtp_receiver::RTCRtpReceiver;
use crate::rtp_transceiver::rtp_sender::RTCRtpSender;
use crate::transports::sctp_transport::RTCSctpTransport;
use crate::track::track_local::TrackLocal;
use rcgen::KeyPair;*/
use crate::peer_connection::certificate::RTCCertificate;
use crate::transport::dtls_transport::RTCDtlsTransport;
use crate::transport::ice_transport::ice_gatherer::{RTCIceGatherOptions, RTCIceGatherer};
use crate::transport::ice_transport::RTCIceTransport;
use crate::transport::sctp_transport::RTCSctpTransport;
use shared::error::Result;

/// API bundles the global functions of the WebRTC and ORTC API.
/// Some of these functions are also exported globally using the
/// defaultAPI object. Note that the global version of the API
/// may be phased out in the future.
pub struct API {
    pub(crate) setting_engine: Arc<SettingEngine>,
    pub(crate) media_engine: MediaEngine,
    //TODO: pub(crate) interceptor_registry: Registry,
}

impl API {
    /// new_peer_connection creates a new PeerConnection with the provided configuration against the received API object
    pub fn new_peer_connection(
        &self,
        configuration: RTCConfiguration,
    ) -> Result<RTCPeerConnection> {
        RTCPeerConnection::new(self, configuration)
    }

    /// new_ice_gatherer creates a new ice gatherer.
    /// This constructor is part of the ORTC API. It is not
    /// meant to be used together with the basic WebRTC API.
    pub fn new_ice_gatherer(&self, opts: RTCIceGatherOptions) -> Result<RTCIceGatherer> {
        RTCPeerConnection::new_ice_gatherer(opts, &self.setting_engine)
    }

    /// new_ice_transport creates a new ice transport.
    /// This constructor is part of the ORTC API. It is not
    /// meant to be used together with the basic WebRTC API.
    pub fn new_ice_transport(&self, gatherer: RTCIceGatherer) -> RTCIceTransport {
        RTCPeerConnection::new_ice_transport(gatherer)
    }

    /// new_dtls_transport creates a new dtls_transport transport.
    /// This constructor is part of the ORTC API. It is not
    /// meant to be used together with the basic WebRTC API.
    pub fn new_dtls_transport(
        &self,
        certificates: Vec<RTCCertificate>,
    ) -> Result<RTCDtlsTransport> {
        RTCPeerConnection::new_dtls_transport(certificates, &self.setting_engine)
    }

    /// new_sctp_transport creates a new SCTPTransport.
    /// This constructor is part of the ORTC API. It is not
    /// meant to be used together with the basic WebRTC API.
    pub fn new_sctp_transport(&self) -> Result<RTCSctpTransport> {
        RTCPeerConnection::new_sctp_transport(&self.setting_engine)
    }

    /*
    /// new_data_channel creates a new DataChannel.
    /// This constructor is part of the ORTC API. It is not
    /// meant to be used together with the basic WebRTC API.
    pub async fn new_data_channel(
        &self,
        sctp_transport: Arc<RTCSctpTransport>,
        params: DataChannelParameters,
    ) -> Result<RTCDataChannel> {
        // https://w3c.github.io/webrtc-pc/#peer-to-peer-data-api (Step #5)
        if params.label.len() > 65535 {
            return Err(Error::ErrStringSizeLimit);
        }

        let d = RTCDataChannel::new(params, Arc::clone(&self.setting_engine));
        d.open(sctp_transport).await?;

        Ok(d)
    }

    /// new_rtp_receiver constructs a new RTPReceiver
    pub fn new_rtp_receiver(
        &self,
        kind: RTPCodecType,
        transport: Arc<RTCDtlsTransport>,
        interceptor: Arc<dyn Interceptor + Send + Sync>,
    ) -> RTCRtpReceiver {
        RTCRtpReceiver::new(
            self.setting_engine.get_receive_mtu(),
            kind,
            transport,
            Arc::clone(&self.media_engine),
            interceptor,
        )
    }

    /// new_rtp_sender constructs a new RTPSender
    pub async fn new_rtp_sender(
        &self,
        track: Option<Arc<dyn TrackLocal + Send + Sync>>,
        transport: Arc<RTCDtlsTransport>,
        interceptor: Arc<dyn Interceptor + Send + Sync>,
    ) -> RTCRtpSender {
        RTCRtpSender::new(
            self.setting_engine.get_receive_mtu(),
            track,
            transport,
            Arc::clone(&self.media_engine),
            interceptor,
            false,
        )
        .await
    }*/

    /// Returns the internal [`SettingEngine`].
    pub fn setting_engine(&self) -> &SettingEngine {
        &self.setting_engine
    }

    /// Returns the internal [`MediaEngine`].
    pub fn media_engine(&self) -> &MediaEngine {
        &self.media_engine
    }
}

#[derive(Default)]
pub struct APIBuilder {
    setting_engine: Option<Arc<SettingEngine>>,
    media_engine: Option<MediaEngine>,
    //TODO: interceptor_registry: Option<Registry>,
}

impl APIBuilder {
    pub fn new() -> Self {
        APIBuilder::default()
    }

    pub fn build(mut self) -> API {
        API {
            setting_engine: if let Some(setting_engine) = self.setting_engine.take() {
                setting_engine
            } else {
                Arc::new(SettingEngine::default())
            },
            media_engine: if let Some(media_engine) = self.media_engine.take() {
                media_engine
            } else {
                MediaEngine::default()
            },
            /*TODO:interceptor_registry: if let Some(interceptor_registry) =
                self.interceptor_registry.take()
            {
                interceptor_registry
            } else {
                Registry::new()
            },*/
        }
    }

    /// WithSettingEngine allows providing a SettingEngine to the API.
    /// Settings should not be changed after passing the engine to an API.
    pub fn with_setting_engine(mut self, setting_engine: Arc<SettingEngine>) -> Self {
        self.setting_engine = Some(setting_engine);
        self
    }

    /// WithMediaEngine allows providing a MediaEngine to the API.
    /// Settings can be changed after passing the engine to an API.
    pub fn with_media_engine(mut self, media_engine: MediaEngine) -> Self {
        self.media_engine = Some(media_engine);
        self
    }

    /*TODO: /// with_interceptor_registry allows providing Interceptors to the API.
    /// Settings should not be changed after passing the registry to an API.
    pub fn with_interceptor_registry(mut self, interceptor_registry: Registry) -> Self {
        self.interceptor_registry = Some(interceptor_registry);
        self
    }*/
}
