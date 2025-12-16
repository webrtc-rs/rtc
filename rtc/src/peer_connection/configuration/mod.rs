pub mod bundle_policy;
pub mod ice_transport_policy;
pub mod offer_answer_options;
pub mod rtcp_mux_policy;
pub mod sdp_semantics;

use crate::peer_connection::certificate::RTCCertificate;
use crate::transport::ice::server::RTCIceServer;
use bundle_policy::RTCBundlePolicy;
use ice_transport_policy::RTCIceTransportPolicy;
use rtcp_mux_policy::RTCRtcpMuxPolicy;

/// A Configuration defines how peer-to-peer communication via PeerConnection
/// is established or re-established.
/// Configurations may be set up once and reused across multiple connections.
/// Configurations are treated as readonly. As long as they are unmodified,
/// they are safe for concurrent use.
///
/// ## Specifications
///
/// * [W3C]
///
/// [W3C]: https://w3c.github.io/webrtc-pc/#rtcconfiguration-dictionary
#[derive(Default, Clone)]
pub struct RTCConfiguration {
    /// ice_servers defines a slice describing servers available to be used by
    /// ICE, such as STUN and TURN servers.
    pub(crate) ice_servers: Vec<RTCIceServer>,

    /// ice_transport_policy indicates which candidates the ICEAgent is allowed
    /// to use.
    pub(crate) ice_transport_policy: RTCIceTransportPolicy,

    /// bundle_policy indicates which media-bundling policy to use when gathering
    /// ICE candidates.
    pub(crate) bundle_policy: RTCBundlePolicy,

    /// rtcp_mux_policy indicates which rtcp-mux policy to use when gathering ICE
    /// candidates.
    pub(crate) rtcp_mux_policy: RTCRtcpMuxPolicy,

    /// peer_identity sets the target peer identity for the PeerConnection.
    /// The PeerConnection will not establish a connection to a remote peer
    /// unless it can be successfully authenticated with the provided name.
    pub(crate) peer_identity: String,

    /// certificates describes a set of certificates that the PeerConnection
    /// uses to authenticate. Valid values for this parameter are created
    /// through calls to the generate_certificate function. Although any given
    /// DTLS connection will use only one certificate, this attribute allows the
    /// caller to provide multiple certificates that support different
    /// algorithms. The final certificate will be selected based on the DTLS
    /// handshake, which establishes which certificates are allowed. The
    /// PeerConnection implementation selects which of the certificates is
    /// used for a given connection; how certificates are selected is outside
    /// the scope of this specification. If this value is absent, then a default
    /// set of certificates is generated for each PeerConnection instance.
    pub(crate) certificates: Vec<RTCCertificate>,

    /// ice_candidate_pool_size describes the size of the prefetched ICE pool.
    pub(crate) ice_candidate_pool_size: u8,
}

impl RTCConfiguration {
    /// get_iceservers side-steps the strict parsing mode of the ice package
    /// (as defined in https://tools.ietf.org/html/rfc7064) by copying and then
    /// stripping any erroneous queries from "stun(s):" URLs before parsing.
    #[allow(clippy::assigning_clones)]
    pub(crate) fn get_ice_servers(&self) -> Vec<RTCIceServer> {
        let mut ice_servers = self.ice_servers.clone();

        for ice_server in &mut ice_servers {
            for raw_url in &mut ice_server.urls {
                if raw_url.starts_with("stun") {
                    // strip the query from "stun(s):" if present
                    let parts: Vec<&str> = raw_url.split('?').collect();
                    *raw_url = parts[0].to_owned();
                }
            }
        }

        ice_servers
    }
}

#[derive(Default)]
pub struct RTCConfigurationBuilder {
    /// ice_servers defines a slice describing servers available to be used by
    /// ICE, such as STUN and TURN servers.
    pub(crate) ice_servers: Vec<RTCIceServer>,

    /// ice_transport_policy indicates which candidates the ICEAgent is allowed
    /// to use.
    pub(crate) ice_transport_policy: RTCIceTransportPolicy,

    /// bundle_policy indicates which media-bundling policy to use when gathering
    /// ICE candidates.
    pub(crate) bundle_policy: RTCBundlePolicy,

    /// rtcp_mux_policy indicates which rtcp-mux policy to use when gathering ICE
    /// candidates.
    pub(crate) rtcp_mux_policy: RTCRtcpMuxPolicy,

    /// peer_identity sets the target peer identity for the PeerConnection.
    /// The PeerConnection will not establish a connection to a remote peer
    /// unless it can be successfully authenticated with the provided name.
    pub(crate) peer_identity: String,

    /// certificates describes a set of certificates that the PeerConnection
    /// uses to authenticate. Valid values for this parameter are created
    /// through calls to the generate_certificate function. Although any given
    /// DTLS connection will use only one certificate, this attribute allows the
    /// caller to provide multiple certificates that support different
    /// algorithms. The final certificate will be selected based on the DTLS
    /// handshake, which establishes which certificates are allowed. The
    /// PeerConnection implementation selects which of the certificates is
    /// used for a given connection; how certificates are selected is outside
    /// the scope of this specification. If this value is absent, then a default
    /// set of certificates is generated for each PeerConnection instance.
    pub(crate) certificates: Vec<RTCCertificate>,

    /// ice_candidate_pool_size describes the size of the prefetched ICE pool.
    pub(crate) ice_candidate_pool_size: u8,
}

impl RTCConfigurationBuilder {
    pub fn new() -> Self {
        RTCConfigurationBuilder::default()
    }

    pub fn with_ice_servers(mut self, ice_servers: Vec<RTCIceServer>) -> Self {
        self.ice_servers = ice_servers;
        self
    }

    pub fn with_ice_transport_policy(
        mut self,
        ice_transport_policy: RTCIceTransportPolicy,
    ) -> Self {
        self.ice_transport_policy = ice_transport_policy;
        self
    }

    pub fn with_bundle_policy(mut self, bundle_policy: RTCBundlePolicy) -> Self {
        self.bundle_policy = bundle_policy;
        self
    }

    pub fn with_rtcp_mux_policy(mut self, rtcp_mux_policy: RTCRtcpMuxPolicy) -> Self {
        self.rtcp_mux_policy = rtcp_mux_policy;
        self
    }

    pub fn with_peer_identitys(mut self, peer_identity: String) -> Self {
        self.peer_identity = peer_identity;
        self
    }

    pub fn with_certificates(mut self, certificates: Vec<RTCCertificate>) -> Self {
        self.certificates = certificates;
        self
    }

    pub fn with_ice_candidate_pool_size(mut self, ice_candidate_pool_size: u8) -> Self {
        self.ice_candidate_pool_size = ice_candidate_pool_size;
        self
    }

    pub fn build(self) -> RTCConfiguration {
        RTCConfiguration {
            ice_servers: self.ice_servers,
            ice_transport_policy: self.ice_transport_policy,
            bundle_policy: self.bundle_policy,
            rtcp_mux_policy: self.rtcp_mux_policy,
            peer_identity: self.peer_identity,
            certificates: self.certificates,
            ice_candidate_pool_size: self.ice_candidate_pool_size,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_configuration_get_iceservers() {
        {
            let expected_server_str = "stun:stun.l.google.com:19302";
            let cfg = RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec![expected_server_str.to_owned()],
                    ..Default::default()
                }])
                .build();

            let parsed_urls = cfg.get_ice_servers();
            assert_eq!(parsed_urls[0].urls[0], expected_server_str);
        }

        {
            // ignore the fact that stun URLs shouldn't have a query
            let server_str = "stun:global.stun.twilio.com:3478?transport=udp";
            let expected_server_str = "stun:global.stun.twilio.com:3478";
            let cfg = RTCConfigurationBuilder::new()
                .with_ice_servers(vec![RTCIceServer {
                    urls: vec![server_str.to_owned()],
                    ..Default::default()
                }])
                .build();

            let parsed_urls = cfg.get_ice_servers();
            assert_eq!(parsed_urls[0].urls[0], expected_server_str);
        }
    }

    /*TODO:#[test] fn test_configuration_json() {

         let j = r#"
            {
                "iceServers": [{"URLs": ["turn:turn.example.org"],
                                "username": "jch",
                                "credential": "topsecret"
                              }],
                "iceTransportPolicy": "relay",
                "bundlePolicy": "balanced",
                "rtcpMuxPolicy": "require"
            }"#;

        conf := Configuration{
            ICEServers: []ICEServer{
                {
                    URLs:       []string{"turn:turn.example.org"},
                    Username:   "jch",
                    Credential: "topsecret",
                },
            },
            ICETransportPolicy: ICETransportPolicyRelay,
            BundlePolicy:       BundlePolicyBalanced,
            RTCPMuxPolicy:      RTCPMuxPolicyRequire,
        }

        var conf2 Configuration
        assert.NoError(t, json.Unmarshal([]byte(j), &conf2))
        assert.Equal(t, conf, conf2)

        j2, err := json.Marshal(conf2)
        assert.NoError(t, err)

        var conf3 Configuration
        assert.NoError(t, json.Unmarshal(j2, &conf3))
        assert.Equal(t, conf2, conf3)
    }*/
}
