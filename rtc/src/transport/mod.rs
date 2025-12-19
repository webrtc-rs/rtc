use crate::transport::dtls::parameters::DTLSParameters;
use crate::transport::ice::parameters::RTCIceParameters;
use ::sctp::{Association, AssociationHandle};
use serde::{Deserialize, Serialize};
use shared::{FourTuple, TransportProtocol};
use srtp::context::Context;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub mod dtls;
pub mod ice;
pub mod sctp;

pub(crate) type UserName = String;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ConnectionCredentials {
    pub(crate) ice_params: RTCIceParameters,
    pub(crate) dtls_params: DTLSParameters,
}

#[derive(Default, Clone)]
pub(crate) struct CandidatePair {
    pub(crate) remote_conn_cred: ConnectionCredentials,
    pub(crate) local_conn_cred: ConnectionCredentials,
}

impl CandidatePair {
    pub(crate) fn username(&self) -> UserName {
        format!(
            "{}:{}",
            self.local_conn_cred.ice_params.username_fragment,
            self.remote_conn_cred.ice_params.username_fragment
        )
    }

    pub(crate) fn remote_connection_credentials(&self) -> &ConnectionCredentials {
        &self.remote_conn_cred
    }

    pub(crate) fn local_connection_credentials(&self) -> &ConnectionCredentials {
        &self.local_conn_cred
    }

    /// get_remote_parameters returns the remote's ICE parameters
    pub(crate) fn get_remote_parameters(&self) -> &RTCIceParameters {
        &self.remote_conn_cred.ice_params
    }

    /// get_local_parameters returns the local's ICE parameters.
    pub(crate) fn get_local_parameters(&self) -> &RTCIceParameters {
        &self.local_conn_cred.ice_params
    }
}

pub(crate) struct Transport {
    four_tuple: FourTuple,

    // ICE
    pub(crate) candidate_pair: Arc<CandidatePair>,

    // DTLS
    dtls_endpoint: ::dtls::endpoint::Endpoint,

    // SCTP
    sctp_endpoint: ::sctp::Endpoint,
    sctp_associations: HashMap<AssociationHandle, Association>,

    // DataChannel
    association_handle: Option<usize>,
    stream_id: Option<u16>,

    // SRTP
    local_srtp_context: Option<Context>,
    remote_srtp_context: Option<Context>,
}

impl Transport {
    pub(crate) fn new(
        four_tuple: FourTuple,
        transport_protocol: TransportProtocol,
        candidate_pair: Arc<CandidatePair>,
        dtls_handshake_config: Arc<::dtls::config::HandshakeConfig>,
        sctp_endpoint_config: Arc<::sctp::EndpointConfig>,
        sctp_server_config: Arc<::sctp::ServerConfig>,
    ) -> Self {
        Self {
            four_tuple,

            candidate_pair,

            dtls_endpoint: ::dtls::endpoint::Endpoint::new(
                four_tuple.local_addr,
                transport_protocol,
                Some(dtls_handshake_config),
            ),

            sctp_endpoint: ::sctp::Endpoint::new(
                four_tuple.local_addr,
                transport_protocol,
                sctp_endpoint_config,
                Some(sctp_server_config),
            ),
            sctp_associations: HashMap::new(),

            association_handle: None,
            stream_id: None,

            local_srtp_context: None,
            remote_srtp_context: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct TransportStates {
    candidates: Mutex<HashMap<UserName, Arc<CandidatePair>>>,
    transports: Mutex<HashMap<FourTuple, Transport>>,
}

impl TransportStates {
    pub(crate) fn find_candidate_pair(&self, username: &UserName) -> Option<Arc<CandidatePair>> {
        let candidates = self.candidates.lock().unwrap();
        candidates.get(username).cloned()
    }

    pub(crate) fn has_transport(&self, four_tuple: &FourTuple) -> bool {
        let transports = self.transports.lock().unwrap();
        transports.contains_key(four_tuple)
    }

    pub(crate) fn add_transport(&self, four_tuple: FourTuple, transport: Transport) {
        let mut transports = self.transports.lock().unwrap();
        transports.insert(four_tuple, transport);
    }
}
