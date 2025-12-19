use crate::transport::dtls::parameters::DTLSParameters;
use crate::transport::ice::parameters::RTCIceParameters;
use ::sctp::{Association, AssociationHandle};
use serde::{Deserialize, Serialize};
use shared::{FourTuple, TransportProtocol};
use srtp::context::Context;
use std::collections::HashMap;

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
    pub(crate) candidate_pair: CandidatePair,

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
        candidate_pair: CandidatePair,
        dtls_handshake_config: &::dtls::config::HandshakeConfig,
        sctp_endpoint_config: &::sctp::EndpointConfig,
        sctp_server_config: &::sctp::ServerConfig,
    ) -> Self {
        Self {
            four_tuple,

            candidate_pair,

            dtls_endpoint: ::dtls::endpoint::Endpoint::new(
                four_tuple.local_addr,
                transport_protocol,
                Some(dtls_handshake_config.clone().into()),
            ),

            sctp_endpoint: ::sctp::Endpoint::new(
                four_tuple.local_addr,
                transport_protocol,
                sctp_endpoint_config.clone().into(),
                Some(sctp_server_config.clone().into()),
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
    candidates: HashMap<UserName, CandidatePair>,
    transports: HashMap<FourTuple, Transport>,
}

impl TransportStates {
    pub(crate) fn add_candidate_pair(&mut self, username: UserName, pair: CandidatePair) {
        self.candidates.insert(username, pair);
    }

    pub(crate) fn find_candidate_pair(&self, username: &UserName) -> Option<&CandidatePair> {
        self.candidates.get(username)
    }

    pub(crate) fn has_transport(&self, four_tuple: &FourTuple) -> bool {
        self.transports.contains_key(four_tuple)
    }

    pub(crate) fn add_transport(&mut self, four_tuple: FourTuple, transport: Transport) {
        self.transports.insert(four_tuple, transport);
    }

    pub(crate) fn find_transport(&self, four_tuple: &FourTuple) -> Option<&Transport> {
        self.transports.get(four_tuple)
    }

    pub(crate) fn find_transport_mut(&mut self, four_tuple: &FourTuple) -> Option<&mut Transport> {
        self.transports.get_mut(four_tuple)
    }
}
