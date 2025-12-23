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
    pub(crate) fn new(
        remote_conn_cred: ConnectionCredentials,
        local_conn_cred: ConnectionCredentials,
    ) -> Self {
        Self {
            remote_conn_cred,
            local_conn_cred,
        }
    }
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
    pub(crate) four_tuple: FourTuple,

    // ICE
    pub(crate) candidate_pair: CandidatePair,

    // DTLS
    pub(crate) dtls_endpoint: ::dtls::endpoint::Endpoint,

    // SCTP
    pub(crate) sctp_endpoint: ::sctp::Endpoint,
    pub(crate) sctp_associations: HashMap<AssociationHandle, Association>,

    // DataChannel
    pub(crate) association_handle: Option<usize>,

    // SRTP
    pub(crate) local_srtp_context: Option<Context>,
    pub(crate) remote_srtp_context: Option<Context>,
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

            local_srtp_context: None,
            remote_srtp_context: None,
        }
    }

    pub(crate) fn get_dtls_endpoint_mut(&mut self) -> &mut ::dtls::endpoint::Endpoint {
        &mut self.dtls_endpoint
    }

    pub(crate) fn get_dtls_endpoint(&self) -> &::dtls::endpoint::Endpoint {
        &self.dtls_endpoint
    }

    pub(crate) fn get_sctp_endpoint_mut(&mut self) -> &mut ::sctp::Endpoint {
        &mut self.sctp_endpoint
    }

    pub(crate) fn get_sctp_endpoint(&self) -> &::sctp::Endpoint {
        &self.sctp_endpoint
    }

    pub(crate) fn get_sctp_associations_mut(
        &mut self,
    ) -> &mut HashMap<AssociationHandle, Association> {
        &mut self.sctp_associations
    }

    pub(crate) fn get_sctp_associations(&self) -> &HashMap<AssociationHandle, Association> {
        &self.sctp_associations
    }

    pub(crate) fn get_sctp_endpoint_associations_mut(
        &mut self,
    ) -> (
        &mut ::sctp::Endpoint,
        &mut HashMap<AssociationHandle, Association>,
    ) {
        (&mut self.sctp_endpoint, &mut self.sctp_associations)
    }

    pub(crate) fn local_srtp_context(&mut self) -> Option<&mut Context> {
        self.local_srtp_context.as_mut()
    }

    pub(crate) fn remote_srtp_context(&mut self) -> Option<&mut Context> {
        self.remote_srtp_context.as_mut()
    }

    pub(crate) fn set_local_srtp_context(&mut self, local_srtp_context: Context) {
        self.local_srtp_context = Some(local_srtp_context);
    }

    pub(crate) fn set_remote_srtp_context(&mut self, remote_srtp_context: Context) {
        self.remote_srtp_context = Some(remote_srtp_context);
    }

    pub(crate) fn set_association_handle(&mut self, association_handle: usize) {
        self.association_handle = Some(association_handle);
    }

    pub(crate) fn association_handle(&mut self) -> Option<usize> {
        self.association_handle
    }
}

#[derive(Default)]
pub(crate) struct TransportStates {
    transports: HashMap<FourTuple, Transport>,
}

impl TransportStates {
    pub(crate) fn has_transport(&self, four_tuple: &FourTuple) -> bool {
        self.transports.contains_key(four_tuple)
    }

    pub(crate) fn add_transport(&mut self, four_tuple: FourTuple, transport: Transport) {
        self.transports.insert(four_tuple, transport);
    }

    pub(crate) fn remove_transport(&mut self, four_tuple: FourTuple) {
        let _ = self.transports.remove(&four_tuple);
    }

    pub(crate) fn find_transport(&self, four_tuple: &FourTuple) -> Option<&Transport> {
        self.transports.get(four_tuple)
    }

    pub(crate) fn find_transport_mut(&mut self, four_tuple: &FourTuple) -> Option<&mut Transport> {
        self.transports.get_mut(four_tuple)
    }

    pub(crate) fn get_transports(&self) -> &HashMap<FourTuple, Transport> {
        &self.transports
    }

    pub(crate) fn get_transports_mut(&mut self) -> &mut HashMap<FourTuple, Transport> {
        &mut self.transports
    }
}
