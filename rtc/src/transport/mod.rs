use ::sctp::{Association, AssociationHandle};
use shared::{FourTuple, TransportProtocol};
use srtp::context::Context;
use std::collections::HashMap;

pub mod dtls;
pub mod ice;
pub mod sctp;

pub(crate) struct Transport {
    pub(crate) four_tuple: FourTuple,

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
        sctp_endpoint_config: &::sctp::EndpointConfig,
        sctp_server_config: &::sctp::ServerConfig,
    ) -> Self {
        Self {
            four_tuple,

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
