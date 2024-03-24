pub mod dtls_transport;
pub mod ice_transport;
pub mod sctp_transport;

/*TODO: to be removed
pub struct RTCTransport {
    pub(crate) last_activity: Instant,

    pub(crate) five_tuple: FiveTuple,

    // DTLS
    pub(crate) dtls_endpoint: dtls::endpoint::Endpoint,

    // SCTP
    pub(crate) sctp_endpoint: sctp::Endpoint,
    pub(crate) sctp_associations: HashMap<AssociationHandle, Association>,

    // DataChannel
    pub(crate) data_channels: HashMap<AssociationHandle, RTCDataChannel>,

    // SRTP
    pub(crate) local_srtp_context: Option<Context>,
    pub(crate) remote_srtp_context: Option<Context>,
}

impl RTCTransport {
    pub fn new(
        five_tuple: FiveTuple,
        dtls_handshake_config: Arc<dtls::config::HandshakeConfig>,
        sctp_endpoint_config: Arc<sctp::EndpointConfig>,
        sctp_server_config: Arc<sctp::ServerConfig>,
    ) -> Self {
        Self {
            last_activity: Instant::now(),
            five_tuple,

            dtls_endpoint: dtls::endpoint::Endpoint::new(
                five_tuple.local_addr,
                five_tuple.protocol,
                Some(dtls_handshake_config),
            ),

            sctp_endpoint: sctp::Endpoint::new(
                five_tuple.local_addr,
                five_tuple.protocol,
                sctp_endpoint_config,
                Some(sctp_server_config),
            ),
            sctp_associations: HashMap::new(),
            data_channels: HashMap::new(),

            local_srtp_context: None,
            remote_srtp_context: None,
        }
    }

    pub fn four_tuple(&self) -> FourTuple {
        FourTuple {
            local_addr: self.five_tuple.local_addr,
            peer_addr: self.five_tuple.peer_addr,
        }
    }

    pub fn five_tuple(&self) -> FiveTuple {
        self.five_tuple
    }

    pub fn get_mut_dtls_endpoint(&mut self) -> &mut dtls::endpoint::Endpoint {
        &mut self.dtls_endpoint
    }

    pub fn get_dtls_endpoint(&self) -> &dtls::endpoint::Endpoint {
        &self.dtls_endpoint
    }

    pub fn get_mut_sctp_endpoint(&mut self) -> &mut sctp::Endpoint {
        &mut self.sctp_endpoint
    }

    pub fn get_sctp_endpoint(&self) -> &sctp::Endpoint {
        &self.sctp_endpoint
    }

    pub fn get_mut_sctp_associations(&mut self) -> &mut HashMap<AssociationHandle, Association> {
        &mut self.sctp_associations
    }

    pub fn get_mut_sctp_endpoint_associations(
        &mut self,
    ) -> (
        &mut sctp::Endpoint,
        &mut HashMap<AssociationHandle, Association>,
    ) {
        (&mut self.sctp_endpoint, &mut self.sctp_associations)
    }

    pub fn get_sctp_associations(&self) -> &HashMap<AssociationHandle, Association> {
        &self.sctp_associations
    }

    pub fn get_data_channels(&self) -> &HashMap<AssociationHandle, RTCDataChannel> {
        &self.data_channels
    }

    pub fn get_data_channel(
        &self,
        association_handle: &AssociationHandle,
    ) -> Option<&RTCDataChannel> {
        self.data_channels.get(association_handle)
    }

    pub fn get_mut_data_channel(
        &mut self,
        association_handle: &AssociationHandle,
    ) -> Option<&mut RTCDataChannel> {
        self.data_channels.get_mut(association_handle)
    }

    pub fn local_srtp_context(&mut self) -> Option<&mut Context> {
        self.local_srtp_context.as_mut()
    }

    pub fn remote_srtp_context(&mut self) -> Option<&mut Context> {
        self.remote_srtp_context.as_mut()
    }

    pub fn set_local_srtp_context(&mut self, local_srtp_context: Context) {
        self.local_srtp_context = Some(local_srtp_context);
    }

    pub fn set_remote_srtp_context(&mut self, remote_srtp_context: Context) {
        self.remote_srtp_context = Some(remote_srtp_context);
    }

    pub fn is_local_srtp_context_ready(&self) -> bool {
        self.local_srtp_context.is_some()
    }

    pub fn keep_alive(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }
}
*/
