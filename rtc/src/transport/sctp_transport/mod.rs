//TODO:#[cfg(test)]
//TODO:mod sctp_transport_test;

pub mod sctp_transport_capabilities;
pub mod sctp_transport_state;

//use datachannel::data_channel::DataChannel;
//use datachannel::message::message_channel_open::ChannelType;
use sctp::Association;
use sctp_transport_state::RTCSctpTransportState;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::api::setting_engine::SettingEngine;
//use crate::transports::data_channel::data_channel_parameters::DataChannelParameters;
use crate::transport::data_channel::data_channel_state::RTCDataChannelState;
use crate::transport::data_channel::RTCDataChannel;
use crate::transport::dtls_transport::dtls_role::DTLSRole;
//use crate::transports::dtls_transport::*;
use crate::stats::stats_collector::StatsCollector;
use crate::stats::PeerConnectionStats;
use crate::stats::StatsReportType::PeerConnection;
use crate::transport::sctp_transport::sctp_transport_capabilities::SCTPTransportCapabilities;
use shared::error::*;

const SCTP_MAX_CHANNELS: u16 = u16::MAX;

pub enum SctpTransportEvent {
    OnError,
    OnDataChannel(RTCDataChannel),
    OnDataChannelOpened(RTCDataChannel),
}

/// SCTPTransport provides details about the SCTP transport.
#[derive(Default)]
pub struct RTCSctpTransport {
    //todo: pub(crate) dtls_transport: Arc<RTCDtlsTransport>,

    // State represents the current state of the SCTP transport.
    state: RTCSctpTransportState,

    // SCTPTransportState doesn't have an enum to distinguish between New/Connecting
    // so we need a dedicated field
    is_started: bool,

    // max_message_size represents the maximum size of data that can be passed to
    // DataChannel's send() method.
    max_message_size: usize,

    // max_channels represents the maximum amount of DataChannel's that can
    // be used simultaneously.
    max_channels: u16,

    sctp_association: Option<Association>,

    // DataChannels
    pub(crate) data_channels: Vec<RTCDataChannel>,
    pub(crate) data_channels_opened: u32,
    pub(crate) data_channels_requested: u32,
    data_channels_accepted: u32,

    setting_engine: Arc<SettingEngine>,
}

impl RTCSctpTransport {
    pub(crate) fn new(setting_engine: Arc<SettingEngine>) -> Self {
        RTCSctpTransport {
            //dtls_transport,
            state: RTCSctpTransportState::Connecting,
            is_started: false,
            max_message_size: RTCSctpTransport::calc_message_size(65536, 65536),
            max_channels: SCTP_MAX_CHANNELS,
            sctp_association: None,

            data_channels: vec![],
            data_channels_opened: 0,
            data_channels_requested: 0,
            data_channels_accepted: 0,

            setting_engine,
        }
    }

    /// get_capabilities returns the SCTPCapabilities of the SCTPTransport.
    pub fn get_capabilities(&self) -> SCTPTransportCapabilities {
        SCTPTransportCapabilities {
            max_message_size: self.max_message_size as u32,
        }
    }

    /// Start the SCTPTransport. Since both local and remote parties must mutually
    /// create an SCTPTransport, SCTP SO (Simultaneous Open) is used to establish
    /// a connection over SCTP.
    /*TODO:pub async fn start(&self, _remote_caps: SCTPTransportCapabilities) -> Result<()> {
        if self.is_started.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.is_started.store(true, Ordering::SeqCst);

        let dtls_transport = self.transport();
        if let Some(net_conn) = &dtls_transport.conn().await {
            let sctp_association = loop {
                tokio::select! {
                    _ = self.notify_tx.notified() => {
                        // It seems like notify_tx is only notified on Stop so perhaps this check
                        // is redundant.
                        // TODO: Consider renaming notify_tx to shutdown_tx.
                        if self.state.load(Ordering::SeqCst) == RTCSctpTransportState::Closed as u8 {
                            return Err(Error::ErrSCTPTransportDTLS);
                        }
                    },
                    association = sctp::association::Association::client(sctp::association::Config {
                        net_conn: Arc::clone(net_conn) as Arc<dyn Conn + Send + Sync>,
                        max_receive_buffer_size: 0,
                        max_message_size: 0,
                        name: String::new(),
                    }) => {
                        break Arc::new(association?);
                    }
                };
            };

            {
                let mut sa = self.sctp_association.lock().await;
                *sa = Some(Arc::clone(&sctp_association));
            }
            self.state
                .store(RTCSctpTransportState::Connected as u8, Ordering::SeqCst);

            let param = AcceptDataChannelParams {
                notify_rx: self.notify_tx.clone(),
                sctp_association,
                data_channels: Arc::clone(&self.data_channels),
                on_error_handler: Arc::clone(&self.on_error_handler),
                on_data_channel_handler: Arc::clone(&self.on_data_channel_handler),
                on_data_channel_opened_handler: Arc::clone(&self.on_data_channel_opened_handler),
                data_channels_opened: Arc::clone(&self.data_channels_opened),
                data_channels_accepted: Arc::clone(&self.data_channels_accepted),
                setting_engine: Arc::clone(&self.setting_engine),
            };
            tokio::spawn(async move {
                RTCSctpTransport::accept_data_channels(param).await;
            });

            Ok(())
        } else {
            Err(Error::ErrSCTPTransportDTLS)
        }
    }*/

    /// Stop stops the SCTPTransport
    pub fn stop(&mut self) -> Result<()> {
        self.state = RTCSctpTransportState::Closed;
        Ok(())
    }

    /*todo: fn accept_data_channels(param: AcceptDataChannelParams) {
        let dcs = param.data_channels.lock().await;
        let mut existing_data_channels = Vec::new();
        for dc in dcs.iter() {
            if let Some(dc) = dc.data_channel.lock().await.clone() {
                existing_data_channels.push(dc);
            }
        }
        drop(dcs);

        loop {
            let dc = tokio::select! {
                _ = param.notify_rx.notified() => break,
                result = DataChannel::accept(
                    &param.sctp_association,
                    data::data_channel::Config::default(),
                    &existing_data_channels,
                ) => {
                    match result {
                        Ok(dc) => dc,
                        Err(err) => {
                            if data::Error::ErrStreamClosed == err {
                                log::error!("Failed to accept data channel: {}", err);
                                if let Some(handler) = &*param.on_error_handler.load() {
                                    let mut f = handler.lock().await;
                                    f(err.into()).await;
                                }
                            }
                            break;
                        }
                    }
                }
            };

            let mut max_retransmits = 0;
            let mut max_packet_lifetime = 0;
            let val = dc.config.reliability_parameter as u16;
            let ordered;

            match dc.config.channel_type {
                ChannelType::Reliable => {
                    ordered = true;
                }
                ChannelType::ReliableUnordered => {
                    ordered = false;
                }
                ChannelType::PartialReliableRexmit => {
                    ordered = true;
                    max_retransmits = val;
                }
                ChannelType::PartialReliableRexmitUnordered => {
                    ordered = false;
                    max_retransmits = val;
                }
                ChannelType::PartialReliableTimed => {
                    ordered = true;
                    max_packet_lifetime = val;
                }
                ChannelType::PartialReliableTimedUnordered => {
                    ordered = false;
                    max_packet_lifetime = val;
                }
            };

            let negotiated = if dc.config.negotiated {
                Some(dc.stream_identifier())
            } else {
                None
            };
            let rtc_dc = Arc::new(RTCDataChannel::new(
                DataChannelParameters {
                    label: dc.config.label.clone(),
                    protocol: dc.config.protocol.clone(),
                    negotiated,
                    ordered,
                    max_packet_life_time: max_packet_lifetime,
                    max_retransmits,
                },
                Arc::clone(&param.setting_engine),
            ));

            if let Some(handler) = &*param.on_data_channel_handler.load() {
                let mut f = handler.lock().await;
                f(Arc::clone(&rtc_dc)).await;

                param.data_channels_accepted.fetch_add(1, Ordering::SeqCst);

                let mut dcs = param.data_channels.lock().await;
                dcs.push(Arc::clone(&rtc_dc));
            }

            rtc_dc.handle_open(Arc::new(dc)).await;

            if let Some(handler) = &*param.on_data_channel_opened_handler.load() {
                let mut f = handler.lock().await;
                f(rtc_dc).await;
                param.data_channels_opened.fetch_add(1, Ordering::SeqCst);
            }
        }
    }*/

    fn calc_message_size(remote_max_message_size: usize, can_send_size: usize) -> usize {
        if remote_max_message_size == 0 && can_send_size == 0 {
            usize::MAX
        } else if remote_max_message_size == 0 {
            can_send_size
        } else if can_send_size == 0 || can_send_size > remote_max_message_size {
            remote_max_message_size
        } else {
            can_send_size
        }
    }

    /// max_channels is the maximum number of RTCDataChannels that can be open simultaneously.
    pub fn max_channels(&self) -> u16 {
        if self.max_channels == 0 {
            SCTP_MAX_CHANNELS
        } else {
            self.max_channels
        }
    }

    /// state returns the current state of the SCTPTransport
    pub fn state(&self) -> RTCSctpTransportState {
        self.state
    }

    pub(crate) fn collect_stats(
        &mut self,
        collector: &mut StatsCollector,
        peer_connection_id: String,
    ) {
        //TODO: let dtls_transport = self.transport();
        //TODO": dtls_transport.collect_stats(collector);

        // data channels
        let mut data_channels_closed = 0;
        for data_channel in &mut self.data_channels {
            match data_channel.ready_state() {
                RTCDataChannelState::Connecting => (),
                RTCDataChannelState::Open => (),
                _ => data_channels_closed += 1,
            }
            data_channel.collect_stats(collector);
        }

        let mut reports = HashMap::new();
        let peer_connection_stats =
            PeerConnectionStats::new(self, peer_connection_id.clone(), data_channels_closed);
        reports.insert(peer_connection_id, PeerConnection(peer_connection_stats));

        /*TODO: if let Some(agent) = dtls_transport.ice_transport.gatherer.get_agent().await {
            let stats = ICETransportStats::new("sctp_transport".to_owned(), agent);
            reports.insert(stats.id.clone(), SCTPTransport(stats));
        }*/

        collector.merge(reports);
    }

    pub(crate) fn generate_and_set_data_channel_id(&self, dtls_role: DTLSRole) -> Result<u16> {
        let mut id = 0u16;
        if dtls_role != DTLSRole::Client {
            id += 1;
        }

        // Create map of ids so we can compare without double-looping each time.
        let mut ids_map = HashSet::new();
        {
            for dc in &self.data_channels {
                ids_map.insert(dc.id());
            }
        }

        let max = self.max_channels();
        while id < max - 1 {
            if ids_map.contains(&id) {
                id += 2;
            } else {
                return Ok(id);
            }
        }

        Err(Error::ErrMaxDataChannelID)
    }

    pub(crate) fn association(&self) -> Option<&Association> {
        self.sctp_association.as_ref()
    }

    pub(crate) fn data_channels_accepted(&self) -> u32 {
        self.data_channels_accepted
    }

    pub(crate) fn data_channels_opened(&self) -> u32 {
        self.data_channels_opened
    }

    pub(crate) fn data_channels_requested(&self) -> u32 {
        self.data_channels_requested
    }
}
