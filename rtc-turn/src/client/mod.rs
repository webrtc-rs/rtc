/*#[cfg(test)]
mod client_test;
*/
pub mod binding;
pub mod periodic_timer;
pub mod permission;
/*pub mod relay_conn;*/
pub mod transaction;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use bytes::BytesMut;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;

use stun::attributes::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;

use binding::*;
use transaction::*;
/*
use relay_conn::*;
*/

use crate::proto::chandata::*;
use crate::proto::channum::ChannelNumber;
use crate::proto::data::*;
use crate::proto::peeraddr::*;
use shared::error::{Error, Result};
use shared::{Protocol, Transmit, TransportContext};

const DEFAULT_RTO_IN_MS: u64 = 200;
const MAX_DATA_BUFFER_SIZE: usize = u16::MAX as usize; // message size limit for Chromium
const MAX_READ_QUEUE_SIZE: usize = 1024;

pub enum Event {
    BindingResponse(String, SocketAddr),
    BindingRequestTimeout(String),
    DataIndication(SocketAddr, BytesMut),
    ChannelData(ChannelNumber, SocketAddr, BytesMut),
}

//              interval [msec]
// 0: 0 ms      +500
// 1: 500 ms	+1000
// 2: 1500 ms   +2000
// 3: 3500 ms   +4000
// 4: 7500 ms   +8000
// 5: 15500 ms  +16000
// 6: 31500 ms  +32000
// -: 63500 ms  failed

/// ClientConfig is a bag of config parameters for Client.
pub struct ClientConfig {
    pub stun_serv_addr: String, // STUN server address (e.g. "stun.abc.com:3478")
    pub turn_serv_addr: String, // TURN server address (e.g. "turn.abc.com:3478")
    pub local_addr: SocketAddr,
    pub protocol: Protocol,
    pub username: String,
    pub password: String,
    pub realm: String,
    pub software: String,
    pub rto_in_ms: u64,
}

/// Client is a STUN client
pub struct Client {
    stun_serv_addr: Option<SocketAddr>,
    turn_serv_addr: SocketAddr,
    local_addr: SocketAddr,
    protocol: Protocol,
    username: Username,
    password: String,
    realm: Realm,
    integrity: MessageIntegrity,
    software: Software,
    tr_map: TransactionMap,
    binding_mgr: BindingManager,
    rto_in_ms: u64,

    transmits: VecDeque<Transmit<BytesMut>>,
    events: VecDeque<Event>,
}

impl Client {
    /// new returns a new Client instance. listeningAddress is the address and port to listen on, default "0.0.0.0:0"
    pub fn new(config: ClientConfig) -> Result<Self> {
        let stun_serv_addr = if config.stun_serv_addr.is_empty() {
            None
        } else {
            Some(SocketAddr::from_str(config.stun_serv_addr.as_str())?)
        };

        let turn_serv_addr = if config.turn_serv_addr.is_empty() {
            return Err(Error::ErrNilTurnSocket);
        } else {
            SocketAddr::from_str(config.turn_serv_addr.as_str())?
        };

        Ok(Client {
            stun_serv_addr,
            turn_serv_addr,
            local_addr: config.local_addr,
            protocol: config.protocol,
            username: Username::new(ATTR_USERNAME, config.username),
            password: config.password,
            realm: Realm::new(ATTR_REALM, config.realm),
            software: Software::new(ATTR_SOFTWARE, config.software),
            tr_map: TransactionMap::new(),
            binding_mgr: BindingManager::new(),
            rto_in_ms: if config.rto_in_ms != 0 {
                config.rto_in_ms
            } else {
                DEFAULT_RTO_IN_MS
            },
            integrity: MessageIntegrity::new_short_term_integrity(String::new()),

            transmits: VecDeque::new(),
            events: VecDeque::new(),
        })
    }

    pub fn poll_timout(&self) -> Option<Instant> {
        self.tr_map.poll_timout()
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.tr_map.handle_timeout(now);
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit<BytesMut>> {
        while let Some(transmit) = self.tr_map.poll_transmit() {
            self.transmits.push_back(transmit);
        }
        self.transmits.pop_front()
    }

    pub fn handle_transmit(&mut self, msg: Transmit<BytesMut>) -> Result<()> {
        self.handle_inbound(&msg.message[..], msg.transport.peer_addr)
    }

    pub(crate) fn poll_event(&mut self) -> Option<Event> {
        while let Some(event) = self.tr_map.poll_event() {
            self.events.push_back(event);
        }
        self.events.pop_front()
    }

    // handle_inbound handles data received.
    // This method handles incoming packet demultiplex it by the source address
    // and the types of the message.
    // This return Ok(handled or not) and if there was an error.
    // Caller should check if the packet was handled by this client or not.
    // If not handled, it is assumed that the packet is application data.
    // If an error is returned, the caller should discard the packet regardless.
    fn handle_inbound(&mut self, data: &[u8], from: SocketAddr) -> Result<()> {
        // +-------------------+-------------------------------+
        // |   Return Values   |                               |
        // +-------------------+       Meaning / Action        |
        // | handled |  error  |                               |
        // |=========+=========+===============================+
        // |  false  |   nil   | Handle the packet as app data |
        // |---------+---------+-------------------------------+
        // |  true   |   nil   |        Nothing to do          |
        // |---------+---------+-------------------------------+
        // |  false  |  error  |     (shouldn't happen)        |
        // |---------+---------+-------------------------------+
        // |  true   |  error  | Error occurred while handling |
        // +---------+---------+-------------------------------+
        // Possible causes of the error:
        //  - Malformed packet (parse error)
        //  - STUN message was a request
        //  - Non-STUN message from the STUN server

        if is_message(data) {
            self.handle_stun_message(data)
        } else if ChannelData::is_channel_data(data) {
            self.handle_channel_data(data)
        } else if self.stun_serv_addr.is_some() && &from == self.stun_serv_addr.as_ref().unwrap() {
            // received from STUN server, but it is not a STUN message
            Err(Error::ErrNonStunmessage)
        } else {
            // assume, this is an application data
            log::trace!("non-STUN/TURN packet, unhandled");
            Ok(())
        }
    }

    fn handle_stun_message(&mut self, data: &[u8]) -> Result<()> {
        let mut msg = Message::new();
        msg.raw = data.to_vec();
        msg.decode()?;

        if msg.typ.class == CLASS_REQUEST {
            return Err(Error::Other(format!(
                "{:?} : {}",
                Error::ErrUnexpectedStunrequestMessage,
                msg
            )));
        }

        if msg.typ.class == CLASS_INDICATION {
            if msg.typ.method == METHOD_DATA {
                let mut peer_addr = PeerAddress::default();
                peer_addr.get_from(&msg)?;
                let from = SocketAddr::new(peer_addr.ip, peer_addr.port);

                let mut data = Data::default();
                data.get_from(&msg)?;

                log::debug!("data indication received from {}", from);

                self.events
                    .push_back(Event::DataIndication(from, BytesMut::from(&data.0[..])))
            }

            return Ok(());
        }

        // This is a STUN response message (transactional)
        // The type is either:
        // - stun.ClassSuccessResponse
        // - stun.ClassErrorResponse

        let tr_key = BASE64_STANDARD.encode(msg.transaction_id.0);

        if self.tr_map.find(&tr_key).is_none() {
            // silently discard
            log::debug!("no transaction for {}", msg);
            return Ok(());
        }

        if let Some(tr) = self.tr_map.delete(&tr_key) {
            let mut refl_addr = XorMappedAddress::default();
            refl_addr.get_from(&msg)?;
            self.events.push_back(Event::BindingResponse(
                tr.key,
                SocketAddr::new(refl_addr.ip, refl_addr.port),
            ));
        }

        Ok(())
    }

    fn handle_channel_data(&mut self, data: &[u8]) -> Result<()> {
        let mut ch_data = ChannelData {
            raw: data.to_vec(),
            ..Default::default()
        };
        ch_data.decode()?;

        let addr = self
            .find_addr_by_channel_number(ch_data.number.0)
            .ok_or(Error::ErrChannelBindNotFound)?;

        log::trace!(
            "channel data received from {} (ch={})",
            addr,
            ch_data.number.0
        );

        self.events.push_back(Event::ChannelData(
            ch_data.number,
            addr,
            BytesMut::from(&ch_data.data[..]),
        ));

        Ok(())
    }

    /// Close closes this client
    pub fn close(&mut self) {
        self.tr_map.delete_all();
    }

    /// send_binding_request_to sends a new STUN request to the given transport address
    /// return key to find out corresponding Event either BindingResponse or BindingRequestTimeout
    pub fn send_binding_request_to(&mut self, to: SocketAddr) -> Result<String> {
        let msg = {
            let attrs: Vec<Box<dyn Setter>> = if !self.software.text.is_empty() {
                vec![
                    Box::new(TransactionId::new()),
                    Box::new(BINDING_REQUEST),
                    Box::new(self.software.clone()),
                ]
            } else {
                vec![Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)]
            };

            let mut msg = Message::new();
            msg.build(&attrs)?;
            msg
        };

        log::debug!("client.SendBindingRequestTo call PerformTransaction 1");
        self.perform_transaction(&msg, to)
    }

    /// send_binding_request sends a new STUN request to the STUN server
    /// return key to find out corresponding Event either BindingResponse or BindingRequestTimeout
    pub fn send_binding_request(&mut self) -> Result<String> {
        if let Some(stun_serv_addr) = &self.stun_serv_addr {
            self.send_binding_request_to(*stun_serv_addr)
        } else {
            Err(Error::ErrStunserverAddressNotSet)
        }
    }

    // find_addr_by_channel_number returns a peer address associated with the
    // channel number on this UDPConn
    fn find_addr_by_channel_number(&self, ch_num: u16) -> Option<SocketAddr> {
        self.binding_mgr.find_by_number(ch_num).map(|b| b.addr)
    }

    // stun_server_addr return the STUN server address
    fn stun_server_addr(&self) -> Option<SocketAddr> {
        self.stun_serv_addr
    }

    /*/// Allocate sends a TURN allocation request to the given transport address
    TODO:pub fn allocate(&mut self) -> Result<RelayConnConfig> {
        {
            let read_ch_tx = self.read_ch_tx.lock().await;
            log::debug!("allocate check: read_ch_tx_opt = {}", read_ch_tx.is_some());
            if read_ch_tx.is_some() {
                return Err(Error::ErrOneAllocateOnly);
            }
        }

        let mut msg = Message::new();
        msg.build(&[
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
            Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            }),
            Box::new(FINGERPRINT),
        ])?;

        log::debug!("client.Allocate call PerformTransaction 1");
        let tr_res = self
            .perform_transaction(&msg, &self.turn_serv_addr.clone(), false)
            .await?;
        let res = tr_res.msg;

        // Anonymous allocate failed, trying to authenticate.
        let nonce = Nonce::get_from_as(&res, ATTR_NONCE)?;
        self.realm = Realm::get_from_as(&res, ATTR_REALM)?;

        self.integrity = MessageIntegrity::new_long_term_integrity(
            self.username.text.clone(),
            self.realm.text.clone(),
            self.password.clone(),
        );

        // Trying to authorize.
        msg.build(&[
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
            Box::new(RequestedTransport {
                protocol: PROTO_UDP,
            }),
            Box::new(self.username.clone()),
            Box::new(self.realm.clone()),
            Box::new(nonce.clone()),
            Box::new(self.integrity.clone()),
            Box::new(FINGERPRINT),
        ])?;

        log::debug!("client.Allocate call PerformTransaction 2");
        let tr_res = self
            .perform_transaction(&msg, &self.turn_serv_addr.clone(), false)
            .await?;
        let res = tr_res.msg;

        if res.typ.class == CLASS_ERROR_RESPONSE {
            let mut code = ErrorCodeAttribute::default();
            let result = code.get_from(&res);
            if result.is_err() {
                return Err(Error::Other(format!("{}", res.typ)));
            } else {
                return Err(Error::Other(format!("{} (error {})", res.typ, code)));
            }
        }

        // Getting relayed addresses from response.
        let mut relayed = RelayedAddress::default();
        relayed.get_from(&res)?;
        let relayed_addr = SocketAddr::new(relayed.ip, relayed.port);

        // Getting lifetime from response
        let mut lifetime = Lifetime::default();
        lifetime.get_from(&res)?;

        let (read_ch_tx, read_ch_rx) = mpsc::channel(MAX_READ_QUEUE_SIZE);
        {
            let mut read_ch_tx_opt = self.read_ch_tx.lock().await;
            *read_ch_tx_opt = Some(read_ch_tx);
            log::debug!("allocate: read_ch_tx_opt = {}", read_ch_tx_opt.is_some());
        }

        Ok(RelayConnConfig {
            relayed_addr,
            integrity: self.integrity.clone(),
            nonce,
            lifetime: lifetime.0,
            binding_mgr: Arc::clone(&self.binding_mgr),
            read_ch_rx: Arc::new(Mutex::new(read_ch_rx)),
        })
    }

    pub async fn allocate(&self) -> Result<impl Conn> {
        let config = {
            let mut ci = self.client_internal.lock().await;
            ci.allocate().await?
        };

        Ok(RelayConn::new(Arc::clone(&self.client_internal), config).await)
    }*/

    /// turn_server_addr return the TURN server address
    fn turn_server_addr(&self) -> SocketAddr {
        self.turn_serv_addr
    }

    /// username returns username
    fn username(&self) -> Username {
        self.username.clone()
    }

    /// realm return realm
    fn realm(&self) -> Realm {
        self.realm.clone()
    }

    /// WriteTo sends data to the specified destination using the base socket.
    fn write(&mut self, data: &[u8], remote: SocketAddr) {
        self.transmits.push_back(Transmit {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: self.local_addr,
                peer_addr: remote,
                protocol: self.protocol,
                ecn: None,
            },
            message: BytesMut::from(data),
        });
    }

    // PerformTransaction performs STUN transaction
    fn perform_transaction(&mut self, msg: &Message, to: SocketAddr) -> Result<String> {
        let tr_key = BASE64_STANDARD.encode(msg.transaction_id.0);

        let tr = Transaction::new(TransactionConfig {
            key: tr_key.clone(),
            raw: BytesMut::from(&msg.raw[..]),
            local_addr: self.local_addr,
            peer_addr: to,
            protocol: self.protocol,
            interval: self.rto_in_ms,
        });

        log::trace!(
            "start {} transaction {} to {}",
            msg.typ,
            tr_key,
            tr.peer_addr
        );
        self.tr_map.insert(tr_key.clone(), tr);

        self.write(&msg.raw, to);

        Ok(tr_key)
    }
}
