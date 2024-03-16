#[cfg(test)]
mod client_test;

pub mod binding;
pub mod permission;
pub mod relay;
pub mod transaction;

use bytes::BytesMut;
use log::{debug, trace};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use stun::attributes::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;
use stun::xoraddr::*;

use binding::*;
use transaction::*;

use crate::client::relay::{Relay, RelayState};
use crate::proto::chandata::*;
use crate::proto::channum::ChannelNumber;
use crate::proto::data::*;
use crate::proto::lifetime::Lifetime;
use crate::proto::peeraddr::*;
use crate::proto::relayaddr::RelayedAddress;
use crate::proto::reqtrans::RequestedTransport;
use crate::proto::{PROTO_TCP, PROTO_UDP};
use shared::error::{Error, Result};
use shared::util::lookup_host;
use shared::{Protocol, Transmit, TransportContext};
use stun::error_code::ErrorCodeAttribute;
use stun::fingerprint::FINGERPRINT;

const DEFAULT_RTO_IN_MS: u64 = 200;
const MAX_DATA_BUFFER_SIZE: usize = u16::MAX as usize; // message size limit for Chromium
const MAX_READ_QUEUE_SIZE: usize = 1024;

pub type RelayedAddr = SocketAddr;
pub type ReflexiveAddr = SocketAddr;
pub type PeerAddr = SocketAddr;

pub enum Event {
    TransactionTimeout(TransactionId),

    BindingResponse(TransactionId, ReflexiveAddr),
    BindingError(TransactionId, Error),

    AllocateResponse(TransactionId, RelayedAddr),
    AllocateError(TransactionId, Error),

    CreatePermissionResponse(TransactionId),
    CreatePermissionError(TransactionId, Error),

    DataIndicationOrChannelData(Option<ChannelNumber>, PeerAddr, BytesMut),
}

enum AllocateState {
    Attempting,
    Requesting(TextAttribute),
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
    turn_serv_addr: Option<SocketAddr>,
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

    relays: HashMap<RelayedAddr, RelayState>,
    transmits: VecDeque<Transmit<BytesMut>>,
    events: VecDeque<Event>,
}

impl Client {
    /// new returns a new Client instance. listeningAddress is the address and port to listen on, default "0.0.0.0:0"
    pub fn new(config: ClientConfig) -> Result<Self> {
        let stun_serv_addr = if config.stun_serv_addr.is_empty() {
            None
        } else {
            Some(lookup_host(
                config.local_addr.is_ipv4(),
                config.stun_serv_addr.as_str(),
            )?)
        };

        let turn_serv_addr = if config.turn_serv_addr.is_empty() {
            None
        } else {
            Some(lookup_host(
                config.local_addr.is_ipv4(),
                config.turn_serv_addr.as_str(),
            )?)
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

            relays: HashMap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        })
    }

    pub fn poll_timout(&mut self) -> Option<Instant> {
        let mut eto = None;
        if let Some(to) = self.tr_map.poll_timout() {
            if eto.is_none() || to < *eto.as_ref().unwrap() {
                eto = Some(to);
            }
        }

        #[allow(clippy::map_clone)]
        let relayed_addrs: Vec<SocketAddr> = self.relays.keys().map(|key| *key).collect();
        for relayed_addr in relayed_addrs {
            let relay = Relay {
                relayed_addr,
                client: self,
            };
            if let Some(to) = relay.poll_timeout() {
                if eto.is_none() || to < *eto.as_ref().unwrap() {
                    eto = Some(to);
                }
            }
        }

        eto
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.tr_map.handle_timeout(now);

        #[allow(clippy::map_clone)]
        let relayed_addrs: Vec<SocketAddr> = self.relays.keys().map(|key| *key).collect();
        for relayed_addr in relayed_addrs {
            let mut relay = Relay {
                relayed_addr,
                client: self,
            };
            relay.handle_timeout(now);
        }
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

    pub fn poll_event(&mut self) -> Option<Event> {
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
            trace!("non-STUN/TURN packet, unhandled");
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

                debug!("data indication received from {}", from);

                self.events.push_back(Event::DataIndicationOrChannelData(
                    None,
                    from,
                    BytesMut::from(&data.0[..]),
                ))
            }

            return Ok(());
        }

        // This is a STUN response message (transactional)
        // The type is either:
        // - stun.ClassSuccessResponse
        // - stun.ClassErrorResponse

        if self.tr_map.find(&msg.transaction_id).is_none() {
            // silently discard
            debug!("no transaction for {}", msg);
            return Ok(());
        }

        if let Some(tr) = self.tr_map.delete(&msg.transaction_id) {
            match msg.typ.method {
                METHOD_BINDING => {
                    if msg.typ.class == CLASS_ERROR_RESPONSE {
                        let mut code = ErrorCodeAttribute::default();
                        let err = if code.get_from(&msg).is_err() {
                            Error::Other(format!("{}", msg.typ))
                        } else {
                            Error::Other(format!("{} (error {})", msg.typ, code))
                        };
                        self.events
                            .push_back(Event::BindingError(tr.transaction_id, err));
                    } else {
                        let mut refl_addr = XorMappedAddress::default();
                        match refl_addr.get_from(&msg) {
                            Ok(_) => {
                                self.events.push_back(Event::BindingResponse(
                                    tr.transaction_id,
                                    ReflexiveAddr::new(refl_addr.ip, refl_addr.port),
                                ));
                            }
                            Err(err) => {
                                self.events
                                    .push_back(Event::BindingError(tr.transaction_id, err));
                            }
                        }
                    }
                }
                METHOD_ALLOCATE => {
                    self.handle_allocate_response(msg, tr.transaction_type)?;
                }
                METHOD_CREATE_PERMISSION => {
                    if let TransactionType::CreatePermissionRequest(relayed_addr, peer_addr) =
                        tr.transaction_type
                    {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_create_permission_response(msg, peer_addr)?;
                    }
                }
                METHOD_REFRESH => {
                    if let TransactionType::RefreshRequest(relayed_addr) = tr.transaction_type {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_refresh_allocation_response(msg)?;
                    }
                }
                METHOD_CHANNEL_BIND => {
                    if let TransactionType::ChannelBindRequest(relayed_addr, bind_addr) =
                        tr.transaction_type
                    {
                        let mut relay = Relay {
                            relayed_addr,
                            client: self,
                        };
                        relay.handle_channel_bind_response(msg, bind_addr)?;
                    }
                }
                _ => {}
            }
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

        trace!(
            "channel data received from {} (ch={})",
            addr,
            ch_data.number.0
        );

        self.events.push_back(Event::DataIndicationOrChannelData(
            Some(ch_data.number),
            addr,
            BytesMut::from(&ch_data.data[..]),
        ));

        Ok(())
    }

    /// Close closes this client
    pub fn close(&mut self) {
        self.tr_map.delete_all();
    }

    pub fn relay(&mut self, relayed_addr: SocketAddr) -> Result<Relay<'_>> {
        if !self.relays.contains_key(&relayed_addr) {
            Err(Error::ErrStreamNotExisted)
        } else {
            Ok(Relay {
                relayed_addr,
                client: self,
            })
        }
    }

    /// send_binding_request_to sends a new STUN request to the given transport address
    /// return key to find out corresponding Event either BindingResponse or BindingRequestTimeout
    pub fn send_binding_request_to(&mut self, to: SocketAddr) -> Result<TransactionId> {
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

        debug!("client.SendBindingRequestTo call PerformTransaction 1");
        Ok(self.perform_transaction(&msg, to, TransactionType::BindingRequest))
    }

    /// send_binding_request sends a new STUN request to the STUN server
    /// return key to find out corresponding Event either BindingResponse or BindingRequestTimeout
    pub fn send_binding_request(&mut self) -> Result<TransactionId> {
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

    /* https://datatracker.ietf.org/doc/html/rfc8656#section-20
    TURN                                 TURN          Peer         Peer
    client                               server         A            B
      |                                    |            |            |
      |--- Allocate request -------------->|            |            |
      |    Transaction-Id=0xA56250D3F17ABE679422DE85    |            |
      |    SOFTWARE="Example client, version 1.03"      |            |
      |    LIFETIME=3600 (1 hour)          |            |            |
      |    REQUESTED-TRANSPORT=17 (UDP)    |            |            |
      |    DONT-FRAGMENT                   |            |            |
      |                                    |            |            |
      |<-- Allocate error response --------|            |            |
      |    Transaction-Id=0xA56250D3F17ABE679422DE85    |            |
      |    SOFTWARE="Example server, version 1.17"      |            |
      |    ERROR-CODE=401 (Unauthorized)   |            |            |
      |    REALM="example.com"             |            |            |
      |    NONCE="obMatJos2gAAAadl7W7PeDU4hKE72jda"     |            |
      |    PASSWORD-ALGORITHMS=MD5 and SHA256           |            |
      |                                    |            |            |
      |--- Allocate request -------------->|            |            |
      |    Transaction-Id=0xC271E932AD7446A32C234492    |            |
      |    SOFTWARE="Example client 1.03"  |            |            |
      |    LIFETIME=3600 (1 hour)          |            |            |
      |    REQUESTED-TRANSPORT=17 (UDP)    |            |            |
      |    DONT-FRAGMENT                   |            |            |
      |    USERNAME="George"               |            |            |
      |    REALM="example.com"             |            |            |
      |    NONCE="obMatJos2gAAAadl7W7PeDU4hKE72jda"     |            |
      |    PASSWORD-ALGORITHMS=MD5 and SHA256           |            |
      |    PASSWORD-ALGORITHM=SHA256       |            |            |
      |    MESSAGE-INTEGRITY=...           |            |            |
      |    MESSAGE-INTEGRITY-SHA256=...    |            |            |
      |                                    |            |            |
      |<-- Allocate success response ------|            |            |
      |    Transaction-Id=0xC271E932AD7446A32C234492    |            |
      |    SOFTWARE="Example server, version 1.17"      |            |
      |    LIFETIME=1200 (20 minutes)      |            |            |
      |    XOR-RELAYED-ADDRESS=192.0.2.15:50000         |            |
      |    XOR-MAPPED-ADDRESS=192.0.2.1:7000            |            |
      |    MESSAGE-INTEGRITY-SHA256=...    |            |            |
    */
    /// Allocate sends a TURN allocation request to the given transport address
    pub fn allocate(&mut self) -> Result<TransactionId> {
        let mut msg = Message::new();
        msg.build(&[
            Box::new(TransactionId::new()),
            Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
            Box::new(RequestedTransport {
                protocol: if self.protocol == Protocol::UDP {
                    PROTO_UDP
                } else {
                    PROTO_TCP
                },
            }),
            Box::new(FINGERPRINT),
        ])?;

        debug!("client.Allocate call PerformTransaction 1");
        let tid = self.perform_transaction(
            &msg,
            self.turn_server_addr()?,
            TransactionType::AllocateAttempt,
        );
        Ok(tid)
    }

    fn handle_allocate_response(
        &mut self,
        response: Message,
        allocate_state: TransactionType,
    ) -> Result<()> {
        match allocate_state {
            TransactionType::AllocateAttempt => {
                // Anonymous allocate failed, trying to authenticate.
                let nonce = match Nonce::get_from_as(&response, ATTR_NONCE) {
                    Ok(nonce) => nonce,
                    Err(err) => {
                        self.events
                            .push_back(Event::AllocateError(response.transaction_id, err));
                        return Ok(());
                    }
                };
                self.realm = match Realm::get_from_as(&response, ATTR_REALM) {
                    Ok(realm) => realm,
                    Err(err) => {
                        self.events
                            .push_back(Event::AllocateError(response.transaction_id, err));
                        return Ok(());
                    }
                };

                self.integrity = MessageIntegrity::new_long_term_integrity(
                    self.username.text.clone(),
                    self.realm.text.clone(),
                    self.password.clone(),
                );

                let mut msg = Message::new();
                // Trying to authorize.
                msg.build(&[
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
                    Box::new(RequestedTransport {
                        protocol: if self.protocol == Protocol::UDP {
                            PROTO_UDP
                        } else {
                            PROTO_TCP
                        },
                    }),
                    Box::new(self.username.clone()),
                    Box::new(self.realm.clone()),
                    Box::new(nonce.clone()),
                    Box::new(self.integrity.clone()),
                    Box::new(FINGERPRINT),
                ])?;

                debug!("client.Allocate call PerformTransaction 2");
                self.perform_transaction(
                    &msg,
                    self.turn_server_addr()?,
                    TransactionType::AllocateRequest(nonce),
                );
            }
            TransactionType::AllocateRequest(nonce) => {
                if response.typ.class == CLASS_ERROR_RESPONSE {
                    let mut code = ErrorCodeAttribute::default();
                    let err = if code.get_from(&response).is_err() {
                        Error::Other(format!("{}", response.typ))
                    } else {
                        Error::Other(format!("{} (error {})", response.typ, code))
                    };
                    self.events
                        .push_back(Event::AllocateError(response.transaction_id, err));
                    return Ok(());
                }

                // Getting relayed addresses from response.
                let mut relayed = RelayedAddress::default();
                relayed.get_from(&response)?;
                let relayed_addr = RelayedAddr::new(relayed.ip, relayed.port);

                // Getting lifetime from response
                let mut lifetime = Lifetime::default();
                lifetime.get_from(&response)?;

                self.relays.insert(
                    relayed_addr,
                    RelayState::new(relayed_addr, self.integrity.clone(), nonce, lifetime.0),
                );
                self.events.push_back(Event::AllocateResponse(
                    response.transaction_id,
                    relayed_addr,
                ));
            }
            _ => {}
        }
        Ok(())
    }

    /// turn_server_addr return the TURN server address
    fn turn_server_addr(&self) -> Result<SocketAddr> {
        self.turn_serv_addr.ok_or(Error::ErrNilTurnSocket)
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
    fn write_to(&mut self, data: &[u8], remote: SocketAddr) {
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
    fn perform_transaction(
        &mut self,
        msg: &Message,
        to: SocketAddr,
        transaction_type: TransactionType,
    ) -> TransactionId {
        let tr = Transaction::new(TransactionConfig {
            transaction_id: msg.transaction_id,
            transaction_type,
            raw: BytesMut::from(&msg.raw[..]),
            local_addr: self.local_addr,
            peer_addr: to,
            protocol: self.protocol,
            interval: self.rto_in_ms,
        });

        trace!(
            "start {} transaction {:?} to {}",
            msg.typ,
            msg.transaction_id,
            tr.peer_addr
        );
        self.tr_map.insert(msg.transaction_id, tr);

        self.write_to(&msg.raw, to);

        msg.transaction_id
    }
}
