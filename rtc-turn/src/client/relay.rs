use log::{debug, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Add;
use std::time::{Duration, Instant};

use stun::attributes::*;
use stun::error_code::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;

use super::permission::*;
use super::transaction::*;
use crate::proto;

use crate::client::binding::BindingState;
use crate::client::{Client, Event, RelayedAddr};
use shared::error::{Error, Result};

const PERM_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
// https://datatracker.ietf.org/doc/html/rfc8656#name-permissions-2
// The Permission Lifetime MUST be 300 seconds (= 5 minutes).
const PERM_LIFETIME: Duration = Duration::from_secs(300);
const MAX_RETRY_ATTEMPTS: u16 = 3;

// RelayState is a set of params use by Relay
pub(crate) struct RelayState {
    pub(crate) relayed_addr: RelayedAddr,
    pub(crate) integrity: MessageIntegrity,
    pub(crate) nonce: Nonce,
    pub(crate) lifetime: Duration,
    perm_map: HashMap<SocketAddr, Permission>,
    refresh_alloc_timer: Instant,
    refresh_perms_timer: Instant,
}

impl RelayState {
    pub(super) fn new(
        relayed_addr: RelayedAddr,
        integrity: MessageIntegrity,
        nonce: Nonce,
        lifetime: Duration,
    ) -> Self {
        debug!("initial lifetime: {} seconds", lifetime.as_secs());

        Self {
            relayed_addr,
            integrity,
            nonce,
            lifetime,
            perm_map: HashMap::new(),
            refresh_alloc_timer: Instant::now().add(lifetime / 2),
            refresh_perms_timer: Instant::now().add(PERM_REFRESH_INTERVAL),
        }
    }

    pub(super) fn set_nonce_from_msg(&mut self, msg: &Message) {
        // Update nonce
        match Nonce::get_from_as(msg, ATTR_NONCE) {
            Ok(nonce) => {
                self.nonce = nonce;
                debug!("refresh allocation: 438, got new nonce.");
            }
            Err(_) => warn!("refresh allocation: 438 but no nonce."),
        }
    }
}

// Relay is the implementation of the Conn interfaces for UDP Relayed network connections.
pub struct Relay<'a> {
    pub(crate) relayed_addr: RelayedAddr,
    pub(crate) client: &'a mut Client,
}

impl<'a> Relay<'a> {
    pub fn create_permission(&mut self, peer_addr: SocketAddr) -> Result<Option<TransactionId>> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            relay
                .perm_map
                .entry(peer_addr)
                .or_insert_with(Permission::default);
            if let Some(perm) = relay.perm_map.get(&peer_addr) {
                if perm.state() == PermState::Idle {
                    return Ok(Some(
                        self.create_permissions(&[peer_addr], Some(peer_addr))?,
                    ));
                }
            }
            Ok(None)
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        if let Some(relay) = self.client.relays.get(&self.relayed_addr) {
            if relay.refresh_alloc_timer < relay.refresh_perms_timer {
                Some(relay.refresh_alloc_timer)
            } else {
                Some(relay.refresh_perms_timer)
            }
        } else {
            None
        }
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant) {
        let (refresh_alloc_timer, refresh_perms_timer) = if let Some(relay) =
            self.client.relays.get_mut(&self.relayed_addr)
        {
            let refresh_alloc_timer = if relay.refresh_alloc_timer <= now {
                relay.refresh_alloc_timer = relay.refresh_alloc_timer.add(relay.lifetime / 2);
                Some(relay.lifetime)
            } else {
                None
            };

            let refresh_perms_timer = if relay.refresh_perms_timer <= now {
                relay.refresh_perms_timer = relay.refresh_perms_timer.add(PERM_REFRESH_INTERVAL);
                true
            } else {
                false
            };

            (refresh_alloc_timer, refresh_perms_timer)
        } else {
            (None, false)
        };

        if let Some(lifetime) = refresh_alloc_timer {
            let _ = self.refresh_allocation(lifetime);
        }
        if refresh_perms_timer {
            let _ = self.refresh_permissions();
        }
    }

    pub fn send_to(&mut self, p: &[u8], peer_addr: SocketAddr) -> Result<()> {
        // check if we have a permission for the destination IP addr
        let result = if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            if let Some(perm) = relay.perm_map.get_mut(&peer_addr) {
                if perm.state() != PermState::Permitted {
                    Err(Error::ErrNoPermission)
                } else {
                    Ok((relay.integrity.clone(), relay.nonce.clone()))
                }
            } else {
                Err(Error::ErrNoPermission)
            }
        } else {
            Err(Error::ErrConnClosed)
        };

        let (integrity, nonce) = result?;

        self.send(p, peer_addr, integrity, nonce)
    }

    fn send(
        &mut self,
        p: &[u8],
        peer_addr: SocketAddr,
        integrity: MessageIntegrity,
        nonce: Nonce,
    ) -> Result<()> {
        let channel_number = {
            let (bind_st, bind_at, bind_number, bind_addr) = {
                let b = if let Some(b) = self.client.binding_mgr.find_by_addr(&peer_addr) {
                    b
                } else {
                    self.client
                        .binding_mgr
                        .create(peer_addr)
                        .ok_or_else(|| Error::Other("Addr not found".to_owned()))?
                };
                (b.state(), b.refreshed_at(), b.number, b.addr)
            };

            if bind_st == BindingState::Idle
                || bind_st == BindingState::Request
                || bind_st == BindingState::Failed
            {
                // block only callers with the same binding until
                // the binding transaction has been complete
                // binding state may have been changed while waiting. check again.
                if bind_st == BindingState::Idle {
                    if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr) {
                        b.set_state(BindingState::Request);
                    }
                    self.channel_bind(self.relayed_addr, bind_addr, bind_number, nonce, integrity)?;
                }

                // send data using SendIndication
                let mut msg = Message::new();
                msg.build(&[
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_SEND, CLASS_INDICATION)),
                    Box::new(proto::data::Data(p.to_vec())),
                    Box::new(proto::peeraddr::PeerAddress {
                        ip: peer_addr.ip(),
                        port: peer_addr.port(),
                    }),
                    Box::new(FINGERPRINT),
                ])?;

                // indication has no transaction (fire-and-forget)
                self.client
                    .write_to(&msg.raw, self.client.turn_server_addr()?);
                return Ok(());
            }

            // binding is ready
            // check if the binding needs a refresh
            if bind_st == BindingState::Ready
                && Instant::now()
                    .checked_duration_since(bind_at)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    > PERM_LIFETIME
            {
                if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr) {
                    b.set_state(BindingState::Refresh);
                }
                self.channel_bind(self.relayed_addr, bind_addr, bind_number, nonce, integrity)?;
            }

            bind_number
        };

        // send via ChannelData
        self.send_channel_data(p, channel_number)
    }

    // Close closes the connection.
    // Any blocked ReadFrom or write_to operations will be unblocked and return errors.
    pub fn close(&mut self) -> Result<()> {
        self.refresh_allocation(Duration::from_secs(0))
    }

    fn create_permissions(
        &mut self,
        peer_addrs: &[SocketAddr],
        peer_addr_opt: Option<SocketAddr>,
    ) -> Result<TransactionId> {
        let (username, realm) = (self.client.username(), self.client.realm());
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            let msg = {
                let mut setters: Vec<Box<dyn Setter>> = vec![
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_CREATE_PERMISSION, CLASS_REQUEST)),
                ];

                for addr in peer_addrs {
                    setters.push(Box::new(proto::peeraddr::PeerAddress {
                        ip: addr.ip(),
                        port: addr.port(),
                    }));
                }

                setters.push(Box::new(username));
                setters.push(Box::new(realm));
                setters.push(Box::new(relay.nonce.clone()));
                setters.push(Box::new(relay.integrity.clone()));
                setters.push(Box::new(FINGERPRINT));

                let mut msg = Message::new();
                msg.build(&setters)?;
                msg
            };

            Ok(self.client.perform_transaction(
                &msg,
                self.client.turn_server_addr()?,
                TransactionType::CreatePermissionRequest(self.relayed_addr, peer_addr_opt),
            ))
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    pub(super) fn handle_create_permission_response(
        &mut self,
        res: Message,
        peer_addr_opt: Option<SocketAddr>,
    ) -> Result<()> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            if res.typ.class == CLASS_ERROR_RESPONSE {
                let mut code = ErrorCodeAttribute::default();
                let result = code.get_from(&res);
                let err = if result.is_err() {
                    Error::Other(format!("{}", res.typ))
                } else if code.code == CODE_STALE_NONCE {
                    relay.set_nonce_from_msg(&res);
                    Error::ErrTryAgain
                } else {
                    Error::Other(format!("{} (error {})", res.typ, code))
                };
                if let Some(peer_addr) = peer_addr_opt {
                    self.client
                        .events
                        .push_back(Event::CreatePermissionError(res.transaction_id, err));
                    relay.perm_map.remove(&peer_addr);
                }
            } else if let Some(peer_addr) = peer_addr_opt {
                if let Some(perm) = relay.perm_map.get_mut(&peer_addr) {
                    perm.set_state(PermState::Permitted);
                    self.client
                        .events
                        .push_back(Event::CreatePermissionResponse(
                            res.transaction_id,
                            peer_addr,
                        ));
                }
            }

            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    fn refresh_allocation(&mut self, lifetime: Duration) -> Result<()> {
        let (username, realm) = (self.client.username(), self.client.realm());
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            let mut msg = Message::new();
            msg.build(&[
                Box::new(TransactionId::new()),
                Box::new(MessageType::new(METHOD_REFRESH, CLASS_REQUEST)),
                Box::new(proto::lifetime::Lifetime(lifetime)),
                Box::new(username),
                Box::new(realm),
                Box::new(relay.nonce.clone()),
                Box::new(relay.integrity.clone()),
                Box::new(FINGERPRINT),
            ])?;

            let _ = self.client.perform_transaction(
                &msg,
                self.client.turn_server_addr()?,
                TransactionType::RefreshRequest(self.relayed_addr),
            );

            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    pub(super) fn handle_refresh_allocation_response(&mut self, res: Message) -> Result<()> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            if res.typ.class == CLASS_ERROR_RESPONSE {
                let mut code = ErrorCodeAttribute::default();
                let result = code.get_from(&res);
                if result.is_err() {
                    Err(Error::Other(format!("{}", res.typ)))
                } else if code.code == CODE_STALE_NONCE {
                    relay.set_nonce_from_msg(&res);
                    //Error::ErrTryAgain
                    Ok(())
                } else {
                    Err(Error::Other(format!("{} (error {})", res.typ, code)))
                }
            } else {
                // Getting lifetime from response
                let mut updated_lifetime = proto::lifetime::Lifetime::default();
                updated_lifetime.get_from(&res)?;

                relay.lifetime = updated_lifetime.0;
                debug!("updated lifetime: {} seconds", relay.lifetime.as_secs());

                Ok(())
            }
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    fn refresh_permissions(&mut self) -> Result<()> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            #[allow(clippy::map_clone)]
            let addrs: Vec<SocketAddr> = relay.perm_map.keys().map(|addr| *addr).collect();
            if addrs.is_empty() {
                debug!("no permission to refresh");
                return Ok(());
            }
            let _ = self.create_permissions(&addrs, None)?;
            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    fn channel_bind(
        &mut self,
        relayed_addr: RelayedAddr,
        bind_addr: SocketAddr,
        bind_number: u16,
        nonce: Nonce,
        integrity: MessageIntegrity,
    ) -> Result<()> {
        let (msg, turn_server_addr) = {
            let setters: Vec<Box<dyn Setter>> = vec![
                Box::new(TransactionId::new()),
                Box::new(MessageType::new(METHOD_CHANNEL_BIND, CLASS_REQUEST)),
                Box::new(proto::peeraddr::PeerAddress {
                    ip: bind_addr.ip(),
                    port: bind_addr.port(),
                }),
                Box::new(proto::channum::ChannelNumber(bind_number)),
                Box::new(self.client.username()),
                Box::new(self.client.realm()),
                Box::new(nonce),
                Box::new(integrity),
                Box::new(FINGERPRINT),
            ];

            let mut msg = Message::new();
            msg.build(&setters)?;

            (msg, self.client.turn_server_addr()?)
        };

        debug!("UDPConn.bind call PerformTransaction 1");
        let _ = self.client.perform_transaction(
            &msg,
            turn_server_addr,
            TransactionType::ChannelBindRequest(relayed_addr, bind_addr),
        );

        Ok(())
    }

    pub(super) fn handle_channel_bind_response(
        &mut self,
        res: Message,
        bind_addr: SocketAddr,
    ) -> Result<()> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            let result = if res.typ.class == CLASS_ERROR_RESPONSE {
                let mut code = ErrorCodeAttribute::default();
                let result = code.get_from(&res);
                if result.is_err() {
                    Err(Error::Other(format!("{}", res.typ)))
                } else if code.code == CODE_STALE_NONCE {
                    relay.set_nonce_from_msg(&res);
                    Err(Error::ErrTryAgain)
                } else {
                    Err(Error::Other(format!("{} (error {})", res.typ, code)))
                }
            } else if res.typ != MessageType::new(METHOD_CHANNEL_BIND, CLASS_SUCCESS_RESPONSE) {
                Err(Error::ErrUnexpectedResponse)
            } else {
                Ok(())
            };

            if let Err(err) = result {
                if Error::ErrUnexpectedResponse != err {
                    self.client.binding_mgr.delete_by_addr(&bind_addr);
                } else if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr) {
                    b.set_state(BindingState::Failed);
                }

                // keep going...
                warn!("bind() failed: {}", err);
            } else if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr) {
                b.set_refreshed_at(Instant::now());
                b.set_state(BindingState::Ready);
                debug!("channel binding successful: {}", bind_addr);
            }
            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    fn send_channel_data(&mut self, data: &[u8], channel_number: u16) -> Result<()> {
        let mut ch_data = proto::chandata::ChannelData {
            data: data.to_vec(),
            number: proto::channum::ChannelNumber(channel_number),
            ..Default::default()
        };
        ch_data.encode();

        self.client
            .write_to(&ch_data.raw, self.client.turn_server_addr()?);

        Ok(())
    }
}
