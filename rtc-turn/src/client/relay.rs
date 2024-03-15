//TODO: #[cfg(test)]
//mod relay_conn_test;

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

use crate::client::{Client, Event};
use shared::error::{Error, Result};

const PERM_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
const MAX_RETRY_ATTEMPTS: u16 = 3;

// RelayState is a set of params use by Relay
pub(crate) struct RelayState {
    pub(crate) relayed_addr: SocketAddr,
    pub(crate) integrity: MessageIntegrity,
    pub(crate) nonce: Nonce,
    pub(crate) lifetime: Duration,
    perm_map: PermissionMap,
    refresh_alloc_timer: Instant,
    refresh_perms_timer: Instant,
}

impl RelayState {
    pub(crate) fn new(
        relayed_addr: SocketAddr,
        integrity: MessageIntegrity,
        nonce: Nonce,
        lifetime: Duration,
    ) -> Self {
        log::debug!("initial lifetime: {} seconds", lifetime.as_secs());

        Self {
            relayed_addr,
            integrity,
            nonce,
            lifetime,
            perm_map: PermissionMap::new(),
            refresh_alloc_timer: Instant::now().add(lifetime / 2),
            refresh_perms_timer: Instant::now().add(PERM_REFRESH_INTERVAL),
        }
    }

    pub fn set_nonce_from_msg(&mut self, msg: &Message) {
        // Update nonce
        match Nonce::get_from_as(msg, ATTR_NONCE) {
            Ok(nonce) => {
                self.nonce = nonce;
                log::debug!("refresh allocation: 438, got new nonce.");
            }
            Err(_) => log::warn!("refresh allocation: 438 but no nonce."),
        }
    }
}

// Relay is the implementation of the Conn interfaces for UDP Relayed network connections.
pub struct Relay<'a> {
    pub(crate) relayed_addr: SocketAddr,
    pub(crate) client: &'a mut Client,
}

impl<'a> Relay<'a> {
    /// This func-block would block, per destination IP (, or perm), until
    /// the perm state becomes "requested". Purpose of this is to guarantee
    /// the order of packets (within the same perm).
    /// Note that CreatePermission transaction may not be complete before
    /// all the data transmission. This is done assuming that the request
    /// will be mostly likely successful and we can tolerate some loss of
    /// UDP packet (or reorder), inorder to minimize the latency in most cases.
    pub fn create_permission(&mut self, addr: SocketAddr) -> Result<()> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            if !relay.perm_map.contains(&addr) {
                relay.perm_map.insert(addr, Permission::default());
            }

            if let Some(perm) = relay.perm_map.get(&addr) {
                if perm.state() == PermState::Idle {
                    // punch a hole! (this would block a bit..)
                    self.create_permissions(&[addr], Some(addr))?;
                }
            }
            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    pub fn poll_timeout(&self) -> Option<Instant> {
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

    pub fn handle_timeout(&mut self, now: Instant) {
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

    // new creates a new instance of UDPConn
    // write_to writes a packet with payload p to addr.
    // write_to can be made to time out and return
    // an Error with Timeout() == true after a fixed time limit;
    // see SetDeadline and SetWriteDeadline.
    // On packet-oriented connections, write timeouts are rare.
    pub fn send_to(&mut self, _p: &[u8], addr: SocketAddr) -> Result<()> {
        // check if we have a permission for the destination IP addr
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            if let Some(perm) = relay.perm_map.get_mut(&addr) {
                if perm.state() != PermState::Permitted {
                    Err(Error::ErrNoPermission)
                } else {
                    //TODO:
                    Ok(())
                }
            } else {
                Err(Error::ErrNoPermission)
            }
        } else {
            Err(Error::ErrConnClosed)
        }

        /*TODO:
        let number = {
            let (bind_st, bind_at, bind_number, bind_addr) = {
                let b = if let Some(b) = self.client.binding_mgr.find_by_addr(&addr) {
                    b
                } else {
                    self.client
                        .binding_mgr
                        .create(addr)
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
                    let nonce = self.nonce.clone();
                    let integrity = self.integrity.clone();
                    {
                        if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr) {
                            b.set_state(BindingState::Request);
                        }
                    }
                    tokio::spawn(async move {
                        let result = RelayConnInternal::bind(
                            rc_obs,
                            bind_addr,
                            bind_number,
                            nonce,
                            integrity,
                        )
                        .await;

                        {
                            if let Err(err) = result {
                                if Error::ErrUnexpectedResponse != err {
                                    self.client.binding_mgr.delete_by_addr(&bind_addr);
                                } else if let Some(b) =
                                    self.client.binding_mgr.get_by_addr(&bind_addr)
                                {
                                    b.set_state(BindingState::Failed);
                                }

                                // keep going...
                                log::warn!("bind() failed: {}", err);
                            } else if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr)
                            {
                                b.set_state(BindingState::Ready);
                            }
                        }
                    });
                }

                // send data using SendIndication
                let peer_addr = proto::peeraddr::PeerAddress {
                    ip: addr.ip(),
                    port: addr.port(),
                };
                let mut msg = Message::new();
                msg.build(&[
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_SEND, CLASS_INDICATION)),
                    Box::new(proto::data::Data(p.to_vec())),
                    Box::new(peer_addr),
                    Box::new(FINGERPRINT),
                ])?;

                // indication has no transaction (fire-and-forget)
                let turn_server_addr = self.client.turn_server_addr();
                return Ok(self.client.write_to(&msg.raw, &turn_server_addr)?);
            }

            // binding is either ready

            // check if the binding needs a refresh
            if bind_st == BindingState::Ready
                && Instant::now()
                    .checked_duration_since(bind_at)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    > Duration::from_secs(5 * 60)
            {
                let nonce = self.nonce.clone();
                let integrity = self.integrity.clone();
                {
                    if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr) {
                        b.set_state(BindingState::Refresh);
                    }
                }
                tokio::spawn(async move {
                    let result =
                        RelayConnInternal::bind(rc_obs, bind_addr, bind_number, nonce, integrity)
                            .await;

                    {
                        if let Err(err) = result {
                            if Error::ErrUnexpectedResponse != err {
                                self.client.binding_mgr.delete_by_addr(&bind_addr);
                            } else if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr)
                            {
                                b.set_state(BindingState::Failed);
                            }

                            // keep going...
                            log::warn!("bind() for refresh failed: {}", err);
                        } else if let Some(b) = self.client.binding_mgr.get_by_addr(&bind_addr) {
                            b.set_refreshed_at(Instant::now());
                            b.set_state(BindingState::Ready);
                        }
                    }
                });
            }

            bind_number
        };

        // send via ChannelData
        self.send_channel_data(p, number)
         */
    }

    // Close closes the connection.
    // Any blocked ReadFrom or write_to operations will be unblocked and return errors.
    pub fn close(&mut self) -> Result<()> {
        self.refresh_allocation(Duration::from_secs(0))
    }

    fn create_permissions(
        &mut self,
        addrs: &[SocketAddr],
        addr: Option<SocketAddr>,
    ) -> Result<TransactionId> {
        let (username, realm) = (self.client.username(), self.client.realm());
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            let msg = {
                let mut setters: Vec<Box<dyn Setter>> = vec![
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_CREATE_PERMISSION, CLASS_REQUEST)),
                ];

                for addr in addrs {
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
                self.client.turn_server_addr(),
                TransactionType::CreatePermissionRequest(self.relayed_addr, addr),
            ))
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    pub(crate) fn handle_create_permission_response(
        &mut self,
        res: Message,
        addr: Option<SocketAddr>,
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
                self.client.events.push_back(Event::CreatePermissionError(
                    res.transaction_id,
                    Box::new(err),
                ));
                if let Some(addr) = addr {
                    relay.perm_map.delete(&addr);
                }
            } else if let Some(addr) = addr {
                if let Some(perm) = relay.perm_map.get_mut(&addr) {
                    perm.set_state(PermState::Permitted);
                    self.client
                        .events
                        .push_back(Event::CreatePermissionResponse(res.transaction_id));
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
                self.client.turn_server_addr(),
                TransactionType::RefreshRequest,
            );

            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    pub(crate) fn handle_refresh_allocation_response(&mut self, res: Message) -> Result<()> {
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
                self.client.events.push_back(Event::CreatePermissionError(
                    res.transaction_id,
                    Box::new(err),
                ));
            } else {
                // Getting lifetime from response
                let mut updated_lifetime = proto::lifetime::Lifetime::default();
                updated_lifetime.get_from(&res)?;

                relay.lifetime = updated_lifetime.0;
                log::debug!("updated lifetime: {} seconds", relay.lifetime.as_secs());
            }
            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    fn refresh_permissions(&mut self) -> Result<()> {
        if let Some(relay) = self.client.relays.get_mut(&self.relayed_addr) {
            let addrs = relay.perm_map.addrs();
            if addrs.is_empty() {
                log::debug!("no permission to refresh");
                return Ok(());
            }

            if let Err(err) = self.create_permissions(&addrs, None) {
                if Error::ErrTryAgain != err {
                    log::error!("fail to refresh permissions: {}", err);
                }
                return Err(err);
            }

            log::debug!("refresh permissions successful");
            Ok(())
        } else {
            Err(Error::ErrConnClosed)
        }
    }

    /*TODO: fn bind(
        &mut self,
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

            (msg, self.client.turn_server_addr())
        };

        log::debug!("UDPConn.bind call PerformTransaction 1");
        let tr_res = self.client.perform_transaction(
            &msg,
            turn_server_addr,
            TransactionType::ChannelBindRequest,
        );

        let res = tr_res.msg;

        if res.typ != MessageType::new(METHOD_CHANNEL_BIND, CLASS_SUCCESS_RESPONSE) {
            return Err(Error::ErrUnexpectedResponse);
        }

        log::debug!("channel binding successful: {} {}", bind_addr, bind_number);

        // Success.
        Ok(())
    }*/

    fn send_channel_data(&mut self, data: &[u8], ch_num: u16) -> Result<()> {
        let mut ch_data = proto::chandata::ChannelData {
            data: data.to_vec(),
            number: proto::channum::ChannelNumber(ch_num),
            ..Default::default()
        };
        ch_data.encode();

        self.client
            .write_to(&ch_data.raw, self.client.turn_server_addr());

        Ok(())
    }
}

/*
impl<T: RelayConnObserver + Send + Sync> PeriodicTimerTimeoutHandler for RelayConnInternal<T> {
    async fn on_timeout(&mut self, id: TimerIdRefresh) {
        log::debug!("refresh timer {:?} expired", id);
        match id {
            TimerIdRefresh::Alloc => {
                let lifetime = self.lifetime;
                // limit the max retries on errTryAgain to 3
                // when stale nonce returns, sencond retry should succeed
                let mut result = Ok(());
                for _ in 0..MAX_RETRY_ATTEMPTS {
                    result = self.refresh_allocation(lifetime, false).await;
                    if let Err(err) = &result {
                        if Error::ErrTryAgain != *err {
                            break;
                        }
                    }
                }
                if result.is_err() {
                    log::warn!("refresh allocation failed");
                }
            }
            TimerIdRefresh::Perms => {
                let mut result = Ok(());
                for _ in 0..MAX_RETRY_ATTEMPTS {
                    result = self.refresh_permissions().await;
                    if let Err(err) = &result {
                        if Error::ErrTryAgain != *err {
                            break;
                        }
                    }
                }
                if result.is_err() {
                    log::warn!("refresh permissions failed");
                }
            }
        }
    }
}
*/
