#[cfg(test)]
mod client_test;

use shared::error::*;
use std::collections::HashMap;
use std::io::BufReader;
use std::ops::Add;
use std::time::{Duration, Instant};

use crate::agent::*;
use crate::message::*;

const DEFAULT_TIMEOUT_RATE: Duration = Duration::from_millis(5);
const DEFAULT_RTO: Duration = Duration::from_millis(300);
const DEFAULT_MAX_ATTEMPTS: u32 = 7;
const DEFAULT_MAX_BUFFER_SIZE: usize = 8;

/// ClientTransaction represents transaction in progress.
/// If transaction is succeed or failed, f will be called
/// provided by event.
/// Concurrent access is invalid.
#[derive(Debug, Clone)]
pub struct ClientTransaction {
    id: TransactionId,
    attempt: u32,
    calls: u32,
    start: Instant,
    rto: Duration,
    raw: Vec<u8>,
}

impl ClientTransaction {
    pub(crate) fn next_timeout(&self, now: Instant) -> Instant {
        now.add((self.attempt + 1) * self.rto)
    }
}

struct ClientSettings {
    buffer_size: usize,
    rto: Duration,
    rto_rate: Duration,
    max_attempts: u32,
    closed: bool,
}

impl Default for ClientSettings {
    fn default() -> Self {
        ClientSettings {
            buffer_size: DEFAULT_MAX_BUFFER_SIZE,
            rto: DEFAULT_RTO,
            rto_rate: DEFAULT_TIMEOUT_RATE,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            closed: false,
        }
    }
}

#[derive(Default)]
pub struct ClientBuilder {
    settings: ClientSettings,
}

impl ClientBuilder {
    /// with_rto sets client RTO as defined in STUN RFC.
    pub fn with_rto(mut self, rto: Duration) -> Self {
        self.settings.rto = rto;
        self
    }

    /// with_timeout_rate sets RTO timer minimum resolution.
    pub fn with_timeout_rate(mut self, d: Duration) -> Self {
        self.settings.rto_rate = d;
        self
    }

    /// with_buffer_size sets buffer size.
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.settings.buffer_size = buffer_size;
        self
    }

    /// with_no_retransmit disables retransmissions and sets RTO to
    /// DEFAULT_MAX_ATTEMPTS * DEFAULT_RTO which will be effectively time out
    /// if not set.
    /// Useful for TCP connections where transport handles RTO.
    pub fn with_no_retransmit(mut self) -> Self {
        self.settings.max_attempts = 0;
        if self.settings.rto == Duration::from_secs(0) {
            self.settings.rto = DEFAULT_MAX_ATTEMPTS * DEFAULT_RTO;
        }
        self
    }

    pub fn new() -> Self {
        ClientBuilder {
            settings: ClientSettings::default(),
        }
    }

    pub fn build(self) -> Result<Client> {
        Ok(Client::new(self.settings))
    }
}

/// Client simulates "connection" to STUN server.
#[derive(Default)]
pub struct Client {
    agent: Agent,
    settings: ClientSettings,
    transactions: HashMap<TransactionId, ClientTransaction>,
}

impl Client {
    fn new(settings: ClientSettings) -> Self {
        Self {
            agent: Agent::new(),
            settings,
            transactions: HashMap::new(),
        }
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.agent.poll_event()
    }

    pub fn handle_read(&mut self, buf: &[u8]) -> Result<()> {
        let mut msg = Message::new();
        let mut reader = BufReader::new(buf);
        msg.read_from(&mut reader)?;
        self.agent.handle_event(ClientAgent::Process(msg))
    }

    pub fn handle_write(&mut self, m: &Message) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }

        let t = ClientTransaction {
            id: m.transaction_id,
            attempt: 0,
            calls: 0,
            start: Instant::now(),
            rto: self.settings.rto,
            raw: m.raw.clone(),
        };
        let deadline = t.next_timeout(t.start);
        self.insert(t)?;
        self.agent
            .handle_event(ClientAgent::Start(m.transaction_id, deadline))?;

        Ok(())
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        self.agent.poll_timeout()
    }

    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.agent.handle_event(ClientAgent::Collect(now))
    }

    fn insert(&mut self, ct: ClientTransaction) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }

        self.transactions.entry(ct.id).or_insert(ct);

        Ok(())
    }

    fn remove(&mut self, id: TransactionId) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }

        self.transactions.remove(&id);

        Ok(())
    }

    /*
    fn start(
        conn: Option<Arc<dyn Conn + Send + Sync>>,
        mut handler_rx: mpsc::UnboundedReceiver<Event>,
        client_agent_tx: Arc<mpsc::Sender<ClientAgent>>,
        mut t: HashMap<TransactionId, ClientTransaction>,
        max_attempts: u32,
    ) {
        tokio::spawn(async move {
            while let Some(event) = handler_rx.recv().await {
                match event.event_type {
                    EventType::Callback(id) => {
                        let mut ct = if t.contains_key(&id) {
                            t.remove(&id).unwrap()
                        } else {
                            continue;
                        };

                        if ct.attempt >= max_attempts || event.event_body.is_ok() {
                            if let Some(handler) = ct.handler {
                                let _ = handler.send(event);
                            }
                            continue;
                        }

                        // Doing re-transmission.
                        ct.attempt += 1;

                        let raw = ct.raw.clone();
                        let timeout = ct.next_timeout(Instant::now());
                        let id = ct.id;

                        // Starting client transaction.
                        t.insert(ct.id, ct);

                        // Starting agent transaction.
                        if client_agent_tx
                            .send(ClientAgent::Start(id, timeout))
                            .await
                            .is_err()
                        {
                            let ct = t.remove(&id).unwrap();
                            if let Some(handler) = ct.handler {
                                let _ = handler.send(event);
                            }
                            continue;
                        }

                        // Writing message to connection again.
                        if let Some(c) = &conn {
                            if c.send(&raw).await.is_err() {
                                let _ = client_agent_tx.send(ClientAgent::Stop(id)).await;

                                let ct = t.remove(&id).unwrap();
                                if let Some(handler) = ct.handler {
                                    let _ = handler.send(event);
                                }
                                continue;
                            }
                        }
                    }
                };
            }
        });
    }*/

    /// close stops internal connection and agent, returning CloseErr on error.
    pub fn close(&mut self) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }
        self.settings.closed = true;
        self.agent.handle_event(ClientAgent::Close)
    }
}
