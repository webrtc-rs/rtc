use bytes::BytesMut;
use shared::error::*;
use std::collections::{HashMap, VecDeque};
use std::io::BufReader;
use std::net::SocketAddr;
use std::ops::Add;
use std::time::{Duration, Instant};

use crate::agent::*;
use crate::message::*;
use shared::{TaggedBytesMut, TransportContext, TransportMessage, TransportProtocol};

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

    pub fn build(
        self,
        local: SocketAddr,
        remote: SocketAddr,
        protocol: TransportProtocol,
    ) -> Result<Client> {
        Ok(Client::new(local, remote, protocol, self.settings))
    }
}

/// Client simulates "connection" to STUN server.
pub struct Client {
    local: SocketAddr,
    remote: SocketAddr,
    transport_protocol: TransportProtocol,
    agent: Agent,
    settings: ClientSettings,
    transactions: HashMap<TransactionId, ClientTransaction>,
    transmits: VecDeque<TransportMessage<BytesMut>>,
}

impl Client {
    fn new(
        local: SocketAddr,
        remote: SocketAddr,
        transport_protocol: TransportProtocol,
        settings: ClientSettings,
    ) -> Self {
        Self {
            local,
            remote,
            transport_protocol,
            agent: Agent::new(),
            settings,
            transactions: HashMap::new(),
            transmits: VecDeque::new(),
        }
    }
}

impl sansio::Protocol<TaggedBytesMut, Message, Event> for Client {
    type Rout = ();
    type Wout = TaggedBytesMut;
    type Eout = Event;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        let mut stun_msg = Message::new();
        let mut reader = BufReader::new(&msg.message[..]);
        stun_msg.read_from(&mut reader)?;
        self.agent.handle_event(ClientAgent::Process(stun_msg))
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    fn handle_write(&mut self, m: Message) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }

        let payload = BytesMut::from(&m.raw[..]);

        let ct = ClientTransaction {
            id: m.transaction_id,
            attempt: 0,
            start: Instant::now(),
            rto: self.settings.rto,
            raw: m.raw,
        };
        let deadline = ct.next_timeout(ct.start);
        self.transactions.entry(ct.id).or_insert(ct);
        self.agent
            .handle_event(ClientAgent::Start(m.transaction_id, deadline))?;

        self.transmits.push_back(TransportMessage {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: self.local,
                peer_addr: self.remote,
                ecn: None,
                transport_protocol: self.transport_protocol,
            },
            message: payload,
        });

        Ok(())
    }

    /// Returns packets to transmit
    ///
    /// It should be polled for transmit after:
    /// - the application performed some I/O
    /// - a call was made to `handle_read`
    /// - a call was made to `handle_write`
    /// - a call was made to `handle_timeout`
    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        while let Some(event) = self.agent.poll_event() {
            let mut ct = if self.transactions.contains_key(&event.id) {
                self.transactions.remove(&event.id).unwrap()
            } else {
                continue;
            };

            if ct.attempt >= self.settings.max_attempts || event.result.is_ok() {
                return Some(event);
            }

            // Doing re-transmission.
            ct.attempt += 1;

            let payload = BytesMut::from(&ct.raw[..]);
            let timeout = ct.next_timeout(Instant::now());
            let id = ct.id;

            // Starting client transaction.
            self.transactions.entry(ct.id).or_insert(ct);

            // Starting agent transaction.
            if self
                .agent
                .handle_event(ClientAgent::Start(id, timeout))
                .is_err()
            {
                self.transactions.remove(&id);
                return Some(event);
            }

            // Writing message to connection again.
            self.transmits.push_back(TransportMessage {
                now: Instant::now(),
                transport: TransportContext {
                    local_addr: self.local,
                    peer_addr: self.remote,
                    ecn: None,
                    transport_protocol: self.transport_protocol,
                },
                message: payload,
            });
        }

        None
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        self.agent.poll_timeout()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        self.agent.handle_event(ClientAgent::Collect(now))
    }

    fn close(&mut self) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }
        self.settings.closed = true;
        self.agent.handle_event(ClientAgent::Close)
    }
}
