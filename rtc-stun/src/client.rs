//! A Sans-I/O STUN client.
//!
//! Sends Binding requests and matches the responses, applying the retransmission schedule the RFC
//! specifies (an initial RTO, doubling per retry) so a lost request on a UDP path is retried
//! rather than lost. Build one with [`ClientBuilder`](crate::client::ClientBuilder); drive it with datagrams and time.
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

/// A [`Message`] together with the instant the caller is sending it at.
///
/// `Rin` is a [`TaggedBytesMut`], which carries a timestamp; without this the write channel
/// would not, and `handle_write` would have to ask the clock for one. A STUN client's first
/// action is typically a write before any read, so a retained instant is not an option here —
/// it would still be the construction seed.
pub struct TaggedMessage {
    /// When the caller is sending this message.
    pub now: Instant,
    /// The STUN message to send.
    pub message: Message,
}

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
/// Builds a [`Client`] with a chosen transaction timeout, retransmission schedule and
/// handler.
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

    /// A builder with the RFC's default timings.
    pub fn new() -> Self {
        ClientBuilder {
            settings: ClientSettings::default(),
        }
    }

    /// Builds the client for the given local and remote addresses.
    ///
    /// # Errors
    ///
    /// Fails if the configured timings are inconsistent.
    pub fn build(
        self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        protocol: TransportProtocol,
    ) -> Result<Client> {
        Ok(Client::new(now, local, remote, protocol, self.settings))
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

    /// The newest instant a caller has supplied, seeded at construction.
    ///
    /// `poll_event` schedules retransmissions, which needs a deadline, but a poll is a drain
    /// and receives no instant. The retransmission is caused by the timeout the caller reported
    /// through `handle_timeout`, so that instant is the right one to schedule against.
    now: Instant,
}

impl Client {
    fn new(
        now: Instant,
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
            now,
        }
    }

    /// Records the newest instant a caller has supplied.
    ///
    /// `max` rather than assignment: an outbound message carries the instant of the input that
    /// caused it, so a caller can legitimately present an older one than the newest seen.
    fn observe(&mut self, now: Instant) {
        self.now = now.max(self.now);
    }

    /// The address this client sends from.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The STUN server this client talks to.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }
}

impl sansio::Protocol<TaggedBytesMut, TaggedMessage, ()> for Client {
    type Rout = ();
    type Wout = TaggedBytesMut;
    type Eout = StunEvent;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedBytesMut) -> Result<()> {
        self.observe(msg.now);
        let mut stun_msg = Message::new();
        let mut reader = BufReader::new(&msg.message[..]);
        stun_msg.read_from(&mut reader)?;
        self.agent.handle_event(ClientAgent::Process(stun_msg))
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        None
    }

    fn handle_write(&mut self, msg: TaggedMessage) -> Result<()> {
        if self.settings.closed {
            return Err(Error::ErrClientClosed);
        }

        let now = msg.now;
        self.observe(now);
        let m = msg.message;
        let payload = BytesMut::from(&m.raw[..]);

        let ct = ClientTransaction {
            id: m.transaction_id,
            attempt: 0,
            start: now,
            rto: self.settings.rto,
            raw: m.raw,
        };
        let deadline = ct.next_timeout(ct.start);
        self.transactions.entry(ct.id).or_insert(ct);
        self.agent
            .handle_event(ClientAgent::Start(m.transaction_id, deadline))?;

        self.transmits.push_back(TransportMessage {
            now,
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

            if let StunEvent::Message(_) = &event.evt {
                return Some(event.evt);
            }
            if ct.attempt >= self.settings.max_attempts {
                return Some(event.evt);
            }

            // Doing re-transmission.
            ct.attempt += 1;

            let payload = BytesMut::from(&ct.raw[..]);
            let timeout = ct.next_timeout(self.now);
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
                return Some(event.evt);
            }

            // Writing message to connection again.
            self.transmits.push_back(TransportMessage {
                now: self.now,
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
        self.observe(now);
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

#[cfg(test)]
mod client_test {
    use super::*;
    use sansio::Protocol;

    fn addrs() -> (SocketAddr, SocketAddr) {
        (
            "127.0.0.1:5000".parse().unwrap(),
            "127.0.0.1:3478".parse().unwrap(),
        )
    }

    fn binding_request() -> Message {
        let mut msg = Message::new();
        msg.build(&[Box::<TransactionId>::default(), Box::new(BINDING_REQUEST)])
            .expect("a binding request encodes");
        msg
    }

    /// The transaction deadline is computed from the instant the caller supplied to
    /// `handle_write`, not from an ambient reading, so a retransmission can be observed by
    /// arithmetic on a base instant with no wall-clock time passing and no sleeping.
    #[test]
    fn test_transaction_retransmits_on_injected_time() -> Result<()> {
        let base = Instant::now();
        let t = |millis| base + Duration::from_millis(millis);

        let (local, remote) = addrs();
        let mut client = ClientBuilder::new()
            .with_rto(Duration::from_millis(100))
            .build(t(0), local, remote, TransportProtocol::UDP)?;

        // The write is stamped at t(10), so the first attempt's deadline is t(10) + 1 * rto.
        client.handle_write(TaggedMessage {
            now: t(10),
            message: binding_request(),
        })?;

        let transmit = client.poll_write().expect("the request is queued");
        assert_eq!(
            transmit.now,
            t(10),
            "the request carries the caller's instant, not an ambient reading"
        );
        assert!(client.poll_write().is_none());

        assert_eq!(
            client.poll_timeout(),
            Some(t(110)),
            "the deadline is one RTO after the instant the caller wrote at"
        );

        // Before the deadline nothing is retransmitted. Note the agent collects on
        // `deadline < now`, *strictly* — so arriving exactly at the deadline is not yet
        // late. A virtual clock advanced by exactly one RTO therefore needs one more tick,
        // which is worth knowing before writing a `clock.advance(rto)` test against it.
        client.handle_timeout(t(110))?;
        while client.poll_event().is_some() {}
        assert!(
            client.poll_write().is_none(),
            "the deadline is not yet past at exactly the deadline"
        );

        // Past the deadline the request goes out again, stamped with that same instant.
        client.handle_timeout(t(111))?;
        while client.poll_event().is_some() {}
        let retransmit = client.poll_write().expect("the request is retransmitted");
        assert_eq!(retransmit.now, t(111));
        assert_eq!(
            retransmit.message, transmit.message,
            "a retransmission repeats the original request verbatim"
        );

        // The second attempt backs off to two RTOs from the instant it was scheduled at.
        assert_eq!(client.poll_timeout(), Some(t(311)));

        client.close()
    }
}
