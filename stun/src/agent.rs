#[cfg(test)]
mod agent_test;

use shared::error::*;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use crate::message::*;

/// Agent is low-level abstraction over transaction list that
/// handles concurrency and time outs (via Collect call).
#[derive(Default)]
pub struct Agent {
    /// transactions is map of transactions that are currently
    /// in progress. Event handling is done in such way when
    /// transaction is unregistered before AgentTransaction access,
    /// minimizing mux lock and protecting AgentTransaction from
    /// data races via unexpected concurrent access.
    transactions: HashMap<TransactionId, AgentTransaction>,
    /// all calls are invalid if true
    closed: bool,
    /// events queue
    events_queue: VecDeque<Event>,
}

/// Event is passed to Handler describing the transaction event.
/// Do not reuse outside Handler.
#[derive(Debug)] //Clone
pub struct Event {
    pub id: TransactionId,
    pub result: Result<Message>,
}

impl Default for Event {
    fn default() -> Self {
        Event {
            id: TransactionId::default(),
            result: Ok(Message::default()),
        }
    }
}

/// AgentTransaction represents transaction in progress.
/// Concurrent access is invalid.
pub(crate) struct AgentTransaction {
    id: TransactionId,
    deadline: Instant,
}

/// AGENT_COLLECT_CAP is initial capacity for Agent.Collect slices,
/// sufficient to make function zero-alloc in most cases.
const AGENT_COLLECT_CAP: usize = 100;

/// ClientAgent is Agent implementation that is used by Client to
/// process transactions.
#[derive(Debug)]
pub enum ClientAgent {
    Process(Message),
    Collect(Instant),
    Start(TransactionId, Instant),
    Stop(TransactionId),
    Close,
}

impl Agent {
    /// new initializes and returns new Agent with provided handler.
    pub fn new() -> Self {
        Agent {
            transactions: HashMap::new(),
            closed: false,
            events_queue: VecDeque::new(),
        }
    }

    pub(crate) fn handle_event(&mut self, client_agent: ClientAgent) -> Result<()> {
        match client_agent {
            ClientAgent::Process(message) => self.process(message),
            ClientAgent::Collect(deadline) => self.collect(deadline),
            ClientAgent::Start(tid, deadline) => self.start(tid, deadline),
            ClientAgent::Stop(tid) => self.stop(tid),
            ClientAgent::Close => self.close(),
        }
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let mut deadline = None;
        for transaction in self.transactions.values() {
            if deadline.is_none() || transaction.deadline < *deadline.as_ref().unwrap() {
                deadline = Some(transaction.deadline);
            }
        }
        deadline
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events_queue.pop_front()
    }

    /// process incoming message, synchronously passing it to handler.
    fn process(&mut self, message: Message) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }

        self.transactions.remove(&message.transaction_id);

        self.events_queue.push_back(Event {
            id: message.transaction_id,
            result: Ok(message),
        });

        Ok(())
    }

    /// close terminates all transactions with ErrAgentClosed and renders Agent to
    /// closed state.
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }

        for id in self.transactions.keys() {
            self.events_queue.push_back(Event {
                id: *id,
                result: Err(Error::ErrAgentClosed),
            });
        }
        self.transactions.clear();
        self.closed = true;

        Ok(())
    }

    /// start registers transaction with provided id and deadline.
    /// Could return ErrAgentClosed, ErrTransactionExists.
    ///
    /// Agent handler is guaranteed to be eventually called.
    fn start(&mut self, id: TransactionId, deadline: Instant) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }
        if self.transactions.contains_key(&id) {
            return Err(Error::ErrTransactionExists);
        }

        self.transactions
            .insert(id, AgentTransaction { id, deadline });

        Ok(())
    }

    /// stop stops transaction by id with ErrTransactionStopped, blocking
    /// until handler returns.
    fn stop(&mut self, id: TransactionId) -> Result<()> {
        if self.closed {
            return Err(Error::ErrAgentClosed);
        }

        let v = self.transactions.remove(&id);
        if let Some(t) = v {
            self.events_queue.push_back(Event {
                id: t.id,
                result: Err(Error::ErrTransactionStopped),
            });
            Ok(())
        } else {
            Err(Error::ErrTransactionNotExists)
        }
    }

    /// collect terminates all transactions that have deadline before provided
    /// time, blocking until all handlers will process ErrTransactionTimeOut.
    /// Will return ErrAgentClosed if agent is already closed.
    ///
    /// It is safe to call Collect concurrently but makes no sense.
    fn collect(&mut self, deadline: Instant) -> Result<()> {
        if self.closed {
            // Doing nothing if agent is closed.
            // All transactions should be already closed
            // during Close() call.
            return Err(Error::ErrAgentClosed);
        }

        let mut to_remove: Vec<TransactionId> = Vec::with_capacity(AGENT_COLLECT_CAP);

        // Adding all transactions with deadline before gc_time
        // to toCall and to_remove slices.
        // No allocs if there are less than AGENT_COLLECT_CAP
        // timed out transactions.
        for (id, t) in &self.transactions {
            if t.deadline < deadline {
                to_remove.push(*id);
            }
        }
        // Un-registering timed out transactions.
        for id in &to_remove {
            self.transactions.remove(id);
        }

        for id in to_remove {
            self.events_queue.push_back(Event {
                id,
                result: Err(Error::ErrTransactionTimeOut),
            });
        }

        Ok(())
    }
}
