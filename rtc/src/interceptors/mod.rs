use crate::messages::TaggedMessageEvent;
use crate::types::FourTuple;
use std::time::Instant;

pub(crate) mod nack;
pub(crate) mod report;
pub(crate) mod twcc;

pub enum InterceptorEvent {
    Inbound(TaggedMessageEvent),
    Outbound(TaggedMessageEvent),
    Error(Box<dyn std::error::Error>),
}

pub trait Interceptor {
    fn chain(self: Box<Self>, next: Box<dyn Interceptor>) -> Box<dyn Interceptor>;
    fn next(&mut self) -> Option<&mut Box<dyn Interceptor>>;

    fn read(&mut self, msg: &mut TaggedMessageEvent) -> Vec<InterceptorEvent> {
        if let Some(next) = self.next() {
            next.read(msg)
        } else {
            vec![]
        }
    }
    fn write(&mut self, msg: &mut TaggedMessageEvent) -> Vec<InterceptorEvent> {
        if let Some(next) = self.next() {
            next.write(msg)
        } else {
            vec![]
        }
    }

    fn handle_timeout(&mut self, now: Instant, four_tuples: &[FourTuple]) -> Vec<InterceptorEvent> {
        if let Some(next) = self.next() {
            next.handle_timeout(now, four_tuples)
        } else {
            vec![]
        }
    }

    fn poll_timeout(&mut self, eto: &mut Instant) {
        if let Some(next) = self.next() {
            next.poll_timeout(eto);
        }
    }
}

/// InterceptorBuilder provides an interface for constructing interceptors
pub trait InterceptorBuilder {
    fn build(&self, id: &str) -> Box<dyn Interceptor>;
}

/// Registry is a collector for interceptors.
#[derive(Default)]
pub struct Registry {
    builders: Vec<Box<dyn InterceptorBuilder + Send + Sync>>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// add a new InterceptorBuilder to the registry.
    pub fn add(&mut self, builder: Box<dyn InterceptorBuilder + Send + Sync>) {
        self.builders.push(builder);
    }

    /// build a single Interceptor from an InterceptorRegistry
    pub fn build(&self, id: &str) -> Box<dyn Interceptor> {
        let mut next = Box::new(NoOp) as Box<dyn Interceptor>;
        for interceptor in self.builders.iter().rev().map(|b| b.build(id)) {
            next = interceptor.chain(next);
        }
        next
    }
}

/// NoOp is an Interceptor that does not modify any packets. It can be embedded in other interceptors, so it's
/// possible to implement only a subset of the methods.
struct NoOp;

impl Interceptor for NoOp {
    fn chain(self: Box<Self>, _next: Box<dyn Interceptor>) -> Box<dyn Interceptor> {
        self
    }

    fn next(&mut self) -> Option<&mut Box<dyn Interceptor>> {
        None
    }
}
