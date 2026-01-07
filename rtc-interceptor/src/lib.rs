#![warn(rust_2018_idioms)]
#![allow(dead_code)]

/*
mod noop;
mod registry;
pub(crate) mod nack;
pub(crate) mod report;
pub(crate) mod twcc;

pub enum InterceptorEvent {
    Inbound(TaggedMessageEvent),
    Outbound(TaggedMessageEvent),
    Error(Box<dyn std::error::Error>),
}*/

#[allow(clippy::type_complexity)]
pub trait Interceptor<Msg, Evt> {
    type Error;
    type Time;

    fn chain(
        self: Box<Self>,
        next: Box<dyn Interceptor<Msg, Evt, Error = Self::Error, Time = Self::Time>>,
    ) -> Box<dyn Interceptor<Msg, Evt, Error = Self::Error, Time = Self::Time>>;
    fn next(
        &mut self,
    ) -> Option<&mut Box<dyn Interceptor<Msg, Evt, Error = Self::Error, Time = Self::Time>>>;

    /*
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
    }*/
}
