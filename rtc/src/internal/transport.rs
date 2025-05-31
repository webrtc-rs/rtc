use crate::message::Message;
use crate::utils::CallBackFnMut;
use log::trace;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

pub(crate) trait Transport {
    fn on_recv(&mut self, callback: Option<CallBackFnMut<Arc<Message>>>);
    fn on_state_change(&mut self, callback: Option<CallBackFnMut<State>>);

    fn start(&mut self);
    fn stop(&mut self);
    fn send(&mut self, message: Arc<Message>) -> bool;

    fn incoming(&mut self, message: Arc<Message>);

    fn outgoing(&mut self, message: Arc<Message>) -> bool;
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq)]
pub(crate) enum State {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Completed,
    Failed,
}

impl From<u8> for State {
    fn from(v: u8) -> Self {
        match v {
            0 => State::Disconnected,
            1 => State::Connecting,
            2 => State::Connected,
            3 => State::Completed,
            _ => State::Failed,
        }
    }
}

pub(crate) struct TransportImpl {
    lower: Option<Arc<Mutex<dyn Transport>>>,
    state_change_callback: Option<CallBackFnMut<State>>,
    recv_callback: Option<CallBackFnMut<Arc<Message>>>,
    state: Arc<AtomicU8>, //  = ;
}

impl TransportImpl {
    pub(crate) fn new(
        lower: Option<Arc<Mutex<dyn Transport>>>,
        state_change_callback: Option<CallBackFnMut<State>>,
    ) -> Self {
        Self {
            lower,
            state_change_callback,
            recv_callback: None,
            state: Arc::new(AtomicU8::new(State::Disconnected as u8)),
        }
    }

    pub(crate) fn register_incoming(&self) {
        if let Some(lower) = &self.lower {
            trace!("Registering incoming callback");
            if let Ok(mut _l) = lower.lock() {
                /*TODO: l.on_recv(Some(Box::new(|message: Arc<Message>| {
                    self.incoming(message);
                })));*/
            }
        }
    }
    pub(crate) fn unregister_incoming(&self) {
        if let Some(lower) = &self.lower {
            trace!("Unregistering incoming callback");
            if let Ok(mut l) = lower.lock() {
                l.on_recv(None);
            }
        }
    }
    pub(crate) fn state(&self) -> State {
        self.state.load(Ordering::SeqCst).into()
    }

    pub(crate) fn recv(&self, _message: Arc<Message>) {}
    pub(crate) fn change_state(&mut self, _state: State) {}
}

impl Drop for TransportImpl {
    fn drop(&mut self) {
        self.unregister_incoming();
        if let Some(lower) = self.lower.take() {
            if let Ok(mut l) = lower.lock() {
                l.stop();
            }
        }
    }
}

impl Transport for TransportImpl {
    fn on_recv(&mut self, callback: Option<CallBackFnMut<Arc<Message>>>) {
        self.recv_callback = callback;
    }
    fn on_state_change(&mut self, callback: Option<CallBackFnMut<State>>) {
        self.state_change_callback = callback;
    }

    fn start(&mut self) {}
    fn stop(&mut self) {}
    fn send(&mut self, _message: Arc<Message>) -> bool {
        true
    }

    fn incoming(&mut self, _message: Arc<Message>) {}
    fn outgoing(&mut self, _message: Arc<Message>) -> bool {
        false
    }
}
