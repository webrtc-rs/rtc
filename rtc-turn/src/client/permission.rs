use std::net::SocketAddr;

#[derive(Default, Copy, Clone, PartialEq, Debug)]
pub(crate) enum PermState {
    #[default]
    Idle = 0,
    Permitted = 1,
}

impl From<u8> for PermState {
    fn from(v: u8) -> Self {
        match v {
            0 => PermState::Idle,
            _ => PermState::Permitted,
        }
    }
}

pub(crate) struct Permission {
    // The peer address that first asked for this permission. Refreshes send it as the
    // XOR-PEER-ADDRESS; the server only looks at its IP.
    addr: SocketAddr,
    st: PermState,
}

impl Permission {
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            st: PermState::Idle,
        }
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(crate) fn set_state(&mut self, state: PermState) {
        self.st = state;
    }

    pub(crate) fn state(&self) -> PermState {
        self.st
    }
}
