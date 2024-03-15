use std::collections::HashMap;
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

#[derive(Default)]
pub(crate) struct Permission {
    st: PermState,
}

impl Permission {
    pub(crate) fn set_state(&mut self, state: PermState) {
        self.st = state;
    }

    pub(crate) fn state(&self) -> PermState {
        self.st
    }
}

// Thread-safe Permission map
#[derive(Default)]
pub(crate) struct PermissionMap {
    perm_map: HashMap<String, Permission>,
}

impl PermissionMap {
    pub(crate) fn new() -> PermissionMap {
        PermissionMap {
            perm_map: HashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, addr: SocketAddr, p: Permission) {
        self.perm_map.insert(addr.ip().to_string(), p);
    }

    pub(crate) fn contains(&self, addr: &SocketAddr) -> bool {
        self.perm_map.contains_key(&addr.ip().to_string())
    }

    pub(crate) fn get(&self, addr: &SocketAddr) -> Option<&Permission> {
        self.perm_map.get(&addr.ip().to_string())
    }

    pub(crate) fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut Permission> {
        self.perm_map.get_mut(&addr.ip().to_string())
    }

    pub(crate) fn delete(&mut self, addr: &SocketAddr) {
        self.perm_map.remove(&addr.ip().to_string());
    }

    pub(crate) fn addrs(&self) -> Vec<SocketAddr> {
        let mut a = vec![];
        for k in self.perm_map.keys() {
            if let Ok(ip) = k.parse() {
                a.push(SocketAddr::new(ip, 0));
            }
        }
        a
    }
}
