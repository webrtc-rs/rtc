use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use shared::error::{Error, Result};

/// Resource limits and lifetimes for a UDP TURN server.
///
/// All times are advanced explicitly by the host. This initial server implements the
/// RFC 5766 long-term credential profile with MESSAGE-INTEGRITY (HMAC-SHA1).
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Authentication realm. Credential keys must be derived for this exact realm.
    pub realm: String,
    /// Lifetime granted when the client omits LIFETIME.
    pub default_lifetime: Duration,
    /// Maximum allocation lifetime; a smaller requested lifetime is honored.
    pub max_lifetime: Duration,
    /// Lifetime of a stateless nonce, at most one hour.
    pub nonce_lifetime: Duration,
    /// Time allowed for the host to complete a relay socket allocation.
    pub pending_lifetime: Duration,
    /// How long authenticated transaction responses are retained for UDP replay.
    pub replay_lifetime: Duration,
    /// Maximum number of active and pending allocations combined.
    pub max_allocations: usize,
    /// Maximum active and pending allocations per authenticated username.
    pub max_allocations_per_user: usize,
    /// Maximum IP permissions per allocation.
    pub max_permissions: usize,
    /// Maximum channel bindings per allocation.
    pub max_channels: usize,
    /// Admission limit for queued output events. Expiry may add at most max_allocations releases.
    pub max_events: usize,
    /// Maximum retained authenticated response transactions across the server.
    pub max_replay_entries: usize,
    /// Maximum control message size. Relay payloads have their separate UDP limit.
    pub max_request_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            realm: "webrtc.rs".into(),
            default_lifetime: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(3600),
            nonce_lifetime: Duration::from_secs(600),
            pending_lifetime: Duration::from_secs(10),
            replay_lifetime: Duration::from_secs(40),
            max_allocations: 1024,
            max_allocations_per_user: 16,
            max_permissions: 64,
            max_channels: 64,
            max_events: 1024,
            max_replay_entries: 4096,
            max_request_bytes: 2048,
        }
    }
}

impl ServerConfig {
    pub(super) fn validate(&self) -> Result<()> {
        if self.realm.is_empty()
            || self.realm.len() > 763
            || self.default_lifetime.as_secs() == 0
            || self.default_lifetime > self.max_lifetime
            || self.max_lifetime > Duration::from_secs(3600)
            || self.nonce_lifetime.as_secs() == 0
            || self.nonce_lifetime > Duration::from_secs(3600)
            || self.pending_lifetime.is_zero()
            || self.pending_lifetime > Duration::from_secs(60)
            || self.replay_lifetime < Duration::from_secs(40)
            || self.replay_lifetime > Duration::from_secs(600)
            || self.max_allocations == 0
            || self.max_allocations_per_user == 0
            || self.max_permissions == 0
            || self.max_channels == 0
            || self.max_events < 2
            || self.max_replay_entries == 0
            || !(20..=4096).contains(&self.max_request_bytes)
        {
            return Err(Error::Other("invalid TURN server configuration".into()));
        }
        Ok(())
    }
}

/// Application-owned long-term credentials and peer access policy.
///
/// This callback is synchronous: use a local credential snapshot, never block on a
/// database or network request from the protocol event loop. It owns business identity;
/// the server only verifies STUN authentication and enforces allocation ownership.
pub trait Authenticator: Send + Sync {
    /// Return the 16-byte MD5(username:realm:password) key, or None to deny/revoke a user.
    ///
    /// Returning a key authorizes new allocations. Existing allocations retain their
    /// original key across credential rotation; returning None also revokes their requests.
    /// Username/password preparation (SASLprep for this profile) belongs to the caller.
    fn credential_key(&self, username: &str, realm: &str) -> Option<Vec<u8>>;

    /// Decide whether this user may contact a peer. Called for permission, binding and data.
    /// CreatePermission ignores the wire port and passes port 1 to this policy.
    ///
    /// The default rejects local/private, multicast, unspecified and broadcast addresses.
    /// Override explicitly for trusted private-network deployments. The host must also
    /// reject listener aliases and enforce deployment-specific firewall rules. Other relay
    /// allocations may be valid peers when both endpoints use this server.
    fn allow_peer(&self, _username: &str, peer: SocketAddr) -> bool {
        if peer.port() == 0 {
            return false;
        }
        match peer.ip() {
            IpAddr::V4(ip) => {
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_private()
                    && !ip.is_link_local()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && ip.octets()[0] != 0
                    && ip.octets()[0] < 240
            }
            IpAddr::V6(ip) => {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    return self
                        .allow_peer(_username, SocketAddr::new(IpAddr::V4(ip), peer.port()));
                }
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_unique_local()
                    && !ip.is_unicast_link_local()
            }
        }
    }
}
