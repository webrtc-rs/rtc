//! Authentication for the TURN server: long-term credentials ([RFC 5389 §10.2]), nonces, and the
//! time-windowed shared-secret credentials TURN deployments use.
//!
//! [RFC 5389 §10.2]: https://www.rfc-editor.org/rfc/rfc5389#section-10.2

use crypto::{HmacAlgorithm, RTCCrypto, RTCCryptoProvider};
use rand::RngExt;
use shared::error::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun::integrity::MessageIntegrity;
use stun::message::Method;

/// What the server tells an [`AuthHandler`] about a request it wants to authenticate.
#[derive(Debug, Clone)]
pub struct AuthRequest<'a> {
    /// The `USERNAME` attribute.
    pub username: &'a str,
    /// The `REALM` attribute the client answered with.
    pub realm: &'a str,
    /// The client's address.
    pub src_addr: SocketAddr,
    /// The STUN method being authenticated (Allocate, Refresh, CreatePermission, ChannelBind).
    pub method: Method,
}

/// A user the server accepted: who they are and the key their requests are signed with.
#[derive(Debug, Clone)]
pub struct AuthCredentials {
    /// Identifies the user for quotas and for tying an allocation to who made it. Often the
    /// username.
    pub user_id: String,
    /// The long-term credential key: `MD5(username ":" realm ":" password)`; see
    /// [`generate_auth_key`].
    pub key: Vec<u8>,
}

/// Looks up the key of a user the server should accept.
///
/// Returning `None` rejects the request. Any `Fn(&AuthRequest) -> Option<AuthCredentials>` is one.
pub trait AuthHandler: Send + Sync {
    /// Authenticates `request`, returning the user's credentials if they are known.
    fn auth(&self, request: &AuthRequest<'_>) -> Option<AuthCredentials>;
}

impl<F> AuthHandler for F
where
    F: Fn(&AuthRequest<'_>) -> Option<AuthCredentials> + Send + Sync,
{
    fn auth(&self, request: &AuthRequest<'_>) -> Option<AuthCredentials> {
        self(request)
    }
}

/// Decides whether a user may create another allocation (`486 Allocation Quota Reached` if not).
pub trait QuotaHandler: Send + Sync {
    /// Whether `user_id` in `realm`, connecting from `src_addr`, may allocate.
    fn allow(&self, user_id: &str, realm: &str, src_addr: SocketAddr) -> bool;
}

impl<F> QuotaHandler for F
where
    F: Fn(&str, &str, SocketAddr) -> bool + Send + Sync,
{
    fn allow(&self, user_id: &str, realm: &str, src_addr: SocketAddr) -> bool {
        self(user_id, realm, src_addr)
    }
}

/// Decides whether a client may create permissions for a peer address (`403 Forbidden` if not).
pub trait PermissionHandler: Send + Sync {
    /// Whether the client at `client_addr` may relay to `peer`.
    fn allow(&self, client_addr: SocketAddr, peer: std::net::IpAddr) -> bool;
}

impl<F> PermissionHandler for F
where
    F: Fn(SocketAddr, std::net::IpAddr) -> bool + Send + Sync,
{
    fn allow(&self, client_addr: SocketAddr, peer: std::net::IpAddr) -> bool {
        self(client_addr, peer)
    }
}

/// The key requests are signed with for `username`, `realm` and `password`.
///
/// # Errors
///
/// Fails if the crypto provider cannot compute MD5.
pub fn generate_auth_key(
    username: &str,
    realm: &str,
    password: &str,
    crypto: &dyn RTCCrypto,
) -> Result<Vec<u8>> {
    MessageIntegrity::long_term_integrity_key(
        username.to_owned(),
        realm.to_owned(),
        password.to_owned(),
        crypto,
    )
}

/// Mints and checks nonces: 8 bytes of a timestamp followed by an HMAC of them, so a nonce can be
/// verified, and expired, without the server remembering it.
pub(crate) struct NonceManager {
    key: [u8; NONCE_KEY_LENGTH],
    crypto: Arc<dyn RTCCryptoProvider>,
    epoch: Instant,
}

const NONCE_KEY_LENGTH: usize = 64;
/// How long a nonce stays valid (RFC 5766 §4).
const NONCE_LIFETIME: Duration = Duration::from_secs(3600);
const NONCE_HASH_LENGTH: usize = 32;

impl NonceManager {
    pub(crate) fn new(crypto: Arc<dyn RTCCryptoProvider>, now: Instant) -> Self {
        let mut key = [0u8; NONCE_KEY_LENGTH];
        rand::rng().fill(&mut key);
        Self {
            key,
            crypto,
            epoch: now,
        }
    }

    fn mac(&self, stamp: &[u8]) -> Result<[u8; NONCE_HASH_LENGTH]> {
        let mut out = [0u8; NONCE_HASH_LENGTH];
        self.crypto
            .crypto()
            .new_hmac(HmacAlgorithm::Sha256, &self.key)
            .and_then(|mut mac| mac.sign(&[stamp], &mut out))
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(out)
    }

    pub(crate) fn generate(&self, now: Instant) -> Result<String> {
        let millis = now.saturating_duration_since(self.epoch).as_millis() as u64;
        let stamp = millis.to_be_bytes();
        let mut nonce = stamp.to_vec();
        nonce.extend_from_slice(&self.mac(&stamp)?);
        Ok(nonce.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Whether `nonce` was minted by this server and has not expired.
    pub(crate) fn validate(&self, now: Instant, nonce: &str) -> bool {
        if nonce.len() != (8 + NONCE_HASH_LENGTH) * 2 {
            return false;
        }
        let mut bytes = Vec::with_capacity(8 + NONCE_HASH_LENGTH);
        for pair in nonce.as_bytes().chunks(2) {
            let Ok(s) = std::str::from_utf8(pair) else {
                return false;
            };
            let Ok(b) = u8::from_str_radix(s, 16) else {
                return false;
            };
            bytes.push(b);
        }
        let (stamp, hash) = bytes.split_at(8);
        let issued = Duration::from_millis(u64::from_be_bytes(stamp.try_into().unwrap()));
        if now.saturating_duration_since(self.epoch) > issued + NONCE_LIFETIME {
            return false;
        }
        match self.mac(stamp) {
            Ok(expected) => crypto::constant_time_eq(&expected, hash),
            Err(_) => false,
        }
    }
}

/// Time-windowed credentials from a shared secret, for services that mint short-lived TURN logins
/// for their users (the "TURN REST API" scheme, draft-uberti-behave-turn-rest).
///
/// The username is a Unix timestamp (optionally followed by `:user`) after which it stops
/// working; the password is the base64 HMAC-SHA1 of the username under the shared secret.
pub struct LongTermCredentials {
    shared_secret: String,
    crypto: Arc<dyn RTCCryptoProvider>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl LongTermCredentials {
    /// Credentials checked against the system clock.
    pub fn new(shared_secret: impl Into<String>, crypto: Arc<dyn RTCCryptoProvider>) -> Self {
        Self::with_clock(shared_secret, crypto, system_unix_time)
    }

    /// Credentials checked against `clock`, which returns the current Unix time in seconds.
    pub fn with_clock(
        shared_secret: impl Into<String>,
        crypto: Arc<dyn RTCCryptoProvider>,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            shared_secret: shared_secret.into(),
            crypto,
            clock: Box::new(clock),
        }
    }

    fn password(&self, username: &str) -> Result<String> {
        use base64::Engine;
        let mut out = [0u8; 20];
        self.crypto
            .crypto()
            .new_hmac(HmacAlgorithm::Sha1, self.shared_secret.as_bytes())
            .and_then(|mut mac| mac.sign(&[username.as_bytes()], &mut out))
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(out))
    }

    /// A username and password valid for `duration`.
    pub fn generate(&self, duration: Duration) -> Result<(String, String)> {
        let username = ((self.clock)() + duration.as_secs()).to_string();
        let password = self.password(&username)?;
        Ok((username, password))
    }

    /// As [`generate`](Self::generate), with `user` appended to the username so that servers can
    /// tell who a login was minted for.
    pub fn generate_rest(&self, user: &str, duration: Duration) -> Result<(String, String)> {
        let username = format!("{}:{user}", (self.clock)() + duration.as_secs());
        let password = self.password(&username)?;
        Ok((username, password))
    }

    fn check(&self, request: &AuthRequest<'_>, rest: bool) -> Option<AuthCredentials> {
        let (timestamp, user_id) = if rest {
            match request.username.split_once(':') {
                Some((t, user)) => (t, user),
                None => (request.username, request.username),
            }
        } else {
            (request.username, request.username)
        };
        let expires: u64 = timestamp.parse().ok()?;
        if expires < (self.clock)() {
            return None;
        }
        let password = self.password(request.username).ok()?;
        let key = generate_auth_key(
            request.username,
            request.realm,
            &password,
            self.crypto.crypto(),
        )
        .ok()?;
        Some(AuthCredentials {
            user_id: user_id.to_owned(),
            key,
        })
    }

    /// An [`AuthHandler`] accepting logins from [`generate`](Self::generate).
    pub fn auth_handler(self) -> impl AuthHandler {
        move |request: &AuthRequest<'_>| self.check(request, false)
    }

    /// An [`AuthHandler`] accepting logins from [`generate_rest`](Self::generate_rest).
    pub fn rest_auth_handler(self) -> impl AuthHandler {
        move |request: &AuthRequest<'_>| self.check(request, true)
    }
}

fn system_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
