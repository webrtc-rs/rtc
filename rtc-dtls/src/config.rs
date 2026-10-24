//! Handshake configuration.
//!
//! [`ConfigBuilder`](crate::config::ConfigBuilder) is what a caller supplies: certificates, the client/server role, which cipher
//! suites and curves to offer, the SRTP protection profiles to negotiate through `use_srtp`,
//! and how strictly to require the extended master secret
//! ([`ExtendedMasterSecretType`](crate::config::ExtendedMasterSecretType)).
//!
//! WebRTC authenticates peers by comparing the certificate fingerprint against the one
//! signalled in SDP, not against a CA chain — so certificates here are normally self-signed
//! (see [`gen_self_signed_root_cert`](crate::config::gen_self_signed_root_cert)) and the check is implemented by supplying a
//! [`VerifyPeerCertificateFn`](crate::config::VerifyPeerCertificateFn).
//!
//! [`HandshakeConfig`](crate::config::HandshakeConfig) is the resolved form the handshake
//! actually runs with, produced by [`ConfigBuilder::build`](crate::config::ConfigBuilder::build).

#[cfg(test)]
mod config_test;

use crate::cipher_suite::*;
use crate::conn::{
    DEFAULT_MAXIMUM_RETRANSMIT_NUMBER, DEFAULT_REPLAY_PROTECTION_WINDOW, INITIAL_TICKER_INTERVAL,
};
use crate::crypto::*;
use crate::curve::named_curve::NamedCurve;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::handshake::HandshakeMessage;
use crate::handshake::handshake_message_certificate_request::HandshakeMessageCertificateRequest;
use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
use crate::handshake::handshake_message_server_hello::HandshakeMessageServerHello;
use crate::signature_hash_algorithm::{
    SignatureHashAlgorithm, SignatureScheme, parse_certificate_signature_schemes,
    parse_signature_schemes,
};
use crate::state::State;
use crypto::RTCCryptoProvider;
use log::warn;
use shared::error::*;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::CertificateDer;
use rustls::server::danger::ClientCertVerifier;

/// Explicit rustls/webpki backend used only for CA-chain and hostname verification.
///
/// This policy adapter is separate from [`RTCCryptoProvider`]. Applications authenticating with
/// SDP fingerprints do not need it, while applications enabling WebPKI validation can select its
/// backend without changing their primitive RTC provider.
#[derive(Clone)]
pub struct RustlsVerifierAdapter {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl RustlsVerifierAdapter {
    /// Wraps a rustls crypto provider for WebPKI verification.
    #[must_use]
    pub fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { provider }
    }

    /// Uses rustls's ring verification backend.
    #[cfg(feature = "crypto-ring")]
    #[must_use]
    pub fn ring() -> Self {
        Self::new(Arc::new(rustls::crypto::ring::default_provider()))
    }

    /// Uses rustls's AWS-LC-RS verification backend.
    #[cfg(feature = "crypto-aws-lc-rs")]
    #[must_use]
    pub fn aws_lc_rs() -> Self {
        Self::new(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    }
}

fn default_verifier_adapter() -> Option<RustlsVerifierAdapter> {
    #[cfg(feature = "crypto-ring")]
    {
        Some(RustlsVerifierAdapter::ring())
    }
    #[cfg(all(not(feature = "crypto-ring"), feature = "crypto-aws-lc-rs"))]
    {
        Some(RustlsVerifierAdapter::aws_lc_rs())
    }
    #[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
    {
        None
    }
}

/// Builds the default server-certificate verifier, with an explicit provider where we have one.
///
/// # Errors
///
/// Fails if the root store holds no usable trust anchors.
fn server_cert_verifier(
    roots: std::sync::Arc<rustls::RootCertStore>,
    adapter: &RustlsVerifierAdapter,
) -> Result<std::sync::Arc<dyn ServerCertVerifier>> {
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        roots,
        adapter.provider.clone(),
    )
    .build()
    .map_err(|err| Error::Other(format!("rustls server cert verifier: {err}")))?;
    Ok(verifier)
}

/// Config is used to configure a DTLS client or server.
/// After a Config is passed to a DTLS function it must not be modified.
#[derive(Clone)]
pub struct ConfigBuilder {
    crypto_provider: Option<Arc<dyn RTCCryptoProvider>>,
    certificates: Vec<Certificate>,
    cipher_suites: Vec<CipherSuiteId>,
    signature_schemes: Vec<SignatureScheme>,
    certificate_signature_schemes: Vec<SignatureScheme>,
    elliptic_curves: Vec<NamedCurve>,
    srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    supported_protocols: Vec<String>,
    client_auth: ClientAuthType,
    extended_master_secret: ExtendedMasterSecretType,
    flight_interval: Duration,
    psk: Option<PskCallback>,
    psk_identity_hint: Option<Vec<u8>>,
    insecure_skip_verify: bool,
    insecure_skip_verify_hello: bool,
    insecure_hashes: bool,
    insecure_verification: bool,
    verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    verify_connection: Option<VerifyConnectionFn>,
    get_certificate: Option<GetCertificateFn>,
    get_client_certificate: Option<GetClientCertificateFn>,
    hello_random_bytes_generator: Option<HelloRandomBytesGeneratorFn>,
    client_hello_message_hook: Option<ClientHelloMessageHook>,
    server_hello_message_hook: Option<ServerHelloMessageHook>,
    certificate_request_message_hook: Option<CertificateRequestMessageHook>,
    key_logger: Option<Arc<dyn KeyLogger>>,
    roots_cas: rustls::RootCertStore,
    client_cas: rustls::RootCertStore,
    verifier_adapter: Option<RustlsVerifierAdapter>,
    server_name: String,
    mtu: usize,
    replay_protection_window: usize,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            crypto_provider: None,
            certificates: vec![],
            cipher_suites: vec![],
            signature_schemes: vec![],
            certificate_signature_schemes: vec![],
            elliptic_curves: vec![],
            srtp_protection_profiles: vec![],
            supported_protocols: vec![],
            client_auth: ClientAuthType::default(),
            extended_master_secret: ExtendedMasterSecretType::default(),
            flight_interval: Duration::default(),
            psk: None,
            psk_identity_hint: None,
            insecure_skip_verify: false,
            insecure_skip_verify_hello: false,
            insecure_hashes: false,
            insecure_verification: false,
            verify_peer_certificate: None,
            verify_connection: None,
            get_certificate: None,
            get_client_certificate: None,
            hello_random_bytes_generator: None,
            client_hello_message_hook: None,
            server_hello_message_hook: None,
            certificate_request_message_hook: None,
            key_logger: None,
            roots_cas: rustls::RootCertStore::empty(),
            client_cas: rustls::RootCertStore::empty(),
            verifier_adapter: default_verifier_adapter(),
            server_name: String::default(),
            mtu: 0,
            replay_protection_window: 0,
        }
    }
}

impl ConfigBuilder {
    /// Selects the cryptography and CSPRNG implementation for this DTLS association.
    ///
    /// The provider is resolved while building the handshake configuration and is reused for the
    /// entire handshake and record lifetime. No global registration is required.
    pub fn with_crypto_provider(mut self, provider: Arc<dyn RTCCryptoProvider>) -> Self {
        self.crypto_provider = Some(provider);
        self
    }

    /// certificates contains certificate chain to present to the other side of the connection.
    /// Server MUST set this if psk is nil, and MAY set it alongside a psk to serve both families
    /// Client SHOULD set this so CertificateRequests can be handled, and MUST NOT set it with a psk
    pub fn with_certificates(mut self, certificates: Vec<Certificate>) -> Self {
        self.certificates = certificates;
        self
    }

    /// cipher_suites is a list of supported cipher suites.
    /// If cipher_suites is nil, a default list is used
    pub fn with_cipher_suites(mut self, cipher_suites: Vec<CipherSuiteId>) -> Self {
        self.cipher_suites = cipher_suites;
        self
    }

    /// signature_schemes contains the signature and hash schemes that the peer requests to verify.
    pub fn with_signature_schemes(mut self, signature_schemes: Vec<SignatureScheme>) -> Self {
        self.signature_schemes = signature_schemes;
        self
    }

    /// certificate_signature_schemes contains the signature and hash schemes that may be used
    /// in digital signatures over X.509 certificates, which is distinct from
    /// [`with_signature_schemes`](Self::with_signature_schemes) (handshake signatures).
    ///
    /// When non-empty, a client sends the `signature_algorithms_cert` extension (type 50)
    /// alongside `signature_algorithms`, and a server retains the schemes a client offers
    /// there, as in pion.
    pub fn with_certificate_signature_schemes(
        mut self,
        certificate_signature_schemes: Vec<SignatureScheme>,
    ) -> Self {
        self.certificate_signature_schemes = certificate_signature_schemes;
        self
    }

    /// elliptic_curves restricts the curves offered and accepted for ECDHE, most preferred
    /// first. Empty (the default) offers the crate's default curve list in its default order.
    pub fn with_elliptic_curves(mut self, elliptic_curves: Vec<NamedCurve>) -> Self {
        self.elliptic_curves = elliptic_curves;
        self
    }

    /// srtp_protection_profiles are the supported protection profiles
    /// Clients will send this via use_srtp and assert that the server properly responds
    /// Servers will assert that clients send one of these profiles and will respond as needed
    pub fn with_srtp_protection_profiles(
        mut self,
        srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    ) -> Self {
        self.srtp_protection_profiles = srtp_protection_profiles;
        self
    }

    /// The application protocols this endpoint speaks, most preferred first, for ALPN
    /// ([RFC 7301]). Clients offer them in the ClientHello; servers pick the first of their own
    /// that the client offered, and refuse the handshake with a `no_application_protocol` alert
    /// when both sides offered protocols and none matches. Empty (the default) disables ALPN.
    ///
    /// [`build`](Self::build) rejects empty names, names longer than 255 bytes, and lists too long
    /// for the extension.
    ///
    /// [RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
    pub fn with_supported_protocols(mut self, supported_protocols: Vec<String>) -> Self {
        self.supported_protocols = supported_protocols;
        self
    }

    /// client_auth determines the server's policy for
    /// TLS Client Authentication. The default is NoClientCert.
    pub fn with_client_auth(mut self, client_auth: ClientAuthType) -> Self {
        self.client_auth = client_auth;
        self
    }

    /// extended_master_secret determines if the "Extended Master Secret" extension
    /// should be disabled, requested, or required (default requested).
    pub fn with_extended_master_secret(
        mut self,
        extended_master_secret: ExtendedMasterSecretType,
    ) -> Self {
        self.extended_master_secret = extended_master_secret;
        self
    }

    /// flight_interval controls how often we send outbound handshake messages
    /// defaults to time.Second
    pub fn with_flight_interval(mut self, flight_interval: Duration) -> Self {
        self.flight_interval = flight_interval;
        self
    }

    /// psk sets the pre-shared key used by this DTLS connection
    /// A client with a psk offers only psk cipher_suites; a server that also holds certificates
    /// offers both families and lets the negotiated suite decide which credential it uses
    pub fn with_psk(mut self, psk: Option<PskCallback>) -> Self {
        self.psk = psk;
        self
    }

    /// psk_identity_hint sets the pre-shared key hint
    pub fn with_psk_identity_hint(mut self, psk_identity_hint: Option<Vec<u8>>) -> Self {
        self.psk_identity_hint = psk_identity_hint;
        self
    }

    /// insecure_skip_verify controls whether a client verifies the
    /// server's certificate chain and host name.
    /// If insecure_skip_verify is true, TLS accepts any certificate
    /// presented by the server and any host name in that certificate.
    /// In this mode, TLS is susceptible to man-in-the-middle attacks.
    /// This should be used only for testing.
    pub fn with_insecure_skip_verify(mut self, insecure_skip_verify: bool) -> Self {
        self.insecure_skip_verify = insecure_skip_verify;
        self
    }

    /// insecure_skip_verify_hello, when set on a server, lets a ClientHello that skips the
    /// HelloVerifyRequest cookie exchange be answered directly, as in pion. The cookie
    /// exchange is a defence against using the handshake for amplification, so this should
    /// only be enabled on networks where that trade-off is acceptable.
    pub fn with_insecure_skip_verify_hello(mut self, insecure_skip_verify_hello: bool) -> Self {
        self.insecure_skip_verify_hello = insecure_skip_verify_hello;
        self
    }

    /// insecure_hashes allows the use of hashing algorithms that are known
    /// to be vulnerable.
    pub fn with_insecure_hashes(mut self, insecure_hashes: bool) -> Self {
        self.insecure_hashes = insecure_hashes;
        self
    }

    /// insecure_verification allows the use of verification algorithms that are
    /// known to be vulnerable or deprecated
    pub fn with_insecure_verification(mut self, insecure_verification: bool) -> Self {
        self.insecure_verification = insecure_verification;
        self
    }

    /// VerifyPeerCertificate, if not nil, is called after normal
    /// certificate verification by either a client or server. It
    /// receives the certificate provided by the peer and also a flag
    /// that tells if normal verification has succeeded. If it returns a
    /// non-nil error, the handshake is aborted and that error results.
    ///
    /// If normal verification fails then the handshake will abort before
    /// considering this callback. If normal verification is disabled by
    /// setting insecure_skip_verify, or (for a server) when client_auth is
    /// RequestClientCert or RequireAnyClientCert, then this callback will
    /// be considered but the verifiedChains will always be nil.
    pub fn with_verify_peer_certificate(
        mut self,
        verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    ) -> Self {
        self.verify_peer_certificate = verify_peer_certificate;
        self
    }

    /// VerifyConnection, if not nil, is called after normal certificate/PSK verification
    /// and after `verify_peer_certificate`, by both client and server, once the peer's
    /// `Finished` has been verified. An error aborts the handshake: a fatal
    /// `bad_certificate` alert is sent to the peer and the callback's error is returned
    /// locally, as in pion.
    pub fn with_verify_connection(mut self, verify_connection: Option<VerifyConnectionFn>) -> Self {
        self.verify_connection = verify_connection;
        self
    }

    /// get_certificate, on a server, chooses the certificate to present from the information
    /// in the client's ClientHello (SNI `server_name`, offered cipher suites, signature
    /// schemes, curves and random bytes). `None` falls back to the configured certificates
    /// and `name_to_certificate` selection, as in pion; an error aborts the handshake with a
    /// `handshake_failure` alert.
    pub fn with_get_certificate(mut self, get_certificate: Option<GetCertificateFn>) -> Self {
        self.get_certificate = get_certificate;
        self
    }

    /// get_client_certificate, on a client, chooses the certificate to present when the
    /// server sends a CertificateRequest, whose acceptable signature schemes and certificate
    /// authorities arrive in a [`CertificateRequestInfo`]. An error aborts the handshake with
    /// a `handshake_failure` alert, as in pion.
    pub fn with_get_client_certificate(
        mut self,
        get_client_certificate: Option<GetClientCertificateFn>,
    ) -> Self {
        self.get_client_certificate = get_client_certificate;
        self
    }

    /// hello_random_bytes_generator overrides the 28 random bytes of the client's hello
    /// random. The generator's output feeds key derivation exactly like the provider's
    /// randomness would; a debugging and fingerprinting facility, as in pion.
    pub fn with_hello_random_bytes_generator(
        mut self,
        hello_random_bytes_generator: Option<HelloRandomBytesGeneratorFn>,
    ) -> Self {
        self.hello_random_bytes_generator = hello_random_bytes_generator;
        self
    }

    /// client_hello_message_hook, when set on the client, receives the ClientHello about to
    /// be sent and returns the handshake message to send instead — the same message with
    /// tweaks, or a different one entirely. A testing and fingerprinting facility, as in
    /// pion.
    pub fn with_client_hello_message_hook(
        mut self,
        client_hello_message_hook: Option<ClientHelloMessageHook>,
    ) -> Self {
        self.client_hello_message_hook = client_hello_message_hook;
        self
    }

    /// server_hello_message_hook, when set on the server, receives the ServerHello about to
    /// be sent and returns the handshake message to send instead. A testing and
    /// fingerprinting facility, as in pion.
    pub fn with_server_hello_message_hook(
        mut self,
        server_hello_message_hook: Option<ServerHelloMessageHook>,
    ) -> Self {
        self.server_hello_message_hook = server_hello_message_hook;
        self
    }

    /// certificate_request_message_hook, when set on the server, receives the
    /// CertificateRequest about to be sent and returns the handshake message to send
    /// instead. A testing and fingerprinting facility, as in pion.
    pub fn with_certificate_request_message_hook(
        mut self,
        certificate_request_message_hook: Option<CertificateRequestMessageHook>,
    ) -> Self {
        self.certificate_request_message_hook = certificate_request_message_hook;
        self
    }

    /// key_logger, if set, receives the session's key material in the NSS key log format
    /// once the master secret is derived, for decrypting captured traffic (Wireshark et al.).
    ///
    /// A debugging facility: every enabled process writes session secrets somewhere.
    pub fn with_key_logger(mut self, key_logger: Option<Arc<dyn KeyLogger>>) -> Self {
        self.key_logger = key_logger;
        self
    }

    /// roots_cas defines the set of root certificate authorities
    /// that one peer uses when verifying the other peer's certificates.
    /// If RootCAs is nil, TLS uses the host's root CA set.
    /// Used by Client to verify server's certificate
    pub fn with_roots_cas(mut self, roots_cas: rustls::RootCertStore) -> Self {
        self.roots_cas = roots_cas;
        self
    }

    /// client_cas defines the set of root certificate authorities
    /// that servers use if required to verify a client certificate
    /// by the policy in client_auth.
    /// Used by Server to verify client's certificate
    pub fn with_client_cas(mut self, client_cas: rustls::RootCertStore) -> Self {
        self.client_cas = client_cas;
        self
    }

    /// Selects the rustls/webpki adapter used for optional CA-chain and hostname verification.
    pub fn with_rustls_verifier_adapter(mut self, adapter: RustlsVerifierAdapter) -> Self {
        self.verifier_adapter = Some(adapter);
        self
    }

    /// server_name is used to verify the hostname on the returned
    /// certificates unless insecure_skip_verify is given.
    pub fn with_server_name(mut self, server_name: String) -> Self {
        self.server_name = server_name;
        self
    }

    /// mtu is the length at which handshake messages will be fragmented to
    /// fit within the maximum transmission unit (default is 1200 bytes)
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// replay_protection_window is the size of the replay attack protection window.
    /// Duplication of the sequence number is checked in this window size.
    /// Packet with sequence number older than this value compared to the latest
    /// accepted packet will be discarded. (default is 64)
    pub fn with_replay_protection_window(mut self, replay_protection_window: usize) -> Self {
        self.replay_protection_window = replay_protection_window;
        self
    }
}

pub(crate) const DEFAULT_MTU: usize = 1200; // bytes

/// PSKCallback is called once we have the remote's psk_identity_hint.
/// If the remote provided none it will be nil
pub(crate) type PskCallback = Arc<dyn (Fn(&[u8]) -> Result<Vec<u8>>) + Send + Sync>;

/// ClientAuthType declares the policy the server will follow for
/// TLS Client Authentication.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientAuthType {
    #[default]
    /// `NO_CLIENT_CERT` (`0`).
    NoClientCert = 0,
    /// `REQUEST_CLIENT_CERT` (`1`).
    RequestClientCert = 1,
    /// `REQUIRE_ANY_CLIENT_CERT` (`2`).
    RequireAnyClientCert = 2,
    /// `VERIFY_CLIENT_CERT_IF_GIVEN` (`3`).
    VerifyClientCertIfGiven = 3,
    /// `REQUIRE_AND_VERIFY_CLIENT_CERT` (`4`).
    RequireAndVerifyClientCert = 4,
}

// ExtendedMasterSecretType declares the policy the client and server
// will follow for the Extended Master Secret extension
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
/// How strictly to require the extended master secret extension ([RFC 7627]).
pub enum ExtendedMasterSecretType {
    #[default]
    /// `REQUEST` (`0`).
    Request = 0,
    /// `REQUIRE` (`1`).
    Require = 1,
    /// `DISABLE` (`2`).
    Disable = 2,
}

impl ConfigBuilder {
    fn offered_cipher_suites(&self, is_client: bool) -> Result<Vec<Box<dyn CipherSuite>>> {
        // As pion's `includeCertificateSuites`: certificate suites are offered unless this is a
        // PSK-only endpoint — certificates, `get_certificate` or `get_client_certificate` all
        // bring them back.
        let has_certificate_answer = !self.certificates.is_empty()
            || self.get_certificate.is_some()
            || self.get_client_certificate.is_some();
        let exclude_certificate = if is_client {
            self.psk.is_some() && !has_certificate_answer
        } else {
            !has_certificate_answer
        };

        parse_cipher_suites(&self.cipher_suites, self.psk.is_none(), exclude_certificate)
    }

    fn validate(&self, is_client: bool) -> Result<()> {
        // pion checks this one first, so a server with an identity but no PSK reports it rather
        // than the missing certificate.
        if self.psk_identity_hint.is_some() && self.psk.is_none() {
            return Err(Error::ErrIdentityNoPsk);
        }

        if is_client && self.psk.is_some() && self.psk_identity_hint.is_none() {
            return Err(Error::ErrPskAndIdentityMustBeSetForClient);
        }

        if !is_client && self.psk.is_none() && self.certificates.is_empty() {
            // A server may present no certificate of its own as long as `get_certificate`
            // will answer for it, as in pion.
            if self.get_certificate.is_none() {
                return Err(Error::ErrServerMustHaveCertificate);
            }
        }

        // A server may hold both and let each handshake pick
        if is_client && !self.certificates.is_empty() && self.psk.is_some() {
            return Err(Error::ErrPskAndCertificate);
        }

        self.offered_cipher_suites(is_client)?;

        Ok(())
    }

    /// build handshake config
    pub fn build(
        mut self,
        is_client: bool,
        remote_addr: Option<SocketAddr>,
    ) -> Result<HandshakeConfig> {
        // The caller supplies the provider; this crate never resolves a default. An application
        // that wants the feature-selected built-in passes `crypto::default_provider()?`.
        let crypto_provider = self.crypto_provider.take().ok_or_else(|| {
            Error::Crypto(
                "no crypto provider configured: call ConfigBuilder::with_crypto_provider"
                    .to_owned(),
            )
        })?;
        self.validate(is_client)?;
        let alpn_len: usize = self.supported_protocols.iter().map(|p| 1 + p.len()).sum();
        if self
            .supported_protocols
            .iter()
            .any(|p| p.is_empty() || p.len() > 255)
            || alpn_len + 2 > 0xffff
        {
            return Err(Error::ErrAlpnInvalidFormat);
        }

        // Each id is paired with the suite's own `is_psk`, so the checks below can tell the two
        // families apart without a second definition of which suites are psk.
        let mut local_cipher_suites: Vec<(CipherSuiteId, bool)> = self
            .offered_cipher_suites(is_client)?
            .iter()
            .map(|cs| (cs.id(), cs.is_psk()))
            .filter(|(id, _)| id.supported_by(crypto_provider.crypto()))
            .collect();
        if local_cipher_suites.is_empty() {
            return Err(Error::ErrNoAvailableCipherSuites);
        }

        let sigs: Vec<u16> = self.signature_schemes.iter().map(|x| *x as u16).collect();
        let local_signature_schemes: Vec<_> = parse_signature_schemes(&sigs, self.insecure_hashes)?
            .into_iter()
            .filter(|algorithm| {
                algorithm.crypto_scheme().is_ok_and(|scheme| {
                    crypto_provider
                        .crypto()
                        .supports(crypto::CryptoAlgorithm::Signature(scheme))
                })
            })
            .collect();

        // Certificate-signature schemes are parsed with the same hybrid decoding pion uses for
        // `signature_algorithms_cert`: full-u16 PSS code points next to byte-split 1.2 pairs.
        let cert_sigs: Vec<u16> = self
            .certificate_signature_schemes
            .iter()
            .map(|x| *x as u16)
            .collect();
        let local_certificate_signature_schemes = if cert_sigs.is_empty() {
            vec![]
        } else {
            parse_certificate_signature_schemes(&cert_sigs, self.insecure_hashes)?
                .into_iter()
                .filter(|algorithm| {
                    algorithm.crypto_scheme().is_ok_and(|scheme| {
                        crypto_provider
                            .crypto()
                            .supports(crypto::CryptoAlgorithm::Signature(scheme))
                    })
                })
                .collect()
        };

        let has_non_psk_suites = local_cipher_suites.iter().any(|(_, is_psk)| !is_psk);
        if has_non_psk_suites && local_signature_schemes.is_empty() {
            return Err(Error::ErrNoAvailableSignatureSchemes);
        }

        let configured_curves = if self.elliptic_curves.is_empty() {
            // pion's `defaultCurves`.
            vec![NamedCurve::X25519, NamedCurve::P256, NamedCurve::P384]
        } else {
            self.elliptic_curves.clone()
        };
        let local_named_curves: Vec<_> = configured_curves
            .into_iter()
            .filter(|curve| {
                curve.crypto_algorithm().is_ok_and(|algorithm| {
                    crypto_provider
                        .crypto()
                        .supports(crypto::CryptoAlgorithm::KeyExchange(algorithm))
                })
            })
            .collect();
        if has_non_psk_suites && local_named_curves.is_empty() {
            return Err(Error::ErrNoAvailableCipherSuites);
        }

        if !is_client && has_non_psk_suites && !self.certificates.is_empty() {
            let signing_key = &self.certificates[0].private_key.signing_key;
            local_cipher_suites.retain(|(id, is_psk)| {
                *is_psk
                    || local_signature_schemes.iter().any(|algorithm| {
                        let signature_family_matches =
                            match id {
                                CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256
                                | CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha
                                | CipherSuiteId::Tls_Ecdhe_Rsa_With_ChaCha20_Poly1305_Sha256 => {
                                    algorithm.signature
                                        == crate::signature_hash_algorithm::SignatureAlgorithm::Rsa
                                }
                                _ => algorithm.signature
                                    == crate::signature_hash_algorithm::SignatureAlgorithm::Ecdsa,
                            };
                        signature_family_matches
                            && algorithm
                                .crypto_scheme()
                                .is_ok_and(|scheme| signing_key.supports(scheme))
                    })
            });
            // A mixed config keeps its psk suites either way, so being left with only those
            // means the certificate can sign none of the suites offered alongside them.
            let only_psk_suites_left = local_cipher_suites.iter().all(|(_, is_psk)| *is_psk);
            if only_psk_suites_left {
                return Err(Error::ErrNoAvailableCipherSuites);
            }
        }

        let local_cipher_suites: Vec<CipherSuiteId> =
            local_cipher_suites.into_iter().map(|(id, _)| id).collect();

        let retransmit_interval = if self.flight_interval != Duration::from_secs(0) {
            self.flight_interval
        } else {
            INITIAL_TICKER_INTERVAL
        };

        let maximum_transmission_unit = if self.mtu == 0 { DEFAULT_MTU } else { self.mtu };

        // `..Default::default()` used to supply this; when P7 replaced that with an explicit
        // field list it wrote `0`, which means *no retransmits are permitted at all*. The very
        // first firing of the retransmit timer then takes the handshake straight to `Errored`
        // (see `handshaker::handshake_timeout`), so a single reply arriving later than one
        // `retransmit_interval` kills the handshake instead of being retried.
        //
        // That is exactly what a loaded CI machine produces: under `-Cinstrument-coverage` on a
        // two-vCPU runner, a round trip between two in-process peers can easily exceed the 1 s
        // interval, and the connection dies with the misleading `ErrInvalidFsmTransition`.
        let maximum_retransmit_number = DEFAULT_MAXIMUM_RETRANSMIT_NUMBER;

        let replay_protection_window = if self.replay_protection_window == 0 {
            DEFAULT_REPLAY_PROTECTION_WINDOW
        } else {
            self.replay_protection_window
        };

        let mut server_name = self.server_name.clone();

        // Use host from conn address when server_name is not provided
        if is_client && server_name.is_empty() {
            if let Some(remote_addr) = remote_addr {
                server_name = remote_addr.ip().to_string();
            } else {
                warn!(
                    "conn.remote_addr is empty, please set explicitly server_name in Config! Use default \"localhost\" as server_name now"
                );
                "localhost".clone_into(&mut server_name);
            }
        }

        let name_to_certificate = name_to_certificate(&self.certificates);

        let server_cert_verifier = if self.insecure_skip_verify {
            None
        } else {
            let adapter = self.verifier_adapter.as_ref().ok_or_else(|| {
                Error::Crypto("CA-chain verification requires a RustlsVerifierAdapter".to_owned())
            })?;
            let roots = if self.roots_cas.is_empty() {
                gen_self_signed_root_cert()
            } else {
                self.roots_cas.clone()
            };
            Some(server_cert_verifier(Arc::new(roots), adapter)?)
        };

        let client_cert_verifier = if self.client_auth as u8
            >= ClientAuthType::VerifyClientCertIfGiven as u8
        {
            let adapter = self.verifier_adapter.as_ref().ok_or_else(|| {
                Error::Crypto(
                    "client-certificate verification requires a RustlsVerifierAdapter".to_owned(),
                )
            })?;
            Some(
                rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(self.client_cas.clone()),
                    adapter.provider.clone(),
                )
                .build()
                .map_err(|err| Error::Other(format!("rustls client cert verifier: {err}")))?
                    as Arc<dyn ClientCertVerifier>,
            )
        } else {
            None
        };

        // Fields not derived from the builder come from `HandshakeConfig::new`, which also
        // supplies `crypto_provider`.
        Ok(HandshakeConfig {
            crypto_provider,
            local_psk_callback: self.psk.take(),
            local_psk_identity_hint: self.psk_identity_hint.take(),
            local_cipher_suites,
            local_named_curves,
            local_signature_schemes,
            local_certificate_signature_schemes,
            extended_master_secret: self.extended_master_secret,
            local_srtp_protection_profiles: self.srtp_protection_profiles,
            local_supported_protocols: self.supported_protocols,
            server_name,
            sni_server_name: self.server_name.clone(),
            client_auth: self.client_auth,
            local_certificates: self.certificates,
            name_to_certificate,
            insecure_skip_verify: self.insecure_skip_verify,
            insecure_skip_verify_hello: self.insecure_skip_verify_hello,
            insecure_verification: self.insecure_verification,
            verify_peer_certificate: self.verify_peer_certificate.take(),
            verify_connection: self.verify_connection.take(),
            get_certificate: self.get_certificate.take(),
            get_client_certificate: self.get_client_certificate.take(),
            hello_random_bytes_generator: self.hello_random_bytes_generator.take(),
            client_hello_message_hook: self.client_hello_message_hook.take(),
            server_hello_message_hook: self.server_hello_message_hook.take(),
            certificate_request_message_hook: self.certificate_request_message_hook.take(),
            key_logger: self.key_logger.clone(),
            roots_cas: self.roots_cas,
            server_cert_verifier,
            client_cert_verifier,
            retransmit_interval,
            initial_epoch: 0,
            maximum_transmission_unit,
            maximum_retransmit_number,
            replay_protection_window,
        })
    }
}

/// A callback that decides whether a peer's certificate chain is acceptable.
///
/// WebRTC verifies the fingerprint from SDP instead of a CA chain, so this is where that check
/// goes.
pub type VerifyPeerCertificateFn =
    Arc<dyn (Fn(&[Vec<u8>], &[CertificateDer<'static>]) -> Result<()>) + Send + Sync>;

/// A callback run against the handshake state once the peer's `Finished` has been verified,
/// after normal certificate/PSK verification and `verify_peer_certificate`.
pub type VerifyConnectionFn = Arc<dyn (Fn(&State) -> Result<()>) + Send + Sync>;

/// A callback that chooses a server certificate from a client's ClientHello.
pub type GetCertificateFn =
    Arc<dyn (Fn(&ClientHelloInfo) -> Result<Option<Certificate>>) + Send + Sync>;

/// A callback that chooses a client certificate in answer to a server's CertificateRequest.
pub type GetClientCertificateFn =
    Arc<dyn (Fn(&CertificateRequestInfo) -> Result<Certificate>) + Send + Sync>;

/// Produces the 28 random bytes of a client hello random.
pub type HelloRandomBytesGeneratorFn =
    Arc<dyn (Fn() -> [u8; crate::handshake::handshake_random::RANDOM_BYTES_LENGTH]) + Send + Sync>;

/// Rewrites the ClientHello about to be sent; the returned message is sent and enters the
/// transcript.
pub type ClientHelloMessageHook =
    Arc<dyn (Fn(HandshakeMessageClientHello) -> HandshakeMessage) + Send + Sync>;

/// Rewrites the ServerHello about to be sent; the returned message is sent and enters the
/// transcript.
pub type ServerHelloMessageHook =
    Arc<dyn (Fn(HandshakeMessageServerHello) -> HandshakeMessage) + Send + Sync>;

/// Rewrites the CertificateRequest about to be sent; the returned message is sent and enters
/// the transcript.
pub type CertificateRequestMessageHook =
    Arc<dyn (Fn(HandshakeMessageCertificateRequest) -> HandshakeMessage) + Send + Sync>;

/// Information from a received ClientHello, handed to [`GetCertificateFn`] so a server can
/// pick a certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientHelloInfo {
    /// The server name the client asked for through SNI, empty when it sent none.
    pub server_name: String,
    /// The cipher suites the client offered.
    pub cipher_suites: Vec<CipherSuiteId>,
    /// The signature and hash pairs the client offered.
    pub signature_schemes: Vec<SignatureHashAlgorithm>,
    /// The curves the client offered for ECDHE.
    pub elliptic_curves: Vec<NamedCurve>,
    /// The 28 random bytes of the client's hello random.
    pub random_bytes: [u8; crate::handshake::handshake_random::RANDOM_BYTES_LENGTH],
}

impl ClientHelloInfo {
    /// Builds the summary a server sees of a ClientHello.
    pub fn new(
        server_name: String,
        cipher_suites: Vec<CipherSuiteId>,
        signature_schemes: Vec<SignatureHashAlgorithm>,
        elliptic_curves: Vec<NamedCurve>,
        random_bytes: [u8; crate::handshake::handshake_random::RANDOM_BYTES_LENGTH],
    ) -> Self {
        Self {
            server_name,
            cipher_suites,
            signature_schemes,
            elliptic_curves,
            random_bytes,
        }
    }
}

/// Information from a server's CertificateRequest, handed to [`GetClientCertificateFn`] so a
/// client can pick a certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CertificateRequestInfo {
    /// The certificate types the server accepts; an empty list means no restriction.
    pub certificate_types: Vec<crate::client_certificate_type::ClientCertificateType>,
    /// The signature and hash pairs the server listed as acceptable.
    pub signature_hash_algorithms: Vec<SignatureHashAlgorithm>,
    /// DER-encoded distinguished names of the certificate authorities the server accepts;
    /// an empty list means it has no preference.
    pub certificate_authorities: Vec<Vec<u8>>,
}

impl CertificateRequestInfo {
    /// Builds the summary a client sees of a server's CertificateRequest.
    pub fn new(
        certificate_types: Vec<crate::client_certificate_type::ClientCertificateType>,
        signature_hash_algorithms: Vec<SignatureHashAlgorithm>,
        certificate_authorities: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            certificate_types,
            signature_hash_algorithms,
            certificate_authorities,
        }
    }
}

/// Receives handshake key material in the NSS key log format, once per completed key
/// derivation.
///
/// The lines are exactly what `SSLKEYLOGFILE` expects, so an implementation typically
/// appends them to a file that Wireshark (or another analyzer) is pointed at to decrypt
/// DTLS and the SRTP derived from it. This is a debugging facility: shipping it enabled
/// discloses every session's secrets, so applications gate it behind an opt-in flag.
pub trait KeyLogger: Send + Sync {
    /// Receives one ready-to-append key log line, including its trailing newline.
    fn write_line(&self, line: &str);
}

/// A [`KeyLogger`] that appends to a file — the ergonomic equivalent of handing pion an
/// already-open file, ready to be named in Wireshark's "TLS pre-master-secret log
/// filename" field.
///
/// `SSLKEYLOGFILE=keys.log` plus `FileKeyLogger::create("keys.log")` is the whole setup:
/// the file is opened once in append mode and each line is written and flushed as the
/// handshake derives the keys, so a capture taken while the process runs is decryptable
/// immediately, with no shutdown wait. Trailing writes after the last handshake are the
/// only ones a hard kill can lose — the same durability window `SSLKEYLOGFILE` tooling
/// already accepts.
///
/// This is a debugging facility and discloses session secrets: gate it behind an opt-in
/// flag, exactly as an application gates `SSLKEYLOGFILE` itself.
pub struct FileKeyLogger {
    file: std::sync::Mutex<std::fs::File>,
}

impl std::fmt::Debug for FileKeyLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeyLogger").finish_non_exhaustive()
    }
}

impl FileKeyLogger {
    /// Opens (or creates) `path` for appending, returning a logger that streams key log
    /// lines to it.
    pub fn create<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: std::sync::Mutex::new(file),
        })
    }
}

impl KeyLogger for FileKeyLogger {
    fn write_line(&self, line: &str) {
        use std::io::Write as _;
        // A failed write logs and moves on: key logging is a debugging aid, and failing
        // the handshake over a full disk would trade a capture for the connection.
        if let Ok(mut file) = self.file.lock()
            && let Err(err) = file.write_all(line.as_bytes()).and_then(|()| file.flush())
        {
            log::warn!("key logger write failed: {err}");
        }
    }
}

/// Emits one `CLIENT_RANDOM` line to the configured [`KeyLogger`], if any.
///
/// `client_random` is the 32-byte ClientHello random of the client end (regardless of which
/// end we are), and `master_secret` the derived secret. Both are the raw bytes; the
/// formatting and newline are added here so implementations cannot get the format wrong.
pub(crate) fn log_master_secret(cfg: &HandshakeConfig, client_random: &[u8], master_secret: &[u8]) {
    use std::fmt::Write as _;
    let Some(logger) = cfg.key_logger.as_ref() else {
        return;
    };
    let mut line =
        String::with_capacity(13 + client_random.len() * 2 + 1 + master_secret.len() * 2 + 1);
    line.push_str("CLIENT_RANDOM ");
    for byte in client_random {
        let _ = write!(line, "{byte:02x}");
    }
    line.push(' ');
    for byte in master_secret {
        let _ = write!(line, "{byte:02x}");
    }
    line.push('\n');
    logger.write_line(&line);
}

/// Generates a self-signed certificate, as WebRTC endpoints use.
pub fn gen_self_signed_root_cert() -> rustls::RootCertStore {
    #[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
    {
        let mut certs = rustls::RootCertStore::empty();
        certs
            .add(
                rcgen::generate_simple_self_signed(vec![])
                    .unwrap()
                    .cert
                    .der()
                    .to_owned(),
            )
            .unwrap();
        certs
    }
    #[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs")))]
    {
        rustls::RootCertStore::empty()
    }
}

/// Maps every name a certificate vouches for (its subject common name and DNS subject
/// alternative names, lowercased) to that certificate, so a server holding several can answer a
/// client's `server_name` with the right one. Later certificates win a shared name, as in Go's
/// `tls.Config.BuildNameToCertificate`, which pion's selection mirrors.
fn name_to_certificate(certificates: &[Certificate]) -> HashMap<String, Certificate> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::{FromDer, X509Certificate};

    let mut names = HashMap::new();
    for certificate in certificates {
        let Some(leaf) = certificate.certificate.first() else {
            continue;
        };
        let Ok((_, parsed)) = X509Certificate::from_der(leaf.as_ref()) else {
            continue;
        };
        if let Some(common_name) = parsed
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .filter(|cn| !cn.is_empty())
        {
            names.insert(common_name.to_lowercase(), certificate.clone());
        }
        if let Ok(Some(san)) = parsed.subject_alternative_name() {
            for name in &san.value.general_names {
                if let GeneralName::DNSName(dns) = name {
                    names.insert(dns.to_lowercase(), certificate.clone());
                }
            }
        }
    }
    names
}

#[derive(Clone)]
/// The resolved configuration a handshake runs with, produced by [`ConfigBuilder::build`].
pub struct HandshakeConfig {
    pub(crate) crypto_provider: Arc<dyn RTCCryptoProvider>,
    pub(crate) local_psk_callback: Option<PskCallback>,
    pub(crate) local_psk_identity_hint: Option<Vec<u8>>,
    pub(crate) local_cipher_suites: Vec<CipherSuiteId>, // Available CipherSuites
    pub(crate) local_named_curves: Vec<NamedCurve>,
    pub(crate) local_signature_schemes: Vec<SignatureHashAlgorithm>, // Available signature schemes
    pub(crate) local_certificate_signature_schemes: Vec<SignatureHashAlgorithm>, // Schemes for certificate signatures, empty = fall back to local_signature_schemes
    pub(crate) extended_master_secret: ExtendedMasterSecretType, // Policy for the Extended Master Support extension
    pub(crate) local_srtp_protection_profiles: Vec<SrtpProtectionProfile>, // Available SRTPProtectionProfiles, if empty no SRTP support
    pub(crate) local_supported_protocols: Vec<String>, // ALPN protocols, if empty no ALPN
    pub(crate) server_name: String,
    /// The name to send in the `server_name` extension: only one the application configured.
    pub(crate) sni_server_name: String,
    pub(crate) client_auth: ClientAuthType, // If we are a client should we request a client certificate
    pub(crate) local_certificates: Vec<Certificate>,
    pub(crate) name_to_certificate: HashMap<String, Certificate>,
    pub(crate) insecure_skip_verify: bool,
    pub(crate) insecure_skip_verify_hello: bool,
    pub(crate) insecure_verification: bool,
    pub(crate) verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    pub(crate) verify_connection: Option<VerifyConnectionFn>,
    pub(crate) get_certificate: Option<GetCertificateFn>,
    pub(crate) get_client_certificate: Option<GetClientCertificateFn>,
    pub(crate) hello_random_bytes_generator: Option<HelloRandomBytesGeneratorFn>,
    pub(crate) client_hello_message_hook: Option<ClientHelloMessageHook>,
    pub(crate) server_hello_message_hook: Option<ServerHelloMessageHook>,
    pub(crate) certificate_request_message_hook: Option<CertificateRequestMessageHook>,
    /// Where completed key derivations are reported, for traffic decryption.
    pub(crate) key_logger: Option<Arc<dyn KeyLogger>>,
    pub(crate) roots_cas: rustls::RootCertStore,
    pub(crate) server_cert_verifier: Option<Arc<dyn ServerCertVerifier>>,
    pub(crate) client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
    pub(crate) retransmit_interval: Duration,
    pub(crate) initial_epoch: u16,
    pub(crate) maximum_transmission_unit: usize,
    pub(crate) maximum_retransmit_number: usize,
    pub(crate) replay_protection_window: usize,
}

impl fmt::Debug for HandshakeConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("HandshakeConfig<T>")
            .field("crypto_provider", &self.crypto_provider.name())
            .field("local_psk_identity_hint", &self.local_psk_identity_hint)
            .field("local_cipher_suites", &self.local_cipher_suites)
            .field("local_named_curves", &self.local_named_curves)
            .field("local_signature_schemes", &self.local_signature_schemes)
            .field("extended_master_secret", &self.extended_master_secret)
            .field(
                "local_srtp_protection_profiles",
                &self.local_srtp_protection_profiles,
            )
            .field("local_supported_protocols", &self.local_supported_protocols)
            .field("server_name", &self.server_name)
            .field("client_auth", &self.client_auth)
            .field("local_certificates", &self.local_certificates)
            .field("name_to_certificate", &self.name_to_certificate)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("insecure_verification", &self.insecure_verification)
            .field("roots_cas", &self.roots_cas)
            .field("retransmit_interval", &self.retransmit_interval)
            .field("initial_epoch", &self.initial_epoch)
            .field("maximum_transmission_unit", &self.maximum_transmission_unit)
            .field("maximum_retransmit_number", &self.maximum_retransmit_number)
            .field("replay_protection_window", &self.replay_protection_window)
            .finish()
    }
}

impl HandshakeConfig {
    pub(crate) fn new(crypto_provider: Arc<dyn RTCCryptoProvider>) -> Self {
        Self {
            crypto_provider,
            local_psk_callback: None,
            local_psk_identity_hint: None,
            local_cipher_suites: vec![],
            local_named_curves: vec![],
            local_signature_schemes: vec![],
            local_certificate_signature_schemes: vec![],
            extended_master_secret: ExtendedMasterSecretType::Disable,
            local_srtp_protection_profiles: vec![],
            local_supported_protocols: vec![],
            server_name: String::new(),
            sni_server_name: String::new(),
            client_auth: ClientAuthType::NoClientCert,
            local_certificates: vec![],
            name_to_certificate: HashMap::new(),
            insecure_skip_verify: false,
            insecure_skip_verify_hello: false,
            insecure_verification: false,
            verify_peer_certificate: None,
            verify_connection: None,
            get_certificate: None,
            get_client_certificate: None,
            hello_random_bytes_generator: None,
            client_hello_message_hook: None,
            server_hello_message_hook: None,
            certificate_request_message_hook: None,
            key_logger: None,
            roots_cas: rustls::RootCertStore::empty(),
            server_cert_verifier: default_verifier_adapter().and_then(|adapter| {
                server_cert_verifier(Arc::new(gen_self_signed_root_cert()), &adapter).ok()
            }),
            client_cert_verifier: None,
            retransmit_interval: std::time::Duration::from_secs(0),
            initial_epoch: 0,
            maximum_transmission_unit: DEFAULT_MTU,
            maximum_retransmit_number: DEFAULT_MAXIMUM_RETRANSMIT_NUMBER,
            replay_protection_window: DEFAULT_REPLAY_PROTECTION_WINDOW,
        }
    }

    pub(crate) fn provider(&self) -> &Arc<dyn RTCCryptoProvider> {
        &self.crypto_provider
    }

    /// Chooses the certificate to present, as pion's `getCertificate`: the callback runs when
    /// one is configured and either no certificates are held or the client named a server
    /// through SNI; `Ok(None)` and "no callback" fall through to the configured certificates
    /// and `name_to_certificate` selection.
    pub(crate) fn get_certificate_for_hello(&self, info: &ClientHelloInfo) -> Result<Certificate> {
        if let Some(get_certificate) = &self.get_certificate
            && (self.local_certificates.is_empty() || !info.server_name.is_empty())
        {
            match get_certificate(info) {
                Ok(Some(certificate)) => return Ok(certificate),
                Ok(None) => {}
                Err(err) => return Err(err),
            }
        }
        self.get_certificate(&info.server_name)
    }

    pub(crate) fn get_certificate(&self, server_name: &str) -> Result<Certificate> {
        if self.local_certificates.is_empty() {
            return Err(Error::ErrNoCertificates);
        }

        if self.local_certificates.len() == 1 {
            // There's only one choice, so no point doing any work.
            return Ok(self.local_certificates[0].clone());
        }

        if server_name.is_empty() {
            return Ok(self.local_certificates[0].clone());
        }

        let lower = server_name.to_lowercase();
        let name = lower.trim_end_matches('.');

        if let Some(cert) = self.name_to_certificate.get(name) {
            return Ok(cert.clone());
        }

        // try replacing labels in the name with wildcards until we get a
        // match.
        let mut labels: Vec<&str> = name.split_terminator('.').collect();
        for i in 0..labels.len() {
            labels[i] = "*";
            let candidate = labels.join(".");
            if let Some(cert) = self.name_to_certificate.get(&candidate) {
                return Ok(cert.clone());
            }
        }

        // If nothing matches, return the first certificate.
        Ok(self.local_certificates[0].clone())
    }
}

#[cfg(test)]
mod file_key_logger_tests {
    use super::{FileKeyLogger, KeyLogger};

    /// Lines land verbatim — trailing newline included — and append, not truncate, so a
    /// restart of the process extends the capture rather than replacing it.
    #[test]
    fn appends_lines_verbatim() {
        let dir = std::env::temp_dir().join(format!("rtc-dtls-keylog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.log");

        for (i, line) in ["CLIENT_RANDOM a0 b1\n", "CLIENT_RANDOM c2 d3\n"]
            .iter()
            .enumerate()
        {
            if i == 0 {
                std::fs::remove_file(&path).ok();
            }
            let logger = FileKeyLogger::create(&path).unwrap();
            logger.write_line(line);
            // Dropped here: append mode means the next open extends, never truncates.
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents, "CLIENT_RANDOM a0 b1\nCLIENT_RANDOM c2 d3\n",
            "both lines must be present, appended, with the newline carried through"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// Summarizes a received ClientHello for [`GetCertificateFn`]: the SNI it named, the cipher
/// suites, signature schemes and curves it offered, and its random bytes.
pub(crate) fn client_hello_info(client_hello: &HandshakeMessageClientHello) -> ClientHelloInfo {
    let mut info = ClientHelloInfo {
        server_name: String::new(),
        cipher_suites: client_hello.cipher_suites.clone(),
        signature_schemes: vec![],
        elliptic_curves: vec![],
        random_bytes: client_hello.random.random_bytes,
    };
    for extension in &client_hello.extensions {
        match extension {
            crate::extension::Extension::ServerName(e) => {
                info.server_name.clone_from(&e.server_name);
            }
            crate::extension::Extension::SupportedSignatureAlgorithms(e) => {
                info.signature_schemes = e.signature_hash_algorithms.clone();
            }
            crate::extension::Extension::SupportedEllipticCurves(e) => {
                info.elliptic_curves = e.elliptic_curves.clone();
            }
            _ => {}
        }
    }
    info
}
