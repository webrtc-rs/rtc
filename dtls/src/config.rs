use crate::cipher_suite::*;
use crate::conn::{DEFAULT_REPLAY_PROTECTION_WINDOW, INITIAL_TICKER_INTERVAL};
use crate::crypto::*;
use crate::extension::extension_use_srtp::SrtpProtectionProfile;
use crate::signature_hash_algorithm::{
    parse_signature_schemes, SignatureHashAlgorithm, SignatureScheme,
};
use shared::error::*;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

/// Config is used to configure a DTLS client or server.
/// After a Config is passed to a DTLS function it must not be modified.
#[derive(Clone)]
pub struct ConfigBuilder {
    certificates: Vec<Certificate>,
    cipher_suites: Vec<CipherSuiteId>,
    signature_schemes: Vec<SignatureScheme>,
    srtp_protection_profiles: Vec<SrtpProtectionProfile>,
    client_auth: ClientAuthType,
    extended_master_secret: ExtendedMasterSecretType,
    flight_interval: Duration,
    psk: Option<PskCallback>,
    psk_identity_hint: Option<Vec<u8>>,
    insecure_skip_verify: bool,
    insecure_hashes: bool,
    insecure_verification: bool,
    verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    roots_cas: rustls::RootCertStore,
    client_cas: rustls::RootCertStore,
    server_name: String,
    mtu: usize,
    replay_protection_window: usize,
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self {
            certificates: vec![],
            cipher_suites: vec![],
            signature_schemes: vec![],
            srtp_protection_profiles: vec![],
            client_auth: ClientAuthType::default(),
            extended_master_secret: ExtendedMasterSecretType::default(),
            flight_interval: Duration::default(),
            psk: None,
            psk_identity_hint: None,
            insecure_skip_verify: false,
            insecure_hashes: false,
            insecure_verification: false,
            verify_peer_certificate: None,
            roots_cas: rustls::RootCertStore::empty(),
            client_cas: rustls::RootCertStore::empty(),
            server_name: String::default(),
            mtu: 0,
            replay_protection_window: 0,
        }
    }
}

impl ConfigBuilder {
    /// certificates contains certificate chain to present to the other side of the connection.
    /// Server MUST set this if psk is non-nil
    /// client SHOULD sets this so CertificateRequests can be handled if psk is non-nil
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
    /// If psk is non-nil only psk cipher_suites will be used
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

pub(crate) const DEFAULT_MTU: usize = 1228; // bytes

/// PSKCallback is called once we have the remote's psk_identity_hint.
/// If the remote provided none it will be nil
pub(crate) type PskCallback = Rc<dyn (Fn(&[u8]) -> Result<Vec<u8>>)>;

/// ClientAuthType declares the policy the server will follow for
/// TLS Client Authentication.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum ClientAuthType {
    #[default]
    NoClientCert = 0,
    RequestClientCert = 1,
    RequireAnyClientCert = 2,
    VerifyClientCertIfGiven = 3,
    RequireAndVerifyClientCert = 4,
}

// ExtendedMasterSecretType declares the policy the client and server
// will follow for the Extended Master Secret extension
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
pub enum ExtendedMasterSecretType {
    #[default]
    Request = 0,
    Require = 1,
    Disable = 2,
}

impl ConfigBuilder {
    fn validate(&self, is_client: bool) -> Result<()> {
        if is_client && self.psk.is_some() && self.psk_identity_hint.is_none() {
            return Err(Error::ErrPskAndIdentityMustBeSetForClient);
        }

        if !is_client && self.psk.is_none() && self.certificates.is_empty() {
            return Err(Error::ErrServerMustHaveCertificate);
        }

        if !self.certificates.is_empty() && self.psk.is_some() {
            return Err(Error::ErrPskAndCertificate);
        }

        if self.psk_identity_hint.is_some() && self.psk.is_none() {
            return Err(Error::ErrIdentityNoPsk);
        }

        for cert in &self.certificates {
            match cert.private_key.kind {
                CryptoPrivateKeyKind::Ed25519(_) => {}
                CryptoPrivateKeyKind::Ecdsa256(_) => {}
                _ => return Err(Error::ErrInvalidPrivateKey),
            }
        }

        parse_cipher_suites(&self.cipher_suites, self.psk.is_none(), self.psk.is_some())?;

        Ok(())
    }

    /// build handshake config
    pub fn build(
        mut self,
        is_client: bool,
        remote_addr: Option<SocketAddr>,
    ) -> Result<HandshakeConfig> {
        self.validate(is_client)?;

        let local_cipher_suites: Vec<CipherSuiteId> =
            parse_cipher_suites(&self.cipher_suites, self.psk.is_none(), self.psk.is_some())?
                .iter()
                .map(|cs| cs.id())
                .collect();

        let sigs: Vec<u16> = self.signature_schemes.iter().map(|x| *x as u16).collect();
        let local_signature_schemes = parse_signature_schemes(&sigs, self.insecure_hashes)?;

        let retransmit_interval = if self.flight_interval != Duration::from_secs(0) {
            self.flight_interval
        } else {
            INITIAL_TICKER_INTERVAL
        };

        let maximum_transmission_unit = if self.mtu == 0 { DEFAULT_MTU } else { self.mtu };

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
                log::warn!("conn.remote_addr is empty, please set explicitly server_name in Config! Use default \"localhost\" as server_name now");
                server_name = "localhost".to_owned();
            }
        }

        Ok(HandshakeConfig {
            local_psk_callback: self.psk.take(),
            local_psk_identity_hint: self.psk_identity_hint.take(),
            local_cipher_suites,
            local_signature_schemes,
            extended_master_secret: self.extended_master_secret,
            local_srtp_protection_profiles: self.srtp_protection_profiles,
            server_name,
            client_auth: self.client_auth,
            local_certificates: self.certificates,
            insecure_skip_verify: self.insecure_skip_verify,
            insecure_verification: self.insecure_verification,
            verify_peer_certificate: self.verify_peer_certificate.take(),
            roots_cas: self.roots_cas,
            server_cert_verifier: Rc::new(rustls::client::WebPkiVerifier::new(
                rustls::RootCertStore::empty(),
                None,
            )),
            client_cert_verifier: None,
            retransmit_interval,
            initial_epoch: 0,
            maximum_transmission_unit,
            replay_protection_window,
            ..Default::default()
        })
    }
}

pub(crate) type VerifyPeerCertificateFn =
    Rc<dyn (Fn(&[Vec<u8>], &[rustls::Certificate]) -> Result<()>)>;

#[derive(Clone)]
pub struct HandshakeConfig {
    pub(crate) local_psk_callback: Option<PskCallback>,
    pub(crate) local_psk_identity_hint: Option<Vec<u8>>,
    pub(crate) local_cipher_suites: Vec<CipherSuiteId>, // Available CipherSuites
    pub(crate) local_signature_schemes: Vec<SignatureHashAlgorithm>, // Available signature schemes
    pub(crate) extended_master_secret: ExtendedMasterSecretType, // Policy for the Extended Master Support extension
    pub(crate) local_srtp_protection_profiles: Vec<SrtpProtectionProfile>, // Available SRTPProtectionProfiles, if empty no SRTP support
    pub(crate) server_name: String,
    pub(crate) client_auth: ClientAuthType, // If we are a client should we request a client certificate
    pub(crate) local_certificates: Vec<Certificate>,
    pub(crate) name_to_certificate: HashMap<String, Certificate>,
    pub(crate) insecure_skip_verify: bool,
    pub(crate) insecure_verification: bool,
    pub(crate) verify_peer_certificate: Option<VerifyPeerCertificateFn>,
    pub(crate) roots_cas: rustls::RootCertStore,
    pub(crate) server_cert_verifier: Rc<dyn rustls::client::ServerCertVerifier>,
    pub(crate) client_cert_verifier: Option<Rc<dyn rustls::server::ClientCertVerifier>>,
    pub(crate) retransmit_interval: std::time::Duration,
    pub(crate) initial_epoch: u16,
    pub(crate) maximum_transmission_unit: usize,
    pub(crate) maximum_retransmit_number: usize,
    pub(crate) replay_protection_window: usize,
}

impl fmt::Debug for HandshakeConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("HandshakeConfig<T>")
            .field("local_psk_identity_hint", &self.local_psk_identity_hint)
            .field("local_cipher_suites", &self.local_cipher_suites)
            .field("local_signature_schemes", &self.local_signature_schemes)
            .field("extended_master_secret", &self.extended_master_secret)
            .field(
                "local_srtp_protection_profiles",
                &self.local_srtp_protection_profiles,
            )
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

impl Default for HandshakeConfig {
    fn default() -> Self {
        HandshakeConfig {
            local_psk_callback: None,
            local_psk_identity_hint: None,
            local_cipher_suites: vec![],
            local_signature_schemes: vec![],
            extended_master_secret: ExtendedMasterSecretType::Disable,
            local_srtp_protection_profiles: vec![],
            server_name: String::new(),
            client_auth: ClientAuthType::NoClientCert,
            local_certificates: vec![],
            name_to_certificate: HashMap::new(),
            insecure_skip_verify: false,
            insecure_verification: false,
            verify_peer_certificate: None,
            roots_cas: rustls::RootCertStore::empty(),
            server_cert_verifier: Rc::new(rustls::client::WebPkiVerifier::new(
                rustls::RootCertStore::empty(),
                None,
            )),
            client_cert_verifier: None,
            retransmit_interval: std::time::Duration::from_secs(0),
            initial_epoch: 0,
            maximum_transmission_unit: DEFAULT_MTU,
            maximum_retransmit_number: 7,
            replay_protection_window: DEFAULT_REPLAY_PROTECTION_WINDOW,
        }
    }
}

impl HandshakeConfig {
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
