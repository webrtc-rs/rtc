pub(crate) mod flight0;
pub(crate) mod flight1;
pub(crate) mod flight2;
pub(crate) mod flight3;
pub(crate) mod flight4;
pub(crate) mod flight5;
pub(crate) mod flight6;

use crate::alert::*;
use crate::handshake::handshake_cache::*;
use crate::handshaker::*;
use crate::record_layer::*;
use crate::state::*;
use shared::error::Error;

use crate::config::HandshakeConfig;
use std::fmt;

/*
  DTLS messages are grouped into a series of message flights, according
  to the diagrams below.  Although each Flight of messages may consist
  of a number of messages, they should be viewed as monolithic for the
  purpose of timeout and retransmission.
  https://tools.ietf.org/html/rfc4347#section-4.2.4
  Client                                          Server
  ------                                          ------
                                      Waiting                 Flight 0

  ClientHello             -------->                           Flight 1

                          <-------    HelloVerifyRequest      Flight 2

  ClientHello              -------->                           Flight 3

                                             ServerHello    \
                                            Certificate*     \
                                      ServerKeyExchange*      Flight 4
                                     CertificateRequest*     /
                          <--------      ServerHelloDone    /

  Certificate*                                              \
  ClientKeyExchange                                          \
  CertificateVerify*                                          Flight 5
  [ChangeCipherSpec]                                         /
  Finished                -------->                         /

                                      [ChangeCipherSpec]    \ Flight 6
                          <--------             Finished    /

*/

#[derive(Clone, Debug)]
pub(crate) struct Packet {
    pub(crate) record: RecordLayer,
    pub(crate) should_encrypt: bool,
    pub(crate) reset_local_sequence_number: bool,
}

pub(crate) trait Flight: fmt::Display + fmt::Debug + Send + Sync {
    fn is_last_send_flight(&self) -> bool {
        false
    }
    fn is_last_recv_flight(&self) -> bool {
        false
    }
    fn has_retransmit(&self) -> bool {
        true
    }

    fn parse(
        &self,
        //tx: &mut mpsc::Sender<mpsc::Sender<()>>,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Box<dyn Flight>, (Option<Alert>, Option<Error>)>;

    fn generate(
        &self,
        state: &mut State,
        cache: &HandshakeCache,
        cfg: &HandshakeConfig,
    ) -> Result<Vec<Packet>, (Option<Alert>, Option<Error>)>;
}

use crate::handshake::handshake_message_client_hello::HandshakeMessageClientHello;

/// Builds the ClientHello a client sends, applying the `client_hello_message_hook` when one is
/// configured: the hook receives the finished message and its replacement is what goes out and
/// enters the transcript, as in pion.
pub(crate) fn build_client_hello_message(
    state: &State,
    cfg: &HandshakeConfig,
) -> Result<crate::handshake::HandshakeMessage, (Option<Alert>, Option<Error>)> {
    use crate::compression_methods::default_compression_methods;
    use crate::extension::extension_alpn::ExtensionAlpn;
    use crate::extension::extension_server_name::ExtensionServerName;
    use crate::extension::extension_supported_elliptic_curves::ExtensionSupportedEllipticCurves;
    use crate::extension::extension_supported_point_formats::{
        ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED, ExtensionSupportedPointFormats,
    };
    use crate::extension::extension_supported_signature_algorithms::ExtensionSupportedSignatureAlgorithms;
    use crate::extension::extension_use_extended_master_secret::ExtensionUseExtendedMasterSecret;
    use crate::extension::extension_use_srtp::ExtensionUseSrtp;
    use crate::extension::renegotiation_info::ExtensionRenegotiationInfo;
    use crate::extension::Extension;
    use crate::record_layer::record_layer_header::PROTOCOL_VERSION1_2;

    let mut extensions = vec![
        Extension::SupportedSignatureAlgorithms(ExtensionSupportedSignatureAlgorithms {
            signature_hash_algorithms: cfg.local_signature_schemes.clone(),
        }),
        Extension::RenegotiationInfo(ExtensionRenegotiationInfo {
            renegotiated_connection: 0,
        }),
    ];

    if cfg.local_psk_callback.is_none() {
        extensions.extend_from_slice(&[
            Extension::SupportedEllipticCurves(ExtensionSupportedEllipticCurves {
                elliptic_curves: cfg.local_named_curves.clone(),
            }),
            Extension::SupportedPointFormats(ExtensionSupportedPointFormats {
                point_formats: vec![ELLIPTIC_CURVE_POINT_FORMAT_UNCOMPRESSED],
            }),
        ]);
    }

    // The certificate-signature schemes travel in their own extension, as in pion.
    if !cfg.local_certificate_signature_schemes.is_empty() {
        extensions.push(Extension::SignatureAlgorithmsCert(
            crate::extension::extension_signature_algorithms_cert::ExtensionSignatureAlgorithmsCert {
                signature_hash_algorithms: cfg.local_certificate_signature_schemes.clone(),
            },
        ));
    }

    if !cfg.local_srtp_protection_profiles.is_empty() {
        extensions.push(Extension::UseSrtp(ExtensionUseSrtp {
            protection_profiles: cfg.local_srtp_protection_profiles.clone(),
        }));
    }

    if !cfg.local_supported_protocols.is_empty() {
        extensions.push(Extension::Alpn(ExtensionAlpn {
            protocols: cfg.local_supported_protocols.clone(),
        }));
    }

    if cfg.extended_master_secret == crate::config::ExtendedMasterSecretType::Request
        || cfg.extended_master_secret == crate::config::ExtendedMasterSecretType::Require
    {
        extensions.push(Extension::UseExtendedMasterSecret(
            ExtensionUseExtendedMasterSecret { supported: true },
        ));
    }

    // RFC 6066 §3: literal IP addresses are not permitted in server_name.
    if !cfg.sni_server_name.is_empty()
        && cfg.sni_server_name.parse::<std::net::IpAddr>().is_err()
    {
        extensions.push(Extension::ServerName(ExtensionServerName {
            server_name: cfg.sni_server_name.clone(),
        }));
    }

    let message = HandshakeMessageClientHello {
        version: PROTOCOL_VERSION1_2,
        random: state.local_random.clone(),
        cookie: state.cookie.clone(),
        cipher_suites: cfg.local_cipher_suites.clone(),
        compression_methods: default_compression_methods(),
        extensions,
    };

    if let Some(hook) = &cfg.client_hello_message_hook {
        return Ok(hook(message));
    }
    Ok(crate::handshake::HandshakeMessage::ClientHello(message))
}

/// Summarizes the negotiated ClientHello and selects the certificate for the answer, as pion
/// does while negotiating: the `get_certificate` callback runs first (when configured and the
/// hello is relevant to it), and its result is retained in the state so retransmits reuse it.
pub(crate) fn negotiate_server_certificate(
    state: &mut State,
    cfg: &HandshakeConfig,
    client_hello: &HandshakeMessageClientHello,
) -> Result<(), (Option<Alert>, Option<Error>)> {
    let info = crate::config::client_hello_info(client_hello);
    // A PSK handshake presents no certificate (pion gates on the suite's authentication type).
    if state
        .cipher_suite
        .as_ref()
        .is_some_and(|cipher_suite| !cipher_suite.is_psk())
    {
        match cfg.get_certificate_for_hello(&info) {
            Ok(certificate) => state.server_certificate = Some(certificate),
            Err(err) => {
                return Err((
                    Some(Alert {
                        alert_level: AlertLevel::Fatal,
                        alert_description: AlertDescription::HandshakeFailure,
                    }),
                    Some(err),
                ));
            }
        }
    }
    state.client_hello_info = Some(info);
    Ok(())
}

/// Re-reads the `signature_algorithms_cert` offer from a ClientHello into the state, as pion
/// re-negotiation does for the second hello of the cookie exchange.
pub(crate) fn retain_remote_cert_signature_schemes(
    state: &mut State,
    client_hello: &HandshakeMessageClientHello,
) {
    for extension in &client_hello.extensions {
        if let crate::extension::Extension::SignatureAlgorithmsCert(e) = extension {
            state.remote_cert_signature_schemes = e.signature_hash_algorithms.clone();
        }
    }
}
