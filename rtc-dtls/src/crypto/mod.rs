//! Cryptographic primitives for DTLS.
//!
//! The record ciphers ([`crypto_gcm`](crate::crypto::crypto_gcm), [`crypto_ccm`](crate::crypto::crypto_ccm), [`crypto_chacha20`](crate::crypto::crypto_chacha20), [`crypto_cbc`](crate::crypto::crypto_cbc)), plus
//! the certificate and signature handling the handshake needs. Which cipher is used is decided by
//! the negotiated cipher suite, so a caller normally reaches these only through
//! [`CipherSuite`](crate::cipher_suite::CipherSuite).
//!
//! Certificates here are usually self-signed: WebRTC authenticates a peer by comparing the
//! certificate fingerprint against the one signalled in SDP, not by validating a CA chain.
#[cfg(test)]
mod crypto_test;

/// AES-CBC with a separate HMAC, for the older CBC suites.
pub mod crypto_cbc;
/// AES-CCM authenticated encryption.
pub mod crypto_ccm;
/// ChaCha20-Poly1305 authenticated encryption.
pub mod crypto_chacha20;
/// AES-GCM authenticated encryption.
pub mod crypto_gcm;

use std::convert::TryFrom;
use std::sync::Arc;

use der_parser::oid;
use der_parser::oid::Oid;

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::danger::ClientCertVerifier;

use crypto::{
    PublicKey, PublicKeyEncoding, RTCCrypto, SignatureScheme as CryptoSignatureScheme, SigningKey,
};
#[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
use rcgen::{CertifiedKey, KeyPair, generate_simple_self_signed};

use crate::curve::named_curve::*;
use crate::record_layer::record_layer_header::*;
use crate::signature_hash_algorithm::{HashAlgorithm, SignatureAlgorithm, SignatureHashAlgorithm};
use shared::error::*;

pub(crate) fn crypto_error(error: crypto::CryptoError) -> Error {
    Error::Crypto(error.to_string())
}

pub(crate) fn authentication_error(_: crypto::CryptoError) -> Error {
    Error::ErrInvalidMac
}

fn signature_verification_error(error: crypto::CryptoError) -> Error {
    match error {
        crypto::CryptoError::InvalidSignature => Error::ErrKeySignatureMismatch,
        crypto::CryptoError::UnsupportedAlgorithm(_) => Error::ErrKeySignatureVerifyUnimplemented,
        error => crypto_error(error),
    }
}

/// A X.509 certificate(s) used to authenticate a DTLS connection.
#[derive(Clone, PartialEq, Debug)]
pub struct Certificate {
    /// DER-encoded certificates.
    pub certificate: Vec<CertificateDer<'static>>,
    /// Private key.
    pub private_key: CryptoPrivateKey,
}

impl Certificate {
    #[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
    /// Generates a self-signed certificate, importing its key into `provider`.
    pub fn generate_self_signed(
        subject_alt_names: impl Into<Vec<String>>,
        crypto: &dyn RTCCrypto,
    ) -> Result<Self> {
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names)
            .map_err(|error| Error::Other(error.to_string()))?;
        Ok(Certificate {
            certificate: vec![cert.der().to_owned()],
            private_key: CryptoPrivateKey::from_key_pair(&signing_key, crypto)?,
        })
    }

    #[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
    /// Generates a self-signed certificate with `alg`, importing its key into `provider`.
    pub fn generate_self_signed_with_alg(
        subject_alt_names: impl Into<Vec<String>>,
        alg: &'static rcgen::SignatureAlgorithm,
        crypto: &dyn RTCCrypto,
    ) -> Result<Self> {
        let params = rcgen::CertificateParams::new(subject_alt_names)
            .map_err(|error| Error::Other(error.to_string()))?;
        let key_pair =
            rcgen::KeyPair::generate_for(alg).map_err(|error| Error::Other(error.to_string()))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|error| Error::Other(error.to_string()))?;

        Ok(Certificate {
            certificate: vec![cert.der().to_owned()],
            private_key: CryptoPrivateKey::from_key_pair(&key_pair, crypto)?,
        })
    }

    /// Parses a PEM certificate and imports its PKCS#8 key into `crypto`.
    pub fn from_pem(pem_str: &str, crypto: &dyn RTCCrypto) -> Result<Self> {
        let mut pems = pem::parse_many(pem_str).map_err(|e| Error::InvalidPEM(e.to_string()))?;
        if pems.len() < 2 {
            return Err(Error::InvalidPEM(format!(
                "expected at least two PEM blocks, got {}",
                pems.len()
            )));
        }
        if pems[0].tag() != "PRIVATE_KEY" {
            return Err(Error::InvalidPEM(format!(
                "invalid tag (expected: 'PRIVATE_KEY', got: '{}')",
                pems[0].tag()
            )));
        }

        let private_key_der = pems[0].contents().to_vec();

        let mut rustls_certs = Vec::new();
        for p in pems.drain(1..) {
            if p.tag() != "CERTIFICATE" {
                return Err(Error::InvalidPEM(format!(
                    "invalid tag (expected: 'CERTIFICATE', got: '{}')",
                    p.tag()
                )));
            }
            rustls_certs.push(CertificateDer::from(p.contents().to_vec()));
        }

        let schemes = [
            CryptoSignatureScheme::Ed25519,
            CryptoSignatureScheme::EcdsaP256Sha256,
            CryptoSignatureScheme::RsaPkcs1Sha256,
        ];
        let signing_key = schemes
            .into_iter()
            .filter(|scheme| crypto.supports(crypto::CryptoAlgorithm::SigningKeyImport(*scheme)))
            .find_map(|scheme| crypto.import_signing_key(scheme, &private_key_der).ok())
            .ok_or_else(|| Error::InvalidPEM("can't decode PKCS#8 signing key".into()))?;

        Ok(Certificate::from_signing_key(rustls_certs, signing_key))
    }

    /// Serializes the certificate (including the private key) in PKCS#8 format in PEM.
    pub fn serialize_pem(&self) -> Result<String> {
        let private_key = self
            .private_key
            .signing_key
            .to_pkcs8_der()
            .map_err(crypto_error)?
            .ok_or_else(|| Error::Other("the certificate signing key is not exportable".into()))?;
        let mut data = vec![pem::Pem::new(
            "PRIVATE_KEY".to_string(),
            private_key.as_ref(),
        )];
        for rustls_cert in &self.certificate {
            data.push(pem::Pem::new(
                "CERTIFICATE".to_string(),
                rustls_cert.as_ref(),
            ));
        }
        Ok(pem::encode_many(&data))
    }

    /// Builds a certificate chain around an application-owned signing key, including HSM/KMS keys.
    pub fn from_signing_key(
        certificate: Vec<CertificateDer<'static>>,
        signing_key: Arc<dyn SigningKey>,
    ) -> Self {
        Self {
            certificate,
            private_key: CryptoPrivateKey::from_signing_key(signing_key),
        }
    }
}

pub(crate) fn value_key_message(
    client_random: &[u8],
    server_random: &[u8],
    public_key: &[u8],
    named_curve: NamedCurve,
) -> Vec<u8> {
    let mut server_ecdh_params = vec![0u8; 4];
    server_ecdh_params[0] = 3; // named curve
    server_ecdh_params[1..3].copy_from_slice(&(named_curve as u16).to_be_bytes());
    server_ecdh_params[3] = public_key.len() as u8;

    let mut plaintext = vec![];
    plaintext.extend_from_slice(client_random);
    plaintext.extend_from_slice(server_random);
    plaintext.extend_from_slice(&server_ecdh_params);
    plaintext.extend_from_slice(public_key);

    plaintext
}

/// Provider-neutral DTLS signing key.
#[derive(Clone)]
pub struct CryptoPrivateKey {
    /// Provider-owned signing key. It may be non-exportable.
    pub signing_key: Arc<dyn SigningKey>,
}

impl PartialEq for CryptoPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        let left = self.signing_key.public_key();
        let right = other.signing_key.public_key();
        left.encoding == right.encoding && left.bytes == right.bytes
    }
}

impl std::fmt::Debug for CryptoPrivateKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let public_key = self.signing_key.public_key();
        formatter
            .debug_struct("CryptoPrivateKey")
            .field("public_key_encoding", &public_key.encoding)
            .field("public_key_len", &public_key.bytes.len())
            .finish()
    }
}

impl CryptoPrivateKey {
    /// Imports an rcgen key pair into an explicit provider.
    #[cfg(any(feature = "crypto-ring", feature = "crypto-aws-lc-rs"))]
    pub fn from_key_pair(key_pair: &KeyPair, crypto: &dyn RTCCrypto) -> Result<Self> {
        let serialized_der = key_pair.serialize_der();
        let scheme = if key_pair.is_compatible(&rcgen::PKCS_ED25519) {
            CryptoSignatureScheme::Ed25519
        } else if key_pair.is_compatible(&rcgen::PKCS_ECDSA_P256_SHA256) {
            CryptoSignatureScheme::EcdsaP256Sha256
        } else if key_pair.is_compatible(&rcgen::PKCS_RSA_SHA256) {
            CryptoSignatureScheme::RsaPkcs1Sha256
        } else {
            return Err(Error::Other("Unsupported key_pair".to_owned()));
        };
        let signing_key = crypto
            .import_signing_key(scheme, &serialized_der)
            .map_err(crypto_error)?;
        Ok(Self { signing_key })
    }

    /// Wraps a provider-neutral, potentially non-exportable signing key.
    pub fn from_signing_key(signing_key: Arc<dyn SigningKey>) -> Self {
        Self { signing_key }
    }
}

// If the client provided a "signature_algorithms" extension, then all
// certificates provided by the server MUST be signed by a
// hash/signature algorithm pair that appears in that extension
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
pub(crate) fn generate_key_signature(
    client_random: &[u8],
    server_random: &[u8],
    public_key: &[u8],
    named_curve: NamedCurve,
    algorithm: &SignatureHashAlgorithm,
    private_key: &CryptoPrivateKey,
) -> Result<Vec<u8>> {
    validate_signature_hash_pair(algorithm.hash, algorithm.signature)?;
    let scheme = algorithm.crypto_scheme()?;
    if !private_key.signing_key.supports(scheme) {
        return Err(Error::ErrInvalidSignatureAlgorithm);
    }

    let msg = value_key_message(client_random, server_random, public_key, named_curve);
    private_key
        .signing_key
        .sign(scheme, &msg)
        .map_err(crypto_error)
}

// add OID_ED25519 which is not defined in x509_parser
/// The X.509 algorithm OID for Ed25519.
pub const OID_ED25519: Oid<'static> = oid!(1.3.101.112);
/// The X.509 algorithm OID for ECDSA with a named curve.
pub const OID_ECDSA: Oid<'static> = oid!(1.2.840.10045.2.1);
/// The X.509 algorithm OID for an RSA public key (`rsaEncryption`).
pub const OID_RSA: Oid<'static> = oid!(1.2.840.113549.1.1.1);
/// The X.509 algorithm OID for an RSA-PSS public key (`id-RSASSA-PSS`).
pub const OID_RSASSA_PSS: Oid<'static> = oid!(1.2.840.113549.1.1.10);

/// The kind of public key a certificate carries, as far as handshake signing is concerned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum CertificateKeyKind {
    /// An Ed25519 key; signs the message directly, with no separate hash.
    Ed25519,
    /// An ECDSA key over a NIST curve.
    Ecdsa,
    /// An RSA key, used with PKCS#1 v1.5 or (not yet) PSS padding.
    Rsa,
}

impl CertificateKeyKind {
    fn from_spki_oid(oid: &Oid<'_>) -> Result<Self> {
        if *oid == OID_RSA || *oid == OID_RSASSA_PSS {
            // An `id-RSASSA-PSS` key is an RSA key too; which padding the certificate's OID
            // allows is `validate_signature_alg_oid`'s job, as in pion.
            Ok(CertificateKeyKind::Rsa)
        } else if *oid == OID_ECDSA {
            Ok(CertificateKeyKind::Ecdsa)
        } else if *oid == OID_ED25519 {
            Ok(CertificateKeyKind::Ed25519)
        } else {
            Err(Error::ErrInvalidCertificate)
        }
    }
}

// A PSS signature scheme must be paired with the certificate public key OID its family requires,
// as pion's validateSignatureAlgOID does (RFC 8446 §4.2.3): the RSAE variants require
// `rsaEncryption`, the PSS variants `id-RSASSA-PSS`. Every other scheme places no OID constraint.
fn validate_signature_alg_oid(
    certificate_oid: &Oid<'_>,
    signature_algorithm: SignatureAlgorithm,
) -> Result<()> {
    let required = match signature_algorithm {
        SignatureAlgorithm::RsaPssRsaeSha256
        | SignatureAlgorithm::RsaPssRsaeSha384
        | SignatureAlgorithm::RsaPssRsaeSha512 => &OID_RSA,
        SignatureAlgorithm::RsaPssPssSha256
        | SignatureAlgorithm::RsaPssPssSha384
        | SignatureAlgorithm::RsaPssPssSha512 => &OID_RSASSA_PSS,
        _ => return Ok(()),
    };
    if certificate_oid != required {
        return Err(Error::ErrInvalidCertificateOID);
    }
    Ok(())
}

// Binds the wire signature scheme to the certificate's key and hash, as pion's
// validateHandshakeSignatureScheme does. RSA and ECDSA keys must never sign or verify a
// digest-less handshake, and an Ed25519 key must be labeled with the Ed25519 scheme: a valid
// signature over one scheme must not authenticate a different one.
pub(crate) fn validate_handshake_signature_scheme(
    key_kind: CertificateKeyKind,
    hash_algorithm: HashAlgorithm,
    signature_algorithm: SignatureAlgorithm,
) -> Result<()> {
    if key_kind == CertificateKeyKind::Ed25519 {
        if signature_algorithm == SignatureAlgorithm::Ed25519
            && hash_algorithm == HashAlgorithm::Ed25519
        {
            return Ok(());
        }

        return Err(Error::ErrInvalidSignatureAlgorithm);
    }

    // pion rejects every hash with no crypto hash — `None` (this crate's `Md2` code point),
    // Ed25519's "null" hash, and unknown values — for non-Ed25519 keys.
    if matches!(
        hash_algorithm,
        HashAlgorithm::Md2 | HashAlgorithm::Ed25519 | HashAlgorithm::Unsupported
    ) {
        return Err(Error::ErrInvalidSignatureAlgorithm);
    }

    match key_kind {
        CertificateKeyKind::Ecdsa => {
            if signature_algorithm == SignatureAlgorithm::Ecdsa {
                return Ok(());
            }
        }
        CertificateKeyKind::Rsa => {
            // get_pss_hash returns the `Md2` code point for non-PSS schemes, which the
            // no-real-hash check above already excluded.
            if signature_algorithm == SignatureAlgorithm::Rsa
                || signature_algorithm.get_pss_hash() == hash_algorithm
            {
                return Ok(());
            }
        }
        CertificateKeyKind::Ed25519 => {}
    }

    Err(Error::ErrInvalidSignatureAlgorithm)
}

// The wire-scheme rules that hold regardless of key type, mirroring the key-independent half of
// pion's validateHandshakeSignatureScheme: an Ed25519 signature must be paired with the
// Ed25519 hash, and every other signature needs a real hash.
pub(crate) fn validate_signature_hash_pair(
    hash_algorithm: HashAlgorithm,
    signature_algorithm: SignatureAlgorithm,
) -> Result<()> {
    if signature_algorithm == SignatureAlgorithm::Ed25519 {
        if hash_algorithm == HashAlgorithm::Ed25519 {
            return Ok(());
        }

        return Err(Error::ErrInvalidSignatureAlgorithm);
    }

    if matches!(
        hash_algorithm,
        HashAlgorithm::Md2 | HashAlgorithm::Ed25519 | HashAlgorithm::Unsupported
    ) {
        return Err(Error::ErrInvalidSignatureAlgorithm);
    }

    Ok(())
}

fn verify_signature(
    crypto: &dyn crypto::RTCCrypto,
    message: &[u8],
    hash_algorithm: &SignatureHashAlgorithm,
    remote_key_signature: &[u8],
    raw_certificates: &[Vec<u8>],
    insecure_verification: bool,
) -> Result<()> {
    if raw_certificates.is_empty() {
        return Err(Error::ErrLengthMismatch);
    }

    let certificate = parse_peer_certificate(&raw_certificates[0])?;

    // The wire scheme must match the certificate's key and hash before any cryptographic work.
    validate_signature_alg_oid(
        certificate.tbs_certificate.subject_pki.algorithm.oid(),
        hash_algorithm.signature,
    )?;
    let key_kind =
        CertificateKeyKind::from_spki_oid(certificate.tbs_certificate.subject_pki.algorithm.oid())?;
    validate_handshake_signature_scheme(key_kind, hash_algorithm.hash, hash_algorithm.signature)?;

    let encoding = match hash_algorithm.signature {
        SignatureAlgorithm::Ed25519 => PublicKeyEncoding::Ed25519Raw,
        SignatureAlgorithm::Ecdsa => PublicKeyEncoding::EcUncompressedPoint,
        SignatureAlgorithm::Rsa => PublicKeyEncoding::RsaPkcs1Der,
        // The PSS schemes are parsed on the wire but no provider signs or verifies them yet,
        // and anonymous pairs have no key to verify against.
        SignatureAlgorithm::RsaPssRsaeSha256
        | SignatureAlgorithm::RsaPssRsaeSha384
        | SignatureAlgorithm::RsaPssRsaeSha512
        | SignatureAlgorithm::RsaPssPssSha256
        | SignatureAlgorithm::RsaPssPssSha384
        | SignatureAlgorithm::RsaPssPssSha512
        | SignatureAlgorithm::Anonymous
        | SignatureAlgorithm::Unsupported => return Err(Error::ErrKeySignatureVerifyUnimplemented),
    };
    if hash_algorithm.signature == SignatureAlgorithm::Rsa
        && remote_key_signature.len() < 256
        && !insecure_verification
    {
        return Err(Error::ErrKeySignatureMismatch);
    }
    let scheme = match (hash_algorithm.signature, hash_algorithm.hash) {
        (SignatureAlgorithm::Ecdsa, crate::signature_hash_algorithm::HashAlgorithm::Sha256) => {
            if certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .len()
                == 97
            {
                crypto::SignatureScheme::EcdsaP384Sha256
            } else {
                crypto::SignatureScheme::EcdsaP256Sha256
            }
        }
        _ => hash_algorithm.crypto_scheme()?,
    };

    crypto
        .verify_signature(
            scheme,
            PublicKey {
                encoding,
                bytes: &certificate
                    .tbs_certificate
                    .subject_pki
                    .subject_public_key
                    .data,
            },
            message,
            remote_key_signature,
        )
        .map_err(signature_verification_error)
}

pub(crate) fn verify_key_signature(
    crypto: &dyn crypto::RTCCrypto,
    message: &[u8],
    hash_algorithm: &SignatureHashAlgorithm,
    remote_key_signature: &[u8],
    raw_certificates: &[Vec<u8>],
    insecure_verification: bool,
) -> Result<()> {
    verify_signature(
        crypto,
        message,
        hash_algorithm,
        remote_key_signature,
        raw_certificates,
        insecure_verification,
    )
}

// If the server has sent a CertificateRequest message, the client MUST send the Certificate
// message.  The ClientKeyExchange message is now sent, and the content
// of that message will depend on the public key algorithm selected
// between the ClientHello and the ServerHello.  If the client has sent
// a certificate with signing ability, a digitally-signed
// CertificateVerify message is sent to explicitly verify possession of
// the private key in the certificate.
// https://tools.ietf.org/html/rfc5246#section-7.3
pub(crate) fn generate_certificate_verify(
    handshake_bodies: &[u8],
    algorithm: &SignatureHashAlgorithm,
    private_key: &CryptoPrivateKey,
) -> Result<Vec<u8>> {
    validate_signature_hash_pair(algorithm.hash, algorithm.signature)?;
    let scheme = algorithm.crypto_scheme()?;
    if !private_key.signing_key.supports(scheme) {
        return Err(Error::ErrInvalidSignatureAlgorithm);
    }

    private_key
        .signing_key
        .sign(scheme, handshake_bodies)
        .map_err(crypto_error)
}

pub(crate) fn verify_certificate_verify(
    crypto: &dyn crypto::RTCCrypto,
    handshake_bodies: &[u8],
    hash_algorithm: &SignatureHashAlgorithm,
    remote_key_signature: &[u8],
    raw_certificates: &[Vec<u8>],
    insecure_verification: bool,
) -> Result<()> {
    verify_signature(
        crypto,
        handshake_bodies,
        hash_algorithm,
        remote_key_signature,
        raw_certificates,
        insecure_verification,
    )
}

/// Matches `crypto/tls`'s default limit, bounding the verification work a peer can demand with an
/// RSA public key (pion: `maxPeerRSAKeyBits`).
const MAX_PEER_RSA_KEY_BITS: usize = 8192;

/// The bit length of an RSA modulus, DER content bytes in hand — Go's `big.Int.BitLen`: leading
/// zero bytes are not significant, and within the first significant byte the leading zero bits
/// are not either.
fn rsa_bit_length(bytes: &[u8]) -> usize {
    let Some(first) = bytes.iter().position(|&b| b != 0) else {
        return 0;
    };
    let significant = &bytes[first..];
    significant.len() * 8 - significant[0].leading_zeros() as usize
}

/// Parses one peer certificate, rejecting an RSA public key above [`MAX_PEER_RSA_KEY_BITS`] with
/// `errPeerRSAKeyTooLarge` before any verification work, as pion's `parsePeerCertificate` does.
pub(crate) fn parse_peer_certificate(
    raw: &[u8],
) -> Result<x509_parser::certificate::X509Certificate<'_>> {
    let (_, certificate) =
        x509_parser::parse_x509_certificate(raw).map_err(|e| Error::Other(e.to_string()))?;
    if certificate.tbs_certificate.subject_pki.algorithm.oid() == &OID_RSA
        && rsa_bit_length(rsa_modulus(
            certificate
                .tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .as_ref(),
        )) > MAX_PEER_RSA_KEY_BITS
    {
        return Err(Error::ErrPeerRSAKeyTooLarge);
    }
    Ok(certificate)
}

/// The raw modulus of a DER `RSAPublicKey`, empty when the subject public key is not one.
fn rsa_modulus(subject_public_key: &[u8]) -> &[u8] {
    use x509_parser::prelude::FromDer;
    x509_parser::public_key::RSAPublicKey::from_der(subject_public_key)
        .map(|(_, key)| key.modulus)
        .unwrap_or(&[])
}

pub(crate) fn load_certs(raw_certificates: &[Vec<u8>]) -> Result<Vec<CertificateDer<'static>>> {
    if raw_certificates.is_empty() {
        return Err(Error::ErrLengthMismatch);
    }

    let mut certs = vec![];
    for raw_cert in raw_certificates {
        // Parsing through `parse_peer_certificate` applies the peer RSA key size limit to every
        // certificate in the chain, as pion's `loadCerts` does.
        parse_peer_certificate(raw_cert)?;
        let cert = CertificateDer::from(raw_cert.to_vec());
        certs.push(cert);
    }

    Ok(certs)
}

pub(crate) fn verify_client_cert(
    raw_certificates: &[Vec<u8>],
    cert_verifier: &Arc<dyn ClientCertVerifier>,
) -> Result<Vec<CertificateDer<'static>>> {
    let chains = load_certs(raw_certificates)?;

    let (end_entity, intermediates) = chains
        .split_first()
        .ok_or(Error::ErrClientCertificateRequired)?;

    match cert_verifier.verify_client_cert(
        end_entity,
        intermediates,
        rustls::pki_types::UnixTime::now(),
    ) {
        Ok(_) => {}
        Err(err) => return Err(Error::Other(err.to_string())),
    };

    Ok(chains)
}

pub(crate) fn verify_server_cert(
    raw_certificates: &[Vec<u8>],
    cert_verifier: &Arc<dyn ServerCertVerifier>,
    server_name: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    let chains = load_certs(raw_certificates)?;
    let server_name = match ServerName::try_from(server_name) {
        Ok(server_name) => server_name,
        Err(err) => return Err(Error::Other(err.to_string())),
    };

    let (end_entity, intermediates) = chains
        .split_first()
        .ok_or(Error::ErrServerMustHaveCertificate)?;
    match cert_verifier.verify_server_cert(
        end_entity,
        intermediates,
        &server_name,
        &[],
        rustls::pki_types::UnixTime::now(),
    ) {
        Ok(_) => {}
        Err(err) => return Err(Error::Other(err.to_string())),
    };

    Ok(chains)
}

pub(crate) fn generate_aead_additional_data(h: &RecordLayerHeader, payload_len: usize) -> [u8; 13] {
    let mut additional_data = [0u8; 13];
    // SequenceNumber MUST be set first
    // we only want uint48, clobbering an extra 2 (using uint64, rust doesn't have uint48)
    additional_data[..8].copy_from_slice(&h.sequence_number.to_be_bytes());
    additional_data[..2].copy_from_slice(&h.epoch.to_be_bytes());
    additional_data[8] = h.content_type as u8;
    additional_data[9] = h.protocol_version.major;
    additional_data[10] = h.protocol_version.minor;
    additional_data[11..].copy_from_slice(&(payload_len as u16).to_be_bytes());

    additional_data
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_certificate_serialize_pem_and_from_pem() -> Result<()> {
        let provider = crypto::default_provider().map_err(crypto_error)?;
        let cert =
            Certificate::generate_self_signed(vec!["webrtc.rs".to_owned()], provider.crypto())?;

        let pem = cert.serialize_pem()?;
        let loaded_cert = Certificate::from_pem(&pem, provider.crypto())?;

        assert_eq!(loaded_cert, cert);

        Ok(())
    }
}
