/// Application-Layer Protocol Negotiation ([RFC 7301]).
///
/// [RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
pub mod extension_alpn;
/// The `certificate_authorities` extension of TLS 1.3 / DTLS 1.3.
pub mod extension_certificate_auth;
/// The `connection_id` extension, which decouples records from the 4-tuple.
pub mod extension_connection_id;
/// The TLS 1.3-style `cookie` extension of DTLS 1.3.
pub mod extension_cookie;
/// The `early_data` extension, which negotiates 0-RTT data.
pub mod extension_early_data_indication;
/// The `key_share` extension, which carries the TLS 1.3 key-exchange shares.
pub mod extension_key_share;
/// The `oid_filters` extension, which constrains the client certificate by OID.
pub mod extension_oid_filters;
/// The `post_handshake_auth` extension, which offers authentication after the handshake.
pub mod extension_post_handshake_auth;
/// The `pre_shared_key` extension, which offers or selects a PSK identity.
pub mod extension_pre_shared_key;
/// The `psk_key_exchange_modes` extension, which constrains PSK handshakes.
pub mod extension_psk_key_exchange_modes;
/// Server Name Indication (SNI).
pub mod extension_server_name;
/// The curves a client will accept for ECDHE.
pub mod extension_supported_elliptic_curves;
/// The EC point formats a client will accept; WebRTC uses uncompressed.
pub mod extension_supported_point_formats;
/// The signature and hash algorithm pairs a client will accept.
pub mod extension_supported_signature_algorithms;
/// The `supported_versions` extension, which negotiates the DTLS/TLS version.
pub mod extension_supported_versions;
/// The extended master secret extension ([RFC 7627]), which binds the master secret to the
/// whole handshake.
pub mod extension_use_extended_master_secret;
/// The `use_srtp` extension, which negotiates SRTP protection profiles during the DTLS
/// handshake ([RFC 5764]).
pub mod extension_use_srtp;
/// The renegotiation info extension, sent empty to signal renegotiation is not supported.
pub mod renegotiation_info;

use extension_alpn::*;
use extension_certificate_auth::*;
use extension_connection_id::*;
use extension_cookie::*;
use extension_early_data_indication::*;
use extension_key_share::*;
use extension_oid_filters::*;
use extension_post_handshake_auth::*;
use extension_pre_shared_key::*;
use extension_psk_key_exchange_modes::*;
use extension_server_name::*;
use extension_supported_elliptic_curves::*;
use extension_supported_point_formats::*;
use extension_supported_signature_algorithms::*;
use extension_supported_versions::*;
use extension_use_extended_master_secret::*;
use extension_use_srtp::*;

use shared::error::*;

use crate::extension::renegotiation_info::ExtensionRenegotiationInfo;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
#[derive(Clone, Debug, PartialEq, Eq)]
/// The extension type code points this crate understands.
#[non_exhaustive]
pub enum ExtensionValue {
    /// `SERVER_NAME` (`0`).
    ServerName = 0,
    /// `SUPPORTED_ELLIPTIC_CURVES` (`10`).
    SupportedEllipticCurves = 10,
    /// `SUPPORTED_POINT_FORMATS` (`11`).
    SupportedPointFormats = 11,
    /// `SUPPORTED_SIGNATURE_ALGORITHMS` (`13`).
    SupportedSignatureAlgorithms = 13,
    /// `USE_SRTP` (`14`).
    UseSrtp = 14,
    /// `APPLICATION_LAYER_PROTOCOL_NEGOTIATION` (`16`).
    Alpn = 16,
    /// `USE_EXTENDED_MASTER_SECRET` (`23`).
    UseExtendedMasterSecret = 23,
    /// `PRE_SHARED_KEY` (`41`).
    PreSharedKey = 41,
    /// `EARLY_DATA` (`42`).
    EarlyDataIndication = 42,
    /// `SUPPORTED_VERSIONS` (`43`).
    SupportedVersions = 43,
    /// `COOKIE` (`44`).
    Cookie = 44,
    /// `PSK_KEY_EXCHANGE_MODES` (`45`).
    PskKeyExchangeModes = 45,
    /// `CERTIFICATE_AUTHORITIES` (`47`).
    CertificateAuthorities = 47,
    /// `OID_FILTERS` (`48`).
    OidFilters = 48,
    /// `POST_HANDSHAKE_AUTH` (`49`).
    PostHandshakeAuth = 49,
    /// `KEY_SHARE` (`51`).
    KeyShare = 51,
    /// `CONNECTION_ID` (`54`).
    ConnectionId = 54,
    /// `RENEGOTIATION_INFO` (`65281`).
    RenegotiationInfo = 65281,
    /// An extension this crate does not implement, which is ignored.
    Unsupported,
}

impl From<u16> for ExtensionValue {
    fn from(val: u16) -> Self {
        match val {
            0 => ExtensionValue::ServerName,
            10 => ExtensionValue::SupportedEllipticCurves,
            11 => ExtensionValue::SupportedPointFormats,
            13 => ExtensionValue::SupportedSignatureAlgorithms,
            14 => ExtensionValue::UseSrtp,
            16 => ExtensionValue::Alpn,
            23 => ExtensionValue::UseExtendedMasterSecret,
            41 => ExtensionValue::PreSharedKey,
            42 => ExtensionValue::EarlyDataIndication,
            43 => ExtensionValue::SupportedVersions,
            44 => ExtensionValue::Cookie,
            45 => ExtensionValue::PskKeyExchangeModes,
            47 => ExtensionValue::CertificateAuthorities,
            48 => ExtensionValue::OidFilters,
            49 => ExtensionValue::PostHandshakeAuth,
            51 => ExtensionValue::KeyShare,
            54 => ExtensionValue::ConnectionId,
            65281 => ExtensionValue::RenegotiationInfo,
            _ => ExtensionValue::Unsupported,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// A parsed hello extension.
#[non_exhaustive]
pub enum Extension {
    /// Server Name Indication.
    ServerName(ExtensionServerName),
    /// The curves the sender accepts for ECDHE.
    SupportedEllipticCurves(ExtensionSupportedEllipticCurves),
    /// The EC point formats the sender accepts.
    SupportedPointFormats(ExtensionSupportedPointFormats),
    /// The signature and hash pairs the sender accepts.
    SupportedSignatureAlgorithms(ExtensionSupportedSignatureAlgorithms),
    /// The SRTP protection profiles offered or selected.
    UseSrtp(ExtensionUseSrtp),
    /// The application protocols offered or selected.
    Alpn(ExtensionAlpn),
    /// The PSK identities offered, or the one selected.
    PreSharedKey(ExtensionPreSharedKey),
    /// The early-data indication, and the 0-RTT budget in a NewSessionTicket.
    EarlyDataIndication(ExtensionEarlyDataIndication),
    /// The versions offered, or the one selected.
    SupportedVersions(ExtensionSupportedVersions),
    /// The cookie a client echoes after a HelloRetryRequest.
    Cookie(ExtensionCookie),
    /// The PSK key exchange modes offered.
    PskKeyExchangeModes(ExtensionPskKeyExchangeModes),
    /// The certificate authorities a server accepts.
    CertificateAuthorities(ExtensionCertificateAuthorities),
    /// The OID/value pairs a client certificate should match.
    OidFilters(ExtensionOidFilters),
    /// The offer to authenticate after the handshake. A disabled value marshals to nothing, as
    /// in pion: the extension is omitted rather than sent empty.
    PostHandshakeAuth(ExtensionPostHandshakeAuth),
    /// The key-exchange shares of a TLS 1.3 handshake.
    KeyShare(ExtensionKeyShare),
    /// The connection ID a peer wants records addressed by.
    ConnectionId(ExtensionConnectionId),
    /// The extended master secret extension.
    UseExtendedMasterSecret(ExtensionUseExtendedMasterSecret),
    /// The renegotiation info extension.
    RenegotiationInfo(ExtensionRenegotiationInfo),
}

impl Extension {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        match self {
            Extension::ServerName(ext) => ext.extension_value(),
            Extension::SupportedEllipticCurves(ext) => ext.extension_value(),
            Extension::SupportedPointFormats(ext) => ext.extension_value(),
            Extension::SupportedSignatureAlgorithms(ext) => ext.extension_value(),
            Extension::UseSrtp(ext) => ext.extension_value(),
            Extension::Alpn(ext) => ext.extension_value(),
            Extension::PreSharedKey(ext) => ext.extension_value(),
            Extension::EarlyDataIndication(ext) => ext.extension_value(),
            Extension::SupportedVersions(ext) => ext.extension_value(),
            Extension::Cookie(ext) => ext.extension_value(),
            Extension::PskKeyExchangeModes(ext) => ext.extension_value(),
            Extension::CertificateAuthorities(ext) => ext.extension_value(),
            Extension::OidFilters(ext) => ext.extension_value(),
            Extension::PostHandshakeAuth(ext) => ext.extension_value(),
            Extension::KeyShare(ext) => ext.extension_value(),
            Extension::ConnectionId(ext) => ext.extension_value(),
            Extension::UseExtendedMasterSecret(ext) => ext.extension_value(),
            Extension::RenegotiationInfo(ext) => ext.extension_value(),
        }
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        // A disabled post_handshake_auth is omitted from the wire entirely, as in pion: it
        // marshals to zero bytes, not to an empty extension.
        if let Extension::PostHandshakeAuth(ext) = self
            && !ext.enabled
        {
            return 0;
        }

        let mut len = 2;

        len += match self {
            Extension::ServerName(ext) => ext.size(),
            Extension::SupportedEllipticCurves(ext) => ext.size(),
            Extension::SupportedPointFormats(ext) => ext.size(),
            Extension::SupportedSignatureAlgorithms(ext) => ext.size(),
            Extension::UseSrtp(ext) => ext.size(),
            Extension::Alpn(ext) => ext.size(),
            Extension::PreSharedKey(ext) => ext.size(),
            Extension::EarlyDataIndication(ext) => ext.size(),
            Extension::SupportedVersions(ext) => ext.size(),
            Extension::Cookie(ext) => ext.size(),
            Extension::PskKeyExchangeModes(ext) => ext.size(),
            Extension::CertificateAuthorities(ext) => ext.size(),
            Extension::OidFilters(ext) => ext.size(),
            Extension::PostHandshakeAuth(ext) => ext.size(),
            Extension::KeyShare(ext) => ext.size(),
            Extension::ConnectionId(ext) => ext.size(),
            Extension::UseExtendedMasterSecret(ext) => ext.size(),
            Extension::RenegotiationInfo(ext) => ext.size(),
        };

        len
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a field exceeds the length its wire format allows.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        // A disabled post_handshake_auth is omitted from the wire entirely, as in pion: it
        // marshals to zero bytes, not to an empty extension.
        if let Extension::PostHandshakeAuth(ext) = self
            && !ext.enabled
        {
            return Ok(());
        }

        writer.write_u16::<BigEndian>(self.extension_value() as u16)?;
        match self {
            Extension::ServerName(ext) => ext.marshal(writer),
            Extension::SupportedEllipticCurves(ext) => ext.marshal(writer),
            Extension::SupportedPointFormats(ext) => ext.marshal(writer),
            Extension::SupportedSignatureAlgorithms(ext) => ext.marshal(writer),
            Extension::UseSrtp(ext) => ext.marshal(writer),
            Extension::Alpn(ext) => ext.marshal(writer),
            Extension::PreSharedKey(ext) => ext.marshal(writer),
            Extension::EarlyDataIndication(ext) => ext.marshal(writer),
            Extension::SupportedVersions(ext) => ext.marshal(writer),
            Extension::Cookie(ext) => ext.marshal(writer),
            Extension::PskKeyExchangeModes(ext) => ext.marshal(writer),
            Extension::CertificateAuthorities(ext) => ext.marshal(writer),
            Extension::OidFilters(ext) => ext.marshal(writer),
            Extension::PostHandshakeAuth(ext) => ext.marshal(writer),
            Extension::KeyShare(ext) => ext.marshal(writer),
            Extension::ConnectionId(ext) => ext.marshal(writer),
            Extension::UseExtendedMasterSecret(ext) => ext.marshal(writer),
            Extension::RenegotiationInfo(ext) => ext.marshal(writer),
        }
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated or its contents are not a valid encoding.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let extension_value: ExtensionValue = reader.read_u16::<BigEndian>()?.into();
        match extension_value {
            ExtensionValue::ServerName => Ok(Extension::ServerName(
                ExtensionServerName::unmarshal(reader)?,
            )),
            ExtensionValue::SupportedEllipticCurves => Ok(Extension::SupportedEllipticCurves(
                ExtensionSupportedEllipticCurves::unmarshal(reader)?,
            )),
            ExtensionValue::SupportedPointFormats => Ok(Extension::SupportedPointFormats(
                ExtensionSupportedPointFormats::unmarshal(reader)?,
            )),
            ExtensionValue::SupportedSignatureAlgorithms => {
                Ok(Extension::SupportedSignatureAlgorithms(
                    ExtensionSupportedSignatureAlgorithms::unmarshal(reader)?,
                ))
            }
            ExtensionValue::UseSrtp => Ok(Extension::UseSrtp(ExtensionUseSrtp::unmarshal(reader)?)),
            ExtensionValue::Alpn => Ok(Extension::Alpn(ExtensionAlpn::unmarshal(reader)?)),
            ExtensionValue::PreSharedKey => Ok(Extension::PreSharedKey(
                ExtensionPreSharedKey::unmarshal(reader)?,
            )),
            ExtensionValue::EarlyDataIndication => Ok(Extension::EarlyDataIndication(
                ExtensionEarlyDataIndication::unmarshal(reader)?,
            )),
            ExtensionValue::SupportedVersions => Ok(Extension::SupportedVersions(
                ExtensionSupportedVersions::unmarshal(reader)?,
            )),
            ExtensionValue::Cookie => Ok(Extension::Cookie(ExtensionCookie::unmarshal(reader)?)),
            ExtensionValue::PskKeyExchangeModes => Ok(Extension::PskKeyExchangeModes(
                ExtensionPskKeyExchangeModes::unmarshal(reader)?,
            )),
            ExtensionValue::CertificateAuthorities => Ok(Extension::CertificateAuthorities(
                ExtensionCertificateAuthorities::unmarshal(reader)?,
            )),
            ExtensionValue::OidFilters => Ok(Extension::OidFilters(
                ExtensionOidFilters::unmarshal(reader)?,
            )),
            ExtensionValue::PostHandshakeAuth => Ok(Extension::PostHandshakeAuth(
                ExtensionPostHandshakeAuth::unmarshal(reader)?,
            )),
            ExtensionValue::KeyShare => {
                Ok(Extension::KeyShare(ExtensionKeyShare::unmarshal(reader)?))
            }
            ExtensionValue::ConnectionId => Ok(Extension::ConnectionId(
                ExtensionConnectionId::unmarshal(reader)?,
            )),
            ExtensionValue::UseExtendedMasterSecret => Ok(Extension::UseExtendedMasterSecret(
                ExtensionUseExtendedMasterSecret::unmarshal(reader)?,
            )),
            ExtensionValue::RenegotiationInfo => Ok(Extension::RenegotiationInfo(
                ExtensionRenegotiationInfo::unmarshal(reader)?,
            )),
            _ => Err(Error::ErrInvalidExtensionType),
        }
    }
}

/// Parses the body of a hello's extension block. Extension types this crate does not implement
/// are skipped, but a known type that does not parse rejects the whole message, as in pion.
///
/// # Errors
///
/// [`Error::ErrBufferTooSmall`] when the block ends inside an extension header or body, or the
/// error of the extension that failed to parse.
pub(crate) fn unmarshal_extensions(buffer: &[u8]) -> Result<Vec<Extension>> {
    let mut extensions = vec![];
    let mut offset = 0;
    while offset < buffer.len() {
        if offset + 4 > buffer.len() {
            return Err(Error::ErrBufferTooSmall);
        }
        let kind = ExtensionValue::from(u16::from_be_bytes([buffer[offset], buffer[offset + 1]]));
        let len = u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]) as usize;
        if offset + 4 + len > buffer.len() {
            return Err(Error::ErrBufferTooSmall);
        }
        if kind == ExtensionValue::Unsupported {
            log::warn!(
                "Unsupported Extension Type {} {}",
                buffer[offset],
                buffer[offset + 1]
            );
        } else {
            let mut reader = std::io::BufReader::new(&buffer[offset..offset + 4 + len]);
            extensions.push(Extension::unmarshal(&mut reader)?);
        }
        offset += 4 + len;
    }
    Ok(extensions)
}

/// Encodes an extension block — a `u16` byte count followed by the extensions — which is the
/// shape pion's `extension.Marshal` produces and hellos and TLS 1.3 messages carry on the wire.
///
/// # Errors
///
/// [`Error::ErrInvalidExtensionsLength`] when the block exceeds 65535 bytes, or the error of an
/// extension that failed to encode.
pub(crate) fn marshal_extensions_block<W: Write>(
    extensions: &[Extension],
    writer: &mut W,
) -> Result<()> {
    let mut buffer = vec![];
    {
        let mut extension_writer = std::io::BufWriter::<&mut Vec<u8>>::new(buffer.as_mut());
        for extension in extensions {
            extension.marshal(&mut extension_writer)?;
        }
    }
    if buffer.len() > 0xffff {
        return Err(Error::ErrInvalidExtensionsLength);
    }
    writer.write_u16::<BigEndian>(buffer.len() as u16)?;
    writer.write_all(&buffer)?;
    Ok(writer.flush()?)
}

/// Parses an extension block — a `u16` byte count followed by the extensions — the shape pion's
/// `extension.Unmarshal` accepts. An empty buffer is an empty block, not an error.
///
/// # Errors
///
/// [`Error::ErrBufferTooSmall`] when the block ends inside its length field, and
/// [`Error::ErrLengthMismatch`] when the count disagrees with the bytes present, or the error of
/// an extension that failed to parse.
pub(crate) fn unmarshal_extensions_block(buffer: &[u8]) -> Result<Vec<Extension>> {
    if buffer.is_empty() {
        return Ok(vec![]);
    }
    if buffer.len() < 2 {
        return Err(Error::ErrBufferTooSmall);
    }
    let declared_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    if buffer.len() - 2 != declared_len {
        return Err(Error::ErrLengthMismatch);
    }
    unmarshal_extensions(&buffer[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An extension block with a type this crate does not know skips it and keeps parsing, as in
    /// pion: the unknown extension is dropped, the known one survives.
    #[test]
    fn unmarshal_extensions_skips_unknown_types() -> Result<()> {
        // block: an unassigned type 0x001f with 2 body bytes, then a supported_versions one.
        let block = [
            0x00, 0x1f, 0x00, 0x02, 0x99, 0x99, // unknown, body deliberately garbage
            0x00, 0x2b, 0x00, 0x02, 0xfe, 0xfc, // supported_versions: DTLS 1.3
        ];
        let extensions = unmarshal_extensions(&block)?;
        assert_eq!(extensions.len(), 1);
        assert_eq!(
            extensions[0].extension_value(),
            ExtensionValue::SupportedVersions
        );
        Ok(())
    }

    /// A *known* extension type that fails to parse rejects the whole block — including the new
    /// DTLS 1.3 types, which become known the moment they join the `Extension` enum.
    #[test]
    fn unmarshal_extensions_rejects_malformed_known_types() -> Result<()> {
        // key_share (51) claiming a length the body cannot satisfy.
        let block = [
            0x00, 0x33, 0x00, 0x03, 0x00, 0x01, 0xff, // truncated client_shares entry
        ];
        assert_eq!(
            unmarshal_extensions(&block).unwrap_err(),
            Error::ErrInvalidKeyShareFormat
        );

        // The same block inside a hello with other extensions around it still fails as a whole.
        let block = [
            0x00, 0x2b, 0x00, 0x02, 0xfe, 0xfc, // valid supported_versions
            0x00, 0x33, 0x00, 0x01, 0x00, // key_share: one stray byte is no valid share
        ];
        assert!(unmarshal_extensions(&block).is_err());
        Ok(())
    }
}
