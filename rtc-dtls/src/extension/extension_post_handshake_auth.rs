#[cfg(test)]
mod extension_post_handshake_auth_test;

use super::*;

/// The `post_handshake_auth` extension ([RFC 8446 §4.2.6]): a client willing to authenticate
/// after the handshake sends it, empty.
///
/// In pion the extension is also a switch: `Marshal` on a disabled value emits nothing at all, so
/// the extension is simply omitted from the message. The [`Extension`] enum mirrors that — a
/// disabled `post_handshake_auth` contributes no bytes and no size — while a present one encodes
/// as the four-byte empty extension.
///
/// [RFC 8446 §4.2.6]: https://datatracker.ietf.org/html/rfc8446#section-4.2.6
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionPostHandshakeAuth {
    /// Whether the client offers post-handshake authentication. Unmarshaling an extension off
    /// the wire always sets this: the extension's presence *is* the offer.
    pub(crate) enabled: bool,
}

impl ExtensionPostHandshakeAuth {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::PostHandshakeAuth
    }

    /// The encoded size of this message in bytes.
    ///
    /// Only the enabled form is ever on the wire: a disabled `post_handshake_auth` is omitted
    /// entirely, as in pion, so this is always 4 (type, zero length).
    pub fn size(&self) -> usize {
        2 + 2
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body — the zero length, because the extension
    /// carries no data; the [`Extension`] enum writes the type code, and omits a disabled
    /// extension altogether, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// Fails on a write error only; the extension body is always well-formed.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_u16::<BigEndian>(0)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Reads the extension length prefix and body; the [`Extension`] enum reads and dispatches
    /// the type code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the input is truncated, and
    /// [`Error::ErrLengthMismatch`] when the extension carries data: pion requires the two
    /// length bytes to be zero.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let extension_len = reader
            .read_u16::<BigEndian>()
            .map_err(|_| Error::ErrBufferTooSmall)?;
        if extension_len != 0 {
            return Err(Error::ErrLengthMismatch);
        }

        Ok(ExtensionPostHandshakeAuth { enabled: true })
    }
}
