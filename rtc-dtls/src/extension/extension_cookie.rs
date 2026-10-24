#[cfg(test)]
mod extension_cookie_test;

use super::*;

/// The largest cookie the extension can carry: the `opaque Cookie<1..2^16-1>` vector minus its
/// own length prefix.
const MAX_COOKIE_SIZE: usize = 0xffff - 2;

/// The `cookie` extension ([RFC 8446 §4.2.2] as adapted by [RFC 9147 §5.3]): the cookie a client
/// echoes back after a HelloRetryRequest, proving it can receive at its claimed address.
///
/// Not to be confused with DTLS 1.2's HelloVerifyRequest cookie, which travels in the hello
/// itself rather than an extension.
///
/// [RFC 8446 §4.2.2]: https://datatracker.ietf.org/html/rfc8446#section-4.2.2
/// [RFC 9147 §5.3]: https://datatracker.ietf.org/html/rfc9147#section-5.3
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionCookie {
    /// The cookie; non-empty, and no longer than 65533 bytes.
    pub(crate) cookie: Vec<u8>,
}

impl ExtensionCookie {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::Cookie
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2 + self.cookie.len()
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrCookieExtFormat`] when the cookie is empty or longer than 65533 bytes, as in
    /// pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let cookie_len = self.cookie.len();
        if cookie_len == 0 || cookie_len > MAX_COOKIE_SIZE {
            return Err(Error::ErrCookieExtFormat);
        }

        writer.write_u16::<BigEndian>(2 + cookie_len as u16)?;
        writer.write_u16::<BigEndian>(cookie_len as u16)?;
        writer.write_all(&self.cookie)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Reads the extension length prefix and body; the [`Extension`] enum reads and dispatches
    /// the type code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the input is truncated, [`Error::ErrCookieExtFormat`]
    /// when the cookie is empty or longer than 65533 bytes, and [`Error::ErrLengthMismatch`] on
    /// trailing data, as in pion.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let extension_len = reader
            .read_u16::<BigEndian>()
            .map_err(|_| Error::ErrBufferTooSmall)? as usize;
        let mut ext_data = vec![0u8; extension_len];
        reader
            .read_exact(&mut ext_data)
            .map_err(|_| Error::ErrBufferTooSmall)?;
        Self::unmarshal_body(&ext_data)
    }

    /// Parses the extension body, mirroring pion's cryptobyte logic and error choices.
    fn unmarshal_body(ext_data: &[u8]) -> Result<Self> {
        if ext_data.len() < 2 {
            return Err(Error::ErrCookieExtFormat);
        }
        let cookie_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
        if ext_data.len() < 2 + cookie_len {
            return Err(Error::ErrCookieExtFormat);
        }
        if cookie_len == 0 || cookie_len > MAX_COOKIE_SIZE {
            return Err(Error::ErrCookieExtFormat);
        }
        if ext_data.len() != 2 + cookie_len {
            return Err(Error::ErrLengthMismatch);
        }

        Ok(ExtensionCookie {
            cookie: ext_data[2..2 + cookie_len].to_vec(),
        })
    }
}
