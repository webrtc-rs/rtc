#[cfg(test)]
mod extension_alpn_test;

use super::*;

/// The Application-Layer Protocol Negotiation extension ([RFC 7301]): a client offers the
/// protocols it speaks, the server answers with the one it picked.
///
/// [RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionAlpn {
    /// The protocol names, most preferred first. A server's answer holds exactly one.
    pub(crate) protocols: Vec<String>,
}

impl ExtensionAlpn {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::Alpn
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2 + self.protocols.iter().map(|p| 1 + p.len()).sum::<usize>()
    }

    /// Encodes this message to `writer`.
    ///
    /// # Errors
    ///
    /// Fails on a write error, or if a protocol name is empty or longer than 255 bytes, or the
    /// list is longer than 65535 bytes.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let list_len: usize = self.protocols.iter().map(|p| 1 + p.len()).sum();
        if self.protocols.iter().any(|p| p.is_empty() || p.len() > 255) || list_len + 2 > 0xffff {
            return Err(Error::ErrAlpnInvalidFormat);
        }
        writer.write_u16::<BigEndian>(list_len as u16 + 2)?;
        writer.write_u16::<BigEndian>(list_len as u16)?;
        for protocol in &self.protocols {
            writer.write_u8(protocol.len() as u8)?;
            writer.write_all(protocol.as_bytes())?;
        }

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// # Errors
    ///
    /// Fails if `reader` is truncated, the list is empty or has an empty name, or the lengths
    /// disagree.
    pub fn unmarshal<R: Read>(reader: &mut R) -> Result<Self> {
        let extension_len = reader.read_u16::<BigEndian>()? as usize;
        let list_len = reader.read_u16::<BigEndian>()? as usize;
        if list_len == 0 {
            return Err(Error::ErrAlpnInvalidFormat);
        }
        if extension_len != list_len + 2 {
            return Err(Error::ErrLengthMismatch);
        }

        let mut list = vec![0u8; list_len];
        reader.read_exact(&mut list)?;
        let mut protocols = vec![];
        let mut rest = &list[..];
        while !rest.is_empty() {
            let len = rest[0] as usize;
            if len == 0 || rest.len() < 1 + len {
                return Err(Error::ErrAlpnInvalidFormat);
            }
            // Protocol names are opaque bytes; pion keeps them as Go strings and so does this
            // crate as far as they are UTF-8. Anything else is not a protocol name we can match.
            let name =
                std::str::from_utf8(&rest[1..1 + len]).map_err(|_| Error::ErrAlpnInvalidFormat)?;
            protocols.push(name.to_owned());
            rest = &rest[1 + len..];
        }

        Ok(ExtensionAlpn { protocols })
    }
}

/// Picks the protocol both sides speak, preferring the order of `supported` ([RFC 7301 §3.2]).
///
/// Returns `None` when either side offered nothing, which is not an error: ALPN is optional.
///
/// # Errors
///
/// [`Error::ErrAlpnNoAppProto`] when both offered protocols and none is shared.
///
/// [RFC 7301 §3.2]: https://www.rfc-editor.org/rfc/rfc7301#section-3.2
pub fn alpn_protocol_selection<'a>(
    supported: &'a [String],
    peer_supported: &[String],
) -> Result<Option<&'a str>> {
    if supported.is_empty() || peer_supported.is_empty() {
        return Ok(None);
    }
    supported
        .iter()
        .find(|s| peer_supported.contains(s))
        .map(|s| Some(s.as_str()))
        .ok_or(Error::ErrAlpnNoAppProto)
}
