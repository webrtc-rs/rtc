#[cfg(test)]
mod extension_pre_shared_key_test;

use super::*;

/// A PSK identity offered by a client in the `pre_shared_key` extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskIdentity {
    /// The opaque ticket the client wants to resume.
    pub identity: Vec<u8>,
    /// The ticket age the client observed, obfuscated with the ticket's `ticket_age_add`.
    pub obfuscated_ticket_age: u32,
}

/// The binder value associated with one PSK identity: an HMAC over the handshake so far.
pub type PskBinderEntry = Vec<u8>;

/// The minimum binder size, the width of a finished MAC (RFC 8446 §4.2.11.2).
const MIN_PSK_BINDER_SIZE: usize = 32;

/// The `pre_shared_key` extension ([RFC 8446 §4.2.11]).
///
/// Only the fields of one context are populated at a time, as in pion: `identities` and
/// `binders` in a ClientHello, `selected_identity` in a ServerHello. Marshaling with an empty
/// identity or binder list produces the ServerHello form.
///
/// [RFC 8446 §4.2.11]: https://datatracker.ietf.org/html/rfc8446#section-4.2.11
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionPreSharedKey {
    /// ClientHello only - offered PSK identities.
    pub(crate) identities: Vec<PskIdentity>,
    /// ClientHello only - binder values associated with a PSK identity.
    pub(crate) binders: Vec<PskBinderEntry>,
    /// ServerHello only - index of selected identity.
    pub(crate) selected_identity: u16,
}

impl ExtensionPreSharedKey {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::PreSharedKey
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        if self.identities.is_empty() || self.binders.is_empty() {
            // ServerHello
            2 + 2
        } else {
            2 + 2
                + self
                    .identities
                    .iter()
                    .map(|i| 2 + i.identity.len() + 4)
                    .sum::<usize>()
                + 2
                + self.binders.iter().map(|b| 1 + b.len()).sum::<usize>()
        }
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrPreSharedKeyFormat`] when an identity is empty, a binder is shorter than 32
    /// bytes, or a length prefix would overflow, as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut body = vec![];

        // ServerHello
        if self.identities.is_empty() || self.binders.is_empty() {
            body.extend_from_slice(&self.selected_identity.to_be_bytes());
            writer.write_u16::<BigEndian>(body.len() as u16)?;
            writer.write_all(&body)?;

            return Ok(writer.flush()?);
        }

        // ClientHello
        let mut identities = vec![];
        for identity in &self.identities {
            if identity.identity.is_empty() || identity.identity.len() > 0xffff {
                return Err(Error::ErrPreSharedKeyFormat);
            }
            identities.extend_from_slice(&(identity.identity.len() as u16).to_be_bytes());
            identities.extend_from_slice(&identity.identity);
            identities.extend_from_slice(&identity.obfuscated_ticket_age.to_be_bytes());
        }
        if identities.len() > 0xffff {
            return Err(Error::ErrPreSharedKeyFormat);
        }

        let mut binders = vec![];
        for binder in &self.binders {
            if binder.len() < MIN_PSK_BINDER_SIZE || binder.len() > u8::MAX as usize {
                return Err(Error::ErrPreSharedKeyFormat);
            }
            binders.push(binder.len() as u8);
            binders.extend_from_slice(binder);
        }
        if binders.len() > 0xffff {
            return Err(Error::ErrPreSharedKeyFormat);
        }

        body.extend_from_slice(&(identities.len() as u16).to_be_bytes());
        body.extend_from_slice(&identities);
        body.extend_from_slice(&(binders.len() as u16).to_be_bytes());
        body.extend_from_slice(&binders);

        if body.len() > 0xffff {
            return Err(Error::ErrPreSharedKeyFormat);
        }
        writer.write_u16::<BigEndian>(body.len() as u16)?;
        writer.write_all(&body)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Reads the extension length prefix and body; the [`Extension`] enum reads and dispatches
    /// the type code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the input is truncated, [`Error::ErrPreSharedKeyFormat`]
    /// for any other malformed body (including a binder count that does not match the identity
    /// count) and [`Error::ErrLengthMismatch`] on trailing data, as in pion.
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
        let mut extension = ExtensionPreSharedKey::default();

        // ServerHello
        if ext_data.len() == 2 {
            extension.selected_identity = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            return Ok(extension);
        }

        // ClientHello
        let (mut identities, rest) =
            read_length_prefixed_u16(ext_data).map_err(|_| Error::ErrPreSharedKeyFormat)?;
        if identities.is_empty() {
            return Err(Error::ErrPreSharedKeyFormat);
        }

        while !identities.is_empty() {
            let (identity, identity_rest) =
                read_length_prefixed_u16(identities).map_err(|_| Error::ErrPreSharedKeyFormat)?;
            if identity.is_empty() || identity_rest.len() < 4 {
                return Err(Error::ErrPreSharedKeyFormat);
            }
            let obfuscated_ticket_age = u32::from_be_bytes([
                identity_rest[0],
                identity_rest[1],
                identity_rest[2],
                identity_rest[3],
            ]);
            extension.identities.push(PskIdentity {
                identity: identity.to_vec(),
                obfuscated_ticket_age,
            });
            identities = &identity_rest[4..];
        }

        let (mut binders, rest) =
            read_length_prefixed_u16(rest).map_err(|_| Error::ErrPreSharedKeyFormat)?;
        if binders.is_empty() {
            return Err(Error::ErrPreSharedKeyFormat);
        }

        while !binders.is_empty() {
            let binder_len = binders[0] as usize;
            if binders.len() < 1 + binder_len || binder_len < MIN_PSK_BINDER_SIZE {
                return Err(Error::ErrPreSharedKeyFormat);
            }
            extension.binders.push(binders[1..1 + binder_len].to_vec());
            binders = &binders[1 + binder_len..];
        }

        if !rest.is_empty() {
            return Err(Error::ErrLengthMismatch);
        }

        // Ensure there is one binder value per identity in list
        if extension.binders.len() != extension.identities.len() {
            return Err(Error::ErrPreSharedKeyFormat);
        }

        Ok(extension)
    }
}

/// Reads a `u16`-length-prefixed slice from the front of `data`, returning it with the rest.
fn read_length_prefixed_u16(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < 2 {
        return Err(Error::ErrBufferTooSmall);
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let data = &data[2..];
    if data.len() < len {
        return Err(Error::ErrBufferTooSmall);
    }
    Ok((&data[..len], &data[len..]))
}
