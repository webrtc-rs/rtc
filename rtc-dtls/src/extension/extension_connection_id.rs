#[cfg(test)]
mod extension_connection_id_test;

use super::*;

/// The `connection_id` extension ([RFC 9146]): an alternative to the 4-tuple for associating a
/// record with its connection, so records survive an address change.
///
/// A zero-length CID is meaningful: it tells the peer that CIDs will be sent to it but it need
/// not respond with one.
///
/// [RFC 9146]: https://tools.ietf.org/html/rfc9146
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionConnectionId {
    /// The connection ID, at most 255 bytes.
    pub(crate) cid: Vec<u8>,
}

impl ExtensionConnectionId {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::ConnectionId
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 1 + self.cid.len()
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrInvalidConnectionIdFormat`] when the CID is longer than 255 bytes, the most a
    /// 1-byte length prefix can address (pion's builder fails the same way).
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.cid.len() > u8::MAX as usize {
            return Err(Error::ErrInvalidConnectionIdFormat);
        }

        writer.write_u16::<BigEndian>(1 + self.cid.len() as u16)?;
        writer.write_u8(self.cid.len() as u8)?;
        writer.write_all(&self.cid)?;

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Reads the extension length prefix and body; the [`Extension`] enum reads and dispatches
    /// the type code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the input is truncated, [`Error::ErrInvalidConnectionIdFormat`]
    /// when the CID length prefix exceeds the body, and [`Error::ErrLengthMismatch`] on trailing
    /// data, as in pion.
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
        if ext_data.is_empty() {
            return Err(Error::ErrInvalidConnectionIdFormat);
        }
        let cid_len = ext_data[0] as usize;
        if ext_data.len() < 1 + cid_len {
            return Err(Error::ErrInvalidConnectionIdFormat);
        }
        if ext_data.len() != 1 + cid_len {
            return Err(Error::ErrLengthMismatch);
        }

        Ok(ExtensionConnectionId {
            cid: ext_data[1..1 + cid_len].to_vec(),
        })
    }
}
