#[cfg(test)]
mod extension_early_data_indication_test;

use super::*;

/// The `early_data` extension ([RFC 8446 §4.2.10]).
///
/// In a ClientHello or EncryptedExtensions it is empty — the indication is the extension's
/// presence. Only a NewSessionTicket carries `max_early_data_size`, held in the private
/// `max_early_data` field.
///
/// [RFC 8446 §4.2.10]: https://datatracker.ietf.org/html/rfc8446#section-4.2.10
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionEarlyDataIndication {
    /// The maximum bytes of 0-RTT data a server permits; `None` in a ClientHello or
    /// EncryptedExtensions.
    pub(crate) max_early_data: Option<u32>,
}

impl ExtensionEarlyDataIndication {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::EarlyDataIndication
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + self.max_early_data.map_or(0, |max| max as usize)
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// Fails on a write error only; the extension body is always well-formed.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self.max_early_data {
            None => writer.write_u16::<BigEndian>(0)?, // zero length
            // new_session_ticket
            Some(max_early_data) => {
                writer.write_u16::<BigEndian>(4)?;
                writer.write_u32::<BigEndian>(max_early_data)?;
            }
        }

        Ok(writer.flush()?)
    }

    /// Decodes one of these messages from `reader`.
    ///
    /// Reads the extension length prefix and body; the [`Extension`] enum reads and dispatches
    /// the type code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrBufferTooSmall`] when the input is truncated and
    /// [`Error::ErrEarlyDataIndicationFormat`] when the body is not empty and not exactly a
    /// `max_early_data_size`, as in pion.
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
        // new_session_ticket
        if !ext_data.is_empty() {
            if ext_data.len() != 4 {
                return Err(Error::ErrEarlyDataIndicationFormat);
            }
            return Ok(ExtensionEarlyDataIndication {
                max_early_data: Some(u32::from_be_bytes([
                    ext_data[0],
                    ext_data[1],
                    ext_data[2],
                    ext_data[3],
                ])),
            });
        }

        Ok(ExtensionEarlyDataIndication {
            max_early_data: None,
        })
    }
}
