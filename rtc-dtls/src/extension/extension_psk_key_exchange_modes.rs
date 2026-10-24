#[cfg(test)]
mod extension_psk_key_exchange_modes_test;

use super::*;

/// A PSK key exchange mode ([RFC 8446 §4.2.9]): whether a PSK-only handshake also runs a (EC)DHE
/// exchange for forward secrecy.
///
/// A transparent `u8` newtype mirroring pion's `PskKeyExchangeMode`: any mode byte parses, so
/// values this crate does not offer still round-trip.
///
/// [RFC 8446 §4.2.9]: https://datatracker.ietf.org/html/rfc8446#section-4.2.9
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PskKeyExchangeMode(pub u8);

impl PskKeyExchangeMode {
    /// `psk_ke` (`0`): PSK-only key establishment.
    pub const PSK_KE: PskKeyExchangeMode = PskKeyExchangeMode(0);
    /// `psk_dhe_ke` (`1`): PSK with a Diffie-Hellman exchange.
    pub const PSK_DHE_KE: PskKeyExchangeMode = PskKeyExchangeMode(1);
}

/// The `psk_key_exchange_modes` extension ([RFC 8446 §4.2.9]): the key exchange modes a client
/// offers for a PSK handshake.
///
/// [RFC 8446 §4.2.9]: https://datatracker.ietf.org/html/rfc8446#section-4.2.9
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionPskKeyExchangeModes {
    /// The offered modes; must not be empty to marshal.
    pub(crate) ke_modes: Vec<PskKeyExchangeMode>,
}

impl ExtensionPskKeyExchangeModes {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::PskKeyExchangeModes
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 1 + self.ke_modes.len()
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrNoPskKeyExchangeMode`] when no mode is set, and
    /// [`Error::ErrPskKeyExchangeModesFormat`] when the list exceeds 255 bytes, as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        if self.ke_modes.is_empty() {
            return Err(Error::ErrNoPskKeyExchangeMode);
        }
        if self.ke_modes.len() > u8::MAX as usize {
            return Err(Error::ErrPskKeyExchangeModesFormat);
        }

        let mut body = Vec::with_capacity(1 + self.ke_modes.len());
        body.push(self.ke_modes.len() as u8);
        for mode in &self.ke_modes {
            body.push(mode.0);
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
    /// [`Error::ErrBufferTooSmall`] when the input is truncated,
    /// [`Error::ErrPskKeyExchangeModesFormat`] when the mode list is empty and
    /// [`Error::ErrLengthMismatch`] on trailing data, as in pion.
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
            return Err(Error::ErrPskKeyExchangeModesFormat);
        }

        let modes_len = ext_data[0] as usize;
        if ext_data.len() < 1 + modes_len {
            return Err(Error::ErrPskKeyExchangeModesFormat);
        }
        let modes = &ext_data[1..1 + modes_len];
        if modes.is_empty() {
            return Err(Error::ErrPskKeyExchangeModesFormat);
        }

        if ext_data.len() != 1 + modes_len {
            return Err(Error::ErrLengthMismatch);
        }

        Ok(ExtensionPskKeyExchangeModes {
            ke_modes: modes.iter().map(|m| PskKeyExchangeMode(*m)).collect(),
        })
    }
}
