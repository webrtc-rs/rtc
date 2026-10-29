#[cfg(test)]
mod extension_key_share_test;

use super::*;

/// A named group (an IANA "TLS Group" code point) as it appears in a `key_share` entry.
///
/// A transparent `u16` newtype mirroring pion's `elliptic.Curve`: unlike
/// [`NamedCurve`](crate::curve::named_curve::NamedCurve), which collapses unknown values, it keeps
/// the raw code point so a share offered for a group this crate cannot use still round-trips.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    /// `X25519` (`0x001d`).
    pub const X25519: NamedGroup = NamedGroup(0x001d);
    /// `P-256` (`0x0017`), IANA `secp256r1`.
    pub const P256: NamedGroup = NamedGroup(0x0017);
    /// `P-384` (`0x0018`), IANA `secp384r1`.
    pub const P384: NamedGroup = NamedGroup(0x0018);

    /// Whether this crate can perform a key exchange over the group, mirroring pion's
    /// `elliptic.Curves()` membership.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::X25519 | Self::P256 | Self::P384)
    }
}

/// One `KeyShareEntry`: a group and this side's public key exchange value for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyShareEntry {
    /// The group the share belongs to.
    pub group: NamedGroup,
    /// The sender's public key exchange value for `group`.
    pub key_exchange: Vec<u8>,
}

/// The `key_share` extension ([RFC 8446 §4.2.8]), which carries the key-exchange shares of a
/// TLS 1.3 / DTLS 1.3 handshake.
///
/// Exactly one of the three contexts is used at a time, as in pion: [`client_shares`](Self::client_shares)
/// in a ClientHello (an empty vector is allowed), [`server_share`](Self::server_share) in a
/// ServerHello, [`selected_group`](Self::selected_group) in a HelloRetryRequest. A `None`
/// everywhere is marshaled as a ClientHello with an empty `client_shares` vector.
///
/// [RFC 8446 §4.2.8]: https://datatracker.ietf.org/html/rfc8446#section-4.2.8
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionKeyShare {
    /// The client's offered shares; `Some` marks the ClientHello context. The vector may be
    /// empty, meaning the client offers no shares.
    pub client_shares: Option<Vec<KeyShareEntry>>,
    /// The server's selected share; `Some` marks the ServerHello context.
    pub server_share: Option<KeyShareEntry>,
    /// The group the server asks the client to use instead; `Some` marks the HelloRetryRequest
    /// context. Only set on unmarshal when the group is one this crate implements, as in pion.
    pub selected_group: Option<NamedGroup>,
}

impl ExtensionKeyShare {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::KeyShare
    }

    /// The encoded size of this message in bytes.
    ///
    /// Mirrors the context [`marshal`](Self::marshal) would encode: HelloRetryRequest, then
    /// ServerHello, then a (possibly empty) ClientHello vector.
    pub fn size(&self) -> usize {
        let body = if self.selected_group.is_some() {
            2
        } else if let Some(share) = &self.server_share {
            4 + share.key_exchange.len()
        } else {
            2 + self.client_shares.as_ref().map_or(0, |shares| {
                shares
                    .iter()
                    .map(|e| 4 + e.key_exchange.len())
                    .sum::<usize>()
            })
        };
        2 + body
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrInvalidKeyShareFormat`] when more than one context is set, a key exchange
    /// value is empty or longer than 65535 bytes, or a length prefix would overflow; and
    /// [`Error::ErrDuplicateKeyShare`] when a ClientHello repeats a group, as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let has_client_shares = self.client_shares.is_some(); // vector MAY be empty
        let has_server_share = self.server_share.is_some();
        let has_hello_retry_request = self.selected_group.is_some();

        // There must be exactly one context.
        if has_too_many_contexts(has_client_shares, has_server_share, has_hello_retry_request) {
            return Err(Error::ErrInvalidKeyShareFormat);
        }

        if let Some(shares) = &self.client_shares {
            let mut seen_groups = vec![];
            for entry in shares {
                if seen_groups.contains(&entry.group) {
                    return Err(Error::ErrDuplicateKeyShare);
                }
                seen_groups.push(entry.group);

                let len = entry.key_exchange.len();
                if len == 0 || len > 0xffff {
                    return Err(Error::ErrInvalidKeyShareFormat);
                }
            }
        }

        if let Some(share) = &self.server_share {
            let len = share.key_exchange.len();
            if len == 0 || len > 0xffff {
                return Err(Error::ErrInvalidKeyShareFormat);
            }
        }

        let mut body = vec![];
        if let Some(group) = self.selected_group {
            // KeyShareHelloRetryRequest { NamedGroup selected_group; }
            body.extend_from_slice(&group.0.to_be_bytes());
        } else if let Some(share) = &self.server_share {
            // KeyShareServerHello { KeyShareEntry server_share; }
            add_key_share_entry(&mut body, share);
        } else {
            // KeyShareClientHello { KeyShareEntry client_shares<0..2^16-1>; }
            let mut entries = vec![];
            for entry in self.client_shares.as_deref().unwrap_or(&[]) {
                add_key_share_entry(&mut entries, entry);
            }
            let vector_len = entries.len();
            if vector_len > 0xffff {
                return Err(Error::ErrInvalidKeyShareFormat);
            }
            body.extend_from_slice(&(vector_len as u16).to_be_bytes());
            body.extend_from_slice(&entries);
        }

        if body.len() > 0xffff {
            return Err(Error::ErrInvalidKeyShareFormat);
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
    /// [`Error::ErrBufferTooSmall`] when the input is truncated, [`Error::ErrInvalidKeyShareFormat`]
    /// for any other malformed body, and [`Error::ErrDuplicateKeyShare`] when a ClientHello
    /// repeats a group, as in pion.
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
        let mut key_share = ExtensionKeyShare::default();

        if ext_data.is_empty() {
            return Err(Error::ErrInvalidKeyShareFormat);
        }

        // ClientHello: client_shares is a u16-length-prefixed vector.
        if ext_data.len() >= 2 {
            let vector_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            if vector_len == ext_data.len() - 2 {
                let mut rest = &ext_data[2..];
                let mut seen_groups = vec![];
                let mut entries = vec![];
                while !rest.is_empty() {
                    let (entry, remaining) = parse_key_share_entry(rest)?;
                    if seen_groups.contains(&entry.group) {
                        return Err(Error::ErrDuplicateKeyShare);
                    }
                    seen_groups.push(entry.group);
                    entries.push(entry);
                    rest = remaining;
                }
                // An empty vector unmarshals to no context at all, matching pion's nil slice.
                key_share.client_shares = (!entries.is_empty()).then_some(entries);

                return Ok(key_share);
            }
        }

        // HelloRetryRequest: exactly 2 bytes = selected_group.
        if ext_data.len() == 2 {
            let group = NamedGroup(u16::from_be_bytes([ext_data[0], ext_data[1]]));
            if group.is_supported() {
                key_share.selected_group = Some(group);
            }

            return Ok(key_share);
        }

        // ServerHello: exactly one KeyShareEntry and no trailing bytes.
        let (share, rest) = parse_key_share_entry(ext_data)?;
        if !rest.is_empty() {
            return Err(Error::ErrInvalidKeyShareFormat);
        }
        key_share.server_share = Some(share);

        Ok(key_share)
    }
}

/// Reads one `KeyShareEntry` from the front of `data`, returning it with the rest.
fn parse_key_share_entry(data: &[u8]) -> Result<(KeyShareEntry, &[u8])> {
    if data.len() < 2 {
        return Err(Error::ErrInvalidKeyShareFormat);
    }
    let group = NamedGroup(u16::from_be_bytes([data[0], data[1]]));
    let data = &data[2..];

    if data.len() < 2 {
        return Err(Error::ErrInvalidKeyShareFormat);
    }
    let key_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let data = &data[2..];

    if key_len == 0 || data.len() < key_len {
        return Err(Error::ErrInvalidKeyShareFormat);
    }

    Ok((
        KeyShareEntry {
            group,
            key_exchange: data[..key_len].to_vec(),
        },
        &data[key_len..],
    ))
}

/// Appends one `KeyShareEntry` to `out`.
fn add_key_share_entry(out: &mut Vec<u8>, entry: &KeyShareEntry) {
    out.extend_from_slice(&entry.group.0.to_be_bytes());
    out.extend_from_slice(&(entry.key_exchange.len() as u16).to_be_bytes());
    out.extend_from_slice(&entry.key_exchange);
}

/// Whether more than exactly one key-share context is set. Used by [`ExtensionKeyShare::marshal`],
/// and pion's `hasTooManyContexts`.
pub(crate) fn has_too_many_contexts(a: bool, b: bool, c: bool) -> bool {
    (a && b) || (a && c) || (b && c)
}
