#[cfg(test)]
mod extension_oid_filters_test;

use super::*;

/// One `OIDFilter`: an X.509 extension OID and the value(s) the client's certificate must carry
/// for it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct OidFilter {
    /// The DER-encoded object identifier; must not be empty.
    pub(crate) oid: Vec<u8>,
    /// The DER-encoded value; may be empty, meaning any value matches.
    pub(crate) values: Vec<u8>,
}

/// The `oid_filters` extension ([RFC 8446 §4.2.5]): the OID/value pairs a server would like the
/// client's certificate to match.
///
/// [RFC 8446 §4.2.5]: https://datatracker.ietf.org/html/rfc8446#section-4.2.5
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ExtensionOidFilters {
    /// The filters; each OID may appear at most once.
    pub(crate) filters: Vec<OidFilter>,
}

impl ExtensionOidFilters {
    /// The extension type this value is carried under.
    pub fn extension_value(&self) -> ExtensionValue {
        ExtensionValue::OidFilters
    }

    /// The encoded size of this message in bytes.
    pub fn size(&self) -> usize {
        2 + 2
            + self
                .filters
                .iter()
                .map(|f| 1 + f.oid.len() + 2 + f.values.len())
                .sum::<usize>()
    }

    /// Encodes this message to `writer`.
    ///
    /// Writes only the extension length prefix and body; the [`Extension`] enum writes the type
    /// code, following this crate's extension-module layout.
    ///
    /// # Errors
    ///
    /// [`Error::ErrEmptyOidFilter`] when a filter carries no OID, [`Error::ErrDuplicateOid`] when
    /// an OID repeats, and [`Error::ErrOidFiltersFormat`] when a length prefix would overflow,
    /// as in pion.
    pub fn marshal<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut filters = vec![];
        let mut seen = vec![];
        for filter in &self.filters {
            if filter.oid.is_empty() || filter.oid.len() > u8::MAX as usize {
                return Err(Error::ErrEmptyOidFilter);
            }
            if seen.contains(&filter.oid) {
                return Err(Error::ErrDuplicateOid);
            }
            seen.push(filter.oid.clone());
            filters.push(filter.oid.len() as u8);
            filters.extend_from_slice(&filter.oid);
            if filter.values.len() > 0xffff {
                return Err(Error::ErrOidFiltersFormat);
            }
            filters.extend_from_slice(&(filter.values.len() as u16).to_be_bytes());
            filters.extend_from_slice(&filter.values);
        }
        if filters.len() > 0xffff {
            return Err(Error::ErrOidFiltersFormat);
        }

        let mut body = Vec::with_capacity(2 + filters.len());
        body.extend_from_slice(&(filters.len() as u16).to_be_bytes());
        body.extend_from_slice(&filters);
        if body.len() > 0xffff {
            return Err(Error::ErrOidFiltersFormat);
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
    /// [`Error::ErrBufferTooSmall`] when the input is truncated, [`Error::ErrLengthMismatch`]
    /// when the filter-list length disagrees with the body, [`Error::ErrOidFiltersFormat`] for a
    /// malformed filter and [`Error::ErrDuplicateOid`] when an OID repeats, as in pion.
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
        // Both a filter list that does not decode and trailing data after it are length
        // mismatches in pion.
        if ext_data.len() < 2 {
            return Err(Error::ErrLengthMismatch);
        }
        let filter_list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
        if ext_data.len() != 2 + filter_list_len {
            return Err(Error::ErrLengthMismatch);
        }
        let mut rest = &ext_data[2..];

        let mut filters = vec![];
        let mut seen = vec![];
        while !rest.is_empty() {
            let oid_len = rest[0] as usize;
            rest = &rest[1..];
            if rest.len() < oid_len || oid_len == 0 {
                return Err(Error::ErrOidFiltersFormat);
            }
            let oid = rest[..oid_len].to_vec();
            rest = &rest[oid_len..];

            if seen.contains(&oid) {
                return Err(Error::ErrDuplicateOid);
            }
            seen.push(oid.clone());

            if rest.len() < 2 {
                return Err(Error::ErrOidFiltersFormat);
            }
            let values_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            rest = &rest[2..];
            if rest.len() < values_len {
                return Err(Error::ErrOidFiltersFormat);
            }
            let values = rest[..values_len].to_vec();
            rest = &rest[values_len..];

            filters.push(OidFilter { oid, values });
        }

        Ok(ExtensionOidFilters { filters })
    }
}
