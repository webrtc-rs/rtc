//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/oid_filters_test.go`.

use super::*;

use std::io::{BufReader, BufWriter};

fn marshal(ext: &ExtensionOidFilters) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::OidFilters(ext.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionOidFilters> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::OidFilters(ext) => Ok(ext),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestOIDFilters`.
#[test]
fn oid_filters() -> Result<()> {
    let oid = vec![0x55, 0x04, 0x03];
    let values = vec![0xde, 0xad, 0xbe, 0xef];
    let filter = OidFilter {
        oid: oid.clone(),
        values: values.clone(),
    };
    let extension = ExtensionOidFilters {
        filters: vec![filter],
    };

    let expect = [
        0x00, 0x30, // extension type (48)
        0x00, 0x0c, // extension data length
        0x00, 0x0a, // filter list length
        0x03, // OID length
        0x55, 0x04, 0x03, // OID bytes (id-at-commonName)
        0x00, 0x04, // values length
        0xde, 0xad, 0xbe, 0xef, // values bytes
    ];

    let raw = marshal(&extension)?;
    assert_eq!(raw, expect);

    let new_extension = unmarshal(&expect)?;
    assert_eq!(new_extension.filters.len(), 1);
    assert_eq!(new_extension.filters[0].oid, oid);
    assert_eq!(new_extension.filters[0].values, values);
    Ok(())
}

/// pion's `TestOIDFilters_MultipleFilters`.
#[test]
fn oid_filters_multiple_filters() -> Result<()> {
    let oid1 = vec![0x55, 0x04];
    let values1 = vec![0xaa, 0xbb];
    let oid2 = vec![0x55, 0x05];
    let values2 = vec![0x01, 0x02, 0x03, 0x04];
    let extension = ExtensionOidFilters {
        filters: vec![
            OidFilter {
                oid: oid1.clone(),
                values: values1.clone(),
            },
            OidFilter {
                oid: oid2.clone(),
                values: values2.clone(),
            },
        ],
    };

    let expect = [
        0x00, 0x30, // extension type
        0x00, 0x12, // extension data length
        0x00, 0x10, // filter list length
        0x02, // OID length
        0x55, 0x04, // OID bytes
        0x00, 0x02, // values length
        0xaa, 0xbb, // values bytes
        0x02, // OID length
        0x55, 0x05, // OID bytes
        0x00, 0x04, // values length
        0x01, 0x02, 0x03, 0x04, // values bytes
    ];

    let raw = marshal(&extension)?;
    assert_eq!(raw, expect);

    let new_extension = unmarshal(&expect)?;
    assert_eq!(new_extension.filters.len(), 2);
    assert_eq!(new_extension.filters[0].oid, oid1);
    assert_eq!(new_extension.filters[0].values, values1);
    assert_eq!(new_extension.filters[1].oid, oid2);
    assert_eq!(new_extension.filters[1].values, values2);
    Ok(())
}

/// pion's `TestOIDFilters_DuplicateFilters`.
#[test]
fn oid_filters_duplicate_filters() -> Result<()> {
    let oid = vec![0x55, 0x04];
    let values1 = vec![0xaa, 0xbb];
    let values2 = vec![0xcc, 0xdd];
    let extension = ExtensionOidFilters {
        filters: vec![
            OidFilter {
                oid: oid.clone(),
                values: values1,
            },
            OidFilter {
                oid: oid.clone(),
                values: values2,
            },
        ],
    };

    assert_eq!(marshal(&extension).unwrap_err(), Error::ErrDuplicateOid);

    let raw = [
        0x00, 0x30, // extension type
        0x00, 0x10, // extension data length
        0x00, 0x0e, // filter list length
        0x02, // OID length
        0x55, 0x04, // OID bytes
        0x00, 0x02, // values length
        0xaa, 0xbb, // values bytes
        0x02, // OID length
        0x55, 0x04, // OID bytes
        0x00, 0x02, // values length
        0xcc, 0xdd, // values bytes
    ];

    assert_eq!(unmarshal(&raw).unwrap_err(), Error::ErrDuplicateOid);
    Ok(())
}

/// pion's `TestOIDFilters_EmptyValues`.
#[test]
fn oid_filters_empty_values() -> Result<()> {
    let oid = vec![0x55, 0x04, 0x03];
    let extension = ExtensionOidFilters {
        filters: vec![OidFilter {
            oid: oid.clone(),
            values: vec![],
        }],
    };

    let expect = [
        0x00, 0x30, // extension type
        0x00, 0x08, // extension data length
        0x00, 0x06, // filter list length
        0x03, // OID length
        0x55, 0x04, 0x03, // OID bytes
        0x00, 0x00, // values length (empty)
    ];

    let raw = marshal(&extension)?;
    assert_eq!(raw, expect);

    let new_extension = unmarshal(&expect)?;
    assert_eq!(new_extension.filters.len(), 1);
    assert_eq!(new_extension.filters[0].oid, oid);
    assert!(new_extension.filters[0].values.is_empty());
    Ok(())
}

/// pion's `TestOIDFilters_EmptyFilterList`.
#[test]
fn oid_filters_empty_filter_list() -> Result<()> {
    let extension = ExtensionOidFilters { filters: vec![] };

    let expect = [
        0x00, 0x30, // extension type
        0x00, 0x02, // extension data length
        0x00, 0x00, // filter list length (empty)
    ];

    let raw = marshal(&extension)?;
    assert_eq!(raw, expect);

    let new_extension = unmarshal(&expect)?;
    assert!(new_extension.filters.is_empty());
    Ok(())
}

/// pion's `TestOIDFilters_EmptyOID`.
#[test]
fn oid_filters_empty_oid() -> Result<()> {
    let raw = [
        0x00, 0x30, // extension type
        0x00, 0x04, // extension data length
        0x00, 0x02, // filter list length
        0x00, // OID length = 0 (invalid)
        0x00, // start of values length
    ];
    assert_eq!(unmarshal(&raw).unwrap_err(), Error::ErrOidFiltersFormat);
    Ok(())
}

/// pion's `TestOIDFilters_MarshalEmptyOID`.
#[test]
fn oid_filters_marshal_empty_oid() -> Result<()> {
    let extension = ExtensionOidFilters {
        filters: vec![OidFilter {
            oid: vec![],
            values: vec![0x01],
        }],
    };
    assert_eq!(marshal(&extension).unwrap_err(), Error::ErrEmptyOidFilter);
    Ok(())
}
