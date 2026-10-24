//! Ported from pion/dtls v3.1.15 `pkg/protocol/extension/certificate_auth_test.go`.
//!
//! pion generates a self-signed certificate and uses its raw DER subject as the authority; the
//! scenario here is the same, through `crate::crypto::Certificate::generate_self_signed` and
//! `x509-parser`.

use super::*;

use std::io::{BufReader, BufWriter};

fn generated_subject() -> Result<Vec<u8>> {
    let provider = crypto::default_provider().map_err(|e| Error::Other(e.to_string()))?;
    let certificate = crate::crypto::Certificate::generate_self_signed(
        vec!["webrtc.rs".to_owned()],
        provider.crypto(),
    )?;
    let der = certificate.certificate[0].as_ref();
    let (_, certificate) =
        x509_parser::parse_x509_certificate(der).map_err(|e| Error::Other(e.to_string()))?;
    Ok(certificate.tbs_certificate.subject.as_raw().to_vec())
}

fn marshal(ext: &ExtensionCertificateAuthorities) -> Result<Vec<u8>> {
    let mut raw = vec![];
    {
        let mut writer = BufWriter::<&mut Vec<u8>>::new(raw.as_mut());
        Extension::CertificateAuthorities(ext.clone()).marshal(&mut writer)?;
    }
    Ok(raw)
}

fn unmarshal(raw: &[u8]) -> Result<ExtensionCertificateAuthorities> {
    match Extension::unmarshal(&mut BufReader::new(raw))? {
        Extension::CertificateAuthorities(ext) => Ok(ext),
        _ => Err(Error::ErrInvalidExtensionType),
    }
}

/// pion's `TestCertificateAuth`.
#[test]
fn certificate_auth() -> Result<()> {
    let subject = generated_subject()?;
    let len_sub = subject.len();

    let extension = ExtensionCertificateAuthorities {
        authorities: vec![subject.clone()],
    };

    let mut expect = vec![
        0x00,
        0x2f, // extension type
        0x00,
        (len_sub + 4) as u8, // extension length
        0x00,
        (len_sub + 2) as u8, // authorities length
        0x00,
        len_sub as u8, // authority length
    ];
    expect.extend_from_slice(&subject);

    assert_eq!(marshal(&extension)?, expect);

    let new_extension = unmarshal(&expect)?;
    assert_eq!(new_extension.authorities, extension.authorities);
    Ok(())
}

/// pion's `TestCertificateAuth_Multiple`.
#[test]
fn certificate_auth_multiple() -> Result<()> {
    let subject = generated_subject()?;
    let len_sub = subject.len();

    let extension = ExtensionCertificateAuthorities {
        authorities: vec![subject.clone(), subject.clone()],
    };

    let mut expect = vec![
        0x00,
        0x2f, // extension type
        0x00,
        (len_sub * 2 + 6) as u8, // extension length
        0x00,
        (len_sub * 2 + 4) as u8, // authorities length
        0x00,
        len_sub as u8, // authority length
    ];
    expect.extend_from_slice(&subject);
    expect.extend_from_slice(&[0x00, len_sub as u8]);
    expect.extend_from_slice(&subject);

    assert_eq!(marshal(&extension)?, expect);

    let new_extension = unmarshal(&expect)?;
    assert_eq!(new_extension.authorities, extension.authorities);
    Ok(())
}

/// pion's `TestCertificateAuth_Empty`.
#[test]
fn certificate_auth_empty() -> Result<()> {
    let extension = ExtensionCertificateAuthorities {
        authorities: vec![],
    };

    assert!(marshal(&extension).is_err());

    let raw = [
        0x00, 0x2f, // extension type
        0x00, 0x02, // extension length
        0x00, 0x00, // empty subjects
    ];
    assert!(unmarshal(&raw).is_err());
    Ok(())
}
