#![warn(rust_2018_idioms)]
#![allow(dead_code)]

use thiserror::Error;

/// KeyingMaterialExporter to extract keying material.
///
/// This trait sits here to avoid getting a direct dependency between
/// the dtls and srtp crates.
pub trait KeyingMaterialExporter {
    fn export_keying_material(
        &self,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> std::result::Result<Vec<u8>, KeyingMaterialExporterError>;
}

/// Possible errors while exporting keying material.
///
/// These errors might have been more logically kept in the dtls
/// crate, but that would have required a direct depdency between
/// srtp and dtls.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum KeyingMaterialExporterError {
    #[error("tls handshake is in progress")]
    HandshakeInProgress,
    #[error("context is not supported for export_keying_material")]
    ContextUnsupported,
    #[error("export_keying_material can not be used with a reserved label")]
    ReservedExportKeyingMaterial,
    #[error("no cipher suite for export_keying_material")]
    CipherSuiteUnset,
    #[error("export_keying_material io: {0}")]
    Io(#[source] IoError),
    #[error("export_keying_material hash: {0}")]
    Hash(String),
    #[error("mutex poison: {0}")]
    PoisonError(String),
}

#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub std::io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<std::io::Error> for KeyingMaterialExporterError {
    fn from(e: std::io::Error) -> Self {
        KeyingMaterialExporterError::Io(IoError(e))
    }
}

impl<T> From<std::sync::PoisonError<T>> for KeyingMaterialExporterError {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        KeyingMaterialExporterError::PoisonError(e.to_string())
    }
}
