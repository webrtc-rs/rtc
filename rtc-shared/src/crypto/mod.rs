use crate::error::Result;

/// KeyingMaterialExporter to extract keying material.
///
/// This trait sits here to avoid getting a direct dependency between
/// the dtls and srtp crates.
pub trait KeyingMaterialExporter {
    fn export_keying_material(&self, label: &str, context: &[u8], length: usize)
    -> Result<Vec<u8>>;
}
