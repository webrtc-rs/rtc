use crate::error::Result;

/// KeyingMaterialExporter to extract keying material.
///
/// This trait sits here to avoid getting a direct dependency between
/// the dtls and srtp crates.
pub trait KeyingMaterialExporter {
    /// Derives keying material from the established session, per RFC 5705.
    ///
    /// `label` and `context` bind the derived key to a purpose — DTLS-SRTP uses the
    /// `EXTRACTOR-dtls_srtp` label to obtain SRTP master keys and salts from a completed
    /// DTLS handshake.
    ///
    /// # Errors
    ///
    /// Fails if the session has not completed its handshake, so no secret is available yet.
    fn export_keying_material(&self, label: &str, context: &[u8], length: usize)
    -> Result<Vec<u8>>;
}
