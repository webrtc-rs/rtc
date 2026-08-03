use std::sync::Arc;

use crate::{CryptoError, RTCCryptoProvider};

/// Constructs the built-in default provider.
///
/// Ring remains the default whenever its feature is enabled. AWS-LC-RS is selected only when it is
/// the sole built-in. With no built-in features this returns [`CryptoError::NoDefaultProvider`].
pub fn default_provider() -> Result<Arc<dyn RTCCryptoProvider>, CryptoError> {
    #[cfg(feature = "ring")]
    {
        Ok(Arc::new(crate::providers::RingProvider::new()))
    }

    #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
    {
        Ok(Arc::new(crate::providers::AwsLcRsProvider::new()))
    }

    #[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
    {
        Err(CryptoError::NoDefaultProvider)
    }
}
