/// Serializes a `SystemInstant` to an approximation of epoch time in the form
/// of an `f64` where the integer portion is seconds and the decimal portion is milliseconds.
pub mod instant_to_epoch {
    use crate::time::SystemInstant;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    /// Serializes an [`SystemInstant`] as a duration relative to the process's reference instant.
    ///
    /// [`SystemInstant`] has no absolute representation, so this encodes the offset instead. Use
    /// with `#[serde(with = "...")]`.
    ///
    /// # Errors
    ///
    /// Propagates any failure from the underlying serializer.
    pub fn serialize<S>(instant: &SystemInstant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let epoch = instant.duration_since_unix_epoch();
        let epoch_s = epoch.as_millis() as f64 / 1000.0;
        epoch_s.serialize(serializer)
    }

    /// Deserializes an [`SystemInstant`] from the relative offset written by [`serialize`].
    ///
    /// # Errors
    ///
    /// Propagates any failure from the underlying deserializer.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemInstant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let epoch_s = f64::deserialize(deserializer)?;
        let epoch_duration = Duration::from_secs_f64(epoch_s);
        Ok(SystemInstant::from_epoch(epoch_duration))
    }
}
