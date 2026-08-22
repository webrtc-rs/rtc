//! The delay-gradient filter: noisy per-group measurements in, a trend out.

/// Kalman filter over the one-way delay gradient, per draft-ietf-rmcat-gcc-02 §5.3.
///
/// # What it is for
///
/// A single inter-group delay measurement is mostly noise: scheduling jitter at either end, the
/// receiver's clock resolution, and TWCC's 250 µs quantisation all move it around by more than the
/// signal does early on. The filter estimates the *trend* — is the queue growing, and how fast —
/// while adapting how much it trusts each new measurement to how noisy the measurements have been.
///
/// # Pure
///
/// No clock, no allocation, no state beyond four numbers. Every input is a parameter, which is what
/// lets upstream's table-driven vectors port directly.
#[derive(Debug, Clone, Copy)]
pub struct Kalman {
    /// Current estimate of the delay gradient, in milliseconds per group.
    estimate: f64,
    /// Estimate error variance.
    error: f64,
    /// Running estimate of measurement noise variance.
    measurement_variance: f64,
    /// How fast the process itself is believed to drift.
    process_noise: f64,
    /// Weight on each new sample when updating the noise estimate.
    ///
    /// Deliberately tiny. The residual that feeds this estimate is *signal* as well as noise, so a
    /// large weight lets a genuine trend inflate the variance, which collapses the gain, which
    /// stops the trend being tracked — the filter talks itself out of the thing it is measuring.
    /// The draft derives it from `chi = 0.01` at the frame rate, which lands around 3e-4.
    noise_gain: f64,
    /// Floor on the measurement-noise estimate, so the filter never trusts a sample completely.
    min_measurement_variance: f64,
}

impl Default for Kalman {
    fn default() -> Self {
        Self {
            estimate: 0.0,
            // A large initial error means the first few measurements move the estimate freely,
            // rather than being damped towards an arbitrary zero.
            error: 0.1,
            measurement_variance: 0.0,
            process_noise: 1e-3,
            noise_gain: 3e-4,
            min_measurement_variance: 1.0,
        }
    }
}

impl Kalman {
    /// A filter with the draft's default tuning.
    pub fn new() -> Self {
        Self::default()
    }

    /// How fast the underlying gradient is assumed to drift. Larger tracks faster and is noisier.
    pub fn with_process_noise(mut self, process_noise: f64) -> Self {
        self.process_noise = process_noise;
        self
    }

    /// The current trend estimate, in milliseconds per group.
    pub fn estimate(&self) -> f64 {
        self.estimate
    }

    /// Fold in one inter-group delay measurement and return the updated estimate.
    ///
    /// `measurement` is arrival spread minus departure spread for a pair of groups, in
    /// milliseconds.
    pub fn update(&mut self, measurement: f64) -> f64 {
        // How far this sample is from what was predicted.
        let residual = measurement - self.estimate;

        // Track the noisiness of the measurements themselves, so a jittery path is trusted less.
        // Clamped from below: with no floor, a run of identical samples drives the variance to
        // zero and the filter starts believing each new sample absolutely.
        self.measurement_variance = ((1.0 - self.noise_gain) * self.measurement_variance
            + self.noise_gain * residual * residual)
            .max(self.min_measurement_variance);

        // Predict: uncertainty grows by the process noise before the measurement is folded in.
        let predicted_error = self.error + self.process_noise;

        // The gain is how much of the residual to believe: high when the estimate is uncertain,
        // low when the measurements are noisy.
        let gain = predicted_error / (predicted_error + self.measurement_variance);

        self.estimate += gain * residual;
        self.error = (1.0 - gain) * predicted_error;

        self.estimate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path that is not queueing measures zero, and the filter must stay there rather than
    /// drifting — a filter that wanders on a quiet path invents congestion.
    #[test]
    fn a_zero_signal_keeps_a_zero_estimate() {
        let mut kalman = Kalman::new();
        for _ in 0..100 {
            kalman.update(0.0);
        }
        assert!(
            kalman.estimate().abs() < 1e-9,
            "estimate drifted to {}",
            kalman.estimate()
        );
    }

    /// A sustained gradient is tracked. Not instantly — that is the point of filtering — but it
    /// must get there, or overuse is never detected.
    #[test]
    fn a_sustained_gradient_is_tracked() {
        let mut kalman = Kalman::new();
        for _ in 0..200 {
            kalman.update(10.0);
        }
        assert!(
            (kalman.estimate() - 10.0).abs() < 1.0,
            "a steady 10 ms gradient should be tracked, got {}",
            kalman.estimate()
        );
    }

    /// Noise around zero must not be mistaken for a trend. This is the property that stops a
    /// jittery but uncongested path from being throttled.
    #[test]
    fn symmetric_noise_does_not_move_the_estimate() {
        let mut kalman = Kalman::new();
        for step in 0..400 {
            // ±8 ms alternating: far larger than any real gradient early on.
            kalman.update(if step % 2 == 0 { 8.0 } else { -8.0 });
        }
        assert!(
            kalman.estimate().abs() < 2.0,
            "alternating noise should average out, got {}",
            kalman.estimate()
        );
    }

    /// The filter is asymmetric in time, not in sign: a negative trend is tracked as readily as a
    /// positive one, or a draining queue would look like a stable one.
    #[test]
    fn a_negative_gradient_is_tracked_too() {
        let mut kalman = Kalman::new();
        for _ in 0..200 {
            kalman.update(-6.0);
        }
        assert!(
            (kalman.estimate() + 6.0).abs() < 1.0,
            "a draining queue should read negative, got {}",
            kalman.estimate()
        );
    }

    /// Higher process noise tracks a change faster. This is the knob, and it must actually do
    /// something — otherwise the tuning is decoration.
    #[test]
    fn process_noise_controls_how_fast_a_change_is_tracked() {
        let mut slow = Kalman::new().with_process_noise(1e-5);
        let mut fast = Kalman::new().with_process_noise(1e-1);

        for _ in 0..30 {
            slow.update(20.0);
            fast.update(20.0);
        }

        assert!(
            fast.estimate() > slow.estimate(),
            "more process noise should track faster: slow {}, fast {}",
            slow.estimate(),
            fast.estimate()
        );
    }
}
