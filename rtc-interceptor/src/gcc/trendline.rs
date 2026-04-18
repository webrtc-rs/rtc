use std::collections::VecDeque;

/// Signal from the overuse detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OveruseSignal {
    /// Queuing delay is stable — safe to hold or increase send rate.
    Normal,
    /// Queuing delay is growing — reduce send rate.
    Overusing,
    /// Queuing delay is shrinking — network has headroom.
    Underusing,
}

/// Trendline delay filter (Chrome-style, RFC 8698 §5.4).
///
/// Maintains a sliding window of `(send_time_ms, smoothed_accumulated_delay_ms)`
/// samples and fits a linear regression to detect whether one-way queuing delay
/// is trending upward (overuse), downward (underuse), or stable.
///
/// # Algorithm summary
///
/// For each consecutive received packet pair (i-1, i):
/// ```text
/// gradient = (recv_i - recv_{i-1}) - (send_i - send_{i-1})
/// smoothed += (1 - smoothing) * (gradient - smoothed)
/// accumulated += smoothed
/// window.push_back((send_i, accumulated))
/// ```
/// A linear regression of `accumulated_delay ~ slope * send_time` over the window
/// gives the trend. `modified_trend = slope * window_len`. Compared against a
/// dynamic threshold `T_hat` (maintained via Kalman-like update) this yields the
/// three-state overuse signal.
pub(crate) struct TrendlineFilter {
    /// Sliding window: (send_time_ms, accumulated_smoothed_delay_ms).
    window: VecDeque<(f64, f64)>,
    /// Maximum window size (default 20).
    window_size: usize,
    /// Previous send time (ms) for computing inter-packet gradients.
    prev_send_ms: Option<f64>,
    /// Previous receive time (ms) for computing inter-packet gradients.
    prev_recv_ms: Option<f64>,
    /// Running sum of smoothed delay gradients.
    accumulated_delay: f64,
    /// Exponential moving average of the delay gradient.
    smoothed_delay: f64,
    /// EMA smoothing coefficient (higher = smoother/slower). Default 0.9.
    smoothing: f64,
    /// Dynamic detection threshold (ms). Bounded to [6, 600].
    threshold: f64,
}

impl Default for TrendlineFilter {
    fn default() -> Self {
        Self {
            window: VecDeque::new(),
            window_size: 20,
            prev_send_ms: None,
            prev_recv_ms: None,
            accumulated_delay: 0.0,
            smoothed_delay: 0.0,
            smoothing: 0.9,
            threshold: 12.5,
        }
    }
}

impl TrendlineFilter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed a new (send_time_ms, recv_time_ms) pair into the filter.
    ///
    /// `send_time_ms` must be monotonically increasing within a session (the
    /// baseline can be arbitrary — only differences matter for the regression).
    /// `recv_time_ms` is the arrival time in the same ms units.
    pub(crate) fn update(&mut self, send_ms: f64, recv_ms: f64) {
        if let (Some(ps), Some(pr)) = (self.prev_send_ms, self.prev_recv_ms) {
            let gradient = (recv_ms - pr) - (send_ms - ps);
            self.smoothed_delay += (1.0 - self.smoothing) * (gradient - self.smoothed_delay);
            self.accumulated_delay += self.smoothed_delay;
        }
        self.prev_send_ms = Some(send_ms);
        self.prev_recv_ms = Some(recv_ms);

        self.window.push_back((send_ms, self.accumulated_delay));
        if self.window.len() > self.window_size {
            self.window.pop_front();
        }

        // Update the dynamic threshold (simplified Kalman-like adaptation).
        let modified_trend = self.slope() * self.window.len() as f64;
        let gamma = modified_trend.abs();
        const K_UP: f64 = 0.0087;
        const K_DOWN: f64 = 0.039;
        if gamma > self.threshold {
            self.threshold += K_UP * (gamma - self.threshold);
        } else {
            self.threshold -= K_DOWN * self.threshold;
        }
        self.threshold = self.threshold.clamp(6.0, 600.0);
    }

    /// Current overuse signal based on the latest trendline slope.
    pub(crate) fn signal(&self) -> OveruseSignal {
        if self.window.len() < 2 {
            return OveruseSignal::Normal;
        }
        let modified_trend = self.slope() * self.window.len() as f64;
        if modified_trend > self.threshold {
            OveruseSignal::Overusing
        } else if modified_trend < -self.threshold {
            OveruseSignal::Underusing
        } else {
            OveruseSignal::Normal
        }
    }

    /// Ordinary least-squares slope of `accumulated_delay ~ k * send_time`.
    fn slope(&self) -> f64 {
        let n = self.window.len() as f64;
        if n < 2.0 {
            return 0.0;
        }
        let mut sx = 0.0f64;
        let mut sy = 0.0f64;
        let mut sxx = 0.0f64;
        let mut sxy = 0.0f64;
        for &(x, y) in &self.window {
            sx += x;
            sy += y;
            sxx += x * x;
            sxy += x * y;
        }
        let denom = n * sxx - sx * sx;
        if denom.abs() < 1e-10 {
            return 0.0;
        }
        (n * sxy - sx * sy) / denom
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signal_normal_constant_delay() {
        let mut f = TrendlineFilter::new();
        // Packets arrive with exactly the same one-way delay — no trend.
        let base_send = 0.0f64;
        let base_recv = 20.0f64; // constant 20 ms delay
        for i in 0..25u32 {
            let send = base_send + i as f64 * 33.0;
            let recv = base_recv + i as f64 * 33.0;
            f.update(send, recv);
        }
        assert_eq!(f.signal(), OveruseSignal::Normal);
    }

    #[test]
    fn test_signal_overuse_increasing_delay() {
        let mut f = TrendlineFilter::new();
        // Each packet adds 50 ms of extra queuing delay — unmistakable overuse.
        // delay_gradient per step = 50ms >> threshold (12.5ms).
        for i in 0..25u32 {
            let send = i as f64 * 33.0;
            let recv = i as f64 * 33.0 + i as f64 * 50.0; // cumulative +50ms/packet
            f.update(send, recv);
        }
        assert_eq!(f.signal(), OveruseSignal::Overusing);
    }

    #[test]
    fn test_signal_underuse_decreasing_delay() {
        let mut f = TrendlineFilter::new();
        // Delay decreases by 50ms per packet: gradient = -50ms >> -threshold.
        // Start with 1200ms to stay non-negative across 24 packets.
        for i in 0..25u32 {
            let send = i as f64 * 33.0;
            let recv = send + (1200.0 - i as f64 * 50.0).max(0.0);
            f.update(send, recv);
        }
        assert_eq!(f.signal(), OveruseSignal::Underusing);
    }

    #[test]
    fn test_window_size_capped() {
        let mut f = TrendlineFilter::new();
        for i in 0..50u32 {
            f.update(i as f64 * 33.0, i as f64 * 33.0 + 20.0);
        }
        assert!(f.window.len() <= f.window_size);
    }

    #[test]
    fn test_threshold_adapts() {
        let mut f = TrendlineFilter::new();
        // Feed packets with 50ms/step gradient — strong sustained overuse.
        // The dynamic threshold adapts (via k_up / k_down update rules) and must
        // remain strictly between the hard bounds [6, 600] ms.
        for i in 0..25u32 {
            let send = i as f64 * 33.0;
            let recv = send + i as f64 * 50.0;
            f.update(send, recv);
        }
        // Threshold must stay within its hard bounds — never hit the floor or ceiling.
        assert!(
            f.threshold > 6.0,
            "threshold should be above floor: {}",
            f.threshold
        );
        assert!(
            f.threshold < 600.0,
            "threshold should be below ceiling: {}",
            f.threshold
        );
        // With sustained high gradient the filter must detect overuse.
        assert_eq!(
            f.signal(),
            OveruseSignal::Overusing,
            "should be overusing with 50ms/packet delay growth"
        );
    }
}
