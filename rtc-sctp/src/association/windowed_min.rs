//! A sliding-window minimum, as RACK keeps the smallest recent round-trip time (pion's
//! `windowedMin`). Time is passed in by the caller, so the structure has no clock of its own.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long a sample counts when no window is given.
pub(crate) const DEFAULT_WINDOW: Duration = Duration::from_secs(30);

/// A monotonic deque of `(time, value)` that answers "smallest value in the last `window`" in
/// amortized constant time: a new sample evicts every queued sample that is not smaller, since
/// those can never be the minimum again.
#[derive(Debug, Clone)]
pub(crate) struct WindowedMin {
    window: Duration,
    deque: VecDeque<(Instant, Duration)>,
}

impl WindowedMin {
    /// A zero window means the default of 30 s.
    pub(crate) fn new(window: Duration) -> Self {
        Self {
            window: if window.is_zero() {
                DEFAULT_WINDOW
            } else {
                window
            },
            deque: VecDeque::new(),
        }
    }

    pub(crate) fn window(&self) -> Duration {
        self.window
    }

    /// Drops the samples older than `now - window`.
    fn prune(&mut self, now: Instant) {
        let Some(cutoff) = now.checked_sub(self.window) else {
            return;
        };
        while self.deque.front().is_some_and(|&(t, _)| t < cutoff) {
            self.deque.pop_front();
        }
    }

    /// Adds a sample, keeping the values non-decreasing from front to back.
    pub(crate) fn push(&mut self, now: Instant, value: Duration) {
        self.prune(now);
        while self.deque.back().is_some_and(|&(_, v)| v >= value) {
            self.deque.pop_back();
        }
        self.deque.push_back((now, value));
    }

    /// The smallest sample in the window, or zero when there is none.
    pub(crate) fn min(&mut self, now: Instant) -> Duration {
        self.prune(now);
        self.deque.front().map_or(Duration::ZERO, |&(_, v)| v)
    }

    /// Number of retained samples, for tests.
    pub(crate) fn len(&self) -> usize {
        self.deque.len()
    }
}

impl Default for WindowedMin {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn test_windowed_min_basic() {
        // pion: TestWindowedMin_Basic
        let mut window = WindowedMin::new(ms(100));
        let base = Instant::now();

        window.push(base, ms(30));
        assert_eq!(ms(30), window.min(base));

        window.push(base + ms(10), ms(20));
        assert_eq!(ms(20), window.min(base + ms(10)));

        // larger value shouldn't change min
        window.push(base + ms(20), ms(40));
        assert_eq!(ms(20), window.min(base + ms(20)));

        // decreasing again shrinks min
        window.push(base + ms(30), ms(10));
        assert_eq!(ms(10), window.min(base + ms(30)));
    }

    #[test]
    fn test_windowed_min_window_expiry() {
        // pion: TestWindowedMin_WindowExpiry
        let mut window = WindowedMin::new(ms(50));
        let base = Instant::now();

        window.push(base, ms(10)); // t=0
        window.push(base + ms(10), ms(20)); // t=10ms

        // at t=60ms, first sample is expired, m becomes 20ms
        assert_eq!(ms(20), window.min(base + ms(60)));

        // at t=200ms, all are expired -> 0
        assert_eq!(Duration::ZERO, window.min(base + ms(200)));
    }

    #[test]
    fn test_windowed_min_equal_values() {
        // pion: TestWindowedMin_EqualValues
        let mut window = WindowedMin::new(Duration::from_secs(1));
        let base = Instant::now();

        window.push(base, ms(15));
        window.push(base + ms(1), ms(15));

        assert_eq!(1, window.len());
        assert_eq!(ms(15), window.min(base + ms(2)));
    }

    #[test]
    fn test_windowed_min_default_window_30s() {
        // pion: TestWindowedMin_DefaultWindow30s. A negative duration cannot be expressed, so
        // only the zero case exists here.
        assert_eq!(
            Duration::from_secs(30),
            WindowedMin::new(Duration::ZERO).window()
        );
        assert_eq!(Duration::from_secs(30), WindowedMin::default().window());
    }

    #[test]
    fn a_sample_exactly_one_window_old_is_still_valid() {
        // pion's prune keeps entries with t >= now - window.
        let mut window = WindowedMin::new(ms(50));
        let base = Instant::now();
        window.push(base, ms(10));
        assert_eq!(ms(10), window.min(base + ms(50)));
        assert_eq!(Duration::ZERO, window.min(base + ms(51)));
    }

    /// Replays `tests/data/pion_wmin_golden.jsonl`: random push/min sequences through pion's
    /// `windowedMin` (v1.12.0). `PION_WMIN_GOLDEN=<file>` replays another file.
    #[test]
    fn matches_pion_windowed_min() {
        let path = std::env::var("PION_WMIN_GOLDEN").unwrap_or_else(|_| {
            format!(
                "{}/tests/data/pion_wmin_golden.jsonl",
                env!("CARGO_MANIFEST_DIR")
            )
        });
        let data = std::fs::read_to_string(path).unwrap();
        let base = Instant::now();
        let mut total = 0;
        for line in data.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let mut w = WindowedMin::new(Duration::from_nanos(v["window"].as_u64().unwrap()));
            let (mut out, mut lens) = (vec![], vec![]);
            for op in v["ops"].as_array().unwrap() {
                let now = base + Duration::from_nanos(op["t"].as_u64().unwrap_or(0));
                match op["k"].as_str().unwrap() {
                    "push" => w.push(now, Duration::from_nanos(op["v"].as_u64().unwrap_or(0))),
                    _ => {
                        out.push(w.min(now).as_nanos() as i64);
                        lens.push(w.len() as u64);
                    }
                }
            }
            let want = |k: &str| -> Vec<i64> {
                v[k].as_array()
                    .map(|a| a.iter().map(|x| x.as_i64().unwrap()).collect())
                    .unwrap_or_default()
            };
            assert_eq!(want("out"), out, "min diverges from pion: {line}");
            assert_eq!(
                want("lens"),
                lens.iter().map(|&l| l as i64).collect::<Vec<_>>(),
                "retained samples diverge from pion: {line}"
            );
            total += 1;
        }
        eprintln!("{total} windowed-min sequences agree with pion");
    }
}
