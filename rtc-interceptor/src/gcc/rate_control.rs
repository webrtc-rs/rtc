//! AIMD: what the target bitrate does in each state.

use super::overuse::Usage;
use super::state::RateControlState;
use std::time::{Duration, Instant};

/// Multiplier applied to the *received* rate when backing off.
pub const DEFAULT_DECREASE_FACTOR: f64 = 0.85;

/// Multiplicative growth per second while climbing well below the last known ceiling.
pub const DEFAULT_INCREASE_FACTOR: f64 = 1.08;

/// How long to wait between changes, so each one is observed before the next.
pub const DEFAULT_RATE_CONTROL_INTERVAL: Duration = Duration::from_millis(200);

/// The AIMD controller: a usage signal and a received rate in, a target bitrate out.
///
/// # Additive versus multiplicative increase
///
/// Climbing multiplicatively is fast but overshoots, which on a path already known to be near its
/// limit means congesting it again immediately. So the controller climbs multiplicatively only
/// while it is *far* from the rate that last caused a backoff, and switches to additive — one
/// packet per round trip — as it approaches. Upstream does the same; it is the difference between
/// probing for capacity and hammering at a known ceiling.
#[derive(Debug, Clone)]
pub struct RateController {
    state: RateControlState,
    /// Current target, in bits per second.
    target: f64,
    min: f64,
    max: f64,
    decrease_factor: f64,
    increase_factor: f64,
    interval: Duration,
    /// The received rate at the last backoff, which is the ceiling to approach carefully.
    last_decrease_rate: Option<f64>,
    last_change: Option<Instant>,
}

impl RateController {
    /// A controller starting at `initial`, clamped to `min..=max`.
    ///
    /// **One clamp, from configuration** — see D3. Upstream clamps in two places with two different
    /// hard-coded ranges, and they disagree.
    pub fn new(initial: f64, min: f64, max: f64) -> Self {
        Self {
            state: RateControlState::default(),
            target: initial.clamp(min, max),
            min,
            max,
            decrease_factor: DEFAULT_DECREASE_FACTOR,
            increase_factor: DEFAULT_INCREASE_FACTOR,
            interval: DEFAULT_RATE_CONTROL_INTERVAL,
            last_decrease_rate: None,
            last_change: None,
        }
    }

    /// How hard to back off, as a fraction of the received rate.
    pub fn with_decrease_factor(mut self, decrease_factor: f64) -> Self {
        self.decrease_factor = decrease_factor;
        self
    }

    /// The current target, in bits per second.
    pub fn target(&self) -> f64 {
        self.target
    }

    /// What the controller is doing.
    pub fn state(&self) -> RateControlState {
        self.state
    }

    /// Fold in a usage signal and the rate the far end is receiving.
    ///
    /// `received` is `None` when the window holds too little to say; the controller then holds
    /// rather than guessing, because every action it could take needs a rate to compute from.
    pub fn update(&mut self, now: Instant, usage: Usage, received: Option<f64>) -> f64 {
        self.state = self.state.next(usage);

        // Each change is given time to take effect before the next. Without this the controller
        // acts several times on the same round trip's worth of evidence.
        if let Some(last) = self.last_change
            && now.saturating_duration_since(last) < self.interval
            && self.state != RateControlState::Decrease
        {
            return self.target;
        }

        match self.state {
            RateControlState::Hold => {}

            RateControlState::Decrease => {
                // Back off from what the path is *delivering*, not from what we were aiming for.
                let Some(received) = received else {
                    return self.target;
                };
                self.target = (received * self.decrease_factor).clamp(self.min, self.max);
                self.last_decrease_rate = Some(received);
                self.last_change = Some(now);
            }

            RateControlState::Increase => {
                let elapsed = self
                    .last_change
                    .map_or(self.interval, |last| now.saturating_duration_since(last));

                let near_the_ceiling = self
                    .last_decrease_rate
                    .is_some_and(|ceiling| self.target > ceiling * 0.85);

                self.target = if near_the_ceiling {
                    // Additive: one MTU per round trip, so the last known ceiling is approached
                    // rather than blown through.
                    (self.target + 12_000.0).clamp(self.min, self.max)
                } else {
                    let growth = self
                        .increase_factor
                        .powf(elapsed.as_secs_f64().min(1.0));
                    (self.target * growth).clamp(self.min, self.max)
                };
                self.last_change = Some(now);
            }
        }

        self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: f64 = 100_000.0;
    const MAX: f64 = 10_000_000.0;

    fn controller() -> RateController {
        RateController::new(1_000_000.0, MIN, MAX)
    }

    /// Overuse backs off to a fraction of what is being **received**, not of the target. On a path
    /// delivering far less than the sender is aiming for, those differ by the whole overshoot.
    #[test]
    fn overuse_backs_off_from_the_received_rate() {
        let epoch = Instant::now();
        let mut controller = RateController::new(2_000_000.0, MIN, MAX);

        let target = controller.update(epoch, Usage::Over, Some(600_000.0));

        assert!(
            (target - 510_000.0).abs() < 1.0,
            "expected 0.85 × 600 kb/s, got {target}"
        );
    }

    /// A quiet path climbs.
    #[test]
    fn a_quiet_path_increases() {
        let epoch = Instant::now();
        let mut controller = controller();

        let mut at = epoch;
        let before = controller.target();
        for _ in 0..10 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Normal, Some(1_000_000.0));
        }

        assert!(
            controller.target() > before,
            "a healthy path should be probed for more: {before} → {}",
            controller.target()
        );
    }

    /// And climbs **carefully** once near a ceiling it has already hit, rather than overshooting
    /// straight back into congestion.
    #[test]
    fn it_climbs_carefully_near_a_known_ceiling() {
        let epoch = Instant::now();
        let mut controller = controller();

        // Establish a ceiling.
        let mut at = epoch;
        controller.update(at, Usage::Over, Some(1_000_000.0));
        let after_backoff = controller.target();

        // Climb back towards it.
        let mut steps = 0;
        while controller.target() < after_backoff * 1.5 && steps < 200 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Normal, Some(1_000_000.0));
            steps += 1;
        }

        assert!(
            steps > 5,
            "approaching a known ceiling should take several steps, took {steps}"
        );
    }

    /// Without a received rate the controller holds. Guessing here is how an estimate collapses on
    /// a feedback gap.
    #[test]
    fn it_holds_when_the_received_rate_is_unknown() {
        let epoch = Instant::now();
        let mut controller = controller();
        let before = controller.target();

        let target = controller.update(epoch, Usage::Over, None);

        assert_eq!(before, target, "no rate to back off from means no change");
    }

    /// One clamp, from configuration (D3). Upstream clamps twice with two different hard-coded
    /// ranges that disagree.
    #[test]
    fn the_target_stays_within_configured_bounds() {
        let epoch = Instant::now();
        let mut controller = RateController::new(MIN, MIN, 500_000.0);

        let mut at = epoch;
        for _ in 0..500 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Normal, Some(10_000_000.0));
        }
        assert!(
            controller.target() <= 500_000.0,
            "ceiling breached: {}",
            controller.target()
        );

        for _ in 0..50 {
            at += DEFAULT_RATE_CONTROL_INTERVAL;
            controller.update(at, Usage::Over, Some(1.0));
        }
        assert!(
            controller.target() >= MIN,
            "floor breached: {}",
            controller.target()
        );
    }

    /// Changes are spaced, so the controller is not acting several times on one round trip's
    /// evidence. A decrease is exempt: congestion is urgent.
    #[test]
    fn increases_are_paced_but_a_decrease_is_not() {
        let epoch = Instant::now();
        let mut controller = controller();

        controller.update(epoch, Usage::Normal, Some(1_000_000.0));
        let after_first = controller.target();
        // Immediately again: too soon to act.
        controller.update(epoch + Duration::from_millis(1), Usage::Normal, Some(1_000_000.0));
        assert_eq!(
            after_first,
            controller.target(),
            "a second increase in the same interval must be ignored"
        );

        let before_backoff = controller.target();
        controller.update(epoch + Duration::from_millis(2), Usage::Over, Some(500_000.0));
        assert!(
            controller.target() < before_backoff,
            "a decrease must not be delayed by the pacing interval"
        );
    }
}
