//! The AIMD state machine: what a usage signal means for the rate.

use super::overuse::Usage;

/// What the rate controller should be doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RateControlState {
    /// Hold the current rate — used immediately after a decrease, so the effect of the backoff can
    /// be observed before changing anything again.
    #[default]
    Hold,
    /// Climb, looking for more capacity.
    Increase,
    /// Back off.
    Decrease,
}

impl RateControlState {
    /// The next state, given what the delay signal now says.
    ///
    /// Pure: no clock, no rate, no history beyond the current state. That is what makes it
    /// exhaustively testable — the whole machine is nine transitions.
    ///
    /// The asymmetry is deliberate and is the heart of AIMD: **overuse always goes straight to
    /// `Decrease`**, from any state, because congestion is urgent; but recovery goes through
    /// `Hold` first, so the rate does not resume climbing before the backoff has taken effect.
    pub fn next(self, usage: Usage) -> Self {
        match (self, usage) {
            // Congestion: back off at once, wherever we were.
            (_, Usage::Over) => Self::Decrease,

            // The queue is draining. Hold: the path is still recovering from whatever emptied it,
            // and climbing now is what makes an estimate oscillate.
            (_, Usage::Under) => Self::Hold,

            // Quiet. Climb, unless we have just decreased — then hold once, to see the result.
            (Self::Hold, Usage::Normal) => Self::Increase,
            (Self::Increase, Usage::Normal) => Self::Increase,
            (Self::Decrease, Usage::Normal) => Self::Hold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Overuse is urgent: it goes to `Decrease` from anywhere, with no intermediate state.
    #[test]
    fn overuse_always_decreases() {
        for state in [
            RateControlState::Hold,
            RateControlState::Increase,
            RateControlState::Decrease,
        ] {
            assert_eq!(
                RateControlState::Decrease,
                state.next(Usage::Over),
                "from {state:?}"
            );
        }
    }

    /// Recovery is not: after a decrease, one hold before climbing again. Without it the rate
    /// resumes climbing before the backoff has reached the far end, and oscillates.
    #[test]
    fn recovery_holds_once_before_climbing() {
        let after_backoff = RateControlState::Decrease.next(Usage::Normal);
        assert_eq!(RateControlState::Hold, after_backoff);

        assert_eq!(
            RateControlState::Increase,
            after_backoff.next(Usage::Normal),
            "and then it may climb"
        );
    }

    /// A quiet path keeps climbing, which is what finds capacity that has appeared.
    #[test]
    fn a_quiet_path_keeps_increasing() {
        let mut state = RateControlState::Increase;
        for _ in 0..10 {
            state = state.next(Usage::Normal);
        }
        assert_eq!(RateControlState::Increase, state);
    }

    /// A draining queue holds rather than climbing: something else is using the path, or the
    /// backlog is still clearing.
    #[test]
    fn a_draining_queue_holds() {
        for state in [
            RateControlState::Hold,
            RateControlState::Increase,
            RateControlState::Decrease,
        ] {
            assert_eq!(
                RateControlState::Hold,
                state.next(Usage::Under),
                "from {state:?}"
            );
        }
    }

    /// The machine is total: nine transitions, all defined, none panicking.
    #[test]
    fn every_transition_is_defined() {
        for state in [
            RateControlState::Hold,
            RateControlState::Increase,
            RateControlState::Decrease,
        ] {
            for usage in [Usage::Normal, Usage::Over, Usage::Under] {
                let _ = state.next(usage);
            }
        }
    }
}
