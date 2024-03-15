use std::time::Duration;

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum TimerIdRefresh {
    #[default]
    Alloc,
    Perms,
}

// PeriodicTimer is a periodic timer
#[derive(Default)]
pub struct PeriodicTimer {
    pub(crate) id: TimerIdRefresh,
    pub(crate) interval: Duration,
}
