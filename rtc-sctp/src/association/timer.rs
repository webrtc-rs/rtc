use std::time::{Duration, Instant};

pub(crate) const ACK_INTERVAL: u64 = 200;
const MAX_INIT_RETRANS: usize = 8;
const PATH_MAX_RETRANS: usize = 5;
const NO_MAX_RETRANS: usize = usize::MAX;
const TIMER_COUNT: usize = 8;

#[derive(Debug, Copy, Clone)]
/// Retransmission limits for the association's timers.
///
/// Each field caps how many times the corresponding timer may fire before the association is
/// abandoned. `Default` follows the RFC 9260 recommendations.
pub struct TimerConfig {
    /// How many times INIT may be retransmitted (T1-init) before the association fails.
    pub max_t1_init_retrans: usize,
    /// How many times COOKIE-ECHO may be retransmitted (T1-cookie).
    pub max_t1_cookie_retrans: usize,
    /// How many times SHUTDOWN may be retransmitted (T2-shutdown).
    pub max_t2_shutdown_retrans: usize,
    /// How many times a DATA chunk may be retransmitted on T3-rtx expiry.
    ///
    /// Defaults to unlimited, leaving reliability to the per-stream partial-reliability settings.
    pub max_t3_rtx_retrans: usize,
    /// How many times a RE-CONFIG chunk (stream reset) may be retransmitted.
    pub max_reconfig_retrans: usize,
    /// How many times a delayed SACK may be retransmitted.
    pub max_ack_retrans: usize,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            max_t1_init_retrans: MAX_INIT_RETRANS,
            max_t1_cookie_retrans: MAX_INIT_RETRANS,
            max_t2_shutdown_retrans: NO_MAX_RETRANS,
            max_t3_rtx_retrans: PATH_MAX_RETRANS,
            max_reconfig_retrans: PATH_MAX_RETRANS,
            max_ack_retrans: PATH_MAX_RETRANS,
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub(crate) enum Timer {
    T1Init = 0,
    T1Cookie = 1,
    T2Shutdown = 2,
    T3RTX = 3,
    Reconfig = 4,
    Ack = 5,
    /// RACK's reorder timer (RFC 8985): re-check suspect chunks after the reordering window.
    Rack = 6,
    /// Probe timeout (tail loss probe, RFC 8985).
    Pto = 7,
}

impl Timer {
    pub(crate) const VALUES: [Self; TIMER_COUNT] = [
        Timer::T1Init,
        Timer::T1Cookie,
        Timer::T2Shutdown,
        Timer::T3RTX,
        Timer::Reconfig,
        Timer::Ack,
        Timer::Rack,
        Timer::Pto,
    ];
}

/// A table of data associated with each distinct kind of `Timer`
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct TimerTable {
    data: [Option<Instant>; TIMER_COUNT],
    retrans: [usize; TIMER_COUNT],
    max_retrans: [usize; TIMER_COUNT],
    shutdown_interval: Option<u64>,
    reconfig_interval: Option<u64>,
    /// Upper bound for the retransmission timers' exponential backoff, in
    /// milliseconds; see [`DEFAULT_RTO_MAX`]. `Default` keeps the RFC value.
    rto_max: u64,
}

impl TimerTable {
    pub fn new(time_config: TimerConfig, rto_max: u64) -> Self {
        TimerTable {
            max_retrans: [
                time_config.max_t1_init_retrans,     //T1Init
                time_config.max_t1_cookie_retrans,   //T1Cookie
                time_config.max_t2_shutdown_retrans, //T2Shutdown
                time_config.max_t3_rtx_retrans,      //T3RTX
                time_config.max_reconfig_retrans,    //Reconfig
                time_config.max_ack_retrans,         //Ack
                usize::MAX,                          //Rack: not a retransmission timer
                usize::MAX,                          //Pto: not a retransmission timer
            ],
            rto_max: if rto_max == 0 {
                DEFAULT_RTO_MAX
            } else {
                rto_max
            },
            ..Default::default()
        }
    }

    pub fn set(&mut self, timer: Timer, time: Option<Instant>) {
        self.data[timer as usize] = time;
    }

    pub fn get(&self, timer: Timer) -> Option<Instant> {
        self.data[timer as usize]
    }

    pub fn next_timeout(&self) -> Option<Instant> {
        self.data.iter().filter_map(|&x| x).min()
    }

    fn control_interval(&mut self, timer: Timer) -> Option<&mut Option<u64>> {
        match timer {
            Timer::T2Shutdown => Some(&mut self.shutdown_interval),
            Timer::Reconfig => Some(&mut self.reconfig_interval),
            _ => None,
        }
    }

    pub fn start(&mut self, timer: Timer, now: Instant, interval: u64) {
        // T3 uses the destination's current RTO, which already includes backoff.
        // Successful DATA acknowledgments reset its error counter independently.
        let interval = if let Some(current) = self.control_interval(timer) {
            // Seed T2/RECONFIG from the current DATA RTO, then double their own
            // interval on expiry. Rearming after serialization must neither
            // compound T3 backoff nor apply this control timer's backoff twice.
            // See RFC 9260 9.2 and RFC 6525 5.1.1.
            *current.get_or_insert(interval)
        } else if matches!(timer, Timer::Ack | Timer::T3RTX) {
            interval
        } else {
            calculate_next_timeout(interval, self.retrans[timer as usize], self.rto_max)
        };

        let time = now + Duration::from_millis(interval);
        self.data[timer as usize] = Some(time);
    }

    /// Start an idle timer without hiding an unhandled expiration. A due
    /// deadline stays armed until timeout processing consumes it, unless an
    /// explicit protocol restart first clears it (for T3, acknowledgment of
    /// the earliest outstanding TSN under RFC 9260 section 6.3.2 R3).
    pub fn start_if_idle(&mut self, timer: Timer, now: Instant, interval: u64) {
        if self.data[timer as usize].is_none() {
            self.start(timer, now, interval);
        }
    }

    pub fn stop(&mut self, timer: Timer) {
        self.data[timer as usize] = None;
        self.reset_retrans(timer);
        if let Some(interval) = self.control_interval(timer) {
            *interval = None;
        }
    }

    pub fn reset_retrans(&mut self, timer: Timer) {
        self.retrans[timer as usize] = 0;
    }

    pub fn is_expired(&mut self, timer: Timer, after: Instant) -> (bool, bool, usize) {
        let expired = self.data[timer as usize].is_some_and(|x| x <= after);
        let mut failure = false;
        if expired {
            let rto_max = self.rto_max;
            if let Some(interval) = self.control_interval(timer) {
                *interval = interval.map(|previous| calculate_next_timeout(previous, 1, rto_max));
            }
        }
        if expired {
            self.retrans[timer as usize] += 1;
            if self.retrans[timer as usize] > self.max_retrans[timer as usize] {
                failure = true;
            }
        }

        (expired, failure, self.retrans[timer as usize])
    }
}

// RFC 9260 §16 recommends a one-second initial RTO.  This value is used by
// both T1-init and T1-cookie before an RTT measurement is available.
const RTO_INITIAL: u64 = 1000; // msec
const RTO_MIN: u64 = 1000; // msec
/// The default RTO ceiling (RFC 9260 §16 recommends 60 s), used when
/// [`crate::TransportConfig::with_rto_max`] leaves the value unset.
pub(crate) const DEFAULT_RTO_MAX: u64 = 60000; // msec
const RTO_ALPHA: u64 = 1;
const RTO_BETA: u64 = 2;
const RTO_BASE: u64 = 8;

/// rtoManager manages Rtx timeout values.
/// This is an implementation of RFC 9260 sec 6.3.1.
#[derive(Debug)]
pub(crate) struct RtoManager {
    pub(crate) srtt: u64,
    pub(crate) rttvar: f64,
    pub(crate) rto: u64,
    pub(crate) no_update: bool,
    /// Upper bound of the RTO in milliseconds; `new` maps 0 to
    /// [`DEFAULT_RTO_MAX`] exactly as pion's `newRTOManager` does.
    rto_max: u64,
}

impl Default for RtoManager {
    fn default() -> Self {
        RtoManager::new(DEFAULT_RTO_MAX)
    }
}

impl RtoManager {
    /// newRTOManager creates a new rtoManager. `rto_max == 0` means the
    /// RFC-recommended 60 s default.
    pub(crate) fn new(rto_max: u64) -> Self {
        RtoManager {
            srtt: 0,
            rttvar: 0.0,
            rto: RTO_INITIAL,
            no_update: false,
            rto_max: if rto_max == 0 {
                DEFAULT_RTO_MAX
            } else {
                rto_max
            },
        }
    }

    /// set_new_rtt takes a newly measured RTT then adjust the RTO in msec.
    pub(crate) fn set_new_rtt(&mut self, rtt: u64) -> u64 {
        if self.no_update {
            return self.srtt;
        }

        if self.srtt == 0 {
            // First measurement
            self.srtt = rtt;
            self.rttvar = rtt as f64 / 2.0;
        } else {
            // Subsequent rtt measurement
            self.rttvar = ((RTO_BASE - RTO_BETA) as f64 * self.rttvar
                + RTO_BETA as f64 * (self.srtt as i64 - rtt as i64).abs() as f64)
                / RTO_BASE as f64;
            self.srtt = ((RTO_BASE - RTO_ALPHA) * self.srtt + RTO_ALPHA * rtt) / RTO_BASE;
        }

        self.rto = (self.srtt + (4.0 * self.rttvar) as u64)
            .max(RTO_MIN)
            .min(self.rto_max);

        self.srtt
    }

    /// get_rto simply returns the current RTO in msec.
    pub(crate) fn get_rto(&self) -> u64 {
        self.rto
    }

    /// RFC 9260 6.3.3 E2: retain backoff until a new RTT measurement updates RTO.
    pub(crate) fn backoff(&mut self) {
        if !self.no_update {
            self.rto = self.rto.saturating_mul(2).min(self.rto_max);
        }
    }

    /// reset resets the RTO variables to the initial values.
    pub(crate) fn reset(&mut self) {
        if self.no_update {
            return;
        }

        self.srtt = 0;
        self.rttvar = 0.0;
        self.rto = RTO_INITIAL;
    }

    /// set RTO value for testing
    pub(crate) fn set_rto(&mut self, rto: u64, no_update: bool) {
        self.rto = rto;
        self.no_update = no_update;
    }

    /// The configured RTO ceiling in milliseconds (pion's `rtoManager.rtoMax`).
    pub(crate) fn rto_max(&self) -> u64 {
        self.rto_max
    }
}

fn calculate_next_timeout(rto: u64, n_rtos: usize, rto_max: u64) -> u64 {
    // RFC 4096 sec 6.3.3.  Handle T3-rtx Expiration
    //   E2)  For the destination address for which the timer expires, set RTO
    //        <- RTO * 2 ("back off the timer").  The maximum value discussed
    //        in rule C7 above (RTO.max) may be used to provide an upper bound
    //        to this doubling operation.
    if n_rtos < 31 {
        // `saturating_mul`, not `<<`: a configured rto_max near `u64::MAX`
        // would overflow the shift in debug builds before the `min` clamps.
        std::cmp::min(rto.saturating_mul(1 << n_rtos), rto_max)
    } else {
        rto_max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rto_backoff_respects_pinned_rto() {
        let mut rto = RtoManager::new(0);
        rto.set_rto(1000, true);
        rto.backoff();
        assert_eq!(1000, rto.get_rto());
        rto.set_rto(1000, false);
        rto.backoff();
        assert_eq!(2000, rto.get_rto());
        rto.set_rto(DEFAULT_RTO_MAX - 1, false);
        rto.backoff();
        assert_eq!(DEFAULT_RTO_MAX, rto.get_rto());
    }

    #[test]
    fn rto_manager_uses_rfc9260_initial_rto() {
        assert_eq!(RTO_INITIAL, 1000);
        assert_eq!(RtoManager::new(0).get_rto(), RTO_INITIAL);
    }

    #[test]
    fn t1_init_starts_at_initial_rto_before_an_rtt_is_measured() {
        let now = Instant::now();
        let mut timers = TimerTable::new(TimerConfig::default(), 0);

        timers.start(Timer::T1Init, now, RtoManager::new(0).get_rto());

        assert_eq!(timers.next_timeout(), Some(now + Duration::from_secs(1)));
    }

    #[test]
    fn control_backoff_uses_one_interval_until_stopped() {
        for timer in [Timer::T2Shutdown, Timer::Reconfig] {
            let mut timers = TimerTable::new(
                TimerConfig {
                    max_reconfig_retrans: usize::MAX,
                    ..TimerConfig::default()
                },
                0,
            );
            let mut now = Instant::now();
            // A new procedure uses the current RTO, including previous DATA
            // backoff. Later DATA RTT updates/backoffs cannot compound it.
            timers.start(timer, now, 8000);
            assert_eq!(Some(now + Duration::from_secs(8)), timers.get(timer));
            for interval in [16, 32, 60, 60] {
                now = timers.get(timer).unwrap();
                assert_eq!((true, false), {
                    let (expired, failed, _) = timers.is_expired(timer, now);
                    (expired, failed)
                });
                timers.set(timer, None);
                for data_rto in [60_000, 1000] {
                    timers.start(timer, now, data_rto);
                    assert_eq!(Some(now + Duration::from_secs(interval)), timers.get(timer));
                }
            }
            timers.stop(timer);
            timers.start(timer, now, 3000);
            assert_eq!(Some(now + Duration::from_secs(3)), timers.get(timer));
            assert_eq!((false, false, 0), timers.is_expired(timer, now));
        }
    }

    // Ported from pion/sctp v1.12.0 rtx_timer_test.go TestRTOManager. pion's
    // manager keeps float state; ours keeps an integer srtt and a float
    // rttvar, which floors the same way pion's assertions do.
    #[test]
    fn test_rto_manager() {
        // "initial values": rto == rtoInitial, srtt == 0, rttvar == 0; a zero
        // rto_max means the 60 s default, exactly as newRTOManager(0).
        let m = RtoManager::new(0);
        assert_eq!(RTO_INITIAL, m.rto);
        assert_eq!(RTO_INITIAL, m.get_rto());
        assert_eq!(0, m.srtt);
        assert_eq!(0.0, m.rttvar);
        assert_eq!(DEFAULT_RTO_MAX, m.rto_max());

        // "RTO calculation (small RTT)": five 600 ms measurements settle
        // toward the 1 s RTO.Min floor.
        let mut m = RtoManager::new(0);
        for exp in [1800, 1500, 1275, 1106, 1000] {
            m.set_new_rtt(600);
            assert_eq!(exp, m.get_rto());
        }

        // "RTO calculation (large RTT)": five 30 s measurements come down
        // from the 60 s RTO.Max cap.
        let mut m = RtoManager::new(0);
        for exp in [60000, 60000, 60000, 55312, 48984] {
            m.set_new_rtt(30000);
            assert_eq!(exp, m.get_rto());
        }

        // "calculateNextTimeout": exponential doubling capped at rto_max,
        // and the nRtos >= 31 shortcut to the cap. pion feeds 1.0/1.5 ms
        // floats; the same semantics in whole milliseconds:
        assert_eq!(calculate_next_timeout(1, 0, DEFAULT_RTO_MAX), 1);
        assert_eq!(calculate_next_timeout(1, 1, DEFAULT_RTO_MAX), 2);
        assert_eq!(calculate_next_timeout(1, 2, DEFAULT_RTO_MAX), 4);
        assert_eq!(calculate_next_timeout(1, 30, DEFAULT_RTO_MAX), 60000);
        assert_eq!(calculate_next_timeout(1, 63, DEFAULT_RTO_MAX), 60000);
        assert_eq!(calculate_next_timeout(1, 64, DEFAULT_RTO_MAX), 60000);

        // "calculateNextTimeout w/ RTOMax": a custom ceiling below both the
        // default cap and RTO.Min still wins.
        assert_eq!(calculate_next_timeout(1, 0, 2), 1);
        assert_eq!(calculate_next_timeout(2, 1, 2), 2);
        assert_eq!(calculate_next_timeout(1, 10, 2), 2);
        assert_eq!(calculate_next_timeout(1, 31, 1000), 1000);

        // "reset": back to the initial values.
        let mut m = RtoManager::new(0);
        for _ in 0..10 {
            m.set_new_rtt(200);
        }
        m.reset();
        assert_eq!(RTO_INITIAL, m.get_rto());
        assert_eq!(0, m.srtt);
        assert_eq!(0.0, m.rttvar);
    }

    // A configured rto_max below RTO.Min still caps the estimate — pion's
    // setNewRTT clamps with min(max(x, rtoMin), rtoMax), and the outer min
    // wins. (Not in pion's test file; pins the ported clamp order.)
    #[test]
    fn rto_max_below_rto_min_still_caps_the_estimate() {
        let mut m = RtoManager::new(500);
        m.set_new_rtt(600);
        assert_eq!(500, m.get_rto());
        m.set_new_rtt(30000);
        assert_eq!(500, m.get_rto());
        let mut m = RtoManager::new(2000);
        m.set_new_rtt(30000);
        assert_eq!(2000, m.get_rto());
        m.backoff();
        m.backoff();
        assert_eq!(2000, m.get_rto(), "backoff must not exceed rto_max");
    }

    // Ported from pion/sctp v1.12.0 rtx_timer_test.go TestRtxTimer. pion's
    // rtxTimer is a wall-clock goroutine timer observed through callbacks; the
    // sans-I/O TimerTable exposes the same state machine as deadlines, so each
    // pion subtest maps to: start -> read the deadline, expire -> the callback
    // fires (and doubles the next deadline), exceeding maxRetrans -> failure.
    // T1Init is the timer shaped like pion's rtxTimer (per-expiry doubling via
    // calculateNextTimeout and a retrans failure bound).
    #[test]
    fn test_rtx_timer() {
        let t0 = Instant::now();
        let path_max_retrans = 5usize; // pion's pathMaxRetrans

        // "callback interval": start(30) fires at 30, 60, 120 and 240 ms —
        // cumulative 30/90/210/450, four callbacks inside 650 ms.
        let mut timers = TimerTable::new(
            TimerConfig {
                max_t1_init_retrans: path_max_retrans,
                ..TimerConfig::default()
            },
            0,
        );
        timers.start(Timer::T1Init, t0, 30);
        let mut now = t0;
        for (i, interval) in [30, 60, 120, 240].into_iter().enumerate() {
            now += Duration::from_millis(interval);
            assert_eq!(Some(now), timers.get(Timer::T1Init));
            let (expired, failure, n_rtos) = timers.is_expired(Timer::T1Init, now);
            assert!(expired);
            assert!(!failure, "within path max retrans");
            assert_eq!(i + 1, n_rtos);
            timers.set(Timer::T1Init, None);
            timers.start(Timer::T1Init, now, 30);
        }
        // The 5th expiry is still a callback (n=5 == pathMaxRetrans) ...
        now += Duration::from_millis(480);
        let (expired, failure, n_rtos) = timers.is_expired(Timer::T1Init, now);
        assert!(expired && !failure);
        assert_eq!(5, n_rtos);
        // ... and the 6th is the failure: pion's "timer should stop after rtx
        // failure" sees 5 callbacks then onRetransmissionFailure at 630 ms
        // from start(10).
        let mut timers = TimerTable::new(
            TimerConfig {
                max_t1_init_retrans: path_max_retrans,
                ..TimerConfig::default()
            },
            0,
        );
        timers.start(Timer::T1Init, t0, 10);
        let mut now = t0;
        let mut cbs = 0;
        loop {
            let due = timers.get(Timer::T1Init).unwrap();
            now = now.max(due);
            let (expired, failure, _) = timers.is_expired(Timer::T1Init, now);
            assert!(expired);
            if failure {
                break;
            }
            cbs += 1;
            timers.set(Timer::T1Init, None);
            timers.start(Timer::T1Init, now, 10);
        }
        assert_eq!(5, cbs, "five RTO callbacks before the failure");
        // 10+20+40+80+160 = 310 ms of callbacks, the failure fires at +320.
        assert_eq!(now.duration_since(t0), Duration::from_millis(630));

        // "timer should not stop if maxRetrans is 0": pion's 0 means
        // unlimited; ours is usize::MAX. Six expiries, still no failure.
        let mut timers = TimerTable::new(
            TimerConfig {
                max_t1_init_retrans: usize::MAX,
                ..TimerConfig::default()
            },
            0,
        );
        timers.start(Timer::T1Init, t0, 10);
        let mut now = t0;
        for n in 1..=6u32 {
            now += Duration::from_millis(10 * (1 << (n - 1)));
            let (expired, failure, n_rtos) = timers.is_expired(Timer::T1Init, now);
            assert!(expired && !failure);
            assert_eq!(n as usize, n_rtos);
            timers.set(Timer::T1Init, None);
            timers.start(Timer::T1Init, now, 10);
        }

        // "stop right after start" / "start, stop then start" / "start and
        // stop in a tight loop": stopping disarms the deadline and resets the
        // backoff counter, so a restart begins from the base interval again.
        let mut timers = TimerTable::new(TimerConfig::default(), 0);
        for _ in 0..1000 {
            timers.start(Timer::T1Init, t0, 30);
            assert!(timers.get(Timer::T1Init).is_some());
            timers.stop(Timer::T1Init);
            assert_eq!(
                (false, false, 0),
                timers.is_expired(Timer::T1Init, t0 + Duration::from_secs(60))
            );
        }
        timers.start(Timer::T1Init, t0, 30);
        timers.stop(Timer::T1Init);
        timers.start(Timer::T1Init, t0, 30);
        assert_eq!(
            Some(t0 + Duration::from_millis(30)),
            timers.get(Timer::T1Init),
            "a restart after stop re-arms at the base interval"
        );

        // A running deadline that is never re-armed keeps doubling across
        // expiries ("last start wins" is pion's API guard against concurrent
        // start; the sans-I/O caller is serialized, and handle_timeout's
        // expire-then-restart is that single winner).
        let mut timers = TimerTable::new(
            TimerConfig {
                max_t1_init_retrans: usize::MAX,
                ..TimerConfig::default()
            },
            2000,
        );
        timers.start(Timer::T1Init, t0, 30);
        let mut now = t0;
        // 30, 60, 120, 240, 480, 960, 1920, then capped at rto_max = 2000.
        for interval in [30, 60, 120, 240, 480, 960, 1920, 2000, 2000] {
            now += Duration::from_millis(interval);
            assert_eq!(Some(now), timers.get(Timer::T1Init), "interval {interval}");
            let (expired, failure, _) = timers.is_expired(Timer::T1Init, now);
            assert!(expired && !failure);
            timers.set(Timer::T1Init, None);
            timers.start(Timer::T1Init, now, 30);
        }
    }
}
