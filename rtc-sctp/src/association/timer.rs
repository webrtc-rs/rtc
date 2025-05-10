use std::time::{Duration, Instant};

pub(crate) const ACK_INTERVAL: u64 = 200;
const MAX_INIT_RETRANS: usize = 8;
const PATH_MAX_RETRANS: usize = 5;
const NO_MAX_RETRANS: usize = usize::MAX;
const TIMER_COUNT: usize = 6;

#[derive(Debug, Copy, Clone)]
pub struct TimerConfig {
    pub max_t1_init_retrans: usize,
    pub max_t1_cookie_retrans: usize,
    pub max_t2_shutdown_retrans: usize,
    pub max_t3_rtx_retrans: usize,
    pub max_reconfig_retrans: usize,
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
}

impl Timer {
    pub(crate) const VALUES: [Self; TIMER_COUNT] = [
        Timer::T1Init,
        Timer::T1Cookie,
        Timer::T2Shutdown,
        Timer::T3RTX,
        Timer::Reconfig,
        Timer::Ack,
    ];
}

/// A table of data associated with each distinct kind of `Timer`
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct TimerTable {
    data: [Option<Instant>; TIMER_COUNT],
    retrans: [usize; TIMER_COUNT],
    max_retrans: [usize; TIMER_COUNT],
}

impl TimerTable {
    pub fn new(time_config: TimerConfig) -> Self {
        TimerTable {
            max_retrans: [
                time_config.max_t1_init_retrans,     //T1Init
                time_config.max_t1_cookie_retrans,   //T1Cookie
                time_config.max_t2_shutdown_retrans, //T2Shutdown
                time_config.max_t3_rtx_retrans,      //T3RTX
                time_config.max_reconfig_retrans,    //Reconfig
                time_config.max_ack_retrans,         //Ack
            ],
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

    pub fn start(&mut self, timer: Timer, now: Instant, interval: u64) {
        let interval = if timer == Timer::Ack {
            interval
        } else {
            calculate_next_timeout(interval, self.retrans[timer as usize])
        };

        let time = now + Duration::from_millis(interval);
        self.data[timer as usize] = Some(time);
    }

    /// Restarts the timer if the current instant is none or elapsed.
    pub fn restart_if_stale(&mut self, timer: Timer, now: Instant, interval: u64) {
        if let Some(current) = self.data[timer as usize] {
            if current >= now {
                return;
            }
        }

        self.start(timer, now, interval);
    }

    pub fn stop(&mut self, timer: Timer) {
        self.data[timer as usize] = None;
        self.retrans[timer as usize] = 0;
    }

    pub fn is_expired(&mut self, timer: Timer, after: Instant) -> (bool, bool, usize) {
        let expired = self.data[timer as usize].is_some_and(|x| x <= after);
        let mut failure = false;
        if expired {
            self.retrans[timer as usize] += 1;
            if self.retrans[timer as usize] > self.max_retrans[timer as usize] {
                failure = true;
            }
        }

        (expired, failure, self.retrans[timer as usize])
    }
}

const RTO_INITIAL: u64 = 3000; // msec
const RTO_MIN: u64 = 1000; // msec
const RTO_MAX: u64 = 60000; // msec
const RTO_ALPHA: u64 = 1;
const RTO_BETA: u64 = 2;
const RTO_BASE: u64 = 8;

/// rtoManager manages Rtx timeout values.
/// This is an implementation of RFC 4960 sec 6.3.1.
#[derive(Default, Debug)]
pub(crate) struct RtoManager {
    pub(crate) srtt: u64,
    pub(crate) rttvar: f64,
    pub(crate) rto: u64,
    pub(crate) no_update: bool,
}

impl RtoManager {
    /// newRTOManager creates a new rtoManager.
    pub(crate) fn new() -> Self {
        RtoManager {
            rto: RTO_INITIAL,
            ..Default::default()
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

        self.rto = (self.srtt + (4.0 * self.rttvar) as u64).clamp(RTO_MIN, RTO_MAX);

        self.srtt
    }

    /// get_rto simply returns the current RTO in msec.
    pub(crate) fn get_rto(&self) -> u64 {
        self.rto
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
}

fn calculate_next_timeout(rto: u64, n_rtos: usize) -> u64 {
    // RFC 4096 sec 6.3.3.  Handle T3-rtx Expiration
    //   E2)  For the destination address for which the timer expires, set RTO
    //        <- RTO * 2 ("back off the timer").  The maximum value discussed
    //        in rule C7 above (RTO.max) may be used to provide an upper bound
    //        to this doubling operation.
    if n_rtos < 31 {
        std::cmp::min(rto << n_rtos, RTO_MAX)
    } else {
        RTO_MAX
    }
}
