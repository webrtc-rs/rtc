use std::ops::Add;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemInstant {
    instant: Instant,
    duration_since_unix_epoch: Duration,
}

impl SystemInstant {
    pub fn now() -> Self {
        Self {
            instant: Instant::now(),
            duration_since_unix_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0)),
        }
    }

    pub fn duration_since_unix_epoch(&self, now: Instant) -> Duration {
        now.duration_since(self.instant)
            .add(self.duration_since_unix_epoch)
    }

    pub fn ntp(&self, now: Instant) -> u64 {
        SystemInstant::unix2ntp(self.duration_since_unix_epoch(now).as_nanos() as u64)
    }

    pub fn instant(&self, ntp: u64) -> Instant {
        let unix = SystemInstant::ntp2unix(ntp);
        let duration_since_unix_epoch =
            Duration::new(unix / 1_000_000_000, (unix % 1_000_000_000) as u32);
        self.instant + duration_since_unix_epoch - self.duration_since_unix_epoch
    }

    fn unix2ntp(u: u64) -> u64 {
        /*let u = st
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos() as u64;*/

        let mut s = u / 1_000_000_000;
        s += 0x83AA7E80; //offset in seconds between unix epoch and ntp epoch
        let mut f = u % 1_000_000_000;
        f <<= 32;
        f /= 1_000_000_000;
        s <<= 32;

        s | f
    }

    fn ntp2unix(t: u64) -> u64 {
        let mut s = t >> 32;
        let mut f = t & 0xFFFFFFFF;
        f *= 1_000_000_000;
        f >>= 32;
        s -= 0x83AA7E80;
        /*let u =*/
        s * 1_000_000_000 + f

        /*UNIX_EPOCH
        .checked_add(Duration::new(u / 1_000_000_000, (u % 1_000_000_000) as u32))
        .unwrap_or(UNIX_EPOCH)*/
    }
}
