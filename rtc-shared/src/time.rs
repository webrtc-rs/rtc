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

    pub fn instant(&self, duration_since_unix_epoch: Duration) -> Instant {
        self.instant + duration_since_unix_epoch - self.duration_since_unix_epoch
    }

    pub fn duration_since_unix_epoch(&self) -> Duration {
        self.duration_since_unix_epoch
    }

    pub fn unix(&self, now: Instant) -> Duration {
        now.duration_since(self.instant)
            .add(self.duration_since_unix_epoch)
    }

    pub fn ntp(&self, now: Instant) -> u64 {
        SystemInstant::unix2ntp(self.unix(now))
    }

    pub fn unix2ntp(duration_since_unix_epoch: Duration) -> u64 {
        let u = duration_since_unix_epoch.as_nanos() as u64;

        let mut s = u / 1_000_000_000;
        s += 0x83AA7E80; //offset in seconds between unix epoch and ntp epoch
        let mut f = u % 1_000_000_000;
        f <<= 32;
        f /= 1_000_000_000;
        s <<= 32;

        s | f
    }

    pub fn ntp2unix(ntp: u64) -> Duration {
        let mut s = ntp >> 32;
        let mut f = ntp & 0xFFFFFFFF;
        f *= 1_000_000_000;
        f >>= 32;
        s -= 0x83AA7E80;
        let u = s * 1_000_000_000 + f;

        /*let duration_since_unix_epoch =*/
        Duration::new(u / 1_000_000_000, (u % 1_000_000_000) as u32)
    }
}
