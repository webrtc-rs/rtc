//! RFC 6762 §10 mDNS record cache.
//!
//! Port of pion/mdns v2.2.2 `cache.go`: TTLs with a 75-minute clamp,
//! goodbye records (§10.1), the cache-flush bit with its one-second grace
//! (§10.2), the 80/85/90/95 % refresh thresholds of §5.2, and a hard cap of
//! 4096 entries evicting the record closest to expiry.
//!
//! The cache is a Sans-I/O data structure: it never reads a clock and never
//! draws randomness. Every method that needs the current time takes an
//! `Instant` argument, and the per-entry refresh jitter — a random 0–2 %
//! addition to the next threshold in pion — is passed in by the caller (as a
//! `jitter: f64` argument to `Cache::insert` and
//! `Cache::take_refresh_candidates`), so tests are fully deterministic.
//!
//! `Cache` and `CacheKey` operate on the crate's wire types, which are
//! crate-private for now, so both are `pub(crate)` — the later client/server
//! work inside this crate drives them; the tunables below are public. pion
//! guards the same structure with an RWMutex because its conn runs on
//! goroutines; a sans-I/O cache owned by one state machine needs no locks.

#[cfg(test)]
mod cache_test;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::message::resource::a::AResource;
use crate::message::resource::aaaa::AaaaResource;
use crate::message::resource::ptr::PtrResource;
use crate::message::resource::srv::SrvResource;
use crate::message::resource::txt::TxtResource;
use crate::message::resource::{Resource, ResourceBody, ResourceHeader};
use crate::message::{DnsClass, DnsType};

/// The cache-flush bit in the rrclass field of a resource record
/// (RFC 6762 §10.2).
pub const RR_CLASS_CACHE_FLUSH: u16 = 1 << 15;

/// The time-to-live for goodbye packets (RFC 6762 §10.1).
///
/// Records with TTL=0 are retained for one second before removal.
pub const GOODBYE_TTL: Duration = Duration::from_secs(1);

/// The grace period before flushing stale records after receiving a
/// cache-flush response (RFC 6762 §10.2).
pub const CACHE_FLUSH_DELAY: Duration = Duration::from_secs(1);

/// Caps the lifetime of cached records. RFC 6762 §10 recommends TTLs of 75
/// minutes or less; clamping protects against hostile or misconfigured
/// responders advertising near-immortal records.
pub const MAX_RECORD_TTL: Duration = Duration::from_secs(75 * 60);

/// Caps the total number of cached records so that a busy or hostile network
/// cannot grow the cache without bound. When full, the entry closest to
/// expiry is evicted to make room.
pub const MAX_CACHE_ENTRIES: usize = 4096;

/// The maximum random jitter added to each refresh threshold, as a fraction
/// of the original TTL (RFC 6762 §5.2).
pub const MAX_REFRESH_JITTER: f64 = 0.02;

/// The fractions of the original TTL at which refresh queries are sent
/// (RFC 6762 §5.2): 80 %, 85 %, 90 %, 95 %.
pub const REFRESH_THRESHOLDS: [f64; 4] = [0.80, 0.85, 0.90, 0.95];

/// Identifies a set of records by lowercased name, type, and class (with the
/// cache-flush bit masked out).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    /// The record owner name, lowercased for case-insensitive matching.
    pub(crate) name: String,
    /// The record type.
    pub(crate) rr_type: DnsType,
    /// The record class with the cache-flush bit masked out.
    pub(crate) rr_class: DnsClass,
}

impl CacheKey {
    /// Builds a cache key from a resource header.
    ///
    /// The name is lowercased for case-insensitive matching and the
    /// cache-flush bit is masked out of the class.
    pub(crate) fn from_header(header: &ResourceHeader) -> Self {
        CacheKey {
            name: header.name.to_string().to_lowercase(),
            rr_type: header.typ,
            rr_class: DnsClass(header.class.0 & !RR_CLASS_CACHE_FLUSH),
        }
    }

    /// Builds a cache key from a lookup name (any case), a type and a class.
    pub(crate) fn from_lookup(name: &str, rr_type: DnsType, rr_class: DnsClass) -> Self {
        CacheKey {
            name: name.to_lowercase(),
            rr_type,
            rr_class: DnsClass(rr_class.0 & !RR_CLASS_CACHE_FLUSH),
        }
    }
}

/// One cached resource record with its timing metadata.
#[derive(Clone, Debug)]
struct CacheEntry {
    resource: Resource,
    created_at: Instant,
    expires_at: Instant,
    original_ttl: Duration,
    refresh_jitter: f64,
    refreshes_sent: u8,
}

/// An mDNS record cache (RFC 6762 §10).
///
/// Records are keyed by (lowercased name, type, class with the cache-flush
/// bit masked); several records with different rdata may live under one key.
/// All time-dependent behaviour is driven by the `Instant` arguments the
/// caller passes in — the cache never reads a clock itself.
#[derive(Debug, Default)]
pub(crate) struct Cache {
    entries: HashMap<CacheKey, Vec<CacheEntry>>,
    size: usize,
}

impl Cache {
    /// Creates an empty cache.
    pub(crate) fn new() -> Self {
        Cache {
            entries: HashMap::new(),
            size: 0,
        }
    }

    /// Adds or updates a record in the cache.
    ///
    /// Handles goodbye packets (TTL=0, RFC 6762 §10.1), the cache-flush bit
    /// (§10.2), and normal insert/update operations. `jitter` is the random
    /// 0–2 % addition applied to the entry's next refresh threshold; the
    /// caller supplies it so the crate stays free of `rand`.
    pub(crate) fn insert(&mut self, mut resource: Resource, received_at: Instant, jitter: f64) {
        let has_cache_flush = resource.header.class.0 & RR_CLASS_CACHE_FLUSH != 0;
        resource.header.class = DnsClass(resource.header.class.0 & !RR_CLASS_CACHE_FLUSH);

        let key = CacheKey::from_header(&resource.header);

        if resource.header.ttl == 0 {
            self.insert_goodbye(key, resource, received_at);
            return;
        }

        if has_cache_flush {
            self.apply_cache_flush(&key, received_at);
        }

        self.insert_or_update(key, resource, received_at, jitter);
    }

    /// Handles a record with TTL=0 (RFC 6762 §10.1).
    ///
    /// If a matching record exists, its expiry is set to now+1s. Otherwise a
    /// new entry is created with a 1s TTL. Goodbye entries keep
    /// `original_ttl` zero so they are never refresh candidates.
    fn insert_goodbye(&mut self, key: CacheKey, mut resource: Resource, received_at: Instant) {
        let entries = self.entries.entry(key.clone()).or_default();
        for entry in entries.iter_mut() {
            if resource_data_equal(&entry.resource, &resource) {
                entry.expires_at = received_at + GOODBYE_TTL;
                entry.original_ttl = Duration::ZERO;
                return;
            }
        }

        // Unknown record: insert with a 1s TTL so that late listeners see
        // the goodbye briefly before it expires.
        resource.header.ttl = 1;
        self.append_entry(
            key,
            CacheEntry {
                resource,
                created_at: received_at,
                expires_at: received_at + GOODBYE_TTL,
                original_ttl: Duration::ZERO,
                refresh_jitter: 0.0,
                refreshes_sent: 0,
            },
        );
    }

    /// Marks old entries for the same key as expiring in 1s (RFC 6762 §10.2).
    ///
    /// Entries created within the last second are preserved.
    fn apply_cache_flush(&mut self, key: &CacheKey, received_at: Instant) {
        // `Instant` subtraction panics on underflow; no entry can predate an
        // instant that is not even a second past the clock's origin.
        let Some(deadline) = received_at.checked_sub(CACHE_FLUSH_DELAY) else {
            return;
        };

        if let Some(entries) = self.entries.get_mut(key) {
            for entry in entries.iter_mut() {
                if entry.created_at < deadline {
                    entry.expires_at = received_at + CACHE_FLUSH_DELAY;
                }
            }
        }
    }

    /// Adds a new record or updates the TTL of an existing record with the
    /// same rdata. TTLs are clamped to [`MAX_RECORD_TTL`].
    fn insert_or_update(
        &mut self,
        key: CacheKey,
        resource: Resource,
        received_at: Instant,
        jitter: f64,
    ) {
        let ttl = std::cmp::min(
            Duration::from_secs(resource.header.ttl as u64),
            MAX_RECORD_TTL,
        );

        let entries = self.entries.entry(key.clone()).or_default();
        for entry in entries.iter_mut() {
            if resource_data_equal(&entry.resource, &resource) {
                entry.resource.header.ttl = resource.header.ttl;
                entry.created_at = received_at;
                entry.expires_at = received_at + ttl;
                entry.original_ttl = ttl;
                entry.refresh_jitter = jitter;
                entry.refreshes_sent = 0;
                return;
            }
        }

        self.append_entry(
            key,
            CacheEntry {
                resource,
                created_at: received_at,
                expires_at: received_at + ttl,
                original_ttl: ttl,
                refresh_jitter: jitter,
                refreshes_sent: 0,
            },
        );
    }

    /// Adds a new entry under `key`, evicting the entry closest to expiry
    /// when the cache is at capacity.
    fn append_entry(&mut self, key: CacheKey, entry: CacheEntry) {
        if self.size >= MAX_CACHE_ENTRIES {
            self.evict_soonest_expiring();
        }

        self.entries.entry(key).or_default().push(entry);
        self.size += 1;
    }

    /// Removes the entry with the earliest expiry.
    fn evict_soonest_expiring(&mut self) {
        let mut victim: Option<(CacheKey, usize, Instant)> = None;

        for (key, entries) in self.entries.iter() {
            for (idx, entry) in entries.iter().enumerate() {
                let sooner = match &victim {
                    Some((_, _, expiry)) => entry.expires_at < *expiry,
                    None => true,
                };
                if sooner {
                    victim = Some((key.clone(), idx, entry.expires_at));
                }
            }
        }

        let Some((victim_key, victim_idx, _)) = victim else {
            return;
        };

        if let Some(entries) = self.entries.get_mut(&victim_key) {
            entries.remove(victim_idx);
            if entries.is_empty() {
                self.entries.remove(&victim_key);
            }
        }

        self.size -= 1;
    }

    /// Returns non-expired records matching the name, type, and class at
    /// `now`.
    ///
    /// The name match is case-insensitive. Each returned record has its TTL
    /// set to the whole seconds remaining before expiry.
    pub(crate) fn lookup(
        &self,
        name: &str,
        rr_type: DnsType,
        rr_class: DnsClass,
        now: Instant,
    ) -> Vec<Resource> {
        let key = CacheKey::from_lookup(name, rr_type, rr_class);

        let mut results = Vec::new();
        if let Some(entries) = self.entries.get(&key) {
            for entry in entries {
                if now >= entry.expires_at {
                    continue;
                }

                let mut res = entry.resource.clone();
                let remaining = entry.expires_at - now;
                res.header.ttl = remaining.as_secs() as u32;
                results.push(res);
            }
        }

        results
    }

    /// Removes all entries that have expired at `now`.
    pub(crate) fn sweep(&mut self, now: Instant) {
        let mut size = 0;
        self.entries.retain(|_, entries| {
            entries.retain(|entry| now < entry.expires_at);
            size += entries.len();
            !entries.is_empty()
        });
        self.size = size;
    }

    /// Consumes and returns the keys (from `keys`, deduplicated, each at
    /// most once) with entries that have reached their next refresh
    /// threshold (RFC 6762 §5.2).
    ///
    /// Each due entry has its `refreshes_sent` counter incremented, so a key
    /// is handed out at most once per threshold; the caller is expected to
    /// send the refresh query, which refreshes all records under the key.
    /// Entries with a zero original TTL (goodbyes) are skipped, expired
    /// entries are skipped, and at most four refreshes are handed out per
    /// entry per TTL. `jitter` is the fresh 0–2 % random addition stored for
    /// each consumed entry's next threshold (pion re-rolls it here).
    pub(crate) fn take_refresh_candidates(
        &mut self,
        keys: &[CacheKey],
        now: Instant,
        jitter: f64,
    ) -> Vec<CacheKey> {
        let mut candidates = Vec::new();
        let mut seen = HashSet::with_capacity(keys.len());

        for key in keys {
            if !seen.insert(key) {
                continue;
            }

            let mut key_added = false;
            if let Some(entries) = self.entries.get_mut(key) {
                for entry in entries.iter_mut() {
                    if entry.original_ttl.is_zero()
                        || entry.refreshes_sent as usize >= REFRESH_THRESHOLDS.len()
                    {
                        continue;
                    }

                    if now >= entry.expires_at {
                        continue;
                    }

                    let started_at = entry.expires_at - entry.original_ttl;
                    let elapsed = (now - started_at).as_secs_f64();
                    let fraction = elapsed / entry.original_ttl.as_secs_f64();

                    if fraction
                        >= REFRESH_THRESHOLDS[entry.refreshes_sent as usize] + entry.refresh_jitter
                    {
                        if !key_added {
                            candidates.push(key.clone());
                            key_added = true;
                        }
                        entry.refreshes_sent += 1;
                        entry.refresh_jitter = jitter;
                    }
                }
            }
        }

        candidates
    }

    /// Drops all entries (RFC 6762 §10.3, topology change).
    pub(crate) fn flush_all(&mut self) {
        self.entries.clear();
        self.size = 0;
    }

    /// Caps the remaining TTL of every entry to `max_remaining` from `now`.
    ///
    /// Entries that already expire sooner are left unchanged.
    pub(crate) fn reduce_ttls(&mut self, max_remaining: Duration, now: Instant) {
        let deadline = now + max_remaining;

        for entries in self.entries.values_mut() {
            for entry in entries.iter_mut() {
                if entry.expires_at > deadline {
                    entry.expires_at = deadline;
                }
            }
        }
    }

    /// Returns the count of entries not expired at `now`.
    pub(crate) fn len(&self, now: Instant) -> usize {
        self.entries
            .values()
            .flatten()
            .filter(|entry| now < entry.expires_at)
            .count()
    }

    /// Returns `true` if the cache holds no live entries at `now`.
    pub(crate) fn is_empty(&self, now: Instant) -> bool {
        self.len(now) == 0
    }
}

/// Reports whether two resources have the same name (compared
/// case-insensitively), type, and body content.
///
/// Only A, AAAA, PTR, SRV and TXT bodies compare equal to their own type —
/// exactly as pion's `resourceDataEqual`; any other body (or a missing body)
/// is never equal.
pub(crate) fn resource_data_equal(res_a: &Resource, res_b: &Resource) -> bool {
    if !res_a
        .header
        .name
        .to_string()
        .eq_ignore_ascii_case(&res_b.header.name.to_string())
    {
        return false;
    }

    if res_a.header.typ != res_b.header.typ {
        return false;
    }

    let (Some(body_a), Some(body_b)) = (res_a.body.as_ref(), res_b.body.as_ref()) else {
        return false;
    };

    resource_body_equal(body_a.as_ref(), body_b.as_ref())
}

/// Compares two resource bodies by type-specific fields.
pub(crate) fn resource_body_equal(body_a: &dyn ResourceBody, body_b: &dyn ResourceBody) -> bool {
    let any_a = body_a.as_any();
    let any_b = body_b.as_any();

    if let Some(a) = any_a.downcast_ref::<AResource>() {
        any_b
            .downcast_ref::<AResource>()
            .is_some_and(|b| a.a == b.a)
    } else if let Some(a) = any_a.downcast_ref::<AaaaResource>() {
        any_b
            .downcast_ref::<AaaaResource>()
            .is_some_and(|b| a.aaaa == b.aaaa)
    } else if let Some(a) = any_a.downcast_ref::<PtrResource>() {
        any_b
            .downcast_ref::<PtrResource>()
            .is_some_and(|b| a.ptr.to_string().eq_ignore_ascii_case(&b.ptr.to_string()))
    } else if let Some(a) = any_a.downcast_ref::<SrvResource>() {
        any_b.downcast_ref::<SrvResource>().is_some_and(|b| {
            a.target
                .to_string()
                .eq_ignore_ascii_case(&b.target.to_string())
                && a.port == b.port
                && a.priority == b.priority
                && a.weight == b.weight
        })
    } else if let Some(a) = any_a.downcast_ref::<TxtResource>() {
        any_b
            .downcast_ref::<TxtResource>()
            .is_some_and(|b| a.txt == b.txt)
    } else {
        false
    }
}
