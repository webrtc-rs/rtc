// Ported from pion/mdns v2.2.2 cache_test.go (41 tests):
// https://github.com/pion/mdns/blob/v2.2.2/cache_test.go.
//
// Where a Go test sleeps, we advance a virtual clock instead: pion's test
// clock (`newTestClock`) becomes an `Instant` anchor plus `Duration` offsets
// passed to every cache method, so nothing sleeps. Test names are the
// snake_case of the Go names; the ledger references them.
//
// `TestCacheConcurrency` is not ported: pion guards its cache with an
// RWMutex and races it from goroutines, while this sans-I/O cache is a
// single-owner `&mut self` type with no interior mutability — there is no
// lock to exercise (the ledger row is `na`).
//
// The take_refresh_candidates tests at the bottom have no pion counterpart
// (pion's cache_test.go does not cover it); they pin the RFC 6762 §5.2
// threshold behaviour with the injected jitter.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::*;
use crate::dnssd::records::{
    build_a_resource, build_aaaa_resource, build_ptr_resource, build_srv_resource,
    build_txt_resource, parse_ptr_target, parse_srv_data, parse_txt_data,
};

// ---------------------------------------------------------------------------
// Test clock — deterministic time for cache tests
// ---------------------------------------------------------------------------

struct TestClock {
    current: Instant,
}

impl TestClock {
    fn new() -> Self {
        TestClock {
            current: Instant::now(),
        }
    }

    fn now(&self) -> Instant {
        self.current
    }

    fn advance(&mut self, dur: Duration) {
        self.current += dur;
    }
}

// ---------------------------------------------------------------------------
// Test helpers — build records without error handling boilerplate
// ---------------------------------------------------------------------------

fn must_build_a(name: &str, a: [u8; 4], ttl: u32) -> Resource {
    build_a_resource(name, IpAddr::V4(Ipv4Addr::from(a)), ttl).unwrap()
}

fn must_build_aaaa(name: &str, segs: [u16; 8], ttl: u32) -> Resource {
    build_aaaa_resource(name, IpAddr::V6(Ipv6Addr::from(segs)), ttl).unwrap()
}

fn must_build_ptr(name: &str, target: &str, ttl: u32) -> Resource {
    build_ptr_resource(name, target, ttl).unwrap()
}

fn must_build_srv(name: &str, target: &str, port: u16, ttl: u32) -> Resource {
    build_srv_resource(name, target, port, 0, 0, ttl).unwrap()
}

fn must_build_txt(name: &str, txts: Vec<&str>, ttl: u32) -> Resource {
    build_txt_resource(name, txts.into_iter().map(str::to_owned).collect(), ttl).unwrap()
}

fn v4(o0: u8, o1: u8, o2: u8, o3: u8) -> [u8; 4] {
    [o0, o1, o2, o3]
}

fn v6(seg0: u16) -> [u16; 8] {
    [seg0, 0, 0, 0, 0, 0, 0, 1]
}

// ---------------------------------------------------------------------------
// Basic insert/lookup — one test per record type
// ---------------------------------------------------------------------------

#[test]
fn test_cache_insert_lookup_a() {
    let clock = TestClock::new();
    let mut ca = Cache::new();
    let rec = must_build_a("host.local.", v4(192, 168, 1, 1), 120);

    ca.insert(rec, clock.now(), 0.0);

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.typ, DnsType::A);

    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(192, 168, 1, 1));
}

#[test]
fn test_cache_insert_lookup_aaaa() {
    let clock = TestClock::new();
    let mut ca = Cache::new();
    let rec = must_build_aaaa("v6host.local.", v6(0xfd00), 120);

    ca.insert(rec, clock.now(), 0.0);

    let results = ca.lookup("v6host.local.", DnsType::Aaaa, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let body = results[0].body.as_ref().unwrap();
    let aaaa = body.as_any().downcast_ref::<AaaaResource>().unwrap();
    assert_eq!(aaaa.aaaa, Ipv6Addr::from(v6(0xfd00)).octets());
}

#[test]
fn test_cache_insert_lookup_ptr() {
    let clock = TestClock::new();
    let mut ca = Cache::new();
    let rec = must_build_ptr("_http._tcp.local.", "My Web._http._tcp.local.", 4500);

    ca.insert(rec, clock.now(), 0.0);

    let results = ca.lookup("_http._tcp.local.", DnsType::Ptr, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let target = parse_ptr_target(results[0].body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(target, "My Web._http._tcp.local.");
}

#[test]
fn test_cache_insert_lookup_srv() {
    let clock = TestClock::new();
    let mut ca = Cache::new();
    let rec = must_build_srv("svc._http._tcp.local.", "myhost.local.", 8080, 120);

    ca.insert(rec, clock.now(), 0.0);

    let results = ca.lookup(
        "svc._http._tcp.local.",
        DnsType::Srv,
        DnsClass(1),
        clock.now(),
    );
    assert_eq!(results.len(), 1);

    let srv = parse_srv_data(results[0].body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(srv.target, "myhost.local.");
    assert_eq!(srv.port, 8080);
}

#[test]
fn test_cache_insert_lookup_txt() {
    let clock = TestClock::new();
    let mut ca = Cache::new();
    let rec = must_build_txt("svc._http._tcp.local.", vec!["txtvers=1", "path=/"], 4500);

    ca.insert(rec, clock.now(), 0.0);

    let results = ca.lookup(
        "svc._http._tcp.local.",
        DnsType::Txt,
        DnsClass(1),
        clock.now(),
    );
    assert_eq!(results.len(), 1);

    let txts = parse_txt_data(results[0].body.as_ref().unwrap().as_ref()).unwrap();
    assert_eq!(txts, vec!["txtvers=1", "path=/"]);
}

// ---------------------------------------------------------------------------
// TTL recalculation
// ---------------------------------------------------------------------------

#[test]
fn test_cache_lookup_remaining_ttl() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();
    let rec = must_build_a("host.local.", v4(192, 168, 1, 1), 120);

    ca.insert(rec, clock.now(), 0.0);
    clock.advance(Duration::from_secs(30));

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.ttl, 90);
}

// ---------------------------------------------------------------------------
// Case-insensitive lookup
// ---------------------------------------------------------------------------

#[test]
fn test_cache_lookup_case_insensitive() {
    let clock = TestClock::new();
    let mut ca = Cache::new();
    let rec = must_build_a("Test.Local.", v4(10, 0, 0, 1), 120);

    ca.insert(rec, clock.now(), 0.0);

    let results = ca.lookup("test.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(10, 0, 0, 1));

    // Also try uppercase lookup.
    let results = ca.lookup("TEST.LOCAL.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(10, 0, 0, 1));
}

// ---------------------------------------------------------------------------
// Multiple records per key
// ---------------------------------------------------------------------------

#[test]
fn test_cache_multiple_records_same_name() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 2), 120),
        clock.now(),
        0.0,
    );

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 2);

    let mut ips = Vec::new();
    for res in &results {
        let body = res.body.as_ref().unwrap();
        let a = body.as_any().downcast_ref::<AResource>().unwrap();
        ips.push(a.a);
    }

    assert!(ips.contains(&v4(192, 168, 1, 1)) && ips.contains(&v4(192, 168, 1, 2)));
}

#[test]
fn test_cache_multiple_ptr_targets() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_ptr("_http._tcp.local.", "Web1._http._tcp.local.", 4500),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_ptr("_http._tcp.local.", "Web2._http._tcp.local.", 4500),
        clock.now(),
        0.0,
    );

    let results = ca.lookup("_http._tcp.local.", DnsType::Ptr, DnsClass(1), clock.now());
    assert_eq!(results.len(), 2);

    let mut targets = Vec::new();
    for res in &results {
        targets.push(parse_ptr_target(res.body.as_ref().unwrap().as_ref()).unwrap());
    }

    assert!(targets.contains(&"Web1._http._tcp.local.".to_owned()));
    assert!(targets.contains(&"Web2._http._tcp.local.".to_owned()));
}

// ---------------------------------------------------------------------------
// TTL expiration
// ---------------------------------------------------------------------------

#[test]
fn test_cache_ttl_expiration() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );
    clock.advance(Duration::from_secs(120));

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert!(results.is_empty());
}

#[test]
fn test_cache_ttl_valid_before_expiry() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );
    clock.advance(Duration::from_secs(119));

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.ttl, 1);
}

// ---------------------------------------------------------------------------
// Sweep
// ---------------------------------------------------------------------------

#[test]
fn test_cache_sweep_removes_expired() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("gone.local.", v4(10, 0, 0, 1), 60),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("alive.local.", v4(10, 0, 0, 2), 300),
        clock.now(),
        0.0,
    );
    clock.advance(Duration::from_secs(120));

    ca.sweep(clock.now());

    assert!(
        ca.lookup("gone.local.", DnsType::A, DnsClass(1), clock.now())
            .is_empty()
    );

    let alive = ca.lookup("alive.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(alive.len(), 1);

    let body = alive[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(10, 0, 0, 2));
}

#[test]
fn test_cache_sweep_empty() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    // Should not panic or error.
    ca.sweep(clock.now());
    assert_eq!(0, ca.len(clock.now()));
}

// ---------------------------------------------------------------------------
// TTL update — same rdata, new TTL
// ---------------------------------------------------------------------------

#[test]
fn test_cache_ttl_update() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 60),
        clock.now(),
        0.0,
    );
    clock.advance(Duration::from_secs(10));

    // Re-insert same rdata with new TTL.
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );

    // Should still be one entry, not two.
    assert_eq!(1, ca.len(clock.now()));

    // Remaining TTL should be based on the new insert: 120s from t=10s.
    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.ttl, 120);
}

// ---------------------------------------------------------------------------
// Goodbye packets — RFC 6762 §10.1
// ---------------------------------------------------------------------------

#[test]
fn test_cache_goodbye_existing_record() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );

    // Send goodbye (TTL=0).
    let goodbye = must_build_a("host.local.", v4(192, 168, 1, 1), 0);
    ca.insert(goodbye, clock.now(), 0.0);

    // Still visible (expires in 1s).
    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(192, 168, 1, 1));
}

#[test]
fn test_cache_goodbye_expiration() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );

    let goodbye = must_build_a("host.local.", v4(192, 168, 1, 1), 0);
    ca.insert(goodbye, clock.now(), 0.0);
    clock.advance(Duration::from_secs(2));

    // After 2s the goodbye entry should be expired.
    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert!(results.is_empty());
}

#[test]
fn test_cache_goodbye_unknown_record() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // Goodbye for a record not in cache — should create a 1s entry.
    let goodbye = must_build_a("host.local.", v4(192, 168, 1, 1), 0);
    ca.insert(goodbye, clock.now(), 0.0);

    assert_eq!(1, ca.len(clock.now()));

    clock.advance(Duration::from_secs(2));
    assert_eq!(0, ca.len(clock.now()));
}

#[test]
fn test_cache_goodbye_selective_by_rdata() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 2), 120),
        clock.now(),
        0.0,
    );

    // Goodbye only the first address.
    let goodbye = must_build_a("host.local.", v4(192, 168, 1, 1), 0);
    ca.insert(goodbye, clock.now(), 0.0);
    clock.advance(Duration::from_secs(2));

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(192, 168, 1, 2));
}

#[test]
fn test_cache_goodbye_then_reinsert() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );

    // Goodbye shortens TTL to 1s.
    let goodbye = must_build_a("host.local.", v4(192, 168, 1, 1), 0);
    ca.insert(goodbye, clock.now(), 0.0);

    // Fresh announcement before the goodbye expires revives the record.
    clock.advance(Duration::from_millis(500));
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 300),
        clock.now(),
        0.0,
    );

    // Well past the original goodbye expiry, record should still be alive.
    clock.advance(Duration::from_secs(5));

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.ttl, 295);
}

// ---------------------------------------------------------------------------
// Cache-flush bit — RFC 6762 §10.2
// ---------------------------------------------------------------------------

#[test]
fn test_cache_flush_bit_stripped() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    let mut rec = must_build_a("host.local.", v4(192, 168, 1, 1), 120);
    rec.header.class = DnsClass(rec.header.class.0 | RR_CLASS_CACHE_FLUSH);

    ca.insert(rec, clock.now(), 0.0);

    // Lookup without the flush bit should find the record.
    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(192, 168, 1, 1));
}

#[test]
fn test_cache_flush_old_entries() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // Insert old record at t=0.
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 300),
        clock.now(),
        0.0,
    );
    clock.advance(Duration::from_secs(2));

    // Insert new record with cache-flush bit at t=2s.
    let mut flusher = must_build_a("host.local.", v4(192, 168, 1, 2), 120);
    flusher.header.class = DnsClass(flusher.header.class.0 | RR_CLASS_CACHE_FLUSH);
    ca.insert(flusher, clock.now(), 0.0);

    // Old entry is marked to expire in 1s (at t=3s). Advance past that.
    clock.advance(Duration::from_secs(2));

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    // Only the new record should survive.
    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(192, 168, 1, 2));
}

#[test]
fn test_cache_flush_preserves_recent() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // Insert record A at t=0.5s (recent).
    clock.advance(Duration::from_millis(500));
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 300),
        clock.now(),
        0.0,
    );

    // Insert record B with cache-flush bit at t=0.8s.
    clock.advance(Duration::from_millis(300));
    let mut flusher = must_build_a("host.local.", v4(192, 168, 1, 2), 120);
    flusher.header.class = DnsClass(flusher.header.class.0 | RR_CLASS_CACHE_FLUSH);
    ca.insert(flusher, clock.now(), 0.0);

    // Record A was created 300ms ago (< 1s), so it is preserved.
    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 2);

    let mut ips = Vec::new();
    for res in &results {
        let body = res.body.as_ref().unwrap();
        let a = body.as_any().downcast_ref::<AResource>().unwrap();
        ips.push(a.a);
    }

    assert!(ips.contains(&v4(192, 168, 1, 1)) && ips.contains(&v4(192, 168, 1, 2)));
}

#[test]
fn test_cache_flush_preserves_refreshed() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // Insert record A at t=0.
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 300),
        clock.now(),
        0.0,
    );

    // Advance well past the 1s cache-flush window before refreshing.
    clock.advance(Duration::from_secs(5));

    // Refresh record A at t=5s (TTL update resets created_at).
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 200),
        clock.now(),
        0.0,
    );

    // Record B arrives with cache-flush at t=5.5s.
    // Deadline = 5.5s - 1s = 4.5s. With created_at reset to 5s, record A
    // survives (5s > 4.5s). Without the reset, created_at=0 < 4.5s and
    // record A would be flushed (expires_at set to 6.5s).
    clock.advance(Duration::from_millis(500));
    let mut flusher = must_build_a("host.local.", v4(192, 168, 1, 2), 120);
    flusher.header.class = DnsClass(flusher.header.class.0 | RR_CLASS_CACHE_FLUSH);
    ca.insert(flusher, clock.now(), 0.0);

    // Advance past the 1s flush expiry so incorrectly flushed records
    // are gone, not just marked.
    clock.advance(Duration::from_secs(2));

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 2);

    let mut ips = Vec::new();
    for res in &results {
        let body = res.body.as_ref().unwrap();
        let a = body.as_any().downcast_ref::<AResource>().unwrap();
        ips.push(a.a);
    }

    assert!(ips.contains(&v4(192, 168, 1, 1)) && ips.contains(&v4(192, 168, 1, 2)));
}

#[test]
fn test_cache_flush_type_isolation() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // Insert A and AAAA for the same name.
    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 300),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_aaaa("host.local.", v6(0xfd00), 300),
        clock.now(),
        0.0,
    );
    clock.advance(Duration::from_secs(2));

    // Cache-flush on a new A record should not touch the AAAA.
    let mut flusher = must_build_a("host.local.", v4(192, 168, 1, 2), 120);
    flusher.header.class = DnsClass(flusher.header.class.0 | RR_CLASS_CACHE_FLUSH);
    ca.insert(flusher, clock.now(), 0.0);
    clock.advance(Duration::from_secs(2));

    // Old A record flushed, new A record present.
    let a_results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(a_results.len(), 1);

    let body = a_results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(192, 168, 1, 2));

    // AAAA record untouched.
    let aaaa_results = ca.lookup("host.local.", DnsType::Aaaa, DnsClass(1), clock.now());
    assert_eq!(aaaa_results.len(), 1);

    let body6 = aaaa_results[0].body.as_ref().unwrap();
    let aaaa = body6.as_any().downcast_ref::<AaaaResource>().unwrap();
    assert_eq!(aaaa.aaaa, Ipv6Addr::from(v6(0xfd00)).octets());
}

// ---------------------------------------------------------------------------
// Topology change — RFC 6762 §10.3
// ---------------------------------------------------------------------------

#[test]
fn test_cache_flush_all() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("a.local.", v4(10, 0, 0, 1), 120),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("b.local.", v4(10, 0, 0, 2), 120),
        clock.now(),
        0.0,
    );
    assert_eq!(2, ca.len(clock.now()));

    ca.flush_all();
    assert_eq!(0, ca.len(clock.now()));
}

#[test]
fn test_cache_reduce_ttls() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("long.local.", v4(10, 0, 0, 1), 300),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("short.local.", v4(10, 0, 0, 2), 3),
        clock.now(),
        0.0,
    );

    ca.reduce_ttls(Duration::from_secs(5), clock.now());

    // Long TTL should be capped to ~5s.
    let results = ca.lookup("long.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.ttl, 5);

    // Short TTL (3s) is already under 5s, should be unchanged.
    let results = ca.lookup("short.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].header.ttl, 3);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_cache_lookup_empty() {
    let clock = TestClock::new();
    let ca = Cache::new();

    let results = ca.lookup("missing.local.", DnsType::A, DnsClass(1), clock.now());
    assert!(results.is_empty());

    // Different class also returns empty.
    let results = ca.lookup("missing.local.", DnsType::A, DnsClass(3), clock.now());
    assert!(results.is_empty());
}

#[test]
fn test_cache_lookup_wrong_type() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(192, 168, 1, 1), 120),
        clock.now(),
        0.0,
    );

    // Same name, wrong type.
    let results = ca.lookup("host.local.", DnsType::Aaaa, DnsClass(1), clock.now());
    assert!(results.is_empty());
}

#[test]
fn test_cache_len() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    assert_eq!(0, ca.len(clock.now()));

    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 1), 60),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 2), 120),
        clock.now(),
        0.0,
    );
    assert_eq!(2, ca.len(clock.now()));

    // Expire the first record.
    clock.advance(Duration::from_secs(60));
    assert_eq!(1, ca.len(clock.now()));
}

// ---------------------------------------------------------------------------
// resource_data_equal — per-type coverage
// ---------------------------------------------------------------------------

#[test]
fn test_resource_data_equal_a() {
    let rec_a = must_build_a("host.local.", v4(192, 168, 1, 1), 120);
    let rec_b = must_build_a("host.local.", v4(192, 168, 1, 1), 60);
    let rec_c = must_build_a("host.local.", v4(192, 168, 1, 2), 120);

    assert!(
        resource_data_equal(&rec_a, &rec_b),
        "same A rdata, different TTL"
    );
    assert!(!resource_data_equal(&rec_a, &rec_c), "different A address");
}

#[test]
fn test_resource_data_equal_aaaa() {
    let rec_a = must_build_aaaa("host.local.", v6(0xfd00), 120);
    let rec_b = must_build_aaaa("host.local.", v6(0xfd00), 60);
    let rec_c = must_build_aaaa("host.local.", v6(0xfd01), 120);

    assert!(resource_data_equal(&rec_a, &rec_b), "same AAAA rdata");
    assert!(
        !resource_data_equal(&rec_a, &rec_c),
        "different AAAA address"
    );
}

#[test]
fn test_resource_data_equal_ptr() {
    let rec_a = must_build_ptr("_http._tcp.local.", "Web._http._tcp.local.", 4500);
    let rec_b = must_build_ptr("_http._tcp.local.", "Web._http._tcp.local.", 120);
    let rec_c = must_build_ptr("_ipp._tcp.local.", "Other._ipp._tcp.local.", 4500);

    assert!(resource_data_equal(&rec_a, &rec_b), "same PTR target");
    assert!(!resource_data_equal(&rec_a, &rec_c), "different PTR target");
}

#[test]
fn test_resource_data_equal_srv() {
    let rec_a = must_build_srv("svc._tcp.local.", "host.local.", 80, 120);
    let rec_b = must_build_srv("svc._tcp.local.", "host.local.", 80, 60);
    let rec_c = must_build_srv("svc._tcp.local.", "host.local.", 8080, 120);

    assert!(resource_data_equal(&rec_a, &rec_b), "same SRV rdata");
    assert!(!resource_data_equal(&rec_a, &rec_c), "different SRV port");
}

#[test]
fn test_resource_data_equal_txt() {
    let rec_a = must_build_txt("svc._tcp.local.", vec!["a=1", "b=2"], 120);
    let rec_b = must_build_txt("svc._tcp.local.", vec!["a=1", "b=2"], 60);
    let rec_c = must_build_txt("svc._tcp.local.", vec!["a=1", "c=3"], 120);
    let rec_d = must_build_txt("svc._tcp.local.", vec!["a=1"], 120);

    assert!(resource_data_equal(&rec_a, &rec_b), "same TXT strings");
    assert!(
        !resource_data_equal(&rec_a, &rec_c),
        "different TXT strings"
    );
    assert!(!resource_data_equal(&rec_a, &rec_d), "different TXT length");
}

#[test]
fn test_resource_data_equal_different_types() {
    let rec_a = must_build_a("host.local.", v4(192, 168, 1, 1), 120);
    let rec_aaaa = must_build_aaaa("host.local.", v6(0xfd00), 120);

    assert!(!resource_data_equal(&rec_a, &rec_aaaa));
}

#[test]
fn test_resource_data_equal_nil_body() {
    let rec_a = must_build_a("host.local.", v4(192, 168, 1, 1), 120);
    let rec_nil = Resource {
        header: rec_a.header.clone(),
        body: None,
    };

    assert!(!resource_data_equal(&rec_a, &rec_nil));
}

#[test]
fn test_resource_data_equal_different_names() {
    let rec_a = must_build_a("a.local.", v4(192, 168, 1, 1), 120);
    let rec_b = must_build_a("b.local.", v4(192, 168, 1, 1), 120);

    assert!(!resource_data_equal(&rec_a, &rec_b));
}

// ---------------------------------------------------------------------------
// TTL clamping and capacity
// ---------------------------------------------------------------------------

#[test]
fn test_cache_ttl_clamped_to_max() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // A 24h TTL is clamped to MAX_RECORD_TTL (75 minutes).
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 1), 86400),
        clock.now(),
        0.0,
    );

    let results = ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);
    assert!(Duration::from_secs(results[0].header.ttl as u64) <= MAX_RECORD_TTL);

    // Expired at the clamp boundary despite the huge advertised TTL.
    clock.advance(MAX_RECORD_TTL + Duration::from_secs(1));
    assert!(
        ca.lookup("host.local.", DnsType::A, DnsClass(1), clock.now())
            .is_empty()
    );
}

// Inserting 4097 distinct records leaves len() == 4096 and evicts the
// soonest-to-expire one (the issue's required capacity test; pion's
// TestCacheCapEvictsSoonestExpiring is exactly this scenario).
#[test]
fn test_cache_cap_evicts_soonest_expiring() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    // Short-lived record that should be evicted when the cache fills up.
    ca.insert(
        must_build_a("victim.local.", v4(10, 0, 0, 1), 5),
        clock.now(),
        0.0,
    );

    for i in 0..MAX_CACHE_ENTRIES {
        let name = format!("host{i}.local.");
        ca.insert(must_build_a(&name, v4(10, 0, 0, 2), 100), clock.now(), 0.0);
    }

    assert_eq!(MAX_CACHE_ENTRIES, ca.len(clock.now()));
    assert!(
        ca.lookup("victim.local.", DnsType::A, DnsClass(1), clock.now())
            .is_empty()
    );
}

#[test]
fn test_cache_cap_eviction_keeps_sibling_entries() {
    let clock = TestClock::new();
    let mut ca = Cache::new();

    // Two records under the same key (same name/type, different rdata);
    // the shorter-lived one is the eviction victim.
    ca.insert(
        must_build_a("shared.local.", v4(10, 0, 0, 1), 5),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("shared.local.", v4(10, 0, 0, 2), 100),
        clock.now(),
        0.0,
    );

    for i in 0..MAX_CACHE_ENTRIES - 1 {
        let name = format!("host{i}.local.");
        ca.insert(must_build_a(&name, v4(10, 0, 0, 3), 100), clock.now(), 0.0);
    }

    // The sibling under the shared key must survive the eviction.
    let results = ca.lookup("shared.local.", DnsType::A, DnsClass(1), clock.now());
    assert_eq!(results.len(), 1);

    let body = results[0].body.as_ref().unwrap();
    let a = body.as_any().downcast_ref::<AResource>().unwrap();
    assert_eq!(a.a, v4(10, 0, 0, 2));
}

// ---------------------------------------------------------------------------
// take_refresh_candidates — RFC 6762 §5.2 (no pion counterpart; pins the
// threshold behaviour with the injected jitter)
// ---------------------------------------------------------------------------

fn refresh_key(name: &str) -> CacheKey {
    CacheKey::from_lookup(name, DnsType::A, DnsClass(1))
}

#[test]
fn test_take_refresh_candidates_thresholds() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // TTL 100s at t0, no jitter.
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 1), 100),
        clock.now(),
        0.0,
    );
    let key = refresh_key("host.local.");
    let keys = [key.clone()];

    // 79 % of the TTL: below the first threshold.
    clock.advance(Duration::from_secs(79));
    assert!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0)
            .is_empty()
    );

    // 81 %: past the 80 % threshold → first refresh.
    clock.advance(Duration::from_secs(2));
    let cands = ca.take_refresh_candidates(&keys, clock.now(), 0.0);
    assert_eq!(cands, vec![key.clone()]);

    // Polling again immediately does not re-hand-out the same threshold.
    assert!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0)
            .is_empty()
    );

    // 85 %, 90 %, 95 % thresholds each hand the key out once more.
    clock.advance(Duration::from_secs(4)); // 85 s
    assert_eq!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0),
        vec![key.clone()]
    );
    clock.advance(Duration::from_secs(5)); // 90 s
    assert_eq!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0),
        vec![key.clone()]
    );
    clock.advance(Duration::from_secs(5)); // 95 s
    assert_eq!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0),
        vec![key.clone()]
    );

    // All four refreshes spent: never again within this TTL.
    clock.advance(Duration::from_secs(4)); // 99 s
    assert!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0)
            .is_empty()
    );
}

#[test]
fn test_take_refresh_candidates_jitter_delays() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // TTL 100s with a 1 % jitter on the first threshold: due at 81 %.
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 1), 100),
        clock.now(),
        0.01,
    );
    let key = refresh_key("host.local.");
    let keys = [key.clone()];

    clock.advance(Duration::from_secs(80)); // 80 % < 80 % + 1 %
    assert!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0)
            .is_empty()
    );

    clock.advance(Duration::from_secs(2)); // 82 % >= 81 %
    assert_eq!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0),
        vec![key]
    );
}

#[test]
fn test_take_refresh_candidates_skips_goodbyes_and_expired() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // A goodbye entry (original TTL zero) is never a refresh candidate.
    let goodbye = must_build_a("bye.local.", v4(10, 0, 0, 1), 0);
    ca.insert(goodbye, clock.now(), 0.0);

    // A live record that later expires: candidate before expiry, not after.
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 2), 10),
        clock.now(),
        0.0,
    );

    let bye_key = refresh_key("bye.local.");
    let host_key = refresh_key("host.local.");

    clock.advance(Duration::from_secs(9));
    let cands = ca.take_refresh_candidates(&[bye_key.clone(), host_key.clone()], clock.now(), 0.0);
    assert_eq!(cands, vec![host_key.clone()]); // goodbye skipped

    clock.advance(Duration::from_secs(2)); // host record expired
    assert!(
        ca.take_refresh_candidates(&[bye_key, host_key], clock.now(), 0.0)
            .is_empty()
    );
}

#[test]
fn test_take_refresh_candidates_dedups_and_groups_keys() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    // Two entries under one key, both due at the same threshold.
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 1), 100),
        clock.now(),
        0.0,
    );
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 2), 100),
        clock.now(),
        0.0,
    );
    let key = refresh_key("host.local.");

    clock.advance(Duration::from_secs(81));
    // Duplicate keys in the input are checked once; the key is returned at
    // most once even though two entries under it are due.
    let cands = ca.take_refresh_candidates(&[key.clone(), key.clone()], clock.now(), 0.0);
    assert_eq!(cands, vec![key.clone()]);

    // Both entries consumed the threshold: the second refresh lands both on
    // the 85 % threshold with a single key again.
    clock.advance(Duration::from_secs(4));
    assert_eq!(
        ca.take_refresh_candidates(&[key], clock.now(), 0.0),
        vec![refresh_key("host.local.")]
    );
}

// Re-inserting the same rdata resets the refresh counters, as pion's
// insertOrUpdate does.
#[test]
fn test_refresh_counters_reset_on_reinsert() {
    let mut clock = TestClock::new();
    let mut ca = Cache::new();

    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 1), 100),
        clock.now(),
        0.0,
    );
    let key = refresh_key("host.local.");
    let keys = [key];

    clock.advance(Duration::from_secs(81));
    assert_eq!(ca.take_refresh_candidates(&keys, clock.now(), 0.0).len(), 1);

    // Refresh the record (same rdata): full new TTL, counters reset.
    ca.insert(
        must_build_a("host.local.", v4(10, 0, 0, 1), 100),
        clock.now(),
        0.0,
    );

    clock.advance(Duration::from_secs(79));
    assert!(
        ca.take_refresh_candidates(&keys, clock.now(), 0.0)
            .is_empty()
    );
    clock.advance(Duration::from_secs(2)); // 81 % of the new TTL
    assert_eq!(ca.take_refresh_candidates(&keys, clock.now(), 0.0).len(), 1);
}
