//! Heap-allocation counting, for reports of allocations per packet or per message.
//!
//! Timing says how long the packet path takes; it does not say why. Allocation counts are the
//! other half, and unlike timings they are close to deterministic: the same workload on the same
//! revision allocates the same number of times on any machine, so a change of one allocation per
//! packet is visible without any statistics.
//!
//! A bench binary opts in by installing [`CountingAllocator`]:
//!
//! ```no_run
//! #[global_allocator]
//! static ALLOCATOR: rtc_bench::allocations::CountingAllocator =
//!     rtc_bench::allocations::CountingAllocator;
//! ```
//!
//! [`Peer`](crate::Peer) then attributes every allocation made inside a call into its connection
//! to that side, exactly as it attributes CPU time; see [`Peer::allocations`](crate::Peer::allocations).
//! Without the allocator installed the counters stay at zero and cost one relaxed atomic load per
//! call.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ops::{AddAssign, Sub};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNT: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

/// A global allocator that forwards to [`System`] and counts every allocation.
///
/// `realloc` counts as an allocation, since growing a buffer usually is one. Frees are not
/// counted: this measures allocation traffic, not retained memory.
pub struct CountingAllocator;

// SAFETY: every method forwards to `System` with its arguments unchanged; the counters have no
// effect on the memory returned.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: forwarded unchanged; the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        // SAFETY: as for `alloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as for `alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn record(bytes: usize) {
    COUNT.fetch_add(1, Ordering::Relaxed);
    BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
}

/// Allocations made, and bytes requested by them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Allocations {
    /// Calls to `alloc`, `alloc_zeroed` and `realloc`.
    pub count: u64,
    /// Bytes those calls requested.
    pub bytes: u64,
}

impl Allocations {
    /// Per-operation averages over `operations`, as `(allocations, bytes)`.
    pub fn per(self, operations: u64) -> (f64, f64) {
        let operations = operations.max(1) as f64;
        (
            self.count as f64 / operations,
            self.bytes as f64 / operations,
        )
    }
}

impl Sub for Allocations {
    type Output = Allocations;

    fn sub(self, earlier: Allocations) -> Allocations {
        Allocations {
            count: self.count - earlier.count,
            bytes: self.bytes - earlier.bytes,
        }
    }
}

impl AddAssign for Allocations {
    fn add_assign(&mut self, other: Allocations) {
        self.count += other.count;
        self.bytes += other.bytes;
    }
}

/// Process-wide totals so far. Always zero unless [`CountingAllocator`] is installed.
pub fn snapshot() -> Allocations {
    Allocations {
        count: COUNT.load(Ordering::Relaxed),
        bytes: BYTES.load(Ordering::Relaxed),
    }
}
