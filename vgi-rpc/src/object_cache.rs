//! The per-process object cache (`STATE_REF_V1.md` §11).
//!
//! Stored [`StateRef`](crate::state_ref::StateRef) values and argument
//! references both name an object in storage by its `object_id`. Resolving one
//! fetches the object, verifies it and opens it; this cache keeps the result so
//! the next turn -- or the next scan thread of the same query -- does not fetch
//! again. The rules, all required by the spec:
//!
//! 1. **Keyed by `object_id`, never by a digest.** Grants mint objects for
//!    claimed hashes without seeing the bytes, so a digest-keyed cache would
//!    hand one principal's value to another who merely knows its hash. An
//!    `object_id` only reaches a server inside a tag or reference sealed for
//!    the caller.
//! 2. **Single-flight.** Concurrent resolves of one `object_id` share one
//!    fetch.
//! 3. **Byte-bounded LRU.** [`OBJECT_CACHE_BYTES_ENV`], default
//!    `min(1 GiB, 40% of the cgroup memory limit)` (or of physical memory when
//!    no cgroup limit is found). A value larger than the bound is returned but
//!    not retained, with a warning.
//! 4. **Memos hold the `object_id`, never the value**, and look it up again on
//!    use, so resident bytes stay bounded by this cache alone.
//! 5. **`fetched_at`.** A hit on an entry fetched more than one day ago is a
//!    miss: an object may be deleted by the bucket lifecycle after a day, and
//!    the cache must not outlive it by more than that.
//!
//! Nothing here is visible on the wire.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use bytes::Bytes;

use crate::errors::{Result, RpcError};

/// Environment variable holding the cache's byte bound.
pub const OBJECT_CACHE_BYTES_ENV: &str = "VGI_RPC_OBJECT_CACHE_BYTES";
/// Entries fetched longer ago than this (one day, the bucket lifecycle bound)
/// are misses.
pub const OBJECT_CACHE_MAX_AGE_SECONDS: f64 = 86_400.0;

const ONE_GIB: u64 = 1 << 30;

/// A snapshot of the cache's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectCacheStats {
    /// Bytes of values currently retained.
    pub resident_bytes: u64,
    /// Number of retained values.
    pub entries: u64,
    /// The byte bound.
    pub max_bytes: u64,
    /// Lookups answered from the cache.
    pub hits: u64,
    /// Lookups that fetched (including aged-out entries and single-flight
    /// joins).
    pub misses: u64,
    /// Entries dropped to stay under the bound or aged out.
    pub evictions: u64,
    /// Fetches actually performed (single-flight joins excluded).
    pub fetches: u64,
}

/// One in-flight fetch that concurrent lookups of the same id wait on.
struct Flight {
    result: Mutex<Option<Result<Bytes>>>,
    done: Condvar,
}

struct Entry {
    value: Bytes,
    fetched_at: f64,
    /// LRU position: the key into [`Inner::order`].
    tick: u64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    /// Recency order, oldest first: `tick -> object_id`.
    order: BTreeMap<u64, String>,
    next_tick: u64,
    resident: u64,
    flights: HashMap<String, Arc<Flight>>,
    hits: u64,
    misses: u64,
    evictions: u64,
    fetches: u64,
}

impl Inner {
    fn remove(&mut self, object_id: &str) -> Option<Entry> {
        let entry = self.entries.remove(object_id)?;
        self.order.remove(&entry.tick);
        self.resident -= entry.value.len() as u64;
        Some(entry)
    }
}

/// Wall-clock source in fractional seconds since the Unix epoch.
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

fn wall_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// A byte-bounded, single-flight LRU of verified object values keyed by
/// `object_id`. Thread-safe.
///
/// Values are the verified, opened, decompressed bytes the caller's `fetch`
/// returns; the cache never inspects them.
pub struct ObjectCache {
    max_bytes: u64,
    max_age: f64,
    clock: Clock,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for ObjectCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectCache")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl ObjectCache {
    /// A cache retaining at most `max_bytes` of values. `0` retains nothing
    /// (every lookup fetches, still single-flight).
    pub fn new(max_bytes: u64) -> Self {
        Self::with_clock(
            max_bytes,
            OBJECT_CACHE_MAX_AGE_SECONDS,
            Arc::new(wall_clock),
        )
    }

    /// [`new`](Self::new) with an explicit age bound and clock (tests).
    pub fn with_clock(max_bytes: u64, max_age_seconds: f64, clock: Clock) -> Self {
        Self {
            max_bytes,
            max_age: max_age_seconds,
            clock,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The byte bound.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current counters.
    pub fn stats(&self) -> ObjectCacheStats {
        let inner = self.lock();
        ObjectCacheStats {
            resident_bytes: inner.resident,
            entries: inner.entries.len() as u64,
            max_bytes: self.max_bytes,
            hits: inner.hits,
            misses: inner.misses,
            evictions: inner.evictions,
            fetches: inner.fetches,
        }
    }

    /// Drop every retained value.
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.entries.clear();
        inner.order.clear();
        inner.resident = 0;
    }

    /// Move every entry's `fetched_at` back by `seconds`; return how many.
    ///
    /// A test hook that proves the one-day age rule without waiting a day.
    pub fn age_entries(&self, seconds: f64) -> usize {
        let mut inner = self.lock();
        for entry in inner.entries.values_mut() {
            entry.fetched_at -= seconds;
        }
        inner.entries.len()
    }

    /// Whether a lookup of `object_id` would hit right now.
    pub fn contains(&self, object_id: &str) -> bool {
        let inner = self.lock();
        inner
            .entries
            .get(object_id)
            .is_some_and(|e| (self.clock)() - e.fetched_at <= self.max_age)
    }

    /// Return the cached value for `object_id`, or run `fetch` to produce it.
    ///
    /// Exactly one caller runs `fetch` per miss; concurrent callers wait for
    /// and share its result (or its error). Returns `(value, hit)`, where
    /// `hit` is `true` when the value came from the cache rather than from
    /// this call's fetch or a joined one.
    pub fn get_or_fetch(
        &self,
        object_id: &str,
        fetch: impl FnOnce() -> Result<Bytes>,
    ) -> Result<(Bytes, bool)> {
        let (flight, leader) = {
            let mut inner = self.lock();
            let now = (self.clock)();
            if let Some(entry) = inner.entries.get(object_id) {
                if now - entry.fetched_at <= self.max_age {
                    let value = entry.value.clone();
                    let old_tick = entry.tick;
                    let tick = inner.next_tick;
                    inner.next_tick += 1;
                    inner.order.remove(&old_tick);
                    inner.order.insert(tick, object_id.to_string());
                    if let Some(entry) = inner.entries.get_mut(object_id) {
                        entry.tick = tick;
                    }
                    inner.hits += 1;
                    tracing::debug!(
                        target: "vgi_rpc.object_cache",
                        event = "hit",
                        resident_bytes = inner.resident,
                        "object_cache hit"
                    );
                    return Ok((value, true));
                }
                // Aged out: the object may already be gone; never serve it.
                inner.remove(object_id);
                inner.evictions += 1;
            }
            inner.misses += 1;
            match inner.flights.get(object_id) {
                Some(flight) => (flight.clone(), false),
                None => {
                    let flight = Arc::new(Flight {
                        result: Mutex::new(None),
                        done: Condvar::new(),
                    });
                    inner.flights.insert(object_id.to_string(), flight.clone());
                    inner.fetches += 1;
                    (flight, true)
                }
            }
        };

        if !leader {
            let mut slot = flight.result.lock().unwrap_or_else(|p| p.into_inner());
            while slot.is_none() {
                slot = flight.done.wait(slot).unwrap_or_else(|p| p.into_inner());
            }
            return slot
                .as_ref()
                .expect("flight result set")
                .clone()
                .map(|v| (v, false));
        }

        tracing::debug!(target: "vgi_rpc.object_cache", event = "miss", "object_cache miss");
        // A panicking fetch must still release the waiters.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(fetch))
            .unwrap_or_else(|_| Err(RpcError::runtime_error("object fetch panicked")));
        {
            let mut inner = self.lock();
            inner.flights.remove(object_id);
            if let Ok(value) = &result {
                self.insert_locked(&mut inner, object_id, value.clone());
            }
        }
        {
            let mut slot = flight.result.lock().unwrap_or_else(|p| p.into_inner());
            *slot = Some(result.clone());
        }
        flight.done.notify_all();
        result.map(|v| (v, false))
    }

    fn insert_locked(&self, inner: &mut Inner, object_id: &str, value: Bytes) {
        let size = value.len() as u64;
        if size > self.max_bytes {
            tracing::warn!(
                target: "vgi_rpc.object_cache",
                event = "not_retained",
                bytes = size,
                max_bytes = self.max_bytes,
                "object_cache: a {size}-byte value exceeds the cache bound ({} bytes, {OBJECT_CACHE_BYTES_ENV}); resolved but not retained",
                self.max_bytes
            );
            return;
        }
        inner.remove(object_id);
        let tick = inner.next_tick;
        inner.next_tick += 1;
        inner.order.insert(tick, object_id.to_string());
        inner.entries.insert(
            object_id.to_string(),
            Entry {
                value,
                fetched_at: (self.clock)(),
                tick,
            },
        );
        inner.resident += size;
        while inner.resident > self.max_bytes {
            let Some((_, oldest)) = inner.order.pop_first() else {
                break;
            };
            if let Some(evicted) = inner.entries.remove(&oldest) {
                inner.resident -= evicted.value.len() as u64;
                inner.evictions += 1;
                tracing::debug!(
                    target: "vgi_rpc.object_cache",
                    event = "evict",
                    resident_bytes = inner.resident,
                    "object_cache evict"
                );
            }
        }
    }
}

fn cgroup_memory_limit() -> Option<u64> {
    for path in [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ] {
        let Ok(raw) = std::fs::read_to_string(path) else {
            continue;
        };
        let raw = raw.trim();
        if raw.is_empty() || raw == "max" {
            return None;
        }
        let Ok(value) = raw.parse::<u64>() else {
            continue;
        };
        // cgroup v1 reports "unlimited" as a huge page-aligned number.
        if value == 0 || value >= (1 << 60) {
            return None;
        }
        return Some(value);
    }
    None
}

fn physical_memory() -> Option<u64> {
    // /proc/meminfo is the one source available without a libc dependency.
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = raw.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

/// The default bound: [`OBJECT_CACHE_BYTES_ENV`] when set, else
/// `min(1 GiB, 40%` of the cgroup memory limit, or of physical memory`)`.
///
/// # Errors
///
/// When the variable is set to anything but a non-negative integer.
pub fn default_object_cache_bytes() -> Result<u64> {
    object_cache_bytes_from(std::env::var(OBJECT_CACHE_BYTES_ENV).ok().as_deref())
}

fn object_cache_bytes_from(raw: Option<&str>) -> Result<u64> {
    if let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) {
        return raw.parse::<u64>().map_err(|_| {
            RpcError::value_error(format!(
                "{OBJECT_CACHE_BYTES_ENV} must be a non-negative integer, got {raw:?}"
            ))
        });
    }
    Ok(match cgroup_memory_limit().or_else(physical_memory) {
        Some(memory) => ONE_GIB.min(memory / 100 * 40),
        None => ONE_GIB,
    })
}

static DEFAULT_CACHE: OnceLock<Arc<ObjectCache>> = OnceLock::new();

/// The process-wide object cache, created on first use.
///
/// Its bound is read from [`OBJECT_CACHE_BYTES_ENV`] (or the memory default)
/// when it is created. An invalid value logs an error and falls back to the
/// memory default rather than failing every resolve; servers call
/// [`default_object_cache_bytes`] at startup to refuse it instead.
pub fn default_object_cache() -> Arc<ObjectCache> {
    DEFAULT_CACHE
        .get_or_init(|| {
            let bound = default_object_cache_bytes().unwrap_or_else(|err| {
                tracing::error!(target: "vgi_rpc.object_cache", "{}", err.message);
                object_cache_bytes_from(None).unwrap_or(ONE_GIB)
            });
            Arc::new(ObjectCache::new(bound))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn value(n: usize) -> Bytes {
        Bytes::from(vec![7u8; n])
    }

    #[test]
    fn hit_after_fetch() {
        let cache = ObjectCache::new(1024);
        let (v, hit) = cache.get_or_fetch("a", || Ok(value(10))).unwrap();
        assert_eq!((v.len(), hit), (10, false));
        let (_, hit) = cache
            .get_or_fetch("a", || panic!("must not refetch"))
            .unwrap();
        assert!(hit);
        let s = cache.stats();
        assert_eq!((s.hits, s.misses, s.fetches, s.entries), (1, 1, 1, 1));
    }

    #[test]
    fn byte_bound_evicts_least_recent() {
        let cache = ObjectCache::new(100);
        cache.get_or_fetch("a", || Ok(value(60))).unwrap();
        cache.get_or_fetch("b", || Ok(value(60))).unwrap();
        let s = cache.stats();
        assert_eq!((s.entries, s.resident_bytes, s.evictions), (1, 60, 1));
        assert!(!cache.contains("a"));
        assert!(cache.contains("b"));
    }

    #[test]
    fn oversized_value_is_returned_not_retained() {
        let cache = ObjectCache::new(10);
        let (v, _) = cache.get_or_fetch("a", || Ok(value(11))).unwrap();
        assert_eq!(v.len(), 11);
        assert_eq!(cache.stats().resident_bytes, 0);
    }

    #[test]
    fn aged_entry_is_a_miss() {
        let cache = ObjectCache::new(1024);
        cache.get_or_fetch("a", || Ok(value(4))).unwrap();
        assert_eq!(cache.age_entries(OBJECT_CACHE_MAX_AGE_SECONDS + 1.0), 1);
        let (_, hit) = cache.get_or_fetch("a", || Ok(value(4))).unwrap();
        assert!(!hit);
        assert_eq!(cache.stats().fetches, 2);
    }

    #[test]
    fn errors_are_not_cached() {
        let cache = ObjectCache::new(1024);
        assert!(cache
            .get_or_fetch("a", || Err(RpcError::runtime_error("boom")))
            .is_err());
        assert!(cache.get_or_fetch("a", || Ok(value(1))).is_ok());
    }

    #[test]
    fn concurrent_lookups_share_one_fetch() {
        let cache = Arc::new(ObjectCache::new(1 << 20));
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (cache, calls, barrier) = (cache.clone(), calls.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    cache
                        .get_or_fetch("x", || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            std::thread::sleep(std::time::Duration::from_millis(50));
                            Ok(value(32))
                        })
                        .unwrap()
                })
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().unwrap().0.len(), 32);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.stats().fetches, 1);
    }

    #[test]
    fn env_bound_parsing() {
        assert_eq!(object_cache_bytes_from(Some("0")).unwrap(), 0);
        assert_eq!(object_cache_bytes_from(Some(" 98304 ")).unwrap(), 98304);
        assert!(object_cache_bytes_from(Some("-1")).is_err());
        assert!(object_cache_bytes_from(Some("lots")).is_err());
        let default = object_cache_bytes_from(None).unwrap();
        assert!(default > 0 && default <= ONE_GIB);
    }
}
