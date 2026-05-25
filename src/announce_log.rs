//! Announce log filter + periodic summary.
//!
//! Reticulum networks are extremely chatty: every node re-broadcasts every
//! announce it sees, so a transport-enabled node like rfed easily ingests
//! 1000+ announces/min. Logging every "Inbound ANNOUNCE / Announce VALID /
//! Path added" line at LOG_NOTICE used to dominate the log file and serialise
//! through the global `LOGGING_LOCK` + file-write on every packet.
//!
//! This module provides:
//!   1. A hardcoded whitelist of destination hashes we actually care about
//!      (rfed's own four destinations, the lxmf.propagation node, etc).
//!   2. Atomic counters that aggregate the suppressed traffic.
//!   3. `flush_if_due()` — call from any frequently-hit code path; emits a
//!      single summary line every `FLUSH_INTERVAL_SECS` seconds.

use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

/// Hardcoded whitelist of 16-byte destination hashes (lowercase hex) that
/// should ALWAYS produce announce/path log lines. Everything else is counted
/// silently.
///
/// Update this list when you want to spotlight a new destination during
/// debugging. It is intentionally code-resident (not a config file) so that
/// the whitelist is grep-able and travels with the binary.
const WHITELIST_HEX: &[&str] = &[
    // rfed own destinations
    "8772cfeaee0489ba496c4b229e849472", // rfed.node
    "589aa0087c3476aac542e8b6f1c9bc08", // rfed.delivery
    "2b8f4b464f8c0c8fb2c314321ac040b5", // rfed.channel
    "c23df05c18280f147d14b3227c18bfc8", // rfed.notify
    // External destinations of interest
    "0f75ac15961b7d2b1577a57bdb1fda3c", // lxmf.propagation node
];

/// How often (seconds) to emit the aggregated summary.
const FLUSH_INTERVAL_SECS: u64 = 30;

static INBOUND_ANNOUNCES_TOTAL: AtomicU64 = AtomicU64::new(0);
static ANNOUNCES_VALID: AtomicU64 = AtomicU64::new(0);
static ANNOUNCES_INVALID: AtomicU64 = AtomicU64::new(0);
static ANNOUNCES_DEDUP_SKIPPED: AtomicU64 = AtomicU64::new(0);
static PATHS_ADDED: AtomicU64 = AtomicU64::new(0);
static LAST_FLUSH_SECS: AtomicU64 = AtomicU64::new(0);
static RUNTIME_WATCH_HEX: Lazy<Mutex<HashMap<String, usize>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[inline]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns true iff the destination should produce per-packet log lines.
/// Pass the raw 16-byte destination hash. `None` is treated as "not on list".
pub fn is_whitelisted(dest_hash: Option<&[u8]>) -> bool {
    let h = match dest_hash {
        Some(h) => h,
        None => return false,
    };
    let hex = crate::hexrep(h, false);
    WHITELIST_HEX.iter().any(|w| *w == hex)
        || RUNTIME_WATCH_HEX
            .lock()
            .map(|watch| watch.contains_key(&hex))
            .unwrap_or(false)
}

/// Temporarily enable announce/path log lines for `dest_hash`.
///
/// Multiple callers may watch the same destination concurrently; logging stays
/// enabled until the final matching [`unwatch_destination`] call.
pub fn watch_destination(dest_hash: &[u8]) {
    let hex = crate::hexrep(dest_hash, false);
    if let Ok(mut watch) = RUNTIME_WATCH_HEX.lock() {
        *watch.entry(hex).or_insert(0) += 1;
    }
}

/// Remove one temporary announce/path log watch for `dest_hash`.
pub fn unwatch_destination(dest_hash: &[u8]) {
    let hex = crate::hexrep(dest_hash, false);
    if let Ok(mut watch) = RUNTIME_WATCH_HEX.lock() {
        let remove = match watch.get_mut(&hex) {
            Some(count) if *count > 1 => {
                *count -= 1;
                false
            }
            Some(_) => true,
            None => false,
        };
        if remove {
            watch.remove(&hex);
        }
    }
}

pub fn count_inbound_announce() {
    INBOUND_ANNOUNCES_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn count_valid() {
    ANNOUNCES_VALID.fetch_add(1, Ordering::Relaxed);
}

pub fn count_invalid() {
    ANNOUNCES_INVALID.fetch_add(1, Ordering::Relaxed);
}

/// Increment when an inbound announce's Ed25519 validation was skipped
/// because we'd already validated this exact `packet_hash` (duplicate
/// re-broadcast). Cheap visibility into the dedup hit-rate.
pub fn count_dedup_skipped() {
    ANNOUNCES_DEDUP_SKIPPED.fetch_add(1, Ordering::Relaxed);
}

pub fn count_path_added() {
    PATHS_ADDED.fetch_add(1, Ordering::Relaxed);
}

/// Emit a single summary log line if `FLUSH_INTERVAL_SECS` has elapsed since
/// the last summary. Cheap when not due (one atomic load + comparison).
pub fn flush_if_due() {
    let now = now_secs();
    let last = LAST_FLUSH_SECS.load(Ordering::Relaxed);
    if last == 0 {
        // First call — initialise without emitting.
        LAST_FLUSH_SECS.store(now, Ordering::Relaxed);
        return;
    }
    if now.saturating_sub(last) < FLUSH_INTERVAL_SECS {
        return;
    }
    // Try to claim the flush slot. If another thread beat us, skip.
    if LAST_FLUSH_SECS
        .compare_exchange(last, now, Ordering::SeqCst, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let inbound = INBOUND_ANNOUNCES_TOTAL.swap(0, Ordering::Relaxed);
    let valid = ANNOUNCES_VALID.swap(0, Ordering::Relaxed);
    let invalid = ANNOUNCES_INVALID.swap(0, Ordering::Relaxed);
    let dedup = ANNOUNCES_DEDUP_SKIPPED.swap(0, Ordering::Relaxed);
    let paths = PATHS_ADDED.swap(0, Ordering::Relaxed);

    if inbound == 0 && valid == 0 && invalid == 0 && paths == 0 && dedup == 0 {
        return;
    }

    let interval = now.saturating_sub(last);
    // Counter relationships (so the line is interpretable at a glance):
    //   inbound  = every announce that entered Transport::inbound
    //   valid    = announces whose Ed25519 signature passed (or was
    //              short-circuited because we'd already verified the same
    //              packet_hash earlier — see `dedup_skipped`)
    //   invalid  = announces whose Ed25519 signature failed
    //   dedup_skipped ⊆ valid  (fast-path verify-skips counted here AND in valid)
    //   paths_added ≤ valid    (only fires when path table was actually mutated;
    //                           drops own-destination echoes and no-improvement updates)
    // So `inbound - (valid + invalid)` represents announces dropped before
    // signature check (e.g. data shorter than a public key).
    crate::log(
        format!(
            "[ANNOUNCE-SUMMARY] window={}s inbound={} valid={} invalid={} dedup_skipped={} paths_added={} ({:.1}/s)",
            interval,
            inbound,
            valid,
            invalid,
            dedup,
            paths,
            inbound as f64 / interval.max(1) as f64,
        ),
        crate::LOG_NOTICE,
        false,
        false,
    );
}

#[cfg(test)]
mod tests {
    use super::{is_whitelisted, unwatch_destination, watch_destination};

    #[test]
    fn runtime_watchlist_toggles_destination_logging() {
        let dest = [0x42u8; 16];
        assert!(!is_whitelisted(Some(&dest)));
        watch_destination(&dest);
        assert!(is_whitelisted(Some(&dest)));
        unwatch_destination(&dest);
        assert!(!is_whitelisted(Some(&dest)));
    }
}
