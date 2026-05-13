// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
//
// 5-second late-success assertion.
//
// If a network send's success callback fires later than 5 seconds after the
// send was initiated, the code is wrong (not the network). The late success
// is masking an upstream ordering, blocking, or readiness bug.
//
// Debug builds panic so the bug cannot be ignored. Release builds log a
// loud structured error so production deployments still surface the
// regression without taking the process down.

use std::time::{SystemTime, UNIX_EPOCH};

/// Hard limit. Do not raise. See DESIGN_PRINCIPLES.md §1 and §3.
pub const SEND_LATENCY_LIMIT_SECS: f64 = 5.0;

#[inline]
fn unix_now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Assert that a send's success callback fired within the 5-second budget.
///
/// `label` identifies the send-type (e.g. "lxmf.direct", "link.establish",
/// "lxmf.propagation.offer") and appears in panic / error output.
///
/// `sent_at_unix_secs` is the unix timestamp captured the moment the send
/// was initiated. Pass `0.0` to skip (send time unknown — log only).
pub fn assert_send_completed_in_time(label: &str, sent_at_unix_secs: f64) {
    if sent_at_unix_secs <= 0.0 {
        return;
    }
    let elapsed = unix_now_seconds() - sent_at_unix_secs;
    if elapsed <= SEND_LATENCY_LIMIT_SECS {
        return;
    }

    let msg = format!(
        "DESIGN_PRINCIPLES §1 VIOLATION: send '{}' succeeded after {:.2}s \
         (limit {:.1}s). A late success is not a success — fix the upstream \
         ordering / readiness bug, do not raise the limit.",
        label, elapsed, SEND_LATENCY_LIMIT_SECS
    );

    #[cfg(debug_assertions)]
    {
        panic!("{}", msg);
    }
    #[cfg(not(debug_assertions))]
    {
        eprintln!("[SEND-ASSERT] {}", msg);
        crate::log(&msg, crate::LOG_ERROR, false, false);
    }
}
