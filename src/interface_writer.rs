//! Per-interface writer actor.
//!
//! Each registered outbound handler is wrapped in a writer actor (one
//! background thread + one bounded mpsc channel). `Transport::dispatch_outbound`
//! enqueues bytes onto this channel and returns immediately; the writer
//! thread drains the channel and invokes the underlying interface's
//! synchronous send function (typically `socket.write_all` or equivalent).
//!
//! ## Why
//!
//! Before this layer existed, `dispatch_outbound` invoked the interface
//! handler synchronously while the global `TRANSPORT` mutex was held by the
//! caller (`Transport::outbound`). A wedged TCP peer could therefore stall:
//!   * the link actor whose request triggered the send,
//!   * the FFI / UI thread waiting on that actor,
//!   * every other thread that needed `TRANSPORT.lock()`,
//!   * every other interface trying to send.
//!
//! The writer actor decouples I/O latency from routing logic: a stuck
//! socket only stalls its own writer thread. Other interfaces, other
//! links, and the rest of the system continue unaffected.
//!
//! ## Determinism contract
//!
//! * `enqueue` returns within microseconds (a single channel send), never
//!   within socket-RTT time.
//! * If the writer's queue is full, `enqueue` returns `false`. Callers
//!   treat this the same as "no handler" — the packet is dropped, but the
//!   system stays responsive. This is the backpressure signal: a wedged
//!   peer manifests as backpressure rather than a hang.
//! * The writer thread itself may block on a slow socket; that is bounded
//!   by the queue depth above (no more than `WRITER_QUEUE_DEPTH` packets
//!   can be in flight per interface) and ultimately by the OS TCP timeout
//!   when the peer is fully dead.
//! * The interface's existing offline-on-write-failure logic (e.g. TCP
//!   marking itself offline and triggering reconnect) is preserved
//!   verbatim — the writer simply invokes the original handler.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;

use crate::{log, LOG_NOTICE, LOG_WARNING};

/// Synchronous outbound handler signature, identical to what the rest of
/// the codebase uses. Returns `true` if the bytes were accepted by the
/// interface (this is the existing semantics; the writer thread treats
/// `false` as a transient failure, not a fatal one).
pub type OutboundHandler = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Default per-interface writer queue depth. Chosen to be large enough
/// for normal bursts (announces, link traffic) but small enough that a
/// wedged peer is detected within a few packets rather than minutes.
pub const DEFAULT_WRITER_QUEUE_DEPTH: usize = 64;

/// Frame on the writer's mpsc channel.
enum WriterMsg {
    /// Bytes to send via the underlying handler.
    Send(Vec<u8>),
    /// Tear down the writer thread (sent by `unregister`).
    Shutdown,
}

/// Handle to a writer actor — cheap to clone, internally an `Arc` over the
/// channel sender.
#[derive(Clone)]
pub struct WriterHandle {
    name: String,
    tx: SyncSender<WriterMsg>,
}

impl WriterHandle {
    /// Spawn a writer thread for `name` that drains a bounded channel and
    /// invokes `handler` for each frame. Returns a handle whose `enqueue`
    /// is the non-blocking send function to register with Transport.
    pub fn spawn(name: String, handler: OutboundHandler, queue_depth: usize) -> Self {
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(queue_depth);
        let writer_name = name.clone();
        thread::Builder::new()
            .name(format!("rns-writer-{}", name))
            .spawn(move || {
                while let Ok(msg) = rx.recv() {
                    match msg {
                        WriterMsg::Send(bytes) => {
                            // Invoke the underlying interface handler.
                            // Any blocking happens here, on this thread,
                            // never on the caller's thread.
                            let _ = handler(&bytes);
                        }
                        WriterMsg::Shutdown => break,
                    }
                }
                log(
                    &format!("[WRITER] thread for {} exiting", writer_name),
                    LOG_NOTICE,
                    false,
                    false,
                );
            })
            .expect("failed to spawn interface writer thread");

        WriterHandle { name, tx }
    }

    /// Non-blocking enqueue. Returns `true` if the bytes were queued,
    /// `false` if the writer's queue is full (backpressure) or the writer
    /// thread has shut down.
    pub fn enqueue(&self, bytes: &[u8]) -> bool {
        match self.tx.try_send(WriterMsg::Send(bytes.to_vec())) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                log(
                    &format!(
                        "[WRITER] backpressure on {} — dropping {} byte frame",
                        self.name,
                        bytes.len()
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                log(
                    &format!("[WRITER] {} disconnected — frame dropped", self.name),
                    LOG_WARNING,
                    false,
                    false,
                );
                false
            }
        }
    }

    /// Signal the writer thread to exit. Idempotent — extra shutdowns are
    /// silently ignored.
    pub fn shutdown(&self) {
        let _ = self.tx.try_send(WriterMsg::Shutdown);
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

// --- Registry ---------------------------------------------------------------

static WRITERS: once_cell::sync::Lazy<Mutex<HashMap<String, WriterHandle>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Register or replace the writer for `name`. The previous writer (if any)
/// is shut down so its thread exits cleanly.
pub fn register(name: &str, handler: OutboundHandler, queue_depth: usize) -> WriterHandle {
    let writer = WriterHandle::spawn(name.to_string(), handler, queue_depth);
    let mut writers = WRITERS.lock().unwrap();
    if let Some(old) = writers.insert(name.to_string(), writer.clone()) {
        old.shutdown();
    }
    writer
}

/// Unregister and shut down the writer for `name`, if any.
pub fn unregister(name: &str) {
    let mut writers = WRITERS.lock().unwrap();
    if let Some(writer) = writers.remove(name) {
        writer.shutdown();
    }
}

/// Look up a writer by interface name (used by `Transport::dispatch_outbound`).
pub fn get(name: &str) -> Option<WriterHandle> {
    WRITERS.lock().unwrap().get(name).cloned()
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// A handler that blocks forever on the first call must not block the
    /// caller of `enqueue` more than the time it takes to send on the
    /// channel.
    #[test]
    fn enqueue_does_not_block_on_wedged_handler() {
        let started = Arc::new(std::sync::Barrier::new(2));
        let started_w = Arc::clone(&started);
        let handler: OutboundHandler = Arc::new(move |_bytes: &[u8]| {
            // Tell the test thread we've started, then sleep "forever".
            started_w.wait();
            thread::sleep(Duration::from_secs(60));
            true
        });

        let writer = WriterHandle::spawn("test-wedged".to_string(), handler, 4);

        // First enqueue picks up the writer thread; it will wedge on sleep.
        assert!(writer.enqueue(b"first"));
        started.wait();

        // The wedged handler holds frame #1. Subsequent enqueues fill the
        // bounded buffer (capacity 4) without blocking.
        let t0 = Instant::now();
        for _ in 0..4 {
            assert!(writer.enqueue(b"queued"));
        }
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "enqueue took too long ({:?}) — should be non-blocking",
            t0.elapsed()
        );

        // Now the buffer is full; the next enqueue must return false
        // (backpressure) instead of blocking.
        let t1 = Instant::now();
        assert!(!writer.enqueue(b"backpressured"));
        assert!(
            t1.elapsed() < Duration::from_millis(50),
            "backpressured enqueue took too long ({:?})",
            t1.elapsed()
        );

        writer.shutdown();
    }

    /// Confirm that bytes pass through to the handler and that a fast
    /// handler drains the queue correctly.
    #[test]
    fn handler_receives_enqueued_bytes_in_order() {
        let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let received_w = Arc::clone(&received);
        let handler: OutboundHandler = Arc::new(move |bytes: &[u8]| {
            received_w.lock().unwrap().push(bytes.to_vec());
            true
        });

        let writer = WriterHandle::spawn("test-fast".to_string(), handler, 16);
        for i in 0..10u8 {
            assert!(writer.enqueue(&[i]));
        }

        // Wait briefly for the writer thread to drain.
        for _ in 0..100 {
            if received.lock().unwrap().len() == 10 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        let got = received.lock().unwrap().clone();
        assert_eq!(got.len(), 10, "expected 10 frames, got {}", got.len());
        for (i, frame) in got.iter().enumerate() {
            assert_eq!(frame.as_slice(), &[i as u8]);
        }

        writer.shutdown();
    }

    /// Registering a writer for an existing name shuts down the old one
    /// and replaces it.
    #[test]
    fn re_register_replaces_writer() {
        let n_a = Arc::new(AtomicUsize::new(0));
        let n_a_w = Arc::clone(&n_a);
        let handler_a: OutboundHandler = Arc::new(move |_| {
            n_a_w.fetch_add(1, Ordering::SeqCst);
            true
        });

        let n_b = Arc::new(AtomicUsize::new(0));
        let n_b_w = Arc::clone(&n_b);
        let handler_b: OutboundHandler = Arc::new(move |_| {
            n_b_w.fetch_add(1, Ordering::SeqCst);
            true
        });

        let writer_a = register("test-replace", handler_a, 4);
        writer_a.enqueue(b"x");
        thread::sleep(Duration::from_millis(20));

        let writer_b = register("test-replace", handler_b, 4);
        writer_b.enqueue(b"y");
        thread::sleep(Duration::from_millis(20));

        assert_eq!(n_a.load(Ordering::SeqCst), 1, "handler A should have run once");
        assert_eq!(n_b.load(Ordering::SeqCst), 1, "handler B should have run once");

        unregister("test-replace");
    }
}
