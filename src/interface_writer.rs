//! Per-interface writer actor.
//!
//! Each registered outbound handler is wrapped in a writer actor (one
//! background thread + one queue). `Transport::dispatch_outbound`
//! enqueues bytes onto this queue and returns immediately; the writer
//! thread drains the queue and invokes the underlying interface's
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
//! * If the writer will not take the frame, `enqueue` returns `false`.
//!   Callers treat this the same as "no handler" — the packet is dropped,
//!   but the system stays responsive.
//! * The interface's existing offline-on-write-failure logic (e.g. TCP
//!   marking itself offline and triggering reconnect) is preserved
//!   verbatim — the writer simply invokes the original handler.
//!
//! ## Two kinds of queue
//!
//! Most interfaces get a queue of `DEFAULT_WRITER_QUEUE_DEPTH` frames; a
//! full queue drops the frame (backpressure).
//!
//! A TCP connection's writer keeps stock RNS 1.5.2's egress control, the
//! rules its BackboneInterface applies to every TCP connection it writes
//! (RNS/Interfaces/BackboneInterface.py `_dp_ec_evaluate` and
//! `__dp_ec_job`, RNS/Interfaces/util/TransmitBuffer.py `append`,
//! RNS/Interfaces/Interface.py `tx_hwm`):
//!   * the queue is bounded in bytes, by `TX_HWM` (4 MiB), not by a number
//!     of frames, so a burst a live peer drains in a second or two is
//!     carried, not dropped;
//!   * at most once a `DP_EC_INTERVAL`, when it is offered a frame, the
//!     writer looks at how much the connection drained since its last look
//!     (`EgressGate::evaluate`). With more than `DP_EC_MID_WM` waiting and
//!     the backlog needing more than `DP_EC_MAX_ETA` to clear, or with no
//!     progress at all over `DP_EC_STALL_TICKS` looks, it gates: new frames
//!     are dropped until the backlog would clear within
//!     `DP_EC_RELEASE_ETA`, or falls to `DP_EC_MID_WM`;
//!   * a connection that takes no data at all for `DP_EC_DEAD_TIME` is torn
//!     down. The socket's write limit (SO_SNDTIMEO, set where the TCP
//!     interfaces open their sockets) makes that write fail, and the
//!     interface's write-failure path closes the connection, so a client
//!     redials and an accepted connection goes, as in the reference.
//!
//! The reference evaluates the gate on a one-second job; here the writer
//! makes the same look when it is next offered a frame, so nothing runs
//! while nothing is sent.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

/// Synchronous outbound handler signature, identical to what the rest of
/// the codebase uses. Returns `true` if the bytes were accepted by the
/// interface (this is the existing semantics; the writer thread treats
/// `false` as a transient failure, not a fatal one).
pub type OutboundHandler = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Default per-interface writer queue depth. Chosen to be large enough
/// for normal bursts (announces, link traffic) but small enough that a
/// wedged peer is detected within a few packets rather than minutes.
pub const DEFAULT_WRITER_QUEUE_DEPTH: usize = 64;

/// RNS/Interfaces/Interface.py `tx_hwm`: the most a connection may hold
/// queued and not yet taken by the socket.
pub const TX_HWM: u64 = 4 * 1024 * 1024;
/// RNS/Interfaces/BackboneInterface.py `DP_EC_INTERVAL`: how often the
/// drain is looked at.
pub const DP_EC_INTERVAL: Duration = Duration::from_secs(1);
/// `DP_EC_MID_WM`: a backlog up to this size is never gated.
pub const DP_EC_MID_WM: u64 = 128 * 1024;
/// `DP_EC_STALL_TICKS`: looks without any progress before gating.
pub const DP_EC_STALL_TICKS: u32 = 3;
/// `DP_EC_MAX_ETA`: seconds a backlog may need to clear before gating.
pub const DP_EC_MAX_ETA: f64 = 10.0;
/// `DP_EC_RELEASE_ETA`: seconds to clear under which the gate opens again.
pub const DP_EC_RELEASE_ETA: f64 = 5.0;
/// `DP_EC_DEAD_TIME`: a connection that takes no data at all for this long
/// is torn down. The TCP interfaces give their sockets this write limit.
pub const DP_EC_DEAD_TIME: Duration = Duration::from_secs(12);

/// Frame on the writer's channel.
enum WriterMsg {
    /// Bytes to send via the underlying handler.
    Send(Vec<u8>),
    /// Tear down the writer thread (sent by `unregister`).
    Shutdown,
}

/// What the gate did at one look (`EgressGate::evaluate`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum GateChange {
    Unchanged,
    /// Gated because the backlog needs this many seconds to clear.
    GatedSlowDrain(f64),
    /// Gated because nothing drained over `DP_EC_STALL_TICKS` looks.
    GatedNoDrain,
    Released,
}

/// The egress-control state of one TCP connection and the look the
/// reference takes at it once a second (BackboneInterface.py
/// `_dp_ec_evaluate`), but for the dead-time teardown, which the socket's
/// write limit makes (see the module notes).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct EgressGate {
    /// `_dp_ec_prev_sent`: bytes sent at the previous look.
    prev_sent: u64,
    /// `_dp_ec_zero_ticks`: looks in a row with no progress.
    zero_ticks: u32,
    /// `tx_stalled`: new frames are dropped while this holds.
    pub(crate) stalled: bool,
}

impl EgressGate {
    /// One look, `elapsed` seconds after the previous one, with `pending`
    /// bytes queued and not yet sent and `sent_total` bytes sent so far.
    /// The reference divides the drained bytes by `DP_EC_INTERVAL`, the
    /// spacing of its looks; here looks are at least that far apart, and
    /// the drained bytes are divided by the time that actually passed.
    pub(crate) fn evaluate(&mut self, pending: u64, sent_total: u64, elapsed: f64) -> GateChange {
        let was_stalled = self.stalled;
        let drained = sent_total.saturating_sub(self.prev_sent);
        self.prev_sent = sent_total;

        let mut slow_drain_eta = None;
        if pending == 0 {
            self.zero_ticks = 0;
            self.stalled = false;
        } else if drained > 0 {
            self.zero_ticks = 0;
            let drain_rate = drained as f64 / elapsed.max(f64::MIN_POSITIVE);
            let clear_eta = pending as f64 / drain_rate;
            if pending > DP_EC_MID_WM && clear_eta > DP_EC_MAX_ETA {
                self.stalled = true;
                slow_drain_eta = Some(clear_eta);
            } else if clear_eta < DP_EC_RELEASE_ETA || pending <= DP_EC_MID_WM {
                self.stalled = false;
            }
        } else if pending > DP_EC_MID_WM {
            self.zero_ticks += 1;
            if self.zero_ticks >= DP_EC_STALL_TICKS {
                self.stalled = true;
            }
        } else {
            self.zero_ticks = 0;
            self.stalled = false;
        }

        match (was_stalled, self.stalled) {
            (false, true) => match slow_drain_eta {
                Some(eta) => GateChange::GatedSlowDrain(eta),
                None => GateChange::GatedNoDrain,
            },
            (true, false) => GateChange::Released,
            _ => GateChange::Unchanged,
        }
    }
}

/// Byte accounting and gate of one egress-controlled writer.
struct Egress {
    /// Bytes accepted into the queue (TransmitBuffer `_tx_total`).
    queued: AtomicU64,
    /// Bytes the writer has handed to the interface (TransmitBuffer
    /// `_tx_sent`).
    sent: AtomicU64,
    look: Mutex<Look>,
}

struct Look {
    gate: EgressGate,
    at: Instant,
    dropped_frames: u64,
    dropped_bytes: u64,
}

impl Egress {
    fn new() -> Self {
        Egress {
            queued: AtomicU64::new(0),
            sent: AtomicU64::new(0),
            look: Mutex::new(Look {
                gate: EgressGate::default(),
                at: Instant::now(),
                dropped_frames: 0,
                dropped_bytes: 0,
            }),
        }
    }

    /// Queue `bytes` unless the gate is shut or the backlog would pass
    /// `TX_HWM` (TransmitBuffer.append with `limit`).
    fn admit(&self, name: &str, tx: &Sender<WriterMsg>, bytes: &[u8]) -> bool {
        let mut look = self.look.lock().unwrap();
        let sent = self.sent.load(Ordering::Acquire);
        let pending = self.queued.load(Ordering::Acquire).saturating_sub(sent);

        let now = Instant::now();
        let elapsed = now.duration_since(look.at);
        if elapsed >= DP_EC_INTERVAL {
            look.at = now;
            match look.gate.evaluate(pending, sent, elapsed.as_secs_f64()) {
                GateChange::Unchanged => {}
                GateChange::GatedSlowDrain(eta) => log(
                    &format!(
                        "Egress control drain ETA of {:.1}s exceeds maximum on {}, gating outbound ({} bytes waiting)",
                        eta, name, pending
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                ),
                GateChange::GatedNoDrain => log(
                    &format!(
                        "No egress control drain progress on {}, gating outbound ({} bytes waiting)",
                        name, pending
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                ),
                GateChange::Released => {
                    log(
                        &format!(
                            "Egress control drain recovered on {}, resuming outbound ({} frames, {} bytes dropped meanwhile)",
                            name, look.dropped_frames, look.dropped_bytes
                        ),
                        LOG_NOTICE,
                        false,
                        false,
                    );
                    look.dropped_frames = 0;
                    look.dropped_bytes = 0;
                }
            }
        }

        let len = bytes.len() as u64;
        if look.gate.stalled || pending + len > TX_HWM {
            look.dropped_frames += 1;
            look.dropped_bytes += len;
            log(
                &format!(
                    "[WRITER] egress control dropping outbound frame of {} bytes on {} ({} bytes waiting{})",
                    len,
                    name,
                    pending,
                    if look.gate.stalled { ", gated" } else { ", queue full" }
                ),
                LOG_DEBUG,
                false,
                false,
            );
            return false;
        }

        // Counted before it is sent, so the writer never reports more sent
        // than was queued.
        self.queued.fetch_add(len, Ordering::AcqRel);
        if tx.send(WriterMsg::Send(bytes.to_vec())).is_err() {
            self.queued.fetch_sub(len, Ordering::AcqRel);
            log(
                &format!("[WRITER] {} disconnected — frame dropped", name),
                LOG_WARNING,
                false,
                false,
            );
            return false;
        }
        true
    }
}

#[derive(Clone)]
enum Queue {
    /// A fixed number of frames.
    Frames(SyncSender<WriterMsg>),
    /// Stock egress control (TCP connections).
    Egress(Sender<WriterMsg>, Arc<Egress>),
}

/// Handle to a writer actor — cheap to clone, internally an `Arc` over the
/// channel sender.
#[derive(Clone)]
pub struct WriterHandle {
    name: String,
    queue: Queue,
}

impl WriterHandle {
    /// Spawn a writer thread for `name` that drains a channel of
    /// `queue_depth` frames and invokes `handler` for each frame. Returns a
    /// handle whose `enqueue` is the non-blocking send function to register
    /// with Transport.
    pub fn spawn(name: String, handler: OutboundHandler, queue_depth: usize) -> Self {
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(queue_depth);
        Self::run(name.clone(), handler, rx, None);
        WriterHandle { name, queue: Queue::Frames(tx) }
    }

    /// Spawn a writer thread for the TCP connection `name`, with the
    /// reference's egress control (see the module notes).
    pub fn spawn_with_egress_control(name: String, handler: OutboundHandler) -> Self {
        let (tx, rx) = mpsc::channel::<WriterMsg>();
        let egress = Arc::new(Egress::new());
        Self::run(name.clone(), handler, rx, Some(Arc::clone(&egress)));
        WriterHandle { name, queue: Queue::Egress(tx, egress) }
    }

    fn run(
        writer_name: String,
        handler: OutboundHandler,
        rx: Receiver<WriterMsg>,
        egress: Option<Arc<Egress>>,
    ) {
        thread::Builder::new()
            .name(format!("rns-writer-{}", writer_name))
            .spawn(move || {
                while let Ok(msg) = rx.recv() {
                    match msg {
                        WriterMsg::Send(bytes) => {
                            // Invoke the underlying interface handler.
                            // Any blocking happens here, on this thread,
                            // never on the caller's thread.
                            let _ = handler(&bytes);
                            if let Some(egress) = &egress {
                                egress.sent.fetch_add(bytes.len() as u64, Ordering::AcqRel);
                            }
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
    }

    /// Non-blocking enqueue. Returns `true` if the bytes were queued,
    /// `false` if the writer will not take them (a full frame queue, egress
    /// control's gate or byte limit) or the writer thread has shut down.
    pub fn enqueue(&self, bytes: &[u8]) -> bool {
        let tx = match &self.queue {
            Queue::Frames(tx) => tx,
            Queue::Egress(tx, egress) => return egress.admit(&self.name, tx, bytes),
        };
        match tx.try_send(WriterMsg::Send(bytes.to_vec())) {
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
        match &self.queue {
            Queue::Frames(tx) => {
                let _ = tx.try_send(WriterMsg::Shutdown);
            }
            Queue::Egress(tx, _) => {
                let _ = tx.send(WriterMsg::Shutdown);
            }
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Give a TCP connection's socket the reference's dead time as its write
/// limit (SO_SNDTIMEO). A write the peer lets take nothing for
/// `DP_EC_DEAD_TIME` then fails with `WouldBlock`, and the interface's
/// write-failure path tears the connection down, as the reference's egress
/// control does (BackboneInterface.py `_dp_ec_evaluate`). A write that
/// makes progress is not cut short; nothing changes while nothing is sent.
pub fn apply_tcp_write_limit(stream: &std::net::TcpStream) {
    if let Err(e) = stream.set_write_timeout(Some(DP_EC_DEAD_TIME)) {
        log(
            &format!("Could not give a TCP socket its write limit: {}", e),
            crate::LOG_ERROR,
            false,
            false,
        );
    }
}

/// The reference's notice for a connection torn down by its dead time.
pub fn dead_time_notice(interface: &str) -> String {
    format!(
        "No egress control drain progress for {}s on {}, tearing down",
        DP_EC_DEAD_TIME.as_secs(),
        interface
    )
}

// --- Registry ---------------------------------------------------------------

static WRITERS: once_cell::sync::Lazy<Mutex<HashMap<String, WriterHandle>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

fn insert(name: &str, writer: WriterHandle) -> WriterHandle {
    let mut writers = WRITERS.lock().unwrap();
    if let Some(old) = writers.insert(name.to_string(), writer.clone()) {
        old.shutdown();
    }
    writer
}

/// Register or replace the writer for `name`. The previous writer (if any)
/// is shut down so its thread exits cleanly.
pub fn register(name: &str, handler: OutboundHandler, queue_depth: usize) -> WriterHandle {
    insert(name, WriterHandle::spawn(name.to_string(), handler, queue_depth))
}

/// Register or replace the writer for the TCP connection `name`, with the
/// reference's egress control.
pub fn register_with_egress_control(name: &str, handler: OutboundHandler) -> WriterHandle {
    insert(name, WriterHandle::spawn_with_egress_control(name.to_string(), handler))
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

    /// The gateway, 2026-11-28: a transfer through it toward the
    /// discovered peer "murph" offered up to 1,153 Resource parts of 483
    /// bytes in one second while the connection's socket was briefly full.
    /// The 64-frame queue dropped all but 64 of them, on a peer that was
    /// draining. Under the reference's egress control the burst (557 KB)
    /// is far below `TX_HWM` and no look has found a slow drain yet, so
    /// every part is queued and, once the socket drains, written in order.
    #[test]
    fn a_tcp_writer_carries_a_burst_a_frame_queue_dropped() {
        const PARTS: usize = 1153;
        const PART_LEN: usize = 483;
        let hold = Arc::new(std::sync::Barrier::new(2));
        let hold_w = Arc::clone(&hold);
        let written = Arc::new(AtomicUsize::new(0));
        let written_w = Arc::clone(&written);
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let handler: OutboundHandler = Arc::new(move |bytes: &[u8]| {
            // The socket is full for the first frame, until the burst has
            // been offered; then it drains.
            if first.swap(false, Ordering::SeqCst) {
                hold_w.wait();
            }
            assert_eq!(bytes.len(), PART_LEN);
            written_w.fetch_add(1, Ordering::SeqCst);
            true
        });

        let writer = WriterHandle::spawn_with_egress_control("test-burst".to_string(), handler);
        let accepted = (0..PARTS).filter(|_| writer.enqueue(&[0x5a; PART_LEN])).count();
        assert_eq!(accepted, PARTS, "egress control must take the whole burst");
        hold.wait();

        let deadline = Instant::now() + Duration::from_secs(5);
        while written.load(Ordering::SeqCst) < PARTS && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(written.load(Ordering::SeqCst), PARTS);

        // The same burst at the old 64-frame queue: all but the held frame
        // and the 64 queued behind it are dropped.
        let hold = Arc::new(std::sync::Barrier::new(2));
        let hold_w = Arc::clone(&hold);
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let handler: OutboundHandler = Arc::new(move |_bytes: &[u8]| {
            if first.swap(false, Ordering::SeqCst) {
                hold_w.wait();
            }
            true
        });
        let frames = WriterHandle::spawn("test-burst-frames".to_string(), handler, DEFAULT_WRITER_QUEUE_DEPTH);
        assert!(frames.enqueue(&[0x5a; PART_LEN]));
        // Let the writer take the first frame into the held handler.
        thread::sleep(Duration::from_millis(50));
        let accepted = 1 + (1..PARTS).filter(|_| frames.enqueue(&[0x5a; PART_LEN])).count();
        assert_eq!(accepted, 1 + DEFAULT_WRITER_QUEUE_DEPTH);
        hold.wait();

        writer.shutdown();
        frames.shutdown();
    }

    /// A TCP connection's handler registered through Transport gets the
    /// egress-controlled writer, so the gateway's burst goes through
    /// `dispatch_outbound` whole; any other interface keeps its frame queue.
    #[test]
    fn transport_gives_a_tcp_connection_the_egress_controlled_writer() {
        const PARTS: usize = 1153;
        let burst = |name: &str, tcp: bool| -> usize {
            let hold = Arc::new(std::sync::Barrier::new(2));
            let hold_w = Arc::clone(&hold);
            let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let handler: OutboundHandler = Arc::new(move |_bytes: &[u8]| {
                if first.swap(false, Ordering::SeqCst) {
                    hold_w.wait();
                }
                true
            });
            if tcp {
                crate::transport::Transport::register_outbound_handler_with_egress_control(name, handler);
            } else {
                crate::transport::Transport::register_outbound_handler(name, handler);
            }
            assert!(crate::transport::Transport::dispatch_outbound(name, &[0x5a; 483]));
            thread::sleep(Duration::from_millis(50));
            let accepted = 1 + (1..PARTS)
                .filter(|_| crate::transport::Transport::dispatch_outbound(name, &[0x5a; 483]))
                .count();
            hold.wait();
            crate::transport::Transport::unregister_outbound_handler(name);
            accepted
        };
        assert_eq!(burst("test-transport-burst-tcp", true), PARTS);
        assert_eq!(burst("test-transport-burst-other", false), 1 + DEFAULT_WRITER_QUEUE_DEPTH);
    }

    /// TransmitBuffer.append's limit: a frame that would take the backlog
    /// past `TX_HWM` is refused, whatever the gate says; once the socket
    /// takes the backlog, frames are queued again.
    #[test]
    fn a_tcp_writer_refuses_a_frame_past_tx_hwm() {
        const FRAME: usize = 64 * 1024;
        let hold = Arc::new(std::sync::Barrier::new(2));
        let hold_w = Arc::clone(&hold);
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let handler: OutboundHandler = Arc::new(move |_bytes: &[u8]| {
            if first.swap(false, Ordering::SeqCst) {
                hold_w.wait();
            }
            true
        });
        let writer = WriterHandle::spawn_with_egress_control("test-hwm".to_string(), handler);
        let fits = (TX_HWM as usize) / FRAME;
        for i in 0..fits {
            assert!(writer.enqueue(&vec![0u8; FRAME]), "frame {} of {} must fit", i + 1, fits);
        }
        assert!(!writer.enqueue(&vec![0u8; FRAME]), "a frame past TX_HWM must be refused");
        assert!(!writer.enqueue(&[0u8; 1]), "even one byte past TX_HWM must be refused");
        hold.wait();

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut queued_again = false;
        while Instant::now() < deadline {
            if writer.enqueue(&vec![0u8; FRAME]) {
                queued_again = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(queued_again, "frames must be queued again once the backlog drains");
        writer.shutdown();
    }

    /// Vectors produced by stock RNS 1.5.2's own
    /// `BackboneInterface._dp_ec_evaluate` (tests/fixtures/egress_vectors.py,
    /// output in tests/fixtures/egress_vectors.txt). Each line is one
    /// connection's sequence of looks one `DP_EC_INTERVAL` apart:
    /// `pending,sent_total -> stalled` per look, `;`-separated, after a
    /// `name:` prefix. The port's gate must reach the same `stalled` at
    /// every look.
    #[test]
    fn the_gate_matches_the_reference_evaluation() {
        let vectors = include_str!("../tests/fixtures/egress_vectors.txt");
        let mut cases = 0;
        for line in vectors.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let (name, steps) = line.split_once(':').expect("name: steps");
            let mut gate = EgressGate::default();
            for (i, step) in steps.split(';').map(str::trim).filter(|s| !s.is_empty()).enumerate() {
                let (input, want) = step.split_once("->").expect("input -> stalled");
                let mut fields = input.trim().split(',').map(|f| f.trim().parse::<u64>().expect("number"));
                let pending = fields.next().unwrap();
                let sent = fields.next().unwrap();
                let want = match want.trim() {
                    "True" => true,
                    "False" => false,
                    other => panic!("{}: bad expectation {}", name, other),
                };
                gate.evaluate(pending, sent, DP_EC_INTERVAL.as_secs_f64());
                assert_eq!(gate.stalled, want, "{} look {}: pending={} sent={}", name, i + 1, pending, sent);
            }
            cases += 1;
        }
        assert!(cases >= 8, "expected the reference's vectors, found {} cases", cases);
    }

    /// A gate edge is reported once, with why it shut.
    #[test]
    fn the_gate_reports_its_edges() {
        let mut gate = EgressGate::default();
        // 1 MiB waiting, 50 KB drained in the last second: 20 s to clear.
        assert_eq!(gate.evaluate(1 << 20, 50_000, 1.0), GateChange::GatedSlowDrain(1048576.0 / 50_000.0));
        assert_eq!(gate.evaluate(1 << 20, 100_000, 1.0), GateChange::Unchanged);
        // Drained fast: 1 MiB in a second, 64 KiB left.
        assert_eq!(gate.evaluate(64 * 1024, 100_000 + (1 << 20), 1.0), GateChange::Released);
        // Nothing drains with 200 KiB waiting: gated at the third look.
        let sent = 100_000 + (1 << 20);
        assert_eq!(gate.evaluate(200 * 1024, sent, 1.0), GateChange::Unchanged);
        assert_eq!(gate.evaluate(200 * 1024, sent, 1.0), GateChange::Unchanged);
        assert_eq!(gate.evaluate(200 * 1024, sent, 1.0), GateChange::GatedNoDrain);
        // The backlog is taken: open.
        assert_eq!(gate.evaluate(0, sent + 200 * 1024, 1.0), GateChange::Released);
    }
}
