//! App-link primitive.
//!
//! Phase 3 of the app-link hardening work: lifts the spec, registry and
//! lifecycle for "open chat-screen" style proactive links out of LXMF and
//! into Reticulum-rust so that any crate (rfed-channel, rfed-notify, …)
//! can register an app-link without depending on `LXMRouter`.
//!
//! Triggers (carried over verbatim from the LXMF Phase 1b implementation):
//!   * `AppLinks::open(...)`             — host explicitly opens / re-opens
//!   * `AppLinks::announce_received(...)`— announce arrived for the dest
//!   * `AppLinks::network_changed()`     — host signalled network state flip
//!   * post-ACTIVE drop                  — exactly ONE auto-retry from the
//!                                         link_closed callback when a link
//!                                         that previously reached ACTIVE
//!                                         goes down. Further attempts
//!                                         require one of the triggers above.
//!
//! `attempt_in_flight` per spec collapses overlapping triggers to a single LR.
//!
//! Hosts that need to mirror link state into their own bookkeeping (e.g.
//! LXMF's `direct_links` for the DIRECT-send picker) register a
//! [`AppLinkStatusCallback`]; the registry fires it whenever a link is
//! attached / detached for an app-link destination.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use crate::destination::Destination;
use crate::link::{Link, LinkHandle, MODE_AES256_CBC, STATE_ACTIVE, STATE_HANDSHAKE, STATE_PENDING};
use crate::transport::{AnnounceCallback, AnnounceHandler, Transport};
use crate::{hexrep, log, LOG_ERROR, LOG_NOTICE};

/// Maximum number of in-flight outbound LRs we'll race per app-link
/// destination. Set to 2 to bound the cost: with this cap we trade exactly
/// one extra LR (and one extra inbound `Link` on the daemon, torn down
/// immediately on win) per cold-start in exchange for not waiting on the
/// per-hop establishment timeout when a fresher path arrives mid-LR.
///
/// Why not 3+? Each racer is one full ECDH handshake the daemon has to
/// process plus a ~6 s × hops watchdog if we forget to teardown. Two
/// racers cover the only scenarios that matter today (cached/incumbent vs
/// announce-supplied better path; or first-trigger-no-path, request_path,
/// then pre-ACTIVE arrival of an improved announce). Any deeper racing is
/// CPU/wire overhead with diminishing returns.
const MAX_RACERS_PER_DEST: usize = 2;

/// Monotonic per-process racer ID. Each racer LinkHandle gets a unique ID
/// so its callbacks can identify themselves in the `racers` table without
/// relying on `LinkHandle` equality (which isn't defined).
static NEXT_RACER_ID: AtomicU64 = AtomicU64::new(1);

// ─── Public status constants ────────────────────────────────────────────
pub const APP_LINK_NONE: u8 = 0x00;
pub const APP_LINK_PATH_REQUESTED: u8 = 0x01;
pub const APP_LINK_ESTABLISHING: u8 = 0x02;
pub const APP_LINK_ACTIVE: u8 = 0x03;
pub const APP_LINK_DISCONNECTED: u8 = 0x04;

/// Host lifecycle policy that gates which triggers are allowed to attempt
/// new link establishments. Set via [`AppLinks::set_policy`] from the host
/// (iOS app lifecycle hooks, Android Lifecycle observer, etc.).
///
/// Default is [`LinkPolicy::Foreground`].
///
/// Trigger gate matrix (✓ = fires, ✗ = no-op):
///
/// | trigger                        | Foreground | Background | Suspended |
/// |--------------------------------|:----------:|:----------:|:---------:|
/// | `open()`                       |     ✓      |     ✓      |     ✗     |
/// | `announce_received()`          |     ✓      |     ✓      |     ✗     |
/// | `network_changed()`            |     ✓      |     ✗      |     ✗     |
/// | post-ACTIVE auto-retry (close) |     ✓      |     ✗      |     ✗     |
///
/// `Background` keeps existing links and still reacts to push announces
/// (cheap — peer is already alive) but never spends battery on a
/// network-change retry storm. `Suspended` tears down all tracked links
/// when entered; transitioning back to `Foreground` or `Background` fires a
/// network-change-style attempt for every registered destination so links
/// re-form on resume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkPolicy {
	Foreground,
	Background,
	Suspended,
}

impl Default for LinkPolicy {
	fn default() -> Self { LinkPolicy::Foreground }
}

/// Callback fired by the registry whenever an app-link's tracked
/// `LinkHandle` changes state in a way the host cares about.
///
/// `(dest_hash, status, link)` — `link` is `Some` when the registry has a
/// live `LinkHandle` for the destination (status `APP_LINK_ESTABLISHING` or
/// `APP_LINK_ACTIVE`), `None` when the link has just been detached
/// (`APP_LINK_DISCONNECTED` / `APP_LINK_NONE`).
pub type AppLinkStatusCallback = Arc<dyn Fn(&[u8], u8, Option<LinkHandle>) + Send + Sync>;

/// Per-destination state held by the registry.
#[derive(Clone)]
pub struct AppLinkSpec {
	pub app_name: String,
	pub aspects: Vec<String>,
	/// True from the moment `establish` decides to attempt until the
	/// link callback fires (either established or closed).
	pub attempt_in_flight: Arc<AtomicBool>,
	/// True once this link has reached ACTIVE at least once since open.
	pub ever_established: Arc<AtomicBool>,
}

impl AppLinkSpec {
	pub fn new(app_name: impl Into<String>, aspects: Vec<String>) -> Self {
		Self {
			app_name: app_name.into(),
			aspects,
			attempt_in_flight: Arc::new(AtomicBool::new(false)),
			ever_established: Arc::new(AtomicBool::new(false)),
		}
	}
}

struct Registry {
	specs: HashMap<Vec<u8>, AppLinkSpec>,
	/// LinkHandle currently tracked as the *winner* for an app-link
	/// destination — populated only when an outbound LR for this dest has
	/// reached `STATE_ACTIVE`. Until then the handle (or handles, plural,
	/// when racing) live in `racers`. Inbound peer-initiated links live in
	/// the host (e.g. LXMF's `backchannel_links`), not here.
	links: HashMap<Vec<u8>, LinkHandle>,
	/// In-flight outbound LRs per destination, capped by
	/// [`MAX_RACERS_PER_DEST`]. The first racer's `link_established`
	/// callback to fire wins, gets promoted into `links`, and the
	/// remaining racers are torn down. Pre-ACTIVE close of an individual
	/// racer just removes it from this list without disturbing siblings.
	racers: HashMap<Vec<u8>, Vec<Racer>>,
	status_callbacks: Vec<AppLinkStatusCallback>,
	/// Set once the announce handler has been registered with `Transport`.
	announce_handler_installed: bool,
	/// Host lifecycle policy. Gates trigger-driven establishments — see
	/// [`LinkPolicy`].
	policy: LinkPolicy,
}

impl Registry {
	fn new() -> Self {
		Self {
			specs: HashMap::new(),
			links: HashMap::new(),
			racers: HashMap::new(),
			status_callbacks: Vec::new(),
			announce_handler_installed: false,
			policy: LinkPolicy::Foreground,
		}
	}
}

/// One in-flight LR being raced toward a destination.
///
/// `id` is unique within the process and is the only stable identity for
/// a `LinkHandle` available to closures (LinkHandle has no `Eq`).
/// `hops` records the path hop-count *at the time the racer was
/// spawned* — used by `establish()` to gate spawning new racers: a fresh
/// announce only spawns a 2nd racer if its current path is strictly
/// shorter than every existing racer's. Without this gate, two announces
/// arriving over the same path waste one of the two racer slots on a
/// duplicate LR (observed in retichat.log 2026-04-30 17:42:46/48).
struct Racer {
	id: u64,
	handle: LinkHandle,
	hops: u8,
	/// Name of the interface the LR was emitted on at spawn time.
	/// Used by the same-hops tie rule in `establish()` so we don't
	/// burn racer slots on a duplicate path down the same upstream
	/// (observed retichat.log 2026-04-30 22:45:32-22:45:52: both
	/// racers went out London and we paid two LR-timeouts before a
	/// re-announce gave us RMap, where the link came up in <1s).
	interface: Option<String>,
}

static REGISTRY: Lazy<Mutex<Registry>> = Lazy::new(|| Mutex::new(Registry::new()));

/// Public façade.
pub struct AppLinks;

impl AppLinks {
	// ─── Host integration ────────────────────────────────────────────────

	/// Subscribe to status changes.  Multiple callbacks are supported.
	/// Callbacks are invoked synchronously from whichever thread the
	/// underlying link callback runs on (link actor thread).  Implementers
	/// must NOT block.
	pub fn register_status_callback(callback: AppLinkStatusCallback) {
		let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
		reg.status_callbacks.push(callback);
	}

	/// Current host lifecycle policy.  Defaults to [`LinkPolicy::Foreground`].
	pub fn policy() -> LinkPolicy {
		REGISTRY
			.lock()
			.map(|r| r.policy)
			.unwrap_or(LinkPolicy::Foreground)
	}

	/// Update the host lifecycle policy.
	///
	/// Side effects:
	///   * Entering [`LinkPolicy::Suspended`] tears down every tracked link
	///     immediately (specs are kept; links re-form on the next non-Suspended
	///     trigger). Status callbacks fire `APP_LINK_DISCONNECTED` for each.
	///   * Leaving [`LinkPolicy::Suspended`] (to Foreground or Background)
	///     fires a network-change-style attempt for every registered
	///     destination so links re-establish on resume.
	pub fn set_policy(policy: LinkPolicy) {
		let prev = {
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			let prev = reg.policy;
			reg.policy = policy;
			prev
		};
		if prev == policy {
			return;
		}
		log(
			&format!("[APP_LINK] policy {:?} -> {:?}", prev, policy),
			LOG_NOTICE, false, false,
		);
		match policy {
			LinkPolicy::Suspended => {
				// Tear down everything.
				for dest in Self::destinations() {
					Self::detach_link(&dest, /*notify*/ true);
				}
			}
			LinkPolicy::Foreground | LinkPolicy::Background => {
				if prev == LinkPolicy::Suspended {
					// Resume: re-attempt every registered destination using
					// the network-change code path. network_changed() itself
					// is gated on policy below, so call the inner helper
					// directly via a fresh trigger after the policy is set.
					Self::resume_attempts();
				}
			}
		}
	}

	/// Internal: identical fan-out to `network_changed` but unconditional
	/// (used by `set_policy` to drive re-establishment on resume regardless
	/// of which non-Suspended policy we resumed into).
	fn resume_attempts() {
		let candidates: Vec<Vec<u8>> = Self::destinations()
			.into_iter()
			.filter(|h| {
				let s = Self::status(h);
				s != APP_LINK_ACTIVE && s != APP_LINK_ESTABLISHING
			})
			.collect();
		if candidates.is_empty() {
			return;
		}
		let (with_path, without_path): (Vec<_>, Vec<_>) = candidates
			.into_iter()
			.partition(|d| Transport::has_path(d));
		if !with_path.is_empty() {
			log(
				&format!("[APP_LINK] policy resume → attempting {} link(s)", with_path.len()),
				LOG_NOTICE, false, false,
			);
			for dest in &with_path {
				Self::establish(dest);
			}
		}
		for dest in &without_path {
			log(
				&format!("[APP_LINK] policy resume: no path → requesting for {}", hexrep(dest, false)),
				LOG_NOTICE, false, false,
			);
			Transport::request_path(dest, None, None, None, None);
		}
	}

	/// True when `dest_hash` is currently registered as an app-link.
	pub fn contains(dest_hash: &[u8]) -> bool {
		REGISTRY
			.lock()
			.map(|r| r.specs.contains_key(dest_hash))
			.unwrap_or(false)
	}

	/// Snapshot of all currently-registered app-link destination hashes.
	pub fn destinations() -> Vec<Vec<u8>> {
		REGISTRY
			.lock()
			.map(|r| r.specs.keys().cloned().collect())
			.unwrap_or_default()
	}

	/// Returns the `AppLinkSpec` for `dest_hash` if registered.  Cheap clone.
	pub fn spec(dest_hash: &[u8]) -> Option<AppLinkSpec> {
		REGISTRY.lock().ok().and_then(|r| r.specs.get(dest_hash).cloned())
	}

	// ─── Public lifecycle ───────────────────────────────────────────────

	/// Open an app link for `dest_hash`.
	///
	/// Adds the destination to the registry (with its app/aspects so we can
	/// resolve the right identity on every (re)establishment), ensures the
	/// global announce handler is installed, ensures the dest is watched on
	/// Transport, and kicks off path-request / link-establishment as far as
	/// current state allows.  Returns immediately.
	pub fn open(dest_hash: &[u8], app_name: &str, aspects: &[&str]) {
		Self::ensure_announce_handler();

		let spec = AppLinkSpec::new(
			app_name,
			aspects.iter().map(|s| (*s).to_string()).collect(),
		);

		// Capture state BEFORE the spec insertion so we can distinguish
		// "first-ever open" (status NONE — must kick off path request) from
		// "subsequent piled-up open" (status PATH_REQUESTED — already in
		// flight, must be a no-op).
		let als_before = Self::status(dest_hash);

		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.specs.insert(dest_hash.to_vec(), spec);
		}

		Transport::watch_announce(dest_hash.to_vec());

		// Suspended: record the spec but do not attempt establishment.
		// On resume the next non-Suspended `set_policy` call fires attempts.
		if Self::policy() == LinkPolicy::Suspended {
			return;
		}

		// If the link is already active, mid-establishment, or a path
		// request is already pending, leave it alone.
		if als_before == APP_LINK_ACTIVE
			|| als_before == APP_LINK_ESTABLISHING
			|| als_before == APP_LINK_PATH_REQUESTED
		{
			return;
		}

		// Clean any stale/closed link entry before trying fresh.
		Self::detach_link(dest_hash, /*notify*/ false);

		if Transport::has_path(dest_hash) {
			Self::establish(dest_hash);
		} else {
			log(
				&format!("[APP_LINK] No path → requesting for {}", hexrep(dest_hash, false)),
				LOG_NOTICE, false, false,
			);
			Transport::request_path(dest_hash, None, None, None, None);
		}
	}

	/// Close an app link.  Removes the destination from the registry, tears
	/// down the winner link AND any in-flight racers, and fires a `NONE`
	/// status callback.
	pub fn close(dest_hash: &[u8]) {
		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.specs.remove(dest_hash);
		}
		Self::teardown_all_racers(dest_hash);
		Self::detach_link(dest_hash, /*notify*/ true);
	}

	/// Snapshot status for `dest_hash`.  See `APP_LINK_*` constants.
	///
	/// Racing-aware: if the winner slot (`links`) holds an ACTIVE handle
	/// we report ACTIVE; otherwise if there are any in-flight racers we
	/// report ESTABLISHING; otherwise we fall back to the path-availability
	/// classification.
	pub fn status(dest_hash: &[u8]) -> u8 {
		let reg = match REGISTRY.lock() {
			Ok(g) => g,
			Err(_) => return APP_LINK_NONE,
		};
		if !reg.specs.contains_key(dest_hash) {
			return APP_LINK_NONE;
		}
		if let Some(arc) = reg.links.get(dest_hash) {
			let s = arc.status();
			if s == STATE_ACTIVE {
				return APP_LINK_ACTIVE;
			}
			if s == STATE_PENDING || s == STATE_HANDSHAKE {
				return APP_LINK_ESTABLISHING;
			}
			// Winner slot holds a CLOSED handle (rare race window between
			// closed-callback fire and registry cleanup). Fall through to
			// the racers / path check below.
		}
		if reg.racers.get(dest_hash).map(|v| !v.is_empty()).unwrap_or(false) {
			return APP_LINK_ESTABLISHING;
		}
		if Transport::has_path(dest_hash) {
			APP_LINK_DISCONNECTED
		} else {
			APP_LINK_PATH_REQUESTED
		}
	}

	/// Get a clone of the LinkHandle currently tracked for `dest_hash`.
	pub fn get_handle(dest_hash: &[u8]) -> Option<LinkHandle> {
		REGISTRY.lock().ok().and_then(|r| r.links.get(dest_hash).cloned())
	}

	// ─── External triggers ──────────────────────────────────────────────

	/// Trigger one fresh app-link attempt for `dest_hash` on the strength
	/// of a fresh announce.  No-op if no entry exists, link is already
	/// active, or the racer cap is full.
	///
	/// Note: ESTABLISHING is NOT a bail condition with bounded racing.
	/// When a fresh announce arrives mid-LR, we want to spawn a 2nd racer
	/// down the new path (subject to [`MAX_RACERS_PER_DEST`]) so the path
	/// improvement isn't gated on the in-flight LR completing first. The
	/// cap check inside [`establish`] enforces the bound.
	pub fn announce_received(dest_hash: &[u8]) {
		if !Self::contains(dest_hash) {
			return;
		}
		if Self::policy() == LinkPolicy::Suspended {
			return;
		}
		if Self::status(dest_hash) == APP_LINK_ACTIVE {
			return;
		}
		// NOTE: do NOT log "announce trigger" here. Two separate Transport
		// announce handlers (the global app_links one + a per-aspect LXMF
		// reconnect handler) can fan in to this function for the same
		// inbound announce; only one of them will win the in_flight gate in
		// `establish()`. Logging here produces misleading duplicate lines
		// (observed in retichat.log Apr 2026). Let `establish()` log when
		// it actually proceeds.
		Self::establish(dest_hash);
	}

	/// Trigger one fresh attempt for every app-link not currently
	/// active/establishing.  Call from the host on a network state change.
	pub fn network_changed() {
		if Self::policy() != LinkPolicy::Foreground {
			return;
		}
		let candidates: Vec<Vec<u8>> = Self::destinations()
			.into_iter()
			.filter(|h| {
				let s = Self::status(h);
				s != APP_LINK_ACTIVE && s != APP_LINK_ESTABLISHING
			})
			.collect();
		if candidates.is_empty() {
			return;
		}
		let (with_path, without_path): (Vec<_>, Vec<_>) = candidates
			.into_iter()
			.partition(|d| Transport::has_path(d));
		if !with_path.is_empty() {
			log(
				&format!("[APP_LINK] network-change trigger → attempting {} link(s)", with_path.len()),
				LOG_NOTICE, false, false,
			);
			for dest in &with_path {
				Self::establish(dest);
			}
		}
		for dest in &without_path {
			log(
				&format!("[APP_LINK] network-change: no path → requesting for {}", hexrep(dest, false)),
				LOG_NOTICE, false, false,
			);
			Transport::request_path(dest, None, None, None, None);
		}
	}

	// ─── Internals ──────────────────────────────────────────────────────

	/// Tear down (if present) and remove the winner LinkHandle for
	/// `dest_hash`.  When `notify` is true, fires a status callback so
	/// hosts can drop their mirror entries.
	///
	/// Does NOT touch racers — callers that need a full wipe (e.g.
	/// [`close`]) must call [`teardown_all_racers`] first.
	fn detach_link(dest_hash: &[u8], notify: bool) {
		let removed = {
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.links.remove(dest_hash)
		};
		if let Some(handle) = removed {
			handle.set_link_closed_callback(None);
			handle.set_link_established_callback(None);
			handle.teardown();
		}
		if notify {
			let cbs: Vec<AppLinkStatusCallback> = REGISTRY
				.lock()
				.map(|r| r.status_callbacks.clone())
				.unwrap_or_default();
			for cb in &cbs {
				cb(dest_hash, APP_LINK_NONE, None);
			}
		}
	}

	/// Tear down every in-flight racer for `dest_hash` and clear the
	/// `racers` slot. Used by [`close`].
	///
	/// Callbacks are detached BEFORE `teardown()` so the loser's
	/// `link_closed` doesn't re-enter the registry mutating logic. We
	/// have already removed them from `racers` under the lock so even if
	/// a stray callback fires it will find nothing to remove.
	fn teardown_all_racers(dest_hash: &[u8]) {
		let drained: Vec<Racer> = {
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.racers.remove(dest_hash).unwrap_or_default()
		};
		for racer in drained {
			racer.handle.set_link_closed_callback(None);
			racer.handle.set_link_established_callback(None);
			racer.handle.teardown();
		}
	}

	/// Tear down every racer for `dest_hash` EXCEPT the one identified by
	/// `winner_id`. Used by the winner-promotion path in the
	/// link-established callback.
	fn teardown_losing_racers(dest_hash: &[u8], winner_id: u64) {
		let losers: Vec<Racer> = {
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			match reg.racers.get_mut(dest_hash) {
				Some(v) => {
					let (winners, losers): (Vec<_>, Vec<_>) =
						v.drain(..).partition(|r| r.id == winner_id);
					// Re-insert the winner so callers (e.g. status())
					// continue to observe the in-flight set as non-empty
					// until it's promoted into `links`.
					for w in winners {
						v.push(w);
					}
					losers
				}
				None => Vec::new(),
			}
		};
		if !losers.is_empty() {
			log(
				&format!(
					"[APP_LINK] tearing down {} losing racer(s) for {}",
					losers.len(),
					hexrep(dest_hash, false)
				),
				LOG_NOTICE, false, false,
			);
		}
		for racer in losers {
			racer.handle.set_link_closed_callback(None);
			racer.handle.set_link_established_callback(None);
			racer.handle.teardown();
		}
	}

	/// Remove the racer with `id` from `racers[dest_hash]` if present.
	/// Returns true if the entry was found and removed.
	fn remove_racer(dest_hash: &[u8], id: u64) -> bool {
		let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
		if let Some(v) = reg.racers.get_mut(dest_hash) {
			let before = v.len();
			v.retain(|r| r.id != id);
			let removed = v.len() < before;
			if v.is_empty() {
				reg.racers.remove(dest_hash);
			}
			return removed;
		}
		false
	}

	/// Number of in-flight racers for `dest_hash`.
	fn racer_count(dest_hash: &[u8]) -> usize {
		REGISTRY
			.lock()
			.ok()
			.and_then(|r| r.racers.get(dest_hash).map(|v| v.len()))
			.unwrap_or(0)
	}

	/// Single-use install of the global announce handler.  Idempotent.
	///
	/// The flip from "not installed" to "installed" must be atomic with
	/// respect to other `open()` callers, otherwise two concurrent opens
	/// each see `installed == false` and each call
	/// `Transport::register_announce_handler(...)`.  When that happens, every
	/// inbound announce fires the registry callback twice and we issue two
	/// link requests for one announce — observed in retichat.log Apr 2026 as
	/// duplicate "[APP_LINK] announce trigger → attempting" / "Establishing
	/// link to" pairs at startup when RfedNotify + RfedChannel + APNs all
	/// open the same RFed destination concurrently.
	fn ensure_announce_handler() {
		// Claim the install slot under a single lock acquisition; if another
		// thread won the race, bail out before constructing the handler.
		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			if reg.announce_handler_installed {
				return;
			}
			reg.announce_handler_installed = true;
		}

		let callback: AnnounceCallback = Arc::new(
			|destination_hash, _identity, _app_data, _announce_hash, _is_path_response| {
				if AppLinks::contains(destination_hash) {
					AppLinks::announce_received(destination_hash);
				}
			},
		);
		Transport::register_announce_handler(AnnounceHandler {
			aspect_filter: None, // match all; we filter by registered dest hash
			receive_path_responses: true,
			callback,
		});
	}

	/// Create and initiate a link for an already-registered destination.
	///
	/// Caller is responsible for having ensured the destination is in
	/// `specs`.
	///
	/// Bounded LR racing
	/// =================
	///
	/// We allow up to [`MAX_RACERS_PER_DEST`] in-flight outbound LRs per
	/// destination. The first racer to reach `STATE_ACTIVE` wins and is
	/// promoted into `Registry.links`; the losers are torn down by the
	/// winner's `link_established` callback via [`teardown_losing_racers`].
	///
	/// Why race at all?
	/// - Cold start often commits to a stale long-hop path the first
	///   announce supplied; a fresher (shorter) announce arriving mid-LR
	///   used to be either ignored (we'd wait the per-hop timeout) or
	///   eagerly torn down by Transport (which stranded the destination
	///   when the re-trigger raced the teardown — see retichat.log
	///   2026-04-30 17:01:36). Racing keeps the in-flight LR as a
	///   guaranteed fallback while a 2nd LR explores the better path.
	///
	/// Why cap at 2?
	/// - Each racer is a full ECDH handshake the receiver must process;
	///   the receiver does NOT dedup by initiator identity (every LR
	///   produces a fresh inbound `Link` with `KEEPALIVE = 360 s`).
	///   Letting losers linger would leave 6+ minute zombies on the daemon.
	///   With cap=2 we trade one extra handshake (immediately torn down on
	///   win) for path-improvement responsiveness; deeper racing is wire
	///   overhead with diminishing returns.
	///
	/// `attempt_in_flight` semantics
	/// =============================
	///
	/// `attempt_in_flight` collapses *concurrent* triggers from the same
	/// announce (the global app_links handler + a per-aspect LXMF reconnect
	/// handler can both fan in for a single packet). It is held only for
	/// the duration of the spawn-and-register block here, then released
	/// immediately. The bound on simultaneous racers is enforced by
	/// [`MAX_RACERS_PER_DEST`], NOT by this flag — otherwise a 2nd
	/// announce could never spawn a racer.
	fn establish(dest_hash: &[u8]) {
		if Self::policy() == LinkPolicy::Suspended {
			return;
		}
		let spec = match Self::spec(dest_hash) {
			Some(s) => s,
			None => {
				log(
					&format!("[APP_LINK] establish called for unknown dest {}", hexrep(dest_hash, false)),
					LOG_ERROR, false, false,
				);
				return;
			}
		};
		// Atomically claim the in-flight slot. Two concurrent triggers
		// for the same announce collapse here. `compare_exchange` is the
		// single hardware op that makes it race-free.
		if spec.attempt_in_flight
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.is_err()
		{
			// Silent: a sibling trigger is mid-spawn; it will spawn a
			// racer if room (or skip if cap reached). Logging here would
			// duplicate the line about to be emitted just below.
			return;
		}

		// Decide eligibility:
		//   1. Bail if we're already ACTIVE (winner exists).
		//   2. Bail if the racer cap is full.
		//   3. Bail if the current path is worse than the best existing
		//      racer's path. "Worse" = strictly more hops.
		//   4. If the current path ties the best existing hop count, allow
		//      the new racer ONLY IF it would go out a different upstream
		//      interface than every existing racer at that hop count.
		//      Rationale: the whole point of racing same-hops paths is
		//      that one upstream may be momentarily wedged while another
		//      is healthy (observed retichat.log 2026-04-30 22:45:32-52:
		//      both racers went out London, both LR-timed-out at 18s,
		//      and only after expire+re-announce did we get an RMap path
		//      where the link came up in <1s). Racing two LRs down the
		//      SAME interface just doubles wire load and shares fate —
		//      a duplicate path is no better than the original one.
		//
		// First-racer (no existing racers) ALWAYS allowed regardless of
		// hops — that's the cold-start trigger.
		let current_hops = Transport::path_hops(dest_hash);
		let current_iface = Transport::next_hop_interface(dest_hash);
		{
			let reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			if let Some(existing) = reg.links.get(dest_hash) {
				if existing.status() == STATE_ACTIVE {
					spec.attempt_in_flight.store(false, Ordering::Release);
					return;
				}
				// Else `links` holds a CLOSED handle from a prior race
				// in cleanup; fall through and replace it (detach below).
			}
			let existing_racers = reg.racers.get(dest_hash);
			let n = existing_racers.map(|v| v.len()).unwrap_or(0);
			if n >= MAX_RACERS_PER_DEST {
				spec.attempt_in_flight.store(false, Ordering::Release);
				return;
			}
			if n > 0 {
				// Allow the new racer if it strictly improves on the
				// best existing path, OR ties the best path AND would
				// go out a different upstream interface than every
				// existing racer at that hop count (see eligibility
				// comment above).
				let best_existing = existing_racers
					.and_then(|v| v.iter().map(|r| r.hops).min())
					.unwrap_or(u8::MAX);
				let ifaces_at_best: Vec<Option<String>> = existing_racers
					.map(|v| v.iter()
						.filter(|r| r.hops == best_existing)
						.map(|r| r.interface.clone())
						.collect())
					.unwrap_or_default();
				let new_iface_distinct = match &current_iface {
					Some(iface) => !ifaces_at_best.iter().any(|e| e.as_deref() == Some(iface.as_str())),
					// If we don't know which interface this racer would
					// take, treat it as a same-path duplicate to be safe.
					None => false,
				};
				let allow = match current_hops {
					Some(h) if h < best_existing => true,
					Some(h) if h == best_existing && new_iface_distinct => true,
					_ => false,
				};
				if !allow {
					log(
						&format!(
							"[APP_LINK] skip racer for {} — path hops {:?} iface {:?} not better than existing racer (best={}, ifaces_at_best={:?})",
							hexrep(dest_hash, false),
							current_hops,
							current_iface,
							best_existing,
							ifaces_at_best,
						),
						LOG_NOTICE, false, false,
					);
					spec.attempt_in_flight.store(false, Ordering::Release);
					return;
				}
			}
		}
		// `current_hops` may legitimately be None for a first racer when
		// `establish()` is called before the path table has been populated
		// (e.g. retry after expire_path). Use u8::MAX as a sentinel so any
		// real future announce will improve on it.
		let my_hops = current_hops.unwrap_or(u8::MAX);

		// Detach any dead `links` entry (CLOSED handle) before adding a
		// new racer. Does NOT touch `racers`.
		{
			let drop_dead = {
				let reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
				reg.links.get(dest_hash).map(|h| h.status())
					.map(|s| s != STATE_ACTIVE && s != STATE_PENDING && s != STATE_HANDSHAKE)
					.unwrap_or(false)
			};
			if drop_dead {
				Self::detach_link(dest_hash, /*notify*/ false);
			}
		}

		log(
			&format!("[APP_LINK] trigger → spawning LR (racer #{}/{}, hops={}) for {}",
				Self::racer_count(dest_hash) + 1,
				MAX_RACERS_PER_DEST,
				my_hops,
				hexrep(dest_hash, false)),
			LOG_NOTICE, false, false,
		);

		// Path-refresh hedge — UNCONDITIONAL on first racer.
		//
		// Per the SUBSYSTEMS.md AppLinks contract: every link
		// establishment must race the cached path against a freshly
		// requested one. The cached path may have been valid when
		// learned but become stale due to upstream NAT rebinding,
		// intermediate-hop reverse-route GC after an iface flap,
		// or a peer that has since moved interfaces. We have no
		// in-band signal for those events, so we treat every
		// establishment as a potential stale-path scenario and
		// fire a parallel PATH_REQUEST whenever there's an existing
		// path to race against.
		//
		// Three outcomes (unchanged from the previous hedge):
		//
		//   1. Cached route works → link establishes in ~RTT, racer
		//      wins, the parallel PATH_REQUEST is harmless background
		//      noise (deduped by `Transport::path_requests`).
		//
		//   2. Cached route is stale → upstream answers with a fresh
		//      announce on a better/working route. The announce
		//      handler spawns racer #2 (subject to MAX_RACERS_PER_DEST)
		//      via the standard inbound path. First success wins.
		//
		//   3. Both routes are dead → cached racer hits its LR
		//      timeout, then the "Last racer closed pre-ACTIVE" branch
		//      expires the path and re-requests.
		//
		// We do this BEFORE `Link::new_outbound` so the request hits
		// the wire concurrently with the handshake — we are NOT
		// waiting for it. DESIGN_PRINCIPLES.md §3 (no timeouts as
		// readiness signals): the racing mechanism IS the readiness
		// signal — whichever route's link establishes first wins.
		//
		// Cost: one extra PATH_REQUEST packet per first establishment
		// attempt per destination. Path-request rate-limiting and
		// dedup in Transport bound the wire impact. The benefit is
		// that we recover from silent stale-path failures (the
		// 2026-05-01 Android TCP-flap case where the cached route
		// looked valid but the reverse-path on intermediate hops had
		// been GC'd) in one round-trip instead of waiting for the
		// link establishment to time out.
		// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 and
		// Reticulum-rust/SUBSYSTEMS.md §1 (AppLinks).
		if Self::racer_count(dest_hash) == 0 && current_hops.is_some() {
			log(
				&format!("[APP_LINK] hedge → parallel request_path for cached path to {}",
					hexrep(dest_hash, false)),
				LOG_NOTICE, false, false,
			);
			Transport::request_path(dest_hash, None, None, None, None);
		}

		let aspect_refs: Vec<&str> = spec.aspects.iter().map(|s| s.as_str()).collect();
		let destination = match Destination::from_destination_hash(dest_hash, &spec.app_name, &aspect_refs) {
			Ok(d) => d,
			Err(e) => {
				log(
					&format!("[APP_LINK] Destination resolve failed ({}/{}): {}",
						spec.app_name, spec.aspects.join("."), e),
					LOG_ERROR, false, false,
				);
				spec.attempt_in_flight.store(false, Ordering::Release);
				return;
			}
		};

		let link = match Link::new_outbound(destination, MODE_AES256_CBC) {
			Ok(l) => l,
			Err(e) => {
				log(&format!("[APP_LINK] Link::new_outbound failed: {}", e), LOG_ERROR, false, false);
				spec.attempt_in_flight.store(false, Ordering::Release);
				return;
			}
		};
		let link_handle = LinkHandle::spawn(link);
		let my_racer_id = NEXT_RACER_ID.fetch_add(1, Ordering::Relaxed);

		// Per-handle latches.
		// `was_established` is per-RACER (set by this racer's own
		// link_established, regardless of win/lose). `is_winner` is set
		// only by the racer that won the compare_exchange in the
		// established callback. The closed callback uses both to choose
		// among: pure-loser teardown (silent), winner post-ACTIVE retry,
		// and pre-ACTIVE expire+request_path (only when no other racers
		// are in flight).
		let was_established = Arc::new(AtomicBool::new(false));
		let is_winner = Arc::new(AtomicBool::new(false));
		let was_established_closed = was_established.clone();
		let is_winner_closed = is_winner.clone();
		let ever_established_estab = spec.ever_established.clone();

		// Defence-in-depth: Link::teardown() in Reticulum-rust is
		// idempotent in *state* but NOT in callback firing — every call
		// re-invokes link_closed() even when the link is already CLOSED.
		// This latch ensures the close-handling block runs at most once
		// per racer regardless of how many times the layer fires it.
		let closed_fired = Arc::new(AtomicBool::new(false));
		let dest_for_estab = dest_hash.to_vec();
		let dest_for_closed = dest_hash.to_vec();
		let handle_for_estab = link_handle.clone();

		link_handle.set_link_established_callback(Some(Arc::new(move |_| {
			was_established.store(true, Ordering::Relaxed);

			// Race promotion: the FIRST racer to reach ACTIVE wins.
			// Subsequent ESTABLISHED firings (other racers we haven't yet
			// torn down) lose — they silently teardown themselves; the
			// winner's `teardown_losing_racers` will also catch them but
			// either path is fine.
			let won = {
				let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
				if reg.links.contains_key(&dest_for_estab) {
					// A peer racer already won. We're a loser.
					false
				} else {
					// We won. Move our handle into `links`. We stay in
					// `racers` for now; teardown_losing_racers below
					// preserves us by id.
					reg.links.insert(dest_for_estab.clone(), handle_for_estab.clone());
					true
				}
			};

			if won {
				is_winner.store(true, Ordering::Relaxed);
				ever_established_estab.store(true, Ordering::Relaxed);
				log(
					&format!("[APP_LINK] Direct link ESTABLISHED (winner racer={}) for {}",
						my_racer_id, hexrep(&dest_for_estab, false)),
					LOG_NOTICE, false, false,
				);

				// Fire status callback so the host can wake outbound, etc.
				let cbs: Vec<AppLinkStatusCallback> = REGISTRY
					.lock()
					.map(|r| r.status_callbacks.clone())
					.unwrap_or_default();
				for cb in &cbs {
					cb(&dest_for_estab, APP_LINK_ACTIVE, Some(handle_for_estab.clone()));
				}

				// Tear down losers. They get their `link_closed`
				// invoked but `is_winner=false` and `was_established`
				// likely false → they take the silent-loser branch in
				// the close callback below.
				AppLinks::teardown_losing_racers(&dest_for_estab, my_racer_id);
			} else {
				log(
					&format!("[APP_LINK] Racer {} reached ACTIVE after a sibling already won for {} — tearing down",
						my_racer_id, hexrep(&dest_for_estab, false)),
					LOG_NOTICE, false, false,
				);
				// Silent self-teardown. Detach our own callbacks first
				// so the close path takes the silent branch (we already
				// removed ourselves from racers conceptually — actually
				// no, we're still there; let the close callback handle
				// the racers cleanup).
				handle_for_estab.teardown();
			}
		})));

		link_handle.set_link_closed_callback(Some(Arc::new(move |_closed_handle: LinkHandle| {
			if closed_fired.swap(true, Ordering::Relaxed) {
				return;
			}

			// Remove ourselves from `racers` (idempotent — no-op if
			// already drained by teardown_losing_racers / close()).
			let _ = AppLinks::remove_racer(&dest_for_closed, my_racer_id);

			let we_were_winner = is_winner_closed.load(Ordering::Relaxed);
			let we_reached_active = was_established_closed.load(Ordering::Relaxed);

			if we_were_winner {
				// We were the active link. Remove from `links` and
				// notify hosts.
				{
					let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
					reg.links.remove(&dest_for_closed);
				}
				let cbs: Vec<AppLinkStatusCallback> = REGISTRY
					.lock()
					.map(|r| r.status_callbacks.clone())
					.unwrap_or_default();
				for cb in &cbs {
					cb(&dest_for_closed, APP_LINK_DISCONNECTED, None);
				}

				// Post-ACTIVE auto-retry only fires in Foreground. In
				// Background we keep what we have but don't burn battery
				// on retries; in Suspended we're tearing down anyway.
				if AppLinks::policy() != LinkPolicy::Foreground {
					log(
						&format!("[APP_LINK] Winner link torn down post-ACTIVE for {} — retry suppressed by policy {:?}",
							hexrep(&dest_for_closed, false), AppLinks::policy()),
						LOG_NOTICE, false, false,
					);
					return;
				}
				log(
					&format!("[APP_LINK] Winner link torn down post-ACTIVE for {} — single auto-retry",
						hexrep(&dest_for_closed, false)),
					LOG_NOTICE, false, false,
				);
				let dest_retry = dest_for_closed.clone();
				std::thread::spawn(move || {
					AppLinks::establish(&dest_retry);
				});
				return;
			}

			// We're a non-winner racer.
			//
			// Case A: we reached ACTIVE but lost the race → we were torn
			// down by the winner. Silent.
			//
			// Case B: we never reached ACTIVE → either we lost the LR
			// (timeout, peer rejection) or we were torn down because a
			// sibling racer won. Either way:
			//   - if any other racers are still in flight, OR a winner
			//     already exists in `links`, do NOTHING (don't expire
			//     path, don't request_path — would clobber a path that
			//     is actively working for another racer).
			//   - if we were the LAST racer and there's no winner, the
			//     destination is fully down: expire the path and request
			//     a fresh one. This is the original cold-fail behaviour.
			let any_others_alive = {
				let reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
				let racers_left = reg.racers.get(&dest_for_closed)
					.map(|v| !v.is_empty()).unwrap_or(false);
				let winner_present = reg.links.contains_key(&dest_for_closed);
				racers_left || winner_present
			};

			if any_others_alive {
				if we_reached_active {
					log(
						&format!("[APP_LINK] Loser racer {} torn down post-ACTIVE for {} — silent (winner owns lifecycle)",
							my_racer_id, hexrep(&dest_for_closed, false)),
						LOG_NOTICE, false, false,
					);
				}
				// No path expire, no retry — sibling keeps going.
				return;
			}

			// Last racer down with no winner. This is the genuine cold
			// fail. Expire stale path and request a fresh one so the
			// next announce-trigger has a clean slate.
			log(
				&format!("[APP_LINK] Last racer {} closed pre-ACTIVE with no winner for {} — expiring stale path",
					my_racer_id, hexrep(&dest_for_closed, false)),
				LOG_NOTICE, false, false,
			);
			let cbs: Vec<AppLinkStatusCallback> = REGISTRY
				.lock()
				.map(|r| r.status_callbacks.clone())
				.unwrap_or_default();
			for cb in &cbs {
				cb(&dest_for_closed, APP_LINK_DISCONNECTED, None);
			}
			Transport::expire_path(&dest_for_closed);
			Transport::request_path(&dest_for_closed, None, None, None, None);
		})));

		// Insert into the racers list BEFORE spawning the initiate so
		// status() and the racer-cap check are immediately consistent
		// with the new in-flight LR.
		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.racers.entry(dest_hash.to_vec())
				.or_insert_with(Vec::new)
				.push(Racer {
					id: my_racer_id,
					handle: link_handle.clone(),
					hops: my_hops,
					interface: current_iface.clone(),
				});
		}

		// Release the in-flight gate now — we've successfully claimed a
		// racer slot. A subsequent trigger from an independent announce
		// is allowed to claim again and spawn another racer (subject to
		// the cap). Holding it until ESTABLISHED/CLOSED would defeat the
		// whole point of bounded racing.
		spec.attempt_in_flight.store(false, Ordering::Release);

		// Notify hosts of the new establishing link so they can mirror it.
		let cbs: Vec<AppLinkStatusCallback> = REGISTRY
			.lock()
			.map(|r| r.status_callbacks.clone())
			.unwrap_or_default();
		for cb in &cbs {
			cb(dest_hash, APP_LINK_ESTABLISHING, Some(link_handle.clone()));
		}

		// Initiate on a background thread so we don't hold callers'
		// locks across the link-actor round-trip + Transport::outbound.
		std::thread::spawn(move || {
			if let Err(e) = link_handle.initiate() {
				log(&format!("[APP_LINK] Link initiate failed: {}", e), LOG_ERROR, false, false);
				// initiate() failing means our LinkHandle never reaches
				// HANDSHAKE/ACTIVE; the link actor will fire link_closed
				// shortly which handles racer removal + cold-fail.
			}
		});
	}
}
