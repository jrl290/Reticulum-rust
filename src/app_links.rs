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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;

use crate::destination::Destination;
use crate::link::{Link, LinkHandle, MODE_AES256_CBC, STATE_ACTIVE, STATE_HANDSHAKE, STATE_PENDING};
use crate::transport::{AnnounceCallback, AnnounceHandler, Transport};
use crate::{hexrep, log, LOG_ERROR, LOG_NOTICE};

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
	/// LinkHandle currently tracked for an app-link destination.  This is
	/// the outbound link the registry created — peer-initiated inbound
	/// links live in the host (e.g. LXMF's `backchannel_links`).
	links: HashMap<Vec<u8>, LinkHandle>,
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
			status_callbacks: Vec::new(),
			announce_handler_installed: false,
			policy: LinkPolicy::Foreground,
		}
	}
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
	/// down the tracked link (if any), and fires a `NONE` status callback.
	pub fn close(dest_hash: &[u8]) {
		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.specs.remove(dest_hash);
		}
		Self::detach_link(dest_hash, /*notify*/ true);
	}

	/// Snapshot status for `dest_hash`.  See `APP_LINK_*` constants.
	pub fn status(dest_hash: &[u8]) -> u8 {
		let reg = match REGISTRY.lock() {
			Ok(g) => g,
			Err(_) => return APP_LINK_NONE,
		};
		if !reg.specs.contains_key(dest_hash) {
			return APP_LINK_NONE;
		}
		match reg.links.get(dest_hash) {
			Some(arc) => {
				let s = arc.status();
				if s == STATE_ACTIVE {
					APP_LINK_ACTIVE
				} else if s == STATE_PENDING || s == STATE_HANDSHAKE {
					APP_LINK_ESTABLISHING
				} else {
					APP_LINK_DISCONNECTED
				}
			}
			None => {
				if Transport::has_path(dest_hash) {
					APP_LINK_DISCONNECTED
				} else {
					APP_LINK_PATH_REQUESTED
				}
			}
		}
	}

	/// Get a clone of the LinkHandle currently tracked for `dest_hash`.
	pub fn get_handle(dest_hash: &[u8]) -> Option<LinkHandle> {
		REGISTRY.lock().ok().and_then(|r| r.links.get(dest_hash).cloned())
	}

	// ─── External triggers ──────────────────────────────────────────────

	/// Trigger one fresh app-link attempt for `dest_hash` on the strength
	/// of a fresh announce.  No-op if no entry exists, link is already
	/// active/establishing, or an attempt is already in flight.
	pub fn announce_received(dest_hash: &[u8]) {
		if !Self::contains(dest_hash) {
			return;
		}
		if Self::policy() == LinkPolicy::Suspended {
			return;
		}
		match Self::status(dest_hash) {
			APP_LINK_ACTIVE | APP_LINK_ESTABLISHING => return,
			_ => {}
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

	/// Tear down (if present) and remove the tracked LinkHandle for
	/// `dest_hash`.  When `notify` is true, fires a status callback so
	/// hosts can drop their mirror entries.
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
	/// `specs`.  Single-attempt policy: skips if `attempt_in_flight` is set.
	fn establish(dest_hash: &[u8]) {
		if Self::policy() == LinkPolicy::Suspended {
			return;
		}
		// Early bail: attempt already in flight?
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
		// Atomically claim the in-flight slot.  A plain load+store would
		// race when two announce-handler invocations (or an announce trigger
		// concurrent with `open()`) both reach this gate before either has
		// stored `true` — both then proceed and we issue duplicate LRs.
		// `compare_exchange` collapses the read+write into a single
		// uncontended hardware op.
		if spec.attempt_in_flight
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.is_err()
		{
			// Silent: this is the dedup point. A previous trigger already
			// claimed the slot; logging here would just be a duplicate.
			return;
		}
		log(
			&format!("[APP_LINK] trigger → establishing {}", hexrep(dest_hash, false)),
			LOG_NOTICE, false, false,
		);

		// If an existing tracked link is still alive, leave it alone.
		{
			let reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			if let Some(existing) = reg.links.get(dest_hash) {
				let st = existing.status();
				if st == STATE_ACTIVE || st == STATE_PENDING || st == STATE_HANDSHAKE {
					// Release the slot we just claimed — the existing link is
					// fine and the callbacks attached to it own the lifecycle.
					spec.attempt_in_flight.store(false, Ordering::Release);
					return;
				}
			}
		}
		// Detach any dead link entry before creating a new one.
		Self::detach_link(dest_hash, /*notify*/ false);

		log(
			&format!("[APP_LINK] Establishing link to {}", hexrep(dest_hash, false)),
			LOG_NOTICE, false, false,
		);

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

		// `attempt_in_flight` was already claimed by compare_exchange above;
		// it stays true until either callback fires.

		// Track whether the link ever became ACTIVE so the closed callback
		// can distinguish a clean teardown from a failed establishment.
		let was_established = Arc::new(AtomicBool::new(false));
		let was_established_closed = was_established.clone();
		let in_flight_estab = spec.attempt_in_flight.clone();
		let in_flight_closed = spec.attempt_in_flight.clone();
		let ever_established_estab = spec.ever_established.clone();

		// Defence-in-depth: Link::teardown() in Reticulum-rust is idempotent
		// in *state* but NOT in callback firing — every call re-invokes
		// link_closed() even when the link is already CLOSED.  This latch
		// ensures the expire_path branch runs at most once per link
		// lifetime regardless of how many times the layer fires it.
		let closed_fired = Arc::new(AtomicBool::new(false));
		let dest_for_estab = dest_hash.to_vec();
		let dest_for_closed = dest_hash.to_vec();
		let handle_for_estab = link_handle.clone();

		link_handle.set_link_established_callback(Some(Arc::new(move |_| {
			log("[APP_LINK] Direct link ESTABLISHED", LOG_NOTICE, false, false);
			was_established.store(true, Ordering::Relaxed);
			ever_established_estab.store(true, Ordering::Relaxed);
			in_flight_estab.store(false, Ordering::Relaxed);

			// Fire status callback so the host can wake outbound, etc.
			let cbs: Vec<AppLinkStatusCallback> = REGISTRY
				.lock()
				.map(|r| r.status_callbacks.clone())
				.unwrap_or_default();
			for cb in &cbs {
				cb(&dest_for_estab, APP_LINK_ACTIVE, Some(handle_for_estab.clone()));
			}
		})));

		link_handle.set_link_closed_callback(Some(Arc::new(move |closed_handle: LinkHandle| {
			// Always release the in-flight flag so the next external trigger
			// is allowed to attempt one new LR.
			in_flight_closed.store(false, Ordering::Relaxed);
			if closed_fired.swap(true, Ordering::Relaxed) {
				return;
			}

			// Drop the registry entry for this destination so subsequent
			// triggers can replace it.  Notify hosts so they drop mirrors.
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

			if !was_established_closed.load(Ordering::Relaxed) {
				// If Transport tore us down because it just learned a better
				// path, the path table already holds a fresher entry — do NOT
				// expire it (would clobber the improvement) and do NOT issue a
				// redundant request_path. The improved-path announce that
				// triggered the cancellation has already invoked the
				// announce-handler path which will re-attempt establishment
				// via `announce_received()`.
				if closed_handle.was_cancelled_for_better_path() {
					log(
						&format!("[APP_LINK] Pending link cancelled by better path for {} — keeping improved path",
							hexrep(&dest_for_closed, false)),
						LOG_NOTICE, false, false,
					);
					return;
				}
				log(
					&format!("[APP_LINK] Link closed before ACTIVE — expiring stale path for {}",
						hexrep(&dest_for_closed, false)),
					LOG_NOTICE, false, false,
				);
				Transport::expire_path(&dest_for_closed);
				Transport::request_path(&dest_for_closed, None, None, None, None);
			} else {
				// Post-ACTIVE auto-retry only fires in Foreground. In
				// Background we keep what we have but don't burn battery on
				// retries; in Suspended we're tearing down anyway.
				if AppLinks::policy() != LinkPolicy::Foreground {
					log(
						&format!("[APP_LINK] Link torn down after ACTIVE for {} — retry suppressed by policy {:?}",
							hexrep(&dest_for_closed, false), AppLinks::policy()),
						LOG_NOTICE, false, false,
					);
					return;
				}
				log(
					&format!("[APP_LINK] Link torn down after being ACTIVE for {} — single auto-retry",
						hexrep(&dest_for_closed, false)),
					LOG_NOTICE, false, false,
				);
				let dest_retry = dest_for_closed.clone();
				std::thread::spawn(move || {
					AppLinks::establish(&dest_retry);
				});
			}
		})));

		// Insert into the registry BEFORE spawning the initiate so that
		// status() and get_handle() are immediately consistent.
		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.links.insert(dest_hash.to_vec(), link_handle.clone());
		}

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
		let in_flight_spawn = spec.attempt_in_flight.clone();
		std::thread::spawn(move || {
			if let Err(e) = link_handle.initiate() {
				log(&format!("[APP_LINK] Link initiate failed: {}", e), LOG_ERROR, false, false);
				in_flight_spawn.store(false, Ordering::Relaxed);
			}
		});
	}
}
