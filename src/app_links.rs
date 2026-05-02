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
use std::time::Instant;

use once_cell::sync::Lazy;

use crate::destination::{Destination, DestinationType};
use crate::identity::Identity;
use crate::link::{Link, LinkHandle, MODE_AES256_CBC, STATE_ACTIVE};
use crate::transport::{AnnounceCallback, AnnounceHandler, Transport};
use crate::{hexrep, log, LOG_NOTICE};

// ─── Path-race AppLink semantics ────────────────────────────────────────
//
// As of the path-race refactor (replaces the previous bounded LR racer
// design), an "AppLink" is no longer a persistent `Link` object. The
// registry instead tracks whether a *path* to the destination is known.
//
//   * `establish()` fires `Transport::request_path` on every online
//     non-LoRa interface in parallel and waits (≤5 s, DESIGN_PRINCIPLES
//     §1) for any iface to populate the path table.
//   * Path arrival = "Ready" (status `APP_LINK_ACTIVE`).
//   * Path expiry (Transport drops it) = "Disconnected" — a background
//     watcher polls `Transport::has_path` for ready entries and emits
//     `APP_LINK_DISCONNECTED` on the flip.
//   * Sending uses LXMF's own DIRECT path (which builds a short-lived
//     `Link` per outbound batch from `handle_outbound`) — AppLinks no
//     longer holds long-lived `LinkHandle`s.
//
// The `AppLinkStatusCallback` `link` parameter is therefore always `None`
// in this implementation. The signature is kept for ABI stability with
// existing iOS/Android FFI callers.
//
// Poll cadence for the ready watcher. A path expiry only matters as a
// hint that the next send will need a fresh race — exactness is not
// required. 5 s keeps wake-up cost negligible.
const READY_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

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
/// state changes.
///
/// `(dest_hash, status, link)` — `link` is `Some(handle)` only when the
/// destination is registered with [`LinkMode::PersistentLink`] and a real
/// outbound `Link` exists in the registry. For [`LinkMode::PathRace`]
/// destinations the parameter is always `None`.
pub type AppLinkStatusCallback = Arc<dyn Fn(&[u8], u8, Option<LinkHandle>) + Send + Sync>;

/// How AppLinks should service a registered destination.
///
/// * [`LinkMode::PathRace`] — *(default)* lightweight liveness only. The
///   registry races a `Transport::request_path` on every online non-LoRa
///   interface; READY = a path arrived. No `Link` object is ever
///   constructed by AppLinks — the caller (e.g. LXMF DIRECT branch)
///   builds short-lived links itself when it needs to send. The status
///   callback's `link` argument is always `None`.
///
/// * [`LinkMode::PersistentLink`] — race a path, then build a real
///   outbound [`Link`] over the winning interface and hold it. Fires
///   `APP_LINK_ESTABLISHING` after `Link::initiate()` is dispatched and
///   `APP_LINK_ACTIVE` (with `Some(LinkHandle)`) when the link reaches
///   `STATE_ACTIVE`. On link-closed: drops the handle, fires
///   `APP_LINK_DISCONNECTED`, and waits for the next external trigger
///   (announce / network_changed / explicit `open`) to re-establish.
///
/// `PersistentLink` is the right mode for things that *require* a live
/// link to function — propagation node uploads/downloads, long-running
/// channel subscriptions — where every send would otherwise pay for a
/// fresh handshake.
///
/// **Single-attempt invariant.** In both modes a per-destination
/// `attempt_in_flight` CAS gate collapses concurrent triggers into a
/// single race. For `PersistentLink` the gate is held through the entire
/// `race_path → new_outbound → initiate → ACTIVE | CLOSED` cycle, so it
/// is impossible for two `LinkHandle`s to coexist for the same
/// destination — fixing the historical "orphan link" bug where a 2nd
/// establish attempt would overwrite the live handle and leave LRPROOFs
/// to be silently dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkMode {
	PathRace,
	PersistentLink,
}

impl Default for LinkMode {
	fn default() -> Self {
		LinkMode::PathRace
	}
}

/// Per-destination state held by the registry.
#[derive(Clone)]
pub struct AppLinkSpec {
	pub app_name: String,
	pub aspects: Vec<String>,
	pub mode: LinkMode,
	/// True from the moment `establish` decides to attempt until the
	/// in-flight cycle resolves. For `PathRace` that's the path-race
	/// thread completion; for `PersistentLink` it spans
	/// race_path → new_outbound → initiate → established|closed so a
	/// concurrent trigger cannot create a second `LinkHandle`.
	pub attempt_in_flight: Arc<AtomicBool>,
	/// True once this destination has reached READY/ACTIVE at least once
	/// since open.
	pub ever_established: Arc<AtomicBool>,
}

impl AppLinkSpec {
	pub fn new(app_name: impl Into<String>, aspects: Vec<String>) -> Self {
		Self::with_mode(app_name, aspects, LinkMode::PathRace)
	}

	pub fn with_mode(
		app_name: impl Into<String>,
		aspects: Vec<String>,
		mode: LinkMode,
	) -> Self {
		Self {
			app_name: app_name.into(),
			aspects,
			mode,
			attempt_in_flight: Arc::new(AtomicBool::new(false)),
			ever_established: Arc::new(AtomicBool::new(false)),
		}
	}
}

struct Registry {
	specs: HashMap<Vec<u8>, AppLinkSpec>,
	/// Destinations currently in the READY state (a path is known). The
	/// instant is when the entry was inserted — used by the watcher for
	/// debug/tracing only; the live source-of-truth is
	/// `Transport::has_path`.
	ready: HashMap<Vec<u8>, Instant>,
	/// Live `LinkHandle`s for [`LinkMode::PersistentLink`] destinations.
	/// PathRace destinations are never present here. At most one entry
	/// per destination (single-attempt CAS invariant).
	links: HashMap<Vec<u8>, LinkHandle>,
	status_callbacks: Vec<AppLinkStatusCallback>,
	/// Set once the announce handler has been registered with `Transport`.
	announce_handler_installed: bool,
	/// Set once the global ready-watcher thread is running.
	ready_watcher_installed: bool,
	/// Host lifecycle policy. Gates trigger-driven establishments — see
	/// [`LinkPolicy`].
	policy: LinkPolicy,
}

impl Registry {
	fn new() -> Self {
		Self {
			specs: HashMap::new(),
			ready: HashMap::new(),
			links: HashMap::new(),
			status_callbacks: Vec::new(),
			announce_handler_installed: false,
			ready_watcher_installed: false,
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
				// Path-race AppLinks have no Link objects to tear down.
				// Drop all READY entries and notify hosts.
				Self::clear_all_ready(/*notify*/ true);
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
		log(
			&format!("[APP_LINK] policy resume → attempting {} link(s)", candidates.len()),
			LOG_NOTICE, false, false,
		);
		for dest in &candidates {
			Self::invalidate_liveness(dest);
			Self::establish(dest);
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

	/// Open an app link for `dest_hash` in [`LinkMode::PathRace`].
	///
	/// Convenience shorthand for [`Self::open_with_mode`] —
	/// see that method for the full lifecycle description.
	pub fn open(dest_hash: &[u8], app_name: &str, aspects: &[&str]) {
		Self::open_with_mode(dest_hash, app_name, aspects, LinkMode::PathRace);
	}

	/// Open an app link for `dest_hash` in [`LinkMode::PersistentLink`].
	///
	/// Convenience shorthand for [`Self::open_with_mode`] — registers
	/// the destination so that AppLinks builds and holds a real outbound
	/// `Link` to it (re-establishing on close, with a single-attempt
	/// CAS gate that prevents orphan handles).
	pub fn open_persistent(dest_hash: &[u8], app_name: &str, aspects: &[&str]) {
		Self::open_with_mode(dest_hash, app_name, aspects, LinkMode::PersistentLink);
	}

	/// Open an app link for `dest_hash` in `mode`.
	///
	/// Adds the destination to the registry (with its app/aspects so we can
	/// resolve the right identity on every (re)establishment), ensures the
	/// global announce handler is installed, ensures the dest is watched on
	/// Transport, and kicks off path-request / link-establishment as far as
	/// current state allows.  Returns immediately.
	pub fn open_with_mode(
		dest_hash: &[u8],
		app_name: &str,
		aspects: &[&str],
		mode: LinkMode,
	) {
		Self::ensure_announce_handler();

		let spec = AppLinkSpec::with_mode(
			app_name,
			aspects.iter().map(|s| (*s).to_string()).collect(),
			mode,
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

		if Transport::has_path(dest_hash) {
			Self::establish(dest_hash);
		} else {
			log(
				&format!("[APP_LINK] No path → requesting for {}", hexrep(dest_hash, false)),
				LOG_NOTICE, false, false,
			);
			Self::establish(dest_hash);
		}
	}

	/// Close an app link.  Removes the destination from the registry,
	/// drops the READY marker (if any), tears down any held `LinkHandle`
	/// (PersistentLink mode), and fires a `NONE` status callback.
	pub fn close(dest_hash: &[u8]) {
		let (was_registered, dropped_link) = {
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			let removed_spec = reg.specs.remove(dest_hash).is_some();
			reg.ready.remove(dest_hash);
			let dropped_link = reg.links.remove(dest_hash);
			(removed_spec, dropped_link)
		};
		// Drop the link handle outside the registry lock so its actor
		// teardown can't deadlock on a callback that takes the lock.
		drop(dropped_link);
		if was_registered {
			let cbs: Vec<AppLinkStatusCallback> = REGISTRY
				.lock()
				.map(|r| r.status_callbacks.clone())
				.unwrap_or_default();
			for cb in &cbs {
				cb(dest_hash, APP_LINK_NONE, None);
			}
		}
	}

	/// Snapshot status for `dest_hash`.  See `APP_LINK_*` constants.
	///
	/// `PathRace` mode:
	///   * `APP_LINK_NONE` — destination is not registered.
	///   * `APP_LINK_ACTIVE` — a path is known.
	///   * `APP_LINK_PATH_REQUESTED` — `establish` is mid-race.
	///   * `APP_LINK_DISCONNECTED` — registered, no path, no race.
	///
	/// `PersistentLink` mode:
	///   * `APP_LINK_NONE` — destination is not registered.
	///   * `APP_LINK_ACTIVE` — held `LinkHandle` reports `STATE_ACTIVE`.
	///   * `APP_LINK_ESTABLISHING` — handle exists but link is not yet
	///     `STATE_ACTIVE` (path-race won, `Link::initiate()` dispatched).
	///   * `APP_LINK_PATH_REQUESTED` — `establish` is mid-race
	///     (no `LinkHandle` yet).
	///   * `APP_LINK_DISCONNECTED` — registered, no link, no race.
	pub fn status(dest_hash: &[u8]) -> u8 {
		let (mode, registered, ready, in_flight, link) = {
			let reg = match REGISTRY.lock() {
				Ok(g) => g,
				Err(_) => return APP_LINK_NONE,
			};
			let spec = reg.specs.get(dest_hash);
			let registered = spec.is_some();
			let mode = spec.map(|s| s.mode).unwrap_or(LinkMode::PathRace);
			let in_flight = spec
				.map(|s| s.attempt_in_flight.load(Ordering::Acquire))
				.unwrap_or(false);
			let ready = reg.ready.contains_key(dest_hash);
			let link = reg.links.get(dest_hash).cloned();
			(mode, registered, ready, in_flight, link)
		};
		if !registered {
			return APP_LINK_NONE;
		}
		match mode {
			LinkMode::PathRace => {
				if ready && Transport::has_path(dest_hash) {
					return APP_LINK_ACTIVE;
				}
				if in_flight {
					return APP_LINK_PATH_REQUESTED;
				}
				APP_LINK_DISCONNECTED
			}
			LinkMode::PersistentLink => {
				if let Some(handle) = link {
					if handle.status() == STATE_ACTIVE {
						return APP_LINK_ACTIVE;
					}
					return APP_LINK_ESTABLISHING;
				}
				if in_flight {
					return APP_LINK_PATH_REQUESTED;
				}
				APP_LINK_DISCONNECTED
			}
		}
	}

	/// Returns the live `LinkHandle` for `dest_hash` if one is held by
	/// the registry. Only ever populated for [`LinkMode::PersistentLink`]
	/// destinations; always `None` for `PathRace`.
	pub fn get_handle(dest_hash: &[u8]) -> Option<LinkHandle> {
		REGISTRY
			.lock()
			.ok()
			.and_then(|r| r.links.get(dest_hash).cloned())
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
		log(
			&format!("[APP_LINK] network-change trigger → attempting {} link(s)", candidates.len()),
			LOG_NOTICE, false, false,
		);
		for dest in &candidates {
			Self::invalidate_liveness(dest);
			Self::establish(dest);
		}
	}

	// ─── Internals ──────────────────────────────────────────────────────

	/// Drop every `ready` entry and every held `LinkHandle`. Used by
	/// [`set_policy`] when entering `Suspended`, and by tests. When
	/// `notify` is true, fires a `DISCONNECTED` status callback per
	/// affected destination so hosts can flush mirrored state.
	fn clear_all_ready(notify: bool) {
		let (dropped, dropped_links) = {
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			let ready_keys: Vec<Vec<u8>> = reg.ready.keys().cloned().collect();
			let link_keys: Vec<Vec<u8>> = reg.links.keys().cloned().collect();
			reg.ready.clear();
			let dropped_links: Vec<LinkHandle> = reg.links.drain().map(|(_, h)| h).collect();
			let mut union: Vec<Vec<u8>> = ready_keys;
			for k in link_keys {
				if !union.contains(&k) {
					union.push(k);
				}
			}
			(union, dropped_links)
		};
		// Drop link handles outside the registry lock.
		drop(dropped_links);
		if !notify || dropped.is_empty() {
			return;
		}
		let cbs: Vec<AppLinkStatusCallback> = REGISTRY
			.lock()
			.map(|r| r.status_callbacks.clone())
			.unwrap_or_default();
		for dest in &dropped {
			for cb in &cbs {
				cb(dest, APP_LINK_DISCONNECTED, None);
			}
		}
	}

	/// Idempotently spawn the global ready-watcher thread. The watcher
	/// polls `Transport::has_path` for every READY entry every
	/// `READY_WATCH_INTERVAL` and emits `APP_LINK_DISCONNECTED` when the
	/// path is gone. The next external trigger (announce / open /
	/// network_changed) re-races the path.
	fn ensure_ready_watcher() {
		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			if reg.ready_watcher_installed {
				return;
			}
			reg.ready_watcher_installed = true;
		}
		std::thread::Builder::new()
			.name("app_links_ready_watch".into())
			.spawn(|| loop {
				std::thread::sleep(READY_WATCH_INTERVAL);
				let to_check: Vec<Vec<u8>> = REGISTRY
					.lock()
					.map(|r| r.ready.keys().cloned().collect())
					.unwrap_or_default();
				if to_check.is_empty() {
					continue;
				}
				let mut expired: Vec<Vec<u8>> = Vec::new();
				for dest in &to_check {
					if !Transport::has_path(dest) {
						expired.push(dest.clone());
					}
				}
				if expired.is_empty() {
					continue;
				}
				let cbs: Vec<AppLinkStatusCallback> = {
					let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
					for dest in &expired {
						reg.ready.remove(dest);
					}
					// Also tear down any held PersistentLink handles for
					// expired destinations — the link is necessarily dead
					// once the path is gone.
					let dropped_links: Vec<LinkHandle> = expired
						.iter()
						.filter_map(|d| reg.links.remove(d))
						.collect();
					let cbs = reg.status_callbacks.clone();
					drop(reg);
					drop(dropped_links);
					cbs
				};
				for dest in &expired {
					log(
						&format!(
							"[APP_LINK] path expired for {} → DISCONNECTED",
							hexrep(dest, false)
						),
						LOG_NOTICE,
						false,
						false,
					);
					AppLinks::invalidate_liveness(dest);
					for cb in &cbs {
						cb(dest, APP_LINK_DISCONNECTED, None);
					}
				}
			})
			.expect("failed to spawn app_links ready watcher");
	}

	/// Single-use install of the global announce handler.  Idempotent.
	///
	/// The flip from "not installed" to "installed" must be atomic with
	/// respect to other `open()` callers, otherwise two concurrent opens
	/// each see `installed == false` and each call
	/// `Transport::register_announce_handler(...)`.  When that happens, every
	/// inbound announce fires the registry callback twice and we issue two
	/// link requests for one announce.
	fn ensure_announce_handler() {
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

	/// Drive a path-race for an already-registered destination.
	///
	/// Path-race semantics
	/// ===================
	///
	/// Replaces the previous bounded LR racing design. We no longer
	/// build a `Link` object; instead we fire `Transport::request_path`
	/// on every online non-LoRa interface in parallel and wait for any
	/// one of them to populate the path table. Path arrival = the
	/// destination is "Ready" (status `APP_LINK_ACTIVE`).
	///
	/// Why this is enough:
	///   * Sending uses LXMF's own DIRECT path which builds a
	///     short-lived `Link` per outbound batch from `handle_outbound`
	///     (or auto-promotes to `RESOURCE` for large messages). AppLinks
	///     no longer needs to hold a long-lived `Link`.
	///   * Path expiry is observed by the global ready-watcher; the
	///     next trigger re-races.
	///   * The 5-second `LIVENESS_BUDGET` (DESIGN_PRINCIPLES §1) is the
	///     hard upper bound on the race; late success past that window
	///     is a defect, not a slow success.
	///
	/// `attempt_in_flight` collapses concurrent triggers from the same
	/// announce (the global app_links handler + a per-aspect LXMF
	/// reconnect handler can both fan in for a single packet) into a
	/// single in-flight race.
	fn establish(dest_hash: &[u8]) {
		if Self::policy() == LinkPolicy::Suspended {
			return;
		}
		let spec = match Self::spec(dest_hash) {
			Some(s) => s,
			None => return,
		};
		// Fast bail: already Ready and the path is still live.
		if Self::status(dest_hash) == APP_LINK_ACTIVE {
			return;
		}
		// Atomically claim the in-flight slot. Two concurrent triggers
		// for the same destination collapse here — the loser sees the
		// in-flight race already running and returns silently.
		if spec
			.attempt_in_flight
			.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
			.is_err()
		{
			return;
		}

		Self::ensure_ready_watcher();

		// Notify hosts of the new in-flight race so they can update UI
		// (PATH_REQUESTED is the only "in flight" state in the path-race
		// implementation; ESTABLISHING is no longer reachable).
		let cbs: Vec<AppLinkStatusCallback> = REGISTRY
			.lock()
			.map(|r| r.status_callbacks.clone())
			.unwrap_or_default();
		for cb in &cbs {
			cb(dest_hash, APP_LINK_PATH_REQUESTED, None);
		}

		log(
			&format!(
				"[APP_LINK] path-race trigger for {}",
				hexrep(dest_hash, false)
			),
			LOG_NOTICE,
			false,
			false,
		);

		let dest_owned = dest_hash.to_vec();
		let in_flight = spec.attempt_in_flight.clone();
		let ever_established = spec.ever_established.clone();
		let mode = spec.mode;
		let app_name = spec.app_name.clone();
		let aspects = spec.aspects.clone();
		std::thread::Builder::new()
			.name("app_links_race".into())
			.spawn(move || {
				// The race itself; ≤ LIVENESS_BUDGET (5 s, §1).
				// `liveness::race_path` is the same primitive used by
				// `AppLinks::send` so cold-trigger and warm-send share
				// one code path.
				let result = liveness::race_path(&dest_owned, LIVENESS_BUDGET);

				let cbs: Vec<AppLinkStatusCallback> = REGISTRY
					.lock()
					.map(|r| r.status_callbacks.clone())
					.unwrap_or_default();

				match result {
					Ok(iface) => {
						{
							let mut reg = REGISTRY
								.lock()
								.expect("app_links registry mutex poisoned");
							reg.ready.insert(dest_owned.clone(), Instant::now());
						}
						ever_established.store(true, Ordering::Relaxed);
						// Pre-warm the liveness cache so the next
						// `AppLinks::send` to this dest skips the race.
						if let Ok(mut cache) = LIVENESS_CACHE.lock() {
							cache.insert(dest_owned.clone(), (iface.clone(), Instant::now()));
						}
						log(
							&format!(
								"[APP_LINK] READY (path via {}) for {}",
								iface,
								hexrep(&dest_owned, false)
							),
							LOG_NOTICE,
							false,
							false,
						);

						match mode {
							LinkMode::PathRace => {
								// Path-race mode: READY = path arrived.
								// Release the in-flight gate before
								// notifying — the callback may itself
								// trigger another establish.
								in_flight.store(false, Ordering::Release);
								for cb in &cbs {
									cb(&dest_owned, APP_LINK_ACTIVE, None);
								}
							}
							LinkMode::PersistentLink => {
								// Persistent mode: build + hold a real
								// `Link`. The in-flight gate stays armed
								// through the entire
								// `new_outbound → initiate → ACTIVE | CLOSED`
								// cycle so a concurrent trigger cannot
								// create a second handle for the same
								// destination (orphan-link prevention).
								Self::start_persistent_link(
									dest_owned.clone(),
									app_name,
									aspects,
									in_flight.clone(),
									cbs.clone(),
								);
							}
						}
					}
					Err(e) => {
						in_flight.store(false, Ordering::Release);
						log(
							&format!(
								"[APP_LINK] path-race failed for {}: {}",
								hexrep(&dest_owned, false),
								e
							),
							LOG_NOTICE,
							false,
							false,
						);
						for cb in &cbs {
							cb(&dest_owned, APP_LINK_DISCONNECTED, None);
						}
					}
				}
			})
			.expect("failed to spawn app_links race thread");
	}

	/// PersistentLink mode: build a `Link::new_outbound` to `dest`,
	/// store the `LinkHandle` in the registry, install link-established
	/// and link-closed callbacks that fire `APP_LINK_*` notifications,
	/// and dispatch `LinkHandle::initiate()` on a fresh thread.
	///
	/// The `attempt_in_flight` gate (passed in via `in_flight`) stays
	/// armed until the link reaches `STATE_ACTIVE` *or* its closed
	/// callback fires. This is the orphan-prevention invariant: while a
	/// handle is in flight no second `Link::new_outbound` will ever be
	/// constructed for the same destination.
	fn start_persistent_link(
		dest: Vec<u8>,
		app_name: String,
		aspects: Vec<String>,
		in_flight: Arc<AtomicBool>,
		cbs: Vec<AppLinkStatusCallback>,
	) {
		// Resolve destination identity from the announce cache.
		let identity = match Identity::recall(&dest) {
			Some(id) => id,
			None => {
				log(
					&format!(
						"[APP_LINK] PersistentLink: no identity for {} → DISCONNECTED",
						hexrep(&dest, false)
					),
					LOG_NOTICE, false, false,
				);
				in_flight.store(false, Ordering::Release);
				for cb in &cbs {
					cb(&dest, APP_LINK_DISCONNECTED, None);
				}
				return;
			}
		};

		let aspects_owned: Vec<String> = aspects.clone();
		let destination = match Destination::new_outbound(
			Some(identity),
			DestinationType::Single,
			app_name.clone(),
			aspects_owned,
		) {
			Ok(d) => d,
			Err(e) => {
				log(
					&format!(
						"[APP_LINK] PersistentLink: new_outbound destination failed for {}: {}",
						hexrep(&dest, false), e
					),
					LOG_NOTICE, false, false,
				);
				in_flight.store(false, Ordering::Release);
				for cb in &cbs {
					cb(&dest, APP_LINK_DISCONNECTED, None);
				}
				return;
			}
		};

		let link = match Link::new_outbound(destination, MODE_AES256_CBC) {
			Ok(l) => l,
			Err(e) => {
				log(
					&format!(
						"[APP_LINK] PersistentLink: Link::new_outbound failed for {}: {}",
						hexrep(&dest, false), e
					),
					LOG_NOTICE, false, false,
				);
				in_flight.store(false, Ordering::Release);
				for cb in &cbs {
					cb(&dest, APP_LINK_DISCONNECTED, None);
				}
				return;
			}
		};

		let handle = LinkHandle::spawn(link);

		// link_established → ACTIVE callback. Releases the in-flight gate.
		{
			let dest_cb = dest.clone();
			let in_flight_cb = in_flight.clone();
			let cbs_cb = cbs.clone();
			handle.set_link_established_callback(Some(Arc::new(move |h: LinkHandle| {
				log(
					&format!(
						"[APP_LINK] PersistentLink ACTIVE for {}",
						hexrep(&dest_cb, false)
					),
					LOG_NOTICE, false, false,
				);
				in_flight_cb.store(false, Ordering::Release);
				for cb in &cbs_cb {
					cb(&dest_cb, APP_LINK_ACTIVE, Some(h.clone()));
				}
			})));
		}

		// link_closed → DISCONNECTED callback. Removes the handle and
		// releases the in-flight gate so the next external trigger
		// (announce / network_changed) can re-establish.
		{
			let dest_cb = dest.clone();
			let in_flight_cb = in_flight.clone();
			let cbs_cb = cbs.clone();
			handle.set_link_closed_callback(Some(Arc::new(move |_: LinkHandle| {
				let dropped_handle = {
					let mut reg = REGISTRY
						.lock()
						.expect("app_links registry mutex poisoned");
					reg.ready.remove(&dest_cb);
					reg.links.remove(&dest_cb)
				};
				drop(dropped_handle);
				in_flight_cb.store(false, Ordering::Release);
				log(
					&format!(
						"[APP_LINK] PersistentLink CLOSED for {}",
						hexrep(&dest_cb, false)
					),
					LOG_NOTICE, false, false,
				);
				for cb in &cbs_cb {
					cb(&dest_cb, APP_LINK_DISCONNECTED, None);
				}
			})));
		}

		// Store the handle in the registry BEFORE initiate() so any
		// concurrent caller of `get_handle` / `status` immediately sees
		// the new (ESTABLISHING) link.
		{
			let mut reg = REGISTRY.lock().expect("app_links registry mutex poisoned");
			reg.links.insert(dest.clone(), handle.clone());
		}

		// Notify hosts we have moved from PATH_REQUESTED → ESTABLISHING.
		for cb in &cbs {
			cb(&dest, APP_LINK_ESTABLISHING, Some(handle.clone()));
		}

		// initiate() is potentially blocking on the link actor — run on
		// a background thread.
		let dest_thread = dest.clone();
		std::thread::Builder::new()
			.name("app_links_link_initiate".into())
			.spawn(move || {
				if let Err(e) = handle.initiate() {
					log(
						&format!(
							"[APP_LINK] PersistentLink initiate failed for {}: {:?}",
							hexrep(&dest_thread, false), e
						),
						LOG_NOTICE, false, false,
					);
				}
			})
			.expect("failed to spawn app_links link-initiate thread");
	}
}

// ─── Top-level send abstraction (Phase 4: AppLinks::send) ──────────────
//
// Goal: apps build a transport-agnostic message (LXMessage today; future:
// channel frames, RFed events) and call `AppLinks::send(message)`. The
// abstraction picks an interface, ensures a path exists, and dispatches
// the message in DIRECT mode. Apps never see iface names or modes.
//
// Strategy (locked in /memories/session/plan.md):
//   1. Liveness cache hit (≤2 s old) → skip race, dispatch immediately.
//   2. Cache miss → race a `request_path` on every non-LoRa, online iface
//      in parallel; first iface to populate the path table wins.
//   3. After path is known (≤5 s budget per DESIGN_PRINCIPLES §1) →
//      cache (dest → iface, now), dispatch the message.
//
// LoRa skip: `InterfaceStub.bitrate` < 50 kbps means a slow link; we
// don't gratuitously wake it for every send. Apps that need LoRa can
// still receive on it, and propagation/announce flow uses it normally —
// only the iface-race shortcut excludes it.

/// Bitrate threshold below which an interface is considered "LoRa-class"
/// and excluded from the liveness race. Units: bits per second.
pub const LORA_BITRATE_THRESHOLD: f64 = 50_000.0;

/// How long a successful liveness result is considered fresh. Within this
/// window subsequent sends to the same destination skip the race entirely.
pub const LIVENESS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(2);

/// 5-second deterministic upper bound for the liveness race (DESIGN
/// PRINCIPLES §1). Late success past this point is a defect, not a slow
/// success — surface failure rather than silently waiting longer.
const LIVENESS_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Polling interval while waiting for a path to populate after firing
/// `request_path`. 20 ms keeps wake-up cost negligible while bounding the
/// extra latency past path arrival to one tick.
const LIVENESS_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Liveness cache entry: (winning iface name, when it was learned).
static LIVENESS_CACHE: Lazy<Mutex<HashMap<Vec<u8>, (String, std::time::Instant)>>> =
	Lazy::new(|| Mutex::new(HashMap::new()));

/// Errors from [`AppLinks::send`] / [`liveness::race_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendErr {
	/// No online non-LoRa interfaces available to race a path on.
	NoUsableInterface,
	/// Liveness race exceeded [`LIVENESS_BUDGET`] without a winner.
	LivenessTimeout,
	/// The message's `dispatch` returned an error. String is verbatim.
	Dispatch(String),
}

impl std::fmt::Display for SendErr {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			SendErr::NoUsableInterface => write!(f, "no usable (online, non-LoRa) interface"),
			SendErr::LivenessTimeout => write!(f, "liveness race timed out (>5s)"),
			SendErr::Dispatch(e) => write!(f, "dispatch failed: {}", e),
		}
	}
}

impl std::error::Error for SendErr {}

/// Liveness race: the smallest possible "is this destination reachable
/// via *any* of my interfaces?" probe. Implemented as a parallel
/// `request_path` pinned to each candidate interface; the first iface
/// whose path-response repopulates the path table wins.
pub mod liveness {
	use super::*;
	use crate::transport::get_state_snapshot;

	/// Race a path-request on every online, non-LoRa interface and return
	/// the name of the iface whose response landed first.
	///
	/// Behaviour:
	///   * Filters interfaces by `online && bitrate >= LORA_BITRATE_THRESHOLD`.
	///     Interfaces with no reported bitrate are kept (assumed fast).
	///   * Fires `Transport::request_path(dest, None, Some(iface), None, None)`
	///     once per candidate interface (parallel, fire-and-forget).
	///   * Polls [`Transport::has_path`] every [`LIVENESS_POLL_INTERVAL`].
	///   * Returns `Transport::next_hop_interface(dest)` on first hit, or
	///     `Err(SendErr::LivenessTimeout)` if no path appears within `budget`.
	///
	/// This function does NOT consult the liveness cache — callers
	/// (`AppLinks::send`) check the cache first.
	pub fn race_path(dest_hash: &[u8], budget: std::time::Duration) -> Result<String, SendErr> {
		let snap = get_state_snapshot();
		let candidates: Vec<String> = snap
			.interfaces
			.iter()
			.filter(|i| {
				i.online && i.bitrate.map_or(true, |b| b >= LORA_BITRATE_THRESHOLD)
			})
			.map(|i| i.name.clone())
			.collect();

		if candidates.is_empty() {
			return Err(SendErr::NoUsableInterface);
		}

		// Fast path: if a usable path already exists, skip the race
		// entirely. The current next_hop iface is the winner by
		// definition.
		if Transport::has_path(dest_hash) {
			if let Some(iface) = Transport::next_hop_interface(dest_hash) {
				return Ok(iface);
			}
		}

		// Fire request_path on every candidate iface in parallel
		// (fire-and-forget; Transport::request_path is itself non-blocking
		// — it queues an outbound packet and returns).
		for iface in &candidates {
			Transport::request_path(
				dest_hash,
				None,
				Some(iface.clone()),
				None,
				None,
			);
		}

		// Poll until a path appears or budget is exhausted.
		let started = std::time::Instant::now();
		while started.elapsed() < budget {
			if Transport::has_path(dest_hash) {
				if let Some(iface) = Transport::next_hop_interface(dest_hash) {
					return Ok(iface);
				}
			}
			std::thread::sleep(LIVENESS_POLL_INTERVAL);
		}

		Err(SendErr::LivenessTimeout)
	}
}

/// Trait apps implement to make a value sendable via [`AppLinks::send`].
///
/// Kept deliberately tiny so it can be implemented for any future message
/// type (LXMF today, channel frames, RFed events) without touching
/// Reticulum-rust. The destination hash is needed up-front so the liveness
/// race can run before dispatch; `dispatch` consumes the value and is
/// responsible for the actual wire send via whatever upper-layer router
/// owns the message type.
pub trait Sendable {
	/// Destination hash this message is bound for. Used to drive the
	/// liveness race and the cache key.
	fn destination_hash(&self) -> Vec<u8>;

	/// Hand the message to its native upper-layer router for transmission.
	/// Called *after* a path to `destination_hash()` is known.
	fn dispatch(self) -> Result<(), String>;
}

impl AppLinks {
	/// Top-level send abstraction. Apps build the message; AppLinks picks
	/// the interface and ensures a path exists, then dispatches.
	///
	/// Sequence (DESIGN_PRINCIPLES §1, §3, §4):
	///   1. Cache check — if a winner from the last [`LIVENESS_CACHE_TTL`]
	///      seconds exists, dispatch immediately.
	///   2. Otherwise [`liveness::race_path`] (≤5 s).
	///   3. Cache the winner and dispatch.
	///
	/// On dispatch failure the cached entry is invalidated so the next
	/// send re-races (defensive: stale path in path table after iface flap).
	pub fn send<M: Sendable>(message: M) -> Result<(), SendErr> {
		let dest = message.destination_hash();

		// 1. Cache hit?
		let cached = {
			let cache = LIVENESS_CACHE.lock().expect("liveness cache mutex poisoned");
			cache.get(&dest).and_then(|(iface, when)| {
				if when.elapsed() <= LIVENESS_CACHE_TTL {
					Some(iface.clone())
				} else {
					None
				}
			})
		};

		// 2. Race if no cache hit.
		let _winning_iface = match cached {
			Some(iface) => iface,
			None => {
				let iface = liveness::race_path(&dest, LIVENESS_BUDGET)?;
				let mut cache = LIVENESS_CACHE.lock().expect("liveness cache mutex poisoned");
				cache.insert(dest.clone(), (iface.clone(), std::time::Instant::now()));
				iface
			}
		};

		// 3. Dispatch. On failure invalidate the cache entry so the next
		//    send re-races (the cached iface may have just gone offline or
		//    its path may have aged out underneath us).
		match message.dispatch() {
			Ok(()) => Ok(()),
			Err(e) => {
				let mut cache = LIVENESS_CACHE.lock().expect("liveness cache mutex poisoned");
				cache.remove(&dest);
				Err(SendErr::Dispatch(e))
			}
		}
	}

	/// Forget the cached liveness winner for `dest_hash`. Hosts can call
	/// this on known network-state changes (e.g. iOS WiFi→cellular) to
	/// force the next send to re-race instead of using a stale entry.
	pub fn invalidate_liveness(dest_hash: &[u8]) {
		if let Ok(mut cache) = LIVENESS_CACHE.lock() {
			cache.remove(dest_hash);
		}
	}
}
