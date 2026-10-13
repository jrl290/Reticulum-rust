//! FFI support module for Reticulum.
//!
//! Provides a handle-based registry and safe Rust wrapper functions
//! suitable for calling from C, JNI, or other foreign interfaces.
//! All heavyweight Rust objects are stored in a global handle map and
//! referenced by opaque `u64` handles across the language boundary.

use std::any::Any;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
    Mutex,
};

use once_cell::sync::Lazy;

use crate::destination::{Destination, DestinationType};
use crate::identity::Identity;
use crate::reticulum::Reticulum;
use crate::transport::Transport;

// ---------------------------------------------------------------------------
// Handle registry
// ---------------------------------------------------------------------------

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static HANDLES: Lazy<Mutex<HashMap<u64, Box<dyn Any + Send>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

/// Store a value in the handle registry and return its handle (always ≥ 1).
pub fn store_handle<T: Send + 'static>(val: T) -> u64 {
    let id = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    HANDLES.lock().unwrap().insert(id, Box::new(val));
    id
}

/// Clone a value out of the registry.  Works for `Identity`, `Arc<Mutex<_>>`, etc.
pub fn get_handle<T: Clone + 'static>(id: u64) -> Option<T> {
    HANDLES
        .lock()
        .unwrap()
        .get(&id)?
        .downcast_ref::<T>()
        .cloned()
}

/// Run `f` on the value behind a handle in place (the handle keeps its id).
/// `None` when the handle does not exist or holds another type.
pub fn with_handle_mut<T: 'static, R>(id: u64, f: impl FnOnce(&mut T) -> R) -> Option<R> {
    let mut handles = HANDLES.lock().unwrap();
    let value = handles.get_mut(&id)?.downcast_mut::<T>()?;
    Some(f(value))
}

/// Remove a value from the registry and return it (transfers ownership).
pub fn take_handle<T: 'static>(id: u64) -> Option<T> {
    let boxed = HANDLES.lock().unwrap().remove(&id)?;
    boxed.downcast::<T>().ok().map(|b| *b)
}

/// Remove and drop a handle.  Returns `true` if the handle existed.
pub fn destroy_handle(id: u64) -> bool {
    HANDLES.lock().unwrap().remove(&id).is_some()
}

/// Return the number of handles currently stored.
pub fn handle_count() -> usize {
    HANDLES.lock().unwrap().len()
}

/// Return all handle IDs currently stored.
pub fn handle_keys() -> Vec<u64> {
    HANDLES.lock().unwrap().keys().cloned().collect()
}

/// Save an error message (thread-local).
pub fn set_error(msg: String) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg));
}

/// Retrieve and clear the last error message.
pub fn take_error() -> Option<String> {
    LAST_ERROR.with(|e| e.borrow_mut().take())
}

// ---------------------------------------------------------------------------
// Reticulum lifecycle
// ---------------------------------------------------------------------------

/// Initialise the Reticulum singleton.
///
/// `config_dir` – path to the directory containing the `config` file.
/// `loglevel`   – 0..7 (LOG_NONE .. LOG_EXTREME), or -1 for default.
///
/// Returns `Ok(())` on success.
pub fn init(config_dir: &str, loglevel: i32) -> Result<(), String> {
    let lvl = if loglevel < 0 { None } else { Some(loglevel) };
    let dir = config_dir.to_string();
    match std::panic::catch_unwind(move || {
        Reticulum::init(
            Some(dir.into()),
            lvl,
            None,  // logdest
            None,  // verbosity
            false, // require_shared_instance
            None,  // shared_instance_type
        )
    }) {
        Ok(result) => result,
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic during init".to_string()
            };
            Err(format!("Reticulum init panicked: {}", msg))
        }
    }
}

/// Shut down Reticulum (best-effort).
///
/// Every runtime link is torn down first, while the interfaces are still
/// attached, so peers get a LINKCLOSE and a stack started later in this
/// process does not inherit link actors from this one (B31).
pub fn shutdown() -> Result<(), String> {
    crate::link::teardown_all_runtime_links();
    crate::reticulum::exit_handler();
    Transport::reset_announce_history();
    Ok(())
}

/// Persist path table + packet hashlist + tunnels to disk (best-effort).
pub fn persist_data() {
    Transport::persist_data();
}

/// Set the log destination to LOG_CALLBACK and install the given closure.
pub fn set_log_callback<F: Fn(String) + Send + Sync + 'static>(callback: F) {
    let mut state = crate::LOG_STATE.lock().unwrap();
    state.logdest = crate::LOG_CALLBACK;
    state.logcall = Some(std::sync::Arc::new(callback));
    state.always_override_destination = false;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Create a new random identity.  Returns a handle.
pub fn identity_create() -> Result<u64, String> {
    let id = Identity::new(true);
    Ok(store_handle(id))
}

/// Load an identity from a file.  Returns a handle.
pub fn identity_from_file(path: &str) -> Result<u64, String> {
    let id = Identity::from_file(Path::new(path))?;
    Ok(store_handle(id))
}

/// Load an identity from raw private-key bytes (64 bytes).  Returns a handle.
pub fn identity_from_bytes(bytes: &[u8]) -> Result<u64, String> {
    let id = Identity::from_bytes(bytes)?;
    Ok(store_handle(id))
}

/// Persist an identity to a file.
pub fn identity_to_file(handle: u64, path: &str) -> Result<(), String> {
    let id: Identity =
        get_handle(handle).ok_or_else(|| "invalid identity handle".to_string())?;
    id.to_file(Path::new(path))
}

/// Return the public key bytes (64 bytes: 32 enc ‖ 32 sign).
pub fn identity_public_key(handle: u64) -> Result<Vec<u8>, String> {
    let id: Identity =
        get_handle(handle).ok_or_else(|| "invalid identity handle".to_string())?;
    id.get_public_key()
}

/// Return the truncated identity hash (16 bytes).
pub fn identity_hash(handle: u64) -> Result<Vec<u8>, String> {
    let id: Identity =
        get_handle(handle).ok_or_else(|| "invalid identity handle".to_string())?;
    id.hash
        .clone()
        .ok_or_else(|| "identity has no hash (no keys loaded)".to_string())
}

/// Sign `data` with the identity's Ed25519 signing key.
/// Returns 64-byte signature.
pub fn identity_sign(handle: u64, data: &[u8]) -> Result<Vec<u8>, String> {
    let id: Identity =
        get_handle(handle).ok_or_else(|| "invalid identity handle".to_string())?;
    Ok(id.sign(data))
}

/// Destroy an identity handle.
pub fn identity_destroy(handle: u64) -> Result<(), String> {
    if destroy_handle(handle) {
        Ok(())
    } else {
        Err("invalid identity handle".to_string())
    }
}

// ---------------------------------------------------------------------------
// Destination helpers
// ---------------------------------------------------------------------------

/// Compute the destination hash for an identity + app_name + aspects
/// without creating a full Destination object.
pub fn destination_hash_for(
    identity_handle: u64,
    app_name: &str,
    aspects: &[&str],
) -> Result<Vec<u8>, String> {
    let id: Identity =
        get_handle(identity_handle).ok_or_else(|| "invalid identity handle".to_string())?;
    let id_hash = id
        .hash
        .as_deref()
        .ok_or_else(|| "identity has no hash".to_string())?;
    Ok(Destination::hash(Some(id_hash), app_name, aspects))
}

/// Create an outbound destination by recalling the remote identity from the
/// known-destinations table by `dest_hash`, then wrapping it with the given
/// `app_name` and `aspects`.  Returns a destination handle.
///
/// This is the one-shot helper iOS uses to send plain encrypted packets to a
/// remote destination when it only knows the destination hash (e.g. rfed.apns).
pub fn destination_create_outbound_from_hash(
    dest_hash: &[u8],
    app_name: &str,
    aspects: Vec<String>,
) -> Result<u64, String> {
    let pub_key = Identity::recall_public_key(dest_hash)
        .ok_or_else(|| "destination not in known-destinations table".to_string())?;
    let id = Identity::from_public_key(&pub_key)
        .map_err(|e| format!("from_public_key: {}", e))?;
    let dest = Destination::new_outbound(
        Some(id),
        DestinationType::Single,
        app_name.to_string(),
        aspects,
    )?;
    Ok(store_handle(dest))
}

/// Create an outbound destination for a known identity and return a handle.
pub fn destination_create_outbound(
    identity_handle: u64,
    app_name: &str,
    aspects: Vec<String>,
) -> Result<u64, String> {
    let id: Identity =
        get_handle(identity_handle).ok_or_else(|| "invalid identity handle".to_string())?;
    let dest = Destination::new_outbound(
        Some(id),
        DestinationType::Single,
        app_name.to_string(),
        aspects,
    )?;
    Ok(store_handle(dest))
}

// ---------------------------------------------------------------------------
// Transport / path queries
// ---------------------------------------------------------------------------

/// Check whether a path to the given destination hash is known.
pub fn transport_has_path(dest_hash: &[u8]) -> bool {
    Transport::has_path(dest_hash)
}

/// Check whether the known path was freshly verified in this process.
pub fn transport_is_path_verified_this_session(dest_hash: &[u8]) -> bool {
    Transport::is_path_verified_this_session(dest_hash)
}

/// Check whether the destination's identity (public key) is in the
/// known-destinations table. Outbound link/packet construction needs
/// the identity to encrypt — `transport_has_path` is not sufficient.
pub fn identity_known(dest_hash: &[u8]) -> bool {
    Identity::recall_public_key(dest_hash).is_some()
}

/// Request a path to a destination hash.
pub fn transport_request_path(dest_hash: &[u8]) -> Result<(), String> {
    Transport::request_path(dest_hash, None, None, None, None);
    Ok(())
}

/// Return the number of hops to a destination, or -1 if unknown.
pub fn transport_hops_to(dest_hash: &[u8]) -> i32 {
    let h = Transport::hops_to(dest_hash);
    if h == 255 { -1 } else { h as i32 }
}

/// Query whether a configured interface (by name) is currently online.
/// Returns: 1 = online, 0 = offline, -1 = no interface with that name.
pub fn interface_online(name: &str) -> i32 {
    for iface in Transport::get_interface_list() {
        if iface.name == name {
            return if iface.online { 1 } else { 0 };
        }
    }
    -1
}

// ---------------------------------------------------------------------------
// Published destinations (Transport-managed announce daemon)
// ---------------------------------------------------------------------------

/// Opt a locally-registered IN/SINGLE destination into the Transport
/// announce daemon.
///
/// * `destination_hash`  16-byte truncated RNS hash of the destination.
/// * `refresh_secs`      Periodic refresh interval in seconds, also the
///                       minimum period between automatic announces per
///                       interface. `0.0` means no periodic refresh; the
///                       destination is still announced once when an
///                       interface comes online (at most once per 30 min
///                       there). The application's own announces are never held.
/// * `app_data`          Optional app_data attached to each announce.
///                       Pass `None` to use the destination's configured
///                       app_data.
pub fn transport_publish_destination(
    destination_hash: &[u8],
    refresh_secs: f64,
    app_data: Option<&[u8]>,
) {
    let refresh = if refresh_secs > 0.0 {
        Some(std::time::Duration::from_secs_f64(refresh_secs))
    } else {
        None
    };
    Transport::publish_destination(
        destination_hash.to_vec(),
        refresh,
        app_data.map(|d| d.to_vec()),
    );
}

/// Remove a destination from the announce daemon's published set.
pub fn transport_unpublish_destination(destination_hash: &[u8]) {
    Transport::unpublish_destination(destination_hash);
}

/// Return whether a destination is currently in the published set.
pub fn transport_is_published(destination_hash: &[u8]) -> bool {
    Transport::is_published(destination_hash)
}

// ---------------------------------------------------------------------------
// Announce filtering
// ---------------------------------------------------------------------------

/// Enable or disable early-dropping of inbound announce packets at the
/// transport layer.  When `true`, all ANNOUNCE packets are silently
/// discarded except PATH_RESPONSE replies to our own path requests,
/// and announces from watchlisted destinations.
/// This is opt-in (default: `false`).
pub fn set_drop_announces(enabled: bool) {
    Transport::set_drop_announces(enabled);
}

/// Query whether announce dropping is currently enabled.
pub fn get_drop_announces() -> bool {
    Transport::drop_announces_enabled()
}

/// Add a destination hash to the announce watchlist.
/// Announces from watchlisted destinations pass through even when
/// drop_announces is enabled.
pub fn watch_announce(destination_hash: Vec<u8>) {
    Transport::watch_announce(destination_hash);
}

/// Remove a destination hash from the announce watchlist.
pub fn unwatch_announce(destination_hash: &[u8]) {
    Transport::unwatch_announce(destination_hash);
}

// ---------------------------------------------------------------------------
// Keepalive tuning
// ---------------------------------------------------------------------------

/// Adjust the keepalive interval (in seconds) for all active links and TCP
/// backbone connections.  Pass `0.0` to restore compiled-in defaults.
pub fn set_keepalive_interval(secs: f64) -> Result<(), String> {
    let instance = Reticulum::get_instance()
        .ok_or_else(|| "Reticulum not initialised".to_string())?;
    let reticulum = instance.lock().unwrap();
    reticulum.set_keepalive_interval(secs);
    Ok(())
}

// ---------------------------------------------------------------------------
// Callback-based interface (for Android BLE bridge)
// ---------------------------------------------------------------------------

/// Register a callback-based transport interface.
///
/// `name`     – human-readable name (e.g. "AndroidBLE").
/// `send_fn`  – called when Reticulum wants to send raw bytes out.
/// `bitrate`  – link bitrate in bits/sec (e.g. 12500 for LoRa SF7/125kHz).
///
/// Returns an opaque interface ID for use with [`callback_interface_receive`].
pub fn register_callback_interface(
    name: &str,
    send_fn: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    bitrate: Option<u64>,
) -> Result<u64, String> {
    use crate::transport::InterfaceStubConfig;

    let mut config = InterfaceStubConfig::default();
    config.name = name.to_string();
    config.mode = crate::transport::InterfaceStub::MODE_FULL;
    config.out = true;
    config.bitrate = bitrate;
    config.announce_cap = Some(crate::reticulum::ANNOUNCE_CAP / 100.0);
    Transport::register_interface_stub_config(config);
    Transport::register_outbound_handler(name, send_fn);

    Ok(store_handle(name.to_string()))
}

/// Deregister a callback-based interface.
pub fn deregister_callback_interface(iface_handle: u64) -> Result<(), String> {
    let name: String =
        take_handle(iface_handle).ok_or_else(|| "invalid interface handle".to_string())?;
    Transport::unregister_outbound_handler(&name);
    Transport::deregister_interface_stub(&name);
    Ok(())
}

/// Feed received data into a callback interface (from BLE, etc.).
///
/// `iface_handle` – handle returned by [`register_callback_interface`].
/// `data`         – raw Reticulum packet bytes (already de-KISS-framed).
pub fn callback_interface_receive(iface_handle: u64, data: &[u8]) -> Result<(), String> {
    let name: String =
        get_handle(iface_handle).ok_or_else(|| "invalid interface handle".to_string())?;
    Transport::inbound(data.to_vec(), Some(name));
    Ok(())
}

/// Update the RSSI / SNR / Q stats on a registered interface stub.
pub fn callback_interface_set_stats(
    iface_handle: u64,
    rssi: Option<f64>,
    snr: Option<f64>,
    q: Option<f64>,
) -> Result<(), String> {
    let name: String =
        get_handle(iface_handle).ok_or_else(|| "invalid interface handle".to_string())?;
    let mut state = crate::transport::TRANSPORT.lock().unwrap();
    if let Some(iface) = state.interfaces.iter_mut().find(|i| i.name == name) {
        iface.r_stat_rssi = rssi;
        iface.r_stat_snr = snr;
        iface.r_stat_q = q;
        Ok(())
    } else {
        Err(format!("interface '{}' not found", name))
    }
}

// ---------------------------------------------------------------------------
// RNode callback interface (KISS framing + radio config in Rust, raw bytes
// shuttled by a native bridge — e.g. CoreBluetooth on iOS)
// ---------------------------------------------------------------------------

#[cfg(feature = "serial")]
pub use crate::interfaces::rnode_interface::{RNodeRadioConfig, RNodeStats};

/// Internal handle payload for a registered RNode callback interface.
#[cfg(feature = "serial")]
#[derive(Clone)]
struct RNodeCallbackHandle {
    name: String,
    interface: Arc<Mutex<crate::interfaces::rnode_interface::RNodeInterface>>,
    feed: std::sync::mpsc::Sender<u8>,
}

/// Register an RNode interface that talks to the radio over a caller-owned
/// byte stream.
///
/// `name`     – human-readable name (e.g. "RNodeBLE").
/// `send_fn`  – called when Reticulum wants to send raw KISS-framed bytes to
///              the radio. The bridge is responsible for any link-MTU
///              chunking (e.g. 20-byte BLE writes).
/// `config`   – radio parameters (frequency, BW, SF, CR, TX power, …).
///
/// Returns an opaque interface handle. Use it with [`rnode_iface_feed`] to
/// push RX bytes from the radio into Reticulum, [`rnode_iface_get_stats`]
/// for telemetry, and [`rnode_iface_deregister`] to tear it down.
///
/// Internally this:
///   1. Builds an `RNodeInterface` with a callback transport.
///   2. Spawns the read loop (KISS deframer + RNode command codec).
///   3. Runs the DETECT/init handshake.
///   4. Registers a Transport interface stub + outbound handler so packets
///      routed to `name` go through `process_outgoing`.
#[cfg(feature = "serial")]
pub fn rnode_iface_register(
    name: &str,
    send_fn: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    config: RNodeRadioConfig,
) -> Result<u64, String> {
    let handle = rnode_iface_create(name, send_fn, config)?;
    match rnode_iface_configure(handle) {
        Ok(()) => Ok(handle),
        Err(e) => {
            // Roll back: deregister so the caller doesn't end up with a
            // half-initialised interface handle leak.
            let _ = rnode_iface_deregister(handle);
            Err(e)
        }
    }
}

/// Build the RNode interface and spawn its read loop, but do NOT run the
/// DETECT/init handshake. This lets the native bridge obtain the handle
/// (and therefore start feeding RX bytes via [`rnode_iface_feed`]) BEFORE
/// blocking inside the handshake. Call [`rnode_iface_configure`] next.
///
/// Returns the handle on success.
#[cfg(feature = "serial")]
pub fn rnode_iface_create(
    name: &str,
    send_fn: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    config: RNodeRadioConfig,
) -> Result<u64, String> {
    use crate::interfaces::rnode_interface::RNodeInterface;

    let (iface, feed) = RNodeInterface::new_with_callback(name, send_fn, config)
        .map_err(|e| format!("RNode interface construction failed: {}", e))?;
    let interface = Arc::new(Mutex::new(iface));

    // Read loop must be running before any bytes are fed in.
    RNodeInterface::start_read_loop(
        Arc::clone(&interface),
        Arc::new(Mutex::new(crate::transport::Transport)),
    );

    Ok(store_handle(RNodeCallbackHandle {
        name: name.to_string(),
        interface,
        feed,
    }))
}

/// Run the DETECT/init handshake on a previously [`rnode_iface_create`]'d
/// handle and wire the interface into the global Transport. Blocks for
/// roughly 2-4 seconds while the radio is probed and configured. RX bytes
/// must be fed in via [`rnode_iface_feed`] for this to succeed.
#[cfg(feature = "serial")]
pub fn rnode_iface_configure(iface_handle: u64) -> Result<(), String> {
    use crate::interfaces::rnode_interface::RNodeInterface;
    use crate::transport::{InterfaceStub, InterfaceStubConfig};

    let h: RNodeCallbackHandle = get_handle(iface_handle)
        .ok_or_else(|| "invalid RNode handle".to_string())?;

    RNodeInterface::configure_device_shared(&h.interface)
        .map_err(|e| format!("RNode configure failed: {}", e))?;

    let mut stub_cfg = InterfaceStubConfig::default();
    stub_cfg.name = h.name.clone();
    stub_cfg.mode = InterfaceStub::MODE_FULL;
    stub_cfg.out = true;
    // Mark the stub online — the device handshake just succeeded and we have
    // a live callback transport to it. Without this, Transport sees the
    // interface as offline (default), which both gates outbound traffic and
    // makes `interface_online()` lie to UI status indicators.
    stub_cfg.online = Some(true);
    let bitrate = h.interface.lock().unwrap().bitrate;
    stub_cfg.bitrate = if bitrate > 0 { Some(bitrate) } else { None };
    stub_cfg.announce_cap = Some(crate::reticulum::ANNOUNCE_CAP / 100.0);
    Transport::register_interface_stub_config(stub_cfg);
    // Belt-and-braces: if the stub already existed (e.g. previous run that
    // didn't clean up), the register call above is a no-op. Force online.
    Transport::set_interface_online(&h.name, true);

    let handler_iface = Arc::clone(&h.interface);
    let name = h.name.clone();
    Transport::register_outbound_handler(
        &name,
        Arc::new(move |raw| {
            let iface = handler_iface.lock().unwrap();
            iface.process_outgoing(raw.to_vec()).is_ok()
        }),
    );

    Ok(())
}

/// Push RX bytes (received over BLE/USB) into the RNode interface's read
/// loop. Bytes are KISS-deframed and routed through the RNode command
/// codec; CMD_DATA frames are forwarded to `Transport::inbound`.
#[cfg(feature = "serial")]
pub fn rnode_iface_feed(iface_handle: u64, data: &[u8]) -> Result<(), String> {
    let h: RNodeCallbackHandle =
        get_handle(iface_handle).ok_or_else(|| "invalid RNode handle".to_string())?;
    for &b in data {
        h.feed
            .send(b)
            .map_err(|_| "RNode read channel closed".to_string())?;
    }
    Ok(())
}

/// Snapshot of all telemetry the read loop currently knows about (RSSI,
/// SNR, airtime, battery, temperature, firmware version, …).
#[cfg(feature = "serial")]
pub fn rnode_iface_get_stats(iface_handle: u64) -> Result<RNodeStats, String> {
    let h: RNodeCallbackHandle =
        get_handle(iface_handle).ok_or_else(|| "invalid RNode handle".to_string())?;
    let snap = h.interface.lock().unwrap().stats_snapshot();
    Ok(snap)
}

/// Send the configured ID-beacon (callsign) immediately, bypassing the
/// scheduled interval.
#[cfg(feature = "serial")]
pub fn rnode_iface_id_beacon_now(iface_handle: u64) -> Result<(), String> {
    let h: RNodeCallbackHandle =
        get_handle(iface_handle).ok_or_else(|| "invalid RNode handle".to_string())?;
    let callsign = h.interface.lock().unwrap().id_callsign_bytes();
    match callsign {
        Some(cs) => h
            .interface
            .lock()
            .unwrap()
            .process_outgoing(cs)
            .map_err(|e| format!("ID beacon send failed: {}", e)),
        None => Err("no id_callsign configured".to_string()),
    }
}

/// Deregister the RNode interface and tear down the Transport binding.
/// The native bridge should drop its TX callback and stop feeding bytes
/// before calling this.
#[cfg(feature = "serial")]
pub fn rnode_iface_deregister(iface_handle: u64) -> Result<(), String> {
    let h: RNodeCallbackHandle =
        take_handle(iface_handle).ok_or_else(|| "invalid RNode handle".to_string())?;
    Transport::unregister_outbound_handler(&h.name);
    Transport::deregister_interface_stub(&h.name);
    // Closing the connection causes the read loop to exit; the callback-mode
    // guard in read_loop_impl skips reconnect_port for callback connections.
    h.interface.lock().unwrap().shutdown();
    Ok(())
}

// ---------------------------------------------------------------------------
// Packet creation & sending
// ---------------------------------------------------------------------------

/// Create a DATA packet to an outbound destination.
///
/// `dest_handle` – destination handle from [`destination_create_outbound`].
/// `data`        – payload bytes.
/// `create_receipt` – if true, a `PacketReceipt` is generated for RTT tracking.
///
/// Returns a packet handle.
pub fn packet_create(
    dest_handle: u64,
    data: &[u8],
    create_receipt: bool,
) -> Result<u64, String> {
    let dest: Destination =
        get_handle(dest_handle).ok_or_else(|| "invalid destination handle".to_string())?;
    let packet = crate::packet::Packet::new(
        Some(dest),
        data.to_vec(),
        crate::packet::DATA,
        crate::packet::NONE,
        crate::transport::BROADCAST,
        crate::packet::HEADER_1,
        None,
        None,
        create_receipt,
        crate::packet::FLAG_UNSET,
    );
    Ok(store_handle(packet))
}

/// Send a packet.  Returns the receipt handle (0 when the packet went out
/// without a receipt being requested).
///
/// A packet no interface could take is an error, as it is in the reference
/// (RNS/Packet.py send() returns False): until 2026-09-24 it returned 0 too,
/// so hosts read "nothing was sent" as "sent, no receipt".
pub fn packet_send(packet_handle: u64) -> Result<u64, String> {
    let mut packet: crate::packet::Packet =
        take_handle(packet_handle).ok_or_else(|| "invalid packet handle".to_string())?;
    match packet.send() {
        Ok(Some(receipt)) => Ok(store_handle(receipt)),
        Ok(None) if packet.sent => Ok(0),
        Ok(None) => Err("No interfaces could process the outbound packet".to_string()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Packet receipt queries
// ---------------------------------------------------------------------------

/// Get the RTT (round-trip time) of a delivered receipt, in seconds.
/// Returns `None` if the receipt hasn't been proved yet.
pub fn receipt_get_rtt(receipt_handle: u64) -> Option<f64> {
    let receipt: crate::packet::PacketReceipt = get_handle(receipt_handle)?;
    receipt.get_rtt()
}

/// Get the receipt status: 0 = FAILED, 1 = SENT, 2 = DELIVERED.
pub fn receipt_get_status(receipt_handle: u64) -> Option<u8> {
    let receipt: crate::packet::PacketReceipt = get_handle(receipt_handle)?;
    Some(receipt.get_status())
}

/// Get the receipt's packet hash (for matching with Transport callbacks).
pub fn receipt_get_hash(receipt_handle: u64) -> Option<Vec<u8>> {
    let receipt: crate::packet::PacketReceipt = get_handle(receipt_handle)?;
    Some(receipt.hash.clone())
}

/// Set delivery and timeout callbacks on the tracked receipt with this hash.
///
/// The delivery callback runs on the thread that received the proof, the
/// timeout callback on a thread of its own. A receipt that already concluded
/// is no longer tracked (RNS/Transport.py drops concluded receipts), so a
/// callback registered here after its proof or timeout does not run; a
/// caller that holds the receipt should set callbacks on it instead
/// (`PacketReceipt::set_delivery_callback` runs a late registration once).
pub fn receipt_set_callbacks(
    receipt_hash: &[u8],
    delivery_cb: Arc<dyn Fn(&crate::packet::PacketReceipt) + Send + Sync>,
    timeout_cb: Arc<dyn Fn(&crate::packet::PacketReceipt) + Send + Sync>,
) {
    Transport::set_receipt_delivery_callback(receipt_hash, delivery_cb);
    Transport::set_receipt_timeout_callback(receipt_hash, timeout_cb);
}

/// Destroy a receipt handle.
pub fn receipt_destroy(receipt_handle: u64) -> bool {
    destroy_handle(receipt_handle)
}

// ---------------------------------------------------------------------------
// Destination helpers (inbound)
// ---------------------------------------------------------------------------

/// Register a local "inbound" destination so that packets addressed to it
/// are accepted and proved.
pub fn destination_create_inbound(
    identity_handle: u64,
    app_name: &str,
    aspects: Vec<String>,
) -> Result<u64, String> {
    let id: Identity =
        get_handle(identity_handle).ok_or_else(|| "invalid identity handle".to_string())?;
    let dest = Destination::new_inbound(
        Some(id),
        DestinationType::Single,
        app_name.to_string(),
        aspects,
    )?;
    Ok(store_handle(dest))
}

/// Announce a destination so that remote peers can discover it.
pub fn destination_announce(dest_handle: u64, app_data: Option<&[u8]>) -> Result<(), String> {
    let mut dest: Destination =
        take_handle(dest_handle).ok_or_else(|| "invalid destination handle".to_string())?;
    dest.announce(app_data, false, None, None, true)?;
    store_handle(dest);
    Ok(())
}

/// Destroy a destination handle.
pub fn destination_destroy(dest_handle: u64) -> bool {
    destroy_handle(dest_handle)
}

// ---------------------------------------------------------------------------
// Link-based request (synchronous one-shot)
// ---------------------------------------------------------------------------

/// Open a Link to a remote destination, send a request on a named path, wait for the response, tear down the
/// link, and return the raw response bytes.
///
/// This is a blocking call — callers should invoke it from a background
/// thread.
///
/// * `dest_hash`  — 16-byte truncated RNS hash of the remote destination.
/// * `app_name`   — RNS app name, e.g. `"rfed"`.
/// * `aspects`    — aspect list, e.g. `vec!["notify"]`.
/// * `identity_handle` — handle to the local identity (used to authorise the link with the server, if needed).
/// * `path`       — request path, e.g. `"/rfed/notify/register"`.
/// * `payload`    — request payload bytes.
/// * `timeout_secs` — seconds to wait for establishment, and the request's
///   own timeout (RNS/Link.py `request(timeout=)`): how long its response may
///   take to begin. A response that arrives as a Resource is then waited for
///   while it moves, however long it takes ([`ResponseWait`]).
///
/// Returns the raw response bytes, or an error string.
pub fn link_request(
    dest_hash: &[u8],
    app_name: &str,
    aspects: Vec<String>,
    identity_handle: u64,
    path: &str,
    payload: &[u8],
    timeout_secs: f64,
) -> Result<Vec<u8>, String> {
    link_request_within(dest_hash, app_name, aspects, identity_handle, path, payload, timeout_secs, None)
}

/// [`link_request`] with a ceiling on the whole call: `ceiling_secs` after it
/// starts, the call ends whatever is still arriving. For a caller that lives
/// under a time budget it does not set, such as an iOS Notification Service
/// Extension, which the system ends after about 30 s. A hard ceiling on a
/// wait that events decide (DESIGN_PRINCIPLES §4), not a measure of the
/// transfer: a response that needs longer is left to a caller without one
/// (rfed keeps a pull page until it is proved).
pub fn link_request_within(
    dest_hash: &[u8],
    app_name: &str,
    aspects: Vec<String>,
    identity_handle: u64,
    path: &str,
    payload: &[u8],
    timeout_secs: f64,
    ceiling_secs: Option<f64>,
) -> Result<Vec<u8>, String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    let call_started = Instant::now();
    let our_identity: Identity =
        get_handle(identity_handle).ok_or_else(|| "invalid identity handle".to_string())?;

    let dest = destination_create_outbound_from_hash(dest_hash, app_name, aspects)?;
    let dest_obj: Destination =
        take_handle(dest).ok_or_else(|| "destination lost".to_string())?;

    let link = crate::link::Link::new_outbound(dest_obj, crate::link::MODE_AES256_CBC)?;
    let link_handle = crate::link::LinkHandle::spawn(link);

    let established = Arc::new(AtomicBool::new(false));
    let est_failed = Arc::new(AtomicBool::new(false));
    let wait = Arc::new(ResponseWait::new());

    // Set callbacks and initiate the link handshake.
    {
        let est = Arc::clone(&established);

        link_handle.set_link_established_callback(Some(Arc::new(move |_handle: crate::link::LinkHandle| {
            est.store(true, Ordering::SeqCst);
        })));

        // The link closing ends the wait for a response as well. The close
        // fails a pending request through its failed callback anyway
        // (Link::link_closed); this covers a close before the request is out.
        let fail = Arc::clone(&est_failed);
        let closed_wait = Arc::clone(&wait);
        link_handle.set_link_closed_callback(Some(Arc::new(move |_| {
            fail.store(true, Ordering::SeqCst);
            closed_wait.conclude(Err("the link closed before the response".to_string()));
        })));

        link_handle.initiate()?;
    }

    // Note: the link actor registers the runtime handle itself once the
    // real link_id is derived inside `initiate_prepare()`. Pre-2026-04-29
    // this site also called `register_runtime_link_handle(...)`, which
    // produced spurious "(replaced existing entry)" log lines on every
    // outbound link. The actor's registration is sufficient.

    // Wait for link establishment, bounded by the caller's timeout (and its
    // ceiling, if that comes first).
    let establish_for = ceiling_secs.map_or(timeout_secs, |ceiling| ceiling.min(timeout_secs));
    let deadline = call_started + Duration::from_secs_f64(establish_for.max(0.0));
    loop {
        if established.load(Ordering::SeqCst) {
            break;
        }
        if est_failed.load(Ordering::SeqCst) {
            return Err("Link establishment failed".to_string());
        }
        if Instant::now() >= deadline {
            link_handle.teardown();
            return Err("Link establishment timed out".to_string());
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Identify the link with our identity BEFORE issuing the request.
    //
    // Without this, the remote handler sees `caller=None` and any path that
    // authenticates by caller hash (e.g. rfed `/rfed/pull`, which keys the
    // deferred-blob queue by subscriber identity) silently returns nothing.
    // That used to manifest as a malformed 19-byte response packet on the
    // wire — see Reticulum-rust commit 8eca76d (now reverted) for the
    // downstream symptom. Mirrors the LXMF propagation sync path which
    // explicitly identifies before requesting.
    if let Err(e) = link_handle.identify(&our_identity) {
        link_handle.teardown();
        return Err(format!("identify failed: {:?}", e));
    }

    // Send the request with the caller's timeout as its own (RNS/Link.py
    // `request(timeout=)`). The link fails the request if no response has
    // begun within it, and stops applying it once the response arrives as a
    // Resource (RECEIVING, `actor_check_request_timeouts`). From then on the
    // transfer's own events decide: its response, the Resource failing, the
    // link closing (DESIGN_PRINCIPLES §1, bulk transfers). Until 2026-10-13
    // this waited `timeout_secs` from the request whatever was still
    // arriving, then tore the link down: a phone never took a /rfed/pull
    // page that needs more than 5 s, and rfed sent it again on every pull
    // (PULL-PROOF-DESIGN.md, the Android emulator run).
    let started = Instant::now();
    // The caller's ceiling on the wait's clock, which starts here.
    let ceiling = ceiling_secs.map(|ceiling| ceiling - started.duration_since(call_started).as_secs_f64());
    let response_cb: Arc<dyn Fn(crate::link::RequestReceipt) + Send + Sync> = {
        let wait = Arc::clone(&wait);
        Arc::new(move |receipt: crate::link::RequestReceipt| {
            wait.conclude(receipt.response.ok_or_else(|| "Request failed or timed out".to_string()));
        })
    };
    let failed_cb: Arc<dyn Fn(crate::link::RequestReceipt) + Send + Sync> = {
        let wait = Arc::clone(&wait);
        Arc::new(move |_receipt| {
            wait.conclude(Err("Request failed or timed out".to_string()));
        })
    };
    // The response Resource's advertisement and every part received.
    let progress_cb: Arc<dyn Fn(crate::link::RequestReceipt) + Send + Sync> = {
        let wait = Arc::clone(&wait);
        let what = path.to_string();
        Arc::new(move |_receipt| {
            wait.moved(started.elapsed().as_secs_f64(), &what);
        })
    };

    // The link's own stale time, from its round-trip time (Link::update_keepalive).
    let stale_after = link_handle
        .snapshot()
        .ok()
        .and_then(|snapshot| snapshot.rtt)
        .map(|rtt| crate::link::keepalive_for_rtt(rtt) * crate::link::STALE_FACTOR)
        .unwrap_or(crate::link::STALE_TIME);

    link_handle.request_with_options(
        path.to_string(),
        payload.to_vec(),
        Some(response_cb),
        Some(failed_cb),
        Some(progress_cb),
        Some(timeout_secs),
        None,
    )?;

    let outcome = loop {
        match wait.step(started.elapsed().as_secs_f64(), stale_after, ceiling, path) {
            ResponseWaitStep::Done(outcome) => break outcome,
            ResponseWaitStep::Ceiling => {
                let ceiling_secs = ceiling_secs.unwrap_or_default();
                crate::log(
                    &format!(
                        "[REQ] '{}' reached the caller's ceiling of {:.1}s before its response was in: tearing the link down",
                        path, ceiling_secs,
                    ),
                    crate::LOG_NOTICE, false, false,
                );
                wait.conclude(Err(format!("the caller's ceiling of {:.1}s came before the response", ceiling_secs)));
                link_handle.teardown();
            }
            ResponseWaitStep::Stale(silence) => {
                crate::log(
                    &format!(
                        "[REQ] the response to '{}' has been silent for {:.1}s, longer than the link's stale time ({:.1}s): tearing the link down",
                        path, silence, stale_after,
                    ),
                    crate::LOG_ERROR, false, false,
                );
                // Concluded first, so this reason stands over the link closing.
                wait.conclude(Err(format!("the response went silent for {:.1}s", silence)));
                link_handle.teardown();
            }
            ResponseWaitStep::Waiting => wait.park(Duration::from_millis(100)),
        }
    };

    // Teardown the link.
    link_handle.teardown();

    // DESIGN_PRINCIPLES §1 ("Panic at the end", James, 2026-10-10): each
    // silence was logged when it was seen; a debug build panics now that the
    // request is over and its link torn down.
    // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
    #[cfg(debug_assertions)]
    {
        let violations = wait.violations();
        if !violations.is_empty() {
            panic!("{}", violations.join(" | "));
        }
    }

    outcome
}

/// DESIGN_PRINCIPLES §1, bulk transfers (James, 2026-09-30): a response that
/// arrives as a Resource must show progress at least this often.
/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
const RESPONSE_SILENCE_LIMIT_SECS: f64 = crate::send_assertion::SEND_LATENCY_LIMIT_SECS;

/// What [`link_request`] waits on once its request is out: the request's own
/// outcome (its response, its failure, the link closing), never a clock of
/// its own (DESIGN_PRINCIPLES §1, bulk transfers; RNS/Link.py RequestReceipt).
///
/// While the response arrives as a Resource, its progress is watched. A
/// silence over the §1 limit is asserted when it is seen: logged in every
/// build, and kept for the panic at the end in a debug build. It never fails
/// the request.
///
/// Between the segments of a split response no Resource is transferring, so
/// no Resource can fail if the next segment never comes. RNS waits there
/// with no end. That happens when the sender gave up between segments: its
/// cancel names a segment the receiver has already finished, so the
/// receiver ignores it, and the link stays up. There, a silence longer than
/// the link's own stale time ends the wait. A phone's pulls queue behind
/// this call (RfedDistroClient's pull lock), so a wait with no end would stop
/// every later pull.
struct ResponseWait {
    state: Mutex<ResponseWaitState>,
    changed: std::sync::Condvar,
}

#[derive(Default)]
struct ResponseWaitState {
    /// The request's outcome: its response, or why there is none. The first
    /// conclusion stands.
    outcome: Option<Result<Vec<u8>, String>>,
    /// When the response last moved (its advertisement, a part received), on
    /// the wait's clock. `None` until the response arrives as a Resource.
    moved_at: Option<f64>,
    /// The silence now running has been asserted.
    silence_asserted: bool,
    /// Each §1 silence asserted, as it was logged.
    violations: Vec<String>,
}

/// What one look at a [`ResponseWait`] found.
#[derive(Debug, PartialEq)]
enum ResponseWaitStep {
    /// The request concluded.
    Done(Result<Vec<u8>, String>),
    /// The response has been silent longer than the link's stale time, for
    /// this many seconds.
    Stale(f64),
    /// The caller's ceiling came ([`link_request_within`]).
    Ceiling,
    Waiting,
}

impl ResponseWait {
    fn new() -> Self {
        ResponseWait { state: Mutex::new(ResponseWaitState::default()), changed: std::sync::Condvar::new() }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ResponseWaitState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The request concluded with `outcome`. A later conclusion changes nothing.
    fn conclude(&self, outcome: Result<Vec<u8>, String>) {
        let mut state = self.lock();
        if state.outcome.is_none() {
            state.outcome = Some(outcome);
        }
        self.changed.notify_all();
    }

    /// The response to `what` moved at `now`. A silence over the limit that
    /// ended here, and was not asserted while it ran, is asserted now.
    fn moved(&self, now: f64, what: &str) {
        let mut state = self.lock();
        if let Some(at) = state.moved_at {
            if now - at > RESPONSE_SILENCE_LIMIT_SECS && !state.silence_asserted {
                state.assert_silence(what, now - at, false);
            }
        }
        state.moved_at = Some(now);
        state.silence_asserted = false;
    }

    /// One look at `now`: the outcome if the request concluded; otherwise a
    /// running silence over the limit is asserted (once), one longer than
    /// `stale_after` is reported, and so is reaching the caller's `ceiling`.
    fn step(&self, now: f64, stale_after: f64, ceiling: Option<f64>, what: &str) -> ResponseWaitStep {
        let mut state = self.lock();
        if let Some(outcome) = state.outcome.clone() {
            return ResponseWaitStep::Done(outcome);
        }
        if let Some(at) = state.moved_at {
            let silence = now - at;
            if silence > RESPONSE_SILENCE_LIMIT_SECS && !state.silence_asserted {
                state.assert_silence(what, silence, true);
                state.silence_asserted = true;
            }
            if silence > stale_after {
                return ResponseWaitStep::Stale(silence);
            }
        }
        if ceiling.map_or(false, |ceiling| now >= ceiling) {
            return ResponseWaitStep::Ceiling;
        }
        ResponseWaitStep::Waiting
    }

    /// Blocks until the wait changes, or for `at_most`.
    fn park(&self, at_most: std::time::Duration) {
        let state = self.lock();
        if state.outcome.is_none() {
            let _ = self.changed.wait_timeout(state, at_most);
        }
    }

    fn violations(&self) -> Vec<String> {
        self.lock().violations.clone()
    }
}

impl ResponseWaitState {
    // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
    fn assert_silence(&mut self, what: &str, secs: f64, running: bool) {
        let msg = format!(
            "DESIGN_PRINCIPLES §1 VIOLATION: the response to '{}' {} silent for {:.2}s while it arrived \
             (limit {:.1}s). A moving transfer must show progress at least that often.",
            what, if running { "has been" } else { "was" }, secs, RESPONSE_SILENCE_LIMIT_SECS,
        );
        eprintln!("[SEND-ASSERT] {}", msg);
        crate::log(&msg, crate::LOG_ERROR, false, false);
        self.violations.push(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_handle_mut_changes_the_value_in_place_and_keeps_the_handle() {
        let id = store_handle(41u32);
        assert_eq!(with_handle_mut(id, |v: &mut u32| { *v += 1; *v }), Some(42));
        assert_eq!(get_handle::<u32>(id), Some(42), "the same handle holds the changed value");
        assert_eq!(with_handle_mut(id, |_: &mut String| ()), None, "another type is not found");
        destroy_handle(id);
        assert_eq!(with_handle_mut(id, |_: &mut u32| ()), None, "a destroyed handle is not found");
    }

    // ── link_request's wait for its response (ResponseWait) ──────────────

    /// A link's stale time at a LAN round-trip time (KEEPALIVE_MIN × STALE_FACTOR).
    const STALE: f64 = 10.0;

    #[test]
    fn a_response_that_keeps_moving_is_waited_for_past_5_s() {
        let wait = ResponseWait::new();
        let mut t = 4.5;   // the advertisement, inside the request's own timeout
        while t < 30.0 {
            wait.moved(t, "/rfed/pull");
            assert_eq!(wait.step(t + 0.9, STALE, None, "/rfed/pull"), ResponseWaitStep::Waiting, "still arriving at {} s", t + 0.9);
            t += 1.0;
        }
        wait.conclude(Ok(vec![1, 2, 3]));
        assert_eq!(wait.step(t, STALE, None, "/rfed/pull"), ResponseWaitStep::Done(Ok(vec![1, 2, 3])));
        assert!(wait.violations().is_empty(), "it never went silent: {:?}", wait.violations());
    }

    #[test]
    fn a_silence_over_the_limit_is_asserted_once_and_never_fails_the_request() {
        let wait = ResponseWait::new();
        wait.moved(1.0, "/rfed/pull");
        assert_eq!(wait.step(6.5, STALE, None, "/rfed/pull"), ResponseWaitStep::Waiting, "a silence is not a failure");
        assert_eq!(wait.step(7.0, STALE, None, "/rfed/pull"), ResponseWaitStep::Waiting);
        assert_eq!(wait.violations().len(), 1, "asserted once while it runs: {:?}", wait.violations());
        assert!(wait.violations()[0].contains("'/rfed/pull' has been silent for 5.50s"), "{:?}", wait.violations());
        wait.moved(8.0, "/rfed/pull");
        assert_eq!(wait.violations().len(), 1, "its end is not a second violation");
        wait.moved(14.5, "/rfed/pull");
        assert_eq!(wait.violations().len(), 2, "a later silence is asserted in its turn");
        wait.conclude(Ok(vec![9]));
        assert_eq!(wait.step(15.0, STALE, None, "/rfed/pull"), ResponseWaitStep::Done(Ok(vec![9])));
    }

    #[test]
    fn a_silence_that_ended_between_looks_is_asserted_too() {
        let wait = ResponseWait::new();
        wait.moved(1.0, "/rfed/pull");
        assert_eq!(wait.step(5.9, STALE, None, "/rfed/pull"), ResponseWaitStep::Waiting);
        wait.moved(6.25, "/rfed/pull");   // 5.25 s since the last move, and no look saw it over the limit
        assert_eq!(wait.violations().len(), 1, "{:?}", wait.violations());
        assert!(wait.violations()[0].contains("was silent for 5.25s"), "{:?}", wait.violations());
    }

    #[test]
    fn a_silence_longer_than_the_links_stale_time_ends_the_wait() {
        let wait = ResponseWait::new();
        wait.moved(1.0, "/rfed/pull");
        assert_eq!(wait.step(10.75, STALE, None, "/rfed/pull"), ResponseWaitStep::Waiting);
        assert_eq!(wait.step(11.5, STALE, None, "/rfed/pull"), ResponseWaitStep::Stale(10.5));
    }

    #[test]
    fn before_the_response_begins_nothing_here_decides() {
        // The request's own timeout decides that phase (the link fails the
        // request), so no silence is counted before the response moves.
        let wait = ResponseWait::new();
        assert_eq!(wait.step(100.0, STALE, None, "/rfed/pull"), ResponseWaitStep::Waiting);
        assert!(wait.violations().is_empty());
    }

    #[test]
    fn the_first_conclusion_stands() {
        let wait = ResponseWait::new();
        wait.conclude(Err("Request failed or timed out".to_string()));
        wait.conclude(Ok(vec![1]));
        assert_eq!(wait.step(0.0, STALE, None, "/rfed/pull"), ResponseWaitStep::Done(Err("Request failed or timed out".to_string())));
    }

    #[test]
    fn park_returns_when_the_request_concludes() {
        let wait = Arc::new(ResponseWait::new());
        let concluder = {
            let wait = Arc::clone(&wait);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(50));
                wait.conclude(Ok(vec![7]));
            })
        };
        let start = std::time::Instant::now();
        while !matches!(wait.step(0.0, STALE, None, "/rfed/pull"), ResponseWaitStep::Done(_)) {
            wait.park(std::time::Duration::from_secs(10));
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "woken by the conclusion, not by its bound");
        concluder.join().unwrap();
    }

    #[test]
    fn the_callers_ceiling_ends_the_wait_even_while_the_response_moves() {
        let wait = ResponseWait::new();
        let mut t = 1.0;
        while t < 20.0 {
            wait.moved(t, "/rfed/pull");
            assert_eq!(wait.step(t + 0.5, STALE, Some(20.0), "/rfed/pull"), ResponseWaitStep::Waiting, "at {} s", t + 0.5);
            t += 1.0;
        }
        wait.moved(20.0, "/rfed/pull");
        assert_eq!(wait.step(20.0, STALE, Some(20.0), "/rfed/pull"), ResponseWaitStep::Ceiling);
        assert!(wait.violations().is_empty(), "a ceiling is not a silence: {:?}", wait.violations());
    }

    #[test]
    fn the_callers_ceiling_bounds_the_wait_before_the_response_begins_too() {
        let wait = ResponseWait::new();
        assert_eq!(wait.step(7.9, STALE, Some(8.0), "/rfed/pull"), ResponseWaitStep::Waiting);
        assert_eq!(wait.step(8.0, STALE, Some(8.0), "/rfed/pull"), ResponseWaitStep::Ceiling);
    }

    #[test]
    fn a_concluded_request_is_done_whatever_the_ceiling() {
        let wait = ResponseWait::new();
        wait.conclude(Ok(vec![5]));
        assert_eq!(wait.step(30.0, STALE, Some(20.0), "/rfed/pull"), ResponseWaitStep::Done(Ok(vec![5])));
    }
}
