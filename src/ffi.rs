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
pub fn shutdown() -> Result<(), String> {
    crate::reticulum::exit_handler();
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
/// * `refresh_secs`      Periodic refresh interval in seconds. `0.0` means
///                       no periodic announce; the destination is only
///                       re-announced on interface up-edges.
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

/// Send a packet.  Returns the receipt handle (0 if no receipt).
pub fn packet_send(packet_handle: u64) -> Result<u64, String> {
    let mut packet: crate::packet::Packet =
        take_handle(packet_handle).ok_or_else(|| "invalid packet handle".to_string())?;
    match packet.send() {
        Ok(Some(receipt)) => Ok(store_handle(receipt)),
        Ok(None) => Ok(0),
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
    Some(receipt.status)
}

/// Get the receipt's packet hash (for matching with Transport callbacks).
pub fn receipt_get_hash(receipt_handle: u64) -> Option<Vec<u8>> {
    let receipt: crate::packet::PacketReceipt = get_handle(receipt_handle)?;
    Some(receipt.hash.clone())
}

/// Set delivery and timeout callbacks on a receipt.
///
/// The callbacks receive (rtt_seconds,) and () respectively.
/// They are called from the Transport job thread.
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
/// * `timeout_secs` — seconds to wait for establishment and for the response.
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    let our_identity: Identity =
        get_handle(identity_handle).ok_or_else(|| "invalid identity handle".to_string())?;

    let dest = destination_create_outbound_from_hash(dest_hash, app_name, aspects)?;
    let dest_obj: Destination =
        take_handle(dest).ok_or_else(|| "destination lost".to_string())?;

    let link = crate::link::Link::new_outbound(dest_obj, crate::link::MODE_AES256_CBC)?;
    let link_handle = crate::link::LinkHandle::spawn(link);

    let established = Arc::new(AtomicBool::new(false));
    let est_failed = Arc::new(AtomicBool::new(false));

    // Set callbacks and initiate the link handshake.
    {
        let est = Arc::clone(&established);

        link_handle.set_link_established_callback(Some(Arc::new(move |_handle: crate::link::LinkHandle| {
            est.store(true, Ordering::SeqCst);
        })));

        let fail = Arc::clone(&est_failed);
        link_handle.set_link_closed_callback(Some(Arc::new(move |_| {
            fail.store(true, Ordering::SeqCst);
        })));

        link_handle.initiate()?;
    }

    // Note: the link actor registers the runtime handle itself once the
    // real link_id is derived inside `initiate_prepare()`. Pre-2026-04-29
    // this site also called `register_runtime_link_handle(...)`, which
    // produced spurious "(replaced existing entry)" log lines on every
    // outbound link. The actor's registration is sufficient.

    // Wait for link establishment, bounded by the caller's timeout.
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
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

    // Send the request and wait for the response.
    let response_data: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let request_done = Arc::new(AtomicBool::new(false));

    let resp_ok = Arc::clone(&response_data);
    let done_ok = Arc::clone(&request_done);
    let response_cb: Arc<dyn Fn(crate::link::RequestReceipt) + Send + Sync> =
        Arc::new(move |receipt: crate::link::RequestReceipt| {
            if let Some(ref data) = receipt.response {
                if let Ok(mut r) = resp_ok.lock() {
                    *r = Some(data.clone());
                }
            }
            done_ok.store(true, Ordering::SeqCst);
        });

    let done_fail = Arc::clone(&request_done);
    let failed_cb: Arc<dyn Fn(crate::link::RequestReceipt) + Send + Sync> =
        Arc::new(move |_receipt| {
            done_fail.store(true, Ordering::SeqCst);
        });

    link_handle.request(
        path.to_string(),
        payload.to_vec(),
        Some(response_cb),
        Some(failed_cb),
        None,
    )?;

    // Wait for request response.
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
    loop {
        if request_done.load(Ordering::SeqCst) {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    // Teardown the link.
    link_handle.teardown();

    // Return the response.
    let result = response_data
        .lock()
        .map_err(|_| "response lock poisoned")?
        .take();
    result.ok_or_else(|| "Request failed or timed out".to_string())
}
