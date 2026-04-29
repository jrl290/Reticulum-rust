//! Universal C FFI for the Reticulum transport client.
//!
//! This is the **single, authoritative** C interface for any language bridge
//! wanting Reticulum transport without LXMF.  Mirrors the `lxmf_*` pattern
//! in LXMF-rust/cffi.rs.
//!
//! # Naming convention
//!
//! | Prefix              | Scope                          |
//! |---------------------|--------------------------------|
//! | `rns_client_*`      | client-handle operations       |
//! | `rns_transport_*`   | path queries                   |
//! | `rns_packet_*`      | single-shot encrypted packets  |
//! | `rns_link_*`        | blocking link request          |
//! | `rns_*`             | library-level helpers/settings |
//!
//! # Handle convention
//!
//! Opaque `u64` handles.  `0` = error (check [`rns_last_error`]).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

use crate::client::{ReticulumClient, ReticulumConfig};
use crate::ffi;
use crate::ffi::{destroy_handle, get_handle, set_error, store_handle, take_error};

// =========================================================================
// Internal helpers
// =========================================================================

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

fn string_to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn slice_from_raw(ptr: *const u8, len: u32) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(ptr, len as usize).to_vec() }
}

/// Lock a client handle or return -1.
macro_rules! with_client {
    ($handle:expr, $name:ident, $body:block) => {{
        let arc: Arc<Mutex<ReticulumClient>> = match get_handle($handle) {
            Some(h) => h,
            None => {
                set_error("invalid client handle".into());
                return -1;
            }
        };
        let $name = arc.lock().unwrap();
        $body
    }};
}

// =========================================================================
// Library helpers
// =========================================================================

/// Get the last error message.  Caller must free with [`rns_free_string`].
/// Returns NULL if no error is set.
#[no_mangle]
pub extern "C" fn rns_last_error() -> *mut c_char {
    match take_error() {
        Some(msg) => string_to_cstr(&msg),
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn rns_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

/// Free bytes returned by this library.
#[no_mangle]
pub extern "C" fn rns_free_bytes(ptr: *mut u8, len: u32) {
    if !ptr.is_null() && len > 0 {
        unsafe { let _ = Vec::from_raw_parts(ptr, len as usize, len as usize); }
    }
}

// =========================================================================
// Client lifecycle
// =========================================================================

/// Start a Reticulum transport client (init transport + load/create identity).
///
/// Returns a client handle (>0) or 0 on error.
#[no_mangle]
pub extern "C" fn rns_client_start(
    config_dir: *const c_char,
    identity_path: *const c_char,
    create_identity: i32,
    log_level: i32,
) -> u64 {
    let config = ReticulumConfig {
        config_dir: unsafe { cstr_to_string(config_dir) },
        identity_path: unsafe { cstr_to_string(identity_path) },
        create_identity: create_identity != 0,
        log_level,
    };

    match ReticulumClient::start(config) {
        Ok(client) => store_handle(Arc::new(Mutex::new(client))),
        Err(e) => {
            set_error(e);
            0
        }
    }
}

/// Shut down a client: destroy identity + tear down transport.
/// Handle is invalidated.  Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_client_shutdown(client: u64) -> i32 {
    let arc: Arc<Mutex<ReticulumClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle".into());
            return -1;
        }
    };
    let c = arc.lock().unwrap();
    match c.shutdown() {
        Ok(()) => {
            destroy_handle(client);
            0
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

// =========================================================================
// Client queries
// =========================================================================

/// Get the client's identity handle (for passing to transport-level
/// functions like `rns_link_request`).
/// Returns 0 on error.
#[no_mangle]
pub extern "C" fn rns_client_identity_handle(client: u64) -> u64 {
    let arc: Arc<Mutex<ReticulumClient>> = match get_handle(client) {
        Some(h) => h,
        None => {
            set_error("invalid client handle".into());
            return 0;
        }
    };
    let c = arc.lock().unwrap();
    c.identity_handle
}

/// Get the client's 16-byte identity hash.
/// Writes to `out_buf`.  Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn rns_client_identity_hash(
    client: u64,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    with_client!(client, c, {
        let hash = &c.identity_hash;
        if buf_len < hash.len() as u32 {
            set_error("buffer too small".into());
            return -1;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, hash.len());
        }
        hash.len() as i32
    })
}

/// Compute a destination hash for this identity + app_name + aspects.
/// `aspects` is comma-separated (e.g. "delivery" or "apns,notify").
/// Writes to `out_buf`.  Returns bytes written, or -1 on error.
#[no_mangle]
pub extern "C" fn rns_client_dest_hash(
    client: u64,
    app_name: *const c_char,
    aspects: *const c_char,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    with_client!(client, c, {
        let app = unsafe { cstr_to_string(app_name) };
        let asp_str = unsafe { cstr_to_string(aspects) };
        let asp_vec: Vec<&str> = asp_str.split(',').map(|s| s.trim()).collect();

        match c.destination_hash(&app, &asp_vec) {
            Ok(hash) => {
                if buf_len < hash.len() as u32 {
                    set_error("buffer too small".into());
                    return -1;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(hash.as_ptr(), out_buf, hash.len());
                }
                hash.len() as i32
            }
            Err(e) => {
                set_error(e);
                -1
            }
        }
    })
}

/// Persist path table and cached data to disk.
#[no_mangle]
pub extern "C" fn rns_client_persist(client: u64) {
    if let Some(arc) = get_handle::<Arc<Mutex<ReticulumClient>>>(client) {
        if let Ok(c) = arc.lock() {
            c.persist();
        }
    }
}

// =========================================================================
// Transport / path queries (stateless — don't need a client handle)
// =========================================================================

/// Check whether transport has a path to the destination.  Returns 1/0.
#[no_mangle]
pub extern "C" fn rns_transport_has_path(dest_hash: *const u8, len: u32) -> i32 {
    let h = slice_from_raw(dest_hash, len);
    if ffi::transport_has_path(&h) { 1 } else { 0 }
}

/// Request a path to a destination.  Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_transport_request_path(dest_hash: *const u8, len: u32) -> i32 {
    let h = slice_from_raw(dest_hash, len);
    match ffi::transport_request_path(&h) {
        Ok(()) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

/// Get hop count to a destination.  Returns hops or -1 if unknown.
#[no_mangle]
pub extern "C" fn rns_transport_hops_to(dest_hash: *const u8, len: u32) -> i32 {
    let h = slice_from_raw(dest_hash, len);
    ffi::transport_hops_to(&h)
}

/// Query whether a configured interface (by name) is currently online.
/// Returns: 1 = online, 0 = offline, -1 = unknown / no such interface.
#[no_mangle]
pub extern "C" fn rns_interface_online(name: *const c_char) -> i32 {
    let n = unsafe { cstr_to_string(name) };
    if n.is_empty() {
        set_error("interface name is empty".into());
        return -1;
    }
    ffi::interface_online(&n)
}

// =========================================================================
// Published destinations (Transport-managed announce daemon)
// =========================================================================

/// Opt a destination into Transport's auto-announce daemon.
///
/// `dest_hash` / `hash_len` — destination hash (16 bytes typical).
/// `refresh_secs`           — periodic refresh interval in seconds. Pass
///                            `0.0` to only re-announce on interface
///                            up-edges (no periodic timer).
/// `app_data` / `app_data_len` — optional app_data; pass `null`/0 to use
///                               the destination's configured app_data.
///
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn rns_transport_publish_destination(
    dest_hash: *const u8,
    hash_len: u32,
    refresh_secs: f64,
    app_data: *const u8,
    app_data_len: u32,
) -> i32 {
    let h = slice_from_raw(dest_hash, hash_len);
    if h.is_empty() {
        set_error("destination hash is empty".into());
        return -1;
    }
    let app = if app_data.is_null() || app_data_len == 0 {
        None
    } else {
        Some(slice_from_raw(app_data, app_data_len))
    };
    ffi::transport_publish_destination(&h, refresh_secs, app.as_deref());
    0
}

/// Remove a destination from the announce daemon's published set.
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn rns_transport_unpublish_destination(
    dest_hash: *const u8,
    hash_len: u32,
) -> i32 {
    let h = slice_from_raw(dest_hash, hash_len);
    if h.is_empty() {
        set_error("destination hash is empty".into());
        return -1;
    }
    ffi::transport_unpublish_destination(&h);
    0
}

/// Query whether a destination is currently published.
/// Returns 1 = published, 0 = not published, -1 = invalid input.
#[no_mangle]
pub extern "C" fn rns_transport_is_published(
    dest_hash: *const u8,
    hash_len: u32,
) -> i32 {
    let h = slice_from_raw(dest_hash, hash_len);
    if h.is_empty() {
        set_error("destination hash is empty".into());
        return -1;
    }
    if ffi::transport_is_published(&h) { 1 } else { 0 }
}

// =========================================================================
// Settings (stateless)
// =========================================================================

/// Enable/disable announce filtering.  1 = drop, 0 = accept.
#[no_mangle]
pub extern "C" fn rns_set_drop_announces(enabled: i32) {
    ffi::set_drop_announces(enabled != 0);
}

/// Set keepalive interval in seconds.  Returns 0 on success.
#[no_mangle]
pub extern "C" fn rns_set_keepalive_interval(secs: f64) -> i32 {
    match ffi::set_keepalive_interval(secs) {
        Ok(()) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

// =========================================================================
// Identity (standalone — outside a client lifecycle)
// =========================================================================

/// Load identity from raw bytes.  Returns handle or 0 on error.
#[no_mangle]
pub extern "C" fn rns_identity_from_bytes(bytes: *const u8, len: u32) -> u64 {
    let b = slice_from_raw(bytes, len);
    match ffi::identity_from_bytes(&b) {
        Ok(h) => h,
        Err(e) => { set_error(e); 0 }
    }
}

/// Get identity public key.  Writes to `out_buf` (>= 64 bytes).
/// Returns byte count written, or -1 on error.
#[no_mangle]
pub extern "C" fn rns_identity_public_key(
    handle: u64,
    out_buf: *mut u8,
    buf_len: u32,
) -> i32 {
    match ffi::identity_public_key(handle) {
        Ok(bytes) => {
            if buf_len < bytes.len() as u32 {
                set_error("buffer too small".into());
                return -1;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
            }
            bytes.len() as i32
        }
        Err(e) => { set_error(e); -1 }
    }
}

/// Destroy a standalone identity handle.  Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_identity_destroy(handle: u64) -> i32 {
    match ffi::identity_destroy(handle) {
        Ok(()) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

// =========================================================================
// Raw packet send
// =========================================================================

/// Send a single encrypted DATA packet to a remote destination by hash.
///
/// The remote identity must be in the known-destinations table (announce heard).
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn rns_packet_send_to_hash(
    dest_hash: *const u8,
    dest_hash_len: u32,
    app_name: *const c_char,
    aspects: *const c_char,
    payload: *const u8,
    payload_len: u32,
) -> i32 {
    let hash = slice_from_raw(dest_hash, dest_hash_len);
    let app = unsafe { cstr_to_string(app_name) };
    let asp_str = unsafe { cstr_to_string(aspects) };
    let asp_vec: Vec<String> = asp_str.split(',').map(|s| s.trim().to_string()).collect();
    let data = slice_from_raw(payload, payload_len);

    let dest_handle = match ffi::destination_create_outbound_from_hash(&hash, &app, asp_vec) {
        Ok(h) => h,
        Err(e) => { set_error(e); return -1; }
    };

    let pkt_handle = match ffi::packet_create(dest_handle, &data, false) {
        Ok(h) => h,
        Err(e) => {
            destroy_handle(dest_handle);
            set_error(e);
            return -1;
        }
    };
    destroy_handle(dest_handle);

    match ffi::packet_send(pkt_handle) {
        Ok(_) => 0,
        Err(e) => { set_error(e); -1 }
    }
}

// =========================================================================
// Link-based request (synchronous one-shot)
// =========================================================================

/// Open a Link, identify, send a request, wait for response, tear down.
///
/// **Blocking** — call from a background thread.
///
/// Returns response bytes (free with `rns_free_bytes`), or NULL on error
/// (check `rns_last_error`).
#[no_mangle]
pub extern "C" fn rns_link_request(
    dest_hash: *const u8,
    dest_hash_len: u32,
    app_name: *const c_char,
    aspects: *const c_char,
    identity_handle: u64,
    path: *const c_char,
    payload: *const u8,
    payload_len: u32,
    timeout_secs: f64,
    out_len: *mut u32,
) -> *mut u8 {
    let hash = slice_from_raw(dest_hash, dest_hash_len);
    let app = unsafe { cstr_to_string(app_name) };
    let asp_str = unsafe { cstr_to_string(aspects) };
    let asp_vec: Vec<String> = asp_str.split(',').map(|s| s.trim().to_string()).collect();
    let req_path = unsafe { cstr_to_string(path) };
    let data = slice_from_raw(payload, payload_len);

    match ffi::link_request(&hash, &app, asp_vec, identity_handle, &req_path, &data, timeout_secs) {
        Ok(resp) => {
            let len = resp.len() as u32;
            let ptr = resp.leak().as_mut_ptr();
            if !out_len.is_null() {
                unsafe { *out_len = len; }
            }
            ptr
        }
        Err(e) => {
            set_error(e);
            if !out_len.is_null() {
                unsafe { *out_len = 0; }
            }
            std::ptr::null_mut()
        }
    }
}

// =========================================================================
// Network connectivity hint
// =========================================================================

/// Signal that network connectivity has been restored.
///
/// Wakes all TCP client interface reconnect loops so they attempt an
/// immediate connect instead of waiting out the full polling interval.
/// Safe to call at any time; no-op if all interfaces are already online.
#[no_mangle]
pub extern "C" fn rns_nudge_reconnect() {
    crate::interfaces::tcp_interface::nudge_reconnect();
}

// =========================================================================
// RNode callback interface (KISS framing + radio config in Rust, raw bytes
// shuttled by a native bridge — e.g. CoreBluetooth on iOS).
// =========================================================================

/// C-ABI radio configuration for an RNode interface.
///
/// All fields are required. To leave an `Option<>` field unset, pass the
/// matching `_set` flag as 0; the value is then ignored.
#[repr(C)]
pub struct RnsRNodeRadioConfig {
    pub frequency: u64,
    pub bandwidth: u32,
    pub txpower: u8,
    pub sf: u8,
    pub cr: u8,
    /// 0 = no flow control, non-zero = enabled.
    pub flow_control: u8,
    /// 0 = no short-term airtime limit, 1 = use `st_alock_pct` (0..=100).
    pub st_alock_set: u8,
    pub st_alock_pct: f32,
    pub lt_alock_set: u8,
    pub lt_alock_pct: f32,
    /// 0 = no ID beacon, 1 = use `id_interval_secs` + `id_callsign`.
    pub id_beacon_set: u8,
    pub id_interval_secs: u64,
    /// Pointer to the callsign bytes (UTF-8 expected, but raw bytes are
    /// accepted). May be NULL when `id_beacon_set == 0`.
    pub id_callsign: *const u8,
    pub id_callsign_len: u32,
}

/// C-ABI snapshot of RNode telemetry returned by [`rns_rnode_iface_get_stats`].
///
/// `*_set` flags indicate whether the matching field has been populated by
/// the read loop yet. Numeric fields with no `_set` flag (like
/// `airtime_short`) are always populated with the latest value (initially 0).
#[repr(C)]
pub struct RnsRNodeStats {
    pub online: u8,
    pub detected: u8,
    pub frequency_set: u8,
    pub frequency: u64,
    pub bandwidth_set: u8,
    pub bandwidth: u32,
    pub txpower_set: u8,
    pub txpower: u8,
    pub sf_set: u8,
    pub sf: u8,
    pub cr_set: u8,
    pub cr: u8,
    pub rssi_set: u8,
    pub rssi: i16,
    pub snr_set: u8,
    pub snr: f32,
    pub q_set: u8,
    pub q: f32,
    pub rx_packets_set: u8,
    pub rx_packets: u32,
    pub tx_packets_set: u8,
    pub tx_packets: u32,
    pub airtime_short: f32,
    pub airtime_long: f32,
    pub channel_load_short: f32,
    pub channel_load_long: f32,
    /// Battery state (see [`crate::interfaces::rnode_interface::BatteryState`]).
    pub battery_state: u8,
    pub battery_percent: u8,
    pub temperature_set: u8,
    pub temperature: i8,
    pub firmware_maj: u8,
    pub firmware_min: u8,
}

/// TX callback signature: invoked from Rust when KISS-framed bytes are ready
/// to be written to the radio. The bridge is responsible for any link-MTU
/// chunking (e.g. 20-byte BLE writes). Return non-zero on success.
pub type RnsRNodeSendFn =
    unsafe extern "C" fn(user_data: *mut std::ffi::c_void, data: *const u8, len: u32) -> i32;

/// Register an RNode callback interface. Spawns the read loop and runs the
/// DETECT/init handshake synchronously (~3s while bytes are fed in).
///
/// `name`      – interface name (also used as the Transport routing key).
/// `send_fn`   – TX callback (see [`RnsRNodeSendFn`]).
/// `user_data` – opaque pointer passed back to `send_fn` on every call.
/// `cfg`       – radio parameters.
///
/// Returns a handle (>0) or 0 on error (check [`rns_last_error`]).
///
/// # Safety
/// `name` must be a NUL-terminated UTF-8 string. `cfg` must point to a valid
/// `RnsRNodeRadioConfig` and remain valid for the duration of this call. If
/// `cfg.id_beacon_set != 0`, `cfg.id_callsign` must point to at least
/// `cfg.id_callsign_len` valid bytes.
#[cfg(feature = "serial")]
#[no_mangle]
pub unsafe extern "C" fn rns_rnode_iface_register(
    name: *const c_char,
    send_fn: RnsRNodeSendFn,
    user_data: *mut std::ffi::c_void,
    cfg: *const RnsRNodeRadioConfig,
) -> u64 {
    if cfg.is_null() {
        set_error("cfg is null".into());
        return 0;
    }
    let name_s = cstr_to_string(name);
    let c = &*cfg;

    let id_callsign: Option<Vec<u8>> = if c.id_beacon_set != 0 && !c.id_callsign.is_null() && c.id_callsign_len > 0 {
        Some(slice_from_raw(c.id_callsign, c.id_callsign_len))
    } else {
        None
    };
    let id_interval = if c.id_beacon_set != 0 {
        Some(std::time::Duration::from_secs(c.id_interval_secs))
    } else {
        None
    };

    let config = crate::interfaces::rnode_interface::RNodeRadioConfig {
        frequency: c.frequency,
        bandwidth: c.bandwidth,
        txpower: c.txpower,
        sf: c.sf,
        cr: c.cr,
        flow_control: c.flow_control != 0,
        st_alock: if c.st_alock_set != 0 { Some(c.st_alock_pct) } else { None },
        lt_alock: if c.lt_alock_set != 0 { Some(c.lt_alock_pct) } else { None },
        id_interval,
        id_callsign,
    };

    // Adapter: wrap the C function pointer + user_data into a Rust closure.
    // SAFETY: `user_data` is treated as an opaque pointer; we never deref it.
    // The bridge must keep whatever it points at alive until the matching
    // `rns_rnode_iface_deregister` call.
    let user_data_addr = user_data as usize;
    let send_arc: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(move |data: &[u8]| -> bool {
        let ud = user_data_addr as *mut std::ffi::c_void;
        let rc = unsafe { send_fn(ud, data.as_ptr(), data.len() as u32) };
        rc != 0
    });

    match crate::ffi::rnode_iface_register(&name_s, send_arc, config) {
        Ok(h) => h,
        Err(e) => {
            set_error(e);
            0
        }
    }
}

/// Build the RNode interface and spawn its read loop, but do NOT run the
/// DETECT/init handshake. The native bridge can call this synchronously,
/// store the returned handle, then start feeding RX bytes via
/// [`rns_rnode_iface_feed`] before calling [`rns_rnode_iface_configure`]
/// on a background thread.
///
/// Returns a handle (>0) or 0 on error (check [`rns_last_error`]).
///
/// # Safety
/// Same as [`rns_rnode_iface_register`].
#[cfg(feature = "serial")]
#[no_mangle]
pub unsafe extern "C" fn rns_rnode_iface_create(
    name: *const c_char,
    send_fn: RnsRNodeSendFn,
    user_data: *mut std::ffi::c_void,
    cfg: *const RnsRNodeRadioConfig,
) -> u64 {
    if cfg.is_null() {
        set_error("cfg is null".into());
        return 0;
    }
    let name_s = cstr_to_string(name);
    let c = &*cfg;

    let id_callsign: Option<Vec<u8>> = if c.id_beacon_set != 0 && !c.id_callsign.is_null() && c.id_callsign_len > 0 {
        Some(slice_from_raw(c.id_callsign, c.id_callsign_len))
    } else {
        None
    };
    let id_interval = if c.id_beacon_set != 0 {
        Some(std::time::Duration::from_secs(c.id_interval_secs))
    } else {
        None
    };

    let config = crate::interfaces::rnode_interface::RNodeRadioConfig {
        frequency: c.frequency,
        bandwidth: c.bandwidth,
        txpower: c.txpower,
        sf: c.sf,
        cr: c.cr,
        flow_control: c.flow_control != 0,
        st_alock: if c.st_alock_set != 0 { Some(c.st_alock_pct) } else { None },
        lt_alock: if c.lt_alock_set != 0 { Some(c.lt_alock_pct) } else { None },
        id_interval,
        id_callsign,
    };

    let user_data_addr = user_data as usize;
    let send_arc: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = Arc::new(move |data: &[u8]| -> bool {
        let ud = user_data_addr as *mut std::ffi::c_void;
        let rc = unsafe { send_fn(ud, data.as_ptr(), data.len() as u32) };
        rc != 0
    });

    match crate::ffi::rnode_iface_create(&name_s, send_arc, config) {
        Ok(h) => h,
        Err(e) => {
            set_error(e);
            0
        }
    }
}

/// Run the DETECT/init handshake on a previously-created RNode handle and
/// wire it into the Transport. Blocks for ~2-4 seconds.
///
/// Returns 0 on success, -1 on error (check [`rns_last_error`]).
#[cfg(feature = "serial")]
#[no_mangle]
pub unsafe extern "C" fn rns_rnode_iface_configure(handle: u64) -> i32 {
    match crate::ffi::rnode_iface_configure(handle) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Push RX bytes (received from the radio over BLE/USB) into the RNode
/// interface's read loop.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `data` must point to at least `len` valid bytes.
#[cfg(feature = "serial")]
#[no_mangle]
pub unsafe extern "C" fn rns_rnode_iface_feed(
    handle: u64,
    data: *const u8,
    len: u32,
) -> i32 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let bytes = std::slice::from_raw_parts(data, len as usize);
    match crate::ffi::rnode_iface_feed(handle, bytes) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Fetch the latest device telemetry into `out`.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `out` must point to a valid, writable [`RnsRNodeStats`].
#[cfg(feature = "serial")]
#[no_mangle]
pub unsafe extern "C" fn rns_rnode_iface_get_stats(
    handle: u64,
    out: *mut RnsRNodeStats,
) -> i32 {
    if out.is_null() {
        set_error("out is null".into());
        return -1;
    }
    let snap = match crate::ffi::rnode_iface_get_stats(handle) {
        Ok(s) => s,
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    *out = RnsRNodeStats {
        online: if snap.online { 1 } else { 0 },
        detected: if snap.detected { 1 } else { 0 },
        frequency_set: if snap.frequency.is_some() { 1 } else { 0 },
        frequency: snap.frequency.unwrap_or(0),
        bandwidth_set: if snap.bandwidth.is_some() { 1 } else { 0 },
        bandwidth: snap.bandwidth.unwrap_or(0),
        txpower_set: if snap.txpower.is_some() { 1 } else { 0 },
        txpower: snap.txpower.unwrap_or(0),
        sf_set: if snap.sf.is_some() { 1 } else { 0 },
        sf: snap.sf.unwrap_or(0),
        cr_set: if snap.cr.is_some() { 1 } else { 0 },
        cr: snap.cr.unwrap_or(0),
        rssi_set: if snap.rssi.is_some() { 1 } else { 0 },
        rssi: snap.rssi.unwrap_or(0),
        snr_set: if snap.snr.is_some() { 1 } else { 0 },
        snr: snap.snr.unwrap_or(0.0),
        q_set: if snap.q.is_some() { 1 } else { 0 },
        q: snap.q.unwrap_or(0.0),
        rx_packets_set: if snap.rx_packets.is_some() { 1 } else { 0 },
        rx_packets: snap.rx_packets.unwrap_or(0),
        tx_packets_set: if snap.tx_packets.is_some() { 1 } else { 0 },
        tx_packets: snap.tx_packets.unwrap_or(0),
        airtime_short: snap.airtime_short,
        airtime_long: snap.airtime_long,
        channel_load_short: snap.channel_load_short,
        channel_load_long: snap.channel_load_long,
        battery_state: snap.battery_state as u8,
        battery_percent: snap.battery_percent,
        temperature_set: if snap.temperature.is_some() { 1 } else { 0 },
        temperature: snap.temperature.unwrap_or(0),
        firmware_maj: snap.firmware_maj,
        firmware_min: snap.firmware_min,
    };
    0
}

/// Send the configured ID-beacon callsign immediately.
/// Returns 0 on success, -1 on error.
#[cfg(feature = "serial")]
#[no_mangle]
pub extern "C" fn rns_rnode_iface_id_beacon_now(handle: u64) -> i32 {
    match crate::ffi::rnode_iface_id_beacon_now(handle) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Deregister an RNode callback interface and tear down the Transport
/// binding. The bridge must stop calling [`rns_rnode_iface_feed`] before
/// invoking this.
/// Returns 0 on success, -1 on error.
#[cfg(feature = "serial")]
#[no_mangle]
pub extern "C" fn rns_rnode_iface_deregister(handle: u64) -> i32 {
    match crate::ffi::rnode_iface_deregister(handle) {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}
