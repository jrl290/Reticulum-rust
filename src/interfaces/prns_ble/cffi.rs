//! C ABI for a host that drives the radio from C or Swift (Retichat iOS).
//! Declared by hand in Retichat-ios `CRetichatFFI.h`; keep the two in step.
//!
//! Every function returns 0 on success or -1 with the reason in
//! `rns_last_error()`, except `rns_prns_ble_sighted`.

use std::ffi::{c_char, c_void, CStr, CString};
use std::path::Path;
use std::sync::Arc;

use super::engine::{Characteristic, LinkState};
use super::runtime::{self, Host};
use super::wire::{Endpoint, IDENTITY_LEN};
use crate::ffi::set_error;

/// Start (`on` non-zero) or stop scanning for the Prns service.
pub type RnsPrnsBleScanFn = extern "C" fn(user_data: *mut c_void, on: i32);
/// Write `len` bytes to the characteristic (0 control, 1 data) with
/// response, then report the result with `rns_prns_ble_link_write_done`.
pub type RnsPrnsBleWriteFn =
    extern "C" fn(user_data: *mut c_void, link: u64, characteristic: u8, data: *const u8, len: u32);
/// Cancel the connection or connection attempt. No `link_closed` needed.
pub type RnsPrnsBleDisconnectFn = extern "C" fn(user_data: *mut c_void, link: u64);
/// The link is handshaking (0), settled (1), closed (2) or dialling (3).
/// `peer_identity` is 16 bytes or NULL, `interface_name` NUL-terminated or
/// NULL; both are valid only during the call.
pub type RnsPrnsBleStateFn = extern "C" fn(
    user_data: *mut c_void,
    link: u64,
    state: i32,
    peer_identity: *const u8,
    interface_name: *const c_char,
);

struct CHost {
    scan: RnsPrnsBleScanFn,
    write: RnsPrnsBleWriteFn,
    disconnect: RnsPrnsBleDisconnectFn,
    state: RnsPrnsBleStateFn,
    user_data: usize,
}

impl Host for CHost {
    fn scan(&self, on: bool) {
        (self.scan)(self.user_data as *mut c_void, on as i32);
    }

    fn write(&self, link: u64, characteristic: Characteristic, bytes: &[u8]) {
        (self.write)(self.user_data as *mut c_void, link, characteristic as u8, bytes.as_ptr(), bytes.len() as u32);
    }

    fn disconnect(&self, link: u64) {
        (self.disconnect)(self.user_data as *mut c_void, link);
    }

    fn link_state(&self, link: u64, state: LinkState, peer: Option<&[u8; IDENTITY_LEN]>, interface: Option<&str>) {
        let name = interface.and_then(|s| CString::new(s).ok());
        (self.state)(
            self.user_data as *mut c_void,
            link,
            state as i32,
            peer.map_or(std::ptr::null(), |p| p.as_ptr()),
            name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
        );
    }
}

fn status(result: Result<(), String>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Starts Bluetooth once the stack is running and its destinations are
/// published. The host starts scanning when this returns, and after that
/// scans only as `scan_fn` says. `storage_dir` holds the persisted BLE
/// identity, written to `identity_out` (16 bytes). `user_data` is passed
/// back to every callback and must stay valid until `rns_prns_ble_stop`
/// returns.
///
/// # Safety
/// `storage_dir` must be a NUL-terminated string, `identity_out` 16 writable
/// bytes or NULL.
#[no_mangle]
pub unsafe extern "C" fn rns_prns_ble_start(
    storage_dir: *const c_char,
    endpoint_stack: u8,
    endpoint_host: u8,
    scan_fn: Option<RnsPrnsBleScanFn>,
    write_fn: Option<RnsPrnsBleWriteFn>,
    disconnect_fn: Option<RnsPrnsBleDisconnectFn>,
    state_fn: Option<RnsPrnsBleStateFn>,
    user_data: *mut c_void,
    identity_out: *mut u8,
) -> i32 {
    let (Some(scan), Some(write), Some(disconnect), Some(state)) = (scan_fn, write_fn, disconnect_fn, state_fn) else {
        set_error("rns_prns_ble_start: a callback is NULL".into());
        return -1;
    };
    if storage_dir.is_null() {
        set_error("rns_prns_ble_start: storage_dir is NULL".into());
        return -1;
    }
    let Some(endpoint) = Endpoint::new(endpoint_stack, endpoint_host) else {
        set_error(format!("rns_prns_ble_start: unknown endpoint {endpoint_stack}/{endpoint_host}"));
        return -1;
    };
    let dir = CStr::from_ptr(storage_dir).to_string_lossy().into_owned();
    let host = Arc::new(CHost { scan, write, disconnect, state, user_data: user_data as usize });
    match runtime::start(Path::new(&dir), endpoint, host) {
        Ok(identity) => {
            if !identity_out.is_null() {
                std::ptr::copy_nonoverlapping(identity.as_ptr(), identity_out, IDENTITY_LEN);
            }
            0
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

/// Closes every link (calling the disconnect callback for each) and removes
/// the RTNodes' interfaces. Blocks briefly; call it off the main thread and
/// before the stack shuts down, and never from inside a callback.
#[no_mangle]
pub extern "C" fn rns_prns_ble_stop() -> i32 {
    runtime::stop();
    0
}

/// An advertisement of the Prns service. `address` is the device's stable
/// name (CoreBluetooth: the peripheral identifier's UUID string);
/// `manufacturer_data` is `kCBAdvDataManufacturerData` whole (company
/// identifier first, little-endian), NULL if absent. Returns the link to
/// dial it on, or 0: not an RTNode, already linked, at capacity, paused
/// after a failure, or Bluetooth not started.
///
/// # Safety
/// `address` must be a NUL-terminated string; `manufacturer_data` must
/// point to `len` readable bytes (or be NULL).
#[no_mangle]
pub unsafe extern "C" fn rns_prns_ble_sighted(address: *const c_char, manufacturer_data: *const u8, len: u32) -> u64 {
    if address.is_null() || manufacturer_data.is_null() || len < 2 {
        return 0;
    }
    let address = CStr::from_ptr(address).to_string_lossy();
    let bytes = std::slice::from_raw_parts(manufacturer_data, len as usize);
    match runtime::sighted(&address, u16::from_le_bytes([bytes[0], bytes[1]]), &bytes[2..]) {
        Ok(Some(link)) => link,
        Ok(None) => 0,
        Err(e) => {
            set_error(e);
            0
        }
    }
}

/// Connected, service discovered, and both characteristics subscribed.
/// `max_write_len` is the value one write carries without becoming an ATT
/// long write: CoreBluetooth `maximumWriteValueLength(for: .withoutResponse)`.
#[no_mangle]
pub extern "C" fn rns_prns_ble_link_ready(link: u64, max_write_len: u32) -> i32 {
    status(runtime::link_ready(link, max_write_len as usize))
}

/// A notification from the control (0) or data (1) characteristic.
///
/// # Safety
/// `data` must point to `len` readable bytes (or be NULL with `len` 0).
#[no_mangle]
pub unsafe extern "C" fn rns_prns_ble_link_received(link: u64, characteristic: u8, data: *const u8, len: u32) -> i32 {
    let Some(characteristic) = Characteristic::from_u8(characteristic) else {
        set_error(format!("unknown characteristic {characteristic}"));
        return -1;
    };
    let bytes: &[u8] = if data.is_null() || len == 0 { &[] } else { std::slice::from_raw_parts(data, len as usize) };
    status(runtime::link_received(link, characteristic, bytes))
}

/// The write the host was asked for completed (`ok` non-zero) or failed.
#[no_mangle]
pub extern "C" fn rns_prns_ble_link_write_done(link: u64, ok: i32) -> i32 {
    status(runtime::link_write_done(link, ok != 0))
}

/// The connection or connection attempt is gone: the OS disconnect or
/// connect-failure callback, or a failure setting the link up (service or
/// characteristic discovery, subscription).
#[no_mangle]
pub extern "C" fn rns_prns_ble_link_closed(link: u64) -> i32 {
    status(runtime::link_closed(link))
}
