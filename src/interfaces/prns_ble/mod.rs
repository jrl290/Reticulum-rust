//! A Bluetooth LE link from a phone to an RTNode, in the Prns native
//! protocol ("PrnsBluetoothAuto"), from the dialer's (GATT central's) side.
//!
//! The phone is only ever the central: it advertises nothing and hosts no
//! GATT service, so nothing can connect to it (James, 2026-09-28: Retichat
//! talks to RTNode, never to another phone). It accepts an advertisement
//! only when its manufacturer data carries the peripheral-only role flag
//! (`wire::is_peripheral_only`), which RTNode sends and phones never do.
//!
//! Split of work:
//! - the platform (CoreBluetooth, Android BLE) connects, discovers the
//!   service, subscribes to the control and data characteristics, performs
//!   the writes it is asked for and reports every event;
//! - this module does the protocol: the Hello/Welcome handshake, fragments,
//!   reassembly, one write in flight per link, and one Transport interface
//!   per RTNode, named by the RTNode's BLE identity so its routes survive a
//!   reconnect.
//!
//! Failure comes from events, never silence: the OS disconnect callback, a
//! failed write, a Close, an undecodable control message. The only timer is
//! the Prns handshake ceiling (`engine::HANDSHAKE_CEILING`), and both the
//! handshake and every write are checked against the 5-second rule. No
//! L2CAP (the Hello offers no PSM, so a peer never tries), no Columba
//! characteristics, no peripheral role.

pub mod cffi;
pub mod engine;
pub mod runtime;
pub mod wire;

pub use engine::{Characteristic, LinkState, HANDSHAKE_CEILING, MAX_FRAGMENT};
pub use runtime::{is_running, link_closed, link_ready, link_received, link_write_done, start, stop, Host, BITRATE};
pub use wire::{is_peripheral_only, Endpoint, CONTROL_UUID, DATA_UUID, SERVICE_UUID};
