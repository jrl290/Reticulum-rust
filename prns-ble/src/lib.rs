//! The Prns native Bluetooth LE protocol ("PrnsBluetoothAuto"), from the
//! dialer's (GATT central's) side: a phone linking to an RTNode.
//!
//! The protocol is the work of the Prns authors
//! (<https://github.com/KenAKAFrosty/Prns>). README.md says what was taken
//! from Prns, what changed, and what Prns builds on.
//!
//! This package holds that protocol and nothing else:
//! - `wire`: the bytes (UUIDs, Hello/Welcome/Close, fragments, the
//!   advertisement's role flag, the identity record);
//! - `engine`: the dialer as a state machine with no radio, threads or
//!   globals: host events in, effects out;
//! - `identity`: the persisted Bluetooth identity.
//!
//! The program using it carries out the engine's effects. In Retichat that
//! is Reticulum-rust (`src/interfaces/prns_ble/`), which registers each
//! RTNode as a Reticulum interface, and the apps, which drive the radio.
//!
//! Copyright (c) 2026 The Prns Authors
//! Copyright (c) 2026 James LaFarge
//! SPDX-License-Identifier: MIT OR Apache-2.0

pub mod engine;
pub mod identity;
pub mod wire;

pub use engine::{
    interface_name, Characteristic, Effect, Engine, Level, LinkState, DIAL_CEILING, DIAL_FAILED_RETRY, DIAL_RETRY,
    HANDSHAKE_CEILING, MAX_FRAGMENT, MAX_NODES, MAX_QUEUED_PACKETS,
};
pub use wire::{is_peripheral_only, Endpoint, CONTROL_UUID, DATA_UUID, IDENTITY_LEN, SERVICE_UUID};

/// Link bitrate Prns assumes for a Bluetooth peer (`BLE_BITRATE_GUESS_BPS`
/// in `policy.rs`, ble-reticulum's `BITRATE_GUESS`), and what RTNode
/// registers for its Bluetooth slots.
pub const BITRATE: u64 = 700_000;
