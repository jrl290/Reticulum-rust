# prns-ble

The Prns native Bluetooth LE protocol ("PrnsBluetoothAuto"), from the dialer's (GATT central's) side. Retichat uses it to link a phone to a nearby RTNode.

## Credit

**The protocol is the work of the Prns authors.** [Prns](https://github.com/KenAKAFrosty/Prns) is a Reticulum stack in Rust by The Prns Authors. Its Bluetooth LE interface defines this protocol:

- the control and data characteristics;
- the Hello/Welcome/Close handshake and its 23-byte greeting;
- the endpoint codes and close reasons;
- the reassembly rules;
- the persisted identity record;
- the dial rules and timers.

Prns has no written specification of the protocol. Its code is the specification.

What was taken, all from Prns 0.3.7 at commit `d48e9fc` (2026-09-02):

| From Prns | Here |
|---|---|
| `prns-core/src/interfaces/bluetooth_auto/`: `advertisement.rs`, `framing.rs`, `handshake.rs`, `identity.rs` | `src/wire.rs`, a port written with AI assistance |
| `prns-core/src/interfaces/bluetooth_auto/policy.rs`: `DIAL_RETRY_TTL_MS`, `DIAL_FAILED_RETRY_TTL_MS`, `BLE_BITRATE_GUESS_BPS` | `src/engine.rs`, `src/lib.rs` |
| `HANDSHAKE_TIMEOUT` (`prns-interfaces/impls/tokio/src/bluetooth_auto/runtime.rs`), `DIAL_TIMEOUT` (`prns-ffi/src/bluetooth_auto/macos/backend.rs`) | `src/engine.rs` |
| The identity file, `<storage>/ble_identity` | `src/identity.rs` |

Prns's protocol builds on [ble-reticulum](https://github.com/torlando-tech/ble-reticulum) by torlando-tech (MIT), the protocol that [Columba](https://github.com/torlando-tech/columba) speaks. The GATT service UUID, the 5-byte fragment header and the role advertisement (manufacturer data with a peripheral-only flag) come from ble-reticulum's protocol v2.2 and v0.3.0.

## What changed from Prns

Apache-2.0 asks for a statement of the changes. They are:

- **Only the dialer's half.** There is no listener, no L2CAP, and none of the Columba characteristics or handshake that Prns also speaks.
- **A state machine.** The dialer (`src/engine.rs`) has no radio, threads or globals: host events go in, effects come out, and the program using it carries the effects out.
- **Dial rules for a phone that links one RTNode:**
  - one node at a time;
  - only advertisements carrying the peripheral-only flag are dialled;
  - a failed handshake keeps the 16-second pause from its dial, where Prns clears it.
- **This crate's own types:** UUIDs as strings, one `Greeting` for Hello and Welcome, and `Endpoint` as a stack and host pair.

## What is not here

No code in this package is derived from Mark Qvist's Reticulum.

- **Reticulum-rust** runs the engine and registers each RTNode as a Reticulum interface, in `src/interfaces/prns_ble/`. That glue is part of Reticulum-rust and under its license.
- **RTNode-HeltecV4** has the listener side, `BlePrns.h`.

## Using it

1. `Engine::new(identity, endpoint)`, with the identity from `identity::load_or_create`.
2. Feed it what the radio reports: `sighted`, `link_ready`, `link_received`, `link_write_done` and `link_closed`.
3. Feed it the packets to send: `send_packet`.
4. Call `expire` at `next_deadline`.

Each call returns `Effect`s:

- for the radio: scan, write, disconnect, state;
- for the network stack: register, hand over, deregister, inbound;
- for the program: a late-send check and a log line.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option, as Prns is.

Copyright (c) 2026 The Prns Authors (the protocol, and the code ported from Prns)
Copyright (c) 2026 James LaFarge (the changes)
