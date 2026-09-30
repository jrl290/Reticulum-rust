# Retichat ↔ RTNode over Bluetooth LE (`interfaces::prns_ble`)

> **See [DESIGN_PRINCIPLES.md](../DESIGN_PRINCIPLES.md): it must be considered on every change here.**

A phone running Retichat reaches the mesh through a nearby RTNode over Bluetooth LE. It speaks the Prns native protocol, from the dialer's (GATT central's) side only. RTNode (`RTNode-HeltecV4/BleInterface.h`) is the listener.

## Scope (James, 2026-09-28)

- **RTNode only, never phone to phone.** "Retichat should not make itself available to another Retichat instance."
  - The phone advertises nothing and hosts no GATT service.
  - It dials only advertisements carrying the peripheral-only role flag, which RTNode sends and no phone or Prns daemon does.
- **Zero configuration.** "It should be any RTNode in range. Zero config."
  - There is no picker, only one switch, Nearby RTNode, which is **off by default** (James, 2026-09-29). On by default would have shown every existing user a Bluetooth permission prompt at launch.
  - Turning the switch on asks for the Bluetooth permission.
    - iOS starts the link on Apply.
    - Android starts it as soon as the permission is granted and the stack is up (`StackRuntime.applyRtnodeBluetoothSetting`).
  - Refusing the permission turns the switch back off.
  - The phone is linked to one RTNode at a time (`engine::MAX_NODES`), so several nodes in range don't each rebroadcast the phone's traffic onto LoRa.
- **A persistent Bluetooth identity:** 16 random bytes in `<config dir>/ble_identity`, in the Prns record format.
- **No L2CAP and no Columba characteristics.** The Hello offers no PSM, so a Prns peer never tries to move the link off GATT.
- **Background behaviour:**
  - iOS uses the `bluetooth-central` background mode: the system keeps the link and wakes the app for it.
  - Android runs no foreground service (James, 2026-09-29). The link works while Retichat is open or was just used, and stops when Android freezes the app.

## Wire format

Taken from Prns 0.3.7 `prns-core/src/interfaces/bluetooth_auto/` (MIT OR Apache-2.0). There is no written spec. See `src/interfaces/prns_ble/wire.rs`, whose tests include RTNode's exact Welcome bytes.

- **Service** `37145b00-442d-4a94-917f-8f42c5da28e3`. Control characteristic `…e7`, data characteristic `…e8`.
- **Advertisement:** manufacturer data, company `0xFFFF`, `[version ≥ 3, flags]`. Flag bit 0 means peripheral-only; RTNode sends `03 01`.
- **Handshake:**
  1. The dialer subscribes to control, then to data.
  2. It writes a Hello to control, with response.
  3. The listener notifies a Welcome on control.
  - Hello and Welcome are 23 bytes: tag, 16-byte identity, endpoint `(stack, host)`, PSM byte, link MTU as u16 big-endian, RSSI.
  - Endpoints: iOS `01 01`, iPadOS `01 02`, Android `03 00`. RTNode answers `05 00` (ESP32).
  - Close is `03 <reason>`.
- **Packets:** at most 500 bytes, split into fragments of `[kind 01|02|03][seq u16 BE][total u16 BE][payload]`.
  - The phone writes data fragments without response when the node's data characteristic allows it (RTNode does from its fast-link firmware), and with response otherwise. One write is in flight per link: a write without response is done once the OS has taken it (iOS `canSendWriteWithoutResponse`, then `peripheralIsReady(toSendWriteWithoutResponse:)`; Android `onCharacteristicWrite`).
  - The listener sends its fragments as notifications on data.
  - A fragment is at most one ATT PDU (MTU − 3). A longer write would become an ATT long write, which Prns peers don't handle.

## Split of work

| Where | What |
|---|---|
| `engine.rs` | A pure state machine: host events in, `Effect`s out. It holds the dial decision, the handshake, fragments, reassembly, write pacing and the interface lifecycle. Unit tested without Bluetooth. |
| `runtime.rs` | One engine per process. Transport effects run in order on the `prns-ble-transport` thread (register before any inbound, deregister after). Host calls run outside the engine lock. `prns-ble-timer` enforces the ceilings. It also manages the identity file. |
| `cffi.rs` | The C ABI (`rns_prns_ble_*`) for iOS. Declared by hand in Retichat-ios `CRetichatFFI.h`. |
| Retichat-android `rust/retichat-jni` | The JNI (`nativePrnsBle*`) plus `JniBleHost`, the Kotlin `PrnsBleCallback`. |
| Retichat-ios `RTNodeBluetoothCoordinator.swift`, Retichat-android `RTNodeBluetooth.kt` | The radio. It scans when asked and reports each advertisement. It connects on the link the engine returns, then does MTU (Android), discovery and both subscriptions, and reports `link_ready`. It performs writes and reports every event. It keeps no timers and never re-dials by itself. |

## Dial rules and timers

These are Prns's rules, taken from `policy.rs` and the Prns backends. A dial is always triggered by an advertisement, and a timer only ever blocks or ends one.

- **Candidates:** dial only an advertisement from an RTNode that is not already linked, while fewer than `MAX_NODES` are linked or dialling.
- **`DIAL_RETRY`, 16 s** (Prns `DIAL_RETRY_TTL_MS`): a node that was dialled isn't dialled again until 16 s after that dial, unless its link settles.
  - Unlike Prns, a failed handshake does not clear this pause. A node that fails every handshake is dialled at most every 16 s, not on every advertisement.
- **`DIAL_FAILED_RETRY`, 5 s:** the pause after a dial that never reached the handshake.
- **Ceilings:** a dial has 15 s to reach `link_ready` (`DIAL_CEILING`, the Prns Apple dial timeout). The handshake has 10 s from Hello to Welcome (`HANDSHAKE_CEILING`, Prns). These are hard ceilings for a peer that never answers (§4).
- **§1 late-success checks:** the dial, the handshake and every write each go through `send_assertion::assert_send_completed_in_time`.
- **Failure comes from events:** the OS disconnect or connect-failure callback, a failed write, a Close, or an undecodable control message. It never comes from silence.

## Transport

Each settled RTNode becomes one interface, `PrnsBLE[<its 16-byte identity>]`. The name is stable across reconnects: Transport keys paths, links and writers by name, so a node that comes back keeps its routes.

- **Settings:** MODE_FULL, 700 kbps (Prns's figure, and what RTNode registers for its slots), announce cap `ANNOUNCE_CAP`.
- **Registration order:**
  1. the outbound handler;
  2. the stub, registered **offline**;
  3. `set_interface_online(true)`.
  - That one up-edge both queues the published-destination sweep and wakes the interface-up listeners, so app-links re-attempts its held links. A stub registered already online gets only the sweep.
- **The apps must start Bluetooth after the delivery destination is published,** so the first link's up-edge announces it (§5). Retichat-android's `RTNodeBluetoothContractTest` pins this order.
- **A reconnect before the old link is reported gone** hands the interface to the new link (`Effect::HandOver`), with no down and up edge.

## Link speed (James, 2026-09-29: "the fastest bluetooth link that is available")

Each side asks for the fastest link the other will take. The OS and the other side decide; RTNode logs each outcome, and its 60 s report shows each slot's interval and PHY.

- **Android**, on connect and before the MTU exchange: `CONNECTION_PRIORITY_HIGH` (11.25-15 ms) and the 2M PHY. Asking this early lets both settle before the Hello. RTNode asks for its own at the Hello, and two updates at once collide and both fail.
- **iOS** has no API for either. RTNode asks, and iOS picks its PHY itself.
- **RTNode**, once the Hello identifies the phone:
  - 251-byte link-layer packets;
  - the 2M PHY;
  - a 15 ms interval, the shortest Apple accepts from an accessory, if the link runs slower. It asks again once if the phone slows the link after setup, as Android does when service discovery ends. A collision with the phone's own update is not a refusal.
- **L2CAP is not used.** Prns's own table allows it between Android and an ESP32 only, not iOS.

## Caveats

- **One phone, two apps, one node.** Android shares one BLE connection per phone and node across apps.
  - If the phone's Columba already holds the RTNode connection, RTNode treats it as a Columba slot and ignores Retichat's Hello, so the dials fail every 5 s.
  - A fix would be RTNode-side.
- **The half-open warning.** Transport's "possible half-open connection" warning fires on a quiet BLE link. It's a TCP heuristic: a BLE link can't be half-open, because the supervision timeout ends it.

## Tested (2026-09-28/29, bench, private network only)

The bench setup:
- An RTNode V4.2 running `rtnode_heltec_v4_bench` at 2 dBm, with only the private stand-in backbone (`rnsd --config RTNode-HeltecV4/tests/wan-backbone`, 192.168.2.117:4290).
- A Python RNS 1.5.2 / LXMF peer on that backbone sends DIRECT messages.

Results:

| Device | Result |
|---|---|
| iPad 9th gen, iPadOS 26.5 | Delivered 3/3 in < 0.7 s. After 90 s in the background: 2/2 delivered. One link dropped with 0x208 (supervision timeout) 5 s after connecting and was re-dialled within 1 s. |
| Pixel 5 | Delivered 3/3 in < 1.1 s. As the previous app: 2/2 delivered. Cached (frozen): 0/2 delivered. |

### Fast link (2026-09-29, same bench)

The RTNode ran its `feature/ble-fast-link` firmware, and both phones ran the fast-link apps. "Before" is the release firmware with the earlier apps.

| Transfer | Before | After |
|---|---|---|
| Backbone peer → Pixel 5, 64 KB of random data | 13.8 s | 4.7-6.7 s |
| Pixel 5 → backbone peer, 48 KB of text | 14.7 s | 1.6-2.4 s |
| Backbone peer → iPad, 64 KB of random data | not measured | 6.2-6.8 s |
| Pixel 5 → iPad through the RTNode, Bluetooth only, 48 KB of text (80 parts after compression) | about 10 parts per 1.2 s round trip | 3.2 s; the last windows moved 12 parts per 0.36 s |

The links as settled:
- **Pixel 5:** 15 ms, 2M PHY, writes without response.
- **iPad 9th gen:** 15 ms, asked for by RTNode and accepted; iOS's own choice is 30 ms. It stays on 1M: Bluetooth 4.2, and the 2M request returns 0x21A. Writes without response. Its supervision timeout rises from 720 ms to 2 s, Apple's minimum for an accessory's request.

What limits a transfer now:
- **The RTNode's WiFi, for traffic to and from the backbone.** A ping from the bench machine averages 93 ms and peaks at 244 ms. WiFi shares the ESP32's radio with Bluetooth, and ESP-IDF requires modem sleep while both are on.
- **RNS itself.** It grows a Resource's window by one part per round trip, as Python does.

A bulk send from the iPad (2026-09-30):
- The photo was 3,701 parts, sent to the Pixel through the RTNode. It arrived; James confirmed it.
- It exercised iOS's without-response flow control. The iPad logged no failed write.
- Once its window passed 64 parts, the engine's per-link queue overflowed: "64 packets queued, 483 byte packet dropped". The receiver re-requested the lost parts.
- `MAX_QUEUED_PACKETS` is now 96. A compile-time check holds it above RNS's largest window, `Resource::WINDOW_MAX_FAST` (75).

Not yet exercised: the RTNode's write-queue wait. `write waits` stayed at 0.
