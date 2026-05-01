# Reticulum-rust application-facing subsystems

This document catalogues the high-level, declarative subsystems that
Reticulum-rust exposes to applications. They exist to separate **what
the app wants** ("I want a connection to this destination", "I want
this destination to be reachable") from **how the system provides it**
(path discovery, link establishment, retry strategy, interface
liveness, announce scheduling, NAT/iface flap recovery).

The principle every subsystem in this document shares:

> Apps express durable intent declaratively. The runtime owns the
> mechanics — including retry, refresh, and recovery — and exposes
> three states: **trying (yellow)**, **ready (green)**, **failed and
> waiting (red)**.

If you find yourself writing app-level retry, polling, or "wait
N seconds and try again" logic, the subsystem is doing the wrong
thing — fix the subsystem, do not paper over it in the app.
(See `DESIGN_PRINCIPLES.md` §1–§7.)

---

## 1. AppLinks — declarative durable connections

**Source:** `src/app_links.rs`
**FFI:** `app_link_open`, `app_link_close`, `app_link_status`,
`app_link_send`, `app_link_set_inbound_callback`, `app_link_network_changed`

### What the app expresses

- "I want a link held open to destination `X`."
  (`AppLinks::open(dest)`)
- "I want to send this packet through the link to `X`."
  (`AppLinks::send(dest, payload)`)
- "Call me when a packet arrives on the link to `X`."
  (`AppLinks::set_inbound_callback(dest, cb)`)
- "I no longer need a link to `X`."
  (`AppLinks::close(dest)`)
- "The host network state just changed (cell→wifi, foregrounded,
  backgrounded, etc.) — re-evaluate everything."
  (`AppLinks::network_changed()`)

### What the system owns

- **Path discovery.** If we have no path, emit a `PATH_REQUEST`. Race
  the cached-path attempt and the path-request attempt in parallel
  (path racing), use whichever produces a working link first, tear
  down the loser.
- **Link establishment.** Open a Reticulum `LINK` over the chosen
  path; track its `STATE_PENDING` → `STATE_ACTIVE` transitions.
- **Liveness.** While `STATE_ACTIVE`, the system maintains the link
  via the link-keepalive mechanism. If the link goes inactive or
  closes, the AppLink moves back to *trying* or *failed*.
- **Retry policy.**
  - Try once on cold open.
  - On a successful open that later fails, **one** automatic re-open
    attempt.
  - After that: **no further automatic retries**. State goes to
    *failed* and stays there until a re-trigger event.
- **Re-trigger events** (move from *failed* back to *trying*):
  - An interface transitions `online: false → true`
    (network change, app foregrounded, NAT rebinding, TCP reconnect).
  - An announce arrives for the target destination.
  - The host calls `AppLinks::network_changed()` explicitly.
  - The host calls `AppLinks::open()` again on the same destination
    (idempotent re-arm).
- **Interface gating.** All establishment attempts are only initiated
  on interfaces whose `online == true`. AppLinks does not hold a
  `STATE_PENDING` link request against a dead interface.

### Public state surface (the "three lights")

| Color  | Meaning                                              |
|--------|------------------------------------------------------|
| Yellow | Trying — path requested, link establishing, racer in flight |
| Green  | Open and ready — link is `STATE_ACTIVE`              |
| Red    | Tries failed; waiting for a re-trigger event         |

> Never show Green until the link is genuinely active.
> Never show Red for "not yet attempted" — that is Grey
> (handled at the UI layer; AppLinks does not emit Grey).

### What the app must NOT do

- Do not poll path tables.
- Do not call `Transport::request_path` itself.
- Do not start, retry, or tear down `Link` instances directly.
- Do not implement timeouts. The runtime owns ordering and readiness.
- Do not call `app_link_open` in a tight loop. Once is enough; the
  runtime keeps trying until the link is up or fails terminally.

### Reference contract

```rust
// App startup, once per durable peer:
AppLinks::open(peer_dest_hash);
AppLinks::set_inbound_callback(peer_dest_hash, |bytes| { ... });

// On user action:
AppLinks::send(peer_dest_hash, payload);

// On host platform network event (Wi-Fi join, app foregrounded, etc):
AppLinks::network_changed();

// At app shutdown / "I don't want this peer anymore":
AppLinks::close(peer_dest_hash);
```

---

## 2. Published Destinations — declarative announce daemon

**Source:** `src/transport.rs` (`publish_destination`,
`unpublish_destination`, `published_destinations`,
the refresh sweep inside `Transport::jobs()`)
**FFI:** `transport_publish_destination`,
`transport_unpublish_destination`, `transport_is_published`

### What the app expresses

- "I want destination `X` to stay discoverable on the network with
  this `app_data`, refreshing every `N` seconds."
  (`Transport::publish_destination(hash, refresh_interval, app_data)`)
- "I no longer want `X` to be auto-announced."
  (`Transport::unpublish_destination(hash)`)

### What the system owns

- **Announce on opt-in.** First periodic refresh sweep after
  `publish_destination` fires immediately, so the app gets an
  announce as soon as it expresses intent.
- **Announce on interface up-edge.** Every time any interface
  transitions `online: false → true`, all published destinations are
  re-announced on that interface. This covers: cold start, TCP
  reconnect, Wi-Fi join, cellular handover, app foreground.
- **Periodic refresh.** Every `refresh_interval` (per published dest)
  the destination is re-announced on every online interface. Default
  guidance: 30 minutes for IN/SINGLE peer destinations.
- **Re-entrancy safety.** The refresh sweep snapshots state, drops
  the `TRANSPORT` lock, builds announce packets outside the lock, then
  re-acquires to update bookkeeping. Two known re-entrancy traps
  (`Transport::outbound` spinwait; `is_connected_to_shared_instance`
  re-locking) are documented in-code and must not be re-introduced.

### What the app must NOT do

- Do not call `Destination::announce()` directly from periodic
  timers — the daemon owns the schedule.
- Do not re-announce on your own network-change handler — that is
  what `set_interface_online(_, true)` already does.
- Do not assume `publish_destination` is one-shot — it is durable
  intent; calling it again with the same hash refreshes the entry.

### Reference contract

```rust
// At identity creation / app startup:
Transport::publish_destination(
    self_dest_hash,
    Some(Duration::from_secs(30 * 60)), // refresh interval
    Some(app_data_bytes),               // optional
);

// On identity teardown:
Transport::unpublish_destination(&self_dest_hash);
```

---

## 3. Interfaces — liveness contract

**Source:** `src/interfaces/*.rs`,
`Transport::set_interface_online`

### What every interface must guarantee

- **Honest `online` state.** `online: true` means: a packet handed to
  this interface in the next ~RTT will reach the wire. `online:
  false` means: drops are guaranteed; do not bother trying.
- **Up-edge notification.** Whenever an interface comes back from
  `false → true` (initial connect, reconnect after drop, manual
  enable), it must call `Transport::set_interface_online(name, true)`.
  This is what fires both the AppLinks re-trigger AND the published-
  destination re-announce.
- **Down-edge notification.** Whenever an interface drops from
  `true → false`, it must call `Transport::set_interface_online(name,
  false)` so dependent subsystems can stop trying.
- **Liveness probing.** Each interface owns its own keepalive /
  watchdog discipline appropriate to its medium (TCP keepalive,
  RNode handshake ping, BLE GATT, etc.). The protocol layer above
  trusts `online`; if the medium is dead, the interface must say so.

### What the runtime gives back in return

- AppLinks will not initiate establishment over an offline interface.
- Published destinations will not be announced to an offline
  interface.
- The first packet you successfully hand to an interface after an
  up-edge is preceded by re-announces (and, if AppLinks is in use,
  by re-establishment of any wanted links).

---

## 4. How the subsystems compose

A typical Retichat-style app boot:

```
1. StackRuntime brings up Reticulum and registers interfaces.
2. App generates / loads identity and registers selfDest.
3. App calls Transport::publish_destination(selfDest, 30 min).
4. App calls AppLinks::open(peerDest) for every durable peer.
5. App calls AppLinks::set_inbound_callback(peerDest, handler).
6. UI binds to AppLinks state stream (yellow/green/red per peer).
7. UI binds to interface online state (for global "connected" badge).
```

That is the entire wiring. From this point forward:

- The system announces selfDest correctly across iface flaps.
- The system establishes and maintains links to declared peers.
- The system retries deterministically on every legitimate
  re-trigger event, and stops retrying otherwise.
- The app only sees: link became ready / link failed / packet
  arrived.

---

## 5. Where to add the next subsystem

Future subsystems should follow the same template:

1. **Single declarative API** the app calls to express durable intent.
2. **System owns the strategy** (retries, refresh schedule, ordering,
   readiness, error recovery).
3. **Three-state surface** (trying / ready / failed) exposed back to
   the app so the UI can render without inventing its own state
   machine.
4. **Re-trigger events** are explicit and small in number
   (interface up-edge; relevant inbound traffic; explicit host
   `network_changed()`).
5. **No timeouts as configuration** — every wait is bounded by a
   real readiness signal, not a clock value the app might tune.

If a proposed subsystem cannot fit this template, it is probably an
imperative API, not a declarative one — reconsider the boundary
before shipping it.
