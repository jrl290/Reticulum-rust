# Contract parity audit against Python RNS 1.5.2

Started 2026-09-22 after 8fb4f70 (a request handler received the path *hash*
instead of the registered path string) reached a deployed build. That defect
was a contract error, not a wire error: every interop test passed while every
multi-path request handler took the wrong branch. This audit is the systematic
pass that should have preceded the "ready" call.

Reference: upstream `markqvist/Reticulum` at tag `1.5.2` (2026-08-29). The
workspace mirror `Reticulum-master` is 1.1.3 with local edits and is not the
reference any more. The interop harness (`tests/interop/run.sh`) passes 16/16
against 1.5.2, which proves the wire, not the contract.

Each item: what Python does, what Rust did, verdict, and what was done. Line
numbers are at 1.5.2 for Python and at 8fb4f70 for Rust.

## A. Application contract (Destination / Link / Resource / Packet / Transport)

| # | Item | Python 1.5.2 | Rust at 8fb4f70 | Verdict | Action |
|---|------|--------------|-----------------|---------|--------|
| A1 | Destination-level REQUEST dispatch | `Destination.receive` (Destination.py:415) never handles REQUEST; a DATA packet with any context reaches the packet callback. Requests exist only on links. | `destination.rs:732` intercepts REQUEST, dispatches with `hex(path_hash)` as the path, no remote identity, no link, and ignores `allow`. | Non-canonical path, and the same defect as 8fb4f70 still live here. | **Removed.** A DATA packet now reaches the packet callback whatever its context, as in Python. Test: `a_request_context_data_packet_reaches_the_packet_callback`. |
| A2 | `Link.get_remote_identity()` | Returns the `Identity` or `None` (Link.py:646). | Returns `Some("remote_identity")`, a literal string (link.rs:2549). | Placeholder shipped as API. | **Fixed:** returns `Option<Identity>`. |
| A3 | `resource_started` callback | Fired from `Resource.accept` once the incoming resource is registered (Resource.py:228). | Stored (link.rs:998) and never called. | Dead callback. | **Fixed:** fired after every successful `Resource::accept` on a link. Re-verified 2026-09-22: `Resource.py:222 has_incoming_resource` was missing, so a re-advertised resource was accepted twice; now checked before accepting. Tests: `resource_started_fires_for_an_accepted_advertisement`, `a_re_advertised_incoming_resource_is_not_accepted_twice`. |
| A4 | ACCEPT_APP `resource` callback | `callbacks.resource(advertisement) -> bool` decides acceptance (Link.py:1106). | Accepts first, then calls `Fn(Arc<Mutex<Resource>>)`; the app cannot refuse (link.rs:3195). | Semantics inverted; LXMF-rust worked around it by cancelling after acceptance. | **Fixed:** callback is `Fn(&ResourceAdvertisement) -> bool`, consulted before acceptance. Callers in LXMF-rust and RFed-rust updated. |
| A5 | Request progress | `RequestReceipt.progress` follows the response Resource; `progress` callback fires on every part (Link.py:1417). | One synthetic call with `progress = 0.1` right after send (link.rs:4047); never again. | Fabricated value. | **Fixed:** progress callback fires from the response Resource's progress; the synthetic 0.1 is gone. Re-verified 2026-09-22: `Link.py:1435`'s `else: resource.cancel()` was missing — a request that had already failed left the response transfer running. Test: `a_failed_request_cancels_the_response_resource_still_arriving`. |
| A6 | `RequestReceipt` shape | `status` (FAILED/SENT/DELIVERED/RECEIVING/READY), `response_size`, `response_transfer_size`, `metadata`, `started_at`, `concluded_at`, `get_status/get_response/get_response_time/concluded`; `request()` returns the live receipt. | `request_id`, `response`, `sent_at`, `received_at`, `progress` only. | Apps cannot branch on request state. | **Fixed for callbacks:** fields and accessors added with Python's values and semantics; every callback receives a receipt snapshot taken at that moment. **Open by choice:** `request()` still returns the request id, not a live receipt to poll; no caller polls (re-verified 2026-09-22). |
| A7 | `Link.request(..., timeout, max_response_size)` | Per-request timeout; oversized responses rejected with `response_rejected()` → `failed` callback (Link.py:473, :1407). | Neither parameter (link.rs:3936). | Missing since 1.5.0. | **Fixed:** `request_with_options` takes both; `request` delegates with `None`. Oversized response advertisements are rejected and fail the request. Tests: `oversized_single_packet_response_is_rejected`, `oversized_response_resource_advertisement_fails_the_request`. |
| A8 | `Destination.set_max_request_size` | Oversized inbound requests (packet or Resource) are ignored/rejected before the handler (Destination.py:369, Link.py:998,1037). | Absent. | Missing since 1.5.0. | **Fixed:** added and enforced on both request forms. Re-verified 2026-09-22: `Link.py:1036`'s `if self.destination.request_handlers:` gate was missing on the Resource path. Tests: `oversized_request_packet_is_ignored`, `oversized_request_resource_advertisement_is_rejected`, `a_request_resource_is_ignored_when_the_destination_has_no_handlers`. |
| A9 | `PacketReceipt` returned by `send()` | The same object Transport tracks; callbacks set afterwards take effect. | A by-value clone (packet.rs:312); `set_delivery_callback` on it is a no-op. Siblings call `Transport::set_receipt_delivery_callback` as a workaround. | Contract trap. | **Fixed:** receipt state is shared between the returned receipt and Transport's copy. The Transport shim remains. |
| A10 | `teardown_reason` | `INITIATOR_CLOSED` / `DESTINATION_CLOSED` set on teardown and on a received LINKCLOSE (Link.py:662-681). | Only `TIMEOUT` ever set. | Closed callback cannot tell a timeout from a close. | **Fixed.** 2026-09-23: a stale link's timeout now sets REASON_TIMEOUT before teardown (`link.rs`, RNS/Link.py:765); it was reported as the closing side. |
| A11 | `link_closed` cancels resources | Every in-flight incoming and outgoing Resource is cancelled (Link.py:686). | Not cancelled; they resolve through their own watchdogs or never. | Missing. | **Fixed.** Test: `link_closed_cancels_in_flight_resources`. |
| A12 | Keepalive watchdog | Wakes when `last_inbound` **or** `last_outbound` is older than keepalive (Link.py:749, e64d8150). | Inbound only (link.rs:690). | 1.5.x fix not carried; false STALE against a peer that only streams. | **Fixed.** |
| A13 | Keepalive reply | 0xFE only if `now >= last_outbound + keepalive` (Link.py:1132). | Always replies. | Minor behavioural drift. | **Fixed.** |
| A14 | LINKIDENTIFY | Accepted once; a second identify does not re-fire the callback (Link.py:990). Blackholed identities are torn down. | Re-identifies every time. No blackhole list exists in Rust. | Identify-once fixed; blackholing is a missing feature (see C). | **Fixed** (identify-once). |
| A15 | Malformed resource advertisement | Any exception while handling RESOURCE_ADV tears the link down (Link.py:1080). | Ignored. | 1.5.x hardening. | **Fixed.** |
| A16 | `Destination` with `identity=None` (inbound, non-PLAIN) | Mints an Identity and appends its hexhash as an aspect (Destination.py:160). | Returns `Err`. | Divergent construction. | **Fixed.** Test: `inbound_destination_without_an_identity_mints_one_and_appends_its_hexhash`. |
| A17 | Link established callback set after establishment | Same in Python: never fires. Python avoids the race by taking the callback in the constructor. | Handle-based set after `spawn`; the race window is the link RTT. | Same semantics; Rust's construction shape makes the race reachable. | Open. Callers set callbacks immediately after `spawn`; documented here. |
| A18 | `Transport::request_path` parameter order | `(hash, on_interface, tag, recursive)`. | `(hash, request_tag, attached_interface, requestor_transport_id, tag)`. | Rust-idiomatic, 30+ callers, types differ (interface name, not object). | Open by choice. Not a semantic difference. |
| A19 | `deregister_announce_handler` | By handler object. | By aspect filter string; removes all with that filter; unfiltered handlers cannot be removed. | Divergent. | Open. No sibling deregisters today. |
| A20 | Destinations self-register with Transport | `Destination.__init__` calls `Transport.register_destination`. | App must call it; Transport stores a snapshot by value. | Ownership model differs. | Open by choice; every sibling registers explicitly. |
| A21 | `path_is_unresponsive` and `path_states` | Real table, marked from link establishment failures. | Hard-coded `false`. | Stub. | Open. No sibling reads it. |
| A22 | `Resource.data` / `Resource.metadata` | File-like data; metadata unpacked. | `Vec<u8>` in memory; metadata raw length-prefixed msgpack. | Type-system departure. | Open by choice; large transfers are bounded by A8/A7 sizes. |
| A23 | File-handle responses `[file, metadata]` | Streams a metadata-bearing Resource. | Not expressible. | Missing. | Open. |
| A24 | `Link.get_channel` / Channel / Buffer | Present. | Placeholder. | Missing subsystem. | Open. No sibling uses channels. |
| A25 | `register_request_handler(auto_compress)` | bool or int size threshold. | bool. | Minor. | Open. |
| A26 | `set_default_app_data(callable)` | Callable evaluated per announce. | Bytes only. | Minor. | Open. |
| A27 | Announce handler dispatch | `received_announce` 3/4/5-arg by arity; Rust always passes 5. | Equivalent. | Same. | None. |
| A28 | Request handler signature | 5- or 6-arg by arity; Rust fixed 6-arg with `Option<&LinkHandle>`. Path is the registered string (8fb4f70). | Equivalent. | Same. | None (test `request_handler_receives_the_registered_path_not_its_hash`). |

## B. Wire and protocol behaviour changed upstream between 1.1.3 and 1.5.2

No packet type, context, header flag, or Link/Packet/Resource status constant
changed. What changed is validation, timing, and routing policy.

| # | Item | Python 1.5.2 | Rust at 8fb4f70 | Action |
|---|------|--------------|-----------------|--------|
| B1 | bz2 decompression bound | Incremental decompressor capped at 64 MiB; overflow → CORRUPT, cancel, link teardown (Resource.py:700, 09b0469f). | Unbounded `read_to_end`. | **Fixed.** |
| B2 | `Resource.REJECTED` | `0x09` (was `0x00`, colliding with NONE). | Already `0x09`. | None. |
| B3 | Receiver-side cancel | Receiver sends RESOURCE_RCL on cancel; CORRUPT also rejects and tears the link down (Resource.py:1096). | Receiver sends nothing. | **Fixed.** Tests: `a_receiver_cancel_sends_resource_rcl_with_the_resource_hash`, `a_corrupt_cancel_rejects_and_tears_the_link_down`. |
| B4 | HMU wait term | Watchdog sleep gains `expected_hmu_wait_remaining = sdu*8*3.5/eifr` while waiting for an HMU or with no outstanding parts (Resource.py:613). | Absent; retries fire early into 1.5.2 senders. | **Fixed.** |
| B5 | HMU handling | Processed only while `waiting_for_hmu`; an HMU with no hashes cancels (Resource.py:490,506). | Processed unconditionally. | **Fixed.** |
| B6 | `request_next` window start | `consecutive_completed_height + 1`. | Already `+1`. | None. |
| B6a | `HASHMAP_IS_EXHAUSTED` request form | The RESOURCE_REQ carrying `HASHMAP_IS_EXHAUSTED` always includes the last map hash, and the receiver sets `waiting_for_hmu` (Resource.py:942-990). | `prepare_request_next_data` sends the exhausted marker without the trailing map hash and without setting `waiting_for_hmu` when the last-hash index is out of range, and tests for "no hash" as four zero bytes rather than `None`. | Open: found during B4/B5; needs its own interop evidence (multi-segment hashmaps). |
| B7 | Advertisement size check | `unpack` raises when `t > MAX_EFFICIENT_SIZE*3` (Resource.py:1374). | No check. | **Fixed.** |
| B8 | Packet validation | `unpack` drops `hops >= 128`, malformed hash fields, zero-length data; `send()` refuses `hops >= 128` (Packet.py:250,292). | Length checks only. | **Fixed.** |
| B9 | Tagless path requests | Protocol violation, dropped; tag truncated to 16 bytes; dedupe against current and previous tag sets; `max_pr_tags` 16000 with whole-generation rotation (Transport.py:1840, :195, :850). | Tagless requests for own destinations were answered ("some clients"); the JS and PHP clients both tag. FIFO eviction of 32000 tags. | **Fixed:** canonical drop, truncation, previous-generation dedupe and rotation. |
| B10 | Announce validated before queueing | `len(raw) > MTU` → drop; bad signature → drop (Transport.py:1804). | Signature checked; no size gate. | **Fixed:** oversized announces dropped in `Transport::inbound` before validation. |
| B11 | Announce queue limits | `MAX_QUEUED_ANNOUNCES` 4096, `QUEUED_ANNOUNCE_LIFE` 3 h. | 16384 and 24 h. | **Aligned.** |
| B12 | TCP framing bounds | Frame accepted only if `HEADER_MINSIZE < len <= HW_MTU + ifac`; buffer reset above `2*HW_MTU`. | Both read loops used a placeholder `HEADER_MINSIZE = 2` and had no upper bound: stub frames and arbitrarily large frames reached `Transport::inbound`. | **Fixed** in both read loops (`check_frame_len`, `frame_buffer_exceeded`). Re-verified 2026-09-22: LocalInterface and BackboneInterface had the same defect (`HEADER_MINSIZE = 2` placeholder / no upper bound). The two helpers now live in `interfaces/interface.rs` and all three read loops call them; frame decoding in those two was split into `drain_frames()` so the bounds are testable. Tests: `local_frame_bounds_reject_stub_and_oversized_frames`, `local_unterminated_frame_buffer_is_dropped_past_twice_hw_mtu`, and the `backbone_*` pair. |
| B13 | `optimise_mtu` thresholds | `>=` at each boundary. | Seven of eleven boundaries were `>`; an interface exactly on a boundary (including the default 62 500 bps) landed a tier low or got no `hw_mtu`. | **Fixed.** Remaining: the reference's final `else` clears `HW_MTU`; Rust leaves the existing value. Open. |
| B14 | Announce gravity (Transport.py:2229) | Duplicate announce on a higher-gravity interface replaces the path. | Absent. | Open: transport policy, per-interface `gravity` config. |
| B15 | Link-request path rebalance (Transport.py:2701) | Transport node updates path hops from an in-transit link proof. | Absent. | Open: transport policy. |
| B16 | `MODE_INTERNAL`, `announces_to/from_internal`, `BOUNDARY_SEARCH_MODES`, `recursive_prs` | New interface mode and PR search rules. | Absent. | Open: transport policy. The gateway runs `mode = gateway`, unaffected. |
| B17 | Traffic-class inbound queues, ingress/egress retune, PR egress limiting | Bounded prioritised queues; new Hz estimator. | Different rate-control implementation. | Open: performance policy. |
| B18 | Blackholing (`Reticulum.is_blackholed`) | Identities can be blackholed by config; announces and links from them are dropped. | Absent. | Open: missing feature. |
| B19 | `local_hops_delta` | Off by default; rewrites hop byte on egress. | Absent. | Open: off by default upstream. |
| B20 | `known_destinations` on-disk format | 5-tuple with `last_used`; `recall` marks in-use; pruning of unused entries. | Own format; no pruning by use. | Open: internal. |
| B21 | Channel window check | Out-of-window envelopes rejected. | No Channel. | n/a (A24). |
| B22 | Announces on interface state changes | None. A destination announces only when the application asks (LXMF: at start and on its own interval). Public transport nodes rate-limit announces per destination (`announce_rate_target/grace/penalty`, 1.5.2 Transport.py:2303) and BLOCK a chatty destination. (The reference's only self-initiated announces are path responses for its own destinations when connected to a shared instance, Transport.py:2911 and :3705; Rust has no shared-instance client mode, see D.) | `Transport::set_interface_online` re-announces every IN/SINGLE destination on each up-transition of any interface, and on every down-transition via all other interfaces (`transport.rs:1726`, `:1750`). The Android app (three TCP backbones) announced its lxmf.delivery 24 times in 40 min on 2026-09-22; the fcm bridge, in a TCP reconnect loop, 46×3 times in 35 min. | **Fixed 2026-09-22/23 (James's design):** the down-edge re-announce, `announce_all_destinations`, the decrypt-failure re-announce in `Destination`, and LXMF-rust's link-close re-announce and latched "repair announce" are gone. What remains is bounded: the application's own announces always go out and start a period; automatic announces (one per interface up-edge, and the `publish_destination` refresh) are held per destination AND per interface for that period (the refresh interval; 30 min without one), so a flapping link costs no more than the refresh and a new interface is announced on at once. `Transport::announce_sent_at` is the record, written in `outbound` for every announce we originate. Refined 2026-09-23 after a source audit: the sweep now writes the announced copy's ratchet state back to the registered destination (test `refresh_sweep_writes_ratchet_state_back`; before, every sweep rotated from a stale copy and overwrote the advertised ratchet on disk), a PATH_RESPONSE does not restart the period, access-point interfaces are excluded from the sweep, records are pruned on interface deregistration and cleared on shutdown. Known gaps: spawned TCP/Backbone client interfaces and cold-start initial connects are registered already online, so they produce no up-edge (destinations with a refresh interval are still announced on them by the next sweep); RNode reports its edge before its stub exists and never reports down-edges; KISS never reports down-edges. Tests `automatic_announces_are_held_per_destination_per_interface`, `refresh_sweep_writes_ratchet_state_back`. A deliberate, bounded departure from the reference's "never automatic"; evidence in section C. |

| B23 | TCP client reconnect pacing | `TCPClientInterface.reconnect()` retries every `RECONNECT_WAIT` = 5 s, forever, with no backoff; a connection the peer resets at once is retried 5 s later. | Exponential backoff 5→300 s per episode (earlier departure), but each accepted connection reset `attempts` to 0, so a peer that accepts-then-resets was dialled every 5 s indefinitely. On 2026-09-23 rns.michmesh.net did exactly that to rfed and the fcm bridge (~11 resets/min each, for hours) after a restart-time sync burst, and our redial rate was itself abusive. | **Fixed 2026-09-23:** a connection that lives under `SHORT_LIVED_CONNECTION_SECS` (10 s) counts as a failed attempt; consecutive short-lived connections seed the next episode's backoff, so seven immediate resets reach the 300 s wait; a connection that lasts resets it. Test `short_lived_connections_keep_the_reconnect_backoff_climbing`. Deliberate departure: the reference's fixed 5 s is what got us throttled. |

## C. How this was tested

- `cargo test` (unit) after each area. Every test added for this audit was
  mutation-checked: the behaviour it pins was broken deliberately, the test
  was confirmed to fail, and the change reverted.
- Re-verification pass, 2026-09-22 (after the audit's own fixes landed): rows
  A1, A3, A7, A8, A11, A16 and B3 were implemented but had no test; they are
  pinned now. The same pass found four gaps, fixed here: the duplicate
  advertisement check (A3), `resource.cancel()` on an already-failed request
  (A5), the request-handler gate on the request Resource path (A8), and the
  frame bounds missing from LocalInterface and BackboneInterface (B12).
- `tests/interop/run.sh` against Python 1.5.2 (the workspace `.venv` was upgraded from rns 1.3.8 to 1.5.2 and lxmf 1.0.1 to 1.1.1 on 2026-09-22): 16/16 before and after.
- Staging network (`test-harnesses/staging`): chain check, `stage_browser.mjs`, flood.

Staging observations on 2026-09-22, recorded because the first two stage runs
failed before the third passed:

- `stage_browser.mjs` had a race of its own: B sent to the distro address
  before rfed's announce for it had given selectiv a path (the path from the
  previous day's runs had expired). The stage now waits for B to see that
  announce before sending.
- In the first gateway instance of the day, four of rfed's seventeen startup
  announces (among them `lxmf.propagation`) were received by the gateway but
  never reached selectiv, so neither browser could open its propagation link
  and the distro fan-out (which rfed intercepts on the propagation upload)
  never happened. A fresh gateway instance relayed all seventeen, and the
  stage passed. The first instance ran at notice level, so the rebroadcast
  decision is not in its log; not reproduced since. Worth watching on the
  production gateway (`GATEWAY_VERBOSE=1 staging.sh up` now runs the staging
  gateway at debug level).

Announce rate limiting on public nodes, 2026-09-22 (B22): a passive rns 1.5.2
client attached to rns.michmesh.net:7822 logged the wire hop count of every
announce copy the node forwarded (`scratchpad mmobs/observe.py`, a wrapper on
`Transport.inbound`). A second fresh client announced a new destination eight
times, 12 s apart: copies 1–7 arrived at wire hops 1, the 8th never did. In
the same window the phone re-announced four times (app relaunch + airplane
toggle) and none arrived; the harness browser's first announce arrived at wire
hops 3 (browser → retichat.com → gateway → node) and its second, 69 s later,
did not. So the 7-hop path the phone held for the browser was not topology:
the direct copies were being dropped at the node for announcing too often,
and the copies that survived came round through the other backbones.

## D. Remaining departures, by choice or deferred

A17–A26 and B14–B21 above, plus these partials found by the 2026-09-23 source audit:
A3 (the duplicate-advertisement check uses `try_lock`, so a locked resource can be accepted twice), A5 (the cancel branch in `fail()` is unreachable in production; its test sets up a state that cannot occur), A6 (response `metadata` is always `None`), A15 (only an unpack error tears the link down in that branch). Reference behaviour Rust lacks: shared-instance path-response announces on `register_destination` and on reconnect (Transport.py:2911, :3705); discovery announces are built on a PLAIN destination and never sent (Discovery.py uses SINGLE); LINKIDENTIFY is accepted on the initiator side; I2P read loops drop inbound frames. The transport-policy items (B14–B17) are the next
pass once the contract is settled; they change what a transport node
rebroadcasts and how paths are chosen, and need their own staging evidence.
