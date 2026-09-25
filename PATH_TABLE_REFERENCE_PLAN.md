Checked against DESIGN_PRINCIPLES.md: this plan adds no timer, retry or timeout (§1, §3, §4). It removes two clock heuristics: `PATH_STALE_THRESHOLD` and the one-second announce limiter. A failed link is now handled from the link's own close event (§5). Every behaviour change ships with a test that fails before the change (§10).

# Reticulum-rust: back to the reference path table, plus gravity (round 3)

`RNS/` means `.venv/lib/python3.13/site-packages/RNS/` (1.5.2). `rs/` means `Reticulum-rust/src/` at e918f86. Where the plan had to choose, it chose the reference. The few things that stay different are listed at the end, each with its reason.

## What changed since the last revision

- **Phones had no working way off a stale path. A15 adds one.**
  - Transport stores a *clone* of each link (`rs/link.rs:2094, 2187`). The clone never changes state, and `activate_link` has no caller.
  - So the jobs pass that expires a path after a failed link (`rs/transport.rs:2970-2998`) never runs. In the reference, that pass is the only way a non-transport node gets off a stale path (`RNS/Transport.py:697-731`).
  - A15 replaces the clones with records keyed by link id. The link's own close and establish events update the records, and the jobs pass then acts as the reference does.
  - This also ends two leaks that last for the life of the process: one clone per failed outbound attempt, and one per incoming link.
- **An unsent link request now gives one signal, not two.**
  - `initiate()` returns Ok, and the failure arrives only through `link_closed`, with reason NOT_SENT. Before, app-links emitted DISCONNECTED twice.
  - After NOT_SENT, a non-transport node with another interface up expires the path and asks again at once.
  - With no interface up, it keeps the path. Nothing can be learned, and the path is the right one when the interface comes back.
- **The one-second announce limiter goes (B7).** Rust drops the 11th and later copies of one destination's announce within a second, before admission (`rs/transport.rs:5446-5468`). The reference has no such drop. When the first copy wins, the dropped copy can be the very gravity-1 LAN copy that should replace it.
- **Tunnel syntheses are now signature-checked (A11).** Rust restores a tunnel's paths for any synthesis packet of the right size (`rs/transport.rs:2654-2663`, marked TODO). With one path per destination, a forged synthesis would move paths onto the forger's connection. The reference checks the signature first (`RNS/Transport.py:2798-2805`).
- **Two more reference rules are copied:** the link-transport rules (A16), and link-proof path rebalance (B8, open row B15). Rebalance matters now because the stored hops decide admission.
- **The announce split-horizon goes too (B3).** Rust never rebroadcasts an announce on the interface it arrived on (`rs/transport.rs:4217-4225`), and its comment cites Python lines that contain no such rule. The reference does rebroadcast there.
- **Local-client routing is out of scope, and the plan now says so.**
  - Rust puts a program's uplink to its shared instance in `local_client_interfaces`. It never registers its LocalServer spawns, and it never applies the local-client hop decrement.
  - The reference's local-client terms would therefore mean the wrong thing in Rust. A6 gates transit on `transport_enabled` alone and deletes INJECT-TID, and the gap is recorded in PARITY section D.
  - No production node shares an instance: `share_instance = No` in rfed's config and in the Android config writer.
- **Saving gets its own lock, and nothing clones the whole table any more.**
  - A8: two savers can no longer interleave on one temp file.
  - A17: `TransportSnapshot` loses `path_table`. LXMF's three RSSI/SNR/Q lookups per message, and rfed's 30 s status file, stop copying 13,853 entries each time.
- **The link table keeps insertion order (B2).** The reference's per-pass `blocked_if` quirk is then copied exactly.
- **Staging now measures the gateway, not PHP.**
  - The looped copy comes from a second PostInterface peer, which then disconnects.
  - Links through the gateway are opened from the RPi side, and the verdict is the gateway's own link-table next hop.
  - The second backbone runs the reference RNS 1.5.2, and iOS is added.
- **A1 counts instead of logging every packet.** It also covers A7's two rules and the limiter. With your permission, it can run on the production gateway for a day (decision 6).

## Which config I trusted

Neither `OPNS-RNS-Post-Bridge` nor `test-harnesses` holds a copy of the live gateway config.
- The OPNsense template and `config/reticulum.conf.example` generate:
  - a `[[Backbone Bridge]]` BackboneInterface at bitrate 1e9;
  - no `mode = gateway`;
  - no TCPClientInterface at all.
- The staging gateway has no `[[LAN]]`, and its Bridge runs at 1e9.
- The gateway's own destination_table (session scratchpad `gwcache/`, copied today at 16:13) names its LAN paths like `Client on LAN [192.168.2.23:49612]`. That is a TCPServerInterface spawn name.

So I trusted the production facts you gave, backed by that table:
- `[[LAN]]` is a TCPServerInterface on 4242;
- the Bridge has `mode = gateway` and `bitrate = 200000`;
- the backbones are TCP clients.

Nobody has read the configured backbone names themselves. The migration numbers below assume the six names that appear in the table, and decision 7 asks for the live config.

## The change

- **One path per destination**, laid out as the reference lays it out: timestamp, next hop, hops, expires, random_blobs, receiving interface, packet hash (`RNS/Transport.py:180, 4122-4128`). A `path_states` map sits beside it.
- **Admission follows the reference branch for branch** (2206-2296).
  - For any one emission, the first copy heard wins.
  - A later copy of the same emission replaces it only when it has hops ≤ the stored path AND arrived on an interface with strictly higher gravity (2245-2251).
  - Every copy reaches admission (B7).
- **Bitrate no longer picks the path.**
- **Every reader uses that one entry, with no online check** (1383-1437, 2017-2119, 3126-3164, 3436-3519).
- **Handlers, the announce table and the cache run only for an admitted copy** (2298-2537). This includes discovery's handler.
- **Gravity is parsed and inherited as in the reference.** A value that is not an integer stops start-up.
- **Link proofs rebalance the stored hops** (2612-2634, 2680-2708).

## The 2026-09-25 case, and what gravity costs

**How the gateway behaves:**
- **LAN copy first.** The 1-hop LAN copy is admitted, and looped copies of the same emission are rejected (2252-2296). The Bridge's bitrate no longer matters.
- **Looped copy first, gravity 0.**
  - The looped copy is admitted.
  - The direct copy of the same emission is then rejected: it has hops ≤ stored and the same emission, and 0 ≤ 0.
  - The detour lasts until rfed's next emission (6 h for lxmf.propagation, B28), or until the path goes unused for 7 days (964-972).
  - Marking the path unresponsive does not help, because that branch admits only copies with more hops (2292).
- **This is not only a restart case.**
  - rfed sends its own announces one interface at a time, about 0.6 s apart (PARITY B22/B41). A copy that leaves on an internet backbone first can reach the gateway before the LAN copy does.
  - After a restart, Rust also never holds announces on a new interface (B17/B25).
- **Looped copy first, `[[LAN]]` at gravity 1.** The LAN copy has hops ≤ stored and 1 > 0, so the gateway logs `Replacing ... due to higher gravity (0->1)` and moves the path. Spawns inherit the listener's gravity (`RNS/Interfaces/TCPInterface.py:640`).

**What else gravity 1 on `[[LAN]]` does.** It applies to every copy that arrives on a LAN spawn, not only to rfed's own destinations.
- rfed is a transport node and relays what it hears on its backbones into the gateway's LAN.
- In today's table:
  - 4,859 destinations have a LAN route;
  - 416 of them have one with no more hops than their best backbone route;
  - of those 416, 3 are 1-hop LAN nodes and 413 are relayed by rfed (192.168.2.23).
- At gravity 1, each of the 413 moves to rfed whenever rfed's copy of an emission lands after a backbone copy.
- The gateway's transit for those internet destinations then runs through the NAS.
- While rfed is disconnected, the gateway has no path for them until tunnel restore puts them back or someone asks.

**My recommendation is still `gravity = 1` under `[[LAN]]`,** with that cost in view. Staging step 7 counts the effect first. The alternatives:
- **Gravity 0** is pure reference. Tunnel restore covers the restart case, but nothing covers the announce race.
- **`gravity = -1` on the Bridge** covers only copies that came through the Bridge.
- **Access-point mode on rfed's gateway client** does not stop the relaying without a worse cost: it also stops rfed's own announces there (`RNS/Transport.py:1475`; Rust's announce sweep skips AP interfaces, `rs/transport.rs:3313-3319`).

Gravity never beats a copy with fewer hops (2236).

## Transit, and the order it has to change in

Today split-horizon is what stops a non-transport node reflecting an overheard LINKREQUEST back out its arrival interface.
- INJECT-TID gives our transport id to any packet whose destination has a path.
- The transit block has no transport gate.
- For DATA, split-horizon stops nothing: the link-table-miss and DATA fallbacks re-send overheard DATA anyway, up to three copies each.

So the order is:
1. **A6** brings transit to the reference while split-horizon is still in place:
   - the foreign transport id filter (1629-1633);
   - transit and proof transport only on transport nodes;
   - no INJECT-TID;
   - no path-table fallbacks.
2. **A16** copies the link-transport rules:
   - nothing is forwarded before the link is validated (2126-2128);
   - a transported link packet is never processed locally (2166);
   - LRPROOF relay runs only on transport nodes (2612);
   - a link-table LRPROOF never goes to a local link.
3. **B3** then removes split-horizon, both for transit and for announce rebroadcasts.

After A6, a non-transport phone forwards nothing that is not its own. A6 also rewrites `plain_data_passes_filter_with_foreign_transport_id` (`rs/transport.rs:10448`). The transport id names the next hop, and the Python PostInterface already runs under the reference filter against the same PHP.

Before any of these branches goes, A1's counters show whether a bridge flow still uses it: in staging, and on the production gateway if you allow it (decision 6).

## A path on a backbone that just went down

The reference keeps such a path. An outgoing TCP client stays registered while it reconnects, and the answer to a path request carries the emission already held, so it is rejected.

What happens on the branch:
- **A local send** on that path reports "not sent" (Fix 4, kept). A link attempt closes at once, with reason NOT_SENT (A5).
- **A non-transport phone with another interface up** expires the path and asks again on the next jobs pass (A15). The reference does the same after its establishment timeout.
  - The answer is admitted as new, and the next attempt works.
  - The message that hit the dead path fails at once, because LXMF-rust counts that close as its last attempt. See decision 8; L1 would avoid this.
- **A phone with no interface up** keeps the path (a departure) and uses it when the interface returns.
- **A transport node** (the gateway, rfed) waits for one of two events:
  - the backbone reconnects (Rust backs off to 300 s, B23; the reference retries every 5 s);
  - the destination emits again.

  Web clients whose links cross the gateway see a silent establishment timeout. The reference has no reject message either (2115-2119).

e918f86 switched to another stored route at once. Staging step 10 measures the outage on both builds, and you choose what to do (decision 5).

## Steps, in landing order

- **Group A:** each step is safe alone on today's table. A15 needs A5.
- **Group B:** B1 must land as one unit. B2-B8 are each safe once B1 is in.
- **L1** is optional and depends on decision 8.

Everything goes on one branch. Nothing reaches main before staging passes.

| Step | What | Reference |
|---|---|---|
| A0 | Interop cell: live tables, a fresh-identity barrier per step, burst and link-transport scenarios | 2206-2296, 1629-1633, 1997-2166 |
| A1 | Counters on every Rust-only branch (evidence for A6, A7, A16, B3, B7) | — |
| A2 | Gravity plumbing; strict parsing; NOTICE registration line | Reticulum.py:579-581, 640-642, 798-799, 1126-1136 |
| A3 | A BackboneClient stays registered when its first connect fails | BackboneInterface.py:898-918 |
| A4 | Backbone spawns get unique names | BackboneInterface.py:1111-1114 |
| A5 | Unsent link request closes at once, with one signal | departure; Link.py:318-323, 712-735 |
| A15 | Pending and active links follow the link's own events | 697-731, 2929-2948 |
| A6 | Transit parity, gated on transport_enabled | 1629-1633, 1997-2119, 2733-2743 |
| A16 | Link-transport rules | 2121-2166, 2612-2711 |
| A7 | Outbound header rules | 1383-1437 |
| A8 | Saves outside TRANSPORT, serialised by their own lock | — |
| A17 | No full-table snapshot | — |
| A9 | Rediscovery request on every interface except blocked_if | 1229-1263 |
| A10 | Remove PATH_STALE_THRESHOLD; reference timestamp rules | 964-972, 1406, 1426, 2113 |
| A11 | Tunnel synthesis: signature check; restore only on a new interface | 2798-2805, 2819-2874 |
| A12 | Pure admission function, not yet wired | 2206-2296, 3725-3742 |
| A13 | rfed: static peers seeded from remembered app_data | LXMRouter.py:633-642 |
| A14 | Phone FFI copies the identity even when the clone is refused | — |
| B1 | The switch (one unit) | 2206-2537, 3126-3164, 3229-3259, 3436-3519 |
| B2 | Jobs; interfaces_configured; insertion-ordered link table | 857-978 |
| B7 | Remove the one-second announce limiter | 2302-2330 |
| B3 | Remove split-horizon for transit and announces (needs your sign-off) | 790-807, 1447-1500, 2057 |
| B4 | Persistence and migration | 404-460, 3788-3875 |
| B5 | Tunnels: blob list, timebase restore and cull | 2467-2476, 2819-2874, 1040-1057 |
| B8 | Link-proof path rebalance (B15) | 2612-2634, 2680-2708 |
| B6 | One PathEntry per destination | 180 |
| L1 | Optional (decision 8): LXMF resolves a dead path before linking | — |
| C1 | PARITY-AUDIT, docs, announce_log whitelist, rebuilds | — |
| C2 | OPNsense template generates the live config | — |
| D1 | Staging proof and interop matrix | — |
| D2 | Rollout | — |

## Tests that carry the argument

Each test fails on e918f86 wherever it compiles there; otherwise it is mutation-checked. The test guards reset path_states and the cull-armed flag.
- **The 2026-09-25 case:** all three orders, each run with the Bridge at 200000 and again with the bitrates swapped.
- **Gravity after a burst:** a gravity-1 copy that arrives after ten looped copies in one second still wins (B7).
- **Transit:**
  - a non-transport node forwards nothing it overhears (A6);
  - a DATA packet in transit leaves once (A6);
  - a link packet is not forwarded before validation, and is not delivered locally when it is transported (A16).
- **Link failure:**
  - a closed pending link expires the path and asks again (A15);
  - an unsent link with no interface up keeps the path (A15);
  - no link record outlives its link (A15);
  - an unsent link request closes once, and app-links emits one DISCONNECTED (A5).
- **Tunnels:** a forged synthesis changes nothing, and a heartbeat never undoes a gravity or unresponsive replacement (A11, B5).
- **Saving:** two concurrent saves leave a readable file that holds the newer table (A8).
- **Rebalance:** a validly signed link proof with the wrong hop count rebalances the path and is relayed (B8).

## Migration

Numbers from the production gateway copy (`gwcache/destination_table`, today 16:13), assuming the six configured names that appear in it:
- **Size:** 13,853 destinations and 39,963 routes. 2,220 destinations hold routes from different emissions, and one route has no cached announce.
- **The rule:**
  1. Filter each entry first: its interface must be configured and its announce cached.
  2. Then pick the newest emission, then the fewest hops, then the latest timestamp.
- **Result:** 13,814 destinations load. 39 have routes only on old LAN spawn names and load none.
- **LAN destinations:** 38 are 1 hop away via the LAN.
  - 35 load no path, and 3 load a backbone detour.
  - All of them come back when rfed reconnects, through tunnel restore or rfed's up-edge announce (staging step 8).
- **The order matters:** choosing an entry before filtering would have lost 250 destinations that had a backbone route.

The report is re-run with the live config's names before deploy (decision 7). The full rules are in `migration`.

## Departures kept

The full list, with reasons, is in `departures_kept`. In short:
- **Kept because the reference would show the user a false outcome:**
  - Fix 4;
  - the immediate NOT_SENT close;
  - keeping the path after NOT_SENT when no interface is up.
- **Kept because Rust's architecture differs:**
  - expire_path removes the path at once;
  - non-transport nodes persist paths;
  - clone_path;
  - the event-driven path waiters;
  - the heartbeat restores only on a changed interface;
  - tunnel blob lists are snapshots;
  - gravity is read by interface name;
  - the file format;
  - the load-time filter by configured names;
  - local-client routing is absent (out of scope).
- **Kept because the reference cannot be reproduced:** blob order after a restore.
- **Unchanged:** diagnostic log lines; hops_to still returns 4.

**Removed:**
- multi-route, bitrate scoring, and the online gate in path selection;
- PATH_STALE_THRESHOLD;
- split-horizon, for transit and for announces;
- INJECT-TID, the three path-table fallbacks and the ungated transit block;
- the one-second announce limiter;
- handlers firing on every copy;
- two outbound header rules;
- deleting routes when a path is marked unresponsive;
- unsigned tunnel syntheses.

## New PARITY rows

New rows, from B43 on:
- **Fixed:**
  - transit parity (A6);
  - link-transport rules (A16);
  - Backbone spawn identity (A4);
  - BackboneClient first connect (A3);
  - outbound header rules (A7);
  - tunnel synthesis signature (A11);
  - pending and active links follow the link (A15);
  - the pre-admission announce limiter (B7);
  - announce split-horizon (B3).
- **Open:**
  - rebroadcast bookkeeping (`hops-1 == entry`);
  - 8 h tunnel lifetimes;
  - the TCP-server spawn stub fields;
  - `announce_rate_target`;
  - in-flight path requests;
  - shared-instance local-client routing (section D);
  - set_keepalive_interval never reaching a live link.
- **Departures:**
  - the unsent link request (A5);
  - the path kept after NOT_SENT with no interface up (A15);
  - the heartbeat restore gate, including its effect on upstream reference peers (A11).
- **Your decision:** paths pinned to an interface that went down (B49).

Existing rows:
- B14, A21 and B15 become fixed.
- B29 is removed.
- B24 is replaced.
- The B32 and B42 notes say the timebase rule is copied, except for blob aliasing.
- Section C gains the clock-skew note.

## Found, not fixed here

`set_keepalive_interval` (`rs/reticulum.rs:2112-2145`), which the phones call when they go to the background, has only ever changed Transport's link clones, never a live link. A15 deletes the dead loop without changing behaviour. Whether to fix it is decision 9.

## Other effects

- **LXMF-rust:** no change unless you choose L1. Link failures now arrive at once, and its RSSI/SNR/Q lookups stop cloning the table (A17).
- **app-links:**
  - switches to `interface_snapshots()` (A17);
  - emits one DISCONNECTED per unsent request (A5).
- **rfed:**
  - A13, A17's four callers, and a rebuild;
  - its fanout already treats "not sent" as deferred (`RFed-rust/rfed/src/fanout.rs:415-443`).
- **Phones:**
  - A14, plus rebuilds: `buildRustNdk` before `assembleDebug`, and the iOS xcframework;
  - paths on BLE and RNode interfaces do not survive a restart, as for a reference client.
- **Risks I accept:**
  - The migration's choice is approximate, because Rust never recorded which copy arrived first.
  - The gap between `Transport::start` and `interfaces_configured()` matters only for a configured interface that fails to register.

---

## Decisions for James, in full

1. Split-horizon (B3): sign off removing it for transit and for announce rebroadcasts, and rewriting its NEVER REMOVE EVER tests (rs/transport.rs:10677-10910). This happens only after A6, A16 and B1. The announce part means every announce also goes back out on the interface it arrived on, held to that interface's announce cap, as in the reference (RNS/Transport.py:790-807, 1447-1500). The marker moves to a_looped_bridge_copy_never_displaces_the_direct_path.

2. Sign off two more NEVER REMOVE EVER changes:
- rewriting same_announce_over_two_routes_keeps_both_paths_and_prefers_fewer_hops (rs/transport.rs:8150-8286) as one_announce_over_two_routes_keeps_the_first_copy_unless_gravity_is_higher, which keeps the marker;
- deleting the dedup-key comment at rs/transport.rs:5857, together with the block it describes.

3. Gravity on the production gateway. I recommend `gravity = 1` under `[[LAN]]`, with both effects in view.

What it gains: rfed's destinations return to the LAN whenever a looped copy wins the race. That happens after a gateway restart, or whenever rfed's copy on an internet backbone leaves first; rfed announces one interface at a time.

What it costs: the rule applies to every copy that arrives on a LAN spawn, not only rfed's own destinations.
- In today's table, 4,859 destinations have a LAN route. 413 of them have an rfed-relayed copy with no more hops than their best backbone copy.
- Each of those would route through rfed on any emission where rfed's copy lands after a backbone copy.
- While rfed is disconnected, the gateway has no path for them until tunnel restore or a path request.
Staging step 7 counts this before you decide.

Alternatives:
- gravity 0: pure reference. Tunnel restore covers the restart case, but nothing covers the announce race;
- -1 on the Bridge: covers only Bridge copies;
- access-point mode on rfed's gateway client: not an option, because it also blocks rfed's own announces there (RNS/Transport.py:1475; rs/transport.rs:3313-3319).

Before setting any value, confirm that [[LAN]] is reachable only from the LAN (listen_ip or firewall), because every spawn inherits it. Optionally, gravity 1 on rfed's client to the gateway has the mirror effect on rfed.

4. The OPNsense template does not produce the live config:
- it generates a Backbone Bridge instead of a [[LAN]] TCPServerInterface;
- it has no mode = gateway;
- it sets bitrate 1e9;
- it has no TCPClientInterfaces at all, so pressing Save today would also remove every backbone.

Choose one:
- C2 (recommended): it generates the live shape, including a verbatim extra-interfaces field, with a render test against the live config;
- or stop using Save for rnsd.

Until C2 is deployed and its test passes, do not press Save.

5. Paths pinned to a backbone that went down (new row B49). Choose after staging step 10 gives the numbers for e918f86 and the branch:
- (a) Accept the reference (recommended). Local sends report not sent. Phones with another interface up expire the path and ask again at once (A15). Web clients through the gateway see a silent establishment timeout. The gateway waits for the reconnect or the next emission.
- (b) Also bring back the reference's 5 s TCP reconnect (B23). This undoes a departure made because public nodes throttle the home IP.
- (c) Mark an interface's paths unresponsive on its down-edge. This is a deterministic departure that lets a more-hops copy of the same emission in. But a transport node that holds a path answers path requests from its cache and asks for no new copy, so I expect little gain. If you choose it, step 10(i) measures it.
- (d) Drop every path on the interface at its down-edge: about 5,000 paths per flap on zer0bitz. Not recommended.

Also weigh this: Rust's 60 s tunnel heartbeat makes each reference backbone restore our tunnel's paths every minute. For destinations it learned through us, that can undo its own gravity and unresponsive replacements. It is recorded in the heartbeat's PARITY row.

6. Evidence before A6, A7, A16, B3 and B7 remove branches.

(i) After staging step 1, may e918f86+A1 run on the production gateway for a day? It only counts: first-occurrence NOTICE lines, plus the existing 30 s summary. You deploy it.

(ii) If a counter shows a bridge flow that depends on a branch being removed, choose one:
- fix it in Reticulum-post (recommended; the Python PostInterface already runs under the reference filter against the same PHP);
- or keep a carve-out on the PostInterface only, recorded as a departure.

7. Rollout gate and access.

The order: I push the branch, not main. You deploy the gateway with rnsd-redeploy.sh <branch rev>. Main is merged, in the D2 order, only after the gateway is verified. You hold the rfed and bridge pulls until then, and the phones go last.

With your permission, I need copies of:
- the live /usr/local/etc/reticulum/config from the gateway, for C2's render test and for the migration's configured names;
- the NAS rfed _rns/storage, cache/announces and config;
and read access to the gateway's syslog in the NAS DB.

8. DIRECT messages when the path's interface is down. LXMF-rust counts a link close as a delivery attempt, and allows 2.

The two cases:
- A phone with no interface up: e918f86 fails the message after about 14 s; the branch fails it at once. Same outcome, sooner.
- A phone whose path's backbone is down while another is up: e918f86 delivered over another stored route. The branch fails that message at once, and the next one works after A15 re-asks.

Choose:
- (a) accept both;
- (b) add L1 (recommended). LXMF-rust re-resolves the path before opening a link when the path's interface is down and another is up, so that message is delivered. The no-interface case stays as in (a).

Staging step 16 measures both.

9. Found, not fixed: set_keepalive_interval (rs/reticulum.rs:2112-2145), which the phones call for background mode, has only ever changed Transport's link clones, never a live link. Only its TCP probe part takes effect. A15 deletes the dead loop without changing behaviour. Choose: fix it separately by routing the value through the runtime link handles, or leave it.

---

## Steps

| Id | Safe alone | Change | Files | Reference | Tests |
|---|---|---|---|---|---|
| A0 | yes | Reference-driven interop cell for admission and transit. Test harness only; no product code.  Nodes, each a small in-process program: - tests/interop/path_node.py runs the venv's RNS 1.5.2 as a transport node, with ingress_control = No; - examples/path_admission_node.rs runs Reticulum-rust as a transport node. Each node has two TCPServerInterfaces: A at gravity 0 and B at gravity 1 (e918f86 ignores the key). On a stdin 'dump' each node prints its live path table as JSON: destination, next_hop, hops, interface. Nothing is compared through SIGTERM or a persisted file.  Feeder, on the venv's RNS: - one TCP connection per server per node; - every announce carries its emission time in the random blob; - the identical bytes go to both nodes on the same side. Then a barrier announce goes on the same socket, and the feeder waits until both nodes print BARRIER; - every barrier is built from a fresh identity, so it is always admitted (branch A), whatever the emission times. Scenario destinations get at most 3 copies within any second. That is below e918f86's limit of 10, except in the burst scenario, which exists to show the limit.  Admission scenarios: A, B1, B-older, B-same-emission-equal-gravity (the detour), B2, B2-lower, C2, C-same-emission, C-older, and burst. Burst sends 11 looped copies of one emission on A within a second, then the same emission on B. C1 and C3 stay unit-only.  Transit scenarios: - DATA with a foreign transport_id; - HEADER_1 DATA for a remote destination; - DATA addressed to the node whose path points back out the arrival interface; - link DATA sent before the link's proof has passed; - an announce whose path arrived on the interface it would be rebroadcast on. Each is followed by a control packet on the same outbound socket. Each writer is FIFO, so 'nothing was forwarded' is decided when the control packet arrives.  The runner records e918f86's differences in tests/interop/path_admission_e918f86.txt. That file is the fails-before record for A6, A16, B1, B3 and B7. | Reticulum-rust/tests/interop/path_admission_interop.py (new), Reticulum-rust/tests/interop/path_node.py (new), Reticulum-rust/examples/path_admission_node.rs (new), Reticulum-rust/tests/interop/run_path_admission.sh (new), Reticulum-rust/tests/interop/run.sh | The oracle is the reference running live: - admission: RNS/Transport.py:2206-2296 - filter: 1629-1633 - transit: 1997-2119 - link transport: 2121-2166 - announce rebroadcast: 790-807, 1447-1500  Other behaviour relied on: - FIFO announce queue: RNS/Transport.py:46-80, 1894-1907 - ingress holding, turned off in the cell: 1812-1825 | Sanity: with both sides pointed at Python nodes, every scenario is identical.  Fails-before on e918f86, recorded: - the detour; - B-older, B2, C2 and C-same-emission; - burst; - foreign transport_id; - HEADER_1-remote; - pre-validation link DATA; - an announce rebroadcast on its arrival interface.  tests/interop/run.sh stays 16/16. |
| A1 | yes | Measure the Rust-only branches before A6, A7, A16, B3 and B7 remove them. Counting and logging only; no behaviour change.  There is one counter per (branch, arrival interface, outbound interface). - The first occurrence of each key logs one NOTICE line: [RUST-ONLY-FWD] branch=<name> ptype arrived_on out_iface dest. - After that, the counts go out in announce_log's existing 30 s summary line, and only when they changed. - There is no line per packet, because the gateway logs to the NAS syslog database.  Branches: - inject-foreign: INJECT-TID replaced a transport_id that was not ours; - inject-remote: INJECT-TID gave our id to a packet that had none; - non-transport-transit: the transit block ran with transport disabled; - linktable-miss-fallback, data-fallback and proof-fallback; - outbound-rule1: hops > 1 and next_hop == destination, sent raw; - outbound-rule2: a HEADER_2 packet sent raw on a multi-hop path; - link-prevalidation: a link packet forwarded before its link-table entry was validated; - lrproof-local-handoff: a link-table LRPROOF handed to a local link; - announce-limiter-drop, counted per arrival interface; - announce-arrival-skip: a rebroadcast held back from its arrival interface.  Each counter goes away with its branch. | Reticulum-rust/src/announce_log.rs, Reticulum-rust/src/transport.rs:4015-4061, Reticulum-rust/src/transport.rs:4217-4225, Reticulum-rust/src/transport.rs:5446-5468, Reticulum-rust/src/transport.rs:6064-6346, Reticulum-rust/src/transport.rs:6380-6450, Reticulum-rust/src/transport.rs:6470-6545, Reticulum-rust/src/transport.rs:6579-6612 | What the reference forwards, and nothing else: - filter: RNS/Transport.py:1629-1633 - transport gate: 1997 - link transport: 2121-2166 - LRPROOF: 2612-2711 - proof transport: 2733-2743 - outbound: 1383-1437 - announce rebroadcast: 790-807, 1447-1500 - rate limiting after admission only: 2302-2330 | One unit test per branch: - a crafted packet increments exactly that counter and logs once; - a second identical packet increments the counter again, with no second line. Each test is mutation-checked by deleting the increment.  Staging step 1 reads the counters over the whole suite. Decision 6 asks to run the same build on the production gateway for a day. |
| A2 | yes | Gravity plumbing. Nothing reads gravity yet, so routing does not change.  Config: - [reticulum] default_gravity and autoconnect_interface_gravity go into ReticulumFlags. - They are read with a new strict integer getter in config.rs. An absent key gives None; a value that is not an integer makes apply_config return Err, as as_int raises. Today's get_int silently returns None (rs/config.rs:32-34). - apply_config validates every [interfaces] section's gravity key the same way, before any interface is built.  Interfaces: - Interface::DEFAULT_GRAVITY = 0; the base Interface, InterfaceStub and InterfaceStubConfig each get a gravity field. - None resolves to default_gravity() BEFORE the TRANSPORT lock is taken, in the synthesize block and in ffi::register_callback_interface. register_interface_stub_config therefore never takes FLAGS while it holds TRANSPORT.  Spawns copy their parent's gravity: - TCP server: SpawnConfig and the spawned stub; - Backbone: the parent capture and the spawned stub; - AutoInterface peers: through stub_config_template.  Local-client stubs stay at 0.  Other: - rs/discovery.rs:757-760 gets a comment: auto-connect uses autoconnect_interface_gravity or 0. - Each interface's gravity is logged at NOTICE when it registers. That line is how the deployed value is confirmed on the gateway, which logs at NOTICE. | Reticulum-rust/src/reticulum.rs:152-187, Reticulum-rust/src/reticulum.rs:1071-1113, Reticulum-rust/src/reticulum.rs:1393-1448, Reticulum-rust/src/reticulum.rs:1541-1576, Reticulum-rust/src/config.rs:32-34, Reticulum-rust/src/interfaces/interface.rs:128-141, Reticulum-rust/src/transport.rs:189-272, Reticulum-rust/src/transport.rs:420-461, Reticulum-rust/src/transport.rs:1745-1760, Reticulum-rust/src/transport.rs:1814-1856, Reticulum-rust/src/ffi.rs:412-431, Reticulum-rust/src/interfaces/tcp_interface.rs:1530-1610, Reticulum-rust/src/interfaces/tcp_interface.rs:1793-1799, Reticulum-rust/src/interfaces/backbone_interface.rs:168-181, Reticulum-rust/src/interfaces/backbone_interface.rs:257-271, Reticulum-rust/src/discovery.rs:757-760 | Reticulum.py: - state: RNS/Reticulum.py:266, 273 - [reticulum] keys: 579-581, 640-642 - per-interface key: 798-799, 944 - _add_interface: 1126-1136 - default: 1176-1177, 2040-2041  Interfaces: - RNS/Interfaces/Interface.py:75, 109 - spawns: TCPInterface.py:640, BackboneInterface.py:740, AutoInterface.py:583 - local clients: LocalInterface.py:436-457  Discovery: RNS/Discovery.py:772-778 | Each test is mutation-checked.  Defaults and overrides: - gravity_defaults_to_zero - default_gravity_applies_to_interfaces_without_their_own - interface_gravity_overrides_default_gravity - negative_gravity_is_accepted  Start-up validation: - a_non_integer_interface_gravity_aborts_startup - a_non_integer_default_gravity_aborts_startup - a_non_integer_autoconnect_interface_gravity_aborts_startup  Spawn inheritance: - tcp_server_spawn_inherits_gravity - backbone_spawn_inherits_gravity - auto_interface_peer_inherits_gravity  Other: - local_client_interfaces_stay_at_zero - callback_interface_gets_default_gravity - registration_logs_the_interfaces_gravity_at_notice  The routing tests pass unchanged. |
| A3 | yes | Today BackboneClientInterface::new returns Err when its first connect fails (rs/interfaces/backbone_interface.rs:446-490). No stub, outbound handler or reconnect loop is then registered, so the interface never comes up for the rest of the run.  Change: - a failed first connect logs, leaves online = false, and returns the interface; - the synthesize block registers the stub and starts the read/reconnect loop, as it already does for TCPClientInterface; - the reconnect's up-edge sets the interface online and synthesizes the tunnel.  This must land before B2, whose interfaces_configured() drops loaded paths on unregistered interfaces. | Reticulum-rust/src/interfaces/backbone_interface.rs:446-560, Reticulum-rust/src/reticulum.rs:1946-1985 | RNS/Interfaces/BackboneInterface.py:898-918: initial_connect starts the reconnect thread when the connect fails. | - a_backbone_client_whose_first_connect_fails_is_registered_offline: fails on e918f86. - a_backbone_client_connects_when_its_peer_appears_later: waits on the up-edge event. Fails on e918f86. |
| A4 | yes | Give each client of a Backbone listener its own name. Today every spawn is named 'Client on {parent}' (rs/interfaces/backbone_interface.rs:187, 406-410), which causes three faults: - a second client's stub is never registered (rs/transport.rs:1747-1751); - the second client's writer replaces the first one (rs/transport.rs:986-995); - the first disconnect deregisters the stub and the writer for every client (rs/interfaces/backbone_interface.rs:815-825).  Change: name spawns 'Client on {parent} [{addr}]', as TCP-server spawns already are named.  On the production gateway nothing changes, because its listener is a TCPServerInterface. The B4 migration report counts paths on shared names. | Reticulum-rust/src/interfaces/backbone_interface.rs:186-188, Reticulum-rust/src/interfaces/backbone_interface.rs:406-410, Reticulum-rust/src/interfaces/backbone_interface.rs:810-825 | RNS/Interfaces/BackboneInterface.py:1111-1114: each connection gets its own spawned interface. | - two_backbone_clients_get_distinct_interface_names: fails on e918f86. - each_backbone_client_receives_only_its_own_traffic: fails on e918f86. - one_backbone_client_leaving_keeps_the_other_registered_with_its_writer: fails on e918f86.  Staged in D1 step 12. |
| A5 | yes | A link request that left on no interface now fails at once, through one channel. This is a departure by choice.  Why a check on sent is needed: Packet::send returns Ok(None) for a LINKREQUEST whether or not it went out (rs/packet.rs:330-364). Link::initiate_send ignores the difference (rs/link.rs:2193-2197), so the link waits for its establishment timeout.  Change, in initiate_send: - after packet.send(), read packet.sent; - if it is false, log '[LINK] link request for <dest> not sent: no interface took it'; - tear the link down with a new Rust-only reason, REASON_NOT_SENT. link_closed fires once, on its own thread, as for any other close.  initiate() still returns Ok, so there is one failure signal, not two. Ok means the request was handed to Transport; the outcome comes through the callbacks (§7). Otherwise app-links would emit DISCONNECTED once from its Err branch and again from its closed callback (app-links/src/lib.rs:1395-1437).  A new LinkHandle::teardown_reason() lets callers and tests read the reason. Every caller already handles a link that closes before it is established. | Reticulum-rust/src/link.rs:2193-2197, Reticulum-rust/src/link.rs:985-1003, Reticulum-rust/src/link.rs:1812, Reticulum-rust/src/packet.rs:330-364, app-links/src/lib.rs:1395-1437 | The reference sends, ignores the result and waits for the establishment timeout: RNS/Link.py:318-323, 712-735.  This is kept as a departure because copying the reference would show a link as establishing when its request never left. | - a_link_request_that_no_interface_takes_closes_at_once: every interface is offline. initiate returns Ok, and link_closed fires exactly once with REASON_NOT_SENT, before any establishment timeout. Fails on e918f86. - a_sent_link_request_still_waits_for_its_proof: passes before and after. - app-links: persistent_open_emits_one_disconnected_for_an_unsent_link_request. Mutation-checked by making initiate also return Err. |
| A15 | yes | Pending and active links follow the link's own events. Needs A5.  The problem today: - Transport::register_link stores a clone of the Link (rs/link.rs:2094, 2187). The actor's Link changes state; the clone never does. - activate_link has no caller. - So the jobs pass (rs/transport.rs:2970-2998) never sees a CLOSED pending link, and one clone per outbound attempt and per incoming link is kept forever.  Change: - pending_links and active_links become records keyed by link id. Each holds the destination hash, the initiator flag, and the close reason once the link has closed. - Link::link_closed is reached from every close path: teardown, the peer's LINKCLOSE, stale, establishment timeout and NOT_SENT. It calls a new Transport::link_closed(link_id, reason), which marks a pending record closed and removes an active one. - On the initiator, handle_proof_packet's activation calls Transport::activate_link(link_id). - The jobs pass handles closed pending records as the reference does. On a non-transport node that is not connected to a shared instance, it calls expire_path(destination), then sends a path request unless PATH_REQUEST_MI throttles it. The record is removed either way. - Exception, a departure: NOT_SENT with no interface online keeps the path. The request never left and nothing can be learned, and the path is right when the interface returns. With another interface online, NOT_SENT is handled like any other close. - set_keepalive_interval (rs/reticulum.rs:2128-2145) wrote keepalive values into the clones, so it has never reached a live link. Its link loop is deleted, which changes no behaviour. See decision 9.  The close event only marks the record, and the jobs pass acts on it, as in the reference. No Transport work beyond marking runs on the link actor's thread. The race the reference also has, where LXMF's own request is answered before the path is expired, is left as it is. | Reticulum-rust/src/transport.rs:469-470, Reticulum-rust/src/transport.rs:2968-2998, Reticulum-rust/src/transport.rs:5247-5266, Reticulum-rust/src/link.rs:2085-2100, Reticulum-rust/src/link.rs:2175-2190, Reticulum-rust/src/link.rs:2973-3030, Reticulum-rust/src/link.rs:3078-3130, Reticulum-rust/src/link.rs:4627-4720, Reticulum-rust/src/reticulum.rs:2112-2150 | - pending-link jobs: RNS/Transport.py:697-731 - register_link and activate_link: 2925-2948 - expire_path: 3219-3226 | End to end through LinkHandle::initiate. Each test is mutation-checked. - a_pending_link_torn_down_before_its_proof_expires_the_path_and_requests_it: a non-transport node. Fails on e918f86. - an_establishment_timeout_expires_the_path_and_requests_it: driven through the actor's establishment check. Fails on e918f86. - a_not_sent_link_with_another_interface_online_expires_and_requests_the_path - a_not_sent_link_with_no_interface_online_keeps_the_path - a_transport_node_keeps_the_path_when_a_pending_link_closes - an_established_link_moves_from_pending_to_active: fails on e918f86. - no_link_record_outlives_its_link: after establish-then-close and after a failed attempt, both maps are empty. Fails on e918f86. - an_incoming_link_record_is_removed_when_it_closes: fails on e918f86. |
| A6 | yes | Transit parity. This lands before split-horizon comes out in B3.  1. Packet filter: after the shared-instance check, drop any non-announce packet whose transport_id is set and is not our identity hash. 2. Gate the transit block, and proof transport through the reverse table, on transport_enabled alone. The reference also opens them for local clients (1997, 2735). Rust has no working local-client routing (PARITY section D), and using its local_client_interfaces would open the gate on every program connected to a shared instance. 3. Delete INJECT-TID. The reference injects only for a hops-0 local-client path (2006), which Rust never has. 4. Delete the link-table-miss path fallback, the DATA FWD-PATH fallback and PROOF-FWD-FALLBACK. 5. Add Transport::is_registered_interface(name), covering interfaces plus local_client_interfaces, since a client's uplink to its shared instance is kept there. A6, B1, B2 and B4 use it. 6. Log one NOTICE line at start: 'Transport enabled' or 'Transport disabled'. A misplaced enable_transport, as happened until 2026-09-21, would stop all transit after A6, so it must be visible at once. 7. A1's counters for these branches go with them. A transit packet with no path logs one DEBUG line.  Staging gate: steps 1 and 15, and the production counters if decision 6 allows. A flow that A1 shows depending on a deleted branch must pass on the branch, or be traced to a Reticulum-post fix. | Reticulum-rust/src/transport.rs:1270-1290, Reticulum-rust/src/transport.rs:5395-5445, Reticulum-rust/src/transport.rs:6064-6100, Reticulum-rust/src/transport.rs:6100-6262, Reticulum-rust/src/transport.rs:6318-6346, Reticulum-rust/src/transport.rs:6380-6450, Reticulum-rust/src/transport.rs:6545-6612, Reticulum-rust/src/transport.rs:10436-10500 | - filter: RNS/Transport.py:1629-1633 - gate: 1997 - inject: 2006-2007 - transported only when addressed to us: 2017-2019 - no-path drop: 2115-2119 - proof transport: 2733-2743  Local-client terms, out of scope: 1938, 1967-1974; RNS/Interfaces/LocalInterface.py:441-442. | - a_non_transport_node_never_forwards_an_overheard_header1_data_packet: no reverse or link entry is created. Fails on e918f86. - a_non_transport_node_never_forwards_an_overheard_linkrequest_for_a_path_on_another_interface: fails on e918f86. - a_non_announce_packet_for_another_transport_instance_is_filtered: rewrites plain_data_passes_filter_with_foreign_transport_id. Fails on e918f86. - a_header1_packet_for_a_remote_destination_is_not_transported_even_on_a_transport_node: fails on e918f86. - a_transited_data_packet_is_sent_once: fails on e918f86. - a_client_of_a_shared_instance_never_transits: mutation-checked. - a_proof_is_transported_only_on_a_transport_node: fails on e918f86. - a_packet_addressed_to_us_is_transported_on_the_path_interface: passes before and after. - startup_logs_whether_transport_is_enabled  A0's transit scenarios are identical to Python. |
| A16 | yes | Link-transport rules as in the reference. This lands after A6.  - A link packet whose link-table entry is not yet validated is dropped, with a log line (2126-2128). Rust sets the flag when it relays the LRPROOF, as the reference does. - After link-table handling the packet is finished, whether or not it was forwarded (2166). Today it falls through to local processing. - LRPROOF relay runs only on a transport node (2612; local-client terms as in A6). - On a transport node, an LRPROOF for a link in the link table is never handed to a local link, even after a hop or interface mismatch. Today rs/transport.rs:6540 hands it over. Any other LRPROOF goes to the local link, as today. | Reticulum-rust/src/transport.rs:6266-6320, Reticulum-rust/src/transport.rs:6470-6545 | RNS/Transport.py: - link transport and return: 2121-2166 - LRPROOF gate and relay: 2612-2666 - local pending link: 2668-2711 | - a_link_packet_before_validation_is_not_forwarded: fails on e918f86. - a_transported_link_packet_is_not_delivered_locally: fails on e918f86. - a_mismatched_link_table_lrproof_is_not_handed_to_a_local_link: fails on e918f86. - a_non_transport_node_does_not_relay_an_lrproof: mutation-checked. - a_validated_link_packet_is_forwarded_once: passes before and after.  A0's pre-validation scenario matches Python. |
| A7 | yes | Two outbound rules that the reference does not have (rs/transport.rs:4015-4061).  Rule 1: when hops > 1 and next_hop == the destination, Rust sends the HEADER_1 packet raw. The reference always inserts transport with the path's next hop. next_hop equals the destination only when an announce arrived as HEADER_1 with hops > 1, and neither reference nodes nor PHP emit that (Reticulum-post/php/src/lib/request_relay_routing_trait.php:105-128).  Rule 2: a HEADER_2 packet on a path with hops > 1, or with hops == 1 behind a shared instance, is sent raw. The reference sends nothing and reports not sent.  Change: copy both reference rules. Rule 2's refusal logs a WARNING, so a caller's bug is not hidden. | Reticulum-rust/src/transport.rs:4015-4061 | RNS/Transport.py:1383-1437: - insertion for hops > 1: 1396-1407 - shared-instance insertion: 1416-1417 - direct send: 1430-1437 | - a_multi_hop_send_always_inserts_the_next_hop: fails on e918f86. - a_header2_packet_on_a_multi_hop_path_is_not_sent: fails on e918f86.  A1's outbound-rule counters must be zero in staging steps 1 and 15, and in production if decision 6 allows. |
| A8 | yes | Save outside the TRANSPORT lock, serialised by a lock of its own.  - New SAVE_PATHS and SAVE_TUNNELS mutexes. save_path_table and save_tunnel_table each:   1. take their own mutex;   2. take TRANSPORT only to copy the table, then release it;   3. serialise and write while still holding their own mutex. - Lock order is SAVE_* before TRANSPORT. No caller holds TRANSPORT when it saves; jobs already drops it (rs/transport.rs:3474-3481). - The savers are: jobs, the iOS and Android save_paths and clone_path_and_identity, ffi::persist_data, and the exit handler. They now run one after the other, so the last file written always holds the newest snapshot, and no two writers share destination_table.tmp. - The comment at rs/transport.rs:3469, which says saving runs without the lock, becomes true. - New examples/path_table_lock_bench.rs builds a table of 13,853 destinations (up to 64 blobs each once B4 is in) and prints how long a save holds TRANSPORT. | Reticulum-rust/src/transport.rs:4633-4740, Reticulum-rust/src/transport.rs:3455-3481, Reticulum-rust/src/ffi.rs:134, Reticulum-rust/examples/path_table_lock_bench.rs (new) | None; this is lock hygiene. The reference's save_path_table (RNS/Transport.py:3788-3875) serialises from its own copy. | - the_path_table_writer_does_not_hold_transport_while_writing: the test takes TRANSPORT after the snapshot, and the write still completes. Completion is observed through a channel whose recv_timeout is only the test-failure mechanism (§7). Fails on e918f86. - two_concurrent_saves_leave_a_file_that_parses_and_holds_the_newer_snapshot: interleaved mutations over many rounds. Mutation-checked by removing SAVE_PATHS. - The same two tests for the tunnel writer. |
| A17 | yes | No caller clones the whole path table any more.  Transport: - TransportSnapshot drops path_table and gains path_table_len. - New accessors, each copying only what it returns while it holds the lock:   - path_table_len();   - interface_snapshots(): name, online, out, bitrate, rx/tx;   - packet_rssi, packet_snr and packet_q(hash), which search the caches in place;   - path_table_rows(max_hops), for the get_path_table RPC;   - drop_all_via(transport_hash), which works in place. - next_hop, next_hop_interface and hops_to copy only their fields.  Callers switched to the new accessors: - the reticulum.rs RPC helpers (rs/reticulum.rs:349-452); - LXMRouter::delivery_packet's three lookups per message (LXMF-rust/src/lxm_router.rs:3688-3700) now clone nothing, with no LXMF-rust change; - rfed's write_status_file, its start-up and 5-minute status, and its heartbeat; - app-links' liveness_candidate_interfaces.  Removing the field makes a stale caller fail to compile, instead of silently reading zero. rfed's CI builds against Reticulum-rust main, so RFed-rust and app-links must merge right after Reticulum-rust (D2). | Reticulum-rust/src/transport.rs:936-966, Reticulum-rust/src/transport.rs:4749-4770, Reticulum-rust/src/reticulum.rs:349-452, RFed-rust/rfed/src/main.rs:199, RFed-rust/rfed/src/main.rs:646, RFed-rust/rfed/src/main.rs:797-807, RFed-rust/rfed/src/main.rs:952-958, app-links/src/lib.rs:2154-2161, Reticulum-rust/examples/path_table_lock_bench.rs | None; this is lock hygiene. The reference reads its tables in place. | - no_snapshot_carries_the_path_table: a source test. - rpc_path_table_and_drop_all_via_match_their_old_output: on a fixture. - The bench records, before and after, how long packet_rssi and a snapshot hold TRANSPORT on the production-shaped table. - cargo test -p rfed and app-links' tests pass. - Staging step 15: flood 6000 against rfed, with blobs present, shows no throughput drop. |
| A9 | yes | The rediscovery path request in jobs goes out ONLY on blocked_if (rs/transport.rs:3863-3869; the third argument is attached_interface, rs/transport.rs:6818-6823). The reference sends it on every interface EXCEPT blocked_if. This is a bug, and the fix copies the reference. | Reticulum-rust/src/transport.rs:3863-3869, Reticulum-rust/src/transport.rs:6818-6823 | RNS/Transport.py:1229-1232 queues the request; 1247-1263 sends it on every interface except blocked_if. | rediscovery_path_request_goes_out_on_every_interface_but_blocked_if: fails on e918f86. |
| A10 | yes | Remove PATH_STALE_THRESHOLD and restore the reference's timestamp rules, still on today's table.  Removed: - the expiry shortening and the stale 'hedge' path requests in outbound (rs/transport.rs:4062-4119); - the constant itself (rs/transport.rs:129-141).  Timestamp refresh on use: - set on both header-insertion sends, for the entry used; - not set on a direct send; - transit refreshes the entry it used, not deque.front().  Path cull: remove an entry when now > timestamp + AP_PATH_TIME, ROAMING_PATH_TIME or DESTINATION_TIMEOUT, chosen by the interface's mode.  This must land before B1. Under reference admission the stale rule would delete working paths, because the answer to its own path request is rejected. | Reticulum-rust/src/transport.rs:129-141, Reticulum-rust/src/transport.rs:3642-3690, Reticulum-rust/src/transport.rs:3925-4119, Reticulum-rust/src/transport.rs:6254-6259 | - timestamp cull: RNS/Transport.py:957-978 - refresh on insertion: 1406, 1426 - no refresh on a direct send: 1430-1437 - transit refresh: 2113 | - sending_never_issues_a_stale_path_request: fails on e918f86. - transport_insertion_refreshes_the_timestamp_of_the_path_used: fails on e918f86. - a_direct_send_does_not_refresh_the_timestamp - transit_refreshes_the_timestamp_of_the_path_it_used: fails on e918f86. - cull_removes_a_path_whose_timestamp_plus_mode_timeout_passed: fails on e918f86. - a_used_path_is_not_culled |
| A11 | yes | Two changes to tunnel synthesis handling.  1. Check the signature. - Today tunnel_synthesize_handler calls handle_tunnel for any packet of the right size (rs/transport.rs:2654-2663, TODO). - Now it loads the public key from the packet and validates the signature over public key + interface hash + random hash, as the reference does. An invalid synthesis is dropped with a log line and changes nothing. - Rust's own syntheses already sign exactly those bytes (rs/transport.rs:1644-1650), and reference peers already check them.  2. Restore only when the tunnel comes back on a different interface. This is a departure. - Rust synthesizes a tunnel every 60 s, on TCP clients, TCP server spawns and Backbone interfaces, as its liveness heartbeat (rs/interfaces/tcp_interface.rs:1395-1418, NEVER REMOVE EVER; rs/interfaces/backbone_interface.rs:1020-1025). The reference synthesizes once per connection. - Restore now runs only when interface_changed (rs/transport.rs:2683) is true. It is also true when the interface was unset after a load. - A same-interface synthesis refreshes only the tunnel's interface binding and expiry.  The heartbeat still reaches reference peers upstream, and each of them restores our tunnel's paths every minute. The PARITY row records that. | Reticulum-rust/src/transport.rs:2634-2718, Reticulum-rust/src/transport.rs:2772-2846, Reticulum-rust/src/identity.rs:324, Reticulum-rust/src/identity.rs:587 | - signature check: RNS/Transport.py:2787-2808 - restore: 2819-2874 - synthesis once per connection: 534-537, 2783; RNS/Interfaces/TCPInterface.py:179, 298 | - a_synthesis_with_a_bad_signature_changes_nothing: fails on e918f86. - a_synthesis_signed_by_another_key_changes_nothing: fails on e918f86. - a_valid_synthesis_is_accepted - a_same_interface_synthesis_restores_nothing: fails on e918f86. - a_reconnect_on_a_new_spawn_restores - a_loaded_tunnel_restores_on_its_first_synthesis - a_same_interface_synthesis_extends_the_tunnel_expiry  B5 adds the gravity and unresponsive cases. |
| A12 | yes | The additive core. Nothing is wired to it yet.  Added: - STATE_UNKNOWN, STATE_UNRESPONSIVE and STATE_RESPONSIVE, and a TransportState.path_states field; - timebase_from_random_blob, timebase_from_random_blobs and announce_emitted; - a RandomBlobs type: Vec<[u8;10]>, serialized as one msgpack bin, with a reader that also accepts the legacy Vec<Vec<u8>>; - random_blobs on PathEntry, marked #[serde(default)]; - a pure function, path_admission(existing, stored_gravity, stored_unresponsive, hops, blob, announce_gravity, now) -> Admission.  Admission has one variant per reference outcome: Unknown, NewerEmission, HigherGravity{from,to}, ExpiredPath, MoreRecentlyEmitted, Unresponsive, or Reject(reason).  The function copies the reference branch for branch: - the hop cap and the missing-blob check come first; - the running-max early break over a prefix of the blob list is copied; - so is the rule for None gravity, and the strict > on gravity. | Reticulum-rust/src/transport.rs:117-127, Reticulum-rust/src/transport.rs:465-497, Reticulum-rust/src/transport.rs:643-675, Reticulum-rust/src/transport.rs:4746-4747 | - states: RNS/Transport.py:148-150, 189 - admission: 2206-2296 - helpers: 3725-3742 - MAX_RANDOM_BLOBS: 162 | A table-driven test with one case per outcome, each mutation-checked by disabling its branch.  Branch A: an unknown destination gives Unknown.  Branch B (hops ≤ stored): - a new blob with a later emission gives NewerEmission; - an older emission is rejected; - the same emission at equal, lower or None gravity is rejected; - the same emission at higher gravity gives HigherGravity.  Branch C (hops > stored): - an expired path with a new blob gives ExpiredPath; with a held blob it is rejected; - a later emission with a new blob gives MoreRecentlyEmitted; with a held blob it is rejected; - the same emission gives Unresponsive only when the path is unresponsive; - an older emission is rejected; - the prefix quirk is copied.  Pre-checks: hops ≥ 129 and an empty blob are both rejected.  RandomBlobs round-trips as bin and still reads the legacy form. |
| A13 | yes | rfed: static propagation peers are refreshed without waiting for a path response.  Why: enable() requests paths for static peers so that the announce handler fires (RFed-rust/rfed/src/lxmf_propagation.rs:560-573). Two things stop that working: - the handler is registered only after enable() (RFed-rust/rfed/src/main.rs:750-753), which breaks §5 ordering; - under reference admission, a cached path response carrying an emission already held is rejected, so the handler never fires.  Change: - register the propagation announce handler before enable(); - in enable(), for each static peer whose app_data is remembered, call handle_propagation_announce(peer, app_data, true), the same code path a path response takes; - then request the peer's path, as today. | RFed-rust/rfed/src/lxmf_propagation.rs:550-575, RFed-rust/rfed/src/main.rs:740-760 | LXMF/LXMRouter.py:633-642 activates static peers with request_path. Its TODO at 638-641 names this same gap. RNS.Identity.recall_app_data is reference API. | - a_static_peer_is_refreshed_from_remembered_app_data_at_enable: fails before. - the_propagation_handler_is_registered_before_static_peer_path_requests: fails before.  Staged in D1 step 14. |
| A14 | yes | Phone FFI: copy the identity even when the clone is refused.  retichat_transport_clone_path_and_identity (iOS) and its JNI twin return before remembering the identity whenever clone_path returns false. B1's guard, which refuses to clone over a session-verified path, would then leave the identity uncopied in one case the Swift and Kotlin callers still reach: hadPath && hadFreshPath && !hadIdentity.  Change: remember the source's public key for the target whenever the target's identity is unknown, whatever clone_path returns. Return 1 when either the path or the identity was seeded. | Retichat-ios/rust/retichat-ffi/src/lib.rs:314-341, Retichat-android/rust/retichat-jni/src/lib.rs:380-396 | None: clone_path is Rust-only. | One unit test in each FFI crate: the target has a verified path but no identity. After the call, the identity is known and the path is unchanged. Fails before.  Staged on iOS in D1 step 18. |
| B1 | yes | The switch. It must land as one unit: any part without the rest leaves a table that loses paths it cannot learn again. It compiles against a VecDeque holding one entry; B6 changes the type. It needs A2, A6, A7, A10, A11 and A12.  Admission (RNS/Transport.py:2206-2296) goes through A12's path_admission: - the stored gravity is the registered stub's gravity, looked up by name, or None if the stub is not registered; the announce gravity comes from the receiving stub, or None; - every rejected copy logs its reason at DEBUG: older emission, same emission at gravity x<=y, or blob already held. Destinations on the announce_log whitelist get NOTICE instead, because the gateway logs at NOTICE; - own destinations never reach the tail.  The tail runs only for an admitted copy, in reference order (2298-2537): 1. retransmit timeout; 2. expires, by the receiving interface's mode; 3. append the blob and cut the list to 64; 4. announce-table insert, on a transport node only and never for a PATH_RESPONSE (moved from rs/transport.rs:5957-5983). The reference's local-client term is out of scope (A6); 5. forward to local clients: unchanged, but now only for admitted copies. pending_local_path_requests stays as today, latent with the rest of local-client routing; 6. answer waiting discovery path requests; 7. cache the announce (moved from 5909); 8. write the single entry; 9. mark_path_unknown_state; 10. record the tunnel with the current blob (B5 records the whole list); 11. interface_announce_handler and the announce handlers (moved from 5607-5640 and 5688-5726). Discovery's stamp check therefore runs only for admitted copies (RNS/Discovery.py:476-477); 12. path_verified_this_session; 13. notify_path_added.  Path states (3229-3259): the three mark functions write only when the destination has a path, and path_is_unresponsive reads the map. The jobs rediscovery marks a path unresponsive instead of deleting routes.  Readers, with no online gate and no expiry check (3126-3164): - has_path means the destination is in the table; - next_hop, next_hop_interface, hops_to and next_hop_interface_locked read the entry; - path requests are answered from entry.packet_hash through the cache, and a cache miss is ignored; - the get_path_table RPC returns one row per destination; - drop_all_via, the PostInterface hop fix and the receipt-timeout hops read the entry.  Outbound (1383-1449): one lookup, the A7 header rules, the A10 timestamp refresh. A known path is never broadcast. A path whose interface is not registered logs a line and reports not sent.  Transit reads the entry and refreshes its timestamp. The arrival-interface exclusion stays, as an explicit check, until B3.  clone_path: - writes the target only if the target has no path, or its path was not verified this session; - takes the source's next_hop, hops, interface and expires, with timestamp now, no blobs and no packet_hash; - copies the verified flag.  Tunnel restore, gated and signature-checked by A11, writes the single entry with the existing 'fewer hops, not expired' rule; B5 brings the timebase rule. Load keeps the front entry of a multi-route file; B4 brings the filters.  Deleted: - admit_route, global_blobs, MAX_GLOBAL_BLOBS and MAX_PATHS_PER_DEST; - select_path, select_path_excluding, select_path_for, select_all_paths and PathEntry::score; - route_eviction_tests; - the NEVER REMOVE EVER dedup-key comment at 5857, which needs your sign-off. | Reticulum-rust/src/transport.rs:117-127, Reticulum-rust/src/transport.rs:465-497, Reticulum-rust/src/transport.rs:643-675, Reticulum-rust/src/transport.rs:1315-1397, Reticulum-rust/src/transport.rs:2207-2253, Reticulum-rust/src/transport.rs:2291-2412, Reticulum-rust/src/transport.rs:2624-2627, Reticulum-rust/src/transport.rs:2772-2846, Reticulum-rust/src/transport.rs:3622-3640, Reticulum-rust/src/transport.rs:3925-4119, Reticulum-rust/src/transport.rs:4441-4458, Reticulum-rust/src/transport.rs:4749-4798, Reticulum-rust/src/transport.rs:4933-5075, Reticulum-rust/src/transport.rs:5163-5200, Reticulum-rust/src/transport.rs:5532-5983, Reticulum-rust/src/transport.rs:6100-6262, Reticulum-rust/src/reticulum.rs:360-412, Reticulum-rust/src/interfaces/post_interface.rs:577-600, Reticulum-rust/src/transport.rs:8066-8286, Reticulum-rust/src/transport.rs:9323-9352, Reticulum-rust/src/transport.rs:10709-10910, Reticulum-rust/src/transport.rs:11963-12033 | RNS/Transport.py: - admission: 2206-2296 - tail: 2298-2537 (expires 2340-2345, blobs 2347-2349, announce table 2351-2396, local clients 2400-2429, discovery 2434-2455, cache 2457, entry 2458-2460, tunnel 2467-2476, handlers 2485-2537) - path states: 3229-3259 - accessors: 3126-3164 - path requests: 3436-3519 - outbound: 1383-1449 - transit: 2017-2119 | Every A12 case runs again through Transport::inbound, with real signed announces and relayed HEADER_2 copies. Each fails on e918f86 wherever the outcome changes.  The 2026-09-25 cases, each run with the Bridge at 200000 and again with the bitrates swapped; the outcome must not change: - looped_copies_after_the_direct_copy_are_rejected: fails on e918f86; - direct_copy_after_looped_copies_keeps_the_first_at_default_gravity: fails on e918f86; - direct_copy_after_looped_copies_moves_to_a_higher_gravity_lan: mutation-checked.  Side effects: - a_rejected_copy_runs_no_handler_no_interface_handler_writes_no_cache_and_is_not_rebroadcast: fails on e918f86; - own_destination_announce_reaches_no_handler: fails on e918f86; - an_older_emission_is_rejected_and_fires_no_handler: fails on e918f86; - admission_resets_path_state_to_unknown - blobs_are_cut_to_the_last_64 - expires_follows_the_receiving_interface_mode: fails on e918f86; - a_repeat_of_the_same_copy_changes_nothing - a_rejection_of_a_whitelisted_destination_logs_at_notice  Readers: - has_path_is_true_for_a_path_on_an_offline_interface: fails on e918f86; - a_path_request_is_answered_from_a_path_on_an_offline_interface: fails on e918f86; - a_path_request_with_no_cached_announce_is_ignored - rpc_path_table_has_one_row_per_destination: fails on e918f86; - a_known_path_is_never_broadcast_even_when_its_interface_is_offline: fails on e918f86; - a_send_on_a_path_whose_interface_is_offline_reports_not_sent: pins Fix 4; - mark_path_unresponsive_keeps_the_path: fails on e918f86.  clone_path: - clone_path_never_replaces_a_session_verified_path - a_cloned_path_is_replaced_by_the_destinations_own_announce - a_clone_of_a_verified_path_is_verified  Rewrites, needing your sign-off where marked NEVER REMOVE EVER: same_announce_over_two_routes_…, inbound_live_announce_replaces_unverified_cached_path_even_when_hops_worse, tunnel_paths_are_recorded_and_restored_on_the_new_interface, and a_route_on_an_unknown_interface_is_never_selected.  Deleted: route_eviction_tests, select_path_excluding_skips_arrival_interface and select_path_prefers_online_interface_over_fresher_offline_path.  A0's admission scenarios, except burst, match Python. |
| B2 | yes | Jobs, and the interface-existence rule. The pending-link handling that used to be here is now A15.  - New Transport::interfaces_configured(), called right after load_system_interfaces (rs/reticulum.rs:893-896). It drops loaded entries whose interface is not registered (is_registered_interface), and arms the vanished-interface cull. A3 must already be in. - Path cull, on top of A10: once armed, it also removes paths whose interface is not registered, and culls path_states whose destination has no path. - Link-table proof-timeout rediscovery (884-955):   - has_path comes from the table and the hops from the entry;   - transport nodes call mark_path_unresponsive, keeping the MODE_BOUNDARY rule;   - non-transport nodes call expire_path;   - blocked_if is one variable per jobs pass, not per entry, as in the reference. - The link table becomes insertion-ordered: indexmap::IndexMap, with removal by shift_remove. The reference's dict keeps insertion order, and the blocked_if quirk depends on it. A new entry goes last; an entry updated in place keeps its place. - Stale-link cull: drop link entries whose next-hop or receiving interface is not registered (880-881). - expire_path also clears the path state. | Reticulum-rust/Cargo.toml, Reticulum-rust/src/reticulum.rs:893-896, Reticulum-rust/src/transport.rs:488, Reticulum-rust/src/transport.rs:3484-3490, Reticulum-rust/src/transport.rs:3530-3690, Reticulum-rust/src/transport.rs:5122-5130 | RNS/Transport.py: - path_states cull: 857-861 - stale links: 880-881 - rediscovery and blocked_if: 688, 884-955 - path cull: 957-978 - expire_path: 3219-3226 - load-time interface filter: 424 | - cull_removes_a_path_on_a_vanished_interface: fails on e918f86. - the_vanished_interface_cull_waits_for_interfaces_configured - interfaces_configured_drops_loaded_paths_on_unregistered_interfaces: fails on e918f86. - a_failed_link_marks_the_path_unresponsive_and_a_longer_same_emission_copy_replaces_it: fails on e918f86. - the_link_table_keeps_insertion_order_across_updates_and_removals: mutation-checked by using swap_remove. - blocked_if_carries_over_to_a_later_link_entry_in_the_same_pass: entries are inserted in a known order. Mutation-checked by resetting blocked_if per entry. - expire_path_removes_the_path_and_its_state - a_link_entry_on_an_unregistered_interface_is_culled  The test guards reset the cull-armed flag. |
| B7 | yes | Remove the pre-admission announce limiter (rs/transport.rs:116, 5446-5468).  Today Rust drops the 11th and later announces for one destination within a second, before admission. The reference admits every copy. It rate-limits only the rebroadcast, and only when announce_rate_target is set (RNS/Transport.py:2302-2330, 2354).  When the first copy wins, the dropped copy can be exactly the one gravity should let win. The gateway hears each emission from five backbones, from rfed over [[LAN]], and over the Bridge.  This lands after B1, so the extra copies are rejected cheaply and run no handler. announce_rate_table is no longer written here; announce_rate_target stays an open row. ANNOUNCE_RATE_LIMIT is deleted. | Reticulum-rust/src/transport.rs:114-116, Reticulum-rust/src/transport.rs:5446-5468 | RNS/Transport.py:2296-2330 (rate limiting after should_add, and only for rebroadcast); 2354. | - a_higher_gravity_copy_after_ten_looped_copies_in_one_second_replaces_the_path: mutation-checked by putting the limiter back. - every_copy_of_an_announce_reaches_admission - A0's burst scenario matches Python. - Staging step 15: flood 6000 shows no throughput drop.  A1's limiter counts, from staging step 1 and from production, show how often the limiter fired. |
| B3 | yes | Remove split-horizon. This needs your sign-off, and A6, A16 and B1 must already be in.  - Transit sends on the path's interface even when it is the arrival interface (2057), with a NOTICE line when it does. The explicit arrival check left in B1 goes, and so does the TRANSIT-DROP split-horizon branch. - Announce rebroadcasts may now leave on the interface the announce arrived on. The rule at rs/transport.rs:4217-4225 goes, together with its false citation.   - The reference builds each rebroadcast as a new packet and sends it on every interface its mode rules allow (RNS/Transport.py:790-807, 1447-1500).   - Each rebroadcast is still held to that interface's announce cap.   - This changes what neighbours hear on shared media, which the rebroadcast bookkeeping (2183-2200, open row) reads. - A path whose interface is not registered is dropped with a log line.  The Rust-only rule that sends no untargeted announce to local client interfaces stays, as part of the local-client scope. | Reticulum-rust/src/transport.rs:4217-4225, Reticulum-rust/src/transport.rs:6100-6262, Reticulum-rust/src/transport.rs:10634-10910 | RNS/Transport.py: - transit interface: 2057 - timestamp refresh: 2113 - no-path drop: 2115-2119 - rebroadcast: 790-807, 1447-1500 | - transit_leaves_on_the_path_interface_even_when_it_is_the_arrival_interface: fails on e918f86. - a_transport_node_rebroadcasts_an_announce_on_its_arrival_interface: fails on e918f86. - a_looped_bridge_copy_never_displaces_the_direct_path: the 2026-08-09 shape. It carries the moved NEVER REMOVE EVER marker. Fails on e918f86. - A6's overhearing tests still pass: the transport gate now stops reflection. - transit_linkrequest_is_not_reflected_back_out_arrival_interface is replaced by the tests above. - A0's transit and arrival-interface announce scenarios match Python. - Staging step 15: flood 6000 shows no throughput drop. |
| B4 | yes | Persistence and migration. The full rules are in `migration`.  Save: - one entry per destination; - transport nodes write the blob list as one bin; non-transport nodes write none; - entries on unregistered interfaces are skipped; - serialised by SAVE_PATHS, outside TRANSPORT (A8).  Load accepts the new file, today's 1-3 route files, and the April SerializedPathEntry list.  Filters are applied per entry, BEFORE a destination's entry is chosen: - the hash is 16 bytes; - the entry's interface is one of the stub names the config will register. Reticulum::start passes that list, derived the same way synthesize_interface names stubs; - on transport nodes, the cached announce exists and unpacks, and the identity is not blackholed; - on non-transport nodes, the cache file exists.  Choice: newest emission, then fewest hops, then latest timestamp.  Seeding: on transport nodes, a chosen entry with no blobs gets its cached announce's blob.  One NOTICE line reports the counts: loaded, migrated from multi-route, and dropped by reason.  New examples/path_table_migration_report.rs takes a storage directory, a cache directory and a config. Writing nothing, it prints each destination's candidates and choice, the drop counts by reason and by configured name, and the paths on shared 'Client on <Backbone listener>' names. | Reticulum-rust/src/transport.rs:1315-1397, Reticulum-rust/src/transport.rs:4633-4700, Reticulum-rust/src/transport.rs:778-795, Reticulum-rust/src/reticulum.rs:893-896, Reticulum-rust/examples/path_table_migration_report.rs (new) | - load: RNS/Transport.py:404-460 (filters at 418-434, no expiry filter) - save: 3788-3875 (active-interface filter at 3829; blob list at 3840) | Load and choice: - loads_a_multi_route_file_choosing_the_newest_emission_then_fewest_hops: fails on e918f86. - the_interface_filter_runs_before_the_choice: mutation-checked. - loads_the_april_serialized_path_entry_file_with_its_blobs  Blobs and filters: - blobs_are_seeded_from_the_cached_announce_on_transport_nodes - load_drops_entries_without_a_cached_announce: fails on e918f86. - a_non_transport_load_checks_the_cache_file_without_unpacking - a_non_transport_node_persists_no_blobs_and_admits_this_sessions_first_copy  Round trip and rollback: - a_saved_table_round_trips_one_entry_per_destination - a_saved_table_loads_in_the_e918f86_shape - save_skips_entries_on_unregistered_interfaces - derived_stub_names_match_registered_names_for_every_interface_type  The migration report runs in CI on a fixture. The A8 bench is re-run with 64 blobs. |
| B5 | yes | Tunnels, completed.  - record_tunnel_path stores a snapshot of the path's full blob list. This is a departure from the reference's shared list object. - Restore uses the reference rule.   - When the destination has a path: restore if tunnel hops ≤ current hops, or the current path has expired, AND the tunnel timebase ≥ the current timebase. Otherwise log why, and drop the tunnel path.   - When there is no path: restore if the tunnel path has not expired.   - The restored entry gets timestamp now, the new interface, and the tunnel's blobs de-duplicated in order. There is no state change, rebroadcast or handler; notify_path_added stays. - Tunnel cull: drop a tunnel path whose active path has a newer timebase. - Every record extends the tunnel's expiry. - save_tunnel_table keeps the last 32 blobs. | Reticulum-rust/src/transport.rs:2666-2771, Reticulum-rust/src/transport.rs:2772-2846, Reticulum-rust/src/transport.rs:3698-3730, Reticulum-rust/src/transport.rs:4657-4738, Reticulum-rust/src/transport.rs:8615-8685 | - record: RNS/Transport.py:2467-2476 - restore: 2819-2874 - tunnel cull: 1040-1057 - save truncation: 3918-3923 - list(set) on restore and load, not reproducible: 2843, 482 | Restore: - tunnel_restore_skips_when_the_existing_path_is_more_recent: fails on e918f86. - tunnel_restore_replaces_an_equal_timebase_path_with_fewer_or_equal_hops - tunnel_restore_after_the_existing_path_expired  Heartbeats, each mutation-checked by removing A11's gate: - a_gravity_replacement_survives_heartbeat_syntheses - an_unresponsive_replacement_survives_heartbeat_syntheses - a_heartbeat_never_overwrites_a_newer_live_path  Record, cull and save: - a_tunnel_records_a_snapshot_of_the_paths_blob_list (named as a departure) - tunnel_cull_drops_paths_older_than_the_active_path - recording_extends_the_tunnel_expiry - tunnel_save_keeps_the_last_32_blobs - announces_recorded_in_a_tunnel_survive_cache_cleaning |
| B8 | yes | Link-proof path rebalance (PARITY B15). With one entry per destination, the stored hops are what admission compares against, so they must follow link proofs as in the reference.  Transit (2612-2634). On a transport node, an LRPROOF qualifies when all of these hold: - its link is in the link table; - its hops differ from the entry's remaining hops; - it arrived on the entry's next-hop interface; - its signature is valid; - the entry is not yet validated. A qualifying proof sets the entry's remaining hops and the destination's path hops to the proof's hops, and logs 'Re-balancing path'. The usual equal-hops check then relays it. Today such a proof is dropped as a hop mismatch, and the link never establishes.  Terminus (2680-2708). When a pending link receives a validly signed LRPROOF whose hops differ from expected_hops, it sets expected_hops and the path's hops to the proof's hops, once per link. A later proof whose hops still differ is not delivered, as in the reference. | Reticulum-rust/src/transport.rs:6470-6545, Reticulum-rust/src/link.rs:2140-2160, Reticulum-rust/src/link.rs:4627-4720 | RNS/Transport.py: - transit rebalance: 2612-2634 - terminus rebalance: 2676-2711 - ALLOW_LINK_PATH_REBALANCE = True: 153 | - a_hop_mismatched_lrproof_with_a_valid_signature_rebalances_and_is_relayed: fails on e918f86. - an_invalid_signature_does_not_rebalance: mutation-checked. - a_validated_link_entry_does_not_rebalance_again - a_link_terminus_rebalances_the_path_once - after_a_rebalance_admission_compares_against_the_new_hops: mutation-checked. |
| B6 | yes | A mechanical type change: - TransportState.path_table becomes HashMap<Vec<u8>, PathEntry>; - .front() and deque access become .get(); - the test helpers are updated; - the doc comments about the multi-entry model are corrected (rs/transport.rs:478-486, 643-646).  PathEntryValue stays for tunnel records. After A17, no sibling crate reads the path table directly. | Reticulum-rust/src/transport.rs:478-486, Reticulum-rust/src/transport.rs:643-675, Reticulum-rust/src/reticulum.rs:360-412, Reticulum-rust/src/interfaces/post_interface.rs:577-600, Reticulum-rust/src/transport.rs:8743-8800 | RNS/Transport.py:180 (one entry per destination) and 4122-4128 (the entry layout). | cargo test -p reticulum_rust is green.  These must all build: - lxmf_rust, rfed, apns-bridge and fcm-bridge; - app-links, retichat-ffi and retichat-jni; - rfed-channel-cli and RNodeProbe's rnode-probe-jni; - test-harnesses/send-strategies and test-harnesses/rfed-notify-test. |
| L1 | yes | Only if you choose decision 8(b). LXMF-rust resolves a dead path before it opens a DIRECT link (§5: path resolution before link establishment).  Reticulum-rust gains two accessors: - Transport::path_interface_online(dest) -> Option<bool>, moved from the iOS FFI; - Transport::any_interface_online().  In the DIRECT no-link branch: - if the path's interface is offline and another interface is online on a non-transport node, the router calls Transport::expire_path and request_path, then takes its existing path-request branch. No delivery attempt is counted and no link is created; - if no interface is online, nothing changes: A5 closes the link at once and the message fails, as today's code does after about 14 s. | LXMF-rust/src/lxm_router.rs:1534-1600, Reticulum-rust/src/transport.rs (new accessors), Retichat-ios/rust/retichat-ffi/src/lib.rs:295-303 | None: this is LXMF-rust's own delivery policy. The Python LXMRouter tolerates the same failure through 5 attempts; LXMF-rust allows 2. | - a_direct_message_whose_path_interface_is_down_waits_for_a_new_path_when_another_interface_is_up: the message is delivered after the path answer. Fails without L1. - a_direct_message_with_no_interface_online_fails_once: attempts are counted as today.  Staging steps 10(ii) and 16. |
| C1 | yes | Documents, comments and rebuilds.  PARITY-AUDIT-1.5.2.md: - B14, A21 and B15 are fixed; B29 is removed; B24 is replaced; - the B32 and B42 notes say the timebase rule is copied, except for aliasing; - the new rows from B43 on, as listed in plan_markdown, including section D for shared-instance local-client routing and the upstream effect of the heartbeat; - every kept departure; - section C: the clock-skew note, and the A0, A1, D1 and bench results.  Other documents: - HOPS.md:263-276 has stale select_path citations; - app-links/src/lib.rs:1123-1134 has a stale comment; - the iOS FFI doc comments: drop_path now removes the path, and path_interface_online can return 0.  announce_log.rs WHITELIST_HEX is checked against rfed's current destinations (rfed.link and rfed's lxmf.propagation included), so D2's NOTICE checks can see them.  Rebuilds: - rfed, checked with rfed --build and check-sibling-drift.sh; - Android: buildRustNdk before assembleDebug; - the iOS xcframework. | Reticulum-rust/PARITY-AUDIT-1.5.2.md, Reticulum-rust/src/announce_log.rs:29-36, HOPS.md:263-276, app-links/src/lib.rs:1123-1134, Retichat-ios/rust/retichat-ffi/src/lib.rs:293-311 | Each row cites the reference lines given in its step. | - app-links' source-text tests still pass. - cargo test -p rfed passes. - The Android .so carries a branch marker string. |
| C2 | yes | OPNsense package: make the template able to generate the live config.  The model, form and template gain: - gravity fields for [[LAN]] and the Bridge; - [[LAN]] as a TCPServerInterface; - mode = gateway on the Bridge, with its bitrate; - the backbone TCPClientInterfaces, as a verbatim 'extra interfaces' text field appended under [interfaces]. The form checks that it parses as interface sections.  The only difference left from the live config is the Generated line. Until this is deployed and its render test passes against the live config, pressing Save in the UI still overwrites the live config and removes every backbone (decision 4). | OPNS-RNS-Post-Bridge/pkg/files/usr/local/opnsense/mvc/app/models/OPNsense/Rnsd/General.php, OPNS-RNS-Post-Bridge/pkg/files/usr/local/opnsense/mvc/app/controllers/OPNsense/Rnsd/forms/general.xml, OPNS-RNS-Post-Bridge/pkg/files/usr/local/opnsense/service/templates/OPNsense/Rnsd/rnsd.conf, OPNS-RNS-Post-Bridge/config/reticulum.conf.example | The per-interface gravity key: RNS/Reticulum.py:798-799. | - Rendered with the live values, the output equals the live /usr/local/etc/reticulum/config apart from the Generated line. This needs the copy requested in decision 7. - Rendered with the model defaults and with gravity set, both outputs load under Reticulum-rust's strict parser (a fixture test in Reticulum-rust). |
| D1 | yes | The staging proof and the interop matrix. The full procedure is in staging_proof.  Builds come from committed revisions (git archive), never from the working tree, and each revision is recorded.  You get these before any deploy: - the step 7 counts; - the step 10 and step 16 timings; - the A1 counts. | test-harnesses/staging/staging.sh, test-harnesses/staging/run/gateway/config, test-harnesses/staging/run/rfed/config, test-harnesses/staging/py/looped_copy_p2.py (new), test-harnesses/staging/py/rpi_link_driver.py (new), test-harnesses/staging/py/tcp_forwarder.py (new), test-harnesses/staging/py/two_backbones.py (new) | The behaviour under test: - admission: RNS/Transport.py:2206-2296 - gravity inheritance: RNS/Interfaces/TCPInterface.py:640 - tunnels: 2787-2874 - transit: 1997-2166 - pending links: 697-731 | The pass criteria are in staging_proof. Every wait is on a log line or an event, and a link is attempted once per triggering event, never in a loop. |
| D2 | no | Rollout. It runs only after D1 passes and decisions 3-9 are made.  1. Push the Reticulum-rust branch, not main.  2. Gateway: - back up destination_table, cache/announces and tunnels; - add the gravity line per decision 3; - run rnsd-redeploy.sh <branch rev> and check the marker string.  Then check the gateway's NOTICE log in the NAS syslog DB: - 'Transport enabled'; - the [[LAN]] registration line with its gravity, and the same value on the spawns; - the migration line; - rfed's whitelisted destinations admitted at 1 hop on 'Client on LAN [192.168.2.23:...]'; - the Bridge's rx/tx on /health in its normal range, and the credential-free /health check.  3. Merge to main and push, under your identity only, in this order: - Reticulum-rust; - app-links (A17); - LXMF-rust, only if L1 is chosen; - RFed-rust (A13 and A17's callers), straight after, because rfed's CI builds against Reticulum-rust main; - Retichat-ios and Retichat-android (A14).  4. rfed: - back up _rns/storage (destination_table and tunnels) and cache/announces from the NAS volume. Every image mounts that volume, so an older image does not undo a migration; - run the migration report on that copy; - trigger the build; you pull; - rfed --build shows the expected shas, and check-sibling-drift.sh is clean.  5. Bridges: rebuild, then you pull.  6. Phones: buildRustNdk, then assembleDebug; the iOS xcframework.  Rollback: - gateway: rnsd-redeploy.sh --rollback, plus its three backed-up files; - rfed: the previous image, plus its backed-up files. | OPNS-RNS-Post-Bridge/rnsd-redeploy.sh, RFed-rust/.github/workflows/build-rfed.yml | None. | - The gateway checks in step 2, all at NOTICE. - rfed and the bridges: rfed --build shows the expected shas, and check-sibling-drift.sh is clean. - After the rollout, the phones reach rfed with no FAILED message caused by a stale path, over one day of use. |

---

## Departures kept

- Fix 4 (rs/transport.rs:4340-4370, NEVER REMOVE EVER). Transport::outbound reports not sent when the transmission's interface is offline. The reference reports the packet sent, and an offline TCP client then drops it silently (RNS/Transport.py:1432-1437; RNS/Interfaces/TCPInterface.py:313-314). Reason: copying the reference would show the user a false outcome. With the online gate gone from path selection, this is where an offline interface is noticed on a known path. A known path whose interface is not registered also reports not sent, and is never broadcast.
- A link request that no interface took closes at once (A5). Link::initiate_send reads packet.sent and tears the link down with the Rust-only reason REASON_NOT_SENT. initiate() still returns Ok, and link_closed fires once. The reference ignores the send result and waits for the establishment timeout (RNS/Link.py:318-323, 712-735). Reason: false outcome. Otherwise a link would show as 'establishing' when its request never left.
- The path is kept after NOT_SENT when no interface is online (A15). The reference would expire it after the establishment timeout (RNS/Transport.py:697-712), but a path request could not go out then either. With another interface online, Rust expires the path and asks again, as the reference does, only sooner. Reason: false outcome. Expiring would say the path is bad when it was never tried. It would also wipe the persisted path on a phone whose TCP connection is still reconnecting after a thaw.
- expire_path removes the entry at once, and clears its path state (rs/transport.rs:5122-5130). The reference sets TIMESTAMP = 0, and the next jobs pass culls it (RNS/Transport.py:3219-3226). Reason: architecture. Rust callers wait on the PATH_ADDED_NOTIFY event instead of polling. After a soft expire, wait_for_path's fast path would return the stale entry.
- Non-transport nodes persist and load the path table (rs/transport.rs:3455-3481, NEVER REMOVE EVER). The reference loads it only with transport enabled (RNS/Transport.py:404). Reason: architecture. Phones are killed without an exit handler, and a cold-start path request used to dominate launch time. The departure is bounded: these nodes persist no blobs, load checks only that the cached announce file exists, and the first copy heard each session is admitted.
- clone_path (rs/transport.rs:4778-4798) has no reference equivalent. Reason: architecture. It seeds sibling destinations through the FFI. It is constrained: it never overwrites a path verified this session, and it writes no blobs and no packet_hash, so a clone never answers a path request and is never persisted. It copies the verified flag, because a clone of a session-verified sibling on the same node is what the call is for. The destination's own announce always replaces a clone.
- path_verified_this_session, wait_for_path, wait_for_path_verified_this_session and PATH_ADDED_NOTIFY are Rust-only (rs/transport.rs:834-855, 4800-4929). Reason: architecture. They are the event-driven readiness signals that §5 and §7 require; the reference's await_path polls. They are set or fired only on admission and on tunnel restore.
- Tunnel synthesis heartbeat (A11). Rust synthesizes a tunnel every 60 s on TCP and Backbone interfaces as its liveness heartbeat (rs/interfaces/tcp_interface.rs:1395-1418, NEVER REMOVE EVER); the reference synthesizes once per connection (RNS/Transport.py:534-537). Rust therefore restores paths only when the tunnel's interface changed, or was unset after a load. Reason: architecture; restoring every minute would undo gravity and unresponsive replacements. Effect on other nodes: every reference backbone we connect to runs handle_tunnel on each heartbeat and restores our tunnel's recorded paths every minute (RNS/Transport.py:2819-2874). For destinations it learned through us, that can undo its own gravity and unresponsive replacements. Syntheses are now signature-checked on receipt, as in the reference.
- Tunnel path blob lists are snapshots (B5). In the reference, the tunnel record and the path entry share one Python list (RNS/Transport.py:2228, 2347-2349, 2473), so later admissions also move the tunnel path's timebase. Rust tables hold values. The difference: after a newer emission lands on another interface, Rust culls and refuses the older tunnel path, where the reference could still restore it. Reason: architecture.
- Order of the blob list after a tunnel restore or a load. The reference rebuilds it with list(set(...)) (RNS/Transport.py:2843, 482), whose order depends on Python's hash seed and cannot be reproduced. Rust de-duplicates and keeps the order. The early-break prefix quirk (2260-2263) IS copied, and so is the per-pass blocked_if quirk, over an insertion-ordered link table (B2).
- The stored path's gravity is read live from the registered stub, by interface name. If the interface is no longer registered, its gravity counts as None (RNS/Transport.py:2246). The reference keeps reading the detached interface object until the cull removes the path, within about 5 s (975-978). Reason: architecture; Rust keeps interfaces as named stubs.
- destination_table format. Rust writes named msgpack maps, identifies the interface by name, stores the blobs as one bin, and keeps the outer Vec<(dest, Vec<PathEntry>)> shape, so e918f86 can still read the file after a rollback. The reference writes positional umsgpack lists with the interface hash (RNS/Transport.py:3844-3862). Parity is in behaviour, not bytes, and Rust and Python never share a storage directory.
- Load-time interface filter by configured names (B4). Rust starts Transport before its interfaces (rs/reticulum.rs:893-896), and §5 requires state to be restored before anything reads it. So it filters loaded entries by the stub names the config will register. interfaces_configured() then drops entries whose interface failed to register, and arms the vanished-interface cull. The reference loads after its interfaces exist (RNS/Transport.py:424). Reason: architecture. Paths on interfaces registered later through the FFI (the phones' BLE and RNode) are not loaded, and a reference client would load none either.
- Shared-instance local-client routing is absent, recorded as out of scope (PARITY section D). Rust puts a program's uplink to its shared instance in local_client_interfaces (rs/reticulum.rs:1234, 1284). It never registers its LocalServerInterface spawns (rs/interfaces/local_interface.rs:557-600), and it never applies the local-client hop decrement (RNS/Transport.py:1938). Consequences: - transit, proof transport, LRPROOF relay and the announce-table insert are gated on transport_enabled alone; - the hops-0 local-client inject is absent; - pending_local_path_requests is latent; - the Rust-only rule that sends no untargeted announce to local client interfaces stays. Reason: architecture. No production node shares an instance.
- Diagnostic log lines, with no behaviour change: - a DEBUG line with the reason for each rejected announce copy, at NOTICE for whitelisted destinations; - a NOTICE line when a transit packet leaves on its arrival interface; - a DEBUG line for a transit packet with no path; - a WARNING when outbound refuses a HEADER_2 packet; - the NOTICE 'Transport enabled' line. A1's counters are temporary and go with their branches. Reason: a silent drop hides the next one.
- hops_to still returns LINK_UNKNOWN_HOP_COUNT = 4 for an unknown destination (rs/transport.rs:36-40), where the reference returns PATHFINDER_M. This departure already existed, and it is unchanged and out of scope: changing it would change link and receipt timeouts as a side effect, which §4 forbids.
- Migration choice for legacy multi-route files: filter first, then pick the newest emission, then the fewest hops, then the latest timestamp. It runs once, and the reference never had such files.

---

## Migration

File and shape
- storage/destination_table keeps its name and its outer msgpack shape, Vec<(dest_hash, Vec<PathEntry>)>, written with rmp_serde to_vec_named (rs/transport.rs:4633-4655). Each destination gets exactly one PathEntry.
- PathEntry gains random_blobs, marked #[serde(default)] and written as one msgpack bin of 10-byte blobs (A12).
  - Transport nodes write the whole list they hold, up to 64, as RNS/Transport.py:3840 does.
  - Non-transport nodes write no blobs.
- Rollback: e918f86 reads the new file as one-route deques, because serde skips the unknown key. A test deserializes the new file into a verbatim copy of e918f86's PathEntry.

What load accepts (Transport::start, rs/transport.rs:1315-1397)
- the new file;
- today's files with 1-3 routes per destination;
- the April SerializedPathEntry list (for example ~/.rfed/_rns/storage). It carries real blobs, and its interface_hash bytes are read as the interface name, as today.

Filters, applied per entry BEFORE one entry is chosen per destination (RNS/Transport.py:418-434)
- The destination hash is 16 bytes.
- The entry's interface is one of the stub names the config will register.
  - The reference instead requires the interface to exist at load (424); Rust loads before its interfaces start.
  - interfaces_configured() (B2) later drops entries whose configured interface failed to register.
  - A3 keeps a BackboneClient whose first connect failed registered.
- Transport nodes: cache/announces/<packet_hash> exists and unpacks, and the identity is not blackholed.
- Non-transport nodes: the cache file exists. It is not unpacked, to keep cold start fast.
- There is no expiry filter, as in the reference. The timestamp cull removes old entries.

Which entry wins
1. The newest emission, read from the cached announce's blob (3725-3742).
2. Then the fewest hops. Rust never recorded arrival order; normally the direct copy came first.
3. Then the latest timestamp.

Blobs
- On transport nodes, a chosen entry with no blobs gets its cached announce's blob. Looped copies of that emission are then rejected after the upgrade (2292-2296).
- Non-transport nodes keep no blobs. The first copy heard each session is admitted.
- path_states are not persisted, as in the reference.

Save
- One entry per destination. Entries on unregistered interfaces are skipped (3829).
- The table is copied under TRANSPORT and serialized and written outside it, serialized by SAVE_PATHS (A8).

Tunnels
- The storage/tunnels format is unchanged. Old tunnel paths hold one blob.
- New saves keep the last 32 blobs (3918-3923). Blobs are de-duplicated in order on load.

Logging: one NOTICE line at start, with the counts loaded, migrated from multi-route, and dropped by reason.

Production gateway copy (gwcache/, 2026-09-25 16:13)
The live config has never been read. These numbers assume the six configured names that appear in the table: zer0bitz IPv46, Arborisis Belgium, Air Barcelona, rns.sofia, Auckland RNS and PostInterface Bridge.
- 13,853 destinations and 39,963 routes: 12,683 destinations with 3 routes, 744 with 2 and 426 with 1. 2,220 destinations hold routes from different emissions, and one route has no cached announce.
- 13,814 destinations load: zer0bitz 5,444, Arborisis 4,181, Air Barcelona 3,814, rns.sofia 191, Auckland 149, Bridge 35.
- 39 destinations have routes only on old 'Client on LAN [...]' spawns and load none.
- 38 destinations are 1 hop away via the LAN. 35 load no path and 3 load a backbone detour (3, 8 and 9 hops). Tunnel restore or rfed's up-edge announce returns them when rfed reconnects (staging step 8).
- Choosing before filtering would have left 250 destinations with no path, although each had a backbone route.
- If a configured name differs from the table, for example a backbone that was renamed or removed, its destinations load no path and are learned again. The report shows the count per name.

Operator steps
- Before each deploy, run examples/path_table_migration_report.rs against a copy of that node's storage, cache/announces and live config: the gateway and the NAS rfed (both copies are requested in decision 7).
- Back up destination_table, cache/announces and tunnels together, on the gateway and on rfed's NAS volume.
  - The branch's cache cleaning deletes the announces of discarded routes, and a rollback to e918f86 needs them.
  - Every rfed image mounts the same volume, so starting the old image does not undo a migration; the backup does.

---

## Staging proof

This runs on the private chain only: local rfed → RPi rnsd ← local gateway rnsd → PostInterface → local PHP, with STAGING_PHP=local.
- Every wait is on a log line or an event, never a sleep.
- A link is attempted once per triggering event, never in a loop.
- Builds come from committed revisions: git archives of the branch tip and of e918f86, each recorded. The RPi builds from the same archives.

0. Preconditions
- RPi: `ss -tn state established "( sport = :4242 )"` shows only the Mac, and `pgrep -u claude -x rnsd` shows only the intended instances.
- The gateway's node_url is http://127.0.0.1:8080. No staging config targets the production gateway.
- The staging gateway config copies production:
  - [[LAN]] is a TCPServerInterface on 127.0.0.1 at a free port, so its spawns are named 'Client on LAN [..]';
  - [[PostInterface Bridge]] has mode = gateway and bitrate = 200000;
  - [[Staging backbone]] is a TCP client to the RPi's Rust rnsd on 4242;
  - [[Staging Backbone Listener]] is a BackboneInterface, used only in step 12;
  - the gateway logs at DEBUG.
- A second RPi instance on port 4243 runs the venv's RNS 1.5.2 rnsd, the reference. rfed connects to it from the start; the gateway connects to it only in step 10.
- rfed has three TCP clients:
  - to [[LAN]], through a driver-controlled TCP forwarder (used in step 8);
  - to 4242;
  - to 4243.
  It has one static propagation peer: a reference lxmd on the chain.
- The drivers run on the venv's RNS 1.5.2. P2 is a second PostInterface peer of the local PHP (distro-pipeline/postinterface_loader.py) that posts one batch and then disconnects.
- The looped-copy recipe:
  1. P2 posts a destination's announce as a relayed HEADER_2 copy, with a foreign transport id and hops 3, and disconnects once PHP has taken the batch.
  2. PHP relays the copy to the gateway over the Bridge.
  3. Before any link is opened, assert from PHP's SQLite path_entries that its row for the destination names P2's interface, which is now offline. PHP then routes nothing for that destination back into the gateway, so the verdict is the gateway's alone.
- The verdict for a link through the gateway is:
  - the gateway's link-table next-hop interface for that link id;
  - and whether the destination received the LINKREQUEST.
  These links are opened by a driver on the RPi, not from the PHP side. On e918f86, select_path_excluding never sends a link that arrived over the Bridge back over it.

1. Baseline on e918f86+A1
- Run staging.sh up and check, stage_browser.mjs, stage_large.mjs, distro stages 3-7, and py/flood.py 6000 (about 330 msg/s on 2026-09-22).
- Record the A1 counters per key over the whole run. A non-zero branch names a flow that A6, A7, A16, B3 or B7 would change; trace it before that step lands.
- If decision 6 allows, run the same build on the production gateway for a day and read the counters from the summary lines in the NAS syslog.

2. The incident on e918f86 (fails-before)
- Driver D connects only to [[LAN]].
- Apply the looped-copy recipe to D's announce. Wait for the gateway to log D on PostInterface Bridge.
- D writes the same announce on its [[LAN]] connection.
- A driver on the RPi opens one link to D.
- Expected on e918f86: the next hop is PostInterface Bridge, because 200000 bps outscores the LAN route. D never receives the request, and the link fails. Record the lines.

3. Migration dry run
- Run examples/path_table_migration_report.rs on the production gateway copy (with the live config once you provide it), on the staging gateway, and on the NAS rfed copy.
- Review the counts by reason and by configured name, and the multi-route choices.

4. Install the branch
- Install on the Mac (gateway and rfed) and on the RPi 4242 instance. Keep the e918f86 binaries beside them.

5. Normal order, on the branch
- D's LAN copy arrives first, then the looped copy. Pass:
  - one 'Loaded ...' line with the migration counts;
  - one 'is now N hops away' line per destination;
  - the looped copy is logged as rejected, with its reason, and never as 'Replacing';
  - get_path_table returns one row per destination;
  - rfed's lxmf.propagation is at 1 hop via 'Client on LAN [..]';
  - a link from the RPi driver to D leaves on the LAN spawn and is established.

6. The detour at gravity 0, on the branch
- Repeat step 2 with a fresh D. Pass:
  - the path stays on the Bridge;
  - the LAN copy is logged 'same emission, gravity 0 <= 0';
  - the RPi driver's link leaves on the Bridge. This is the reference detour.
- D emits again, LAN copy first. Pass:
  - the path is on the LAN spawn;
  - one link attempt after that admission event is established.

7. Gravity 1 on [[LAN]]
- Restart the gateway with gravity = 1 and repeat step 2 with a fresh D. Pass:
  - the gateway logs 'Replacing ... due to higher gravity (0->1)';
  - the spawn's registration line shows gravity 1;
  - the RPi driver's link leaves on the LAN spawn and is established;
  - stage_browser's propagation link goes out on the LAN spawn.
- Relayed destinations:
  - driver R posts one emission to 4242 as a relayed copy carrying one extra hop, and waits for the gateway to admit it via Staging backbone;
  - R then posts the plain copy to 4243. It reaches the gateway through rfed with the same hop count;
  - record R's path at gravity 0 (it should stay on the backbone) and at gravity 1 (it should move to rfed).
- Count the gateway's paths on LAN spawns whose next hop is rfed's transport id with hops > 1, at gravity 0 and at gravity 1. The production estimate is 413 of 13,853.

8. Gateway restart. Run all of this at gravity 0 and again at gravity 1.
(a) Tunnel restore alone:
- rfed keeps running. The driver closes the forwarder that carries rfed's [[LAN]] connection.
- SIGTERM the gateway and start it again.
- Apply the looped-copy recipe to rfed's lxmf.propagation announce, captured from rfed's 4242 connection. Wait until the gateway logs it on the Bridge.
- The driver then opens the forwarder. Pass:
  - 'Restored path to <rfed> ... on Client on LAN [..]' from handle_tunnel;
  - no new rfed emission is admitted. rfed's up-edge announce is held off, because it announced on that interface less than 6 h ago;
  - a stage_browser link to rfed succeeds once the gateway answers PHP's path request.
(b) rfed restarts too:
- Stop rfed, restart the gateway, apply the recipe, then start rfed.
- Pass: rfed's path returns to the LAN spawn. Record which mechanism did it: tunnel restore on the first synthesis, or rfed's start announce as a new emission.

9. Tunnels, heartbeats and signatures
- SIGTERM rfed and start it again. Pass: 'Tunnel ... reappeared ... restored N path(s)' on the new spawn name.
- Make two replacements on the gateway:
  - a gravity replacement;
  - a C3 replacement: a failed link through the gateway marks the path unresponsive, and a longer copy of the same emission replaces it.
- Wait for three heartbeat syntheses on that tunnel: '[HEARTBEAT] ... synthesize_tunnel' on rfed and the tunnel refresh line on the gateway. Pass: neither replacement is undone.
- A driver sends a synthesis carrying rfed's public key and a bad signature, on a new [[LAN]] connection. Pass: it is logged as invalid, and no path moves.

10. Two backbones, one goes down
- A is 4242 (Rust) and B is 4243 (reference). The gateway, a non-transport Rust probe and driver D2 connect to both.
- D2's first copy reaches everyone via A. Then stop A.
(i) Transit:
- A PHP-side link to D2 (probe_link.mjs; PHP's path to D2 is via the gateway) is attempted once at each of three events: A stops; the gateway sees A's reconnect up-edge; the gateway admits D2's next emission.
- Record the outcome and the time between events, on e918f86 and on the branch.
- On the branch, the attempt after A stops fails silently for the web client, through an establishment timeout, as in the reference.
- If you choose decision 5(c), repeat on a build with it.
(ii) The probe, with another interface up. After A stops, the probe opens one link. Pass, in order:
- link_closed fires at once with NOT_SENT;
- the next jobs pass expires the path and sends a path request;
- the answer via B is admitted;
- one link attempt after that admission event is established.
Record the time from NOT_SENT to admission. With L1, the same flow happens without a failed message.
(iii) The probe, with no interface up:
- Stop B too, and attempt one link. Pass: NOT_SENT, and has_path is still true.
- Start A. The next attempt, after A's up-edge, uses the kept path with no path request.
These numbers go to you before any deploy (decision 5).

11. Offline interface on the gateway
- With A still down, the gateway sends to a destination whose path is via A. Pass: not sent (Fix 4), nothing broadcast, and has_path still true.
- Start A. Pass: the same path carries traffic again with no new announce.

12. Backbone listener (A4)
- Two drivers connect to [[Staging Backbone Listener]]. Pass:
  - each gets a distinct name, 'Client on Staging Backbone Listener [addr]';
  - each receives only its own traffic;
  - when one disconnects, the other keeps its writer and its paths.

13. Persistence and rollback
- SIGTERM the gateway and decode destination_table. Pass: one entry per destination, with its blobs stored as a bin.
- Start e918f86 on a copy of the file, with cache/announces and tunnels. Pass: it loads.
- Start the branch again. Pass: the same destinations return, and spawn paths return through tunnel restore.

14. rfed static peer
- Restart rfed with persisted blobs. Pass: rfed refreshes the static peer from remembered app_data at enable, and a log line shows it, before any new emission.

15. Regression suites on the branch
- staging.sh check, stage_browser, stage_large, distro stages 3-7, and flood 6000 against rfed with blobs present. Pass: no throughput drop against step 1.
- The A1 counters are gone with their branches, and every bridge flow passes.

16. Android (mandatory)
- Run buildRustNdk, then assembleDebug. The .so carries a branch marker string. Unlock the phone and keep its screen on.
- Cold start: measure the time from start to the first admitted path for rfed.delivery, on e918f86 and on the branch, by log events.
- Offline send:
  - switch the phone's network off, and wait for the down-edge log line of its TCP interface;
  - send one DIRECT message. Pass: link_closed with NOT_SENT at once, and the path is kept;
  - record the time to FAILED on e918f86 (about 14 s expected) and on the branch.
- Dead destination:
  - with the phone online and rfed stopped, send one DIRECT message. Pass: the link closes at its establishment timeout, and the next jobs pass expires the path and requests it;
  - start rfed. Pass: the answer is admitted, and the next message is delivered.
- With L1: with the phone on two backbones and its path's backbone stopped, one DIRECT message is delivered via the other one, with no FAILED.

17. Lock hold
- Run examples/path_table_lock_bench.rs on a production-shaped fixture (13,853 destinations, up to 64 blobs each), on e918f86 and on the branch.
- Record how long a save, a snapshot and a packet_rssi lookup each hold TRANSPORT.

18. iOS simulator on the chain
- Build the xcframework from the branch.
- Pass: a cold start with persisted paths reaches rfed without a path request.
- Pass: clone_path_and_identity from rfed.node to rfed.notify seeds the identity even when the clone is refused (A14).

Interop matrix
- tests/interop/run.sh: 16/16 on e918f86 and on the branch.
- A0's cell: identical to Python on the branch in every scenario. The e918f86 differences are recorded.
- All results go into PARITY-AUDIT section C.

---

## Open findings from the final critique (not yet resolved in the plan)

- **[major, parity]** departures_kept item 8 (tunnel synthesis heartbeat), A11, decision 5; rs/interfaces/tcp_interface.rs:1392-1418 (and the server-spawn heartbeat at 1438-1474), rs/interfaces/backbone_interface.rs:1020-1025: The departure is kept on wider terms than its reason supports. The code's own doc comment gives three purposes for the 60 s heartbeat. Two of them, NAT keepalive and half-open detection through a write error, only need some periodic outbound packet. The purpose that needs a synthesis in particular is (2), 'upstream tunnel-binding refresh'. That is the per-minute handle_tunnel restore which A11 removes on our side because it 'would undo gravity and unresponsive replacements'. After A11 no Rust peer restores on a heartbeat either, so the only thing the synthesis still does is act on reference peers. Every reference node that gets our synthesis runs the 'reappeared' branch every minute (RNS/Transport.py:2830-2869). That branch rewrites the path entries recorded in our tunnel with timestamp=now, so those paths never cull while we stay connected. It rebuilds their blob lists with list(set()) (2843), which reorders them under the branch-C prefix break (2260-2263). It can also undo the peer's own gravity and unresponsive choices. The reference synthesizes once per connection (TCPInterface.py:179, 298; BackboneInterface.py:918, 1016). The departure text also names only one direction ('reference backbones we connect to'). Rust TCP server spawns synthesize too, so reference clients that dial the gateway's [[LAN]] or rfed get the same per-minute restores. *Proposed fix:* Add a decision for James, since the heartbeat is marked NEVER REMOVE EVER. The proposal: synthesize only on connect and reconnect, as the reference does. Make the 60 s liveness packet one that has no routing effect on the peer, for example a PLAIN HEADER_1 DATA packet to an rnstransport aspect nobody registers. The reference passes that packet through the filter (hops<=1) and drops it with no local destination. This keeps purposes 1 and 3 and ends the remote restores. Keep A11's interface_changed gate as a defence. If James keeps the synthesis payload, the PARITY row and departures_kept must name both directions and the effects on timestamps and blob order, and must say that purpose 2 is the effect A11 calls harmful.
- **[major, blast-radius]** B1 readers (has_path / next_hop_interface lose the online gate); 'Other effects: Phones'; departures_kept (Fix 4): At e918f86, has_path, path_hops and next_hop_interface go through select_path, and select_path skips paths whose interface is offline (rs/transport.rs:4976, 5062-5066, 4765-4770). B1 drops that gate, but the plan never lists the external readers that treat has_path as 'reachable now'. Three of them change what the user sees or what the app requests. (1) iOS ConnectionStateManager.swift:608-613, 626-631 and 671-676 compute the rfed status as has_path AND path_verified_this_session. The verified flag lasts the whole session. (2) Android ConnectionStateManager.kt:622-633 (rfedNodeLinkStatusRuntime) returns ACTIVE whenever transportHasPath. (3) Both apps' requestEssentialPaths skip the path request when has_path is true (Android ConnectionStateManager.kt:732-793; iOS ConnectionStateManager.swift:794-843). So after B1, with the phone's TCP interface down, the rfed indicator shows reachable (green), and reconnect logic stops re-requesting essential paths that are pinned to a dead backbone. This is a false outcome shown to the user. The memory rule 'parity never outranks the truth to the user' covers exactly this case. Fix 4 covers local sends only. Across the sibling Rust crates there are 23 has_path callers, plus the Swift and Kotlin ones, and none are inventoried. *Proposed fix:* Make L1's path_interface_online part of Reticulum-rust unconditionally, not only under decision 8(b). Add Transport::path_is_usable(dest): the entry exists, and its interface is registered and online. Switch the phone status and essential-path callers (the files and lines above) to it through the FFI and JNI. List every has_path, next_hop_interface and hops_to caller in the sibling crates with the semantics each one needs. Add unit tests showing the status is false while the path's interface is offline. Add a staging check in steps 16 and 18: network off, indicator not green, and essential paths re-requested on reconnect. Record it in PARITY as a UI-layer truth departure.
- **[major, blast-radius]** D2 steps 2-4 versus D1 step 4; B3; A11: D2 puts the gateway on the branch while rfed, the bridges and the phones stay on e918f86 until the gateway is verified, which can take days. D1 installs the branch on the gateway, rfed and the RPi together (step 4), so the configuration production runs first is never staged. One concrete interaction: after B3, the gateway rebroadcasts each announce it admits from rfed back out rfed's LAN spawn. e918f86 rfed admits every valid copy with no quality gate (rs/transport.rs:5532-5580, admit_route at 5885). It also re-inserts every admitted copy into its announce table (5957-5983). Its split-horizon skips only the LAN client. So rfed re-rebroadcasts each echoed copy, at hops+2, to all its internet backbones for as long as the window lasts. Other mixed-version paths are unproven too: A11 signature checks on e918f86 rfed's syntheses, and tunnel restore from e918f86's tunnels file after the gateway migration. *Proposed fix:* Add a D1 step that runs the gateway on the branch against rfed and the RPi on e918f86, repeating steps 5, 8, 9 and 15 there, and record rfed's announce egress per interface. Alternatively, keep B3 out of the first gateway deploy: it is separable once A6, A16 and B1 are in. Enable it only after rfed runs the branch, and say so in D2.
- **[major, blast-radius]** staging_proof step 0 and step 8(a); critique_resolution for round-1 blast-radius item 2(c) and the step-8 item: The staging rfed config has announce_interval_minutes = 1 (test-harnesses/staging/run/rfed/config). Production has 360 (rfed-nas.config). Step 8(a) passes only if 'no new rfed emission is admitted', on the grounds that rfed's up-edge announce is held off because it announced less than 6 h ago. With a one-minute interval, rfed emits a new announce every minute, so the step cannot tell a tunnel restore from a new emission, and the detour never lasts long enough to show its production duration. That was round-1 finding 2(c). The round-2 resolution claims it is fixed, but step 0 never changes the interval, so it is still open. *Proposed fix:* In step 0, set announce_interval_minutes = 360 in the staging rfed config, and list that file as changed in D1. In step 8(a), also assert that rfed logged no own-announce between the looped copy's admission and the 'Restored path' line. Report the detour's duration at the production interval.

Minor findings: 22 (in the session record).
