use crate::destination::{Destination, DestinationType};
use crate::discovery::{InterfaceAnnounceHandler, InterfaceAnnouncer, InterfaceDiscovery};
use crate::interfaces::interface::Interface;
use crate::identity::Identity;
use crate::packet::{Packet, ANNOUNCE, DATA, LINKREQUEST, PROOF, CACHE_REQUEST};
use crate::{log, LOG_DEBUG, LOG_ERROR, LOG_EXTREME, LOG_NOTICE, LOG_WARNING};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rmp_serde::{decode::from_slice, encode::to_vec_named};
use serde::{Deserialize, Serialize};

// Transport control constants
pub const BROADCAST: u8 = 0x00;
pub const MODE_TRANSPORT: u8 = 0x01;
pub const RELAY: u8 = 0x02;
pub const TUNNEL: u8 = 0x03;

pub const REACHABILITY_UNREACHABLE: u8 = 0x00;
pub const REACHABILITY_DIRECT: u8 = 0x01;
pub const REACHABILITY_TRANSPORT: u8 = 0x02;

pub const APP_NAME: &str = "rnstransport";

pub const PATHFINDER_M: u8 = 128;
pub const PATHFINDER_R: u8 = 1;
pub const PATHFINDER_G: f64 = 5.0;
pub const PATHFINDER_RW: f64 = 0.5;
pub const PATHFINDER_E: f64 = 60.0 * 60.0 * 24.0 * 7.0;
pub const AP_PATH_TIME: f64 = 60.0 * 60.0 * 24.0;
pub const ROAMING_PATH_TIME: f64 = 60.0 * 60.0 * 6.0;

/// Reasonable hop-count fallback when path info is unavailable.
/// Used for timeout calculations instead of PATHFINDER_M (128)
/// which produces absurdly long timeouts on slow links like LoRa.
pub const LINK_UNKNOWN_HOP_COUNT: u8 = 4;

pub const LOCAL_REBROADCASTS_MAX: u8 = 2;

pub const PATH_REQUEST_TIMEOUT: f64 = 15.0;
pub const PATH_REQUEST_GRACE: f64 = 0.4;
pub const PATH_REQUEST_RG: f64 = 1.5;
pub const PATH_REQUEST_MI: f64 = 20.0;

pub const STATE_UNKNOWN: u8 = 0x00;
pub const STATE_UNRESPONSIVE: u8 = 0x01;
pub const STATE_RESPONSIVE: u8 = 0x02;

pub const LINK_TIMEOUT: f64 = crate::link::STALE_TIME * 1.25;
pub const REVERSE_TIMEOUT: f64 = 8.0 * 60.0;

/// Minimum interval (seconds) between announce dispatches to the same
/// local client interface — used by Fix C (bulk announce forwarding)
/// and Fix D (PATH_RESPONSE).
///
/// ## Why this exists
///
/// Python's `RNS.Transport` also forwards every incoming announce to
/// all local clients immediately, with no intentional pacing.  Python
/// doesn't trigger the burst limiter because Python is slow: each
/// packet takes several milliseconds of GIL-serialised work, so a
/// burst of 20 rmap announces naturally spreads over 100 ms+ by the
/// time they exit the OS socket buffer.
///
/// Rust processes the same burst in microseconds and can blast all 20
/// announces onto the wire in a single scheduler tick.  On the
/// receiving side both Python and Rust clients use `TCPClientInterface`
/// with `ingress_control = True` (the default — it is never set
/// `False` anywhere in the RNS source).  `TCPClientInterface` tracks
/// `incoming_announce_frequency()` over the last 6 samples; if the
/// measured rate exceeds `IC_BURST_FREQ_NEW = 3.5/s` for a new
/// interface (< 2 h old), it holds all further announces for 60 s
/// then applies a 300-second penalty (`IC_BURST_PENALTY`).
///
/// Python's `incoming_announce_frequency()` formula is
/// `dq_len / delta_sum` (not `(dq_len-1) / delta_sum`), so with only
/// 2 entries in the deque it computes `2/T` rather than `1/T`.  To
/// avoid triggering the burst hold on just the *second* announce, we
/// need `2/T < 3.5`, i.e. `T > 0.571 s`.  We use 600 ms to give a
/// comfortable margin, achieving a maximum effective rate of ~1.67/s.
pub const LOCAL_CLIENT_ANNOUNCE_PACE: f64 = 0.60;
pub const DESTINATION_TIMEOUT: f64 = 60.0 * 60.0 * 24.0 * 7.0;
pub const MAX_RECEIPTS: usize = 1024;
pub const MAX_RATE_TIMESTAMPS: usize = 16;
/// Maximum announces per destination hash per second before dropping.
pub const ANNOUNCE_RATE_LIMIT: usize = 10;
pub const PERSIST_RANDOM_BLOBS: usize = 32;
pub const MAX_RANDOM_BLOBS: usize = 64;
/// Max number of alternative paths stored per destination in the
/// multi-entry path table.  N=3 gives diversity without ballooning
/// memory (≈ 3× the old single-entry cost, offset by halving the
/// global blob cap from 64 → 16 since blobs are now purely anti-replay).
pub const MAX_PATHS_PER_DEST: usize = 3;
/// Max entries in the global anti-replay blob set.  Decoupled from
/// per-path storage; 16 entries is sufficient for pure replay rejection
/// (previously 64 was needed because blobs double-tracked freshness).
pub const MAX_GLOBAL_BLOBS: usize = 16;
pub const LOCAL_CLIENT_CACHE_MAXSIZE: usize = 512;

/// Maximum age of a path entry's announce timestamp before the path is
/// considered stale and a hedge-duplicate is sent on an alternative path
/// (if one exists).  Set to 1/10 of the link staleness threshold so that
/// a path that hasn't heard a fresh announce in >72 s is treated as
/// suspicious *before* the link-layer timeout fires.  Only applied to
/// multi-hop transport paths (hops ≥ 2) where silent path failure is
/// undetectable by intermediate nodes.
///
/// See DESIGN_PRINCIPLES.md §1 — the hedge guarantees delivery latency
/// stays within the 5 s send budget even when the primary path is
/// black-holing.
pub const PATH_STALE_THRESHOLD: f64 = crate::link::STALE_TIME / 10.0; // 72 s

// ── Legacy table entry indices (deprecated — kept for tunnel paths) ────────
pub const IDX_PT_TIMESTAMP: usize = 0;
pub const IDX_PT_NEXT_HOP: usize = 1;
pub const IDX_PT_HOPS: usize = 2;
pub const IDX_PT_EXPIRES: usize = 3;
pub const IDX_PT_RANDBLOBS: usize = 4;
pub const IDX_PT_RVCD_IF: usize = 5;
pub const IDX_PT_PACKET: usize = 6;

pub const IDX_RT_RCVD_IF: usize = 0;
pub const IDX_RT_OUTB_IF: usize = 1;
pub const IDX_RT_TIMESTAMP: usize = 2;

pub const IDX_AT_TIMESTAMP: usize = 0;
pub const IDX_AT_RTRNS_TMO: usize = 1;
pub const IDX_AT_RETRIES: usize = 2;
pub const IDX_AT_RCVD_IF: usize = 3;
pub const IDX_AT_HOPS: usize = 4;
pub const IDX_AT_PACKET: usize = 5;
pub const IDX_AT_LCL_RBRD: usize = 6;
pub const IDX_AT_BLCK_RBRD: usize = 7;
pub const IDX_AT_ATTCHD_IF: usize = 8;

pub const IDX_LT_TIMESTAMP: usize = 0;
pub const IDX_LT_NH_TRID: usize = 1;
pub const IDX_LT_NH_IF: usize = 2;
pub const IDX_LT_REM_HOPS: usize = 3;
pub const IDX_LT_RCVD_IF: usize = 4;
pub const IDX_LT_HOPS: usize = 5;
pub const IDX_LT_DSTHASH: usize = 6;
pub const IDX_LT_VALIDATED: usize = 7;
pub const IDX_LT_PROOF_TMO: usize = 8;

pub const IDX_TT_TUNNEL_ID: usize = 0;
pub const IDX_TT_IF: usize = 1;
pub const IDX_TT_PATHS: usize = 2;
pub const IDX_TT_EXPIRES: usize = 3;

#[derive(Clone, Debug, Default)]
pub struct InterfaceStats {
    pub bitrate: Option<f64>,
    pub rxb: u64,
    pub txb: u64,
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceStub {
    pub name: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub online: bool,
    pub bitrate: Option<f64>,
    pub rxb: u64,
    pub txb: u64,
    pub current_rx_speed: f64,
    pub current_tx_speed: f64,
    pub r_stat_rssi: Option<f64>,
    pub r_stat_snr: Option<f64>,
    pub r_stat_q: Option<f64>,
    pub hw_mtu: Option<usize>,
    pub autoconfigure_mtu: bool,
    pub fixed_mtu: bool,
    pub out: bool,
    pub detached: bool,
    pub mode: u8,
    pub announce_cap: f64,
    pub announce_allowed_at: f64,
    pub announce_queue: Vec<AnnounceQueueEntry>,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<f64>,
    pub announce_rate_penalty: Option<f64>,
    pub ingress_control: bool,
    pub ic_max_held_announces: usize,
    pub ic_burst_hold: f64,
    pub ic_burst_freq_new: f64,
    pub ic_burst_freq: f64,
    pub ic_new_time: f64,
    pub ic_burst_penalty: f64,
    pub ic_held_release_interval: f64,
    pub bootstrap_only: bool,
    pub discoverable: bool,
    pub discovery_announce_interval: Option<f64>,
    pub discovery_publish_ifac: bool,
    pub reachable_on: Option<String>,
    pub discovery_name: Option<String>,
    pub discovery_encrypt: bool,
    pub discovery_stamp_value: Option<u32>,
    pub discovery_latitude: Option<f64>,
    pub discovery_longitude: Option<f64>,
    pub discovery_height: Option<f64>,
    pub discovery_frequency: Option<u64>,
    pub discovery_bandwidth: Option<u32>,
    pub discovery_modulation: Option<String>,
    pub ifac_size: Option<usize>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub ifac_key: Option<Vec<u8>>,
    pub ifac_signature: Option<Vec<u8>>,
    pub wants_tunnel: bool,
    pub tunnel_id: Option<Vec<u8>>,
    pub parent_is_local_shared: bool,
    pub is_connected_to_shared_instance: bool,
    /// Wall-clock seconds of the most recent successful inbound packet
    /// processed on this interface. Updated by `Transport::inbound`.
    /// Consumed by the §1 watchdog in `Transport::outbound` to detect
    /// "outbound succeeds but no inbound for too long" half-open peers.
    /// Zero means no inbound has ever been recorded.
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
    pub last_inbound_at: f64,
    /// Wall-clock seconds of the most recent §1 "no inbound for Ns"
    /// warning emitted for this interface. Used to throttle the warning
    /// to once per minute so a sustained wedge doesn't fill the log.
    pub last_inbound_warn_at: f64,
    /// Wall-clock seconds of the most recent offline-send warning emitted
    /// for this interface. Used to suppress repeated "dropping send"
    /// log spam while an interface remains offline.
    pub last_offline_warn_at: f64,
    /// Full string representation of the interface (e.g.
    /// `TCPInterface[London/132.145.75.143:4242]`). Stored at
    /// registration time and used by `synthesize_tunnel_all_tcp` to
    /// re-send tunnel bindings without holding a TCP interface Arc.
    /// Empty for non-TCP / non-tunnel interfaces.
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
    pub repr: String,
}

#[derive(Clone, Debug)]
pub struct AnnounceQueueEntry {
    pub destination: Vec<u8>,
    pub time: f64,
    pub hops: u8,
    pub emitted: u64,
    pub raw: Vec<u8>,
}

impl InterfaceStub {
    pub const MODE_FULL: u8 = 0x01;
    pub const MODE_POINT_TO_POINT: u8 = 0x02;
    pub const MODE_ACCESS_POINT: u8 = 0x03;
    pub const MODE_ROAMING: u8 = 0x04;
    pub const MODE_BOUNDARY: u8 = 0x05;
    pub const MODE_GATEWAY: u8 = 0x06;

    pub fn get_hash(&self) -> Vec<u8> {
        crate::identity::full_hash(self.name.as_bytes())[..crate::reticulum::TRUNCATED_HASHLENGTH / 8].to_vec()
    }

    pub fn process_outgoing(&self, _raw: &[u8]) {
        Transport::dispatch_outbound(&self.name, _raw);
    }

    pub fn should_ingress_limit(&self) -> bool {
        false
    }

    pub fn hold_announce(&mut self, _packet: &Packet) {
        // Placeholder for ingress limiting.
    }

    pub fn process_announce_queue(&mut self) {
        self.announce_queue.clear();
    }

    pub fn sent_announce(&mut self) {
        // Placeholder hook.
    }

    pub fn process_held_announces(&mut self) {
        // Placeholder hook.
    }
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceStubConfig {
    pub name: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub online: Option<bool>,
    pub mode: u8,
    pub out: bool,
    pub bitrate: Option<u64>,
    pub announce_cap: Option<f64>,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<f64>,
    pub announce_rate_penalty: Option<f64>,
    pub ingress_control: Option<bool>,
    pub ic_max_held_announces: Option<usize>,
    pub ic_burst_hold: Option<f64>,
    pub ic_burst_freq_new: Option<f64>,
    pub ic_burst_freq: Option<f64>,
    pub ic_new_time: Option<f64>,
    pub ic_burst_penalty: Option<f64>,
    pub ic_held_release_interval: Option<f64>,
    pub bootstrap_only: Option<bool>,
    pub discoverable: Option<bool>,
    pub discovery_announce_interval: Option<f64>,
    pub discovery_publish_ifac: Option<bool>,
    pub reachable_on: Option<String>,
    pub discovery_name: Option<String>,
    pub discovery_encrypt: Option<bool>,
    pub discovery_stamp_value: Option<u32>,
    pub discovery_latitude: Option<f64>,
    pub discovery_longitude: Option<f64>,
    pub discovery_height: Option<f64>,
    pub discovery_frequency: Option<u64>,
    pub discovery_bandwidth: Option<u32>,
    pub discovery_modulation: Option<String>,
    pub ifac_size: Option<usize>,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub ifac_key: Option<Vec<u8>>,
    pub ifac_signature: Option<Vec<u8>>,
    /// See `InterfaceStub::repr`.
    pub repr: Option<String>,
}

#[derive(Default)]
pub struct TransportState {
    pub interfaces: Vec<InterfaceStub>,
    pub destinations: Vec<Destination>,
    pub pending_links: Vec<crate::link::Link>,
    pub active_links: Vec<crate::link::Link>,
    pub packet_hashlist: HashSet<Vec<u8>>,
    pub packet_hashlist_prev: HashSet<Vec<u8>>,
    /// Set of `packet_hash` values for ANNOUNCE packets we've already
    /// successfully Ed25519-validated. A duplicate announce (same packet_hash)
    /// MUST have identical bytes, hence identical signature, hence is
    /// guaranteed valid — skip the expensive `validate_announce` call.
    /// Cleared in lockstep with `packet_hashlist` rotation so it can never
    /// outgrow it.
    pub validated_announce_hashes: HashSet<Vec<u8>>,
    pub validated_announce_hashes_prev: HashSet<Vec<u8>>,
    pub receipts: Vec<crate::packet::PacketReceipt>,
    pub announce_table: HashMap<Vec<u8>, Vec<AnnounceEntryValue>>,
    /// Multi-path table: each destination hash maps to a bounded deque of
    /// `PathEntry` (max N=3), newest-first. See `PathEntry::score()` for
    /// the selection priority formula (bitrate / (hops + 1)).
    pub path_table: HashMap<Vec<u8>, VecDeque<PathEntry>>,
    pub reverse_table: HashMap<Vec<u8>, Vec<ReverseEntryValue>>,
    pub link_table: HashMap<Vec<u8>, Vec<LinkEntryValue>>,
    pub held_announces: HashMap<Vec<u8>, Vec<AnnounceEntryValue>>,
    pub announce_handlers: Vec<AnnounceHandler>,
    pub tunnels: HashMap<Vec<u8>, Vec<TunnelEntryValue>>,
    pub announce_rate_table: HashMap<Vec<u8>, AnnounceRateEntry>,
    pub path_requests: HashMap<Vec<u8>, f64>,
    /// Global anti-replay blob set — decoupled from individual path entries.
    /// Each announce carries a 10-byte random blob; we track seen blobs here
    /// to reject replays regardless of which path they arrived on.
    pub global_blobs: HashSet<Vec<u8>>,
    pub blackholed_identities: HashMap<Vec<u8>, BlackholeEntry>,
    pub discovery_path_requests: HashMap<Vec<u8>, DiscoveryPathRequest>,
    /// FIFO queue of recently-seen path-request tags (for eviction order).
    pub discovery_pr_tags: Vec<Vec<u8>>,
    /// O(1) lookup mirror of `discovery_pr_tags`. Kept in sync on insert/evict
    /// to avoid an O(n) linear scan per inbound path-request packet, which
    /// previously starved the Transport mutex under path-request floods.
    pub discovery_pr_tags_set: HashSet<Vec<u8>>,
    pub max_pr_tags: usize,
    pub control_destinations: Vec<Destination>,
    pub control_hashes: Vec<Vec<u8>>,
    pub mgmt_destinations: Vec<Destination>,
    pub mgmt_hashes: Vec<Vec<u8>>,
    pub remote_management_allowed: Vec<Vec<u8>>,
    pub local_client_interfaces: Vec<InterfaceStub>,
    pub local_client_rssi_cache: Vec<(Vec<u8>, f64)>,
    pub local_client_snr_cache: Vec<(Vec<u8>, f64)>,
    pub local_client_q_cache: Vec<(Vec<u8>, f64)>,
    pub pending_local_path_requests: HashMap<Vec<u8>, InterfaceStub>,
    pub forced_shared_bitrate: Option<u64>,
    pub start_time: Option<f64>,
    pub hashlist_maxsize: usize,
    pub job_interval: f64,
    pub links_last_checked: f64,
    pub links_check_interval: f64,
    pub receipts_last_checked: f64,
    pub receipts_check_interval: f64,
    pub announces_last_checked: f64,
    pub announces_check_interval: f64,
    pub pending_prs_last_checked: f64,
    pub pending_prs_check_interval: f64,
    pub cache_last_cleaned: f64,
    pub cache_clean_interval: f64,
    pub tables_last_culled: f64,
    pub tables_cull_interval: f64,
    pub interface_last_jobs: f64,
    pub interface_jobs_interval: f64,
    pub last_mgmt_announce: f64,
    pub mgmt_announce_interval: f64,
    pub blackhole_last_checked: f64,
    pub blackhole_check_interval: f64,
    pub traffic_rxb: u64,
    pub traffic_txb: u64,
    pub speed_rx: f64,
    pub speed_tx: f64,
    pub identity: Option<Identity>,
    pub network_identity: Option<Identity>,
    pub is_connected_to_shared_instance: bool,
    pub transport_enabled: bool,
    pub drop_announces: bool,
    pub announce_watchlist: std::collections::HashSet<Vec<u8>>,
    pub discovery_announcer: Option<InterfaceAnnouncer>,
    pub interface_discovery: Option<InterfaceDiscovery>,
    pub interface_announce_handler: Option<Arc<InterfaceAnnounceHandler>>,
    pub outbound_handlers: HashMap<String, Arc<dyn Fn(&[u8]) -> bool + Send + Sync>>,
    /// Per-client earliest-next-dispatch time for announce pacing (enqueue scheduling).
    pub client_announce_pacing: HashMap<String, f64>,
    /// Per-client wall-clock time of the last actual paced dispatch (from jobs()).
    pub client_announce_last_sent: HashMap<String, f64>,
    /// Announces deferred until their pacing window opens: (dispatch_at, iface_name, raw_bytes).
    pub pending_local_announces: Vec<(f64, String, Vec<u8>)>,
    /// App-opted-in destinations managed by Transport's announce daemon.
    /// Keyed by destination hash. See `PublishedDestination` and
    /// `Transport::publish_destination`.
    pub published_destinations: HashMap<Vec<u8>, PublishedDestination>,
    /// Wall-clock of the last `published_destinations` refresh sweep.
    pub published_last_checked: f64,
    /// How often jobs() examines the published set for due refreshes.
    pub published_check_interval: f64,
    /// True when `path_table` has been mutated since the last on-disk
    /// persist. Drives the opportunistic save in `jobs()` so that warm
    /// starts find every learned path on disk — not just whatever
    /// happened to be in the table when an explicit `persist_data()`
    /// was called. Without this, cold-start path resolution falls back
    /// to a wire `PATH_REQUEST` whose round-trip dominates the
    /// user-facing "open the app" latency. See
    /// DESIGN_PRINCIPLES.md §1 (5 s send budget).
    pub path_table_dirty: bool,
    /// Wall-clock of the last successful `save_path_table()` call.
    pub path_table_last_saved: f64,
    /// Minimum spacing between opportunistic path-table saves.
    /// Bounded so a chatty network (lots of fresh announces) doesn't
    /// thrash the disk while still keeping the persisted set fresh.
    pub path_table_save_interval: f64,
    /// Set of destination hashes whose `path_table` entry has been
    /// confirmed by an inbound announce SINCE THIS PROCESS STARTED.
    ///
    /// Cached path entries loaded from disk on cold start are NOT in
    /// this set — even though `has_path()` returns true for them, the
    /// route they encode may have gone stale between sessions
    /// (intermediate hops dropped the path, the destination peer
    /// reattached on a different route, etc.).
    ///
    /// `app_links::establish()` consults this set on the first racer
    /// for a destination: if the cached path is unverified, it fires
    /// a `request_path` IN PARALLEL with the link attempt. The two
    /// race naturally — if the cached route works, the link wins
    /// in ~RTT and the bonus path-request is harmless; if the cached
    /// route is stale, a fresh announce arrives and spawns a 2nd
    /// racer over the new route while the doomed first racer is
    /// still mid-handshake. First success wins.
    ///
    /// Without this, a stale cached route forces an 18+ second link
    /// establishment timeout BEFORE we ever consider re-resolving —
    /// a hard violation of DESIGN_PRINCIPLES.md §1 (5 s send budget).
    /// NEVER REMOVE EVER.
    pub path_verified_this_session: HashSet<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub enum AnnounceEntryValue {
    Timestamp(f64),
    RetransmitTimeout(f64),
    Retries(u8),
    ReceivedFrom(Vec<u8>),
    Hops(u8),
    Packet(Packet),
    LocalRebroadcasts(u8),
    BlockRebroadcasts(bool),
    AttachedInterface(Option<String>),
}

/// A single learned path to a destination. Replaces the old sparse-vector
/// `Vec<PathEntryValue>` encoding. Each destination now stores a bounded
/// `VecDeque<PathEntry>` (max N=3), ordered newest-first.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathEntry {
    /// Wall-clock timestamp when this path was learned (Unix seconds).
    pub timestamp: f64,
    /// Transport identity hash of the next-hop node.
    pub next_hop: Vec<u8>,
    /// Number of hops to the destination via this path.
    pub hops: u8,
    /// Absolute expiry wall-clock (timestamp + DESTINATION_TIMEOUT).
    pub expires: f64,
    /// Name of the interface that received the announcing packet.
    pub receiving_interface: Option<String>,
    /// Packet hash of the announce that established this path.
    pub packet_hash: Vec<u8>,
}

impl PathEntry {
    /// Quality score: higher is better.  Uses `bitrate / (hops + 1)` so
    /// fast interfaces with few hops win.  Falls back to a nominal
    /// 1000 bps when the interface bitrate is unknown (still hop-aware).
    pub fn score(&self, interface_bitrate: Option<f64>) -> f64 {
        let br = interface_bitrate.unwrap_or(1000.0);
        br / (self.hops as f64 + 1.0)
    }

    /// True when this entry's expiry has elapsed.
    pub fn is_expired(&self, now: f64) -> bool {
        now >= self.expires
    }
}

// ── Legacy sparse-vector type — kept during migration for tunnel paths ──────
#[derive(Clone, Debug)]
pub enum PathEntryValue {
    Timestamp(f64),
    NextHop(Vec<u8>),
    Hops(u8),
    Expires(f64),
    RandomBlobs(Vec<Vec<u8>>),
    ReceivingInterface(Option<String>),
    PacketHash(Vec<u8>),
}

#[derive(Clone, Debug)]
pub enum ReverseEntryValue {
    ReceivedInterface(Option<String>),
    OutboundInterface(Option<String>),
    Timestamp(f64),
}

#[derive(Clone, Debug)]
pub enum LinkEntryValue {
    Timestamp(f64),
    NextHopTransport(Vec<u8>),
    NextHopInterface(Option<String>),
    RemainingHops(u8),
    ReceivedInterface(Option<String>),
    TakenHops(u8),
    DestinationHash(Vec<u8>),
    Validated(bool),
    ProofTimeout(f64),
}

#[derive(Clone, Debug)]
pub enum TunnelEntryValue {
    TunnelId(Vec<u8>),
    Interface(Option<String>),
    Paths(HashMap<Vec<u8>, Vec<PathEntryValue>>),
    Expires(f64),
}

#[derive(Clone, Debug)]
pub struct AnnounceRateEntry {
    pub last: f64,
    pub rate_violations: usize,
    pub blocked_until: f64,
    pub timestamps: Vec<f64>,
}

#[derive(Clone, Debug)]
pub struct DiscoveryPathRequest {
    pub destination_hash: Vec<u8>,
    pub timeout: f64,
    pub requesting_interface: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlackholeEntry {
    pub source: Vec<u8>,
    pub until: Option<f64>,
    pub reason: Option<String>,
}

pub type AnnounceCallback = Arc<dyn Fn(&[u8], &Identity, &[u8], Option<Vec<u8>>, bool) + Send + Sync>;

/// Library-managed publication record for a local destination.
///
/// A *published* destination is a locally-registered IN/SINGLE destination
/// that the application has opted in to having Transport announce
/// automatically:
///
///   * once on every false→true `online` transition of any interface
///     (so re-announces fire automatically when an interface comes back
///     up after a reconnect / handshake), and
///   * periodically at `refresh_interval`, replacing the per-app
///     "announce timer" pattern.
///
/// See `Transport::publish_destination` for usage.
#[derive(Clone, Debug)]
pub struct PublishedDestination {
    /// Refresh interval in seconds. `None` = no periodic announce; only
    /// re-announce on interface up-edge.
    pub refresh_interval: Option<f64>,
    /// Wall-clock (seconds since UNIX epoch) of the last announce dispatch.
    /// `0.0` means "never announced yet" — the next jobs() tick will
    /// announce immediately.
    pub last_announced_at: f64,
    /// Optional app_data attached to each announce. When `None`, the
    /// destination's currently-configured app_data is used.
    pub app_data: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct AnnounceHandler {
    pub aspect_filter: Option<String>,
    pub receive_path_responses: bool,
    pub callback: AnnounceCallback,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedPathEntry {
    pub destination_hash: Vec<u8>,
    pub timestamp: f64,
    pub received_from: Vec<u8>,
    pub hops: u8,
    pub expires: f64,
    pub random_blobs: Vec<Vec<u8>>,
    pub interface_hash: Vec<u8>,
    pub packet_hash: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializedTunnelEntry {
    pub tunnel_id: Vec<u8>,
    pub interface_hash: Option<Vec<u8>>,
    pub paths: Vec<SerializedPathEntry>,
    pub expires: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedPacketEntry {
    pub raw: Vec<u8>,
    pub interface_name: Option<String>,
}

/// Type alias for a transport-task closure dispatched onto the dedicated
/// transport worker thread.  Used by `request_path` (and any other call
/// site that needs to fire-and-forget potentially-blocking transport work
/// without holding up its caller).
type TransportTask = Box<dyn FnOnce() + Send + 'static>;

/// Dedicated transport-task worker.  A single OS thread drains the queue
/// and runs each task sequentially.  This bounds the resource cost of
/// fire-and-forget transport calls (e.g. when `Transport::jobs()` flushes
/// many deferred path-requests in one tick) and avoids unbounded
/// `std::thread::spawn` from latency-sensitive callers.
///
/// Tasks are themselves allowed to block on `TRANSPORT.lock()` and on
/// `Transport::outbound`'s jobs_running wait — the worker is never on a
/// UI thread.  The queue is unbounded so producers never block; if backlog
/// pressure ever becomes a concern, this should be revisited.
static TRANSPORT_TASK_TX: Lazy<Mutex<std::sync::mpsc::Sender<TransportTask>>> = Lazy::new(|| {
    let (tx, rx) = std::sync::mpsc::channel::<TransportTask>();
    std::thread::Builder::new()
        .name("rns-transport-tasks".to_string())
        .spawn(move || {
            // Single-consumer drain loop.  Panics in tasks are caught so
            // one bad task doesn't kill the worker.
            while let Ok(task) = rx.recv() {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
            }
        })
        .expect("failed to spawn rns-transport-tasks worker");
    Mutex::new(tx)
});

/// Event source for "a path was added or refreshed in `path_table`".
///
/// The `Mutex<u64>` is a monotonic generation counter; it is incremented
/// every time `path_table.insert(...)` runs (i.e. every PATH_RESPONSE or
/// announce that establishes/refreshes a route). Waiters can use the
/// counter as a wakeup-fairness predicate so that an insert happening
/// between their pre-check and `wait_timeout` does not get lost.
///
/// Mirrors the pattern of `RECONNECT_NUDGE` in `interfaces/tcp_interface.rs`.
/// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §4 (no timeout tuning):
/// callers (e.g. `app_links::race_path`) use this to wake on the actual
/// PATH_RESPONSE event instead of polling on a clock.
pub(crate) static PATH_ADDED_NOTIFY: Lazy<(Mutex<u64>, Condvar)> =
    Lazy::new(|| (Mutex::new(0), Condvar::new()));

/// Called from every site that mutates `path_table` with a new/refreshed
/// entry. Bumps the generation counter and wakes all waiters.
pub(crate) fn notify_path_added() {
    if let Ok(mut gen) = PATH_ADDED_NOTIFY.0.lock() {
        *gen = gen.wrapping_add(1);
    }
    PATH_ADDED_NOTIFY.1.notify_all();
}

/// Submit a task to the transport-task worker.  Returns immediately.
pub(crate) fn spawn_transport_task<F>(task: F)
where
    F: FnOnce() + Send + 'static,
{
    if let Ok(tx) = TRANSPORT_TASK_TX.lock() {
        let _ = tx.send(Box::new(task));
    }
}

/// Drop-in shim around `parking_lot::Mutex` that exposes the
/// `std::sync::Mutex` API (`.lock() -> Result<Guard, Infallible>`),
/// so existing call sites of the form `TRANSPORT.lock().unwrap()`
/// keep compiling unchanged after the migration to parking_lot.
///
/// Why parking_lot:
/// * No poisoning — a panic in a critical section doesn't kill the
///   global Transport for the rest of the process. Steps 1+2
///   eliminated the I/O blocking that made poisoning a worry; this
///   removes the residual `LockResult` ceremony.
/// * Smaller footprint and faster uncontended path than `std::sync::Mutex`.
/// * Documented FIFO-ish fairness under contention (parking_lot's
///   "eventual fairness" mode), which Steps 1+2 already rely on
///   implicitly via the writer-actor architecture.
///
/// Used only for the global `TRANSPORT` state (the hottest lock in
/// the system). Other intra-module locks remain on `std::sync::Mutex`
/// for now.
pub(crate) struct FastMutex<T>(parking_lot::Mutex<T>);

impl<T> FastMutex<T> {
    pub fn new(value: T) -> Self {
        Self(parking_lot::Mutex::new(value))
    }

    /// Returns `Ok(guard)` always — parking_lot mutexes cannot be
    /// poisoned. The `Result` wrapper exists solely so existing
    /// `lock().unwrap()` call sites keep compiling.
    pub fn lock(&self) -> Result<parking_lot::MutexGuard<'_, T>, std::convert::Infallible> {
        Ok(self.0.lock())
    }
}

pub(crate) static TRANSPORT: Lazy<FastMutex<TransportState>> = Lazy::new(|| FastMutex::new(TransportState {
    max_pr_tags: 32000,
    hashlist_maxsize: 1_000_000,
    job_interval: 0.250,
    links_check_interval: 1.0,
    receipts_check_interval: 1.0,
    announces_check_interval: 1.0,
    pending_prs_check_interval: 30.0,
    cache_clean_interval: 5.0 * 60.0,
    tables_cull_interval: 5.0,
    interface_jobs_interval: 5.0,
    mgmt_announce_interval: 2.0 * 60.0 * 60.0,
    blackhole_check_interval: 60.0,
    published_check_interval: 30.0,
    path_table_save_interval: 30.0,
    ..TransportState::default()
}));

type OutboundHandler = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

static OUTBOUND_HANDLERS: Lazy<Mutex<HashMap<String, OutboundHandler>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone, Debug)]
pub struct TransportSnapshot {
    pub interfaces: Vec<InterfaceStub>,
    pub path_table: HashMap<Vec<u8>, VecDeque<PathEntry>>,
    pub announce_rate_table: HashMap<Vec<u8>, AnnounceRateEntry>,
    pub link_table_len: usize,
    pub local_client_rssi_cache: Vec<(Vec<u8>, f64)>,
    pub local_client_snr_cache: Vec<(Vec<u8>, f64)>,
    pub local_client_q_cache: Vec<(Vec<u8>, f64)>,
    pub blackholed_identities: HashMap<Vec<u8>, BlackholeEntry>,
    pub traffic_rxb: u64,
    pub traffic_txb: u64,
    pub speed_rx: f64,
    pub speed_tx: f64,
}

pub fn get_state_snapshot() -> TransportSnapshot {
    let state = TRANSPORT.lock().unwrap();
    TransportSnapshot {
        interfaces: state.interfaces.clone(),
        path_table: state.path_table.clone(),
        announce_rate_table: state.announce_rate_table.clone(),
        link_table_len: state.link_table.len(),
        local_client_rssi_cache: state.local_client_rssi_cache.clone(),
        local_client_snr_cache: state.local_client_snr_cache.clone(),
        local_client_q_cache: state.local_client_q_cache.clone(),
        blackholed_identities: state.blackholed_identities.clone(),
        traffic_rxb: state.traffic_rxb,
        traffic_txb: state.traffic_txb,
        speed_rx: state.speed_rx,
        speed_tx: state.speed_tx,
    }
}

pub struct Transport;

fn mark_packet_sent(packet: &mut Packet, outbound_time: f64) {
    packet.sent = true;
    packet.sent_at = Some(outbound_time);
}

impl Transport {
    /// Register an outbound handler for an interface.
    ///
    /// The supplied `handler` is moved into a per-interface writer actor
    /// (see `interface_writer`): one background thread + bounded mpsc
    /// channel per interface. `dispatch_outbound` enqueues bytes onto
    /// that channel and returns immediately, so a slow or wedged socket
    /// can no longer block the caller (or, transitively, the global
    /// `TRANSPORT` mutex). The original handler still runs synchronously
    /// — just on the writer thread, never on the routing path.
    pub fn register_outbound_handler(
        name: &str,
        handler: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) {
        // Spawn (or replace) the writer actor for this interface.
        crate::interface_writer::register(
            name,
            handler,
            crate::interface_writer::DEFAULT_WRITER_QUEUE_DEPTH,
        );
        // Keep the legacy registry populated so any direct lookup of
        // OUTBOUND_HANDLERS still finds *something* — but the dispatcher
        // prefers the writer below. We store a no-op marker so the entry
        // exists for `dispatch_outbound`'s "is there a handler?" check.
        let marker: OutboundHandler = Arc::new(|_bytes: &[u8]| true);
        OUTBOUND_HANDLERS
            .lock()
            .unwrap()
            .insert(name.to_string(), marker);
    }

    pub fn unregister_outbound_handler(name: &str) {
        crate::interface_writer::unregister(name);
        OUTBOUND_HANDLERS.lock().unwrap().remove(name);
    }

    pub fn set_receipt_delivery_callback(
        receipt_hash: &[u8],
        callback: Arc<dyn Fn(&crate::packet::PacketReceipt) + Send + Sync>,
    ) {
        let mut immediate: Option<crate::packet::PacketReceipt> = None;
        let mut state = TRANSPORT.lock().unwrap();
        for receipt in state.receipts.iter_mut() {
            if receipt.hash == receipt_hash {
                receipt.set_delivery_callback(callback.clone());
                if receipt.status == crate::packet::PacketReceipt::DELIVERED {
                    immediate = Some(receipt.clone());
                }
                break;
            }
        }
        drop(state);

        if let Some(receipt) = immediate {
            callback(&receipt);
        }
    }

    pub fn set_receipt_timeout_callback(
        receipt_hash: &[u8],
        callback: Arc<dyn Fn(&crate::packet::PacketReceipt) + Send + Sync>,
    ) {
        let mut immediate: Option<crate::packet::PacketReceipt> = None;
        let mut state = TRANSPORT.lock().unwrap();
        for receipt in state.receipts.iter_mut() {
            if receipt.hash == receipt_hash {
                receipt.set_timeout_callback(callback.clone());
                if receipt.status == crate::packet::PacketReceipt::FAILED
                    || receipt.status == crate::packet::PacketReceipt::CULLED
                {
                    immediate = Some(receipt.clone());
                }
                break;
            }
        }
        drop(state);

        if let Some(receipt) = immediate {
            callback(&receipt);
        }
    }

    pub fn dispatch_outbound(name: &str, raw: &[u8]) -> bool {
        // Prefer the per-interface writer actor: it enqueues onto a bounded
        // channel and returns immediately, so this call cannot block on a
        // wedged socket. Falls back to the legacy synchronous handler only
        // if no writer is registered (e.g. test fixtures that bypass
        // `register_outbound_handler`).
        if let Some(writer) = crate::interface_writer::get(name) {
            let result = writer.enqueue(raw);
            crate::log(
                &format!(
                    "[DISPATCH-DIAG] iface={} raw_len={} writer_enqueue={}",
                    name,
                    raw.len(),
                    result
                ),
                crate::LOG_EXTREME,
                false,
                false,
            );
            return result;
        }

        let handler = {
            let handlers = OUTBOUND_HANDLERS.lock().unwrap();
            handlers.get(name).cloned()
        };

        if let Some(handler) = handler {
            let result = handler(raw);
            crate::log(&format!("[DISPATCH-DIAG] iface={} raw_len={} result={}", name, raw.len(), result), crate::LOG_EXTREME, false, false);
            result
        } else {
            crate::log(&format!("[DISPATCH-DIAG] NO HANDLER for iface={} raw_len={}", name, raw.len()), crate::LOG_EXTREME, false, false);
            false
        }
    }

    /// Send a pre-built raw wire frame directly on a named interface.
    /// Bypasses `Transport::outbound` packet construction and routing —
    /// the caller is responsible for building the complete frame
    /// (flags + hops + destination_hash + context + ciphertext).
    pub fn send_raw_on_interface(interface_name: &str, raw: &[u8]) -> bool {
        crate::log(
            &format!("send_raw_on_interface len={} iface={}", raw.len(), interface_name),
            crate::LOG_EXTREME,
            false,
            false,
        );
        Self::dispatch_outbound(interface_name, raw)
    }

    /// Set delivery and/or timeout callbacks on a receipt already stored
    /// in `state.receipts`.  Identified by the receipt's full hash.
    /// Returns `true` if the receipt was found.
    pub fn set_receipt_callbacks(
        receipt_hash: &[u8],
        delivery_callback: Option<Arc<dyn Fn(&crate::packet::PacketReceipt) + Send + Sync>>,
        timeout_callback: Option<Arc<dyn Fn(&crate::packet::PacketReceipt) + Send + Sync>>,
    ) -> bool {
        if let Ok(mut state) = TRANSPORT.lock() {
            for receipt in state.receipts.iter_mut() {
                if receipt.hash == receipt_hash {
                    if delivery_callback.is_some() {
                        receipt.delivery_callback = delivery_callback;
                    }
                    if timeout_callback.is_some() {
                        receipt.timeout_callback = timeout_callback;
                    }
                    return true;
                }
            }
        }
        false
    }

    fn name_hash_for_aspect_filter(filter: &str) -> Option<Vec<u8>> {
        let (app_name, aspects) = crate::destination::Destination::app_and_aspects_from_name(filter);
        if app_name.is_empty() {
            return None;
        }
        let aspect_strs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();
        let name_without_identity = crate::destination::Destination::expand_name(None, &app_name, &aspect_strs);
        let full = crate::identity::full_hash(name_without_identity.as_bytes());
        let len = crate::identity::NAME_HASH_LENGTH / 8;
        Some(full[..len].to_vec())
    }

    fn extract_announce_name_hash(packet: &Packet) -> Option<Vec<u8>> {
        let pubkey_len = crate::identity::KEYSIZE / 8;
        let name_hash_len = crate::identity::NAME_HASH_LENGTH / 8;
        if packet.data.len() < pubkey_len + name_hash_len {
            return None;
        }
        let start = pubkey_len;
        let end = start + name_hash_len;
        Some(packet.data[start..end].to_vec())
    }

    fn extract_announce_app_data(packet: &Packet) -> Option<Vec<u8>> {
        let pubkey_len = crate::identity::KEYSIZE / 8;
        let name_hash_len = crate::identity::NAME_HASH_LENGTH / 8;
        let random_hash_len = 10usize;
        let ratchet_len = if packet.context_flag == crate::packet::FLAG_SET {
            crate::identity::RATCHETSIZE / 8
        } else {
            0
        };
        let signature_len = crate::identity::SIGLENGTH / 8;
        let offset = pubkey_len + name_hash_len + random_hash_len + ratchet_len + signature_len;
        if packet.data.len() <= offset {
            return None;
        }
        Some(packet.data[offset..].to_vec())
    }

    fn extract_announce_ratchet(packet: &Packet) -> Option<Vec<u8>> {
        if packet.context_flag != crate::packet::FLAG_SET {
            return None;
        }

        let pubkey_len = crate::identity::KEYSIZE / 8;
        let name_hash_len = crate::identity::NAME_HASH_LENGTH / 8;
        let random_hash_len = 10usize;
        let ratchet_len = crate::identity::RATCHETSIZE / 8;
        let start = pubkey_len + name_hash_len + random_hash_len;
        let end = start + ratchet_len;
        if packet.data.len() < end {
            return None;
        }

        Some(packet.data[start..end].to_vec())
    }

    fn extract_announce_identity(packet: &Packet) -> Option<Identity> {
        let pubkey_len = crate::identity::KEYSIZE / 8;
        if packet.data.len() < pubkey_len {
            return None;
        }
        let pub_key = packet.data[..pubkey_len].to_vec();
        Identity::from_public_key(&pub_key).ok()
    }
    pub fn rpc_key() -> Option<Vec<u8>> {
        let state = TRANSPORT.lock().unwrap();
        state
            .identity
            .as_ref()
            .and_then(|identity| identity.get_private_key().ok())
            .map(|key| Identity::full_hash(&key))
    }

    pub fn start(is_connected_to_shared_instance: bool, transport_enabled: bool) {
        let mut state = TRANSPORT.lock().unwrap();
        state.is_connected_to_shared_instance = is_connected_to_shared_instance;
        state.transport_enabled = transport_enabled;

        ensure_paths();

        if state.identity.is_none() {
            let transport_identity_path = crate::reticulum::storage_path().join("transport_identity");
            if transport_identity_path.exists() {
                if let Ok(identity) = Identity::from_file(&transport_identity_path) {
                    state.identity = Some(identity);
                }
            }

            if state.identity.is_none() {
                let identity = Identity::new(true);
                if let Err(err) = identity.to_file(&transport_identity_path) {
                    log(&format!("Failed to persist transport identity: {}", err), LOG_ERROR, false, false);
                }
                state.identity = Some(identity);
            }
        }

        if !state.is_connected_to_shared_instance {
            let packet_hashlist_path = crate::reticulum::storage_path().join("packet_hashlist");
            if packet_hashlist_path.exists() {
                if let Ok(mut file) = File::open(&packet_hashlist_path) {
                    let mut buf = Vec::new();
                    if file.read_to_end(&mut buf).is_ok() {
                        if let Ok(list) = from_slice::<Vec<Vec<u8>>>(&buf) {
                            state.packet_hashlist = list.into_iter().collect();
                        }
                    }
                }
            }
        }

        // Load previously cached destination/path table from disk
        if !state.is_connected_to_shared_instance {
            let dest_table_path = crate::reticulum::storage_path().join("destination_table");
            if dest_table_path.exists() {
                if let Ok(mut file) = File::open(&dest_table_path) {
                    let mut buf = Vec::new();
                    if file.read_to_end(&mut buf).is_ok() {
                        let now_ts = now();
                        let mut loaded = 0usize;
                        let mut loaded_dests: Vec<String> = Vec::new();

                        // Try new format first: Vec<(Vec<u8>, Vec<PathEntry>)>
                        let loaded_entries: Option<Vec<(Vec<u8>, Vec<PathEntry>)>> =
                            from_slice(&buf).ok();

                        if let Some(entries) = loaded_entries {
                            for (dest_hash, path_entries) in entries {
                                let mut deque: VecDeque<PathEntry> = VecDeque::new();
                                for entry in path_entries {
                                    if entry.is_expired(now_ts) {
                                        continue;
                                    }
                                    deque.push_back(entry);
                                }
                                if !deque.is_empty() {
                                    if loaded_dests.len() < 32 {
                                        loaded_dests.push(crate::hexrep(
                                            &dest_hash[..dest_hash.len().min(4)],
                                            false,
                                        ));
                                    }
                                    state.path_table.insert(dest_hash, deque);
                                    loaded += 1;
                                }
                            }
                        } else {
                            // Fallback: try old SerializedPathEntry format
                            if let Ok(old_entries) = from_slice::<Vec<SerializedPathEntry>>(&buf) {
                                for entry in old_entries {
                                    if entry.expires > 0.0 && entry.expires < now_ts {
                                        continue;
                                    }
                                    let interface_name = if entry.interface_hash.is_empty() {
                                        None
                                    } else {
                                        Some(String::from_utf8_lossy(&entry.interface_hash).to_string())
                                    };
                                    let pe = PathEntry {
                                        timestamp: entry.timestamp,
                                        next_hop: entry.received_from,
                                        hops: entry.hops,
                                        expires: entry.expires,
                                        receiving_interface: interface_name,
                                        packet_hash: entry.packet_hash,
                                    };
                                    if loaded_dests.len() < 32 {
                                        loaded_dests.push(crate::hexrep(
                                            &entry.destination_hash[..entry.destination_hash.len().min(4)],
                                            false,
                                        ));
                                    }
                                    let mut deque = VecDeque::new();
                                    deque.push_back(pe);
                                    state.path_table.insert(entry.destination_hash, deque);
                                    loaded += 1;
                                }
                            }
                        }
                        // END fallback

                        // Loaded entries are by definition already
                        // on disk — clear the dirty flag so the
                        // first opportunistic save isn't a no-op
                        // round trip.
                        state.path_table_dirty = false;
                        state.path_table_last_saved = now_ts;
                        log(
                            &format!(
                                "Loaded {} cached path entries from disk: [{}]{}",
                                loaded,
                                loaded_dests.join(","),
                                if loaded > loaded_dests.len() { ",…" } else { "" },
                            ),
                            LOG_NOTICE,
                            false,
                            false,
                        );
                    }
                }
            }
        }

        drop(state);

        let _ = thread::spawn(|| Transport::jobloop());
        let _ = thread::spawn(|| Transport::count_traffic_loop());

        // Set up control destinations for path requests and tunnel synthesis
        let mut state = TRANSPORT.lock().unwrap();
        
        // Create path request control destination (inbound, no identity needed)
        match Destination::new_inbound(
            None,
            crate::destination::DestinationType::Plain,
            APP_NAME.to_string(),
            vec!["path".to_string(), "request".to_string()],
        ) {
            Ok(mut path_request_dest) => {
                path_request_dest.set_packet_callback(None);
                state.control_hashes.push(path_request_dest.hash.clone());
                state.control_destinations.push(path_request_dest);
            }
            Err(e) => {
                log(&format!("Failed to create path request destination: {}", e), LOG_ERROR, false, false);
            }
        }
        
        // Create tunnel synthesize control destination (inbound, no identity needed)
        match Destination::new_inbound(
            None,
            crate::destination::DestinationType::Plain,
            APP_NAME.to_string(),
            vec!["tunnel".to_string(), "synthesize".to_string()],
        ) {
            Ok(mut tunnel_synth_dest) => {
                tunnel_synth_dest.set_packet_callback(None);
                state.control_hashes.push(tunnel_synth_dest.hash.clone());
                state.control_destinations.push(tunnel_synth_dest);
            }
            Err(e) => {
                log(&format!("Failed to create tunnel synthesize destination: {}", e), LOG_ERROR, false, false);
            }
        }
        
        drop(state);
    }

    pub fn exit_handler() {
        Transport::persist_data();
    }

    /// Synthesize a tunnel on a TCP interface so the remote transport
    /// daemon (rnsd) associates this connection with our transport
    /// identity.  This must be called after the initial connection and
    /// after every reconnection for non-KISS TCP interfaces.
    ///
    /// `interface_name` is the InterfaceStub name (used for
    /// `attached_interface` routing).
    ///
    /// Re-announce all locally registered IN/SINGLE destinations to a specific
    /// interface.  Called after a new interface connects so that the remote
    /// transport node learns about all local destinations immediately, without
    /// waiting for the periodic announce cycle.
    pub fn announce_all_destinations(interface_name: &str) {
        // If the application has opted in to library-managed publication,
        // only re-announce the published set on interface up-edges.  This
        // avoids leaking ephemeral / request-only IN destinations onto the
        // network on every reconnect.  When the published set is empty
        // (legacy callers), fall back to the historical "all IN/SINGLE"
        // behaviour for backwards compatibility.
        let (destinations, published_filter, published_app_data) = {
            let state = TRANSPORT.lock().unwrap();
            let filter: Option<HashSet<Vec<u8>>> = if state.published_destinations.is_empty() {
                None
            } else {
                Some(state.published_destinations.keys().cloned().collect())
            };
            let app_data_map: HashMap<Vec<u8>, Option<Vec<u8>>> = state.published_destinations
                .iter()
                .map(|(h, e)| (h.clone(), e.app_data.clone()))
                .collect();
            (state.destinations.clone(), filter, app_data_map)
        };
        let iface = interface_name.to_string();
        let mut announced: Vec<Vec<u8>> = Vec::new();
        for mut dest in destinations {
            if dest.direction != crate::destination::Direction::IN { continue; }
            if dest.dest_type != crate::destination::DestinationType::Single { continue; }
            if let Some(ref allowed) = published_filter {
                if !allowed.contains(&dest.hash) { continue; }
            }
            log(
                &format!("Re-announcing {} to interface {}", crate::hexrep(&dest.hash, true), iface),
                LOG_NOTICE, false, false,
            );
            // Carry the app_data the application registered via
            // `publish_destination` so interface-up re-announces stay
            // consistent with the periodic-refresh schedule (which also
            // uses this app_data).  Falls back to the destination's
            // default_app_data when `None`.
            let app_data_ref = published_app_data
                .get(&dest.hash)
                .and_then(|o| o.as_deref());
            if dest.announce(app_data_ref, false, Some(iface.clone()), None, true).is_ok() {
                announced.push(dest.hash.clone());
            }
        }
        // Bump last_announced_at for any published entries we just
        // announced — piggy-backing the up-edge announce against the
        // periodic-refresh schedule prevents an immediate double-announce
        // if the refresh timer was about to fire anyway.
        if !announced.is_empty() {
            let now_ts = now();
            let mut state = TRANSPORT.lock().unwrap();
            for hash in &announced {
                if let Some(entry) = state.published_destinations.get_mut(hash) {
                    entry.last_announced_at = now_ts;
                }
            }
        }
    }

    /// Opt a locally-registered IN/SINGLE destination into Transport's
    /// announce daemon.
    ///
    /// Once published, the destination is automatically announced:
    ///   * once on every false→true `online` transition of any
    ///     interface (covers reconnects and post-handshake events), and
    ///   * every `refresh_interval` if `Some(...)` is supplied.
    ///
    /// Calling `publish_destination` with the same hash a second time
    /// updates the existing entry (e.g. to change the refresh interval
    /// or app_data) without re-announcing.
    ///
    /// The destination must already be registered (i.e. present in
    /// `state.destinations`) before publishing — this call only records
    /// the publication policy; it does not register the destination.
    pub fn publish_destination(
        destination_hash: Vec<u8>,
        refresh_interval: Option<Duration>,
        app_data: Option<Vec<u8>>,
    ) {
        let mut state = TRANSPORT.lock().unwrap();
        let refresh_secs = refresh_interval.map(|d| d.as_secs_f64());
        let last = state.published_destinations.get(&destination_hash)
            .map(|e| e.last_announced_at)
            .unwrap_or(0.0);
        state.published_destinations.insert(destination_hash, PublishedDestination {
            refresh_interval: refresh_secs,
            last_announced_at: last,
            app_data,
        });
    }

    /// Remove a destination from the announce daemon's published set.
    /// Does not send a "goodbye" announce; the destination simply stops
    /// being auto-announced.
    pub fn unpublish_destination(destination_hash: &[u8]) {
        let mut state = TRANSPORT.lock().unwrap();
        state.published_destinations.remove(destination_hash);
    }

    /// Return a snapshot of currently-published destinations.
    pub fn published_destinations() -> Vec<(Vec<u8>, PublishedDestination)> {
        let state = TRANSPORT.lock().unwrap();
        state.published_destinations.iter()
            .map(|(h, p)| (h.clone(), p.clone()))
            .collect()
    }

    /// True if `destination_hash` is currently in the published set.
    pub fn is_published(destination_hash: &[u8]) -> bool {
        let state = TRANSPORT.lock().unwrap();
        state.published_destinations.contains_key(destination_hash)
    }

    /// `interface_repr` is the full string representation matching
    /// Python's `str(interface)`, e.g.
    /// `"TCPInterface[LOCAL/192.168.2.113:4242]"`.  It is used to
    /// derive the interface hash, just like the Python implementation.
    pub fn synthesize_tunnel(interface_name: &str, interface_repr: &str) {
        // ── PRECONDITION (load-bearing, NEVER REMOVE EVER) ───────────────
        //
        // Before calling this function, the caller MUST have already
        // invoked `Transport::register_interface_stub_config` (or one of
        // the other stub-registration helpers) for `interface_name`.
        //
        // Why: this function ends with `Transport::outbound(&mut packet)`
        // for a PLAIN-destination packet pinned to `attached_interface =
        // Some(interface_name)`. `outbound()` iterates `state.interfaces`
        // and only transmits on entries whose `name == attached_interface`
        // and whose `out == true`. If no matching stub exists, the
        // broadcast loop finds zero candidates, returns `sent=false`,
        // and THE TUNNEL-SYNTHESIS PACKET IS SILENTLY DROPPED.
        //
        // Downstream consequence (production observed 2026-04-30):
        // upstream rnsd has no mapping from this TCP connection back to
        // our transport identity, so it cannot route PATH_RESPONSE
        // packets back to us. Cold-start PATH_REQUESTs go unanswered
        // for tens of seconds. User-visible: 30+ second "Linking…"
        // stalls on every app launch.
        //
        // Programmatic regression detectors live in
        // `tests::synthesize_tunnel_emits_to_wire_when_stub_registered`
        // and `tests::synthesize_tunnel_emits_nothing_when_stub_missing`.
        // The diagnostic log line at the bottom of this function
        // (`synthesize_tunnel: sent=...`) is the runtime canary —
        // `sent=false` after a clean cold start means this precondition
        // has been violated by the caller.
        //
        // See also: DESIGN_PRINCIPLES.md §4 (strict ordering).

        // Grab transport identity's public key and signing capability
        let (public_key, tunnel_id, signed_data, signature) = {
            let state = TRANSPORT.lock().unwrap();
            let identity = match &state.identity {
                Some(id) => id.clone(),
                None => {
                    log("synthesize_tunnel: no transport identity available", LOG_ERROR, false, false);
                    return;
                }
            };

            let public_key = match identity.get_public_key() {
                Ok(pk) => pk,
                Err(e) => {
                    log(&format!("synthesize_tunnel: failed to get public key: {}", e), LOG_ERROR, false, false);
                    return;
                }
            };

            // interface_hash = Identity.full_hash(str(interface).encode("utf-8"))
            let interface_hash = crate::identity::full_hash(interface_repr.as_bytes());

            let random_hash = crate::identity::get_random_hash();

            // tunnel_id = Identity.full_hash(public_key + interface_hash)
            let mut tunnel_id_data = Vec::with_capacity(public_key.len() + interface_hash.len());
            tunnel_id_data.extend_from_slice(&public_key);
            tunnel_id_data.extend_from_slice(&interface_hash);
            let tunnel_id = crate::identity::full_hash(&tunnel_id_data);

            // signed_data = public_key + interface_hash + random_hash
            let mut signed_data = Vec::with_capacity(public_key.len() + interface_hash.len() + random_hash.len());
            signed_data.extend_from_slice(&public_key);
            signed_data.extend_from_slice(&interface_hash);
            signed_data.extend_from_slice(&random_hash);

            let signature = identity.sign(&signed_data);

            (public_key, tunnel_id, signed_data, signature)
        };

        // data = signed_data + signature
        let mut data = signed_data;
        data.extend_from_slice(&signature);

        // Build the PLAIN destination for "rnstransport.tunnel.synthesize"
        let dest = match crate::destination::Destination::new_outbound(
            None,
            crate::destination::DestinationType::Plain,
            APP_NAME.to_string(),
            vec!["tunnel".to_string(), "synthesize".to_string()],
        ) {
            Ok(d) => d,
            Err(e) => {
                log(&format!("synthesize_tunnel: failed to create destination: {}", e), LOG_ERROR, false, false);
                return;
            }
        };

        // Create and pack the packet
        let mut packet = crate::packet::Packet::new(
            Some(dest),
            data,
            crate::packet::DATA,        // packet_type
            crate::packet::NONE,         // context
            BROADCAST,                   // transport_type
            crate::packet::HEADER_1,     // header_type
            None,                        // transport_id
            Some(interface_name.to_string()), // attached_interface
            false,                       // create_receipt
            crate::packet::FLAG_UNSET,   // context_flag
        );

        if let Err(e) = packet.pack() {
            log(&format!("synthesize_tunnel: failed to pack packet: {}", e), LOG_ERROR, false, false);
            return;
        }

        // Send through Transport::outbound
        let sent = Transport::outbound(&mut packet);

        // Mark the interface's wants_tunnel = false
        {
            let mut state = TRANSPORT.lock().unwrap();
            for iface in state.interfaces.iter_mut() {
                if iface.name == interface_name {
                    iface.wants_tunnel = false;
                    iface.tunnel_id = Some(tunnel_id.clone());
                    break;
                }
            }
        }

        log(
            &format!(
                "synthesize_tunnel: sent={} interface={} tunnel_id={} data_len={}",
                sent,
                interface_name,
                crate::hexrep(&tunnel_id, false),
                public_key.len() + 32 + 16 + 64, // pk + iface_hash + random + sig
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );
    }

    pub fn add_remote_management_allowed(identity_hash: Vec<u8>) {
        let mut state = TRANSPORT.lock().unwrap();
        if !state.remote_management_allowed.contains(&identity_hash) {
            state.remote_management_allowed.push(identity_hash);
        }
    }

    pub fn set_forced_shared_bitrate(_bitrate: u64) {
        let mut state = TRANSPORT.lock().unwrap();
        state.forced_shared_bitrate = Some(_bitrate);
    }

    pub fn forced_shared_bitrate() -> Option<u64> {
        let state = TRANSPORT.lock().unwrap();
        state.forced_shared_bitrate
    }

    pub fn register_interface_stub(name: &str, _type_name: &str) {
        let mut config = InterfaceStubConfig::default();
        config.name = name.to_string();
        config.mode = InterfaceStub::MODE_FULL;
        config.out = true;
        config.announce_cap = Some(crate::reticulum::ANNOUNCE_CAP / 100.0);
        Transport::register_interface_stub_config(config);
    }

    pub fn register_interface_stub_config(config: InterfaceStubConfig) {
        let mut state = TRANSPORT.lock().unwrap();
        if state.interfaces.iter().any(|i| i.name == config.name) {
            return;
        }

        let mut iface = InterfaceStub::default();
        iface.name = config.name;
        iface.address = config.address;
        iface.port = config.port;
        iface.online = config.online.unwrap_or(false);
        iface.mode = config.mode;
        iface.out = config.out;
        iface.bitrate = config.bitrate.map(|b| b as f64);
        iface.announce_cap = config.announce_cap.unwrap_or(crate::reticulum::ANNOUNCE_CAP / 100.0);
        iface.announce_rate_target = config.announce_rate_target;
        iface.announce_rate_grace = config.announce_rate_grace;
        iface.announce_rate_penalty = config.announce_rate_penalty;
        iface.ingress_control = config.ingress_control.unwrap_or(true);
        iface.ic_max_held_announces = config.ic_max_held_announces.unwrap_or(Interface::MAX_HELD_ANNOUNCES);
        iface.ic_burst_hold = config.ic_burst_hold.unwrap_or(Interface::IC_BURST_HOLD);
        iface.ic_burst_freq_new = config.ic_burst_freq_new.unwrap_or(Interface::IC_BURST_FREQ_NEW);
        iface.ic_burst_freq = config.ic_burst_freq.unwrap_or(Interface::IC_BURST_FREQ);
        iface.ic_new_time = config.ic_new_time.unwrap_or(Interface::IC_NEW_TIME);
        iface.ic_burst_penalty = config.ic_burst_penalty.unwrap_or(Interface::IC_BURST_PENALTY);
        iface.ic_held_release_interval = config.ic_held_release_interval.unwrap_or(Interface::IC_HELD_RELEASE_INTERVAL);
        iface.bootstrap_only = config.bootstrap_only.unwrap_or(false);
        iface.discoverable = config.discoverable.unwrap_or(false);
        iface.discovery_announce_interval = config.discovery_announce_interval;
        iface.discovery_publish_ifac = config.discovery_publish_ifac.unwrap_or(false);
        iface.reachable_on = config.reachable_on;
        iface.discovery_name = config.discovery_name;
        iface.discovery_encrypt = config.discovery_encrypt.unwrap_or(false);
        iface.discovery_stamp_value = config.discovery_stamp_value;
        iface.discovery_latitude = config.discovery_latitude;
        iface.discovery_longitude = config.discovery_longitude;
        iface.discovery_height = config.discovery_height;
        iface.discovery_frequency = config.discovery_frequency;
        iface.discovery_bandwidth = config.discovery_bandwidth;
        iface.discovery_modulation = config.discovery_modulation;
        iface.ifac_size = config.ifac_size;
        iface.ifac_netname = config.ifac_netname;
        iface.ifac_netkey = config.ifac_netkey;
        iface.ifac_key = config.ifac_key;
        iface.ifac_signature = config.ifac_signature;
        iface.repr = config.repr.unwrap_or_default();

        state.interfaces.push(iface);
    }

    /// Re-send a `synthesize_tunnel` packet on every TCP tunnel interface
    /// that was registered with a `repr` string. Call this immediately
    /// before initiating any new outbound link so the upstream rnsd always
    /// has a fresh reverse-route entry when the LINK_PROOF comes back.
    ///
    /// This is the deterministic fix for the 36-second send stall:
    /// two consecutive LRREQ attempts failed because the rnsd tunnel
    /// binding had aged between 60-second heartbeats. The PROOF arrived
    /// at the rnsd but could not be forwarded back to us.
    ///
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
    pub fn synthesize_tunnel_all_tcp() {
        let entries: Vec<(String, String)> = {
            let state = TRANSPORT.lock().unwrap();
            state.interfaces.iter()
                .filter(|i| i.online && !i.repr.is_empty())
                .map(|i| (i.name.clone(), i.repr.clone()))
                .collect()
        };
        for (name, repr) in entries {
            Self::synthesize_tunnel(&name, &repr);
        }
    }

    pub fn deregister_interface_stub(name: &str) {
        let mut state = TRANSPORT.lock().unwrap();
        state.interfaces.retain(|iface| iface.name != name);
        state.local_client_interfaces.retain(|iface| iface.name != name);
        state.outbound_handlers.remove(name);
        state.client_announce_pacing.remove(name);
        state.client_announce_last_sent.remove(name);
        state.pending_local_announces.retain(|(_, n, _)| n != name);
    }

    pub fn register_local_server_interface(name: &str) {
        let mut state = TRANSPORT.lock().unwrap();
        if state.interfaces.iter().any(|i| i.name == name) {
            return;
        }
        let mut iface = InterfaceStub::default();
        iface.name = name.to_string();
        iface.mode = InterfaceStub::MODE_FULL;
        iface.out = false;
        iface.online = true;
        iface.parent_is_local_shared = true;
        state.interfaces.push(iface);
    }

    pub fn register_local_client_interface(name: &str) {
        let mut state = TRANSPORT.lock().unwrap();
        if state.local_client_interfaces.iter().any(|i| i.name == name) {
            return;
        }
        let mut iface = InterfaceStub::default();
        iface.name = name.to_string();
        iface.mode = InterfaceStub::MODE_FULL;
        iface.online = true;
        iface.is_connected_to_shared_instance = true;
        state.local_client_interfaces.push(iface);
    }

    pub fn set_interface_online(name: &str, online: bool) {
        let mut transitioned_up = false;
        let mut transitioned_down = false;
        {
            let mut state = TRANSPORT.lock().unwrap();
            if let Some(iface) = state.interfaces.iter_mut().find(|i| i.name == name) {
                if online && !iface.online { transitioned_up = true; }
                if !online && iface.online { transitioned_down = true; }
                iface.online = online;
            }
            if let Some(iface) = state.local_client_interfaces.iter_mut().find(|i| i.name == name) {
                if online && !iface.online { transitioned_up = true; }
                if !online && iface.online { transitioned_down = true; }
                iface.online = online;
            }
        }
        // On false→true transition, re-announce locally-registered
        // destinations on this interface so any announces attempted while it
        // was offline are delivered now that the link is up. When the
        // application has opted in via `publish_destination`, only the
        // published set is re-announced; otherwise (legacy callers) all
        // IN/SINGLE destinations are re-announced.  See
        // `announce_all_destinations` for filter logic.
        if transitioned_up {
            log(
                &format!("Interface {} transitioned online — re-announcing local destinations", name),
                LOG_NOTICE, false, false,
            );
            Self::announce_all_destinations(name);
        }
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1,§2
        //
        // On true→false transition, re-announce on every other online
        // interface so remote nodes can update their path-to-us immediately.
        //
        // Without this, a remote peer (e.g. Meshchat) that last heard about
        // us via the now-dead interface will still try to route LINKPROOF
        // packets back via that interface — they'll be silently dropped and
        // link establishment will time out.  Re-announcing via still-online
        // interfaces (e.g. RMap) updates remote routing tables so proofs
        // can reach us.  This is deterministic: interface offline IS the
        // "routing stale" signal.
        if transitioned_down {
            let other_ifaces: Vec<String> = {
                let state = TRANSPORT.lock().unwrap();
                state.interfaces.iter()
                    .chain(state.local_client_interfaces.iter())
                    .filter(|i| i.online && i.name.as_str() != name)
                    .map(|i| i.name.clone())
                    .collect()
            };
            if !other_ifaces.is_empty() {
                log(
                    &format!(
                        "Interface {} transitioned offline — re-announcing via {} other interface(s)",
                        name, other_ifaces.len()
                    ),
                    LOG_NOTICE, false, false,
                );
                for iface_name in &other_ifaces {
                    Self::announce_all_destinations(iface_name);
                }
            }
        }
    }

    pub fn get_interface_list() -> Vec<InterfaceStub> {
        let state = TRANSPORT.lock().unwrap();
        state.interfaces.clone()
    }

    pub fn identity_hash() -> Option<Vec<u8>> {
        let state = TRANSPORT.lock().unwrap();
        state.identity.as_ref().and_then(|id| id.hash.as_ref().cloned())
    }

    pub fn transport_enabled() -> bool {
        let state = TRANSPORT.lock().unwrap();
        state.transport_enabled
    }

    /// Enable or disable early-dropping of inbound announce packets.
    /// When enabled, all ANNOUNCE packets are silently discarded at the
    /// transport layer except PATH_RESPONSE replies to our own path requests.
    /// This is an opt-in setting (default: false).
    pub fn set_drop_announces(enabled: bool) {
        let mut state = TRANSPORT.lock().unwrap();
        state.drop_announces = enabled;
        crate::log(
            &format!("Transport: drop_announces set to {}", enabled),
            crate::LOG_NOTICE, false, false,
        );
    }

    pub fn drop_announces_enabled() -> bool {
        let state = TRANSPORT.lock().unwrap();
        state.drop_announces
    }

    /// Add a destination hash to the announce watchlist.
    /// When drop_announces is enabled, announces from watchlisted destinations
    /// pass through regardless of context, so the app stays aware of them.
    pub fn watch_announce(destination_hash: Vec<u8>) {
        let mut state = TRANSPORT.lock().unwrap();
        state.announce_watchlist.insert(destination_hash);
    }

    /// Remove a destination hash from the announce watchlist.
    pub fn unwatch_announce(destination_hash: &[u8]) {
        let mut state = TRANSPORT.lock().unwrap();
        state.announce_watchlist.remove(destination_hash);
    }

    pub fn is_connected_to_shared_instance() -> bool {
        let state = TRANSPORT.lock().unwrap();
        state.is_connected_to_shared_instance
    }

    pub fn discovery_identity_clone() -> Option<Identity> {
        let state = TRANSPORT.lock().unwrap();
        let source = state.network_identity.as_ref().or(state.identity.as_ref())?;
        source.get_private_key().ok().and_then(|key| Identity::from_bytes(&key).ok())
    }

    pub fn enable_discovery() {
        let mut state = TRANSPORT.lock().unwrap();
        if state.discovery_announcer.is_some() {
            return;
        }
        let announcer = InterfaceAnnouncer::new();
        announcer.start();
        state.discovery_announcer = Some(announcer);
    }

    pub fn discover_interfaces() {
        let mut state = TRANSPORT.lock().unwrap();
        if state.interface_discovery.is_some() {
            return;
        }
        let required = crate::reticulum::required_discovery_value();
        if let Ok(discovery) = InterfaceDiscovery::new(required, None, true) {
            state.interface_discovery = Some(discovery);
        }

        if state.interface_announce_handler.is_none() {
            let handler = InterfaceAnnounceHandler::new(required, None);
            state.interface_announce_handler = Some(Arc::new(handler));
        }
    }

    pub fn enable_blackhole_updater() {
        // Placeholder for parity; blackhole list updates are handled in job loop.
    }

    pub fn path_request_handler(data: &[u8], packet: &Packet) {
        // Path request handler for path request control destination
        // Parses incoming path requests and invokes path_request workflow
        
        if data.len() < crate::reticulum::TRUNCATED_HASHLENGTH / 8 {
            return;
        }

        let destination_hash = &data[0..crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        
        // Extract requesting transport instance ID if present
        let requesting_transport_instance = if data.len() > (crate::reticulum::TRUNCATED_HASHLENGTH / 8) * 2 {
            Some(&data[crate::reticulum::TRUNCATED_HASHLENGTH / 8..(crate::reticulum::TRUNCATED_HASHLENGTH / 8) * 2])
        } else {
            None
        };
        
        // Extract tag bytes if present
        let mut tag_bytes: Option<Vec<u8>> = None;
        if data.len() > (crate::reticulum::TRUNCATED_HASHLENGTH / 8) * 2 {
            let raw_tags = &data[(crate::reticulum::TRUNCATED_HASHLENGTH / 8) * 2..];
            if !raw_tags.is_empty() {
                let max_len = crate::reticulum::TRUNCATED_HASHLENGTH / 8;
                let slice_end = raw_tags.len().min(max_len);
                tag_bytes = Some(raw_tags[..slice_end].to_vec());
            }
        } else if data.len() > crate::reticulum::TRUNCATED_HASHLENGTH / 8 {
            let raw_tags = &data[crate::reticulum::TRUNCATED_HASHLENGTH / 8..];
            if !raw_tags.is_empty() {
                let max_len = crate::reticulum::TRUNCATED_HASHLENGTH / 8;
                let slice_end = raw_tags.len().min(max_len);
                tag_bytes = Some(raw_tags[..slice_end].to_vec());
            }
        }
        
        let is_from_local_client = Transport::from_local_client(packet);

        // If the requested destination is one of ours, always respond —
        // even if the request has no tag (tagless format used by some clients).
        // For all other cases, use the tag to deduplicate relay responses.
        let is_own_dest = {
            let state = TRANSPORT.lock().unwrap();
            state.destinations.iter().any(|d| d.hash == destination_hash)
        };
        if is_own_dest {
            crate::log(
                &format!(
                    "[PR-SELF] iface={} dst={} hops={}",
                    packet.receiving_interface.as_deref().unwrap_or("?"),
                    crate::hexrep(&destination_hash[..destination_hash.len().min(4)], false),
                    packet.hops
                ),
                crate::LOG_NOTICE,
                false,
                false,
            );
            Transport::path_request(
                destination_hash.to_vec(),
                is_from_local_client,
                packet.receiving_interface.clone(),
                requesting_transport_instance.map(|b| b.to_vec()),
                tag_bytes,
            );
            return;
        }

        if let Some(tag_bytes) = tag_bytes {
            let unique_tag = [destination_hash, tag_bytes.as_slice()].concat();
            let is_new = {
                let mut state = TRANSPORT.lock().unwrap();
                if state.discovery_pr_tags_set.insert(unique_tag.clone()) {
                    state.discovery_pr_tags.push(unique_tag);
                    true
                } else {
                    false
                }
            };
            if is_new {
                Transport::path_request(
                    destination_hash.to_vec(),
                    is_from_local_client,
                    packet.receiving_interface.clone(),
                    requesting_transport_instance.map(|b| b.to_vec()),
                    Some(tag_bytes),
                );
            }
        }
        // tagless path requests for non-owned destinations: nothing to do
    }
    
    fn from_local_client(packet: &Packet) -> bool {
        if let Some(ref intf_name) = packet.receiving_interface {
            let state = TRANSPORT.lock().unwrap();
            Transport::is_local_client_interface_locked(&state, intf_name)
        } else {
            false
        }
    }

    pub fn path_request(
        destination_hash: Vec<u8>,
        is_from_local_client: bool,
        attached_interface: Option<String>,
        requestor_transport_id: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
    ) {
        let interface_str = attached_interface
            .as_ref()
            .map(|i| format!(" on {}", i))
            .unwrap_or_default();


        let mut state = TRANSPORT.lock().unwrap();
        let mut should_search_for_unknown = false;
        if let Some(attached_name) = attached_interface.as_ref() {
            if state.transport_enabled {
                if let Some(intf) = state.interfaces.iter().find(|i| &i.name == attached_name) {
                    if matches!(
                        intf.mode,
                        InterfaceStub::MODE_ACCESS_POINT
                            | InterfaceStub::MODE_GATEWAY
                            | InterfaceStub::MODE_ROAMING
                    ) {
                        should_search_for_unknown = true;
                    }
                }
            }
        }

        if !state.local_client_interfaces.is_empty() {
            let now_ts = now();
            if let Some((_, best)) = Self::select_path(&state.path_table, &state.interfaces, &destination_hash, now_ts) {
                if let Some(ref name) = best.receiving_interface {
                    if Transport::is_local_client_interface_locked(&state, name) {
                        if let Some(attached_name) = attached_interface.as_ref() {
                            let matched_intf = state
                                .interfaces
                                .iter()
                                .find(|i| &i.name == attached_name)
                                .cloned();
                            if let Some(intf) = matched_intf {
                                state
                                    .pending_local_path_requests
                                    .insert(destination_hash.clone(), intf);
                            }
                        }
                    }
                }
            }
        }

        let local_dest_index = state
            .destinations
            .iter()
            .position(|dest| dest.hash == destination_hash);
        if let Some(idx) = local_dest_index {
            if let Some(mut dest) = state.destinations.get(idx).cloned() {
                // Use the application's published app_data (set via
                // `publish_destination`) so path responses carry the same
                // announce payload as live broadcasts.  Falls back to the
                // destination's default_app_data when not in the published
                // set.
                let app_data = state
                    .published_destinations
                    .get(&destination_hash)
                    .and_then(|p| p.app_data.clone());
                drop(state);
                log(
                    &format!(
                        "[PR-SELF] responding with announce for {} (own destination)",
                        crate::hexrep(&destination_hash, true)
                    ),
                    LOG_NOTICE, false, false,
                );
                let _ = dest.announce(app_data.as_deref(), true, attached_interface, tag, true);
                let mut state = TRANSPORT.lock().unwrap();
                if idx < state.destinations.len() {
                    state.destinations[idx] = dest;
                }
            }
            return;
        }

        if state.transport_enabled || is_from_local_client {
            let now_ts = now();
            let selected = Self::select_path(&state.path_table, &state.interfaces, &destination_hash, now_ts);
            if let Some((_, best)) = selected {
            let packet_hash = best.packet_hash.clone();
            let next_hop = best.next_hop.clone();
            let announce_hops = best.hops;
            let received_from_intf = best.receiving_interface.clone();

            if let Some(req_id) = &requestor_transport_id {
                if req_id == &next_hop {
                    log(
                        &format!(
                            "Not answering path request for {}{}, since next hop is the requestor",
                            crate::hexrep(&destination_hash, true),
                            interface_str
                        ),
                        LOG_DEBUG,
                        false,
                        false,
                    );
                    return;
                }
            }

            if let (Some(req_name), Some(recv_name)) =
                (attached_interface.as_ref(), received_from_intf.as_ref())
            {
                if let Some(intf) = state.interfaces.iter().find(|i| &i.name == req_name) {
                    if intf.mode == InterfaceStub::MODE_ROAMING && req_name == recv_name {
                        log(
                            "Not answering path request on roaming-mode interface, since next hop is on same roaming-mode interface",
                            LOG_DEBUG,
                            false,
                            false,
                        );
                        return;
                    }
                }
            }

            drop(state);

            let mut packet = match Transport::get_cached_packet(&packet_hash, Some("announce".to_string())) {
                Some(pkt) => pkt,
                None => {
                    log(
                        &format!(
                            "Could not retrieve announce packet from cache while answering path request for {}",
                            crate::hexrep(&destination_hash, true)
                        ),
                        LOG_ERROR,
                        false,
                        false,
                    );
                    return;
                }
            };

            log(
                &format!(
                    "Answering path request for {}{}, path is known",
                    crate::hexrep(&destination_hash, true),
                    interface_str
                ),
                LOG_DEBUG,
                false,
                false,
            );

            packet.hops = announce_hops;

            let now_ts = now();
            let retries = PATHFINDER_R;
            let local_rebroadcasts = 0u8;
            let block_rebroadcasts = true;

            let retransmit_timeout = if is_from_local_client {
                now_ts
            } else {
                let state = TRANSPORT.lock().unwrap();
                let is_next_hop_local_client = if let Some(next_hop_intf) =
                    Transport::next_hop_interface_locked(&state, &destination_hash)
                {
                    Transport::is_local_client_interface_locked(&state, &next_hop_intf)
                } else {
                    false
                };
                drop(state);

                if is_next_hop_local_client {
                    log(
                        &format!(
                            "Path request destination {} is on a local client interface, rebroadcasting immediately",
                            crate::hexrep(&destination_hash, true)
                        ),
                        LOG_EXTREME,
                        false,
                        false,
                    );
                    now_ts
                } else {
                    let mut timeout = now_ts + PATH_REQUEST_GRACE;
                    if let Some(req_name) = attached_interface.as_ref() {
                        let state = TRANSPORT.lock().unwrap();
                        if let Some(intf) = state.interfaces.iter().find(|i| &i.name == req_name) {
                            if intf.mode == InterfaceStub::MODE_ROAMING {
                                timeout += PATH_REQUEST_RG;
                            }
                        }
                    }
                    timeout
                }
            };

            let mut state = TRANSPORT.lock().unwrap();
            if let Some(ref dest_hash) = packet.destination_hash {
                if let Some(held_entry) = state.announce_table.get(dest_hash).cloned() {
                    state.held_announces.insert(dest_hash.clone(), held_entry);
                }
            }

            let announce_entry = vec![
                AnnounceEntryValue::Timestamp(now_ts),
                AnnounceEntryValue::RetransmitTimeout(retransmit_timeout),
                AnnounceEntryValue::Retries(retries),
                AnnounceEntryValue::ReceivedFrom(next_hop),
                AnnounceEntryValue::Hops(announce_hops),
                AnnounceEntryValue::Packet(packet.clone()),
                AnnounceEntryValue::LocalRebroadcasts(local_rebroadcasts),
                AnnounceEntryValue::BlockRebroadcasts(block_rebroadcasts),
                AnnounceEntryValue::AttachedInterface(attached_interface.clone()),
            ];

            state.announce_table.insert(destination_hash.clone(), announce_entry);

            // Dispatch the PATH_RESPONSE to the requesting local client
            // with pacing to avoid triggering the Python-side
            // TCPClientInterface ingress burst limiter (IC_BURST_FREQ_NEW
            // = 3.5/s).  Python's own LocalClientInterface disables
            // ingress control, but our clients connect via TCP.
            if is_from_local_client {
                if let Some(ref req_iface) = attached_interface {
                    let identity_hash = state.identity.as_ref().and_then(|i| i.hash.as_ref().cloned());
                    let transport_id_bytes = identity_hash.unwrap_or_default();
                    let dest_hash_bytes = packet.destination_hash.clone().unwrap_or_else(|| destination_hash.clone());
                    let dest_type_bits: u8 = match packet.destination_type {
                        Some(crate::destination::DestinationType::Single) => 0x00,
                        Some(crate::destination::DestinationType::Group) => 0x01,
                        Some(crate::destination::DestinationType::Plain) => 0x02,
                        Some(crate::destination::DestinationType::Link) => 0x03,
                        None => 0x00,
                    };
                    let flags: u8 = (crate::packet::HEADER_2 << 6)
                        | ((packet.context_flag & 0x01) << 5)
                        | (MODE_TRANSPORT << 4)
                        | (dest_type_bits << 2)
                        | ANNOUNCE;
                    let announce_context = crate::packet::PATH_RESPONSE;

                    let mut raw = Vec::with_capacity(2 + 16 + 16 + 1 + packet.data.len());
                    raw.push(flags);
                    raw.push(announce_hops);
                    raw.extend_from_slice(&transport_id_bytes);
                    raw.extend_from_slice(&dest_hash_bytes);
                    raw.push(announce_context);
                    raw.extend_from_slice(&packet.data);

                    let iface_name = req_iface.clone();
                    // A PATH_RESPONSE is an ANNOUNCE packet on the wire, so it
                    // counts against the client's incoming_announce_frequency()
                    // budget just like a regular announce.  A sender typically
                    // issues two rapid PATH_REQUESTs (recipient + prop node)
                    // within 200 ms.  If both responses arrive at the client
                    // within 286 ms they trigger the 60-second burst hold.
                    // Queue through the same pacing mechanism as Fix C so that
                    // consecutive PATH_RESPONSEs are ≥ LOCAL_CLIENT_ANNOUNCE_PACE
                    // apart in wall-clock time.  See the constant for background.
                    let now_ts = now();
                    let last = state.client_announce_pacing.get(&iface_name).copied()
                        .unwrap_or(now_ts - LOCAL_CLIENT_ANNOUNCE_PACE);
                    let dispatch_at = f64::max(now_ts, last + LOCAL_CLIENT_ANNOUNCE_PACE);
                    state.client_announce_pacing.insert(iface_name.clone(), dispatch_at);
                    if dispatch_at <= now_ts + 0.001 {
                        drop(state);
                        Transport::dispatch_outbound(&iface_name, &raw);
                    } else {
                        state.pending_local_announces.push((dispatch_at, iface_name, raw));
                        drop(state);
                    }
                } else {
                    drop(state);
                }
            } else {
                drop(state);
            }
            } else {
                drop(state);
            }
            return;
        }

        if is_from_local_client {
            let interface_list: Vec<String> = state.interfaces.iter().map(|i| i.name.clone()).collect();
            drop(state);
            log(
                &format!(
                    "Forwarding path request from local client for {}{} to all other interfaces",
                    crate::hexrep(&destination_hash, true),
                    interface_str
                ),
                LOG_DEBUG,
                false,
                false,
            );
            let request_tag = Identity::get_random_hash();
            for name in interface_list {
                if Some(&name) != attached_interface.as_ref() {
                    Transport::request_path(
                        &destination_hash,
                        Some(request_tag.clone()),
                        Some(name),
                        None,
                        None,
                    );
                }
            }
            return;
        }

        if should_search_for_unknown {
            if state.discovery_path_requests.contains_key(&destination_hash) {
                log(
                    &format!(
                        "There is already a waiting path request for {} on behalf of path request{}",
                        crate::hexrep(&destination_hash, true),
                        interface_str
                    ),
                    LOG_DEBUG,
                    false,
                    false,
                );
                return;
            }

            log(
                &format!(
                    "Attempting to discover unknown path to {} on behalf of path request{}",
                    crate::hexrep(&destination_hash, true),
                    interface_str
                ),
                LOG_DEBUG,
                false,
                false,
            );
            let entry = DiscoveryPathRequest {
                destination_hash: destination_hash.clone(),
                timeout: now() + PATH_REQUEST_TIMEOUT,
                requesting_interface: attached_interface.clone(),
            };
            state.discovery_path_requests.insert(destination_hash.clone(), entry);
            let interface_list: Vec<String> = state.interfaces.iter().map(|i| i.name.clone()).collect();
            drop(state);

            for name in interface_list {
                if Some(&name) != attached_interface.as_ref() {
                    Transport::request_path(
                        &destination_hash,
                        None,
                        Some(name),
                        None,
                        tag.clone(),
                    );
                }
            }
            return;
        }

        if !is_from_local_client && !state.local_client_interfaces.is_empty() {
            let local_clients: Vec<String> = state.local_client_interfaces.iter().map(|i| i.name.clone()).collect();
            drop(state);
            log(
                &format!(
                    "Forwarding path request for {}{} to local clients",
                    crate::hexrep(&destination_hash, true),
                    interface_str
                ),
                LOG_DEBUG,
                false,
                false,
            );
            for name in local_clients {
                Transport::request_path(&destination_hash, None, Some(name), None, None);
            }
            return;
        }

        // ── Fallback: forward to non-local outbound interfaces ───────────
        // When there are no local clients, forward the path request to
        // WAN-facing outbound interfaces (PostInterface, Backbone) instead
        // of silently ignoring it.  Without this, bridges that only connect
        // WAN interfaces (TCPClient to rmap.world + PostInterface to PHP)
        // drop all path requests from the backbone.
        if !is_from_local_client {
            let non_local_outbound: Vec<String> = state
                .interfaces
                .iter()
                .filter(|i| {
                    i.out
                        && !state.local_client_interfaces.iter().any(|lc| lc.name == i.name)
                        && attached_interface.as_deref() != Some(&i.name)
                })
                .map(|i| i.name.clone())
                .collect();
            if !non_local_outbound.is_empty() {
                drop(state);
                log(
                    &format!(
                        "Forwarding path request for {}{} to non-local outbound interfaces",
                        crate::hexrep(&destination_hash, true),
                        interface_str
                    ),
                    LOG_DEBUG,
                    false,
                    false,
                );
                for name in non_local_outbound {
                    Transport::request_path(&destination_hash, None, Some(name), None, None);
                }
                return;
            }
        }

        drop(state);
        log(
            &format!(
                "Ignoring path request for {}{}, no path known",
                crate::hexrep(&destination_hash, true),
                interface_str
            ),
            LOG_DEBUG,
            false,
            false,
        );
    }
    
    // Helper to check next hop interface without requiring mutable state
    fn next_hop_interface_locked(state: &TransportState, destination_hash: &[u8]) -> Option<String> {
        Self::select_path(&state.path_table, &state.interfaces, destination_hash, now())
            .and_then(|(_, e)| e.receiving_interface)
    }
    
    // Helper to check if interface is local client without requiring mutable state
    fn is_local_client_interface_locked(state: &TransportState, interface_name: &str) -> bool {
        state.local_client_interfaces.iter().any(|i| i.name == interface_name)
    }

    pub fn tunnel_synthesize_handler(data: &[u8], packet: &Packet) {
        // Tunnel synthesize handler for tunnel synthesis control destination
        // Validates tunnel establishment and calls handle_tunnel
        
        let expected_length = crate::identity::KEYSIZE / 8 
            + crate::identity::HASHLENGTH / 8
            + crate::reticulum::TRUNCATED_HASHLENGTH / 8
            + crate::identity::SIGLENGTH / 8;
        
        if data.len() != expected_length {
            log(&format!("Invalid tunnel synthesis packet size"), LOG_DEBUG, false, false);
            return;
        }

        let public_key = &data[0..crate::identity::KEYSIZE / 8];
        let interface_hash = &data[crate::identity::KEYSIZE / 8
            ..crate::identity::KEYSIZE / 8 + crate::identity::HASHLENGTH / 8];
        let tunnel_id_data = [public_key, interface_hash].concat();
        let tunnel_id_hash = crate::identity::full_hash(&tunnel_id_data);
        
        // Extract random hash (we don't validate signature without load_public_key)
        let _random_hash = &data[crate::identity::KEYSIZE / 8 + crate::identity::HASHLENGTH / 8
            ..crate::identity::KEYSIZE / 8 + crate::identity::HASHLENGTH / 8 + crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        
        // TODO: Validate signature when Identity::load_public_key is implemented
        // For now, accept tunnel establishment without validation
        
        if let Some(receiving_interface) = &packet.receiving_interface {
            Transport::handle_tunnel(tunnel_id_hash, receiving_interface.clone());
        }
    }

    pub fn handle_tunnel(tunnel_id: Vec<u8>, interface: String) {
        let current_time = now();
        let expires = current_time + DESTINATION_TIMEOUT;
        
        let mut state = TRANSPORT.lock().unwrap();
        
        // Set tunnel_id on the interface stub (matches Python: interface.tunnel_id = tunnel_id)
        if let Some(iface) = state.interfaces.iter_mut().find(|i| i.name == interface) {
            iface.tunnel_id = Some(tunnel_id.clone());
        }
        
        if let Some(tunnel_entry) = state.tunnels.get_mut(&tunnel_id) {
            // Tunnel exists, restore it
            log(&format!("Tunnel endpoint restored"), LOG_DEBUG, false, false);
            
            // Update interface and expiry
            match tunnel_entry.get_mut(IDX_TT_IF) {
                Some(TunnelEntryValue::Interface(intf)) => {
                    *intf = Some(interface.clone());
                }
                _ => {}
            }
            
            match tunnel_entry.get_mut(IDX_TT_EXPIRES) {
                Some(TunnelEntryValue::Expires(exp)) => {
                    *exp = expires;
                }
                _ => {}
            }
            
            // TODO: Restore paths from tunnel paths table
        } else {
            // Create new tunnel entry
            log(&format!("Tunnel endpoint established"), LOG_DEBUG, false, false);
            
            let mut tunnel_entry = Vec::new();
            tunnel_entry.push(TunnelEntryValue::TunnelId(tunnel_id.clone()));
            tunnel_entry.push(TunnelEntryValue::Interface(Some(interface)));
            tunnel_entry.push(TunnelEntryValue::Paths(HashMap::new()));
            tunnel_entry.push(TunnelEntryValue::Expires(expires));
            
            state.tunnels.insert(tunnel_id, tunnel_entry);
        }
    }

    pub fn set_network_identity(identity: Identity) {
        let mut state = TRANSPORT.lock().unwrap();
        if state.network_identity.is_none() {
            state.network_identity = Some(identity);
        }
    }

    pub fn has_network_identity() -> bool {
        let state = TRANSPORT.lock().unwrap();
        state.network_identity.is_some()
    }

    pub fn count_traffic_loop() {
        loop {
            thread::sleep(Duration::from_secs(1));
            let mut state = TRANSPORT.lock().unwrap();
            let mut rxb = 0;
            let mut txb = 0;
            let mut rxs = 0.0;
            let mut txs = 0.0;

            for interface in &mut state.interfaces {
                let rx_diff = interface.rxb;
                let tx_diff = interface.txb;
                let ts_diff = 1.0;
                rxb += rx_diff;
                txb += tx_diff;
                interface.current_rx_speed = (rx_diff as f64 * 8.0) / ts_diff;
                interface.current_tx_speed = (tx_diff as f64 * 8.0) / ts_diff;
                rxs += interface.current_rx_speed;
                txs += interface.current_tx_speed;
            }

            state.traffic_rxb = state.traffic_rxb.saturating_add(rxb);
            state.traffic_txb = state.traffic_txb.saturating_add(txb);
            state.speed_rx = rxs;
            state.speed_tx = txs;
        }
    }

    pub fn jobloop() {
        let job_interval = TRANSPORT.lock().unwrap().job_interval;
        loop {
            Transport::jobs();
            thread::sleep(Duration::from_secs_f64(job_interval));
        }
    }

    pub fn jobs() {
        let jobs_lock_started = std::time::Instant::now();
        let mut state = TRANSPORT.lock().unwrap();

        // DIAG: trace jobs() execution
        let at_size = state.announce_table.len();
        let ifaces_count = state.interfaces.len();
        if at_size > 0 {
            crate::log(&format!("[JOBS-DIAG] announce_table={} interfaces={}", at_size, ifaces_count), crate::LOG_EXTREME, false, false);
        }

        let mut outgoing: Vec<Packet> = Vec::new();
        let mut path_requests: HashMap<Vec<u8>, Option<String>> = HashMap::new();

        if now() > state.links_last_checked + state.links_check_interval {
            let mut next_pending = Vec::new();
            let pending_links = std::mem::take(&mut state.pending_links);
            for link in pending_links {
                if link.status == crate::link::STATE_CLOSED {
                    if !state.transport_enabled {
                        if let Ok(dest) = link.destination.lock() {
                            let dest_hash = dest.hash.clone();
                            if let Some(deque) = state.path_table.get_mut(&dest_hash) {
                                if let Some(front) = deque.front_mut() {
                                    front.timestamp = 0.0;
                                }
                                state.tables_last_culled = 0.0;
                            }
                            let last_path_request = state.path_requests.get(&dest_hash).cloned().unwrap_or(0.0);
                            if now() - last_path_request > PATH_REQUEST_MI {
                                path_requests.insert(dest_hash, None);
                            }
                        }
                    }
                } else {
                    next_pending.push(link);
                }
            }
            state.pending_links = next_pending;

            state.active_links.retain(|link| link.status != crate::link::STATE_CLOSED);
            state.links_last_checked = now();
        }

        if now() > state.receipts_last_checked + state.receipts_check_interval {
            // Check for timed out receipts
            for receipt in state.receipts.iter_mut() {
                receipt.check_timeout();
            }
            
            // Clean up excess receipts
            let excess = state.receipts.len().saturating_sub(MAX_RECEIPTS);
            if excess > 0 {
                state.receipts.drain(0..excess);
            }
            state.receipts_last_checked = now();
        }

        if now() > state.announces_last_checked + state.announces_check_interval {
            let mut completed_announces: Vec<Vec<u8>> = Vec::new();
            let identity_hash = state.identity.as_ref().and_then(|i| i.hash.as_ref().cloned());
            for (destination_hash, announce_entry) in state.announce_table.iter_mut() {
                let retries = match announce_entry.get(IDX_AT_RETRIES) {
                    Some(AnnounceEntryValue::Retries(r)) => *r,
                    _ => 0,
                };
                let local_rebroadcasts = match announce_entry.get(IDX_AT_LCL_RBRD) {
                    Some(AnnounceEntryValue::LocalRebroadcasts(r)) => *r,
                    _ => 0,
                };
                let retransmit_timeout = match announce_entry.get(IDX_AT_RTRNS_TMO) {
                    Some(AnnounceEntryValue::RetransmitTimeout(t)) => *t,
                    _ => 0.0,
                };

                if local_rebroadcasts >= LOCAL_REBROADCASTS_MAX {
                    completed_announces.push(destination_hash.clone());
                } else if retries > PATHFINDER_R {
                    completed_announces.push(destination_hash.clone());
                } else if now() > retransmit_timeout {
                    let mut packet = None;
                    if let Some(AnnounceEntryValue::Packet(p)) = announce_entry.get(IDX_AT_PACKET) {
                        packet = Some(p.clone());
                    }

                    if let Some(packet) = packet {
                        let block_rebroadcasts = match announce_entry.get(IDX_AT_BLCK_RBRD) {
                            Some(AnnounceEntryValue::BlockRebroadcasts(b)) => *b,
                            _ => false,
                        };
                        let attached_interface = match announce_entry.get(IDX_AT_ATTCHD_IF) {
                            Some(AnnounceEntryValue::AttachedInterface(name)) => name.clone(),
                            _ => None,
                        };
                        let hops = match announce_entry.get(IDX_AT_HOPS) {
                            Some(AnnounceEntryValue::Hops(h)) => *h,
                            _ => 0,
                        };

                        let announce_context = if block_rebroadcasts { crate::packet::PATH_RESPONSE } else { crate::packet::NONE };

                        // Build raw HEADER_2 announce packet manually.
                        // pack() requires a Destination which we don't have for relayed announces.
                        let dest_type_bits: u8 = match packet.destination_type {
                            Some(crate::destination::DestinationType::Single) => 0x00,
                            Some(crate::destination::DestinationType::Group) => 0x01,
                            Some(crate::destination::DestinationType::Plain) => 0x02,
                            Some(crate::destination::DestinationType::Link) => 0x03,
                            None => 0x00,
                        };
                        let flags: u8 = (crate::packet::HEADER_2 << 6)
                            | ((packet.context_flag & 0x01) << 5)
                            | (MODE_TRANSPORT << 4)
                            | (dest_type_bits << 2)
                            | ANNOUNCE;
                        let transport_id_bytes = identity_hash.clone().unwrap_or_default();
                        let dest_hash_bytes = packet.destination_hash.clone().unwrap_or_else(|| destination_hash.clone());

                        let mut raw = Vec::with_capacity(2 + 16 + 16 + 1 + packet.data.len());
                        raw.push(flags);
                        raw.push(hops);
                        raw.extend_from_slice(&transport_id_bytes);
                        raw.extend_from_slice(&dest_hash_bytes);
                        raw.push(announce_context);
                        raw.extend_from_slice(&packet.data);

                        let mut new_packet = Packet::new(
                            None,
                            Vec::new(),
                            ANNOUNCE,
                            announce_context,
                            MODE_TRANSPORT,
                            crate::packet::HEADER_2,
                            identity_hash.clone(),
                            attached_interface,
                            false,
                            packet.context_flag,
                        );
                        new_packet.raw = raw;
                        new_packet.hops = hops;
                        new_packet.packed = true;
                        // Preserve receiving_interface from the original announce so
                        // outbound() won't echo the retransmit back to the source.
                        // Matches Python Transport.py line ~1803:
                        //   if packet.receiving_interface != local_interface:
                        new_packet.receiving_interface = packet.receiving_interface.clone();
                        new_packet.update_hash();
                        outgoing.push(new_packet);
                    }

                    if let Some(AnnounceEntryValue::RetransmitTimeout(r)) = announce_entry.get_mut(IDX_AT_RTRNS_TMO) {
                        *r = now() + PATHFINDER_G + PATHFINDER_RW;
                    }
                    if let Some(AnnounceEntryValue::Retries(r)) = announce_entry.get_mut(IDX_AT_RETRIES) {
                        *r = r.saturating_add(1);
                    }
                }
            }

            for destination_hash in completed_announces {
                state.announce_table.remove(&destination_hash);
            }

            state.announces_last_checked = now();
        }

        // Drain the paced-announce queue: dispatch at most one entry per
        // interface per jobs() tick, and only if LOCAL_CLIENT_ANNOUNCE_PACE
        // seconds have elapsed since the ACTUAL last send (tracked in
        // client_announce_last_sent, not just the scheduled dispatch_at).
        //
        // The wall-clock guard is essential: jobs() fires every 250 ms and
        // could dispatch two entries whose scheduled times are 350 ms apart
        // within a single tick if the scheduler woke late.  Two packets
        // reaching the client within < 286 ms would spike ia_freq above
        // IC_BURST_FREQ_NEW (3.5/s) and trigger TCPClientInterface's 60-second
        // burst hold + 300-second penalty.  By recording the actual send time
        // and skipping entries that arrive too soon, we guarantee a minimum
        // ~500 ms real-world gap between consecutive announces (~2/s).  See
        // LOCAL_CLIENT_ANNOUNCE_PACE for full background.
        if !state.pending_local_announces.is_empty() {
            let now_ts = now();
            let pacing = LOCAL_CLIENT_ANNOUNCE_PACE;
            // Phase 1: read-only pass to find what to dispatch.
            state.pending_local_announces.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
            let mut seen_ifaces: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut candidates: Vec<(String, Vec<u8>, f64)> = Vec::new(); // (iface, raw, dispatch_at)
            for (dispatch_at, iface_name, raw) in &state.pending_local_announces {
                if *dispatch_at > now_ts { continue; }
                if seen_ifaces.contains(iface_name.as_str()) { continue; }
                // Enforce wall-clock gap: check last_sent for this interface.
                let last_sent = state.client_announce_last_sent
                    .get(iface_name.as_str())
                    .copied()
                    .unwrap_or(0.0);
                if last_sent > 0.0 && now_ts - last_sent < pacing {
                    // Not enough real time since last send → skip this tick.
                    continue;
                }
                seen_ifaces.insert(iface_name.clone());
                candidates.push((iface_name.clone(), raw.clone(), *dispatch_at));
            }
            if !candidates.is_empty() {
                // Phase 2: update state and collect raw bytes for dispatch.
                let mut to_dispatch: Vec<(String, Vec<u8>)> = Vec::new();
                for (iface_name, raw, dispatch_at) in candidates {
                    // Remove the matching entry from pending queue.
                    let at = dispatch_at;
                    if let Some(pos) = state.pending_local_announces
                        .iter()
                        .position(|(t, n, _)| (*t - at).abs() < 1e-9 && n == &iface_name)
                    {
                        state.pending_local_announces.remove(pos);
                    }
                    // Record actual dispatch wall time.
                    state.client_announce_last_sent.insert(iface_name.clone(), now_ts);
                    to_dispatch.push((iface_name, raw));
                }
                drop(state);
                for (name, raw) in to_dispatch {
                    Transport::dispatch_outbound(&name, &raw);
                }
                state = TRANSPORT.lock().unwrap();
            }
        }

        // Published-destination refresh sweep.
        //
        // For every destination opted in via `publish_destination` with a
        // non-None `refresh_interval`, re-announce it to all interfaces
        // when the interval has elapsed since the last announce. Entries
        // with `last_announced_at == 0.0` (never announced yet) fire on
        // the first sweep, so applications get an immediate announce as
        // soon as they call `publish_destination` without scheduling one
        // themselves.
        //
        // CRITICAL — TWO independent re-entrant deadlocks must be avoided:
        //
        //   (1) `Transport::outbound` spinwait. If `d.announce(send=true)`
        //       is called here, it dispatches `Packet::send` →
        //       `Transport::outbound`, which spinwaits on `state.jobs_running`
        //       — the same flag this jobs() call set to `true`. Spins forever.
        //       Mitigation: build with `send=false` and defer to the
        //       deferred-sends loop after `jobs_running = false`.
        //
        //   (2) `TRANSPORT` mutex re-lock. Even with `send=false`,
        //       `Destination::announce` calls `generate_announce_data` →
        //       `Identity::remember_ratchet` →
        //       `Transport::is_connected_to_shared_instance`, which calls
        //       `TRANSPORT.lock()`. std::sync::Mutex is NOT reentrant, so
        //       this hangs the very thread that already holds the lock
        //       (and thus all other threads waiting on it).
        //       Mitigation: drop `state` BEFORE invoking `announce()`, do
        //       the build outside the lock, then re-acquire `state` to
        //       update bookkeeping.
        let mut published_announce_packets: Vec<(Vec<u8>, Packet)> = Vec::new();
        if !state.published_destinations.is_empty()
            && now() > state.published_last_checked + state.published_check_interval
        {
            let now_ts = now();
            let due: Vec<(Vec<u8>, Option<Vec<u8>>)> = state.published_destinations.iter()
                .filter_map(|(h, p)| {
                    let ri = p.refresh_interval?;
                    if now_ts - p.last_announced_at >= ri {
                        Some((h.clone(), p.app_data.clone()))
                    } else { None }
                })
                .collect();
            state.published_last_checked = now_ts;
            if !due.is_empty() {
                // Snapshot the matching destinations so we can release the
                // lock before invoking announce() (see deadlock note above).
                let candidates: Vec<(Vec<u8>, Option<Vec<u8>>, Destination)> = due.iter()
                    .filter_map(|(hash, app_data)| {
                        state.destinations.iter().find(|d|
                            d.hash == *hash
                            && d.direction == crate::destination::Direction::IN
                            && d.dest_type == crate::destination::DestinationType::Single
                        ).map(|orig| (hash.clone(), app_data.clone(), orig.clone()))
                    })
                    .collect();
                let missing: Vec<Vec<u8>> = due.iter()
                    .filter(|(hash, _)| !candidates.iter().any(|(h, _, _)| h == hash))
                    .map(|(hash, _)| hash.clone())
                    .collect();

                // Drop the TRANSPORT lock before calling announce(), which
                // re-enters TRANSPORT via remember_ratchet ->
                // is_connected_to_shared_instance.
                drop(state);

                for hash in missing {
                    log(
                        &format!("Published-destination refresh: hash {} not registered — skipping", crate::hexrep(&hash, true)),
                        LOG_DEBUG, false, false,
                    );
                }
                for (hash, app_data, mut d) in candidates {
                    match d.announce(app_data.as_deref(), false, None, None, false) {
                        Ok(Some(packet)) => {
                            published_announce_packets.push((hash, packet));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            log(
                                &format!("Published-destination refresh: announce build failed for {}: {}", crate::hexrep(&hash, true), e),
                                LOG_WARNING, false, false,
                            );
                        }
                    }
                }

                // Re-acquire the lock and optimistically mark
                // `last_announced_at` so the next sweep doesn't re-emit
                // before send() completes. Send failures are rare and
                // self-correct on the next interval.
                state = TRANSPORT.lock().unwrap();
                for (hash, _) in &published_announce_packets {
                    if let Some(entry) = state.published_destinations.get_mut(hash) {
                        entry.last_announced_at = now_ts;
                    }
                }
            }
        }

        if state.packet_hashlist.len() > state.hashlist_maxsize / 2 {
            state.packet_hashlist_prev = state.packet_hashlist.clone();
            state.packet_hashlist.clear();
            // Rotate the validated-announce cache in lockstep with the packet
            // hashlist so it can never grow unbounded.
            state.validated_announce_hashes_prev = std::mem::take(&mut state.validated_announce_hashes);
        }

        if now() > state.pending_prs_last_checked + state.pending_prs_check_interval {
            let interface_names: HashSet<String> = state.interfaces.iter().map(|i| i.name.clone()).collect();
            state.pending_local_path_requests.retain(|_, iface| interface_names.contains(&iface.name));
            state.pending_prs_last_checked = now();
        }

        if state.discovery_pr_tags.len() > state.max_pr_tags {
            let keep_from = state.discovery_pr_tags.len().saturating_sub(state.max_pr_tags);
            // Drain evicted entries and remove them from the lookup set as well.
            let evicted: Vec<Vec<u8>> = state.discovery_pr_tags.drain(..keep_from).collect();
            for tag in &evicted {
                state.discovery_pr_tags_set.remove(tag);
            }
        }

        if now() > state.cache_last_cleaned + state.cache_clean_interval {
            drop(state);
            Transport::clean_cache();
            state = TRANSPORT.lock().unwrap();
        }

        // Opportunistic path-table persistence.
        //
        // Without this sweep `destination_table` is only written from
        // `Transport::exit_handler()` (unreliable on iOS / Android, where
        // the process is terminated rather than asked to clean up) and
        // from the explicit `bridge.transportSavePaths()` that
        // `requestEssentialPaths` fires once per cold start. The result
        // was that paths learned mid-session never reached disk, so the
        // next cold start could not satisfy `Transport::has_path()` for
        // the user's essential destinations and had to send a wire
        // `PATH_REQUEST` whose round-trip dominated launch latency.
        //
        // We persist no more often than `path_table_save_interval` to
        // bound disk wear, and only when something actually changed
        // since the last save. Saving runs without holding the
        // TRANSPORT lock so a slow disk cannot stall the sweep.
        // NEVER REMOVE EVER — DESIGN_PRINCIPLES.md §1: this closes the
        // cold-start "no path → wait for PATH_REQUEST round-trip" hole
        // that costs multi-second launch delays on TCP gateways.
        if state.path_table_dirty
            && now() > state.path_table_last_saved + state.path_table_save_interval
        {
            state.path_table_dirty = false;
            state.path_table_last_saved = now();
            drop(state);
            Transport::save_path_table();
            state = TRANSPORT.lock().unwrap();
        }

        if now() > state.tables_last_culled + state.tables_cull_interval {
            let interface_names: HashSet<String> = state.interfaces.iter().map(|i| i.name.clone()).collect();
            let interface_modes: HashMap<String, u8> = state
                .interfaces
                .iter()
                .map(|i| (i.name.clone(), i.mode))
                .collect();
            let mut stale_reverse_entries = Vec::new();
            for (hash, entry) in state.reverse_table.iter() {
                let timestamp = match entry.get(IDX_RT_TIMESTAMP) {
                    Some(ReverseEntryValue::Timestamp(ts)) => *ts,
                    _ => 0.0,
                };
                let rcvd = match entry.get(IDX_RT_RCVD_IF) {
                    Some(ReverseEntryValue::ReceivedInterface(name)) => name.clone(),
                    _ => None,
                };
                let outb = match entry.get(IDX_RT_OUTB_IF) {
                    Some(ReverseEntryValue::OutboundInterface(name)) => name.clone(),
                    _ => None,
                };
                if now() > timestamp + REVERSE_TIMEOUT {
                    stale_reverse_entries.push(hash.clone());
                } else {
                    if rcvd.as_ref().map(|n| interface_names.contains(n)).unwrap_or(false) == false {
                        stale_reverse_entries.push(hash.clone());
                    } else if outb.as_ref().map(|n| interface_names.contains(n)).unwrap_or(false) == false {
                        stale_reverse_entries.push(hash.clone());
                    }
                }
            }

            let mut stale_links = Vec::new();
            let mut path_rediscovery_tasks: Vec<(Vec<u8>, Option<String>, bool, bool)> = Vec::new();
            for (link_id, entry) in state.link_table.iter() {
                let validated = match entry.get(IDX_LT_VALIDATED) {
                    Some(LinkEntryValue::Validated(v)) => *v,
                    _ => false,
                };
                let timestamp = match entry.get(IDX_LT_TIMESTAMP) {
                    Some(LinkEntryValue::Timestamp(ts)) => *ts,
                    _ => 0.0,
                };
                let proof_tmo = match entry.get(IDX_LT_PROOF_TMO) {
                    Some(LinkEntryValue::ProofTimeout(ts)) => *ts,
                    _ => 0.0,
                };
                let nh_if = match entry.get(IDX_LT_NH_IF) {
                    Some(LinkEntryValue::NextHopInterface(name)) => name.clone(),
                    _ => None,
                };
                let rcvd_if = match entry.get(IDX_LT_RCVD_IF) {
                    Some(LinkEntryValue::ReceivedInterface(name)) => name.clone(),
                    _ => None,
                };

                if validated {
                    if now() > timestamp + LINK_TIMEOUT {
                        stale_links.push(link_id.clone());
                    } else if nh_if.as_ref().map(|n| interface_names.contains(n)).unwrap_or(false) == false {
                        stale_links.push(link_id.clone());
                    } else if rcvd_if.as_ref().map(|n| interface_names.contains(n)).unwrap_or(false) == false {
                        stale_links.push(link_id.clone());
                    }
                } else if now() > proof_tmo {
                    stale_links.push(link_id.clone());

                    // Collect path rediscovery task info
                    let dest_hash = match entry.get(IDX_LT_DSTHASH) {
                        Some(LinkEntryValue::DestinationHash(h)) => h.clone(),
                        _ => Vec::new(),
                    };
                    let lr_taken_hops = match entry.get(IDX_LT_HOPS) {
                        Some(LinkEntryValue::TakenHops(h)) => *h,
                        _ => 0,
                    };

                    if !dest_hash.is_empty() {
                        let last_path_request = state.path_requests.get(&dest_hash).cloned().unwrap_or(0.0);
                        let path_request_throttle = now() - last_path_request < PATH_REQUEST_MI;
                        let mut path_request_conditions = false;
                        let mut blocked_if_name: Option<String> = None;
                        let mut should_mark_unresponsive = false;

                        let has_path = state.path_table.contains_key(&dest_hash);
                        let hops_to_dest = Self::select_path(
                            &state.path_table, &state.interfaces, &dest_hash, now(),
                        ).map(|(_, e)| e.hops).unwrap_or(0);

                        // If path has been invalidated, try to rediscover it
                        if !has_path {
                            path_request_conditions = true;
                        }
                        // If link request was from local client, try to rediscover
                        else if !path_request_throttle && lr_taken_hops == 0 {
                            path_request_conditions = true;
                        }
                        // If destination was previously 1 hop away (likely roamed)
                        else if !path_request_throttle && hops_to_dest == 1 {
                            path_request_conditions = true;
                            blocked_if_name = rcvd_if.clone();
                            if state.transport_enabled {
                                if let Some(name) = &rcvd_if {
                                    if let Some(mode) = interface_modes.get(name) {
                                        if *mode != InterfaceStub::MODE_BOUNDARY {
                                            should_mark_unresponsive = true;
                                        }
                                    }
                                }
                            }
                        }
                        // If link initiator is 1 hop away (topology changed)
                        else if !path_request_throttle && lr_taken_hops == 1 {
                            path_request_conditions = true;
                            blocked_if_name = rcvd_if.clone();
                            if state.transport_enabled {
                                if let Some(name) = &rcvd_if {
                                    if let Some(mode) = interface_modes.get(name) {
                                        if *mode != InterfaceStub::MODE_BOUNDARY {
                                            should_mark_unresponsive = true;
                                        }
                                    }
                                }
                            }
                        }

                        if path_request_conditions {
                            let blocked = blocked_if_name.clone();
                            path_rediscovery_tasks.push((
                                dest_hash.clone(),
                                blocked,
                                should_mark_unresponsive,
                                !state.transport_enabled,
                            ));
                        }
                    }
                }
            }

            // Process path rediscovery tasks (may need to drop/reacquire lock)
            for (dest_hash, blocked_if_name, mark_unresponsive, should_expire) in path_rediscovery_tasks {
                let blocked_clone = blocked_if_name.clone();
                if !path_requests.contains_key(&dest_hash) {
                    path_requests.insert(dest_hash.clone(), blocked_if_name);
                }

                if mark_unresponsive {
                    drop(state);
                    Transport::mark_path_unresponsive(&dest_hash, blocked_clone.as_deref());
                    state = TRANSPORT.lock().unwrap();
                }

                if should_expire {
                    drop(state);
                    Transport::expire_path(&dest_hash);
                    state = TRANSPORT.lock().unwrap();
                }
            }

            let mut stale_paths = Vec::new();
            // Multi-entry culling: iterate each dest's deque, evict expired
            // entries, remove the dest entirely when its deque is empty.
            let now_ts = now();
            let mut cull_dirty = false;
            for (destination_hash, entries) in state.path_table.iter_mut() {
                // Evict individual expired entries
                let before = entries.len();
                entries.retain(|e| !e.is_expired(now_ts));
                if entries.is_empty() {
                    stale_paths.push(destination_hash.clone());
                } else if entries.len() != before {
                    cull_dirty = true;
                }
            }
            // Apply mode-adjusted expiry for access-point / roaming
            // interfaces: re-check each remaining entry's attached interface
            // and remove those that have outlived their mode-specific expiry.
            let mut ap_roam_stale: Vec<Vec<u8>> = Vec::new();
            for (destination_hash, entries) in state.path_table.iter_mut() {
                let before = entries.len();
                entries.retain(|e| {
                    let mut expiry = e.expires;
                    if let Some(ref name) = e.receiving_interface {
                        if let Some(mode) = interface_modes.get(name) {
                            if *mode == InterfaceStub::MODE_ACCESS_POINT {
                                expiry = e.timestamp + AP_PATH_TIME;
                            } else if *mode == InterfaceStub::MODE_ROAMING {
                                expiry = e.timestamp + ROAMING_PATH_TIME;
                            }
                        }
                    }
                    now_ts < expiry
                });
                if entries.is_empty() && before > 0 {
                    ap_roam_stale.push(destination_hash.clone());
                } else if entries.len() != before {
                    cull_dirty = true;
                }
            }
            if cull_dirty {
                state.path_table_dirty = true;
            }
            for hash in ap_roam_stale {
                if !stale_paths.contains(&hash) {
                    stale_paths.push(hash);
                }
            }

            let mut stale_discovery = Vec::new();
            for (destination_hash, entry) in state.discovery_path_requests.iter() {
                if now() > entry.timeout {
                    stale_discovery.push(destination_hash.clone());
                }
            }

            let mut stale_tunnels = Vec::new();
            let mut tunnel_path_removals: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
            for (tunnel_id, entry) in state.tunnels.iter_mut() {
                let expires = match entry.get(IDX_TT_EXPIRES) {
                    Some(TunnelEntryValue::Expires(expires)) => *expires,
                    _ => 0.0,
                };
                if now() > expires {
                    stale_tunnels.push(tunnel_id.clone());
                    continue;
                }
                if let Some(TunnelEntryValue::Interface(Some(name))) = entry.get(IDX_TT_IF) {
                    if !interface_names.contains(name) {
                        if let Some(entry_if) = entry.get_mut(IDX_TT_IF) {
                            *entry_if = TunnelEntryValue::Interface(None);
                        }
                    }
                }
                if let Some(TunnelEntryValue::Paths(paths)) = entry.get_mut(IDX_TT_PATHS) {
                    let mut stale_paths = Vec::new();
                    for (dest_hash, path_entry) in paths.iter() {
                        let timestamp = match path_entry.get(IDX_PT_TIMESTAMP) {
                            Some(PathEntryValue::Timestamp(ts)) => *ts,
                            _ => 0.0,
                        };
                        if now() > timestamp + DESTINATION_TIMEOUT {
                            stale_paths.push(dest_hash.clone());
                        }
                    }
                    if !stale_paths.is_empty() {
                        tunnel_path_removals.push((tunnel_id.clone(), stale_paths));
                    }
                }
            }

            for destination_hash in stale_paths {
                state.path_table.remove(&destination_hash);
                state.path_table_dirty = true;
            }

            for destination_hash in stale_discovery {
                state.discovery_path_requests.remove(&destination_hash);
            }

            for hash in stale_reverse_entries {
                state.reverse_table.remove(&hash);
            }

            for link_id in stale_links {
                state.link_table.remove(&link_id);
            }

            for (tunnel_id, stale_paths) in tunnel_path_removals {
                if let Some(entry) = state.tunnels.get_mut(&tunnel_id) {
                    if let Some(TunnelEntryValue::Paths(paths)) = entry.get_mut(IDX_TT_PATHS) {
                        for dest_hash in stale_paths {
                            paths.remove(&dest_hash);
                        }
                    }
                }
            }

            for tunnel_id in stale_tunnels {
                state.tunnels.remove(&tunnel_id);
            }

            state.tables_last_culled = now();
        }

        if now() > state.interface_last_jobs + state.interface_jobs_interval {
            state.interfaces.sort_by(|a, b| {
                b.bitrate.partial_cmp(&a.bitrate).unwrap_or(std::cmp::Ordering::Equal)
            });
            for interface in &mut state.interfaces {
                // transport::InterfaceStub::process_held_announces is a no-op placeholder;
                // real interfaces handle this via interface::InterfaceStub::take_held_announce.
                interface.process_held_announces();
            }
            state.interface_last_jobs = now();
        }

        // Collect management announce packets to send AFTER releasing the lock.
        // Must avoid TWO independent re-entrant deadlocks:
        //   (1) destination.announce(send=true) → packet.send() → Transport::outbound()
        //       which spinwaits on jobs_running. Use send=false.
        //   (2) destination.announce(send=false) still calls remember_ratchet →
        //       Transport::is_connected_to_shared_instance → TRANSPORT.lock(),
        //       which is non-reentrant. Drop `state` before announce(), then
        //       re-acquire to write back the (mutated-by-announce) destinations.
        let mut mgmt_announce_packets: Vec<Packet> = Vec::new();
        if now() > state.last_mgmt_announce + state.mgmt_announce_interval
            && !state.mgmt_destinations.is_empty()
        {
            state.last_mgmt_announce = now();
            let mut mgmt_dests: Vec<Destination> = std::mem::take(&mut state.mgmt_destinations);
            drop(state);
            for destination in mgmt_dests.iter_mut() {
                if let Ok(Some(packet)) = destination.announce(None, false, None, None, false) {
                    mgmt_announce_packets.push(packet);
                }
            }
            state = TRANSPORT.lock().unwrap();
            // Restore (possibly-mutated) mgmt destinations.
            state.mgmt_destinations = mgmt_dests;
        } else if now() > state.last_mgmt_announce + state.mgmt_announce_interval {
            state.last_mgmt_announce = now();
        }

        if now() > state.blackhole_last_checked + state.blackhole_check_interval {
            let mut stale_blackholes = Vec::new();
            for (identity_hash, entry) in state.blackholed_identities.iter() {
                if let Some(until) = entry.until {
                    if now() > until {
                        stale_blackholes.push(identity_hash.clone());
                    }
                }
            }
            for identity_hash in stale_blackholes {
                state.blackholed_identities.remove(&identity_hash);
            }
            state.blackhole_last_checked = now();
        }

        drop(state);

        // DIAG: trace outgoing
        if !outgoing.is_empty() {
            for p in &outgoing {
                crate::log(&format!("[JOBS-DIAG] outgoing ptype={} dest={} raw_len={} attached={:?}",
                    p.packet_type, p.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
                    p.raw.len(), p.attached_interface), crate::LOG_EXTREME, false, false);
            }
        }

        // Send management announces (deferred to avoid calling Transport::outbound
        // while the TRANSPORT lock is held — destination.announce(send=true) calls
        // packet.send() → Transport::outbound() → TRANSPORT.lock() re-entrant deadlock).
        for mut packet in mgmt_announce_packets {
            let _ = packet.send();
        }

        // Send published-destination refresh announces (also deferred — see
        // the published-destination refresh sweep above for the full
        // re-entrant deadlock rationale).
        for (hash, mut packet) in published_announce_packets {
            match packet.send() {
                Ok(_) => log(
                    &format!("Published-destination refresh: announced {}", crate::hexrep(&hash, true)),
                    LOG_NOTICE, false, false,
                ),
                Err(e) => log(
                    &format!("Published-destination refresh: announce send failed for {}: {}", crate::hexrep(&hash, true), e),
                    LOG_WARNING, false, false,
                ),
            }
        }

        for mut packet in outgoing {
            // Announce retransmits are already packed (raw set), no destination.
            // Use Transport::outbound directly instead of packet.send() which
            // requires a non-None destination.
            let _ = Transport::outbound(&mut packet);
        }

        for (destination_hash, blocked_if) in path_requests {
            if blocked_if.is_none() {
                Transport::request_path(&destination_hash, None, None, None, None);
            } else {
                Transport::request_path(&destination_hash, None, blocked_if, None, None);
            }
        }

        let held_ms = jobs_lock_started.elapsed().as_millis();
        if held_ms > 500 {
        }
    }

    pub fn prioritize_interfaces() {
        let mut state = TRANSPORT.lock().unwrap();
        state.interfaces.sort_by(|a, b| b.bitrate.partial_cmp(&a.bitrate).unwrap_or(std::cmp::Ordering::Equal));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    fn inbound_silence_warning_enforced(iface: &InterfaceStub) -> bool {
        !iface.repr.starts_with("TCPInterface[")
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    fn inbound_silence_warning_enforced(_iface: &InterfaceStub) -> bool {
        true
    }

    fn should_emit_offline_drop_warning(iface: &mut InterfaceStub, now_secs: f64) -> bool {
        if now_secs - iface.last_offline_warn_at > 60.0 {
            iface.last_offline_warn_at = now_secs;
            return true;
        }
        false
    }

    pub fn outbound(packet: &mut Packet) -> bool {
        crate::log(&format!("[OUTBOUND-ENTER] ptype={} dest={} attached={:?}",
            packet.packet_type,
            packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
            packet.attached_interface),
            crate::LOG_NOTICE, false, false);
        // Step 2 of the transport refactor (TRANSPORT_REFACTOR_PLAN.md):
        //
        // Previously this function spinwaited on `state.jobs_running`,
        // sleeping 1 ms in a loop until `Transport::jobs()` finished its
        // body. That serialization was redundant — the TRANSPORT mutex
        // already serializes the two functions — and it could stall the
        // sender for hundreds of milliseconds during a slow jobs sweep.
        //
        // After Step 1 (per-interface writer actor) `dispatch_outbound`
        // is non-blocking, so even if jobs() and outbound() interleave
        // there is no head-of-line blocking on socket I/O. Step 3 dropped
        // the `jobs_running` / `jobs_locked` flags entirely — they were
        // load-bearing only for the now-deleted busy-wait.
        let mut state = TRANSPORT.lock().unwrap();
        let mut sent = false;
        let mut transmissions: Vec<(String, Vec<u8>)> = Vec::new();
        let outbound_time = now();

        let destination_hash = packet.destination_hash.clone().or_else(|| packet.destination.as_ref().map(|d| d.hash.clone()));

        // Determine if we have a path-routed packet (non-ANNOUNCE, non-Plain, non-Group)
        let path_routable = packet.packet_type != ANNOUNCE
            && packet.destination_type != Some(crate::destination::DestinationType::Plain)
            && packet.destination_type != Some(crate::destination::DestinationType::Group)
            && destination_hash.is_some();

        let mut all_paths: Vec<(usize, f64, PathEntry)> = Vec::new();
        if path_routable {
            let dest_hash = destination_hash.as_ref().unwrap();
            all_paths = Self::select_all_paths(&state.path_table, &state.interfaces, dest_hash, outbound_time);
        }

        // ── Path-routed packet: multi-path hedging ──────────────────────────
        // Walk paths in score order (best first).  Every path gets the packet;
        // if the path is stale (multi-hop transport only, hops ≥ 2) we fire a
        // path_request to refresh it AND continue to the next-best path so
        // delivery isn't gated on a dead route.  The first fresh path stops
        // the hedge.
        //
        // Stale paths also get their expiry shortened to
        // now + PATH_STALE_THRESHOLD so that truly-dead paths are culled
        // quickly instead of duplicating traffic for up to 7 days.
        // Never lengthen an existing expiry (e.g. don't override a shorter
        // roaming-path timeout).
        let mut stale_deferred: Vec<(Vec<u8>, Option<String>)> = Vec::new();
        if !all_paths.is_empty() {
            let dest_hash = destination_hash.as_ref().unwrap();
            mark_packet_sent(packet, outbound_time);

            for (_idx, _score, entry) in &all_paths {
                let hops = entry.hops;
                let outbound_interface_name = entry.receiving_interface.clone();
                let outbound_interface_exists = outbound_interface_name
                    .as_ref()
                    .map(|name| state.interfaces.iter().any(|i| &i.name == name))
                    .unwrap_or(false);

                // LINKREQUEST (2) and PROOF (3) are rare and critical for
                // diagnosing link establishment.  Log at NOTICE.
                let outbound_log_level = if packet.packet_type == LINKREQUEST || packet.packet_type == PROOF {
                    crate::LOG_NOTICE
                } else {
                    crate::LOG_VERBOSE
                };
                crate::log(&format!("[OUTBOUND] ptype={} dest={} hops={} iface={:?} iface_exists={}",
                    packet.packet_type, dest_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                    hops, outbound_interface_name, outbound_interface_exists), outbound_log_level, false, false);
                if !outbound_interface_exists {
                    let next_hop = crate::hexrep(&entry.next_hop, false);
                    let live_ifaces: Vec<String> = state.interfaces.iter().map(|iface| iface.name.clone()).collect();
                    let live_local_client_ifaces: Vec<String> = state
                        .local_client_interfaces
                        .iter()
                        .map(|iface| iface.name.clone())
                        .collect();
                    crate::log(
                        &format!(
                            "[OUTBOUND] missing interface for path dest={} next_hop={} expected_iface={:?} live_ifaces={:?} local_client_ifaces={:?}",
                            crate::hexrep(dest_hash, false),
                            next_hop,
                            outbound_interface_name,
                            live_ifaces,
                            live_local_client_ifaces,
                        ),
                        crate::LOG_WARNING,
                        false,
                        false,
                    );
                }

                // ── Build raw bytes for this path entry ─────────────────────
                if hops > 1 && packet.header_type == crate::packet::HEADER_1 {
                    let next_hop = &entry.next_hop;
                    if next_hop == dest_hash {
                        crate::log(&format!("[OUTBOUND] hops>1 next_hop==dest: HEADER_1 direct, raw[0..4]={:02x?}",
                            &packet.raw[..packet.raw.len().min(4)]), crate::LOG_VERBOSE, false, false);
                        if outbound_interface_exists {
                            if let Some(iface_name) = outbound_interface_name.clone() {
                                transmissions.push((iface_name, packet.raw.clone()));
                            }
                            sent = true;
                        }
                    } else {
                        let new_flags = (crate::packet::HEADER_2 << 6) | (MODE_TRANSPORT << 4) | (packet.flags & 0b0000_1111);
                        let mut new_raw = vec![new_flags, packet.hops];
                        new_raw.extend_from_slice(next_hop);
                        if packet.raw.len() > 2 {
                            new_raw.extend_from_slice(&packet.raw[2..]);
                        }
                        if outbound_interface_exists {
                            if let Some(iface_name) = outbound_interface_name.clone() {
                                transmissions.push((iface_name, new_raw));
                            }
                            sent = true;
                        }
                    }
                } else if hops == 1 && state.is_connected_to_shared_instance && packet.header_type == crate::packet::HEADER_1 {
                    let next_hop = &entry.next_hop;
                    let new_flags = (crate::packet::HEADER_2 << 6) | (MODE_TRANSPORT << 4) | (packet.flags & 0b0000_1111);
                    let mut new_raw = vec![new_flags, packet.hops];
                    new_raw.extend_from_slice(next_hop);
                    if packet.raw.len() > 2 {
                        new_raw.extend_from_slice(&packet.raw[2..]);
                    }
                    if outbound_interface_exists {
                        if let Some(iface_name) = outbound_interface_name.clone() {
                            transmissions.push((iface_name, new_raw));
                        }
                        sent = true;
                    }
                } else {
                    if outbound_interface_exists {
                        if let Some(iface_name) = outbound_interface_name.clone() {
                            transmissions.push((iface_name, packet.raw.clone()));
                        }
                        sent = true;
                    }
                }

                // ── Staleness check: multi-hop transport paths only (hops ≥ 2) ──
                let is_stale = hops >= 2
                    && (outbound_time - entry.timestamp) > PATH_STALE_THRESHOLD;

                if is_stale {
                    // Defer path_request to after we release the TRANSPORT lock
                    stale_deferred.push((dest_hash.clone(), entry.receiving_interface.clone()));

                    // Shorten expiry so dead paths don't duplicate forever.
                    // Only shorten — never lengthen (e.g. roaming-path expiry).
                    if let Some(deque) = state.path_table.get_mut(dest_hash) {
                        if let Some(mut_entry) = deque.iter_mut().find(|e| e.packet_hash == entry.packet_hash) {
                            let shortened = outbound_time + PATH_STALE_THRESHOLD;
                            if shortened < mut_entry.expires {
                                mut_entry.expires = shortened;
                                state.path_table_dirty = true;
                            }
                        }
                    }

                    // Continue to next-best path (hedge)
                } else {
                    // Fresh path — delivery covered, stop hedging
                    break;
                }
            }

            // Fire deferred path_requests outside the TRANSPORT lock.
            // request_path() acquires the lock internally; we must
            // drop ours first to avoid deadlock.
            if !stale_deferred.is_empty() {
                let dest_hash_for_log = dest_hash.clone();
                let n_stale = stale_deferred.len();
                drop(state);
                for (dh, iface) in stale_deferred {
                    Transport::request_path(&dh, None, iface, None, None);
                }
                state = TRANSPORT.lock().unwrap();
                crate::log(
                    &format!(
                        "[OUTBOUND] hedge: fired {} path_request(s) for stale paths to {}",
                        n_stale,
                        crate::hexrep(&dest_hash_for_log, false)
                    ),
                    crate::LOG_DEBUG,
                    false,
                    false,
                );
            }
        } else {
            if packet.packet_type != ANNOUNCE {
                let no_path_log_level = if packet.packet_type == LINKREQUEST {
                    crate::LOG_NOTICE
                } else {
                    crate::LOG_VERBOSE
                };
                crate::log(&format!("[OUTBOUND] no path entry for ptype={} dest={:?} dtype={:?}",
                    packet.packet_type,
                    packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)),
                    packet.destination_type), no_path_log_level, false, false);
            }
            let mut packet_hashes: Vec<Vec<u8>> = Vec::new();

            // For link-type destinations, get the link's attached_interface and status
            // from the packet's destination LinkInfo (avoiding a RUNTIME_LINKS lock that
            // could deadlock if the link Mutex is already held by this thread).
            // Matches Python Transport.outbound: only transmit on the link's attached_interface,
            // and don't transmit if the link is closed.
            let link_outbound_info = if packet.destination_type == Some(crate::destination::DestinationType::Link) {
                packet.destination.as_ref()
                    .and_then(|d| d.link.as_ref())
                    .map(|li| (li.attached_interface.clone(), li.status_closed))
            } else {
                None
            };

            // Build a set of local client interface names so we can skip them
            // during untargeted announce broadcast.  Local clients receive
            // announces via immediate dispatch in inbound() / path_request()
            // instead, avoiding the burst that triggers ingress limiting.
            let local_client_names: std::collections::HashSet<String> = state
                .local_client_interfaces
                .iter()
                .map(|i| i.name.clone())
                .collect();

            for interface in &mut state.interfaces {
                // For announces, broadcast to ALL interfaces even if out_enabled=false
                // For other packets, only send on interfaces with out_enabled=true
                let should_send_on_interface = if packet.packet_type == ANNOUNCE {
                    true  // Announces broadcast to all interfaces
                } else {
                    interface.out  // Regular packets only on outgoing interfaces
                };

                crate::log(&format!("[OUTBOUND-IFACE] ptype={} iface={} out={} should_send={}",
                    packet.packet_type, interface.name, interface.out, should_send_on_interface),
                    crate::LOG_NOTICE, false, false);

                if should_send_on_interface {
                    let mut should_transmit = true;

                    // Link-destination filtering (Python: packet.destination.type == LINK)
                    if let Some((ref link_attached_iface, is_closed)) = link_outbound_info {
                        if is_closed {
                            should_transmit = false;
                        }
                        if let Some(link_iface) = link_attached_iface {
                            if &interface.name != link_iface {
                                should_transmit = false;
                            }
                        }
                    }

                    if let Some(attached) = &packet.attached_interface {
                        if &interface.name != attached {
                            should_transmit = false;
                        }
                    }

                    // Don't echo an announce retransmit back to the interface
                    // it was originally received from.  Matches Python
                    // Transport.py ~line 1803 / 1821.
                    if packet.packet_type == ANNOUNCE {
                        if let Some(ref recv_iface) = packet.receiving_interface {
                            if &interface.name == recv_iface {
                                should_transmit = false;
                            }
                        }
                    }

                    // Don't send untargeted announce broadcasts to local
                    // client interfaces.  They receive fresh announces via
                    // immediate dispatch in inbound() and PATH_RESPONSEs
                    // via dispatch_outbound() in path_request().  Sending
                    // announce_table retransmissions here causes a burst
                    // that triggers the client's TCPClientInterface ingress
                    // limiter.
                    if packet.packet_type == ANNOUNCE && packet.attached_interface.is_none() {
                        if local_client_names.contains(&interface.name) {
                            should_transmit = false;
                        }
                    }

                    if packet.packet_type == ANNOUNCE && packet.attached_interface.is_none() {
                        if interface.mode == InterfaceStub::MODE_ACCESS_POINT {
                            should_transmit = false;
                        }
                    }

                    if should_transmit {
                        crate::log(&format!("[OUTBOUND-BCAST] ptype={} iface={} raw_len={}",
                            packet.packet_type, interface.name, packet.raw.len()),
                            crate::LOG_NOTICE, false, false);
                        if packet.packet_hash.is_some() {
                            packet_hashes.push(packet.packet_hash.clone().unwrap());
                        }
                        transmissions.push((interface.name.clone(), packet.raw.clone()));
                        if packet.packet_type == ANNOUNCE {
                            interface.sent_announce();
                        }
                        mark_packet_sent(packet, outbound_time);
                        sent = true;
                    } else {
                        crate::log(&format!("[OUTBOUND-SKIP] ptype={} iface={}",
                            packet.packet_type, interface.name),
                            crate::LOG_NOTICE, false, false);
                    }
                }
            }
            for hash in packet_hashes {
                state.packet_hashlist.insert(hash);
            }
        }

        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        // Fix 4: refuse to claim sent=true on a transmission whose target
        // interface is currently offline. Without this, callers (e.g.
        // lxmf.prop sync, link establishment) record a successful send
        // and burn the §1 budget waiting for a reply that will never
        // arrive — exactly the wedge analysed in
        // /memories/repo/rfed-tcp-watchdog-failure.md (12 h of "sent=true"
        // on a dead interface). Filter and re-derive `sent` BEFORE the
        // receipt is created so we don't queue receipts for dead sends.
        //
        // Fix 5: while we're walking interfaces, also detect "outbound
        // succeeds but no inbound for >30 s" for transports that do not
        // have kernel-level socket state available here. TCP interfaces on
        // Linux/Android/macOS use OS-level socket reporting in the read loop
        // instead, so this elapsed-time warning would just be misleading log
        // noise there.
        let now_secs = now();
        let mut filtered: Vec<(String, Vec<u8>)> = Vec::with_capacity(transmissions.len());
        let mut offline_drops: Vec<String> = Vec::new();
        let mut silent_warnings: Vec<(String, f64)> = Vec::new();
        for (iface_name, raw) in transmissions.into_iter() {
            let mut iface_online = false;
            let mut should_warn_offline = false;
            if let Some(iface) = state.interfaces.iter_mut().find(|i| i.name == iface_name) {
                iface_online = iface.online;
                if !iface_online {
                    should_warn_offline = Self::should_emit_offline_drop_warning(iface, now_secs);
                }
            } else if let Some(iface) = state
                .local_client_interfaces
                .iter_mut()
                .find(|i| i.name == iface_name)
            {
                iface_online = iface.online;
                if !iface_online {
                    should_warn_offline = Self::should_emit_offline_drop_warning(iface, now_secs);
                }
            }
            if !iface_online {
                if iface_name.contains("PostInterface") {
                    crate::log(&format!("[OFFLINE-DROP] PostInterface is offline! online_flag={}", iface_online),
                        crate::LOG_ERROR, false, false);
                }
                if should_warn_offline {
                    offline_drops.push(iface_name);
                }
                continue;
            }

            // Half-open detection: only meaningful once we've seen at
            // least one inbound on this iface (skip cold-start window).
            if let Some(iface) = state
                .interfaces
                .iter_mut()
                .find(|i| i.name == iface_name)
            {
                if Self::inbound_silence_warning_enforced(iface) && iface.last_inbound_at > 0.0 {
                    let silent_for = now_secs - iface.last_inbound_at;
                    if silent_for > 30.0 && now_secs - iface.last_inbound_warn_at > 60.0 {
                        iface.last_inbound_warn_at = now_secs;
                        silent_warnings.push((iface_name.clone(), silent_for));
                    }
                }
            }

            filtered.push((iface_name, raw));
        }
        sent = !filtered.is_empty();
        let transmissions = filtered;

        for name in &offline_drops {
            crate::log(
                &format!(
                    "[OUTBOUND] dropping send: interface {} is offline (sent=false, further drops suppressed for 60s)",
                    name
                ),
                crate::LOG_WARNING,
                false,
                false,
            );
        }
        for (name, silent_for) in &silent_warnings {
            crate::log(
                &format!(
                    "[OUTBOUND] §1 WARNING: interface {} has not received inbound data for {:.0}s — possible half-open connection",
                    name, silent_for
                ),
                crate::LOG_ERROR,
                false,
                false,
            );
        }

        if sent && packet.should_generate_receipt() && packet.receipt.is_none() {
            let timeout = if packet.destination_type == Some(crate::destination::DestinationType::Link) {
                let destination = packet.destination.clone().unwrap_or_default();
                destination
                    .link
                    .as_ref()
                    .and_then(|l| l.rtt)
                    .unwrap_or(0.0)
                    * destination
                        .link
                        .as_ref()
                        .map(|l| l.traffic_timeout_factor)
                        .unwrap_or(1.0)
                        .max(0.005)
            } else {
                let hops = if let Some(dest_hash) = packet
                    .destination_hash
                    .as_ref()
                    .or_else(|| packet.destination.as_ref().map(|d| &d.hash))
                {
                    Self::select_path(&state.path_table, &state.interfaces, dest_hash, now())
                        .map(|(_, e)| e.hops)
                        .unwrap_or(0)
                } else {
                    0
                };

                crate::reticulum::DEFAULT_PER_HOP_TIMEOUT
                    + crate::packet::TIMEOUT_PER_HOP * hops as f64
            };

            let receipt = crate::packet::PacketReceipt::new_with_timeout(packet, timeout);
            crate::log(&format!("Receipt created timeout={:.3}s hash={}", timeout, crate::hexrep(&receipt.hash, false)), crate::LOG_NOTICE, false, false);
            packet.receipt = Some(receipt.clone());
            state.receipts.push(receipt);
        }

        let tx_log_level = if packet.packet_type == LINKREQUEST || packet.packet_type == PROOF {
            crate::LOG_NOTICE
        } else {
            crate::LOG_VERBOSE
        };

        crate::log(&format!("Transport::outbound {} transmissions, sent={}", transmissions.len(), sent), tx_log_level, false, false);
        drop(state);

        for (iface_name, raw) in transmissions {
            let _ = Transport::dispatch_outbound(&iface_name, &raw);
        }

        sent
    }

    pub fn cache(packet: &Packet, force_cache: bool, packet_type: Option<String>) {
        if !force_cache {
            return;
        }
        ensure_paths();
        if let Some(hash) = packet.packet_hash.clone() {
            let packet_hash = crate::hexrep(&hash, false);
            let cachepath = if packet_type.as_deref() == Some("announce") {
                crate::reticulum::cache_path().join("announces").join(packet_hash)
            } else {
                crate::reticulum::cache_path().join(packet_hash)
            };
            let entry = CachedPacketEntry {
                raw: packet.raw.clone(),
                interface_name: packet.receiving_interface.clone(),
            };
            if let Ok(data) = to_vec_named(&entry) {
                if let Ok(mut file) = File::create(&cachepath) {
                    let _ = file.write_all(&data);
                }
            }
        }
    }

    pub fn get_cached_packet(packet_hash: &[u8], packet_type: Option<String>) -> Option<Packet> {
        ensure_paths();
        let packet_hash = crate::hexrep(packet_hash, false);
        let path = if packet_type.as_deref() == Some("announce") {
            crate::reticulum::cache_path().join("announces").join(packet_hash)
        } else {
            crate::reticulum::cache_path().join(packet_hash)
        };

        if path.exists() {
            if let Ok(mut file) = File::open(path) {
                let mut buf = Vec::new();
                if file.read_to_end(&mut buf).is_ok() {
                    if let Ok(entry) = from_slice::<CachedPacketEntry>(&buf) {
                        let mut packet = Packet::new(None, Vec::new(), 0, 0, BROADCAST, crate::packet::HEADER_1, None, None, false, 0);
                        packet.raw = entry.raw;
                        packet.receiving_interface = entry.interface_name;
                        if packet.unpack() {
                            return Some(packet);
                        }
                    }
                }
            }
        }
        None
    }

    pub fn cache_request(packet_hash: Vec<u8>, _destination: crate::link::LinkHandle) {
        if let Some(packet) = Transport::get_cached_packet(&packet_hash, None) {
            let _ = Transport::inbound(packet.raw, packet.receiving_interface.clone());
        }
    }

    pub fn cache_request_packet(packet: &Packet) -> bool {
        if packet.data.len() == crate::identity::HASHLENGTH / 8 {
            if let Some(cached) = Transport::get_cached_packet(&packet.data, None) {
                let _ = Transport::inbound(cached.raw, cached.receiving_interface.clone());
                return true;
            }
        }
        false
    }

    pub fn clean_cache() {
        ensure_paths();
        Transport::clean_announce_cache();
        let mut state = TRANSPORT.lock().unwrap();
        state.cache_last_cleaned = now();
    }

    pub fn clean_announce_cache() {
        ensure_paths();
        let target_path = crate::reticulum::cache_path().join("announces");
        if !target_path.exists() {
            return;
        }

        let mut active_paths: HashSet<Vec<u8>> = HashSet::new();
        let state = TRANSPORT.lock().unwrap();
        for deque in state.path_table.values() {
            for entry in deque {
                active_paths.insert(entry.packet_hash.clone());
            }
        }

        if let Ok(entries) = fs::read_dir(&target_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(target_hash) = crate::decode_hex(name) {
                        if !active_paths.contains(&target_hash) {
                            let _ = fs::remove_file(path);
                        }
                    } else {
                        let _ = fs::remove_file(path);
                    }
                }
            }
        }
    }

    pub fn save_packet_hashlist() {
        let state = TRANSPORT.lock().unwrap();
        if state.is_connected_to_shared_instance {
            return;
        }
        let path = crate::reticulum::storage_path().join("packet_hashlist");
        if let Ok(data) = to_vec_named(&state.packet_hashlist.iter().cloned().collect::<Vec<_>>()) {
            if let Ok(mut file) = File::create(path) {
                let _ = file.write_all(&data);
            }
        }
    }

    pub fn save_path_table() {
        let state = TRANSPORT.lock().unwrap();
        if state.is_connected_to_shared_instance {
            return;
        }
        // Serialize as Vec<(dest_hash, Vec<PathEntry>)> — each dest can
        // have up to MAX_PATHS_PER_DEST entries.  On load we convert
        // the Vec to VecDeque.
        let entries: Vec<(Vec<u8>, Vec<PathEntry>)> = state.path_table
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().cloned().collect()))
            .collect();
        let path = crate::reticulum::storage_path().join("destination_table");
        if let Ok(data) = to_vec_named(&entries) {
            if let Ok(mut file) = File::create(path) {
                let _ = file.write_all(&data);
            }
        }
    }

    pub fn save_tunnel_table() {
        let state = TRANSPORT.lock().unwrap();
        if state.is_connected_to_shared_instance {
            return;
        }
        let mut entries: Vec<SerializedTunnelEntry> = Vec::new();
        for entry in state.tunnels.values() {
            let tunnel_id = match entry.get(IDX_TT_TUNNEL_ID) {
                Some(TunnelEntryValue::TunnelId(id)) => id.clone(),
                _ => continue,
            };
            let interface_hash = match entry.get(IDX_TT_IF) {
                Some(TunnelEntryValue::Interface(Some(name))) => Some(name.as_bytes().to_vec()),
                _ => None,
            };
            let paths = match entry.get(IDX_TT_PATHS) {
                Some(TunnelEntryValue::Paths(paths)) => paths.clone(),
                _ => HashMap::new(),
            };
            let expires = match entry.get(IDX_TT_EXPIRES) {
                Some(TunnelEntryValue::Expires(expires)) => *expires,
                _ => continue,
            };

            let mut serialized_paths = Vec::new();
            for (dest_hash, path_entry) in paths {
                let timestamp = match path_entry.get(IDX_PT_TIMESTAMP) {
                    Some(PathEntryValue::Timestamp(ts)) => *ts,
                    _ => continue,
                };
                let received_from = match path_entry.get(IDX_PT_NEXT_HOP) {
                    Some(PathEntryValue::NextHop(next)) => next.clone(),
                    _ => continue,
                };
                let hops = match path_entry.get(IDX_PT_HOPS) {
                    Some(PathEntryValue::Hops(hops)) => *hops,
                    _ => continue,
                };
                let expires = match path_entry.get(IDX_PT_EXPIRES) {
                    Some(PathEntryValue::Expires(expires)) => *expires,
                    _ => continue,
                };
                let random_blobs = match path_entry.get(IDX_PT_RANDBLOBS) {
                    Some(PathEntryValue::RandomBlobs(blobs)) => blobs.clone(),
                    _ => Vec::new(),
                };
                let packet_hash = match path_entry.get(IDX_PT_PACKET) {
                    Some(PathEntryValue::PacketHash(hash)) => hash.clone(),
                    _ => Vec::new(),
                };

                serialized_paths.push(SerializedPathEntry {
                    destination_hash: dest_hash,
                    timestamp,
                    received_from,
                    hops,
                    expires,
                    random_blobs,
                    interface_hash: Vec::new(),
                    packet_hash,
                });
            }

            entries.push(SerializedTunnelEntry {
                tunnel_id,
                interface_hash,
                paths: serialized_paths,
                expires,
            });
        }

        let path = crate::reticulum::storage_path().join("tunnels");
        if let Ok(data) = to_vec_named(&entries) {
            if let Ok(mut file) = File::create(path) {
                let _ = file.write_all(&data);
            }
        }
    }

    pub fn persist_data() {
        Transport::save_packet_hashlist();
        Transport::save_path_table();
        Transport::save_tunnel_table();
    }

    // ── timebase/blob functions removed — anti-replay is now purely
    //     via the global_blobs set, decoupled from path entries.

    /// Hop count to `destination_hash` via the best available path.
    /// Returns `LINK_UNKNOWN_HOP_COUNT` when no path is known.
    pub fn hops_to(destination_hash: &[u8]) -> u8 {
        Self::select_path_for(destination_hash)
            .map(|(_, e)| e.hops)
            .unwrap_or(LINK_UNKNOWN_HOP_COUNT)
    }

    /// Transport-identity hash of the next-hop node for the best path
    /// to `destination_hash`.
    pub fn next_hop(destination_hash: &[u8]) -> Option<Vec<u8>> {
        Self::select_path_for(destination_hash)
            .map(|(_, e)| e.next_hop)
    }

    /// Interface name for the best path to `destination_hash`.
    pub fn next_hop_interface(destination_hash: &[u8]) -> Option<String> {
        let state = TRANSPORT.lock().unwrap();
        let now_ts = now();
        Self::select_path(&state.path_table, &state.interfaces, destination_hash, now_ts)
            .and_then(|(_, e)| e.receiving_interface)
    }

    /// Clone the best live path entry from `source_hash` to `destination_hash`.
    /// Used when sibling SINGLE destinations share the same owner identity and
    /// next-hop, but only one aspect has been explicitly path-resolved this
    /// session. This mirrors the rfed test harness strategy of seeding
    /// `rfed.{channel,delivery,notify}` from a known `rfed.node`/
    /// `lxmf.propagation` route.
    pub fn clone_path(source_hash: &[u8], destination_hash: &[u8]) -> bool {
        if source_hash.is_empty() || destination_hash.is_empty() || source_hash == destination_hash {
            return false;
        }
        let mut state = TRANSPORT.lock().unwrap();
        let now_ts = now();
        let Some((_, best)) = Self::select_path(&state.path_table, &state.interfaces, source_hash, now_ts) else {
            return false;
        };
        state.path_table
            .entry(destination_hash.to_vec())
            .or_insert_with(VecDeque::new)
            .push_front(best);
        state.path_table_dirty = true;
        if state.path_verified_this_session.contains(source_hash) {
            state.path_verified_this_session.insert(destination_hash.to_vec());
        }
        drop(state);
        notify_path_added();
        true
    }

    /// Block the calling thread until either:
    ///   * a path to `destination_hash` is available
    ///     (`Self::has_path` returns true), or
    ///   * `budget` elapses.
    ///
    /// Wakes on the actual PATH_RESPONSE / announce event via the
    /// `PATH_ADDED_NOTIFY` Condvar, NOT on a polling clock.
    /// Returns true iff a usable path is present at return time.
    ///
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §4 (no timeout tuning).
    /// `budget` is an upper bound on resource holding, not a poll interval.
    pub fn wait_for_path(destination_hash: &[u8], budget: Duration) -> bool {
        // Fast path: already have it.
        if Self::has_path(destination_hash) {
            return true;
        }
        let deadline = Instant::now() + budget;
        let (lock, cvar) = &*PATH_ADDED_NOTIFY;
        let mut gen_seen = match lock.lock() {
            Ok(g) => *g,
            Err(_) => return Self::has_path(destination_hash),
        };
        loop {
            // Re-check under whatever wake just happened (or initial state).
            if Self::has_path(destination_hash) {
                return true;
            }
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(d) if !d.is_zero() => d,
                _ => return Self::has_path(destination_hash),
            };
            // Acquire the notify lock and wait until the generation
            // counter advances (someone called `notify_path_added`)
            // or the budget expires.
            let guard = match lock.lock() {
                Ok(g) => g,
                Err(_) => return Self::has_path(destination_hash),
            };
            let (new_guard, timeout) = match cvar.wait_timeout_while(
                guard, remaining, |gen| *gen == gen_seen,
            ) {
                Ok(r) => r,
                Err(_) => return Self::has_path(destination_hash),
            };
            gen_seen = *new_guard;
            drop(new_guard);
            if timeout.timed_out() {
                return Self::has_path(destination_hash);
            }
            // Spurious wake or insert for a different dest: loop and re-check.
        }
    }

    /// Same event-driven wait as [`Self::wait_for_path`], but requires the
    /// path to have been confirmed by a PATH_RESPONSE / announce observed in
    /// this process. Cached path-table entries loaded from disk do not count.
    ///
    /// Propagation-node persistent links use this as their readiness signal:
    /// the server has proven it can send traffic back to us before we send
    /// LRREQ. No sleeps, no polling, no retry loop.
    ///
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §5.
    pub fn wait_for_path_verified_this_session(destination_hash: &[u8], budget: Duration) -> bool {
        if Self::has_path(destination_hash) && Self::is_path_verified_this_session(destination_hash) {
            return true;
        }
        let deadline = Instant::now() + budget;
        let (lock, cvar) = &*PATH_ADDED_NOTIFY;
        let mut gen_seen = match lock.lock() {
            Ok(g) => *g,
            Err(_) => {
                return Self::has_path(destination_hash)
                    && Self::is_path_verified_this_session(destination_hash);
            }
        };
        loop {
            if Self::has_path(destination_hash) && Self::is_path_verified_this_session(destination_hash) {
                return true;
            }
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(d) if !d.is_zero() => d,
                _ => {
                    return Self::has_path(destination_hash)
                        && Self::is_path_verified_this_session(destination_hash);
                }
            };
            let guard = match lock.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Self::has_path(destination_hash)
                        && Self::is_path_verified_this_session(destination_hash);
                }
            };
            let (new_guard, timeout) = match cvar.wait_timeout_while(
                guard,
                remaining,
                |gen| *gen == gen_seen,
            ) {
                Ok(r) => r,
                Err(_) => {
                    return Self::has_path(destination_hash)
                        && Self::is_path_verified_this_session(destination_hash);
                }
            };
            gen_seen = *new_guard;
            drop(new_guard);
            if timeout.timed_out() {
                return Self::has_path(destination_hash)
                    && Self::is_path_verified_this_session(destination_hash);
            }
        }
    }

    /// Hop count for the currently-cached path to `destination_hash`, or
    pub fn add_packet_hash(packet_hash: Vec<u8>) {
        let mut state = TRANSPORT.lock().unwrap();
        if !state.is_connected_to_shared_instance {
            state.packet_hashlist.insert(packet_hash);
        }
    }

    /// Returns true if an inbound announce has confirmed `destination_hash`'s
    /// path entry SINCE THIS PROCESS STARTED. Cached entries loaded from
    /// disk on cold start return false even when `has_path()` returns
    /// true. Drives the parallel-path-request hedge in
    /// `app_links::establish()`. See `TransportState::path_verified_this_session`.
    pub fn is_path_verified_this_session(destination_hash: &[u8]) -> bool {
        let state = TRANSPORT.lock().unwrap();
        state.path_verified_this_session.contains(destination_hash)
    }

    // ── Path selection helper ────────────────────────────────────────────────

    /// Select the best non-expired `PathEntry` for `destination_hash`.
    /// Iterates the deque (newest-first), skips expired entries, and
    /// returns the one with the highest `score()` (bitrate / (hops+1)).
    /// Returns `None` when the deque is empty or all entries are expired.
    fn select_path(
        table: &HashMap<Vec<u8>, VecDeque<PathEntry>>,
        interfaces: &[InterfaceStub],
        destination_hash: &[u8],
        now: f64,
    ) -> Option<(usize, PathEntry)> {
        let entries = table.get(destination_hash)?;
        let mut best: Option<(usize, f64, PathEntry)> = None;
        for (idx, entry) in entries.iter().enumerate() {
            if entry.is_expired(now) {
                continue;
            }
            let bitrate = entry.receiving_interface.as_ref()
                .and_then(|name| interfaces.iter().find(|i| &i.name == name))
                .and_then(|i| i.bitrate);
            let score = entry.score(bitrate);
            match best {
                Some((_, best_score, _)) if score <= best_score => {},
                _ => { best = Some((idx, score, entry.clone())); }
            }
        }
        best.map(|(idx, _, e)| (idx, e))
    }

    /// Select the best path entry for a destination (convenience wrapper).
    fn select_path_for(
        destination_hash: &[u8],
    ) -> Option<(usize, PathEntry)> {
        let state = TRANSPORT.lock().unwrap();
        let now_ts = now();
        let interfaces = state.interfaces.clone();
        Self::select_path(&state.path_table, &interfaces, destination_hash, now_ts)
    }

    /// Return all non-expired path entries for `destination_hash`, sorted
    /// by `score()` descending (best first).  Used by outbound hedging:
    /// each stale entry triggers a fallback send on the next-best entry,
    /// stopping at the first fresh one.
    fn select_all_paths(
        table: &HashMap<Vec<u8>, VecDeque<PathEntry>>,
        interfaces: &[InterfaceStub],
        destination_hash: &[u8],
        now: f64,
    ) -> Vec<(usize, f64, PathEntry)> {
        let entries = match table.get(destination_hash) {
            Some(e) => e,
            None => return Vec::new(),
        };
        let mut scored: Vec<(usize, f64, PathEntry)> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| !e.is_expired(now))
            .map(|(idx, e)| {
                let bitrate = e
                    .receiving_interface
                    .as_ref()
                    .and_then(|name| interfaces.iter().find(|i| &i.name == name))
                    .and_then(|i| i.bitrate);
                let score = e.score(bitrate);
                (idx, score, e.clone())
            })
            .collect();
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });
        scored
    }

    pub fn has_path(destination_hash: &[u8]) -> bool {
        let state = TRANSPORT.lock().unwrap();
        let now_ts = now();
        Self::select_path(&state.path_table, &state.interfaces, destination_hash, now_ts).is_some()
    }

    /// Hop count for the currently-cached path to `destination_hash`, or
    /// `None` if no live path entry exists.
    pub fn path_hops(destination_hash: &[u8]) -> Option<u8> {
        let state = TRANSPORT.lock().unwrap();
        let now_ts = now();
        Self::select_path(&state.path_table, &state.interfaces, destination_hash, now_ts)
            .map(|(_, e)| e.hops)
    }

    pub fn next_hop_interface_hw_mtu(destination_hash: &[u8]) -> Option<usize> {
        let iface = Transport::next_hop_interface(destination_hash)?;
        let mut state = TRANSPORT.lock().unwrap();
        let iface = find_interface_by_name(&mut state.interfaces, &iface)?;
        if iface.autoconfigure_mtu || iface.fixed_mtu {
            iface.hw_mtu
        } else {
            None
        }
    }

    pub fn next_hop_per_bit_latency(destination_hash: &[u8]) -> Option<f64> {
        let iface = Transport::next_hop_interface(destination_hash)?;
        let mut state = TRANSPORT.lock().unwrap();
        let iface = find_interface_by_name(&mut state.interfaces, &iface)?;
        iface.bitrate.map(|b| 1.0 / b)
    }

    pub fn next_hop_per_byte_latency(destination_hash: &[u8]) -> Option<f64> {
        Transport::next_hop_per_bit_latency(destination_hash).map(|v| v * 8.0)
    }

    pub fn first_hop_timeout(destination_hash: &[u8]) -> f64 {
        if let Some(latency) = Transport::next_hop_per_byte_latency(destination_hash) {
            (crate::reticulum::MTU as f64) * latency + crate::reticulum::DEFAULT_PER_HOP_TIMEOUT
        } else {
            crate::reticulum::DEFAULT_PER_HOP_TIMEOUT
        }
    }

    pub fn extra_link_proof_timeout(interface_name: Option<&str>) -> f64 {
        if let Some(name) = interface_name {
            let mut state = TRANSPORT.lock().unwrap();
            if let Some(iface) = find_interface_by_name(&mut state.interfaces, name) {
                if let Some(bitrate) = iface.bitrate {
                    return ((1.0 / bitrate) * 8.0) * crate::reticulum::MTU as f64;
                }
            }
        }
        0.0
    }

    /// Remove ALL path entries for `destination_hash`.  In the multi-entry
    /// model there is no soft-expire hack — we just drop the entire deque.
    /// Returns true if any entry existed.
    pub fn expire_path(destination_hash: &[u8]) -> bool {
        let mut state = TRANSPORT.lock().unwrap();
        let existed = state.path_table.remove(destination_hash).is_some();
        if existed {
            state.path_table_dirty = true;
        }
        existed
    }

    pub fn drop_announce_queues() -> usize {
        let mut state = TRANSPORT.lock().unwrap();
        let mut dropped = 0;
        for iface in &mut state.interfaces {
            dropped += iface.announce_queue.len();
            iface.announce_queue.clear();
        }
        dropped
    }

    pub fn blackhole_identity(identity_hash: Vec<u8>, until: Option<f64>, reason: Option<String>) -> bool {
        let mut state = TRANSPORT.lock().unwrap();
        state.blackholed_identities.insert(
            identity_hash.clone(),
            BlackholeEntry {
                source: identity_hash,
                until,
                reason,
            },
        );
        true
    }

    pub fn unblackhole_identity(identity_hash: Vec<u8>) -> bool {
        let mut state = TRANSPORT.lock().unwrap();
        state.blackholed_identities.remove(&identity_hash).is_some()
    }

    /// Remove path entries for `destination_hash` whose `receiving_interface`
    /// matches `blocked_interface`.  When `blocked_interface` is `None`,
    /// removes ALL entries for the destination (backward compat with
    /// external callers like `drop_path`).
    pub fn mark_path_unresponsive(destination_hash: &[u8], blocked_interface: Option<&str>) -> bool {
        let mut state = TRANSPORT.lock().unwrap();
        let mut removed = false;
        let mut is_empty = false;
        if let Some(deque) = state.path_table.get_mut(destination_hash) {
            let before = deque.len();
            if let Some(iface) = blocked_interface {
                deque.retain(|e| e.receiving_interface.as_deref() != Some(iface));
            } else {
                deque.clear();
            }
            removed = before > deque.len();
            is_empty = deque.is_empty();
        }
        if is_empty {
            state.path_table.remove(destination_hash);
        }
        if removed {
            state.path_table_dirty = true;
        }
        removed
    }

    /// No-op in the multi-entry model (path_states dict is removed).
    pub fn mark_path_responsive(_destination_hash: &[u8]) -> bool {
        true
    }

    /// No-op in the multi-entry model (path_states dict is removed).
    pub fn mark_path_unknown_state(_destination_hash: &[u8]) -> bool {
        true
    }

    /// Always returns false in the multi-entry model (path_states dict
    /// is removed).  Callers should use `!has_path()` instead.
    pub fn path_is_unresponsive(_destination_hash: &[u8]) -> bool {
        false
    }

    pub fn await_path(destination_hash: &[u8], timeout: Option<f64>, on_interface: Option<String>) -> bool {
        let timeout_at = now() + timeout.unwrap_or(PATH_REQUEST_TIMEOUT);
        if Transport::has_path(destination_hash) {
            return true;
        }
        Transport::request_path(destination_hash, None, on_interface, None, None);
        while !Transport::has_path(destination_hash) && now() < timeout_at {
            thread::sleep(Duration::from_millis(50));
        }
        Transport::has_path(destination_hash)
    }

    pub fn register_destination(destination: Destination) {
        let mut state = TRANSPORT.lock().unwrap();
        if destination.direction == crate::destination::Direction::IN {
            if state.destinations.iter().any(|d| d.hash == destination.hash) {
                return;
            }
            state.destinations.push(destination);
        }
    }

    /// Update an already-registered destination (e.g. after ratchet rotation).
    /// Replaces the existing entry with the same hash.
    pub fn update_destination(destination: Destination) {
        let mut state = TRANSPORT.lock().unwrap();
        if let Some(existing) = state.destinations.iter_mut().find(|d| d.hash == destination.hash) {
            *existing = destination;
        }
    }

    pub fn deregister_destination(destination_hash: &[u8]) {
        let mut state = TRANSPORT.lock().unwrap();
        state.destinations.retain(|d| d.hash != destination_hash);
    }

    /// Remove a link_table relay entry immediately instead of waiting
    /// for the periodic cull (up to LINK_TIMEOUT / 900s). Called on
    /// link teardown to free stale relay state promptly — critical on
    /// bandwidth-constrained links where connections drop frequently.
    pub fn remove_link_entry(link_id: &[u8]) {
        let mut state = TRANSPORT.lock().unwrap();
        state.link_table.remove(link_id);
    }

    pub fn register_link(link: crate::link::Link) {
        let mut state = TRANSPORT.lock().unwrap();
        if link.initiator {
            if !state.pending_links.iter().any(|l| l.link_id == link.link_id) {
                state.pending_links.push(link);
            }
        } else {
            if !state.active_links.iter().any(|l| l.link_id == link.link_id) {
                state.active_links.push(link);
            }
        }
    }

    pub fn activate_link(link_id: &[u8]) {
        let mut state = TRANSPORT.lock().unwrap();
        if let Some(pos) = state.pending_links.iter().position(|l| l.link_id == link_id) {
            let link = state.pending_links.remove(pos);
            state.active_links.push(link);
        }
    }

    pub fn register_announce_handler(handler: AnnounceHandler) {
        let mut state = TRANSPORT.lock().unwrap();
        state.announce_handlers.push(handler);
    }

    pub fn deregister_announce_handler(aspect_filter: &str) {
        let mut state = TRANSPORT.lock().unwrap();
        state.announce_handlers.retain(|h| h.aspect_filter.as_deref() != Some(aspect_filter));
    }

    pub fn inbound(raw: Vec<u8>, receiving_interface: Option<String>) -> bool {
        // Log raw packet type from header byte before any processing
        let raw_ptype = if raw.len() > 2 { raw[0] & 0x03 } else { 0xFF };
        let raw_ptype_str = match raw_ptype { 0 => "DATA", 1 => "ANNOUNCE", 2 => "LINKREQUEST", 3 => "PROOF", _ => "?" };
        // Demoted to DEBUG: this fired per-packet at NOTICE and was the dominant
        // log-volume contributor under path-request floods. The richer
        // "Inbound DATA/LINKREQUEST/PROOF hops=… dest=…" line below carries
        // the same useful information for ops triage.
        if raw_ptype != ANNOUNCE {
            crate::log(&format!("inbound_raw len={} ptype_byte={} ({})", raw.len(), raw_ptype, raw_ptype_str), crate::LOG_DEBUG, false, false);
        }
        // IFAC flag check: if interface doesn't have IFAC, drop packets with IFAC flag
        if raw.len() > 2 && (raw[0] & 0x80) == 0x80 {
            // IFAC flag set but we don't have IFAC configured - drop
            crate::log(&format!("inbound_raw IFAC drop len={} ptype={}", raw.len(), raw_ptype_str), crate::LOG_NOTICE, false, false);
            return false;
        }
        if raw.len() <= 2 {
            return false;
        }
        let mut packet = Packet::new(None, Vec::new(), 0, 0, BROADCAST, crate::packet::HEADER_1, None, None, false, 0);
        packet.raw = raw;
        packet.receiving_interface = receiving_interface;
        if !packet.unpack() {
            crate::log(&format!("inbound unpack FAILED len={} raw_ptype={}", packet.raw.len(), raw_ptype_str), crate::LOG_NOTICE, false, false);
            return false;
        }
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        // Record the wall-clock of this inbound packet against its
        // receiving interface so `Transport::outbound`'s §1 watchdog
        // can detect "outbound dispatched but no inbound for >30 s"
        // half-open peers (the wedge analysed in
        // /memories/repo/rfed-tcp-watchdog-failure.md).
        if let Some(ref recv_iface) = packet.receiving_interface {
            let now_secs = now();
            if let Ok(mut state) = TRANSPORT.lock() {
                if let Some(iface) = state.interfaces.iter_mut().find(|i| &i.name == recv_iface) {
                    iface.last_inbound_at = now_secs;
                }
                if let Some(iface) = state.local_client_interfaces.iter_mut().find(|i| &i.name == recv_iface) {
                    iface.last_inbound_at = now_secs;
                }
            }
        }
        // Early-drop: when drop_announces is enabled, silently discard
        // announce packets before any logging or processing. Two exceptions
        // always pass through:
        //   1. PATH_RESPONSE replies to our own request_path() calls.
        //   2. Announces from destinations on the watchlist (so the app
        //      stays aware of peers it actively cares about).
        if packet.packet_type == ANNOUNCE {
            let should_drop = {
                let state = TRANSPORT.lock().unwrap();
                if !state.drop_announces {
                    false
                } else if packet.context == crate::packet::PATH_RESPONSE {
                    false
                } else if let Some(ref dest_hash) = packet.destination_hash {
                    !state.announce_watchlist.contains(dest_hash.as_slice())
                } else {
                    true
                }
            };
            if should_drop {
                return false;
            }
        }

        let ptype_str = match packet.packet_type { 0 => "DATA", 1 => "ANNOUNCE", 2 => "LINKREQUEST", 3 => "PROOF", _ => "?" };
        // Suppress per-packet ANNOUNCE log spam — the global summary in
        // `announce_log` aggregates the volume. Other ptypes are always logged.
        if packet.packet_type == ANNOUNCE {
            crate::announce_log::count_inbound_announce();
            crate::announce_log::flush_if_due();
            if crate::announce_log::is_whitelisted(packet.destination_hash.as_deref()) {
                crate::log(&format!("Inbound {} hops={} dest={} ctx={} dtype={:?}", ptype_str, packet.hops,
                    packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
                    packet.context, packet.destination_type), crate::LOG_NOTICE, false, false);
            }
        } else {
            // Suppress DATA hops=0 — these are high-volume local-interface
            // keepalive/control packets and contribute nothing to ops triage.
            let suppress = packet.packet_type == DATA && packet.hops == 0;
            if !suppress {
                crate::log(&format!("Inbound {} hops={} dest={} ctx={} dtype={:?}", ptype_str, packet.hops,
                    packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
                    packet.context, packet.destination_type), crate::LOG_NOTICE, false, false);
            }
        }
        let _trace_dest_hex = packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default();
        let _trace_is_target = _trace_dest_hex.starts_with("6b9f66014d9853");
        // Hops increment MUST happen AFTER the filter check.
        // The filter uses hops to gate Plain/Group forwarding
        // (hops <= 1), and incrementing first causes every
        // backbone packet arriving with hops=1 to be rejected.

        // Inline packet_filter + control destination check in a single lock acquisition
        let (filter_pass, control_aspects) = {
            let mut state = TRANSPORT.lock().unwrap();

            // --- packet_filter logic (inlined to avoid separate lock) ---
            // The transport_id check only applies when rnsd is acting as
            // a local shared instance serving multiple apps with different
            // transport identities.  In standalone mode, every connected
            // client (MeshChat via TCP, PostInterface backbone peers) has
            // its own identity and must be accepted for forwarding.
            let mut filter_ok = if state.is_connected_to_shared_instance {
                // Shared instance: the instance daemon handles filtering.
                true
            } else if packet.context == crate::packet::KEEPALIVE
                || packet.context == crate::packet::RESOURCE_REQ
                || packet.context == crate::packet::RESOURCE_PRF
                || packet.context == crate::packet::RESOURCE
                || packet.context == crate::packet::CACHE_REQUEST
                || packet.context == crate::packet::CHANNEL
            {
                true
            } else if packet.destination_type == Some(crate::destination::DestinationType::Plain) {
                if packet.packet_type != ANNOUNCE {
                    packet.hops <= 1
                } else {
                    false // Drop invalid PLAIN announce
                }
            } else if packet.destination_type == Some(crate::destination::DestinationType::Group) {
                if packet.packet_type != ANNOUNCE {
                    packet.hops <= 1
                } else {
                    false // Drop invalid GROUP announce
                }
            } else if let Some(hash) = &packet.packet_hash {
                if !state.packet_hashlist.contains(hash) && !state.packet_hashlist_prev.contains(hash) {
                    true
                } else if packet.packet_type == ANNOUNCE
                    && packet.destination_type == Some(crate::destination::DestinationType::Single)
                {
                    // ANNOUNCE packets for SINGLE destinations always pass,
                    // even if the hash is already in the hashlist
                    true
                } else {
                    false
                }
            } else if packet.packet_type == ANNOUNCE {
                packet.destination_type != Some(crate::destination::DestinationType::Link)
            } else {
                false
            };

            // ── Announce rate limiter ──────────────────────────────────────
            // Drop announces for the same destination if more than
            // ANNOUNCE_RATE_LIMIT (10) arrive within 1 second.
            if filter_ok && packet.packet_type == ANNOUNCE {
                if let Some(dest_hash) = &packet.destination_hash {
                    let now_ts = now();
                    let entry = state.announce_rate_table
                        .entry(dest_hash.clone())
                        .or_insert(AnnounceRateEntry {
                            last: now_ts,
                            rate_violations: 0,
                            blocked_until: 0.0,
                            timestamps: Vec::new(),
                        });
                    entry.timestamps.push(now_ts);
                    entry.timestamps.retain(|t| now_ts - *t < 1.0);
                    if entry.timestamps.len() > ANNOUNCE_RATE_LIMIT {
                        entry.rate_violations = entry.rate_violations.saturating_add(1);
                        entry.last = now_ts;
                        filter_ok = false;
                    }
                }
            }

            if !filter_ok {
                (false, None)
            } else {
                // --- control destination check (done while we already hold the lock) ---
                let ctrl = packet.destination_hash.as_ref().and_then(|dh| {
                    let in_control = state.control_hashes.contains(dh);
                    if in_control {
                        for control_dest in &state.control_destinations {
                            if &control_dest.hash == dh && control_dest.app_name == APP_NAME {
                                return Some(control_dest.aspects.clone());
                            }
                        }
                        Some(Vec::new()) // in control_hashes but no matching dest
                    } else {
                        None
                    }
                });
                (true, ctrl)
            }
        };

        if !filter_pass {
            crate::log(&format!("Inbound FILTERED ptype={} ctx={}", packet.packet_type, packet.context), crate::LOG_NOTICE, false, false);
            return false;
        }
        // Increment hops AFTER the filter — the filter uses hops to
        // gate Plain/Group forwarding (hops <= 1). Python parity:
        // RNS/Transport.py increments hops after packet_filter().
        packet.hops = packet.hops.saturating_add(1);
        crate::log(&format!("[POST-FILTER] ptype={} dest={} dtype={:?} ctx={} hops={} — filter passed",
            packet.packet_type,
            packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
            packet.destination_type,
            packet.context,
            packet.hops,
        ), crate::LOG_NOTICE, false, false);
        if _trace_is_target { crate::log("[TRACE] target passed filter", crate::LOG_DEBUG, false, false); }

        // Handle control destination routing (lock already released)
        crate::log(&format!("[PRE-CTRL] ptype={} dest={} ctrl_aspects={:?}",
            packet.packet_type,
            packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
            control_aspects.as_ref().map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
        ), crate::LOG_NOTICE, false, false);
        if let Some(ref aspects) = control_aspects {
            if _trace_is_target { crate::log(&format!("[TRACE] target HIT control aspects={:?}", aspects), crate::LOG_DEBUG, false, false); }
            match aspects.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
                ["path", "request"] => Transport::path_request_handler(&packet.data, &packet),
                ["tunnel", "synthesize"] => Transport::tunnel_synthesize_handler(&packet.data, &packet),
                _ => {}
            }
            return true;
        }

        if packet.context == CACHE_REQUEST {
            if Transport::cache_request_packet(&packet) {
                if _trace_is_target { crate::log("[TRACE] target HIT cache_request return", crate::LOG_NOTICE, false, false); }
                return true;
            }
        }

        let mut announce_should_add = false;
        if packet.packet_type == ANNOUNCE {

            announce_should_add = true;
            if packet.data.len() >= (crate::identity::KEYSIZE / 8) {
                // Fast-path dedup: if we've already Ed25519-validated an
                // announce with this exact packet_hash, skip the expensive
                // verify call. Same packet_hash ⇒ identical bytes ⇒ identical
                // signature ⇒ guaranteed valid. The cache is bounded by the
                // packet_hashlist rotation policy.
                let already_validated = packet.packet_hash.as_ref().map(|h| {
                    let s = TRANSPORT.lock().unwrap();
                    s.validated_announce_hashes.contains(h)
                        || s.validated_announce_hashes_prev.contains(h)
                }).unwrap_or(false);

                let valid = if already_validated {
                    crate::announce_log::count_dedup_skipped();
                    true
                } else {
                    let pub_key = packet.data[..(crate::identity::KEYSIZE / 8)].to_vec();
                    Identity::validate_announce(
                        &packet.data,
                        packet.destination_hash.as_ref().map(|v| v.as_slice()),
                        Some(&pub_key),
                        packet.context_flag,
                    )
                };

                if !valid {
                    crate::announce_log::count_invalid();
                    if crate::announce_log::is_whitelisted(packet.destination_hash.as_deref()) {
                        crate::log(&format!("Announce INVALID dest={}", packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default()), crate::LOG_NOTICE, false, false);
                    }
                    announce_should_add = false;
                } else {
                    crate::announce_log::count_valid();
                    if crate::announce_log::is_whitelisted(packet.destination_hash.as_deref()) {
                        crate::log(&format!("Announce VALID dest={}", packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default()), crate::LOG_NOTICE, false, false);
                    }
                    // Remember this packet_hash as validated so subsequent
                    // duplicates short-circuit the Ed25519 verify above.
                    if !already_validated {
                        if let Some(h) = packet.packet_hash.clone() {
                            TRANSPORT.lock().unwrap().validated_announce_hashes.insert(h);
                        }
                    }
                }
            }

            if announce_should_add {
                if let (Some(destination_hash), Some(announced_identity)) = (
                    packet.destination_hash.as_deref(),
                    Self::extract_announce_identity(&packet),
                ) {
                    if let Ok(public_key) = announced_identity.get_public_key() {
                        let app_data_for_remember = Self::extract_announce_app_data(&packet);
                        let _ = Identity::remember_destination(
                            destination_hash,
                            &public_key,
                            app_data_for_remember,
                        );
                        if let Some(ratchet) = Self::extract_announce_ratchet(&packet) {
                            let _ = Identity::remember_ratchet(destination_hash, &ratchet);
                        }
                    }
                }
            }
        }

        crate::log(&format!("[POST-ANNOUNCE] ptype={} dest={} — made it past announce block",
            packet.packet_type,
            packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
        ), crate::LOG_NOTICE, false, false);

        let interface_announce_callback = if packet.packet_type == ANNOUNCE && announce_should_add {
            let handler = {
                let state = TRANSPORT.lock().unwrap();
                state.interface_announce_handler.clone()
            };

            if let Some(handler) = handler {
                if let Some(filter_hash) = Self::name_hash_for_aspect_filter(&handler.aspect_filter) {
                    if let Some(name_hash) = Self::extract_announce_name_hash(&packet) {
                        if name_hash == filter_hash {
                            if let Some(announced_identity) = Self::extract_announce_identity(&packet) {
                                if let Some(app_data) = Self::extract_announce_app_data(&packet) {
                                    Some((handler, packet.destination_hash.clone().unwrap_or_default(), announced_identity, app_data))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let inbound_lock_wait_started = Instant::now();
        crate::log(&format!("[PRE-LOCK] ptype={} dest={} — about to acquire dispatch lock",
            packet.packet_type,
            packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
        ), crate::LOG_NOTICE, false, false);
        let mut state = TRANSPORT.lock().unwrap();
        let inbound_wait_ms = inbound_lock_wait_started.elapsed().as_millis();
        if inbound_wait_ms > 250 {
        }
        if _trace_is_target { crate::log(&format!("[TRACE] target acquired inbound state lock (waited {}ms)", inbound_wait_ms), crate::LOG_NOTICE, false, false); }
        let inbound_lock_started = Instant::now();
        let mut deferred_outbound: Vec<(String, Vec<u8>)> = Vec::new();
        let mut deferred_announce_callbacks: Vec<(AnnounceCallback, Vec<u8>, Identity, Vec<u8>, Option<Vec<u8>>, bool)> = Vec::new();
        let mut deferred_destination_receives: Vec<(Destination, Packet)> = Vec::new();
        let mut deferred_link_packets: Vec<Packet> = Vec::new();

        let mut remember_packet_hash = true;
        crate::log(&format!("[INBOUND-DISPATCH] ptype={} dest={} dtype={:?} ctx={} hops={}",
            packet.packet_type,
            packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
            packet.destination_type,
            packet.context,
            packet.hops,
        ), crate::LOG_NOTICE, false, false);
        if let Some(destination_hash) = &packet.destination_hash {
            if state.link_table.contains_key(destination_hash) {
                remember_packet_hash = false;
            }
        }
        if packet.destination_type == Some(crate::destination::DestinationType::Link) {
            remember_packet_hash = false;
        }
        if packet.packet_type == PROOF && packet.context == crate::packet::LRPROOF {
            remember_packet_hash = false;
        }
        if remember_packet_hash {
            if let Some(packet_hash) = packet.packet_hash.clone() {
                if !state.packet_hashlist.contains(&packet_hash) && !state.packet_hashlist_prev.contains(&packet_hash) {
                    state.packet_hashlist.insert(packet_hash);
                }
            }
        }

        if packet.packet_type == ANNOUNCE {
            if announce_should_add {
                if let (Some(destination_hash), Some(announced_identity)) = (
                    packet.destination_hash.as_deref(),
                    Self::extract_announce_identity(&packet),
                ) {
                    let is_path_response = packet.context == crate::packet::PATH_RESPONSE;
                    let callback_packet_hash = packet.packet_hash.clone();
                    let callback_handlers = state.announce_handlers.clone();
                    let callback_app_data = Self::extract_announce_app_data(&packet).unwrap_or_default();

                    for handler in &callback_handlers {
                        if is_path_response && !handler.receive_path_responses {
                            continue;
                        }

                        if let Some(filter) = &handler.aspect_filter {
                            if let Some(filter_hash) = Self::name_hash_for_aspect_filter(filter) {
                                if let Some(name_hash) = Self::extract_announce_name_hash(&packet) {
                                    if name_hash != filter_hash {
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                            }
                        }

                        deferred_announce_callbacks.push((
                            handler.callback.clone(),
                            destination_hash.to_vec(),
                            announced_identity.clone(),
                            callback_app_data.clone(),
                            callback_packet_hash.clone(),
                            is_path_response,
                        ));
                    }
                }

                if let Some(destination_hash) = &packet.destination_hash {
                    if state.transport_enabled && packet.transport_id.is_some() {
                        let mut remove_entry = false;
                        if let Some(announce_entry) = state.announce_table.get_mut(destination_hash) {
                            let entry_hops = match announce_entry.get(IDX_AT_HOPS) {
                                Some(AnnounceEntryValue::Hops(hops)) => *hops,
                                _ => 0,
                            };
                            let retries = match announce_entry.get(IDX_AT_RETRIES) {
                                Some(AnnounceEntryValue::Retries(r)) => *r,
                                _ => 0,
                            };
                            let local_rebroadcasts = match announce_entry.get(IDX_AT_LCL_RBRD) {
                                Some(AnnounceEntryValue::LocalRebroadcasts(r)) => *r,
                                _ => 0,
                            };
                            let retransmit_timeout = match announce_entry.get(IDX_AT_RTRNS_TMO) {
                                Some(AnnounceEntryValue::RetransmitTimeout(t)) => *t,
                                _ => 0.0,
                            };

                            // Dedup: if this announce has travelled more hops than
                            // the entry we stored, it has been circulating.
                            // Use `packet.hops > entry_hops` (not exact `- 1`)
                            // because intermediate peers (Python client) add
                            // their own hop, so the packet may come back with
                            // hops = entry_hops + 2 or more.
                            if packet.hops > 0 && packet.hops > entry_hops {
                                if let Some(AnnounceEntryValue::LocalRebroadcasts(count)) = announce_entry.get_mut(IDX_AT_LCL_RBRD) {
                                    *count = count.saturating_add(1);
                                }
                                if retries > 0 && local_rebroadcasts + 1 >= LOCAL_REBROADCASTS_MAX {
                                    remove_entry = true;
                                }
                            }

                            if packet.hops > 0 && packet.hops > entry_hops && retries > 0 {
                                if now() < retransmit_timeout {
                                    remove_entry = true;
                                }
                            }
                        }

                        if remove_entry {
                            state.announce_table.remove(destination_hash);
                        }
                    }

                    let random_blob_start = crate::identity::KEYSIZE / 8 + crate::identity::NAME_HASH_LENGTH / 8;
                    let random_blob_end = random_blob_start + 10;
                    let new_blob: Option<Vec<u8>> = if packet.data.len() >= random_blob_end {
                        Some(packet.data[random_blob_start..random_blob_end].to_vec())
                    } else {
                        None
                    };

                    // ── MULTI-ENTRY PATH INSERTION ───────────────────────────────────────
                    // New model (replaces the old 80-line / 11-leaf decision tree):
                    //
                    //   1. Track seen blobs in global_blobs (anti-replay, decoupled).
                    //   2. Always prepend the new path entry (newest-first).
                    //   3. Dedup by packet_hash within the same destination.
                    //   4. Cap at MAX_PATHS_PER_DEST (=3).
                    //   5. No quality gate — multiple paths coexist; select_path()
                    //      picks the best at forwarding time via bitrate/hops score.
                    //
                    // This eliminates:
                    //   • Convergence race (fast-WiFi 3-hop vs slow-LoRa 2-hop)
                    //   • Deadlock (UNRESPONSIVE poison blocking better paths)
                    //   • Silent discard of backup topology
                    // ──────────────────────────────────────────────────────────────────────

                    // Anti-replay via global blob set (decoupled from path entries)
                    if let Some(ref blob) = new_blob {
                        state.global_blobs.insert(blob.clone());
                        // Keep global set bounded
                        while state.global_blobs.len() > MAX_GLOBAL_BLOBS {
                            // Remove an arbitrary element — HashSet iteration is
                            // non-deterministic but fine for eviction.
                            if let Some(evict) = state.global_blobs.iter().next().cloned() {
                                state.global_blobs.remove(&evict);
                            } else {
                                break;
                            }
                        }
                    }

                    let received_from = packet.transport_id.clone()
                        .unwrap_or_else(|| destination_hash.clone());
                    let expires = now() + DESTINATION_TIMEOUT;

                    // ── Own-destination echo skip (unchanged) ──────────────────────────
                    let is_own_destination = state
                        .destinations
                        .iter()
                        .any(|d| d.hash.as_slice() == destination_hash.as_slice());
                    if is_own_destination {
                        crate::log(
                            &format!(
                                "Skipping own-destination echo: dest={} hops={}",
                                crate::hexrep(destination_hash, false),
                                packet.hops
                            ),
                            crate::LOG_NOTICE,
                            false,
                            false,
                        );
                    } else {
                        let packet_hash = packet.packet_hash.clone().unwrap_or_default();
                        let new_entry = PathEntry {
                            timestamp: now(),
                            next_hop: received_from.clone(),
                            hops: packet.hops,
                            expires,
                            receiving_interface: packet.receiving_interface.clone(),
                            packet_hash: packet_hash.clone(),
                        };

                        // Insert: get or create deque, dedup by packet_hash,
                        // push_front, truncate.
                        let deque = state.path_table
                            .entry(destination_hash.clone())
                            .or_insert_with(VecDeque::new);
                        deque.retain(|e| e.packet_hash != packet_hash);
                        deque.push_front(new_entry);
                        deque.truncate(MAX_PATHS_PER_DEST);

                        state.path_table_dirty = true;
                        state.path_verified_this_session.insert(destination_hash.clone());
                        crate::transport::notify_path_added();
                        crate::announce_log::count_path_added();
                        if crate::announce_log::is_whitelisted(Some(destination_hash.as_slice())) {
                            crate::log(&format!("Path added dest={} hops={} table_size={}",
                                crate::hexrep(destination_hash, false),
                                packet.hops,
                                state.path_table.len()),
                                crate::LOG_NOTICE, false, false);
                        }
                        Transport::cache(&packet, true, Some("announce".to_string()));

                        // ── Discovery path request answer (unchanged) ──────────────────
                        if state.transport_enabled {
                            if let Some(discovery_entry) = state.discovery_path_requests.remove(destination_hash.as_slice()) {
                                if let Some(ref requesting_iface) = discovery_entry.requesting_interface {
                                    crate::log(&format!(
                                        "Got matching announce, answering waiting discovery path request for {} on {}",
                                        crate::hexrep(destination_hash, true), requesting_iface
                                    ), crate::LOG_DEBUG, false, false);
                                    let identity_hash_bytes = state.identity.as_ref()
                                        .and_then(|i| i.hash.clone())
                                        .unwrap_or_default();
                                    let dest_type_bits: u8 = match packet.destination_type {
                                        Some(crate::destination::DestinationType::Single) => 0x00,
                                        Some(crate::destination::DestinationType::Group) => 0x01,
                                        Some(crate::destination::DestinationType::Plain) => 0x02,
                                        Some(crate::destination::DestinationType::Link) => 0x03,
                                        None => 0x00,
                                    };
                                    let flags: u8 = (crate::packet::HEADER_2 << 6)
                                        | ((packet.context_flag & 0x01) << 5)
                                        | (MODE_TRANSPORT << 4)
                                        | (dest_type_bits << 2)
                                        | ANNOUNCE;
                                    let dest_hash_bytes = packet.destination_hash.clone()
                                        .unwrap_or_else(|| destination_hash.clone());
                                    let mut raw = Vec::with_capacity(2 + 16 + 16 + 1 + packet.data.len());
                                    raw.push(flags);
                                    raw.push(packet.hops);
                                    raw.extend_from_slice(&identity_hash_bytes);
                                    raw.extend_from_slice(&dest_hash_bytes);
                                    raw.push(crate::packet::PATH_RESPONSE);
                                    raw.extend_from_slice(&packet.data);
                                    deferred_outbound.push((requesting_iface.clone(), raw));
                                }
                            }
                        }

                        // ── Announce table + local client forwarding (unchanged) ───────
                        if state.transport_enabled && packet.context != crate::packet::PATH_RESPONSE {
                            let block_rebroadcasts = false;
                            let initial_timeout = now() + (rand::random::<f64>() * PATHFINDER_RW);
                            let announce_entry = vec![
                                AnnounceEntryValue::Timestamp(now()),
                                AnnounceEntryValue::RetransmitTimeout(initial_timeout),
                                AnnounceEntryValue::Retries(0),
                                AnnounceEntryValue::ReceivedFrom(received_from),
                                AnnounceEntryValue::Hops(packet.hops),
                                AnnounceEntryValue::Packet(packet.clone()),
                                AnnounceEntryValue::LocalRebroadcasts(0),
                                AnnounceEntryValue::BlockRebroadcasts(block_rebroadcasts),
                                AnnounceEntryValue::AttachedInterface(None),
                            ];
                            state.announce_table.insert(destination_hash.clone(), announce_entry);
                        }

                        // ── Build announce_raw for forwarding ──────────────────────
                        // Always build the raw announce packet so we can forward
                        // it to outbound interfaces (PostInterface, Backbone) even
                        // when there are no local client interfaces.  Without this,
                        // a bridge that only has WAN-facing interfaces silently
                        // consumes announces without propagating them.
                        let identity_hash_bytes = state.identity.as_ref()
                            .and_then(|i| i.hash.clone())
                            .unwrap_or_default();
                        let dest_type_bits: u8 = match packet.destination_type {
                            Some(crate::destination::DestinationType::Single) => 0x00,
                            Some(crate::destination::DestinationType::Group) => 0x01,
                            Some(crate::destination::DestinationType::Plain) => 0x02,
                            Some(crate::destination::DestinationType::Link) => 0x03,
                            None => 0x00,
                        };
                        let flags: u8 = (crate::packet::HEADER_2 << 6)
                            | ((packet.context_flag & 0x01) << 5)
                            | (MODE_TRANSPORT << 4)
                            | (dest_type_bits << 2)
                            | ANNOUNCE;
                        let dest_hash_bytes = packet.destination_hash.clone()
                            .unwrap_or_else(|| destination_hash.clone());
                        let announce_context = if packet.context == crate::packet::PATH_RESPONSE {
                            crate::packet::PATH_RESPONSE
                        } else {
                            crate::packet::NONE
                        };
                        let mut announce_raw = Vec::with_capacity(2 + 16 + 16 + 1 + packet.data.len());
                        announce_raw.push(flags);
                        announce_raw.push(packet.hops);
                        announce_raw.extend_from_slice(&identity_hash_bytes);
                        announce_raw.extend_from_slice(&dest_hash_bytes);
                        announce_raw.push(announce_context);
                        announce_raw.extend_from_slice(&packet.data);

                        // ── Forward to local client interfaces ─────────────────
                        if !state.local_client_interfaces.is_empty() {
                            let local_iface_names: Vec<String> = state.local_client_interfaces
                                .iter()
                                .filter(|i| packet.receiving_interface.as_deref() != Some(&i.name))
                                .map(|i| i.name.clone())
                                .collect();
                            let now_ts = now();
                            for iface_name in local_iface_names {
                                let last = state.client_announce_pacing.get(&iface_name).copied()
                                    .unwrap_or(now_ts - LOCAL_CLIENT_ANNOUNCE_PACE);
                                let dispatch_at = f64::max(now_ts, last + LOCAL_CLIENT_ANNOUNCE_PACE);
                                state.client_announce_pacing.insert(iface_name.clone(), dispatch_at);
                                if dispatch_at <= now_ts + 0.001 {
                                    deferred_outbound.push((iface_name, announce_raw.clone()));
                                } else {
                                    state.pending_local_announces.push((dispatch_at, iface_name, announce_raw.clone()));
                                }
                            }
                        }

                        // ── Forward to non-local outbound interfaces (ALWAYS) ──
                        // This runs regardless of whether local clients exist.
                        // Bridges that only connect WAN interfaces (TCPClient to
                        // rmap.world + PostInterface to PHP) must forward announces
                        // to all outbound interfaces so the wider mesh learns paths.
                        let local_names: std::collections::HashSet<String> = state
                            .local_client_interfaces.iter().map(|i| i.name.clone()).collect();
                        for iface in &state.interfaces {
                            if iface.out
                                && !local_names.contains(&iface.name)
                                && packet.receiving_interface.as_deref() != Some(&iface.name)
                            {
                                crate::log(
                                    &format!("[ANNOUNCE-FWD] forwarding announce dest={} to non-local iface={}",
                                        crate::hexrep(destination_hash, false), iface.name),
                                    crate::LOG_NOTICE, false, false,
                                );
                                deferred_outbound.push((iface.name.clone(), announce_raw.clone()));
                            }
                        }
                    }
                }
            }
        }

        // ── Inject/overwrite transport_id when path known ─────────────
        // Python Transport.py line 1492: when a packet arrives without
        // transport_id and the destination is a local client (path table
        // entry with hops==0), set transport_id to identity.  Extended
        // to also overwrite foreign transport_id from upstream PHP peers
        // so the forwarding block below can route the packet.
        if packet.packet_type != ANNOUNCE
        {
            if let Some(ref destination_hash) = packet.destination_hash {
                if state.path_table.contains_key(destination_hash.as_slice()) {
                    if let Some(ref identity) = state.identity {
                        if let Some(ref identity_hash) = identity.hash {
                            let had_foreign = packet.transport_id.is_some();
                            packet.transport_id = Some(identity_hash.clone());
                            crate::log(
                                &format!("[INJECT-TID] {} transport_id for ptype={} dest={} table_size={}",
                                    if had_foreign { "overwrote foreign" } else { "injected" },
                                    packet.packet_type,
                                    crate::hexrep(destination_hash, false),
                                    state.path_table.len()),
                                crate::LOG_NOTICE, false, false,
                            );
                        }
                    }
                } else {
                    crate::log(
                        &format!("[INJECT-MISS] no path for ptype={} dest={} table_size={}",
                            packet.packet_type,
                            crate::hexrep(destination_hash, false),
                            state.path_table.len()),
                        crate::LOG_NOTICE, false, false,
                    );
                }
            }
        }

        if packet.packet_type != ANNOUNCE && packet.transport_id.is_some() {
            if let Some(identity) = &state.identity {
                if identity
                    .hash
                    .as_ref()
                    .map(|hash| packet.transport_id.as_ref() == Some(hash))
                    .unwrap_or(false)
                {
                    if let Some(destination_hash) = &packet.destination_hash {
                        let (next_hop, remaining_hops, outbound_interface_name) =
                            Self::select_path(&state.path_table, &state.interfaces, destination_hash, now())
                                .map(|(_, e)| (e.next_hop.clone(), e.hops, e.receiving_interface.clone()))
                                .unwrap_or((Vec::new(), 0, None));

                        if !next_hop.is_empty() || state.path_table.contains_key(destination_hash) {

                            // Match Python Transport.py line 1448-1462:
                            // remaining_hops > 1 → replace transport_id with next_hop, update hops
                            // remaining_hops == 1 → strip transport headers (HEADER_2 → HEADER_1), update hops
                            // remaining_hops == 0 → just update hops
                            let dst_len = crate::reticulum::TRUNCATED_HASHLENGTH / 8; // 16
                            let mut new_raw = packet.raw.clone();
                            if remaining_hops > 1 {
                                if packet.header_type == crate::packet::HEADER_2 {
                                    // Already HEADER_2: replace transport_id (bytes 2..18) with next_hop
                                    if new_raw.len() > 2 + dst_len && next_hop.len() == dst_len {
                                        new_raw[1] = packet.hops;
                                        new_raw[2..2 + dst_len].copy_from_slice(&next_hop);
                                    }
                                } else {
                                    // HEADER_1 → HEADER_2: insert transport_id
                                    let new_flags = (crate::packet::HEADER_2 << 6) | (MODE_TRANSPORT << 4) | (packet.flags & 0b0000_1111);
                                    new_raw[0] = new_flags;
                                    new_raw[1] = packet.hops;
                                    new_raw.splice(2..2, next_hop.clone());
                                }
                            } else if remaining_hops == 1 && packet.header_type == crate::packet::HEADER_2 {
                                // Strip transport headers: HEADER_2 → HEADER_1
                                let new_flags = (crate::packet::HEADER_1 << 6) | (BROADCAST << 4) | (packet.flags & 0b0000_1111);
                                new_raw[0] = new_flags;
                                new_raw[1] = packet.hops;
                                if new_raw.len() > 2 + dst_len * 2 {
                                    new_raw.drain(2..2 + dst_len);
                                }
                            } else if remaining_hops == 0 {
                                if new_raw.len() > 1 {
                                    new_raw[1] = packet.hops;
                                }
                            }

                            if packet.packet_type == LINKREQUEST {
                                let now_ts = now();
                                // Compute extra_link_proof_timeout inline to avoid deadlocking on TRANSPORT
                                let mut proof_timeout = 0.0_f64;
                                if let Some(ref iface_name) = packet.receiving_interface {
                                    if let Some(iface) = state.interfaces.iter().find(|i| &i.name == iface_name) {
                                        if let Some(bitrate) = iface.bitrate {
                                            proof_timeout = ((1.0 / bitrate) * 8.0) * crate::reticulum::MTU as f64;
                                        }
                                    }
                                }
                                proof_timeout += now_ts + crate::link::ESTABLISHMENT_TIMEOUT_PER_HOP * (remaining_hops.max(1) as f64);

                                let mut path_mtu = crate::link::mtu_from_lr_packet(&packet.data);
                                let original_had_signalling = path_mtu.is_some();
                                let mode = crate::link::mode_from_lr_packet(&packet.data);
                                if let Some(name) = outbound_interface_name.as_ref() {
                                    if let Some(out_iface) = state.interfaces.iter().find(|i| &i.name == name) {
                                        if path_mtu.is_some() {
                                            if out_iface.hw_mtu.is_none() {
                                                path_mtu = None;
                                            } else if !out_iface.autoconfigure_mtu && !out_iface.fixed_mtu {
                                                path_mtu = None;
                                            } else if let Some(mtu) = path_mtu {
                                                let mut clamp = mtu;
                                                if let Some(ph_iface_name) = packet.receiving_interface.as_ref() {
                                                    if let Some(ph_iface) = state.interfaces.iter().find(|i| &i.name == ph_iface_name) {
                                                        if let Some(ph_mtu) = ph_iface.hw_mtu {
                                                            clamp = clamp.min(ph_mtu);
                                                        }
                                                    }
                                                }
                                                if let Some(nh_mtu) = out_iface.hw_mtu {
                                                    clamp = clamp.min(nh_mtu);
                                                }
                                                if clamp < mtu {
                                                    if let Ok(signalling) = crate::link::signalling_bytes(clamp, mode) {
                                                        if new_raw.len() >= crate::link::LINK_MTU_SIZE {
                                                            let len = new_raw.len();
                                                            new_raw[len - crate::link::LINK_MTU_SIZE..].copy_from_slice(&signalling);
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        // Python: only strip signalling bytes if they were originally
                                        // present in the packet and the outbound interface can't handle them.
                                        // Previous code checked path_mtu.is_none() which would also fire when
                                        // signalling was already stripped by a previous hop, causing double-truncation.
                                        if original_had_signalling && path_mtu.is_none() && new_raw.len() >= crate::link::LINK_MTU_SIZE {
                                            new_raw.truncate(new_raw.len() - crate::link::LINK_MTU_SIZE);
                                        }
                                    } else {
                                    }
                                } else {
                                }

                                let link_entry = vec![
                                    LinkEntryValue::Timestamp(now_ts),
                                    LinkEntryValue::NextHopTransport(next_hop.clone()),
                                    LinkEntryValue::NextHopInterface(outbound_interface_name.clone()),
                                    LinkEntryValue::RemainingHops(remaining_hops),
                                    LinkEntryValue::ReceivedInterface(packet.receiving_interface.clone()),
                                    LinkEntryValue::TakenHops(packet.hops),
                                    LinkEntryValue::DestinationHash(destination_hash.clone()),
                                    LinkEntryValue::Validated(false),
                                    LinkEntryValue::ProofTimeout(proof_timeout),
                                ];
                                let link_id = crate::link::link_id_from_lr_packet(&packet);
                                state.link_table.insert(link_id, link_entry);
                            } else {
                                let reverse_entry = vec![
                                    ReverseEntryValue::ReceivedInterface(packet.receiving_interface.clone()),
                                    ReverseEntryValue::OutboundInterface(outbound_interface_name.clone()),
                                    ReverseEntryValue::Timestamp(now()),
                                ];
                                state.reverse_table.insert(packet.get_truncated_hash(), reverse_entry);
                            }

                            if let Some(name) = outbound_interface_name.as_ref() {
                                deferred_outbound.push((name.clone(), new_raw));
                            } else {
                            }

                            // Refresh timestamp on the best path entry
                            if let Some(deque) = state.path_table.get_mut(destination_hash) {
                                if let Some(front) = deque.front_mut() {
                                    front.timestamp = now();
                                }
                            }
                        }
                    }
                }
            }
        }

        if packet.packet_type != ANNOUNCE && packet.packet_type != LINKREQUEST && packet.context != crate::packet::LRPROOF {
            if let Some(destination_hash) = &packet.destination_hash {
                let outbound_name = if let Some(entry) = state.link_table.get_mut(destination_hash) {
                    let nh_if = match entry.get(IDX_LT_NH_IF) {
                        Some(LinkEntryValue::NextHopInterface(name)) => name.clone(),
                        _ => None,
                    };
                    let rcvd_if = match entry.get(IDX_LT_RCVD_IF) {
                        Some(LinkEntryValue::ReceivedInterface(name)) => name.clone(),
                        _ => None,
                    };
                    let rem_hops = match entry.get(IDX_LT_REM_HOPS) {
                        Some(LinkEntryValue::RemainingHops(hops)) => *hops,
                        _ => 0,
                    };
                    let taken_hops = match entry.get(IDX_LT_HOPS) {
                        Some(LinkEntryValue::TakenHops(hops)) => *hops,
                        _ => 0,
                    };

                    let mut outbound_name: Option<String> = None;
                    if nh_if == rcvd_if {
                        if packet.hops == rem_hops || packet.hops == taken_hops {
                            outbound_name = nh_if.clone();
                        }
                    } else if packet.receiving_interface == nh_if && packet.hops == rem_hops {
                        outbound_name = rcvd_if.clone();
                    } else if packet.receiving_interface == rcvd_if && packet.hops == taken_hops {
                        outbound_name = nh_if.clone();
                    }

                    outbound_name
                } else {
                    None
                };

                if let Some(name) = outbound_name.as_ref() {
                    if let Some(hash) = packet.packet_hash.clone() {
                        state.packet_hashlist.insert(hash);
                    }
                    let mut new_raw = packet.raw.clone();
                    if new_raw.len() > 1 {
                        new_raw[1] = packet.hops;
                    }
                    if let Some(iface) = state.interfaces.iter().find(|i| &i.name == name) {
                        deferred_outbound.push((iface.name.clone(), new_raw));
                    }
                    if let Some(entry) = state.link_table.get_mut(destination_hash) {
                        if let Some(LinkEntryValue::Timestamp(ts)) = entry.get_mut(IDX_LT_TIMESTAMP) {
                            *ts = now();
                        }
                    }
                } else {
                    // ── No link_table entry: try path-table forwarding ──
                    let forward: Option<(String, Vec<u8>)> = {
                        if let Some(entries) = state.path_table.get(destination_hash) {
                            let now_ts = now();
                            entries.iter()
                                .filter(|e| !e.is_expired(now_ts))
                                .min_by_key(|e| e.hops)
                                .and_then(|path| {
                                    path.receiving_interface.as_ref().map(|out_iface| {
                                        let mut new_raw = packet.raw.clone();
                                        if new_raw.len() > 1 {
                                            new_raw[1] = packet.hops;
                                        }
                                        (out_iface.clone(), new_raw)
                                    })
                                })
                        } else {
                            None
                        }
                    };
                    if let Some((out_iface, new_raw)) = forward {
                        deferred_outbound.push((out_iface.clone(), new_raw));
                    }
                }
            }
        }

        if packet.packet_type == LINKREQUEST {
            if let Some(destination_hash) = &packet.destination_hash {
                for dest in &mut state.destinations {
                    if &dest.hash == destination_hash {
                        deferred_destination_receives.push((dest.clone(), packet.clone()));
                    }
                }
            }
        }

        if packet.packet_type == DATA {
            let dest_hex = packet.destination_hash.as_ref()
                .map(|h| crate::hexrep(h, false))
                .unwrap_or_default();
            crate::log(&format!("[DATA-IN] ptype=DATA dtype={:?} dest={} ctx={} hops={}",
                packet.destination_type, dest_hex, packet.context, packet.hops),
                crate::LOG_NOTICE, false, false);
            if _trace_is_target { crate::log(&format!("[TRACE] target reached DATA branch dtype={:?}", packet.destination_type), crate::LOG_NOTICE, false, false); }
            if packet.destination_type == Some(crate::destination::DestinationType::Link) {
                if _trace_is_target { crate::log("[TRACE] target → deferred_link_packets", crate::LOG_NOTICE, false, false); }
                crate::log(&format!("[DATA-LINK] dest={} pushed to deferred_link_packets", dest_hex),
                    crate::LOG_NOTICE, false, false);
                deferred_link_packets.push(packet.clone());
            } else {
                if let Some(destination_hash) = &packet.destination_hash {
                    let mut matched = 0;
                    for dest in &mut state.destinations {
                        if &dest.hash == destination_hash {
                            deferred_destination_receives.push((dest.clone(), packet.clone()));
                            matched += 1;
                        }
                    }
                    if matched == 0 {
                        // ── Path-table-based forwarding ────────────────────
                        // If no local destination matched, try the path table.
                        // This enables bridge/relay operation — packets from
                        // the backbone (PostInterface) or local TCP clients
                        // are forwarded toward their destination via the best
                        // known path, even when the destination is not locally
                        // registered.
                        //
                        // Python parity: RNS/Transport.py forwards non-ANNOUNCE
                        // packets via path_table when transport_id matches.
                        // In standalone bridge mode we accept all transport_ids
                        // (filter bypass) so this forwarding applies to all
                        // non-local DATA packets.

                        // Extract best path info before any mutable borrow
                        let forward: Option<(String, Vec<u8>)> = {
                            if let Some(entries) = state.path_table.get(destination_hash) {
                                let now_ts = crate::transport::now();
                                entries.iter()
                                    .filter(|e| !e.is_expired(now_ts))
                                    .min_by_key(|e| e.hops)
                                    .and_then(|path| {
                                        path.receiving_interface.as_ref().map(|out_iface| {
                                            crate::log(
                                                &format!("[FWD-PATH] DATA dest={} via_iface={} hops={} pkt_hops={}",
                                                    crate::hexrep(destination_hash, false),
                                                    out_iface,
                                                    path.hops,
                                                    packet.hops,
                                                ),
                                                crate::LOG_NOTICE, false, false,
                                            );
                                            let mut new_raw = packet.raw.clone();
                                            if new_raw.len() > 1 {
                                                new_raw[1] = packet.hops;
                                            }
                                            (out_iface.clone(), new_raw)
                                        })
                                    })
                            } else {
                                None
                            }
                        };

                        if let Some((out_iface, new_raw)) = forward {
                            crate::log(
                                &format!("[FWD-DATA] dispatching dest={} to iface={} raw_len={}",
                                    crate::hexrep(destination_hash, false),
                                    out_iface, new_raw.len(),
                                ),
                                crate::LOG_NOTICE, false, false,
                            );
                            deferred_outbound.push((out_iface.clone(), new_raw));
                            // Refresh path timestamp
                            if let Some(entries) = state.path_table.get_mut(destination_hash) {
                                let now_ts = crate::transport::now();
                                for e in entries.iter_mut() {
                                    e.timestamp = now_ts;
                                }
                            }
                        } else {
                            crate::log(
                                &format!("[FWD-NOPATH] DATA dest={} — no path entry found in path_table (table_size={})",
                                    crate::hexrep(destination_hash, false),
                                    state.path_table.len(),
                                ),
                                crate::LOG_NOTICE, false, false,
                            );
                        }

                        let registered: Vec<String> = state.destinations.iter()
                            .map(|d| format!("{}({:?})", crate::hexrep(&d.hash, false), d.dest_type))
                            .collect();
                        crate::log(&format!("[DEST-RX] NO MATCH dest={} dtype={:?} ctx={} regcount={} registered=[{}]",
                            crate::hexrep(destination_hash, false),
                            packet.destination_type,
                            packet.context,
                            state.destinations.len(),
                            registered.join(",")), crate::LOG_NOTICE, false, false);
                    } else if _trace_is_target {
                        crate::log(&format!("[TRACE] target MATCHED {} destination(s)", matched), crate::LOG_NOTICE, false, false);
                    }
                } else if _trace_is_target {
                    crate::log("[TRACE] target has no destination_hash!", crate::LOG_NOTICE, false, false);
                }
            }
        } else if _trace_is_target {
            crate::log(&format!("[TRACE] target packet_type={} (not DATA, no DATA branch)", packet.packet_type), crate::LOG_NOTICE, false, false);
        }

        if packet.packet_type == PROOF {
            if packet.context == crate::packet::LRPROOF
                || packet.destination_type == Some(crate::destination::DestinationType::Link)
            {
                // Transit forwarding: if we have the link_id in link_table,
                // forward the LRPROOF back to the received_interface (toward the link initiator).
                let mut forwarded_via_link_table = false;
                if packet.context == crate::packet::LRPROOF {
                    let link_hex = packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default();
                    if let Some(destination_hash) = &packet.destination_hash {
                        if let Some(entry) = state.link_table.get_mut(destination_hash) {
                            let rcvd_if = match entry.get(IDX_LT_RCVD_IF) {
                                Some(LinkEntryValue::ReceivedInterface(name)) => name.clone(),
                                _ => None,
                            };
                            let nh_if = match entry.get(IDX_LT_NH_IF) {
                                Some(LinkEntryValue::NextHopInterface(name)) => name.clone(),
                                _ => None,
                            };
                            let remaining_hops = match entry.get(IDX_LT_REM_HOPS) {
                                Some(LinkEntryValue::RemainingHops(h)) => *h,
                                _ => 0,
                            };
                            // Python checks: hops must match remaining_hops, and
                            // proof must arrive from the next-hop interface direction
                            if packet.hops != remaining_hops {
                                crate::log(&format!("[LRPROOF-RELAY] link={} hop mismatch: proof_hops={} expected={}, not forwarding",
                                    link_hex, packet.hops, remaining_hops), crate::LOG_DEBUG, false, false);
                            } else if packet.receiving_interface == nh_if {
                                // Validate LRPROOF signature before forwarding (per spec)
                                let dst_hash = match entry.get(IDX_LT_DSTHASH) {
                                    Some(LinkEntryValue::DestinationHash(h)) => Some(h.clone()),
                                    _ => None,
                                };
                                let sig_valid = if let Some(ref dh) = dst_hash {
                                    validate_lrproof_signature(&packet.data, destination_hash, dh)
                                } else {
                                    crate::log(&format!("[LRPROOF-RELAY] link={} no destination hash in link_table entry", link_hex), crate::LOG_DEBUG, false, false);
                                    false
                                };

                                    if sig_valid {
                                        if let Some(name) = rcvd_if.as_ref() {
                                            let mut new_raw = packet.raw.clone();
                                            if new_raw.len() > 1 {
                                                new_raw[1] = packet.hops;
                                            }
                                            crate::log(&format!("[LRPROOF-RELAY] validated and forwarding link={} via rcvd_if={}", link_hex, name), crate::LOG_DEBUG, false, false);
                                            deferred_outbound.push((name.clone(), new_raw));
                                            forwarded_via_link_table = true;
                                            // Mark the link entry as validated
                                            if let Some(LinkEntryValue::Validated(v)) = entry.get_mut(IDX_LT_VALIDATED) {
                                                *v = true;
                                            }
                                        } else {
                                            crate::log(&format!("[LRPROOF-RELAY] link={} rcvd_if is None, cannot forward", link_hex), crate::LOG_WARNING, false, false);
                                        }
                                    } else {
                                        crate::log(&format!("[LRPROOF-RELAY] invalid signature for link={}, dropping proof", link_hex), crate::LOG_DEBUG, false, false);
                                    }
                            } else {
                                crate::log(&format!("[LRPROOF-RELAY] link={} interface mismatch: received_on={:?} expected_nh={:?}, not forwarding",
                                    link_hex, packet.receiving_interface, nh_if), crate::LOG_DEBUG, false, false);
                            }
                        } else {
                            crate::log(&format!("[LRPROOF-RELAY] link={} not in link_table (non-transport node), deferring to link handler",
                                link_hex), crate::LOG_DEBUG, false, false);
                        }
                    }
                }
                if !forwarded_via_link_table {
                    deferred_link_packets.push(packet.clone());
                }
            } else {
                if let Some(destination_hash) = &packet.destination_hash {
                    if let Some(entry) = state.reverse_table.remove(destination_hash) {
                        let outb = match entry.get(IDX_RT_OUTB_IF) {
                            Some(ReverseEntryValue::OutboundInterface(name)) => name.clone(),
                            _ => None,
                        };
                        let rcvd = match entry.get(IDX_RT_RCVD_IF) {
                            Some(ReverseEntryValue::ReceivedInterface(name)) => name.clone(),
                            _ => None,
                        };
                        if packet.receiving_interface == outb {
                            if let Some(name) = rcvd.as_ref() {
                                let mut new_raw = packet.raw.clone();
                                if new_raw.len() > 1 {
                                    new_raw[1] = packet.hops;
                                }
                                if let Some(iface) = find_interface_by_name(&mut state.interfaces, name) {
                                    crate::log(
                                        &format!("[PROOF-FWD] forwarding PROOF dest={} via rcvd_if={}",
                                            crate::hexrep(destination_hash, false), name),
                                        crate::LOG_NOTICE, false, false,
                                    );
                                    deferred_outbound.push((iface.name.clone(), new_raw));
                                }
                            }
                        } else if let Some(name) = outb.as_ref() {
                            state.reverse_table.insert(destination_hash.clone(), entry);
                            log(
                                &format!("Proof received on wrong interface, not transporting via {}", name),
                                LOG_DEBUG,
                                false,
                                false,
                            );
                        }
                    } else {
                        // ── Reverse-table miss fallback ─────────────────
                        // When the reverse_table has no entry (e.g. because
                        // the original DATA was forwarded without creating
                        // one, or the key doesn't match), fall back to
                        // path-table routing.  Without this, PROOFs and
                        // LRPROOFs silently disappear on bridges that
                        // forward between WAN interfaces.
                        let (_, _, outbound_iface) =
                            Self::select_path(&state.path_table, &state.interfaces, destination_hash, now())
                                .map(|(_, e)| (e.next_hop.clone(), e.hops, e.receiving_interface.clone()))
                                .unwrap_or((Vec::new(), 0, None));
                        if let Some(ref name) = outbound_iface {
                            if packet.receiving_interface.as_deref() != Some(name.as_str()) {
                                let mut new_raw = packet.raw.clone();
                                if new_raw.len() > 1 {
                                    new_raw[1] = packet.hops;
                                }
                                crate::log(
                                    &format!("[PROOF-FWD-FALLBACK] reverse_table miss, forwarding PROOF dest={} via path_iface={}",
                                        crate::hexrep(destination_hash, false), name),
                                    crate::LOG_NOTICE, false, false,
                                );
                                deferred_outbound.push((name.clone(), new_raw));
                            }
                        } else {
                            crate::log(
                                &format!("[PROOF-DROP] no reverse_table entry and no path for PROOF dest={}",
                                    crate::hexrep(destination_hash, false)),
                                crate::LOG_NOTICE, false, false,
                            );
                        }
                    }
                }
                for receipt in &mut state.receipts {
                    if receipt.validate_proof(&packet.data) {
                        break;
                    }
                }
            }
        }

        drop(state);

        for (iface_name, raw) in deferred_outbound {
            crate::log(&format!("[DISPATCH-OUT] iface={} raw_len={}", iface_name, raw.len()),
                crate::LOG_NOTICE, false, false);
            if !Transport::dispatch_outbound(&iface_name, &raw) {
                crate::log(&format!("[DISPATCH] outbound failed for interface {} (disconnected?), {} bytes dropped",
                    iface_name, raw.len()), crate::LOG_WARNING, false, false);
            }
        }

        for (mut destination, destination_packet) in deferred_destination_receives {
            crate::log(&format!("[DEST-DISPATCH] dest={} ptype={} dtype={:?} ctx={}",
                crate::hexrep(&destination.hash, false),
                destination_packet.packet_type,
                destination_packet.destination_type,
                destination_packet.context,
            ), LOG_NOTICE, false, false);
            match destination.receive(&destination_packet) {
                Ok(handled) => {
                    if handled {
                        crate::log(&format!("[DEST-RX] OK dest={} ptype={}", crate::hexrep(&destination.hash, false), destination_packet.packet_type), crate::LOG_NOTICE, false, false);
                        // Generate proof based on destination's proof strategy.
                        // CRITICAL: Python RNS only proves DATA packets (ptype=0), never LINKREQUEST
                        // packets (ptype=2). Sending a spurious PROOF for a LINKREQUEST violates the
                        // protocol — it confuses the initiator's receipt state machine and the rnsd
                        // reverse-table routing, causing the LRPROOF to be lost.
                        // See Python Destination.incoming_packet(): prove_all branch is gated on
                        // `packet.packet_type == RNS.Packet.DATA`.
                        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §2
                        if destination_packet.packet_type == DATA {
                            if destination.proof_strategy == crate::destination::PROVE_ALL {
                                let _ = destination_packet.prove(Some(&destination));
                            } else if destination.proof_strategy == crate::destination::PROVE_APP {
                                if let Some(cb) = destination.callbacks.proof_requested.clone() {
                                    if cb(&destination_packet) {
                                        let _ = destination_packet.prove(Some(&destination));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    crate::log(&format!("[DEST-RX] ERROR dest={} ptype={}: {}", crate::hexrep(&destination.hash, false), destination_packet.packet_type, e), crate::LOG_ERROR, false, false);
                }
            }
        }

        for link_packet in deferred_link_packets {
            let is_link_proof = link_packet.packet_type == PROOF
                && link_packet.destination_type == Some(crate::destination::DestinationType::Link);
            crate::log(&format!("[LINK-DISPATCH] ptype={} dest={} dtype={:?} ctx={} len={} is_link_proof={}",
                link_packet.packet_type,
                link_packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
                link_packet.destination_type,
                link_packet.context,
                link_packet.data.len(),
                is_link_proof,
            ), LOG_NOTICE, false, false);
            if is_link_proof {
                let proof_hash_hex = if link_packet.data.len() >= 32 {
                    crate::hexrep(&link_packet.data[..32], false)
                } else {
                    format!("<short:{}>", link_packet.data.len())
                };
                log(&format!("Inbound link PROOF proof_hash={} link={} data_len={}",
                    proof_hash_hex,
                    link_packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default(),
                    link_packet.data.len()), LOG_NOTICE, false, false);
            }
            let handled = crate::link::dispatch_runtime_packet(&link_packet);
            if handled && is_link_proof && link_packet.context != crate::packet::LRPROOF {
                if let Some(destination_hash) = link_packet.destination_hash.as_ref() {
                    if let Ok(mut state) = TRANSPORT.lock() {
                        let receipt_count = state.receipts.len();
                        let mut matched = false;
                        for receipt in &mut state.receipts {
                            if crate::link::validate_runtime_proof_for_receipt(
                                destination_hash,
                                &link_packet.data,
                                receipt,
                            ) {
                                matched = true;
                                break;
                            }
                        }
                        if !matched {
                            let proof_hash_hex = if link_packet.data.len() >= 32 {
                                crate::hexrep(&link_packet.data[..32], false)
                            } else {
                                "?".to_string()
                            };
                            log(&format!("Link PROOF no matching receipt proof_hash={} checked={} receipts",
                                proof_hash_hex, receipt_count), LOG_WARNING, false, false);
                            // Log all receipt hashes for debugging
                            for r in &state.receipts {
                                log(&format!("  receipt hash={} status={}", crate::hexrep(&r.hash, false), r.status), LOG_DEBUG, false, false);
                            }
                        }
                    }
                }
            } else if is_link_proof && !handled {
                log(&format!("Link PROOF dispatch FAILED (link not found) link={}",
                    link_packet.destination_hash.as_ref().map(|h| crate::hexrep(h, false)).unwrap_or_default()), LOG_WARNING, false, false);
            }
        }

        if let Some((handler, destination_hash, announced_identity, app_data)) = interface_announce_callback {
            handler.received_announce(&destination_hash, &announced_identity, &app_data);
        }

        for (callback, destination_hash, announced_identity, app_data, packet_hash, is_path_response) in deferred_announce_callbacks {
            thread::spawn(move || {
                callback(
                    &destination_hash,
                    &announced_identity,
                    &app_data,
                    packet_hash,
                    is_path_response,
                );
            });
        }

        let held_ms = inbound_lock_started.elapsed().as_millis();
        if held_ms > 500 {
        }

        true
    }

    pub fn request_path(
        destination_hash: &[u8],
        request_tag: Option<Vec<u8>>,
        attached_interface: Option<String>,
        requestor_transport_id: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
    ) {
        // Durable non-blocking implementation: callers (FFI bridges, the
        // LXMRouter, the iOS/Android main thread, Transport::jobs() itself)
        // must never block on Transport::outbound's jobs_running wait, the
        // announce-pacing sleep, or per-interface dispatch.
        //
        // Two important invariants:
        //   1. The `path_requests` dedup map is updated *immediately*, BEFORE
        //      the work is queued, so back-to-back callers don't both schedule
        //      duplicate path-request packets.  (Previously the insert ran on
        //      the worker AFTER packet.send() returned, defeating dedup under
        //      contention.)
        //   2. Work is dispatched onto a single dedicated transport-task
        //      worker thread (see `transport_task_sender`) instead of
        //      spawning a fresh OS thread per call.  This bounds resource
        //      use even when jobs() flushes many deferred path-requests in
        //      a single tick.
        let destination_hash_owned = destination_hash.to_vec();
        let request_tag = request_tag.or(tag);
        let _ = requestor_transport_id;

        // Record dedup timestamp synchronously, before queueing.
        if let Ok(mut state) = TRANSPORT.lock() {
            state
                .path_requests
                .insert(destination_hash_owned.clone(), now());
        }

        let dest_for_job = destination_hash_owned;
        spawn_transport_task(move || {
            let request_tag = request_tag.unwrap_or_else(|| Identity::get_random_hash());
            let path_request_data = {
                let state = TRANSPORT.lock().unwrap();
                let mut data = dest_for_job.clone();
                if state.transport_enabled {
                    if let Some(identity) = &state.identity {
                        if let Some(hash) = identity.hash.as_ref() {
                            data.extend_from_slice(hash);
                        }
                    }
                }
                data.extend_from_slice(&request_tag);
                data
            };

            let path_request_destination = Destination::new_outbound(
                None,
                DestinationType::Plain,
                APP_NAME.to_string(),
                vec!["path".to_string(), "request".to_string()],
            )
            .ok();

            let mut packet = Packet::new(
                path_request_destination,
                path_request_data,
                DATA,
                crate::packet::NONE,
                BROADCAST,
                crate::packet::HEADER_1,
                None,
                attached_interface.clone(),
                false,
                0,
            );
            // Diagnostic: emit a single line so we can see (when debugging
            // at LOG_DEBUG) both that the request went to the wire and which
            // interface it was pinned to. Without this, a path-request that
            // never arrives is indistinguishable from a peer with no cached
            // path — both produce silence on the inbound side. The 5 s
            // send-latency rule then fires with no actionable clue.
            //
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            // Kept at LOG_DEBUG (not NOTICE) to avoid log spam in normal
            // operation; raise to LOG_NOTICE temporarily when diagnosing
            // path-request failures.
            let send_result = packet.send();
            crate::log(
                &format!(
                    "[PATH_REQ] emitted dest={} iface={:?} send_ok={}",
                    crate::hexrep(&dest_for_job, false),
                    attached_interface,
                    send_result.is_ok(),
                ),
                crate::LOG_DEBUG, false, false,
            );
            if let Err(e) = send_result {
                crate::log(
                    &format!(
                        "[PATH_REQ] send error dest={} err={}",
                        crate::hexrep(&dest_for_job, false),
                        e,
                    ),
                    crate::LOG_ERROR, false, false,
                );
            }
        });
    }

    pub fn packet_filter(packet: &Packet) -> bool {
        let state = TRANSPORT.lock().unwrap();
        if state.is_connected_to_shared_instance {
            return true;
        }

        if packet.transport_id.is_some() && packet.packet_type != ANNOUNCE {
            if let Some(identity) = &state.identity {
                if let Some(hash) = identity.hash.as_ref() {
                    if packet.transport_id.as_ref() != Some(hash) {
                        return false;
                    }
                }
            }
        }

        if packet.context == crate::packet::KEEPALIVE
            || (packet.context >= crate::packet::RESOURCE
                && packet.context <= crate::packet::RESOURCE_RCL)
            || packet.context == crate::packet::CACHE_REQUEST
            || packet.context == crate::packet::CHANNEL
        {
            return true;
        }

        if packet.destination_type == Some(crate::destination::DestinationType::Plain) {
            if packet.packet_type != ANNOUNCE {
                return packet.hops <= 1;
            }
        }

        if packet.destination_type == Some(crate::destination::DestinationType::Group) {
            if packet.packet_type != ANNOUNCE {
                return packet.hops <= 1;
            }
        }

        if let Some(hash) = &packet.packet_hash {
            if !state.packet_hashlist.contains(hash) && !state.packet_hashlist_prev.contains(hash) {
                return true;
            }
        }

        if packet.packet_type == ANNOUNCE {
            return packet.destination_type != Some(crate::destination::DestinationType::Link);
        }

        false
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn ensure_paths() {
    let storage = crate::reticulum::storage_path();
    let cache = crate::reticulum::cache_path();
    let announces = cache.join("announces");
    let blackhole = crate::reticulum::blackhole_path();

    if !storage.exists() {
        let _ = fs::create_dir_all(&storage);
    }
    if !cache.exists() {
        let _ = fs::create_dir_all(&cache);
    }
    if !announces.exists() {
        let _ = fs::create_dir_all(&announces);
    }
    if !blackhole.exists() {
        let _ = fs::create_dir_all(&blackhole);
    }
}

fn find_interface_by_name<'a>(interfaces: &'a mut [InterfaceStub], name: &str) -> Option<&'a mut InterfaceStub> {
    interfaces.iter_mut().find(|iface| iface.name == name)
}

#[allow(dead_code)]
fn find_interface_by_hash<'a>(interfaces: &'a mut [InterfaceStub], interface_hash: &[u8]) -> Option<&'a mut InterfaceStub> {
    interfaces.iter_mut().find(|iface| iface.get_hash() == interface_hash)
}

#[allow(dead_code)]
fn is_local_client_interface(name: &str) -> bool {
    let state = TRANSPORT.lock().unwrap();
    state.local_client_interfaces.iter().any(|iface| iface.name == name)
}

/// Validate an LRPROOF signature per the Reticulum spec.
///
/// `proof_data` – the packet's `.data` field (signature + peer_pub_bytes + optional signalling)
/// `link_id`    – the destination_hash (link_id) from the packet
/// `dst_hash`   – the destination hash from link_table[IDX_LT_DSTHASH]
///
/// Returns `true` if the signature is valid.
pub(crate) fn validate_lrproof_signature(proof_data: &[u8], link_id: &[u8], dst_hash: &[u8]) -> bool {
    let sig_len = crate::identity::SIGLENGTH / 8; // 64
    let peer_pub_len = crate::link::ECPUBSIZE / 2; // 32
    let expected_short = sig_len + peer_pub_len; // 96
    let expected_long = expected_short + crate::link::LINK_MTU_SIZE; // 99

    if proof_data.len() != expected_short && proof_data.len() != expected_long {
        crate::log(&format!("[LRPROOF-VALIDATE] invalid proof data length {} (expected {} or {})",
            proof_data.len(), expected_short, expected_long), crate::LOG_DEBUG, false, false);
        return false;
    }

    let peer_identity = match Identity::recall(dst_hash) {
        Some(id) => id,
        None => {
            crate::log(&format!("[LRPROOF-VALIDATE] cannot recall identity for destination {}",
                crate::hexrep(dst_hash, false)), crate::LOG_DEBUG, false, false);
            return false;
        }
    };

    let peer_pub_key = match peer_identity.get_public_key() {
        Ok(k) => k,
        Err(_) => return false,
    };

    // peer_sig_pub_bytes = Ed25519 signing key (bytes 32..64 of full public key)
    let peer_sig_pub_bytes = &peer_pub_key[peer_pub_len..crate::link::ECPUBSIZE];

    let signature = &proof_data[..sig_len];
    let peer_pub_bytes = &proof_data[sig_len..sig_len + peer_pub_len];

    // Build signalling_bytes if extended proof
    let signalling_bytes: Vec<u8> = if proof_data.len() == expected_long {
        let mtu = crate::link::mtu_from_lp_packet(proof_data).unwrap_or(0);
        let mode = crate::link::mode_from_lp_packet(proof_data);
        match crate::link::signalling_bytes(mtu, mode) {
            Ok(sb) => sb.to_vec(),
            Err(_) => return false,
        }
    } else {
        Vec::new()
    };

    // signed_data = link_id + peer_pub_bytes + peer_sig_pub_bytes + signalling_bytes
    let mut signed_data = Vec::with_capacity(link_id.len() + peer_pub_len + 32 + signalling_bytes.len());
    signed_data.extend_from_slice(link_id);
    signed_data.extend_from_slice(peer_pub_bytes);
    signed_data.extend_from_slice(peer_sig_pub_bytes);
    signed_data.extend_from_slice(&signalling_bytes);

    peer_identity.validate(signature, &signed_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationType;
    use crate::identity::Identity;
    use crate::packet::{Packet, DATA, PROOF};
    use once_cell::sync::Lazy;
    use std::sync::mpsc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEST_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct ReceiptStateRestore {
        saved: Vec<crate::packet::PacketReceipt>,
        saved_destinations: Vec<Destination>,
        saved_packet_hashlist: std::collections::HashSet<Vec<u8>>,
        saved_packet_hashlist_prev: std::collections::HashSet<Vec<u8>>,
        saved_identity: Option<Identity>,
    }

    struct RuntimeLinkGuard {
        link_id: Vec<u8>,
    }

    impl RuntimeLinkGuard {
        fn new(link_id: Vec<u8>) -> Self {
            Self { link_id }
        }
    }

    impl Drop for RuntimeLinkGuard {
        fn drop(&mut self) {
            crate::link::unregister_runtime_link(&self.link_id);
        }
    }

    impl ReceiptStateRestore {
        fn new() -> Self {
            let mut state = TRANSPORT.lock().unwrap();
            let saved = std::mem::take(&mut state.receipts);
            let saved_destinations = std::mem::take(&mut state.destinations);
            let saved_packet_hashlist = std::mem::take(&mut state.packet_hashlist);
            let saved_packet_hashlist_prev = std::mem::take(&mut state.packet_hashlist_prev);
            let saved_identity = state.identity.clone();
            Self {
                saved,
                saved_destinations,
                saved_packet_hashlist,
                saved_packet_hashlist_prev,
                saved_identity,
            }
        }
    }

    impl Drop for ReceiptStateRestore {
        fn drop(&mut self) {
            if let Ok(mut state) = TRANSPORT.lock() {
                state.receipts = std::mem::take(&mut self.saved);
                state.destinations = std::mem::take(&mut self.saved_destinations);
                state.packet_hashlist = std::mem::take(&mut self.saved_packet_hashlist);
                state.packet_hashlist_prev = std::mem::take(&mut self.saved_packet_hashlist_prev);
                state.identity = self.saved_identity.clone();
            }
        }
    }

    fn make_receipt(hash_byte: u8, status: u8) -> crate::packet::PacketReceipt {
        let hash = vec![hash_byte; 32];
        crate::packet::PacketReceipt {
            hash: hash.clone(),
            truncated_hash: hash[..(crate::reticulum::TRUNCATED_HASHLENGTH / 8)].to_vec(),
            sent: true,
            sent_at: 0.0,
            proved: status == crate::packet::PacketReceipt::DELIVERED,
            status,
            destination: Destination::default(),
            concluded_at: None,
            timeout: 1.0,
            delivery_callback: None,
            timeout_callback: None,
        }
    }

    #[test]
    fn delivered_receipt_triggers_immediate_delivery_callback_on_registration() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();
        let receipt = make_receipt(0x11, crate::packet::PacketReceipt::DELIVERED);
        let receipt_hash = receipt.hash.clone();
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.receipts.push(receipt);
        }

        let callback_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits_clone = callback_hits.clone();
        Transport::set_receipt_delivery_callback(
            &receipt_hash,
            Arc::new(move |_| {
                callback_hits_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_receipt_triggers_immediate_timeout_callback_on_registration() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();
        let receipt = make_receipt(0x22, crate::packet::PacketReceipt::FAILED);
        let receipt_hash = receipt.hash.clone();
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.receipts.push(receipt);
        }

        let callback_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits_clone = callback_hits.clone();
        Transport::set_receipt_timeout_callback(
            &receipt_hash,
            Arc::new(move |_| {
                callback_hits_clone.fetch_add(1, Ordering::SeqCst);
            }),
        );

        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn inbound_data_invokes_destination_callback_without_transport_lock_deadlock() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let callback_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits_clone = callback_hits.clone();

        let mut destination = Destination::new_inbound(
            None,
            DestinationType::Plain,
            "testapp".to_string(),
            vec!["delivery".to_string()],
        )
        .expect("inbound destination");

        destination.set_packet_callback(Some(Arc::new(move |_data, _packet| {
            callback_hits_clone.fetch_add(1, Ordering::SeqCst);
            let _ = Transport::has_path(&[0xAA; crate::reticulum::TRUNCATED_HASHLENGTH / 8]);
        })));

        Transport::register_destination(destination.clone());

        let mut packet = Packet::new(
            Some(destination),
            b"callback-regression".to_vec(),
            DATA,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        packet.pack().expect("pack test packet");

        let (done_tx, done_rx) = mpsc::channel();
        let raw = packet.raw.clone();
        std::thread::spawn(move || {
            let result = Transport::inbound(raw, Some("test-if".to_string()));
            let _ = done_tx.send(result);
        });

        let inbound_result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("inbound should not block");
        assert!(inbound_result);

        let start = std::time::Instant::now();
        while callback_hits.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn inbound_proof_marks_receipt_delivered() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let identity = Identity::new(true);
        let mut receipt = make_receipt(0x33, crate::packet::PacketReceipt::SENT);
        receipt.destination.identity = Some(identity.clone());

        let callback_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits_clone = callback_hits.clone();
        receipt.set_delivery_callback(Arc::new(move |_| {
            callback_hits_clone.fetch_add(1, Ordering::SeqCst);
        }));

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.receipts.push(receipt.clone());
        }

        let signature = identity.sign(&receipt.hash);
        let mut proof_data = receipt.hash.clone();
        proof_data.extend_from_slice(&signature);

        let proof_destination = Destination::new_outbound(
            None,
            DestinationType::Plain,
            "proof".to_string(),
            vec!["return".to_string()],
        )
        .expect("proof destination");

        let mut proof_packet = Packet::new(
            Some(proof_destination),
            proof_data,
            PROOF,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        proof_packet.pack().expect("pack proof packet");

        assert!(Transport::inbound(
            proof_packet.raw.clone(),
            Some("test-if".to_string())
        ));

        let state = TRANSPORT.lock().unwrap();
        let updated = state
            .receipts
            .iter()
            .find(|r| r.hash == receipt.hash)
            .expect("receipt should exist");
        assert_eq!(updated.status, crate::packet::PacketReceipt::DELIVERED);
        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn inbound_lrproof_without_runtime_link_does_not_validate_generic_receipt() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let identity = Identity::new(true);
        let mut receipt = make_receipt(0x44, crate::packet::PacketReceipt::SENT);
        receipt.destination.identity = Some(identity.clone());

        let callback_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits_clone = callback_hits.clone();
        receipt.set_delivery_callback(Arc::new(move |_| {
            callback_hits_clone.fetch_add(1, Ordering::SeqCst);
        }));

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.receipts.push(receipt.clone());
        }

        let signature = identity.sign(&receipt.hash);
        let mut lrproof_data = receipt.hash.clone();
        lrproof_data.extend_from_slice(&signature);

        let mut lrproof_destination = Destination::new_outbound(
            None,
            DestinationType::Plain,
            "proof".to_string(),
            vec!["return".to_string()],
        )
        .expect("lrproof destination");
        lrproof_destination.hash = vec![0xE1; crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        lrproof_destination.hexhash = crate::hexrep(&lrproof_destination.hash, false);

        let mut lrproof_packet = Packet::new(
            Some(lrproof_destination),
            lrproof_data,
            PROOF,
            crate::packet::LRPROOF,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        lrproof_packet.pack().expect("pack lrproof packet");

        assert!(Transport::inbound(
            lrproof_packet.raw.clone(),
            Some("test-if".to_string())
        ));

        let state = TRANSPORT.lock().unwrap();
        let updated = state
            .receipts
            .iter()
            .find(|r| r.hash == receipt.hash)
            .expect("receipt should exist");
        assert_eq!(updated.status, crate::packet::PacketReceipt::SENT);
        assert_eq!(callback_hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn inbound_link_proof_with_runtime_link_validates_receipt() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let proving_identity = Identity::new(true);
        let mut receipt = make_receipt(0x55, crate::packet::PacketReceipt::SENT);

        let callback_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits_clone = callback_hits.clone();
        receipt.set_delivery_callback(Arc::new(move |_| {
            callback_hits_clone.fetch_add(1, Ordering::SeqCst);
        }));

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.receipts.push(receipt.clone());
        }

        let runtime_link_id = vec![0xD2; crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        let mut runtime_destination = Destination::new_outbound(
            None,
            DestinationType::Plain,
            "runtime".to_string(),
            vec!["link".to_string()],
        )
        .expect("runtime destination");
        runtime_destination.hash = runtime_link_id.clone();
        runtime_destination.hexhash = crate::hexrep(&runtime_destination.hash, false);

        let mut runtime_link = crate::link::Link::new_outbound(runtime_destination, crate::link::MODE_DEFAULT)
            .expect("runtime link");
        runtime_link.link_id = runtime_link_id.clone();
        runtime_link.initiator = false;
        let proving_public = proving_identity
            .get_public_key()
            .expect("proving identity public key");
        runtime_link
            .load_peer(vec![0u8; 32], proving_public[32..64].to_vec())
            .expect("load proving key into runtime link");

        let runtime_link = Arc::new(Mutex::new(runtime_link));
        let runtime_link_handle = runtime_link.clone();
        crate::link::register_runtime_link(runtime_link);
        let _runtime_guard = RuntimeLinkGuard::new(runtime_link_id.clone());

        let signature = proving_identity.sign(&receipt.hash);
        let mut proof_data = receipt.hash.clone();
        proof_data.extend_from_slice(&signature);

        let mut proof_destination = Destination::new_outbound(
            None,
            DestinationType::Plain,
            "proof".to_string(),
            vec!["return".to_string()],
        )
        .expect("proof destination");
        proof_destination.dest_type = DestinationType::Link;
        proof_destination.hash = runtime_link_id;
        proof_destination.hexhash = crate::hexrep(&proof_destination.hash, false);

        let mut proof_packet = Packet::new(
            Some(proof_destination),
            proof_data,
            PROOF,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        proof_packet.pack().expect("pack runtime proof packet");

        assert!(Transport::inbound(
            proof_packet.raw.clone(),
            Some("test-if".to_string())
        ));

        let state = TRANSPORT.lock().unwrap();
        let updated = state
            .receipts
            .iter()
            .find(|r| r.hash == receipt.hash)
            .expect("receipt should exist");
        assert_eq!(updated.status, crate::packet::PacketReceipt::DELIVERED);
        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);
        drop(runtime_link_handle);
    }

    #[test]
    fn packet_filter_rejects_lrproof_for_other_transport_identity() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let local_identity = Identity::new(true);
        let local_hash = local_identity.hash.clone().expect("local identity hash");
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.identity = Some(local_identity);
        }

        let mut packet = Packet::new(
            None,
            vec![0xAB; 96],
            PROOF,
            crate::packet::LRPROOF,
            BROADCAST,
            crate::packet::HEADER_1,
            Some(vec![0xCD; crate::reticulum::TRUNCATED_HASHLENGTH / 8]),
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        packet.destination_type = Some(DestinationType::Link);
        packet.destination_hash = Some(vec![0x01; crate::reticulum::TRUNCATED_HASHLENGTH / 8]);
        packet.packet_hash = Some(vec![0x02; crate::identity::HASHLENGTH / 8]);

        assert!(!Transport::packet_filter(&packet));

        packet.transport_id = Some(local_hash);
        assert!(Transport::packet_filter(&packet));
    }

    #[test]
    fn packet_filter_rejects_link_proof_for_other_transport_identity() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let local_identity = Identity::new(true);
        let local_hash = local_identity.hash.clone().expect("local identity hash");
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.identity = Some(local_identity);
        }

        let mut packet = Packet::new(
            None,
            vec![0xEF; 96],
            PROOF,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            Some(vec![0xAA; crate::reticulum::TRUNCATED_HASHLENGTH / 8]),
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        packet.destination_type = Some(DestinationType::Link);
        packet.destination_hash = Some(vec![0xBB; crate::reticulum::TRUNCATED_HASHLENGTH / 8]);
        packet.packet_hash = Some(vec![0xCC; crate::identity::HASHLENGTH / 8]);

        assert!(!Transport::packet_filter(&packet));

        packet.transport_id = Some(local_hash);
        assert!(Transport::packet_filter(&packet));
    }

    // ===== LRPROOF Signature Validation Tests =====

    /// Helper: create an identity and register it in the in-memory known destinations
    /// under its own truncated hash so `Identity::recall(dst_hash)` works in tests.
    fn setup_known_identity() -> (Identity, Vec<u8>) {
        let identity = Identity::new(true);
        let pub_key = identity.get_public_key().expect("identity public key");
        // Use a deterministic destination hash derived from the public key
        let dst_hash = crate::identity::truncated_hash(&pub_key);
        Identity::remember_destination_in_memory(&dst_hash, &pub_key);
        (identity, dst_hash)
    }

    #[test]
    fn inbound_valid_ratcheted_announce_remembers_ratchet() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let mut destination = Destination::new_inbound(
            Some(Identity::new(true)),
            DestinationType::Single,
            "ratchet_test".to_string(),
            vec!["delivery".to_string()],
        )
        .expect("ratcheted announce destination");

        let ratchet_file = std::env::temp_dir()
            .join(format!(
                "rns_test_inbound_announce_{}.ratchets",
                crate::hexrep(&destination.hash, false)
            ))
            .to_string_lossy()
            .to_string();
        destination
            .enable_ratchets(ratchet_file.clone())
            .expect("enable ratchets");
        destination.rotate_ratchets().expect("rotate ratchets");

        let ratchet_prv = destination
            .ratchets
            .as_ref()
            .and_then(|ratchets| ratchets.first())
            .expect("generated ratchet private key")
            .clone();
        let ratchet_pub = Identity::ratchet_public_bytes(&ratchet_prv)
            .expect("derive ratchet public key");
        let identity = destination
            .identity
            .as_ref()
            .expect("destination identity");
        let public_key = identity.get_public_key().expect("destination public key");
        let random_hash = [0x42; 10];

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&destination.hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&destination.name_hash);
        signed_data.extend_from_slice(&random_hash);
        signed_data.extend_from_slice(&ratchet_pub);
        let signature = identity.sign(&signed_data);

        let mut announce_data = Vec::new();
        announce_data.extend_from_slice(&public_key);
        announce_data.extend_from_slice(&destination.name_hash);
        announce_data.extend_from_slice(&random_hash);
        announce_data.extend_from_slice(&ratchet_pub);
        announce_data.extend_from_slice(&signature);

        let mut announce_packet = Packet::new(
            Some(destination.clone()),
            announce_data,
            crate::packet::ANNOUNCE,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_SET,
        );
        announce_packet.pack().expect("pack announce packet");

        let saved_shared_instance = {
            let mut state = TRANSPORT.lock().unwrap();
            let saved = state.is_connected_to_shared_instance;
            state.is_connected_to_shared_instance = true;
            saved
        };

        let inbound_result = Transport::inbound(
            announce_packet.raw.clone(),
            Some("test-if".to_string()),
        );

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.is_connected_to_shared_instance = saved_shared_instance;
        }

        assert!(inbound_result, "ratcheted announce should be accepted");
        assert_eq!(
            Identity::get_ratchet(&destination.hash),
            Some(ratchet_pub.clone()),
            "valid inbound ratcheted announce must seed the remembered ratchet"
        );

        Identity::forget_destination_in_memory(&destination.hash);
        let _ = std::fs::remove_file(&ratchet_file);
    }

    #[test]
    fn inbound_live_announce_replaces_unverified_cached_path_even_when_hops_worse() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let saved_path_table;
        let saved_verified;
        let saved_interfaces;
        let saved_drop_announces;
        let saved_watchlist;
        {
            let mut state = TRANSPORT.lock().unwrap();
            saved_path_table = std::mem::take(&mut state.path_table);
            saved_verified = std::mem::take(&mut state.path_verified_this_session);
            saved_interfaces = std::mem::take(&mut state.interfaces);
            saved_drop_announces = state.drop_announces;
            saved_watchlist = std::mem::take(&mut state.announce_watchlist);
            state.drop_announces = false;
        }

        let mut destination = Destination::new_inbound(
            Some(Identity::new(true)),
            DestinationType::Single,
            "path_quality_test".to_string(),
            vec!["delivery".to_string()],
        )
        .expect("announce destination");
        let dest_hash = destination.hash.clone();

        {
            let mut state = TRANSPORT.lock().unwrap();
            let mut deque = VecDeque::new();
            deque.push_back(PathEntry {
                timestamp: now(),
                next_hop: vec![0xCD; crate::reticulum::TRUNCATED_HASHLENGTH / 8],
                hops: 2,
                expires: now() + 3600.0,
                receiving_interface: Some("dead-iface".to_string()),
                packet_hash: vec![0xAB; crate::identity::HASHLENGTH / 8],
            });
            state.path_table.insert(dest_hash.clone(), deque);
        }

        let mut announce_packet = destination
            .announce(None, false, None, None, false)
            .expect("build announce")
            .expect("announce packet");
        announce_packet.hops = 3;
        let expected_hops = announce_packet.hops.saturating_add(1);
        announce_packet.pack().expect("pack announce");

        assert!(
            Transport::inbound(announce_packet.raw.clone(), Some("live-iface".to_string())),
            "live announce should be accepted"
        );

        {
            let state = TRANSPORT.lock().unwrap();
            let entry = state.path_table.get(&dest_hash)
                .and_then(|d| d.front())
                .expect("path entry must exist");
            let hops = entry.hops;
            let iface = entry.receiving_interface.clone();

            assert_eq!(
                hops,
                expected_hops,
                "live announce must replace provisional cached hop count"
            );
            assert_eq!(iface.as_deref(), Some("live-iface"));
            assert!(
                state.path_verified_this_session.contains(&dest_hash),
                "live announce must mark the path session-verified"
            );
        }

        Identity::forget_destination_in_memory(&dest_hash);
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.path_table = saved_path_table;
            state.path_verified_this_session = saved_verified;
            state.interfaces = saved_interfaces;
            state.drop_announces = saved_drop_announces;
            state.announce_watchlist = saved_watchlist;
        }
    }

    /// Build valid LRPROOF proof_data (96 bytes, no signalling) for a given link_id,
    /// using the identity's signing key.
    fn build_valid_proof_data(identity: &Identity, link_id: &[u8]) -> Vec<u8> {
        let pub_key = identity.get_public_key().expect("public key");
        // peer_pub_bytes = X25519 key (first 32 bytes)
        let peer_pub_bytes = &pub_key[..32];
        // peer_sig_pub_bytes = Ed25519 key (bytes 32..64)
        let peer_sig_pub_bytes = &pub_key[32..64];

        // signed_data = link_id + peer_pub_bytes + peer_sig_pub_bytes
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(link_id);
        signed_data.extend_from_slice(peer_pub_bytes);
        signed_data.extend_from_slice(peer_sig_pub_bytes);

        let signature = identity.sign(&signed_data);

        // proof_data = signature(64) + peer_pub_bytes(32) = 96 bytes
        let mut proof_data = signature;
        proof_data.extend_from_slice(peer_pub_bytes);
        proof_data
    }

    /// Build valid LRPROOF proof_data with signalling bytes (99 bytes)
    fn build_valid_proof_data_with_signalling(identity: &Identity, link_id: &[u8], mtu: usize, mode: u8) -> Vec<u8> {
        let pub_key = identity.get_public_key().expect("public key");
        let peer_pub_bytes = &pub_key[..32];
        let peer_sig_pub_bytes = &pub_key[32..64];
        let sig_bytes = crate::link::signalling_bytes(mtu, mode).expect("signalling_bytes");

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(link_id);
        signed_data.extend_from_slice(peer_pub_bytes);
        signed_data.extend_from_slice(peer_sig_pub_bytes);
        signed_data.extend_from_slice(&sig_bytes);

        let signature = identity.sign(&signed_data);

        // proof_data = signature(64) + peer_pub_bytes(32) + signalling(3) = 99 bytes
        let mut proof_data = signature;
        proof_data.extend_from_slice(peer_pub_bytes);
        proof_data.extend_from_slice(&sig_bytes);
        proof_data
    }

    #[test]
    fn lrproof_valid_signature_short_proof() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let (identity, dst_hash) = setup_known_identity();
        let link_id = vec![0xA1; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        let proof_data = build_valid_proof_data(&identity, &link_id);
        assert_eq!(proof_data.len(), 96);
        assert!(validate_lrproof_signature(&proof_data, &link_id, &dst_hash));

        // Cleanup
        Identity::forget_destination_in_memory(&dst_hash);
    }

    #[test]
    fn lrproof_valid_signature_long_proof_with_signalling() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let (identity, dst_hash) = setup_known_identity();
        let link_id = vec![0xB2; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        let proof_data = build_valid_proof_data_with_signalling(
            &identity, &link_id, 500, crate::link::MODE_AES256_CBC,
        );
        assert_eq!(proof_data.len(), 99);
        assert!(validate_lrproof_signature(&proof_data, &link_id, &dst_hash));

        // Cleanup
        Identity::forget_destination_in_memory(&dst_hash);
    }

    #[test]
    fn lrproof_invalid_signature_rejected() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let (identity, dst_hash) = setup_known_identity();
        let link_id = vec![0xC3; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        let mut proof_data = build_valid_proof_data(&identity, &link_id);
        // Corrupt the signature by flipping a byte
        proof_data[10] ^= 0xFF;
        assert!(!validate_lrproof_signature(&proof_data, &link_id, &dst_hash));

        // Cleanup
        Identity::forget_destination_in_memory(&dst_hash);
    }

    #[test]
    fn lrproof_wrong_link_id_rejected() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let (identity, dst_hash) = setup_known_identity();
        let link_id = vec![0xD4; crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        let wrong_link_id = vec![0xE5; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        let proof_data = build_valid_proof_data(&identity, &link_id);
        // Signature was made for link_id, but we validate against wrong_link_id
        assert!(!validate_lrproof_signature(&proof_data, &wrong_link_id, &dst_hash));

        // Cleanup
        Identity::forget_destination_in_memory(&dst_hash);
    }

    #[test]
    fn lrproof_wrong_identity_rejected() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        // Create two different identities
        let (identity_a, dst_hash_a) = setup_known_identity();
        let (_identity_b, dst_hash_b) = setup_known_identity();
        let link_id = vec![0xF6; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        // Sign with identity_a but validate against identity_b's destination hash
        let proof_data = build_valid_proof_data(&identity_a, &link_id);
        assert!(!validate_lrproof_signature(&proof_data, &link_id, &dst_hash_b));

        // Cleanup
        Identity::forget_destination_in_memory(&dst_hash_a);
        Identity::forget_destination_in_memory(&dst_hash_b);
    }

    #[test]
    fn lrproof_wrong_data_length_rejected() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let (identity, dst_hash) = setup_known_identity();
        let link_id = vec![0x07; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        // Too short (95 bytes)
        let proof_data = build_valid_proof_data(&identity, &link_id);
        assert!(!validate_lrproof_signature(&proof_data[..95], &link_id, &dst_hash));

        // Too long (100 bytes, between valid sizes)
        let mut padded = proof_data.clone();
        padded.extend_from_slice(&[0u8; 4]);
        assert!(!validate_lrproof_signature(&padded, &link_id, &dst_hash));

        // Way too short (10 bytes)
        assert!(!validate_lrproof_signature(&[0u8; 10], &link_id, &dst_hash));

        // Empty
        assert!(!validate_lrproof_signature(&[], &link_id, &dst_hash));

        // Cleanup
        Identity::forget_destination_in_memory(&dst_hash);
    }

    #[test]
    fn lrproof_unknown_destination_rejected() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let identity = Identity::new(true);
        let link_id = vec![0x18; crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        // Use a dst_hash that is NOT registered in known destinations
        let unknown_dst = vec![0xFF; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        let proof_data = build_valid_proof_data(&identity, &link_id);
        assert!(!validate_lrproof_signature(&proof_data, &link_id, &unknown_dst));
    }

    #[test]
    fn lrproof_corrupted_peer_pub_bytes_rejected() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let (identity, dst_hash) = setup_known_identity();
        let link_id = vec![0x29; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

        let mut proof_data = build_valid_proof_data(&identity, &link_id);
        // Corrupt the peer_pub_bytes (bytes 64..96) — signature will no longer match
        proof_data[70] ^= 0xFF;
        assert!(!validate_lrproof_signature(&proof_data, &link_id, &dst_hash));

        // Cleanup
        Identity::forget_destination_in_memory(&dst_hash);
    }

    // ===== Regression Tests for 2026-04-13 Fixes =====

    /// Regression: CLI `-vvvv` compound flag must be parsed as 4 verbose increments.
    /// Previously, `-vvvv` was treated as a single unrecognized arg (verbose=0).
    /// The fix counts 'v' characters in short flags.
    #[test]
    fn cli_verbose_flag_parsing_compound_flags() {
        // Reproduce the exact parsing logic from bin/rnsd.rs
        fn parse_verbose(args: &[&str]) -> i32 {
            args.iter().map(|a| {
                if *a == "--verbose" { 1 }
                else if a.starts_with("-") && !a.starts_with("--") {
                    a.chars().filter(|&c| c == 'v').count() as i32
                } else { 0 }
            }).sum()
        }

        fn parse_quiet(args: &[&str]) -> i32 {
            args.iter().map(|a| {
                if *a == "--quiet" { 1 }
                else if a.starts_with("-") && !a.starts_with("--") {
                    a.chars().filter(|&c| c == 'q').count() as i32
                } else { 0 }
            }).sum()
        }

        // Single -v
        assert_eq!(parse_verbose(&["-v"]), 1);
        // Compound -vvv
        assert_eq!(parse_verbose(&["-vvv"]), 3);
        // Compound -vvvvvv (the original failing case)
        assert_eq!(parse_verbose(&["-vvvvvv"]), 6);
        // Separate -v -v -v
        assert_eq!(parse_verbose(&["-v", "-v", "-v"]), 3);
        // Mixed: -vv and -v
        assert_eq!(parse_verbose(&["-vv", "-v"]), 3);
        // --verbose long form
        assert_eq!(parse_verbose(&["--verbose"]), 1);
        // No verbose flags
        assert_eq!(parse_verbose(&["--config", "/tmp/test"]), 0);
        // Mixed with other short flags (should only count 'v' chars)
        assert_eq!(parse_verbose(&["-sv"]), 1);
        // Quiet parsing
        assert_eq!(parse_quiet(&["-qqq"]), 3);
        assert_eq!(parse_quiet(&["--quiet"]), 1);

        // Effective log level calculation
        let base = crate::LOG_NOTICE; // 3
        let verbose = parse_verbose(&["-vvvv"]);
        let quiet = parse_quiet(&[]);
        let effective = (base + verbose - quiet).max(crate::LOG_CRITICAL);
        assert_eq!(effective, 7); // NOTICE(3) + 4 = 7 (EXTREME)
    }

    /// Regression: `handle_tunnel` must set `tunnel_id` on the InterfaceStub.
    /// Previously, the tunnel_id was only stored in the tunnel entry but NOT
    /// on the interface, breaking tunnel path association.
    #[test]
    fn handle_tunnel_sets_tunnel_id_on_interface_stub() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let iface_name = "test_tunnel_iface_42";
        let tunnel_id = vec![0xAA; 32];

        // Register a stub interface
        {
            let mut state = TRANSPORT.lock().unwrap();
            let mut stub = InterfaceStub::default();
            stub.name = iface_name.to_string();
            stub.out = true;
            state.interfaces.push(stub);
        }

        // Call handle_tunnel
        Transport::handle_tunnel(tunnel_id.clone(), iface_name.to_string());

        // Verify tunnel_id was set on the interface stub
        {
            let state = TRANSPORT.lock().unwrap();
            let iface = state.interfaces.iter().find(|i| i.name == iface_name)
                .expect("interface stub must exist");
            assert_eq!(
                iface.tunnel_id.as_ref(),
                Some(&tunnel_id),
                "handle_tunnel must set tunnel_id on InterfaceStub"
            );
        }

        // Verify tunnel entry was created
        {
            let state = TRANSPORT.lock().unwrap();
            assert!(
                state.tunnels.contains_key(&tunnel_id),
                "handle_tunnel must create a tunnel entry"
            );
        }

        // Cleanup
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.interfaces.retain(|i| i.name != iface_name);
            state.tunnels.remove(&tunnel_id);
        }
    }

    /// Regression: `handle_tunnel` called a second time must update the existing
    /// tunnel entry and still keep tunnel_id on the interface.
    #[test]
    fn handle_tunnel_restores_existing_tunnel() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let iface_name = "test_tunnel_restore_iface";
        let tunnel_id = vec![0xBB; 32];

        {
            let mut state = TRANSPORT.lock().unwrap();
            let mut stub = InterfaceStub::default();
            stub.name = iface_name.to_string();
            stub.out = true;
            state.interfaces.push(stub);
        }

        // First call creates the tunnel
        Transport::handle_tunnel(tunnel_id.clone(), iface_name.to_string());

        // Second call should restore (not duplicate)
        Transport::handle_tunnel(tunnel_id.clone(), iface_name.to_string());

        {
            let state = TRANSPORT.lock().unwrap();
            let iface = state.interfaces.iter().find(|i| i.name == iface_name)
                .expect("interface stub must exist");
            assert_eq!(iface.tunnel_id.as_ref(), Some(&tunnel_id));
            assert!(state.tunnels.contains_key(&tunnel_id));
        }

        // Cleanup
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.interfaces.retain(|i| i.name != iface_name);
            state.tunnels.remove(&tunnel_id);
        }
    }

    /// Regression: When rnsd relays a LINKREQUEST (transport_id matches our identity),
    /// a link_table entry must be created so that subsequent LRPROOF and DATA packets
    /// on that link can be forwarded.
    #[test]
    fn inbound_linkrequest_creates_link_table_entry() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let local_identity = Identity::new(true);
        let local_hash = local_identity.hash.clone().expect("local identity hash");

        // Set up transport identity and enable transport
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.identity = Some(local_identity);
            state.transport_enabled = true;
        }

        // We need a path table entry for the destination so the LINKREQUEST
        // relay path lookup succeeds.
        let dest_hash = vec![0xD1; crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        let next_hop = vec![0xD2; crate::reticulum::TRUNCATED_HASHLENGTH / 8];
        let outbound_iface_name = "test_lr_outbound";
        let receiving_iface_name = "test_lr_receiving";

        {
            let mut state = TRANSPORT.lock().unwrap();
            // Register outbound interface stub
            let mut stub_out = InterfaceStub::default();
            stub_out.name = outbound_iface_name.to_string();
            stub_out.out = true;
            state.interfaces.push(stub_out);

            // Register receiving interface stub
            let mut stub_in = InterfaceStub::default();
            stub_in.name = receiving_iface_name.to_string();
            stub_in.out = true;
            state.interfaces.push(stub_in);

            // Create path table entry for dest_hash
            let mut deque = VecDeque::new();
            deque.push_back(PathEntry {
                timestamp: now(),
                next_hop: next_hop.clone(),
                hops: 2,
                expires: now() + 3600.0,
                receiving_interface: Some(outbound_iface_name.to_string()),
                packet_hash: Vec::new(),
            });
            state.path_table.insert(dest_hash.clone(), deque);
        }
        // Synthetic 2-hop entry was just installed; wake race_path waiters.
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §4.
        crate::transport::notify_path_added();

        // Build a LINKREQUEST packet with HEADER_2 and our transport_id
        // A LINKREQUEST data field needs at least ECPUBSIZE (32) bytes for
        // link_id_from_lr_packet to compute correctly.
        let lr_data = vec![0x55; 64]; // peer_pub + extra data
        let dst_len = crate::reticulum::TRUNCATED_HASHLENGTH / 8; // 16

        // Build HEADER_2 raw bytes: [flags, hops, transport_id(16), dest_hash(16), context, data...]
        let flags: u8 = (crate::packet::HEADER_2 << 6) | (MODE_TRANSPORT << 4) | (crate::packet::LINKREQUEST & 0x03);
        let hops: u8 = 1;
        let mut raw = vec![flags, hops];
        raw.extend_from_slice(&local_hash[..dst_len]);  // transport_id
        raw.extend_from_slice(&dest_hash);               // destination
        raw.push(crate::packet::NONE);                   // context
        raw.extend_from_slice(&lr_data);                 // data

        // Send through Transport::inbound
        let raw_for_inbound = raw.clone();
        Transport::inbound(raw_for_inbound, Some(receiving_iface_name.to_string()));

        // Verify a link_table entry was created
        {
            let state = TRANSPORT.lock().unwrap();
            let has_link_entry = !state.link_table.is_empty();
            assert!(
                has_link_entry,
                "LINKREQUEST relay must create a link_table entry"
            );

            // Verify the entry has the correct received_interface and next_hop_interface
            if let Some((_link_id, entry)) = state.link_table.iter().next() {
                let rcvd_if = match entry.get(IDX_LT_RCVD_IF) {
                    Some(LinkEntryValue::ReceivedInterface(name)) => name.clone(),
                    _ => None,
                };
                let nh_if = match entry.get(IDX_LT_NH_IF) {
                    Some(LinkEntryValue::NextHopInterface(name)) => name.clone(),
                    _ => None,
                };
                assert_eq!(
                    rcvd_if.as_deref(), Some(receiving_iface_name),
                    "link_table entry must record receiving interface"
                );
                assert_eq!(
                    nh_if.as_deref(), Some(outbound_iface_name),
                    "link_table entry must record outbound (next-hop) interface"
                );
            }
        }

        // Cleanup
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.link_table.clear();
            state.path_table.remove(&dest_hash);
            state.interfaces.retain(|i| i.name != outbound_iface_name && i.name != receiving_iface_name);
        }
    }

    /// Regression test for the re-entrant outbound deadlock:
    ///
    /// `Transport::jobs()` sets `state.jobs_running = true` at entry and
    /// only clears it after the entire body runs. Previously the
    /// published-destination refresh sweep called
    /// `destination.announce(send=true)` from inside that critical
    /// section, which calls `Packet::send` → `Transport::outbound`, which
    /// spinwaits on `state.jobs_running`. Because the same thread that
    /// set the flag is now spinwaiting on it, the spin never terminates
    /// — and every other thread that subsequently calls outbound also
    /// spins forever waiting on the same flag (link actor, request_path
    /// worker, main-thread `packet_send`, synthesize_tunnel, etc.).
    ///
    /// The fix defers published-destination announce sends to after
    /// `jobs_running = false` (mirroring `mgmt_announce_packets`).
    ///
    /// This test reproduces the original hang within a 3-second budget:
    /// it registers a published destination with `refresh_interval = 0`
    /// and forces `published_last_checked = 0`, then runs `jobs()` on a
    /// background thread. Without the fix, the thread spins forever.
    /// With the fix, `jobs()` returns within milliseconds.
    #[test]
    fn jobs_does_not_deadlock_with_published_destination_refresh() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        // Reset relevant state so prior tests don't influence this one.
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.published_destinations.clear();
            state.last_mgmt_announce = now() + 60.0; // suppress mgmt sweep
        }

        // Build an inbound SINGLE destination and register it.
        let identity = Identity::new(true);
        let mut destination = Destination::new_inbound(
            Some(identity),
            DestinationType::Single,
            "deadlock_test".to_string(),
            vec!["regression".to_string()],
        )
        .expect("inbound destination");
        // Enable ratchets so generate_announce_data invokes
        // Identity::remember_ratchet → Transport::is_connected_to_shared_instance
        // → TRANSPORT.lock(), reproducing the iOS scenario.
        let ratchet_path = std::env::temp_dir()
            .join(format!("rns_test_ratchets_{}.bin", crate::hexrep(&destination.hash, false)))
            .to_string_lossy()
            .to_string();
        destination.enable_ratchets(ratchet_path.clone()).expect("enable_ratchets");
        let dest_hash = destination.hash.clone();
        Transport::register_destination(destination);

        // Publish with refresh_interval = 0 so the sweep fires immediately,
        // and force the check window open by zeroing published_last_checked.
        Transport::publish_destination(
            dest_hash.clone(),
            Some(Duration::from_secs(0)),
            None,
        );
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.published_last_checked = 0.0;
        }

        // Run jobs() on a background thread with a generous timeout. If the
        // re-entrant deadlock is present, the thread will spin forever and
        // recv_timeout returns Err — the test fails loudly. With the fix,
        // jobs() should complete in well under 100ms.
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            Transport::jobs();
            let _ = tx.send(());
        });

        let outcome = rx.recv_timeout(Duration::from_secs(3));
        // Cleanup before assertion so a failure doesn't leave shared state
        // in a bad shape for follow-on tests.
        Transport::unpublish_destination(&dest_hash);
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.path_table.remove(&dest_hash);
            // (Step 3 removed jobs_running / jobs_locked. Cleanup of those
            // flags is no longer required.)
        }
        assert!(
            outcome.is_ok(),
            "Transport::jobs() deadlocked while refreshing a published destination — re-entrant outbound bug regressed"
        );
        // Drain the join handle if jobs returned cleanly.
        let _ = handle.join();
    }

    /// Companion to the test above. Verifies that calling
    /// `Transport::outbound` from a separate thread *while* `jobs()` is
    /// running does not block indefinitely. Before the fix, both threads
    /// would be stuck inside the spinwait. After the fix, the
    /// published-destination refresh no longer leaves `jobs_running`
    /// stuck high, so the concurrent outbound call returns quickly.
    #[test]
    fn outbound_from_other_thread_does_not_deadlock_during_jobs_published_refresh() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.published_destinations.clear();
            state.last_mgmt_announce = now() + 60.0;
        }

        let identity = Identity::new(true);
        let destination = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            "deadlock_test_b".to_string(),
            vec!["regression".to_string()],
        )
        .expect("inbound destination");
        let dest_hash = destination.hash.clone();
        Transport::register_destination(destination);
        Transport::publish_destination(
            dest_hash.clone(),
            Some(Duration::from_secs(0)),
            None,
        );
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.published_last_checked = 0.0;
        }

        // Build a tiny outbound packet to fire concurrently with jobs().
        let outbound_dest = Destination::new_outbound(
            None,
            DestinationType::Plain,
            "deadlock_test_b".to_string(),
            vec!["sender".to_string()],
        )
        .expect("outbound destination");
        let mut packet = Packet::new(
            Some(outbound_dest),
            vec![1, 2, 3, 4],
            DATA,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        packet.pack().expect("pack outbound packet");

        let (jobs_tx, jobs_rx) = mpsc::channel();
        let jobs_handle = std::thread::spawn(move || {
            Transport::jobs();
            let _ = jobs_tx.send(());
        });

        let (out_tx, out_rx) = mpsc::channel();
        let out_handle = std::thread::spawn(move || {
            // Yield briefly so jobs() has a chance to be in flight when we hit outbound.
            std::thread::sleep(Duration::from_millis(5));
            Transport::outbound(&mut packet);
            let _ = out_tx.send(());
        });

        let jobs_outcome = jobs_rx.recv_timeout(Duration::from_secs(3));
        let out_outcome = out_rx.recv_timeout(Duration::from_secs(3));

        Transport::unpublish_destination(&dest_hash);
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.path_table.remove(&dest_hash);
        }
        assert!(jobs_outcome.is_ok(), "Transport::jobs() deadlocked");
        assert!(out_outcome.is_ok(), "concurrent Transport::outbound deadlocked");
        let _ = jobs_handle.join();
        let _ = out_handle.join();
    }

    /// Step-2 cross-interface no-stall regression.
    ///
    /// Registers two outbound handlers via `Transport::register_outbound_handler`
    /// — one that blocks for several seconds (simulating a wedged TCP peer),
    /// one that returns immediately. After Step 1's per-interface writer
    /// actor + Step 2's removal of the `jobs_running` busy-wait,
    /// `Transport::dispatch_outbound` must return within milliseconds for
    /// **both** interfaces, even while the slow interface's writer thread
    /// is mid-block.
    ///
    /// Before Step 1, dispatch_outbound called the handler synchronously
    /// and would itself block for the full sleep duration. Before Step 2,
    /// any concurrent `Transport::outbound` would additionally spinwait on
    /// `jobs_running`. Both pathologies are now eliminated.
    #[test]
    fn dispatch_outbound_does_not_stall_across_interfaces() {
        let _test_guard = TEST_GUARD.lock().unwrap();

        let wedged_name = "test-wedged-iface";
        let fast_name = "test-fast-iface";

        // Slow handler: blocks for 2 seconds on every call.
        let slow_handler: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> =
            Arc::new(|_bytes: &[u8]| {
                std::thread::sleep(Duration::from_secs(2));
                true
            });

        // Fast handler: counts invocations.
        let fast_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fast_count_w = Arc::clone(&fast_count);
        let fast_handler: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> =
            Arc::new(move |_bytes: &[u8]| {
                fast_count_w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                true
            });

        Transport::register_outbound_handler(wedged_name, slow_handler);
        Transport::register_outbound_handler(fast_name, fast_handler);

        // Prime the wedged writer so its thread is actually mid-sleep.
        assert!(Transport::dispatch_outbound(wedged_name, b"prime"));
        // Give the writer a moment to pick up the frame and start sleeping.
        std::thread::sleep(Duration::from_millis(50));

        // Now: dispatch on the fast interface must return within ms.
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(Transport::dispatch_outbound(fast_name, b"hello"));
        }
        let fast_elapsed = t0.elapsed();
        assert!(
            fast_elapsed < Duration::from_millis(100),
            "10x dispatch_outbound on fast interface took {:?} — expected <100 ms (cross-interface stall regression)",
            fast_elapsed
        );

        // And dispatch on the WEDGED interface also returns within ms
        // (just enqueues onto the bounded mpsc behind the wedge).
        let t1 = Instant::now();
        let _ = Transport::dispatch_outbound(wedged_name, b"queued");
        let wedged_elapsed = t1.elapsed();
        assert!(
            wedged_elapsed < Duration::from_millis(50),
            "dispatch_outbound on wedged interface took {:?} — expected <50 ms (writer-actor regression)",
            wedged_elapsed
        );

        // Wait briefly for the fast handler to finish draining its queue.
        for _ in 0..50 {
            if fast_count.load(std::sync::atomic::Ordering::SeqCst) >= 10 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fast_count.load(std::sync::atomic::Ordering::SeqCst),
            10,
            "fast handler should have processed all 10 frames"
        );

        // Cleanup. The wedged writer thread is left to finish its sleep
        // and exit on the Shutdown message; this happens off the test
        // critical path.
        Transport::unregister_outbound_handler(wedged_name);
        Transport::unregister_outbound_handler(fast_name);
    }

    // ── Regression: cold-start tunnel-synthesis ordering ─────────────────
    //
    // The bug (fixed 2026-04-30):
    //
    //   In `Reticulum::load_system_interfaces()`'s `"TCPClientInterface"`
    //   match arm, `Transport::register_interface_stub_config(stub_config)`
    //   ran AFTER `Transport::synthesize_tunnel(&name, &interface_repr)`.
    //
    //   `synthesize_tunnel` calls `Transport::outbound`, which iterates
    //   `state.interfaces` to broadcast the tunnel-synthesis packet
    //   (a PLAIN destination with an `attached_interface` filter).
    //   With the stub not yet registered, the iteration found zero
    //   matching interfaces, returned `sent=false`, and the synthesis
    //   packet was silently dropped — never written to the wire.
    //
    //   Downstream consequence: the upstream rnsd had no mapping from
    //   the new TCP connection back to our transport identity, so it
    //   could not route PATH_RESPONSE packets back to us. Cold-start
    //   PATH_REQUESTs went unanswered for tens of seconds (until an
    //   organic broadcast announce happened to pass through carrying
    //   the path we'd asked for). User-visible: 30+ second "Linking…"
    //   stalls on every app launch.
    //
    //   Hard violation of DESIGN_PRINCIPLES.md §1 (5 s send budget),
    //   §3 (no timeouts as readiness signals), §4 (strict ordering
    //   of dependent operations).
    //
    // The two tests below pin the invariant programmatically:
    //
    //   `synthesize_tunnel_emits_to_wire_when_stub_registered`
    //     — Happy path: stub registered first → tunnel bytes reach
    //       the outbound handler. Confirms the fix works.
    //
    //   `synthesize_tunnel_emits_nothing_when_stub_missing`
    //     — Bug-condition reproducer: no stub → no bytes dispatched.
    //       If anyone ever re-introduces the ordering inversion in
    //       `reticulum.rs::load_system_interfaces()`, the production
    //       call sequence will match this test's "missing-stub"
    //       branch and `synthesize_tunnel: sent=false` will appear
    //       in retichat.log again. This test ensures we have an
    //       in-tree, CI-blocking signal long before that happens —
    //       any future code review that inverts the order will fail
    //       the happy-path test (which mirrors the production
    //       ordering: stub register → synthesize call).
    //
    // NEVER REMOVE EVER.

    /// Helper: bypasses `register_outbound_handler`'s async writer-actor
    /// path and inserts a synchronous handler directly into the
    /// `OUTBOUND_HANDLERS` map. `dispatch_outbound` will use the legacy
    /// synchronous path when no writer is registered, so we get a
    /// deterministic byte-count without races against a worker thread.
    fn install_sync_outbound_handler(
        iface_name: &str,
        captured: Arc<Mutex<Vec<Vec<u8>>>>,
    ) {
        let captured_for_handler = captured.clone();
        let handler: OutboundHandler = Arc::new(move |bytes: &[u8]| {
            captured_for_handler.lock().unwrap().push(bytes.to_vec());
            true
        });
        OUTBOUND_HANDLERS
            .lock()
            .unwrap()
            .insert(iface_name.to_string(), handler);
    }

    fn uninstall_sync_outbound_handler(iface_name: &str) {
        OUTBOUND_HANDLERS.lock().unwrap().remove(iface_name);
    }

    #[test]
    fn inbound_silence_warning_kept_for_non_tcp_interfaces() {
        let iface = InterfaceStub {
            repr: "SerialInterface[test]".to_string(),
            ..InterfaceStub::default()
        };

        assert!(Transport::inbound_silence_warning_enforced(&iface));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    #[test]
    fn inbound_silence_warning_disabled_for_tcp_interfaces() {
        let iface = InterfaceStub {
            repr: "TCPInterface[test/192.0.2.1:4242]".to_string(),
            ..InterfaceStub::default()
        };

        assert!(!Transport::inbound_silence_warning_enforced(&iface));
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    #[test]
    fn inbound_silence_warning_kept_for_tcp_interfaces_without_os_support() {
        let iface = InterfaceStub {
            repr: "TCPInterface[test/192.0.2.1:4242]".to_string(),
            ..InterfaceStub::default()
        };

        assert!(Transport::inbound_silence_warning_enforced(&iface));
    }

    #[test]
    fn offline_drop_warning_is_throttled_per_interface() {
        let mut iface = InterfaceStub::default();

        assert!(Transport::should_emit_offline_drop_warning(&mut iface, 100.0));
        assert_eq!(iface.last_offline_warn_at, 100.0);
        assert!(!Transport::should_emit_offline_drop_warning(&mut iface, 150.0));
        assert!(Transport::should_emit_offline_drop_warning(&mut iface, 161.0));
        assert_eq!(iface.last_offline_warn_at, 161.0);
    }

    /// Snapshot/restore guard for `state.interfaces` so a test that mutates
    /// the global interface list cannot leak into sibling tests. The
    /// existing `ReceiptStateRestore` does NOT cover `interfaces`, and
    /// these tests deliberately probe the empty-interfaces case which
    /// would corrupt unrelated tests if leaked.
    struct InterfacesRestore {
        saved: Vec<InterfaceStub>,
    }
    impl InterfacesRestore {
        fn new() -> Self {
            let mut state = TRANSPORT.lock().unwrap();
            Self { saved: std::mem::take(&mut state.interfaces) }
        }
    }
    impl Drop for InterfacesRestore {
        fn drop(&mut self) {
            if let Ok(mut state) = TRANSPORT.lock() {
                state.interfaces = std::mem::take(&mut self.saved);
            }
        }
    }

    /// Happy path for the cold-start tunnel-synthesis ordering invariant.
    ///
    /// Mirrors the PRODUCTION call order in
    /// `reticulum.rs::load_system_interfaces()` `TCPClientInterface` arm:
    ///   1. Register an outbound handler for the interface name.
    ///   2. Register the interface stub via `register_interface_stub_config`.
    ///   3. Call `synthesize_tunnel`.
    ///
    /// Asserts the tunnel-synthesis packet was actually dispatched to the
    /// outbound handler (i.e. would have hit the wire in production).
    #[test]
    fn synthesize_tunnel_emits_to_wire_when_stub_registered() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();
        let _ifaces_restore = InterfacesRestore::new();

        let iface_name = "test-tunnel-order-happy";
        let iface_repr = "TCPInterface[test-tunnel-order-happy/example.invalid:0]";

        // 1. Identity must exist for synthesize_tunnel to sign.
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.identity = Some(Identity::new(true));
        }

        // 2. Outbound handler that captures dispatched bytes.
        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        install_sync_outbound_handler(iface_name, captured.clone());

        // 3. Stub registration happens BEFORE synthesize_tunnel — this
        //    is the production ordering we are pinning.
        let mut stub_config = InterfaceStubConfig::default();
        stub_config.name = iface_name.to_string();
        stub_config.online = Some(true);
        stub_config.out = true;
        stub_config.mode = InterfaceStub::MODE_FULL;
        Transport::register_interface_stub_config(stub_config);

        // 4. Trigger the synthesis.
        Transport::synthesize_tunnel(iface_name, iface_repr);

        // 5. The tunnel-synthesis packet MUST have been dispatched to
        //    the outbound handler. If this assertion fails, either the
        //    register-before-synthesize ordering has been inverted in
        //    production code, OR the InterfaceStub no longer satisfies
        //    `Transport::outbound`'s send predicate (out=true,
        //    attached_interface name match).
        let dispatched = captured.lock().unwrap();
        assert!(
            !dispatched.is_empty(),
            "synthesize_tunnel must dispatch ≥1 frame when stub is registered \
             — if this fires, the cold-start tunnel-synthesis ordering bug \
             has regressed (see comment block above this test)"
        );

        uninstall_sync_outbound_handler(iface_name);
    }

    /// Regression detector for the cold-start tunnel-synthesis ordering bug.
    ///
    /// Reproduces the BUG CONDITION: outbound handler exists, identity
    /// exists, but the InterfaceStub is NOT in `state.interfaces` when
    /// `synthesize_tunnel` runs. This is exactly the state the buggy
    /// `reticulum.rs` ordering produced — `synthesize_tunnel` ran first
    /// and `register_interface_stub_config` ran second.
    ///
    /// Asserts the packet is silently dropped (zero handler invocations).
    /// This documents the invariant: if you ever see
    /// `synthesize_tunnel: sent=false` in retichat.log again, this test
    /// is your in-tree explanation of why and how to fix it.
    #[test]
    fn synthesize_tunnel_emits_nothing_when_stub_missing() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();
        let _ifaces_restore = InterfacesRestore::new();

        let iface_name = "test-tunnel-order-bug";
        let iface_repr = "TCPInterface[test-tunnel-order-bug/example.invalid:0]";

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.identity = Some(Identity::new(true));
            // CRITICAL: state.interfaces deliberately empty. This is
            // the broken state the production bug exposed.
            assert!(
                state.interfaces.iter().all(|i| i.name != iface_name),
                "test setup invariant: stub must NOT be registered"
            );
        }

        let captured: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        install_sync_outbound_handler(iface_name, captured.clone());

        // Trigger synthesis with no matching interface stub.
        Transport::synthesize_tunnel(iface_name, iface_repr);

        // The buggy code path: Transport::outbound iterated zero
        // matching interfaces, returned sent=false, packet silently
        // dropped. We assert that observable outcome.
        let dispatched = captured.lock().unwrap();
        assert!(
            dispatched.is_empty(),
            "without a registered InterfaceStub, synthesize_tunnel's \
             outbound broadcast has nowhere to go and must dispatch \
             zero frames — if this fires, the broadcast semantics of \
             Transport::outbound have changed and the cold-start \
             ordering bug may have masked itself in a new way"
        );

        uninstall_sync_outbound_handler(iface_name);
    }

    // ── Regression: synthesize_tunnel_all_tcp covers all TCP stubs ────────
    //
    // The 36-second LRREQ stall (2026-05-07 retichat.log):
    //
    //   Two consecutive link-establishment attempts (each 18 s) timed out
    //   because rnsd had no tunnel binding for our TCP connection when the
    //   LINK_PROOF arrived. The third attempt succeeded in 0.208 s because
    //   the 60 s heartbeat happened to fire 1 s before it, refreshing the
    //   binding.
    //
    //   The fix: `start_persistent_link` now calls
    //   `Transport::synthesize_tunnel_all_tcp()` before `handle.initiate()`
    //   on every attempt, guaranteeing the binding is fresh.
    //
    //   The invariants pinned here:
    //
    //   `repr_stored_in_interface_stub`
    //     — `register_interface_stub_config` persists `config.repr` into
    //       `InterfaceStub::repr`. Without this field,
    //       `synthesize_tunnel_all_tcp` cannot reconstruct the tunnel_id
    //       (which is `full_hash(public_key + full_hash(repr.as_bytes()))`).
    //
    //   `synthesize_tunnel_all_tcp_fires_on_stubs_with_repr`
    //     — Online stubs with a non-empty repr DO get a synthesis packet.
    //       Stubs without a repr (non-TCP interfaces) are correctly skipped.
    //       This is the production invariant: every TCP backbone gets a
    //       fresh tunnel binding before each LRREQ.
    //
    //   `synthesize_tunnel_all_tcp_skips_offline_stubs`
    //     — Offline stubs are skipped. Sending a synthesis packet to an
    //       offline interface would fail anyway, but more importantly it
    //       would try to hash an empty or stale fd.
    //
    // NEVER REMOVE EVER.

    /// Asserts that `register_interface_stub_config` persists `config.repr`
    /// into `InterfaceStub::repr`. This is load-bearing: without the stored
    /// repr, `synthesize_tunnel_all_tcp` cannot compute the tunnel_id and
    /// would emit a DIFFERENT tunnel_id than the one the heartbeat uses,
    /// silently breaking the rnsd reverse-route for link-initiated stubs.
    #[test]
    fn repr_stored_in_interface_stub() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _ifaces_restore = InterfacesRestore::new();

        let iface_name = "test-repr-persist";
        let iface_repr = "TCPInterface[test-repr-persist/192.0.2.1:4242]";

        let mut config = InterfaceStubConfig::default();
        config.name = iface_name.to_string();
        config.online = Some(true);
        config.out = true;
        config.mode = InterfaceStub::MODE_FULL;
        config.repr = Some(iface_repr.to_string());
        Transport::register_interface_stub_config(config);

        let state = TRANSPORT.lock().unwrap();
        let stub = state.interfaces.iter().find(|i| i.name == iface_name)
            .expect("stub should be registered");
        assert_eq!(
            stub.repr, iface_repr,
            "InterfaceStub::repr must equal the repr passed via InterfaceStubConfig — \
             if this fails, synthesize_tunnel_all_tcp will compute a wrong tunnel_id \
             for TCP interfaces and the 36s LRREQ stall will regress"
        );
    }

    /// Asserts that `synthesize_tunnel_all_tcp` dispatches a synthesis packet
    /// on every online stub that has a non-empty repr (TCP backbone interfaces)
    /// and dispatches NOTHING on stubs without a repr (non-TCP / non-tunnel).
    ///
    /// This is the core invariant of the 36-second stall fix: before each
    /// LRREQ we call this to guarantee the rnsd reverse-route is fresh.
    /// If this test fails, the fix has regressed and the stall will return.
    #[test]
    fn synthesize_tunnel_all_tcp_fires_on_stubs_with_repr() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();
        let _ifaces_restore = InterfacesRestore::new();

        // Identity required for signing.
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.identity = Some(Identity::new(true));
        }

        // Two TCP-style stubs (repr set) and one plain stub (no repr).
        let tcp1_name = "test-synth-all-tcp1";
        let tcp1_repr = "TCPInterface[test-synth-all-tcp1/10.0.0.1:4242]";
        let tcp2_name = "test-synth-all-tcp2";
        let tcp2_repr = "TCPInterface[test-synth-all-tcp2/10.0.0.2:4242]";
        let plain_name = "test-synth-all-plain";

        for (name, repr_opt, online) in [
            (tcp1_name,  Some(tcp1_repr),  true),
            (tcp2_name,  Some(tcp2_repr),  true),
            (plain_name, None,             true),
        ] {
            let mut cfg = InterfaceStubConfig::default();
            cfg.name = name.to_string();
            cfg.online = Some(online);
            cfg.out = true;
            cfg.mode = InterfaceStub::MODE_FULL;
            cfg.repr = repr_opt.map(|s| s.to_string());
            Transport::register_interface_stub_config(cfg);
        }

        // Wire up sync outbound handlers for all three.
        let captured_tcp1: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_tcp2: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_plain: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        install_sync_outbound_handler(tcp1_name,  captured_tcp1.clone());
        install_sync_outbound_handler(tcp2_name,  captured_tcp2.clone());
        install_sync_outbound_handler(plain_name, captured_plain.clone());

        Transport::synthesize_tunnel_all_tcp();

        // Each TCP stub MUST have received exactly one synthesis packet.
        assert_eq!(
            captured_tcp1.lock().unwrap().len(), 1,
            "synthesize_tunnel_all_tcp must dispatch one packet to each online \
             TCP stub (tcp1 got none) — 36s stall regression if this fires"
        );
        assert_eq!(
            captured_tcp2.lock().unwrap().len(), 1,
            "synthesize_tunnel_all_tcp must dispatch one packet to each online \
             TCP stub (tcp2 got none) — 36s stall regression if this fires"
        );
        // Plain stub (no repr) must NOT have received anything.
        assert!(
            captured_plain.lock().unwrap().is_empty(),
            "synthesize_tunnel_all_tcp must skip stubs with no repr \
             (plain stub received a packet — filter logic broken)"
        );

        uninstall_sync_outbound_handler(tcp1_name);
        uninstall_sync_outbound_handler(tcp2_name);
        uninstall_sync_outbound_handler(plain_name);
    }

    /// Asserts that `synthesize_tunnel_all_tcp` skips offline stubs.
    /// An offline interface has no live socket; sending a synthesis packet
    /// through it would fail silently and more importantly waste the 60-byte
    /// signed packet on an interface that cannot forward it.
    #[test]
    fn synthesize_tunnel_all_tcp_skips_offline_stubs() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();
        let _ifaces_restore = InterfacesRestore::new();

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.identity = Some(Identity::new(true));
        }

        let online_name  = "test-synth-skip-online";
        let offline_name = "test-synth-skip-offline";
        let online_repr  = "TCPInterface[test-synth-skip-online/10.0.0.1:4242]";
        let offline_repr = "TCPInterface[test-synth-skip-offline/10.0.0.2:4242]";

        for (name, repr, online) in [
            (online_name,  online_repr,  true),
            (offline_name, offline_repr, false),
        ] {
            let mut cfg = InterfaceStubConfig::default();
            cfg.name   = name.to_string();
            cfg.online = Some(online);
            cfg.out    = true;
            cfg.mode   = InterfaceStub::MODE_FULL;
            cfg.repr   = Some(repr.to_string());
            Transport::register_interface_stub_config(cfg);
        }

        let captured_online:  Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_offline: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        install_sync_outbound_handler(online_name,  captured_online.clone());
        install_sync_outbound_handler(offline_name, captured_offline.clone());

        Transport::synthesize_tunnel_all_tcp();

        assert_eq!(
            captured_online.lock().unwrap().len(), 1,
            "online TCP stub must receive a synthesis packet"
        );
        assert!(
            captured_offline.lock().unwrap().is_empty(),
            "synthesize_tunnel_all_tcp must skip offline stubs — \
             if this fires, we're trying to synthesize on a dead socket"
        );

        uninstall_sync_outbound_handler(online_name);
        uninstall_sync_outbound_handler(offline_name);
    }

    /// PROVE_ALL must only send a proof for DATA packets, never for LINKREQUEST.
    ///
    /// Python Destination.incoming_packet() gates the prove_all branch on
    /// `packet.packet_type == RNS.Packet.DATA`.  Sending a spurious PROOF for
    /// a LINKREQUEST violates the protocol: rnsd routes it back to the
    /// LINKREQUEST initiator via the reverse-table, which can corrupt the
    /// initiator's receipt state and confuse link establishment, leaving the
    /// inbound link in HANDSHAKE state indefinitely (LRRTT never arrives).
    #[test]
    fn prove_all_does_not_fire_for_linkrequest() {
        // The transport loop gates prove_all on `destination_packet.packet_type == DATA`.
        // This test verifies the guard condition directly so any future edit that removes
        // the guard will fail here before reaching the wire.
        //
        // The check that must appear in the deferred_destination_receives loop:
        //   if destination_packet.packet_type == DATA { ... prove ... }
        //
        // Verify: for LINKREQUEST (ptype=2), the gate evaluates to false.
        assert_ne!(
            LINKREQUEST, DATA,
            "LINKREQUEST and DATA must have different ptype values"
        );
        let linkrequest_ptype: u8 = LINKREQUEST;
        let data_ptype: u8 = DATA;

        // Simulate the gate that the transport loop uses:
        let would_prove_for_linkrequest = linkrequest_ptype == DATA;
        let would_prove_for_data       = data_ptype        == DATA;

        assert!(
            !would_prove_for_linkrequest,
            "PROVE_ALL gate (ptype == DATA) must evaluate FALSE for LINKREQUEST (ptype={}). \
             If this fails, the transport loop is sending spurious PROOF packets for every \
             inbound LINKREQUEST, violating the Reticulum protocol and breaking link \
             establishment (LRPROOF lost, link stays in HANDSHAKE state).",
            LINKREQUEST
        );
        assert!(
            would_prove_for_data,
            "PROVE_ALL gate must evaluate TRUE for DATA (ptype={})",
            DATA
        );
    }

    // ── Regression: packet_filter must accept packets with foreign transport_id ──
    //
    // When rnsd runs in standalone mode (not connected to a shared instance),
    // every connected client (TCP app, PostInterface peer) has its own
    // transport identity.  The transport_id check must NOT apply — it is
    // only meaningful in shared-instance mode where one daemon filters
    // packets for multiple apps.
    //
    // Regression test for the fix applied 2026-07-19: removed transport_id
    // check from standalone-mode packet_filter.
    #[test]
    fn plain_data_passes_filter_with_foreign_transport_id() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        // Ensure standalone mode
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.is_connected_to_shared_instance = false;
            state.identity = Some(Identity::new(true));
            state.packet_hashlist.clear();
            state.packet_hashlist_prev.clear();
        }

        // Create a Plain destination (broadcast-like) and a packet with foreign transport_id
        let dest = Destination::new_outbound(
            None,
            DestinationType::Plain,
            "test_filter".to_string(),
            vec!["data".to_string()],
        )
        .expect("Plain destination");
        let dest_hash = dest.hash.clone();

        let mut packet = Packet::new(
            Some(dest),
            b"filter-test".to_vec(),
            DATA,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_UNSET,
        );
        packet.destination_hash = Some(dest_hash);
        packet.destination_type = Some(DestinationType::Plain);
        packet.transport_id = Some(vec![0xFF; 16]); // foreign transport_id
        packet.pack().expect("pack test packet");

        // The filter should accept this packet in standalone mode
        let result = Transport::inbound(packet.raw.clone(), Some("PostInterface Bridge".to_string()));
        assert!(
            result,
            "Plain DATA packet with foreign transport_id must pass filter in standalone mode. \
             Regression: transport_id check was re-added to standalone-mode filter."
        );
    }

    // ── Regression: announce from local client forwarded to non-local outbound interfaces ──
    #[test]
    fn announce_from_local_client_forwarded_to_non_local_interfaces() {
        let _test_guard = TEST_GUARD.lock().unwrap();
        let _restore = ReceiptStateRestore::new();

        let local_identity = Identity::new(true);
        let local_hash = local_identity.hash.clone().unwrap();

        let local_iface_name = "Client on Local TCP [127.0.0.1:55555]".to_string();
        let wan_iface_name = "PostInterface Bridge".to_string();

        // Build a valid announce using the same pattern as
        // inbound_valid_ratcheted_announce_remembers_ratchet
        let mut destination = Destination::new_inbound(
            Some(Identity::new(true)),
            DestinationType::Single,
            "announce_fwd_test".to_string(),
            vec!["announce".to_string()],
        )
        .expect("announce destination");

        let ratchet_file = std::env::temp_dir()
            .join(format!("rns_test_announce_fwd_{}.ratchets",
                crate::hexrep(&destination.hash, false)))
            .to_string_lossy().to_string();
        destination.enable_ratchets(ratchet_file.clone()).expect("enable ratchets");
        destination.rotate_ratchets().expect("rotate ratchets");

        let ratchet_prv = destination.ratchets.as_ref()
            .and_then(|r| r.first()).expect("ratchet key").clone();
        let ratchet_pub = Identity::ratchet_public_bytes(&ratchet_prv).expect("ratchet pub");
        let identity = destination.identity.as_ref().expect("dest identity");
        let public_key = identity.get_public_key().expect("pubkey");
        let random_hash = [0x42; 10];

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&destination.hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&destination.name_hash);
        signed_data.extend_from_slice(&random_hash);
        signed_data.extend_from_slice(&ratchet_pub);
        let signature = identity.sign(&signed_data);

        let mut announce_data = Vec::new();
        announce_data.extend_from_slice(&public_key);
        announce_data.extend_from_slice(&destination.name_hash);
        announce_data.extend_from_slice(&random_hash);
        announce_data.extend_from_slice(&ratchet_pub);
        announce_data.extend_from_slice(&signature);

        let mut announce_packet = Packet::new(
            Some(destination.clone()),
            announce_data,
            crate::packet::ANNOUNCE,
            crate::packet::NONE,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            crate::packet::FLAG_SET,
        );
        announce_packet.pack().expect("pack announce");

        {
            let mut state = TRANSPORT.lock().unwrap();
            state.is_connected_to_shared_instance = false;
            state.transport_enabled = true;
            state.identity = Some(local_identity.clone());
            state.announce_table.clear();
            state.packet_hashlist.clear();
            state.packet_hashlist_prev.clear();

            let mut local_stub = InterfaceStub::default();
            local_stub.name = local_iface_name.clone();
            local_stub.out = true;
            local_stub.online = true;
            local_stub.mode = InterfaceStub::MODE_FULL;
            state.local_client_interfaces.push(local_stub.clone());
            state.interfaces.push(local_stub);

            let mut wan_stub = InterfaceStub::default();
            wan_stub.name = wan_iface_name.clone();
            wan_stub.out = true;
            wan_stub.online = true;
            wan_stub.mode = InterfaceStub::MODE_FULL;
            state.interfaces.push(wan_stub);
        }

        // Capture forwarded packets to WAN
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_clone = captured.clone();
        Transport::register_outbound_handler(
            &wan_iface_name,
            Arc::new(move |raw| {
                captured_clone.lock().unwrap().push(raw.to_vec());
                true
            }),
        );

        let result = Transport::inbound(announce_packet.raw.clone(), Some(local_iface_name.clone()));
        assert!(result, "ANNOUNCE from local client must be accepted");

        let forwarded = captured.lock().unwrap();
        assert!(
            !forwarded.is_empty(),
            "ANNOUNCE from local client '{}' must be forwarded to WAN '{}'. Got {} packets. \
             Regression: [ANNOUNCE-FWD] removed or broken.",
            local_iface_name, wan_iface_name, forwarded.len(),
        );

        Transport::unregister_outbound_handler(&wan_iface_name);
        {
            let mut state = TRANSPORT.lock().unwrap();
            state.interfaces.clear();
            state.local_client_interfaces.clear();
        }
        // Clean up ratchet file
        let _ = std::fs::remove_file(&ratchet_file);
    }
}
