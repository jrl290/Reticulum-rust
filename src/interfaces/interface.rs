use crate::identity::Identity;
use crate::transport::Transport;
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Base Interface trait and implementation
/// 
/// All Reticulum interfaces inherit from this base class which provides
/// common functionality for ingress control, announce rate limiting,
/// MTU optimization, and announce frequency tracking.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    Full = 0x01,
    PointToPoint = 0x02,
    AccessPoint = 0x03,
    Roaming = 0x04,
    Boundary = 0x05,
    Gateway = 0x06,
}

impl InterfaceMode {
    /// Interface modes for which Transport should actively discover paths
    pub fn should_discover_paths(&self) -> bool {
        matches!(
            self,
            InterfaceMode::AccessPoint | InterfaceMode::Gateway | InterfaceMode::Roaming
        )
    }
}

pub struct Interface {
    // Direction flags
    pub in_enabled: bool,
    pub out_enabled: bool,
    pub fwd_enabled: bool,
    pub rpt_enabled: bool,
    pub name: Option<String>,

    // Statistics
    pub rxb: u64,
    pub txb: u64,
    pub created: f64,
    pub detached: bool,
    pub online: bool,

    // MTU and performance
    pub bitrate: u64,
    pub hw_mtu: Option<usize>,
    pub autoconfigure_mtu: bool,
    pub fixed_mtu: bool,

    // Discovery
    pub supports_discovery: bool,
    pub discoverable: bool,
    pub last_discovery_announce: f64,
    pub bootstrap_only: bool,

    // Interface hierarchy
    pub parent_interface: Option<Box<Interface>>,
    pub spawned_interfaces: Option<Vec<Interface>>,
    pub tunnel_id: Option<Vec<u8>>,

    // Ingress control
    pub ingress_control: bool,
    pub ic_max_held_announces: usize,
    pub ic_burst_hold: f64,
    pub ic_burst_active: bool,
    pub ic_burst_activated: f64,
    pub ic_held_release: f64,
    pub ic_burst_freq_new: f64,
    pub ic_burst_freq: f64,
    pub ic_new_time: f64,
    pub ic_burst_penalty: f64,
    pub ic_held_release_interval: f64,

    // Held announces storage
    pub held_announces: HashMap<Vec<u8>, Vec<u8>>, // destination_hash -> announce_packet

    // Announce frequency tracking
    pub ia_freq_deque: VecDeque<f64>,
    pub oa_freq_deque: VecDeque<f64>,

    // Announce queue
    pub announce_queue: Vec<QueuedAnnounce>,
    pub announce_cap: f64,
    pub announce_allowed_at: f64,

    // Mode and announce tuning
    pub mode: InterfaceMode,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<f64>,
    pub announce_rate_penalty: Option<f64>,

    // IFAC configuration
    pub ifac_size: usize,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub ifac_key: Option<Vec<u8>>,
    pub ifac_identity: Option<Identity>,
    pub ifac_signature: Option<Vec<u8>>,

    // Forced bitrate throttle (sleep to simulate slower link)
    // Prefixed with underscore to indicate this is an experimental/unsupported feature
    pub _force_bitrate: bool,

    // Discovery fields
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
}

#[derive(Clone)]
pub struct QueuedAnnounce {
    pub raw: Vec<u8>,
    pub hops: u8,
    pub time: f64,
}

impl Interface {
    // Constants
    pub const IA_FREQ_SAMPLES: usize = 6;
    pub const OA_FREQ_SAMPLES: usize = 6;
    pub const MAX_HELD_ANNOUNCES: usize = 256;
    pub const IC_NEW_TIME: f64 = 2.0 * 60.0 * 60.0; // 2 hours
    pub const IC_BURST_FREQ_NEW: f64 = 3.5;
    pub const IC_BURST_FREQ: f64 = 12.0;
    pub const IC_BURST_HOLD: f64 = 1.0 * 60.0; // 1 minute
    pub const IC_BURST_PENALTY: f64 = 5.0 * 60.0; // 5 minutes
    pub const IC_HELD_RELEASE_INTERVAL: f64 = 30.0; // 30 seconds

    pub fn new() -> Self {
        let now = current_time();
        
        Interface {
            in_enabled: false,
            out_enabled: false,
            fwd_enabled: false,
            rpt_enabled: false,
            name: None,
            rxb: 0,
            txb: 0,
            created: now,
            detached: false,
            online: false,
            bitrate: 62500,
            hw_mtu: None,
            autoconfigure_mtu: false,
            fixed_mtu: false,
            supports_discovery: false,
            discoverable: false,
            last_discovery_announce: 0.0,
            bootstrap_only: false,
            parent_interface: None,
            spawned_interfaces: None,
            tunnel_id: None,
            ingress_control: true,
            ic_max_held_announces: Self::MAX_HELD_ANNOUNCES,
            ic_burst_hold: Self::IC_BURST_HOLD,
            ic_burst_active: false,
            ic_burst_activated: 0.0,
            ic_held_release: 0.0,
            ic_burst_freq_new: Self::IC_BURST_FREQ_NEW,
            ic_burst_freq: Self::IC_BURST_FREQ,
            ic_new_time: Self::IC_NEW_TIME,
            ic_burst_penalty: Self::IC_BURST_PENALTY,
            ic_held_release_interval: Self::IC_HELD_RELEASE_INTERVAL,
            held_announces: HashMap::new(),
            ia_freq_deque: VecDeque::with_capacity(Self::IA_FREQ_SAMPLES),
            oa_freq_deque: VecDeque::with_capacity(Self::OA_FREQ_SAMPLES),
            announce_queue: Vec::new(),
            announce_cap: 2.0, // Will be set from Reticulum.ANNOUNCE_CAP
            announce_allowed_at: 0.0,

            mode: InterfaceMode::Full,
            announce_rate_target: None,
            announce_rate_grace: None,
            announce_rate_penalty: None,

            ifac_size: crate::reticulum::IFAC_MIN_SIZE,
            ifac_netname: None,
            ifac_netkey: None,
            ifac_key: None,
            ifac_identity: None,
            ifac_signature: None,

            _force_bitrate: false,

            discovery_announce_interval: None,
            discovery_publish_ifac: false,
            reachable_on: None,
            discovery_name: None,
            discovery_encrypt: false,
            discovery_stamp_value: None,
            discovery_latitude: None,
            discovery_longitude: None,
            discovery_height: None,
            discovery_frequency: None,
            discovery_bandwidth: None,
            discovery_modulation: None,
        }
    }

    /// Get the hash of this interface
    pub fn get_hash(&self) -> Vec<u8> {
        let interface_str = self.name.as_ref().map(|n| n.as_str()).unwrap_or("unnamed");
        Identity::full_hash(interface_str.as_bytes())
    }

    /// If `_force_bitrate` is enabled, sleep proportionally to the data size
    /// to simulate the configured bitrate. This is an experimental feature
    /// and may not be fully supported on all interface types.
    pub fn enforce_bitrate(&self, data_len: usize) {
        if self._force_bitrate && self.bitrate > 0 {
            let delay_secs = (data_len as f64 / self.bitrate as f64) * 8.0;
            std::thread::sleep(std::time::Duration::from_secs_f64(delay_secs));
        }
    }

    /// Determine if ingress limiting should be active
    pub fn should_ingress_limit(&mut self) -> bool {
        if !self.ingress_control {
            return false;
        }

        let now = current_time();
        let freq_threshold = if self.age() < self.ic_new_time {
            self.ic_burst_freq_new
        } else {
            self.ic_burst_freq
        };
        let ia_freq = self.incoming_announce_frequency();

        if self.ic_burst_active {
            if ia_freq < freq_threshold && now > self.ic_burst_activated + self.ic_burst_hold {
                self.ic_burst_active = false;
                self.ic_held_release = now + self.ic_burst_penalty;
            }
            true
        } else {
            if ia_freq > freq_threshold {
                self.ic_burst_active = true;
                self.ic_burst_activated = now;
                true
            } else {
                false
            }
        }
    }

    /// Optimize MTU based on bitrate
    ///
    /// RNS/Interfaces/Interface.py:250-262 — every boundary is `>=` in the
    /// reference. Half of these were `>` here, which put an interface sitting
    /// exactly on a boundary bitrate (e.g. the default 62500) one tier low.
    pub fn optimise_mtu(&mut self) {
        if self.autoconfigure_mtu {
            self.hw_mtu = Some(if self.bitrate >= 1_000_000_000 {
                524288
            } else if self.bitrate >= 750_000_000 {
                262144
            } else if self.bitrate >= 400_000_000 {
                131072
            } else if self.bitrate >= 200_000_000 {
                65536
            } else if self.bitrate >= 100_000_000 {
                32768
            } else if self.bitrate >= 10_000_000 {
                16384
            } else if self.bitrate >= 5_000_000 {
                8192
            } else if self.bitrate >= 2_000_000 {
                4096
            } else if self.bitrate >= 1_000_000 {
                2048
            } else if self.bitrate >= 62_500 {
                1024
            } else {
                return; // Set to None for very low bitrates
            });
        }
    }

    /// Get the age of this interface in seconds
    pub fn age(&self) -> f64 {
        current_time() - self.created
    }

    /// Hold an announce packet during ingress limiting
    pub fn hold_announce(&mut self, destination_hash: Vec<u8>, announce_packet: Vec<u8>) {
        if self.held_announces.contains_key(&destination_hash) {
            self.held_announces.insert(destination_hash, announce_packet);
        } else if self.held_announces.len() < self.ic_max_held_announces {
            self.held_announces.insert(destination_hash, announce_packet);
        }
    }

    /// Process held announces and release when safe
    /// Checks if a held announce is ready to be released, removes it from the
    /// held queue, and returns the raw packet bytes + interface name so the
    /// caller can pass them to `Transport::inbound` *after* releasing the
    /// TRANSPORT lock (calling `Transport::inbound` while holding the TRANSPORT
    /// lock causes a re-entrant deadlock).
    pub fn take_held_announce(&mut self) -> Option<(Vec<u8>, Option<String>)> {
        let now = current_time();

        if self.should_ingress_limit() || self.held_announces.is_empty() || now <= self.ic_held_release {
            return None;
        }

        let freq_threshold = if self.age() < self.ic_new_time {
            self.ic_burst_freq_new
        } else {
            self.ic_burst_freq
        };
        let ia_freq = self.incoming_announce_frequency();

        if ia_freq < freq_threshold {
            // Find announce with minimum hops
            // TODO: This needs packet parsing to get hops - stub for now
            if let Some((dest_hash, _packet)) = self.held_announces.iter().next() {
                let dest_hash = dest_hash.clone();
                self.ic_held_release = now + self.ic_held_release_interval;

                if let Some(announce) = self.held_announces.remove(&dest_hash) {
                    return Some((announce, self.name.clone()));
                }
            }
        }
        None
    }

    /// Process a held announce by re-injecting it into Transport::inbound.
    /// Do NOT call this while the TRANSPORT mutex is held; use `take_held_announce`
    /// and defer the `Transport::inbound` call until after releasing the lock.
    pub fn process_held_announces(&mut self) {
        if let Some((announce, interface_name)) = self.take_held_announce() {
            let _ = Transport::inbound(announce, interface_name);
        }
    }

    /// Track received announce
    pub fn received_announce(&mut self, _from_spawned: bool) {
        let now = current_time();
        
        if self.ia_freq_deque.len() >= Self::IA_FREQ_SAMPLES {
            self.ia_freq_deque.pop_front();
        }
        self.ia_freq_deque.push_back(now);

        // Propagate to parent if exists
        if let Some(ref mut parent) = self.parent_interface {
            parent.received_announce(true);
        }
    }

    /// Track sent announce
    pub fn sent_announce(&mut self, _from_spawned: bool) {
        let now = current_time();
        
        if self.oa_freq_deque.len() >= Self::OA_FREQ_SAMPLES {
            self.oa_freq_deque.pop_front();
        }
        self.oa_freq_deque.push_back(now);

        // Propagate to parent if exists
        if let Some(ref mut parent) = self.parent_interface {
            parent.sent_announce(true);
        }
    }

    /// Calculate incoming announce frequency
    pub fn incoming_announce_frequency(&self) -> f64 {
        calculate_frequency(&self.ia_freq_deque)
    }

    /// Calculate outgoing announce frequency
    pub fn outgoing_announce_frequency(&self) -> f64 {
        calculate_frequency(&self.oa_freq_deque)
    }

    /// Process announce queue with rate limiting
    pub fn process_announce_queue(&mut self) {
        if self.announce_queue.is_empty() {
            return;
        }

        let now = current_time();
        
        // Remove stale announces (older than QUEUED_ANNOUNCE_LIFE)
        self.announce_queue.retain(|a| now <= a.time + crate::reticulum::QUEUED_ANNOUNCE_LIFE);

        if now < self.announce_allowed_at {
            return;
        }

        if self.announce_queue.is_empty() {
            return;
        }

        // Find minimum hops
        let min_hops = self.announce_queue.iter().map(|a| a.hops).min().unwrap();
        
        // Filter and sort by time
        let mut candidates: Vec<_> = self.announce_queue
            .iter()
            .filter(|a| a.hops == min_hops)
            .cloned()
            .collect();
        candidates.sort_by(|a, b| a.time.partial_cmp(&b.time).unwrap());

        if let Some(selected) = candidates.first() {
            let tx_time = (selected.raw.len() as f64 * 8.0) / self.bitrate as f64;
            let wait_time = tx_time / self.announce_cap;
            self.announce_allowed_at = now + wait_time;

            // TODO: Call self.process_outgoing(selected.raw) - requires Transport integration
            self.sent_announce(false);

            // Remove from queue
            self.announce_queue.retain(|a| a.raw != selected.raw);

            // TODO: Schedule next processing with timer if queue not empty
        }
    }

    /// Stub for subclass-specific initialization
    pub fn final_init(&mut self) {
        // Override in subclasses
    }

    /// Stub for interface detachment
    pub fn detach(&mut self) {
        // Override in subclasses
    }
}

impl Default for Interface {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to get current time as f64 seconds since epoch
fn current_time() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Calculate announce frequency from deque of timestamps
fn calculate_frequency(deque: &VecDeque<f64>) -> f64 {
    if deque.len() <= 1 {
        return 0.0;
    }

    let dq_len = deque.len();
    let mut delta_sum = 0.0;
    
    for i in 1..dq_len {
        delta_sum += deque[i] - deque[i - 1];
    }
    delta_sum += current_time() - deque[dq_len - 1];

    if delta_sum == 0.0 {
        0.0
    } else {
        1.0 / (delta_sum / dq_len as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_creation() {
        let iface = Interface::new();
        assert_eq!(iface.rxb, 0);
        assert_eq!(iface.txb, 0);
        assert_eq!(iface.bitrate, 62500);
        assert!(!iface.detached);
        assert!(iface.ingress_control);
    }

    #[test]
    fn test_mtu_optimization() {
        let mut iface = Interface::new();
        iface.autoconfigure_mtu = true;
        
        iface.bitrate = 1_500_000_000;
        iface.optimise_mtu();
        assert_eq!(iface.hw_mtu, Some(524288));

        iface.bitrate = 100_000_000;
        iface.optimise_mtu();
        assert_eq!(iface.hw_mtu, Some(32768));

        iface.bitrate = 1_000_000;
        iface.optimise_mtu();
        assert_eq!(iface.hw_mtu, Some(2048));
    }

    // RNS/Interfaces/Interface.py:250-262 — every tier boundary is `>=`.
    // Exercises exactly the boundaries that used to be `>` here, so a
    // regression to `>` drops each of them one tier.
    #[test]
    fn test_mtu_optimization_boundaries_are_inclusive() {
        let mut iface = Interface::new();
        iface.autoconfigure_mtu = true;

        for (bitrate, expected) in [
            (750_000_000u64, 262144usize),
            (400_000_000, 131072),
            (200_000_000, 65536),
            (10_000_000, 16384),
            (5_000_000, 8192),
            (2_000_000, 4096),
            (62_500, 1024),
        ] {
            iface.hw_mtu = None;
            iface.bitrate = bitrate;
            iface.optimise_mtu();
            assert_eq!(
                iface.hw_mtu,
                Some(expected),
                "a bitrate of exactly {} must land on the {} tier, not the one below it",
                bitrate,
                expected
            );
        }
    }

    #[test]
    fn test_age() {
        let iface = Interface::new();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(iface.age() >= 0.1);
    }

    #[test]
    fn test_interface_mode_discovery() {
        assert!(InterfaceMode::AccessPoint.should_discover_paths());
        assert!(InterfaceMode::Gateway.should_discover_paths());
        assert!(InterfaceMode::Roaming.should_discover_paths());
        assert!(!InterfaceMode::Full.should_discover_paths());
        assert!(!InterfaceMode::PointToPoint.should_discover_paths());
    }
}
