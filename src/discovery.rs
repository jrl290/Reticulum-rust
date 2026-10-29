// Reticulum License
//
// Copyright (c) 2016-2025 Mark Qvist
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// - The Software shall not be used in any kind of system which includes amongst
//   its functions the ability to purposefully do harm to human beings.
//
// - The Software shall not be used, directly or indirectly, in the creation of
//   an artificial intelligence, machine learning or language model training
//   dataset, including but not limited to any use that contributes to the
//   training or development of such a model or algorithm.
//
// - The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use crate::{log, LOG_DEBUG, LOG_ERROR, LOG_EXTREME, LOG_INFO, LOG_NOTICE, LOG_WARNING};
use crate::identity::{self, Identity};
use crate::interfaces::interface::InterfaceMode;
use crate::interfaces::tcp_interface::TcpClientInterface;
use crate::lxstamper::LXStamper;

// Discovery field identifiers
pub const NAME: u8 = 0xFF;
pub const TRANSPORT_ID: u8 = 0xFE;
pub const INTERFACE_TYPE: u8 = 0x00;
pub const TRANSPORT: u8 = 0x01;
pub const REACHABLE_ON: u8 = 0x02;
pub const LATITUDE: u8 = 0x03;
pub const LONGITUDE: u8 = 0x04;
pub const HEIGHT: u8 = 0x05;
pub const PORT: u8 = 0x06;
pub const IFAC_NETNAME: u8 = 0x07;
pub const IFAC_NETKEY: u8 = 0x08;
pub const FREQUENCY: u8 = 0x09;
pub const BANDWIDTH: u8 = 0x0A;
pub const SPREADINGFACTOR: u8 = 0x0B;
pub const CODINGRATE: u8 = 0x0C;
pub const MODULATION: u8 = 0x0D;
pub const CHANNEL: u8 = 0x0E;
pub const OP_ADDR: u8 = 0xF0;

pub const APP_NAME: &str = "rnstransport";

/// An address as Python's `ipaddress.ip_address` reads it, which also takes
/// an IPv6 zone ("fe80::1%en0").
fn parse_ip_address(address_string: &str) -> Option<IpAddr> {
    match address_string.split_once('%') {
        Some((address, zone)) if !zone.is_empty() && !zone.contains('%') => {
            address.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
        }
        Some(_) => None,
        None => address_string.parse::<IpAddr>().ok(),
    }
}

/// Helper function to check if a string is a valid IP address
pub fn is_ip_address(address_string: &str) -> bool {
    parse_ip_address(address_string).is_some()
}

/// An address in Yggdrasil's 200::/7.
pub fn is_ygg_ipv6(address_string: &str) -> bool {
    match parse_ip_address(address_string) {
        Some(IpAddr::V6(address)) => address.octets()[0] & 0xFE == 0x02,
        _ => false,
    }
}

pub fn is_onion_address(address_string: &str) -> bool {
    address_string.to_lowercase().ends_with(".onion")
}

/// The reference's INVALID_IP_ADDRESSES, compared as written.
pub fn is_invalid_ip_address(address_string: &str) -> bool {
    ["127.0.0.1", "0.0.0.0"].contains(&address_string)
}

/// Helper function to check if a string is a valid hostname
pub fn is_hostname(hostname: &str) -> bool {
    // As the reference does: one trailing dot comes off.
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);

    if hostname.len() > 253 {
        return false;
    }
    
    let components: Vec<&str> = hostname.split('.').collect();
    
    // Check if last component is all digits (would be invalid for hostname)
    if let Some(last) = components.last() {
        if last.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    
    // Validate each component
    for label in components {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        
        // Check if starts or ends with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        
        // Check if contains only allowed characters (alphanumeric and hyphen)
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    
    true
}

/// Stamp data structure for proof-of-work validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stamp {
    pub data: Vec<u8>,
}

impl Stamp {
    pub const STAMP_SIZE: usize = 32;
}

/// Interface information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    #[serde(rename = "type")]
    pub interface_type: String,
    pub transport: bool,
    pub name: String,
    pub received: f64,
    pub stamp: Vec<u8>,
    pub value: u32,
    pub transport_id: String,
    pub network_id: String,
    pub hops: u32,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable_on: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifac_netkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sf: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cr: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modulation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_hash: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_lxmf_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heard: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heard_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u32>,
}

/// Announces discoverable interfaces to the network
pub struct InterfaceAnnouncer {
    should_run: Arc<Mutex<bool>>,
    job_interval: Duration,
    stamp_cache: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    last_announce_times: Arc<Mutex<HashMap<String, f64>>>,
}

impl InterfaceAnnouncer {
    pub const JOB_INTERVAL: u64 = 60;
    pub const DEFAULT_STAMP_VALUE: u32 = 16;
    pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 20;
    
    pub const DISCOVERABLE_INTERFACE_TYPES: &'static [&'static str] = &[
        "BackboneInterface",
        "TCPServerInterface", 
        "TCPClientInterface",
        "RNodeInterface",
        "WeaveInterface",
        "I2PInterface",
        "KISSInterface",
    ];
    
    pub fn new() -> Self {
        Self {
            should_run: Arc::new(Mutex::new(false)),
            job_interval: Duration::from_secs(Self::JOB_INTERVAL),
            stamp_cache: Arc::new(Mutex::new(HashMap::new())),
            last_announce_times: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Start the announcer background job
    pub fn start(&self) {
        let mut should_run = self.should_run.lock().unwrap();
        if !*should_run {
            *should_run = true;
            drop(should_run);
            
            let should_run_clone = Arc::clone(&self.should_run);
            let job_interval = self.job_interval;
            let stamp_cache_clone = Arc::clone(&self.stamp_cache);
            let last_announce_clone = Arc::clone(&self.last_announce_times);
            
            thread::spawn(move || {
                Self::job(should_run_clone, job_interval, stamp_cache_clone, last_announce_clone);
            });
        }
    }
    
    /// Stop the announcer
    pub fn stop(&self) {
        let mut should_run = self.should_run.lock().unwrap();
        *should_run = false;
    }
    
    fn job(
        should_run: Arc<Mutex<bool>>, 
        job_interval: Duration, 
        stamp_cache: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
        last_announce_times: Arc<Mutex<HashMap<String, f64>>>,
    ) {
        while *should_run.lock().unwrap() {
            thread::sleep(job_interval);
            
            match Self::job_tick(&stamp_cache, &last_announce_times) {
                Ok(_) => {}
                Err(e) => {
                    log(&format!("Error while preparing interface discovery announces: {}", e), 
                        crate::LOG_ERROR, false, false);
                }
            }
        }
    }

    fn job_tick(
        stamp_cache: &Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
        last_announce_times: &Arc<Mutex<HashMap<String, f64>>>,
    ) -> Result<(), String> {
        use crate::transport::Transport;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        // Get interfaces from Transport
        let interfaces = Transport::get_interface_list();
        
        // Find due interfaces
        let mut due_interfaces: Vec<(String, crate::transport::InterfaceStub, f64)> = Vec::new();
        let last_times = last_announce_times.lock().unwrap();
        
        for interface in interfaces {
            // Check if interface is discoverable and has announce interval
            if !interface.discoverable {
                continue;
            }
            
            let Some(interval) = interface.discovery_announce_interval else {
                continue;
            };
            
            // Check if interface type is discoverable
            let interface_type = Self::get_interface_type(&interface.name);
            if !Self::DISCOVERABLE_INTERFACE_TYPES.contains(&interface_type.as_str()) {
                continue;
            }
            
            let last_announce = last_times.get(&interface.name).copied().unwrap_or(0.0);
            
            if now > last_announce + interval {
                let overdue = now - (last_announce + interval);
                due_interfaces.push((interface.name.clone(), interface, overdue));
            }
        }
        
        drop(last_times);
        
        // Sort by how overdue they are (most overdue first)
        due_interfaces.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        
        if let Some((name, interface, _)) = due_interfaces.first() {
            log(&format!("Preparing interface discovery announce for {}", name), 
                LOG_DEBUG, false, false);
            
            if let Some(app_data) = Self::get_interface_announce_data(&interface, stamp_cache) {
                log(&format!("Sending interface discovery announce for {} with {}B payload", 
                    name, app_data.len()), LOG_DEBUG, false, false);
                
                // Get transport identity and announce via discovery destination
                if let Err(e) = Self::send_discovery_announce(&app_data) {
                    log(&format!("Failed to send discovery announce: {}", e), 
                        crate::LOG_ERROR, false, false);
                } else {
                    // Update last announce time
                    let mut last_times = last_announce_times.lock().unwrap();
                    last_times.insert(name.clone(), now);
                }
            } else {
                log(&format!("Could not generate interface discovery announce data for {}", name), 
                    crate::LOG_ERROR, false, false);
            }
        }
        
        Ok(())
    }
    
    fn send_discovery_announce(app_data: &[u8]) -> Result<(), String> {
        use crate::destination::{Destination, DestinationType};
        use crate::transport::Transport;
        
        // Create discovery destination using transport identity or network identity
        let identity = Transport::discovery_identity_clone();
        // RNS/Discovery.py:67: a SINGLE destination on the discovery
        // identity. (It was PLAIN here, which announce() rejects, so no
        // discovery announce was ever sent.)
        let mut discovery_dest = Destination::new_inbound(
            identity,
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["discovery".to_string(), "interface".to_string()],
        ).map_err(|e| format!("Failed to create discovery destination: {}", e))?;
        
        // Announce with app_data
        discovery_dest.announce(Some(app_data), false, None, None, true)
            .map_err(|e| format!("Failed to announce: {}", e))?;
        
        Ok(())
    }
    
    fn get_interface_type(interface_name: &str) -> String {
        // Try to determine interface type from name or stub config
        // For now, we'll check common patterns
        if interface_name.contains("TCP") || interface_name.contains("tcp") {
            if interface_name.contains("Server") || interface_name.contains("server") {
                "TCPServerInterface".to_string()
            } else {
                "TCPClientInterface".to_string()
            }
        } else if interface_name.contains("UDP") || interface_name.contains("udp") {
            "UDPInterface".to_string()
        } else {
            "UnknownInterface".to_string()
        }
    }
    
    fn sanitize(in_str: &str) -> String {
        in_str.replace('\n', "").replace('\r', "").trim().to_string()
    }
    
    /// Generate announcement data for an interface
    fn get_interface_announce_data(
        interface: &crate::transport::InterfaceStub,
        stamp_cache: &Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    ) -> Option<Vec<u8>> {
        use crate::transport::Transport;
        use rmp_serde::encode::to_vec as msgpack_encode;
        use std::collections::HashMap as MsgPackMap;
        
        let interface_type = Self::get_interface_type(&interface.name);
        
        if !Self::DISCOVERABLE_INTERFACE_TYPES.contains(&interface_type.as_str()) {
            return None;
        }
        
        let _stamp_value = interface.discovery_stamp_value.unwrap_or(Self::DEFAULT_STAMP_VALUE);
        
        // Build info dictionary
        let mut info: MsgPackMap<u8, Vec<u8>> = MsgPackMap::new();
        
        // INTERFACE_TYPE
        info.insert(INTERFACE_TYPE, interface_type.as_bytes().to_vec());
        
        // TRANSPORT (enabled)
        info.insert(TRANSPORT, vec![if Transport::transport_enabled() { 1 } else { 0 }]);
        
        // TRANSPORT_ID
        if let Some(identity_hash) = Transport::identity_hash() {
            info.insert(TRANSPORT_ID, identity_hash);
        }
        
        // NAME
        if let Some(name) = &interface.discovery_name {
            info.insert(NAME, Self::sanitize(name).as_bytes().to_vec());
        }
        
        // LATITUDE, LONGITUDE, HEIGHT
        if let Some(lat) = interface.discovery_latitude {
            info.insert(LATITUDE, lat.to_string().as_bytes().to_vec());
        }
        if let Some(lon) = interface.discovery_longitude {
            info.insert(LONGITUDE, lon.to_string().as_bytes().to_vec());
        }
        if let Some(height) = interface.discovery_height {
            info.insert(HEIGHT, height.to_string().as_bytes().to_vec());
        }
        
        // Reachable_on validation and interface-specific fields
        if let Some(reachable_on) = &interface.reachable_on {
            let reachable = Self::sanitize(reachable_on);
            
            // Simple validation - check if it's an IP or hostname
            if !is_ip_address(&reachable) && !is_hostname(&reachable) {
                log(&format!("The configured reachable_on parameter \"{}\" for {} is not a valid IP address or hostname",
                    reachable, interface.name), crate::LOG_ERROR, false, false);
                log("Aborting discovery announce", crate::LOG_ERROR, false, false);
                return None;
            }
            
            if interface_type == "TCPServerInterface" {
                info.insert(REACHABLE_ON, reachable.as_bytes().to_vec());
                // PORT would need to be extracted from interface config
                // For now, we'll skip it since we don't have bind_port in InterfaceStub
            }
        }
        
        // Discovery frequency/bandwidth/modulation for radio interfaces
        if let Some(freq) = interface.discovery_frequency {
            info.insert(FREQUENCY, freq.to_le_bytes().to_vec());
        }
        if let Some(bw) = interface.discovery_bandwidth {
            info.insert(BANDWIDTH, bw.to_le_bytes().to_vec());
        }
        if let Some(mod_str) = &interface.discovery_modulation {
            info.insert(MODULATION, Self::sanitize(mod_str).as_bytes().to_vec());
        }
        
        // IFAC publishing
        if interface.discovery_publish_ifac {
            if let Some(netname) = &interface.ifac_netname {
                info.insert(IFAC_NETNAME, Self::sanitize(netname).as_bytes().to_vec());
            }
            if let Some(netkey) = &interface.ifac_netkey {
                info.insert(IFAC_NETKEY, Self::sanitize(netkey).as_bytes().to_vec());
            }
        }
        
        // Pack info with msgpack
        let packed = msgpack_encode(&info).ok()?;
        
        // Generate infohash
        let infohash = crate::identity::full_hash(&packed);
        
        // Check stamp cache or generate new stamp
        let stamp_value = interface.discovery_stamp_value.unwrap_or(Self::DEFAULT_STAMP_VALUE);
        let stamp = {
            let cache = stamp_cache.lock().unwrap();
            if let Some(cached_stamp) = cache.get(&infohash) {
                cached_stamp.clone()
            } else {
                drop(cache);
                // Generate LXMF proof-of-work stamp. A cancelled or timed-out
                // search yields None; announcing without a stamp is better than
                // announcing one that fails our own validator, so skip the
                // announce entirely this round.
                let (generated_stamp, _value) = LXStamper::generate_stamp(
                    &infohash,
                    stamp_value,
                    Self::WORKBLOCK_EXPAND_ROUNDS
                );
                let generated_stamp = generated_stamp?;
                let mut cache = stamp_cache.lock().unwrap();
                cache.insert(infohash.clone(), generated_stamp.clone());
                generated_stamp
            }
        };
        
        // Combine packed data and stamp
        let mut payload = packed;
        payload.extend_from_slice(&stamp);
        
        // Handle encryption if requested
        let flags: u8 = if interface.discovery_encrypt {
            log("Discovery encryption not yet implemented", LOG_WARNING, false, false);
            0x00 // FLAG_ENCRYPTED would be set here when encryption is implemented
        } else {
            0x00
        };
        
        // Return flags + payload
        let mut result = vec![flags];
        result.extend_from_slice(&payload);
        Some(result)
    }
}

/// Handles received interface discovery announces
pub struct InterfaceAnnounceHandler {
    pub aspect_filter: String,
    pub required_value: u32,
    pub callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>,
    valid_cache: Mutex<ValidCache>,
    invalid_cache: Mutex<VecDeque<Vec<u8>>>,
    validation_lock: Mutex<()>,
}

/// A checked stamp, kept by the full hash of the announce data that carried it.
#[derive(Clone)]
struct StampCheck {
    valid: bool,
    value: u32,
    packed: Vec<u8>,
    stamp: Vec<u8>,
}

/// The reference's `valid_cache`: a dict trimmed from its oldest entry.
#[derive(Default)]
struct ValidCache {
    entries: HashMap<Vec<u8>, StampCheck>,
    order: VecDeque<Vec<u8>>,
}

impl ValidCache {
    fn insert(&mut self, key: Vec<u8>, check: StampCheck) {
        if self.entries.insert(key.clone(), check).is_none() {
            self.order.push_back(key);
        }
        while self.entries.len() > InterfaceAnnounceHandler::VALID_CACHE_MAX {
            match self.order.pop_front() {
                Some(oldest) => { self.entries.remove(&oldest); }
                None => break,
            }
        }
    }
}

impl InterfaceAnnounceHandler {
    pub const FLAG_SIGNED: u8 = 0b00000001;
    pub const FLAG_ENCRYPTED: u8 = 0b00000010;
    const VALID_CACHE_MAX: usize = 2048;
    const INVALID_CACHE_MAX: usize = 2048;

    pub fn new(required_value: Option<u32>, callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>) -> Self {
        let required_value = required_value.unwrap_or(InterfaceAnnouncer::DEFAULT_STAMP_VALUE);

        Self {
            aspect_filter: format!("{}.discovery.interface", APP_NAME),
            required_value,
            callback,
            valid_cache: Mutex::new(ValidCache::default()),
            invalid_cache: Mutex::new(VecDeque::new()),
            validation_lock: Mutex::new(()),
        }
    }

    /// RNS/Discovery.py `sanitize_name`: ASCII only, runs of spaces shortened,
    /// and everything before the first letter or digit and after the last
    /// letter, digit or ")" removed. The name is part of the discovery hash
    /// an entry is stored under, so this must match the reference exactly.
    /// (The reference's `strip()` is left out: the end trimming removes the
    /// same characters.)
    pub fn sanitize_name(name: &str) -> Option<String> {
        if name.is_empty() {
            return None;
        }
        let mut name: String = name.chars().filter(|c| c.is_ascii()).collect();
        for run in [5, 3, 2] {
            name = name.replace(&" ".repeat(run), " ");
        }
        let kept = |c: char| c.is_ascii_alphanumeric();
        let start = name.find(kept).unwrap_or(name.len());
        name.drain(..start);
        let end = name.rfind(|c: char| kept(c) || c == ')').map(|i| i + 1).unwrap_or(0);
        name.truncate(end);
        Some(name)
    }

    /// Process a received announce
    pub fn received_announce(&self, destination_hash: &[u8], announced_identity: &Identity, app_data: &[u8]) {
        if let Err(e) = self.decode_announce(destination_hash, announced_identity, app_data) {
            log(&format!("An error occurred while trying to decode discovered interface. The contained exception was: {}", e),
                LOG_DEBUG, false, false);
        }
    }

    fn decode_announce(&self, destination_hash: &[u8], announced_identity: &Identity, app_data: &[u8]) -> Result<(), String> {
        let network_id = announced_identity.hash.clone().unwrap_or_default();
        let discovery_sources = crate::reticulum::interface_discovery_sources();
        if !discovery_sources.is_empty() && !discovery_sources.contains(&network_id) {
            log(&format!("Interface discovered from non-authorized network identity {}, ignoring", crate::prettyhexrep(&network_id)),
                LOG_DEBUG, false, false);
            return Ok(());
        }

        if app_data.len() <= LXStamper::STAMP_SIZE + 1 {
            return Ok(());
        }

        let flags = app_data[0];
        let mut app_data = app_data[1..].to_vec();
        let encrypted = (flags & Self::FLAG_ENCRYPTED) != 0;
        let fullhash = identity::full_hash(&app_data);

        if self.invalid_cache.lock().unwrap().contains(&fullhash) {
            log("Ignored previously discovered interface with insufficient stamp value", LOG_EXTREME, false, false);
            return Ok(());
        }

        let cached = self.valid_cache.lock().unwrap().entries.get(&fullhash).cloned();
        let check = match cached {
            Some(check) => {
                log("Discovery announce cache hit", LOG_EXTREME, false, false);
                check
            }
            None => {
                if encrypted {
                    if !crate::transport::Transport::has_network_identity() {
                        return Ok(());
                    }
                    match crate::transport::Transport::network_identity_decrypt(&app_data) {
                        Some(plaintext) => app_data = plaintext,
                        None => return Ok(()),
                    }
                }

                let _validating = match self.validation_lock.try_lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        log("Dropping received interface discovery announce, already validating other discovery stamp",
                            LOG_DEBUG, false, false);
                        return Ok(());
                    }
                };

                if app_data.len() < LXStamper::STAMP_SIZE {
                    return Err("announce data is shorter than a stamp".to_string());
                }
                let split = app_data.len() - LXStamper::STAMP_SIZE;
                let stamp = app_data[split..].to_vec();
                let packed = app_data[..split].to_vec();
                let infohash = identity::full_hash(&packed);
                let workblock = LXStamper::stamp_workblock(&infohash, InterfaceAnnouncer::WORKBLOCK_EXPAND_ROUNDS);
                let value = LXStamper::stamp_value(&workblock, &stamp);
                let valid = LXStamper::stamp_valid(&stamp, self.required_value, &workblock);
                let check = StampCheck { valid, value, packed, stamp };
                self.valid_cache.lock().unwrap().insert(fullhash.clone(), check.clone());
                check
            }
        };

        if !check.valid {
            // RNS.Discovery on the Python side validates these with
            // LXMF.LXStamper, so this path is a direct interop surface. Call out
            // the pre-parity workblock by name: while it was in use, every
            // announce exchanged with a reference node failed here, in both
            // directions, and looked indistinguishable from an empty network.
            let infohash = identity::full_hash(&check.packed);
            if LXStamper::is_legacy_stamp(&infohash, &check.stamp, self.required_value,
                                          InterfaceAnnouncer::WORKBLOCK_EXPAND_ROUNDS) {
                log("Ignored discovered interface: announcer is using the pre-parity stamp \
                     workblock (iterated digest instead of LXMF HKDF expansion)",
                    LOG_WARNING, false, false);
            } else {
                log(&format!("Ignored discovered interface with insufficient stamp value {}", check.value),
                    LOG_DEBUG, false, false);
            }
            let mut invalid = self.invalid_cache.lock().unwrap();
            invalid.push_back(fullhash);
            while invalid.len() > Self::INVALID_CACHE_MAX {
                invalid.pop_front();
            }
            return Ok(());
        }

        if check.value < self.required_value {
            log(&format!("Ignored discovered interface with stamp value {}", check.value), LOG_DEBUG, false, false);
            return Ok(());
        }

        let unpacked = rmpv::decode::read_value(&mut &check.packed[..]).map_err(|e| e.to_string())?;
        let mut info = Self::interface_info(&unpacked, destination_hash, &network_id, &check)?;

        if let (Some(info), Some(op_addr)) = (info.as_mut(), map_get(&unpacked, OP_ADDR)) {
            match op_addr {
                rmpv::Value::Nil => {}
                rmpv::Value::Binary(address) => {
                    if address.len() == crate::reticulum::TRUNCATED_HASHLENGTH / 8 {
                        info.operator_lxmf_address = Some(crate::hexrep(address, false));
                    }
                }
                _ => return Err("Invalid data in operator LXMF address field of announce".to_string()),
            }
        }

        if let (Some(info), Some(callback)) = (info, self.callback.as_ref()) {
            callback(info);
        }
        Ok(())
    }

    /// The `info` the reference builds from the unpacked announce data, or
    /// `None` when the data names no interface type.
    fn interface_info(
        unpacked: &rmpv::Value,
        destination_hash: &[u8],
        network_id: &[u8],
        check: &StampCheck,
    ) -> Result<Option<InterfaceInfo>, String> {
        let interface_type = match map_get(unpacked, INTERFACE_TYPE) {
            Some(value) => value.as_str().unwrap_or_default().to_string(),
            None => return Ok(None),
        };
        let name = match field(unpacked, NAME, "name")? {
            rmpv::Value::String(name) => {
                Self::sanitize_name(name.as_str().ok_or("Invalid data in name field of announce")?)
            }
            rmpv::Value::Nil => None,
            _ => return Err("Invalid data in name field of announce".to_string()),
        };
        let transport = field(unpacked, TRANSPORT, "transport")?
            .as_bool()
            .ok_or("Invalid data in transport field of announce")?;
        let latitude = float_or_nil(field(unpacked, LATITUDE, "latitude")?)
            .ok_or("Invalid data in latitude field of announce")?;
        let longitude = float_or_nil(field(unpacked, LONGITUDE, "longitude")?)
            .ok_or("Invalid data in longitude field of announce")?;
        let height = float_or_nil(field(unpacked, HEIGHT, "height")?)
            .ok_or("Invalid data in height field of announce")?;
        let transport_id = match field(unpacked, TRANSPORT_ID, "transport_id")? {
            rmpv::Value::Binary(id) if id.len() == crate::reticulum::TRUNCATED_HASHLENGTH / 8 => id.clone(),
            _ => return Err("Invalid data in transport_id field of announce".to_string()),
        };
        if !InterfaceAnnouncer::DISCOVERABLE_INTERFACE_TYPES.contains(&interface_type.as_str()) {
            return Err("Invalid interface type in announce data".to_string());
        }
        let reachable_on = match map_get(unpacked, REACHABLE_ON) {
            Some(value) => match value.as_str() {
                Some(address) if is_ip_address(address) || is_hostname(address) => Some(address.to_string()),
                _ => return Err("Invalid data in reachable_on field of announce".to_string()),
            },
            None => None,
        };

        let name = name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("Discovered {}", interface_type));
        let mut info = InterfaceInfo {
            interface_type: interface_type.clone(),
            transport,
            name,
            received: now(),
            stamp: check.stamp.clone(),
            value: check.value,
            transport_id: crate::hexrep(&transport_id, false),
            network_id: crate::hexrep(network_id, false),
            hops: crate::transport::Transport::hops_to(destination_hash) as u32,
            latitude,
            longitude,
            height,
            reachable_on: None,
            port: None,
            ifac_netname: None,
            ifac_netkey: None,
            frequency: None,
            bandwidth: None,
            sf: None,
            cr: None,
            channel: None,
            modulation: None,
            config_entry: None,
            discovery_hash: None,
            operator_lxmf_address: None,
            discovered: None,
            last_heard: None,
            heard_count: None,
            status: None,
            status_code: None,
        };

        if let Some(value) = map_get(unpacked, IFAC_NETNAME) {
            info.ifac_netname = Some(python_str(value)?);
        }
        if let Some(value) = map_get(unpacked, IFAC_NETKEY) {
            info.ifac_netkey = Some(python_str(value)?);
        }

        // The reference writes a config entry for each type; its odd spots
        // (no identity for an RNode, an empty port for Weave) are its own.
        let cfg_name = info.name.clone();
        let cfg_identity_str = format!("\n  transport_identity = {}", info.transport_id);
        let cfg_netname_str = match info.ifac_netname.as_deref() {
            Some(netname) if !netname.is_empty() => format!("\n  network_name = {}", netname),
            _ => String::new(),
        };
        let cfg_netkey_str = match info.ifac_netkey.as_deref() {
            Some(netkey) if !netkey.is_empty() => format!("\n  passphrase = {}", netkey),
            _ => String::new(),
        };
        let shown = |value: Option<String>| value.unwrap_or_else(|| "None".to_string());

        match interface_type.as_str() {
            "BackboneInterface" | "TCPServerInterface" => {
                let remote = reachable_on.ok_or("missing reachable_on field in announce")?;
                let port = field(unpacked, PORT, "port")?
                    .as_u64()
                    .and_then(|port| u16::try_from(port).ok())
                    .ok_or("Invalid data in port field of announce")?;
                let backbone_support = !cfg!(any(target_os = "windows", target_os = "macos"));
                let connection_interface = if backbone_support { "BackboneInterface" } else { "TCPClientInterface" };
                let remote_str = if backbone_support { "remote" } else { "target_host" };
                info.config_entry = Some(format!(
                    "[[{}]]\n  type = {}\n  enabled = yes\n  {} = {}\n  target_port = {}{}{}{}",
                    cfg_name, connection_interface, remote_str, remote, port, cfg_identity_str, cfg_netname_str, cfg_netkey_str
                ));
                info.reachable_on = Some(remote);
                info.port = Some(port);
            }
            "I2PInterface" => {
                let remote = reachable_on.ok_or("missing reachable_on field in announce")?;
                info.config_entry = Some(format!(
                    "[[{}]]\n  type = I2PInterface\n  enabled = yes\n  peers = {}{}{}{}",
                    cfg_name, remote, cfg_identity_str, cfg_netname_str, cfg_netkey_str
                ));
                info.reachable_on = Some(remote);
            }
            "RNodeInterface" => {
                info.frequency = field(unpacked, FREQUENCY, "frequency")?.as_u64();
                info.bandwidth = field(unpacked, BANDWIDTH, "bandwidth")?.as_u64().and_then(|v| u32::try_from(v).ok());
                info.sf = field(unpacked, SPREADINGFACTOR, "spreadingfactor")?.as_u64().and_then(|v| u8::try_from(v).ok());
                info.cr = field(unpacked, CODINGRATE, "codingrate")?.as_u64().and_then(|v| u8::try_from(v).ok());
                info.config_entry = Some(format!(
                    "[[{}]]\n  type = RNodeInterface\n  enabled = yes\n  port = \n  frequency = {}\n  bandwidth = {}\n  spreadingfactor = {}\n  codingrate = {}\n  txpower = {}{}",
                    cfg_name,
                    shown(info.frequency.map(|v| v.to_string())),
                    shown(info.bandwidth.map(|v| v.to_string())),
                    shown(info.sf.map(|v| v.to_string())),
                    shown(info.cr.map(|v| v.to_string())),
                    cfg_netname_str,
                    cfg_netkey_str
                ));
            }
            "WeaveInterface" => {
                info.frequency = field(unpacked, FREQUENCY, "frequency")?.as_u64();
                info.bandwidth = field(unpacked, BANDWIDTH, "bandwidth")?.as_u64().and_then(|v| u32::try_from(v).ok());
                info.channel = field(unpacked, CHANNEL, "channel")?.as_u64().and_then(|v| u8::try_from(v).ok());
                info.modulation = field(unpacked, MODULATION, "modulation")?.as_str().map(String::from);
                info.config_entry = Some(format!(
                    "[[{}]]\n  type = WeaveInterface\n  enabled = yes\n  port = {}{}",
                    cfg_name, cfg_netname_str, cfg_netkey_str
                ));
            }
            "KISSInterface" => {
                info.frequency = field(unpacked, FREQUENCY, "frequency")?.as_u64();
                info.bandwidth = field(unpacked, BANDWIDTH, "bandwidth")?.as_u64().and_then(|v| u32::try_from(v).ok());
                info.modulation = field(unpacked, MODULATION, "modulation")?.as_str().map(String::from);
                info.config_entry = Some(format!(
                    "[[{}]]\n  type = KISSInterface\n  enabled = yes\n  port = \n  # Frequency: {}\n  # Bandwidth: {}\n  # Modulation: {}{}{}{}",
                    cfg_name,
                    shown(info.frequency.map(|v| v.to_string())),
                    shown(info.bandwidth.map(|v| v.to_string())),
                    shown(info.modulation.clone()),
                    cfg_identity_str,
                    cfg_netname_str,
                    cfg_netkey_str
                ));
            }
            _ => {}
        }

        let discovery_hash_material = format!("{}{}", info.transport_id, info.name);
        info.discovery_hash = Some(identity::full_hash(discovery_hash_material.as_bytes()));
        Ok(Some(info))
    }
}

/// A value of the announce's msgpack map, by its integer key (the last one
/// wins, as in the dict the reference unpacks).
fn map_get(map: &rmpv::Value, key: u8) -> Option<&rmpv::Value> {
    map.as_map()?
        .iter()
        .rev()
        .find(|(k, _)| k.as_u64() == Some(key as u64))
        .map(|(_, v)| v)
}

fn field<'a>(map: &'a rmpv::Value, key: u8, name: &str) -> Result<&'a rmpv::Value, String> {
    map_get(map, key).ok_or_else(|| format!("missing {} field in announce", name))
}

/// `None` or a float, as the reference requires of latitude, longitude and height.
fn float_or_nil(value: &rmpv::Value) -> Option<Option<f64>> {
    match value {
        rmpv::Value::Nil => Some(None),
        rmpv::Value::F32(v) => Some(Some(*v as f64)),
        rmpv::Value::F64(v) => Some(Some(*v)),
        _ => None,
    }
}

/// Python's `str()` of a value, for the IFAC fields the reference stores that way.
fn python_str(value: &rmpv::Value) -> Result<String, String> {
    match value {
        rmpv::Value::String(s) => s.as_str().map(String::from).ok_or_else(|| "Invalid string in announce".to_string()),
        rmpv::Value::Nil => Ok("None".to_string()),
        rmpv::Value::Boolean(b) => Ok(if *b { "True" } else { "False" }.to_string()),
        rmpv::Value::Integer(i) => Ok(i.to_string()),
        _ => Err("Invalid IFAC data in announce".to_string()),
    }
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// The reference's class-wide `discovery_lock`: every instance, a listing
/// one included, reads and writes the stored entries under it.
static DISCOVERY_LOCK: Mutex<()> = Mutex::new(());

/// An entry as RNS/Discovery.py stores it: a msgpack map with the same keys
/// and value types, so either side can read the other's.
fn info_to_msgpack(info: &InterfaceInfo) -> rmpv::Value {
    use rmpv::Value as V;
    let text = |s: &str| V::String(s.into());
    let float = |v: Option<f64>| v.map(V::F64).unwrap_or(V::Nil);
    let mut map = vec![
        (text("type"), text(&info.interface_type)),
        (text("transport"), V::Boolean(info.transport)),
        (text("name"), text(&info.name)),
        (text("received"), V::F64(info.received)),
        (text("stamp"), V::Binary(info.stamp.clone())),
        (text("value"), V::from(info.value)),
        (text("transport_id"), text(&info.transport_id)),
        (text("network_id"), text(&info.network_id)),
        (text("hops"), V::from(info.hops)),
        (text("latitude"), float(info.latitude)),
        (text("longitude"), float(info.longitude)),
        (text("height"), float(info.height)),
    ];
    let optional = [
        ("ifac_netname", info.ifac_netname.as_deref().map(text)),
        ("ifac_netkey", info.ifac_netkey.as_deref().map(text)),
        ("reachable_on", info.reachable_on.as_deref().map(text)),
        ("port", info.port.map(V::from)),
        ("frequency", info.frequency.map(V::from)),
        ("bandwidth", info.bandwidth.map(V::from)),
        ("sf", info.sf.map(V::from)),
        ("cr", info.cr.map(V::from)),
        ("channel", info.channel.map(V::from)),
        ("modulation", info.modulation.as_deref().map(text)),
        ("config_entry", info.config_entry.as_deref().map(text)),
        ("discovery_hash", info.discovery_hash.clone().map(V::Binary)),
        ("operator_lxmf_address", info.operator_lxmf_address.as_deref().map(text)),
        ("discovered", info.discovered.map(V::F64)),
        ("last_heard", info.last_heard.map(V::F64)),
        ("heard_count", info.heard_count.map(V::from)),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            map.push((text(key), value));
        }
    }
    V::Map(map)
}

fn info_from_msgpack(value: &rmpv::Value) -> Result<InterfaceInfo, String> {
    let map = value.as_map().ok_or("not a map")?;
    let get = |key: &str| map.iter().rev().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v);
    let text = |key: &str| get(key).and_then(|v| v.as_str()).map(String::from);
    let float = |key: &str| get(key).and_then(|v| v.as_f64());
    let int = |key: &str| get(key).and_then(|v| v.as_u64());
    let bytes = |key: &str| match get(key) {
        Some(rmpv::Value::Binary(b)) => Some(b.clone()),
        _ => None,
    };
    Ok(InterfaceInfo {
        interface_type: text("type").unwrap_or_default(),
        transport: get("transport").and_then(|v| v.as_bool()).ok_or("no transport field")?,
        name: text("name").ok_or("no name field")?,
        received: float("received").unwrap_or(0.0),
        stamp: bytes("stamp").unwrap_or_default(),
        value: int("value").and_then(|v| u32::try_from(v).ok()).ok_or("no value field")?,
        transport_id: text("transport_id").unwrap_or_default(),
        network_id: text("network_id").unwrap_or_default(),
        hops: int("hops").and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
        latitude: float("latitude"),
        longitude: float("longitude"),
        height: float("height"),
        reachable_on: text("reachable_on"),
        port: int("port").and_then(|v| u16::try_from(v).ok()),
        ifac_netname: text("ifac_netname"),
        ifac_netkey: text("ifac_netkey"),
        frequency: int("frequency"),
        bandwidth: int("bandwidth").and_then(|v| u32::try_from(v).ok()),
        sf: int("sf").and_then(|v| u8::try_from(v).ok()),
        cr: int("cr").and_then(|v| u8::try_from(v).ok()),
        channel: int("channel").and_then(|v| u8::try_from(v).ok()),
        modulation: text("modulation"),
        config_entry: text("config_entry"),
        discovery_hash: bytes("discovery_hash"),
        operator_lxmf_address: text("operator_lxmf_address"),
        discovered: float("discovered"),
        last_heard: Some(float("last_heard").ok_or("no last_heard field")?),
        heard_count: int("heard_count").and_then(|v| u32::try_from(v).ok()),
        status: None,
        status_code: None,
    })
}

fn read_info(path: &Path) -> Result<InterfaceInfo, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let value = rmpv::decode::read_value(&mut &data[..]).map_err(|e| e.to_string())?;
    info_from_msgpack(&value)
}

/// Written beside the entry and renamed over it, so a reader never sees half
/// an entry. The listing skips the `.tmp` names.
fn write_info(path: &Path, info: &InterfaceInfo) -> Result<(), String> {
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &info_to_msgpack(info)).map_err(|e| e.to_string())?;
    let partial = path.with_extension("tmp");
    std::fs::write(&partial, &data).map_err(|e| e.to_string())?;
    std::fs::rename(&partial, path).map_err(|e| e.to_string())
}

/// One auto-connected interface. The reference keeps these facts on the
/// interface object (`autoconnect_hash`, `autoconnect_source`,
/// `autoconnect_down`) and the object in `monitored_interfaces`.
struct Autoconnected {
    name: String,
    repr: String,
    endpoint_hash: Vec<u8>,
    interface: Arc<Mutex<TcpClientInterface>>,
    down_since: Option<f64>,
}

#[derive(Default)]
struct Autoconnects {
    monitored: Vec<Autoconnected>,
    /// Endpoints being dialled, with the names they will take. They count
    /// as auto-connected, so two dials running at once cannot both pass the
    /// limit or take one name.
    dialling: Vec<(Vec<u8>, String)>,
}

/// What a pass of the monitor saw of one auto-connected interface.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Watch {
    Online,
    Reconnected,
    Disconnected,
    Down,
    Detach,
}

/// One pass of RNS/Discovery.py `__monitor_job`, decided before anything is
/// done about it.
#[derive(Debug, PartialEq)]
struct MonitorPass {
    watches: Vec<Watch>,
    online: usize,
    teardown_bootstrap: bool,
    restore_bootstrap: bool,
    connect_candidate: bool,
}

/// `seen` holds, per monitored interface, whether it is online and when it
/// was first seen down (`autoconnect_down`). `autoconnected` is the count
/// taken at the start of the pass, as the reference takes it.
fn plan_monitor_pass(
    seen: &[(bool, Option<f64>)],
    now: f64,
    detach_threshold: f64,
    max_autoconnected: usize,
    autoconnected: usize,
    bootstrap_interfaces: usize,
    initial_autoconnect_ran: bool,
) -> MonitorPass {
    let watches: Vec<Watch> = seen
        .iter()
        .map(|&(online, down_since)| match (online, down_since) {
            (true, Some(_)) => Watch::Reconnected,
            (true, None) => Watch::Online,
            (false, None) => Watch::Disconnected,
            (false, Some(down)) if now - down >= detach_threshold => Watch::Detach,
            (false, Some(_)) => Watch::Down,
        })
        .collect();
    let online = seen.iter().filter(|(online, _)| *online).count();
    let free_slots = max_autoconnected.saturating_sub(autoconnected);
    let reserved_slots = max_autoconnected / 4;
    MonitorPass {
        watches,
        online,
        teardown_bootstrap: online >= max_autoconnected,
        restore_bootstrap: online == 0 && bootstrap_interfaces == 0,
        connect_candidate: initial_autoconnect_ran && free_slots > reserved_slots,
    }
}

/// Detach a client if its lock is free now. A writer blocked on a dead
/// socket holds the lock; the caller tries again on its next pass rather
/// than wait on it.
fn try_detach(interface: &Arc<Mutex<TcpClientInterface>>) -> bool {
    match interface.try_lock() {
        Ok(mut client) => {
            client.detach();
            true
        }
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            let mut client = poisoned.into_inner();
            client.detach();
            true
        }
        Err(std::sync::TryLockError::WouldBlock) => false,
    }
}

/// Manages discovered interfaces
///
/// Only `Transport::discover_interfaces` starts one listening: it registers
/// the announce handler and starts `connect_discovered`, which the
/// reference's constructor does when `discover_interfaces` is set. Never
/// call into an `InterfaceDiscovery` while holding the TRANSPORT lock: it
/// takes its own lock and then Transport's.
pub struct InterfaceDiscovery {
    pub required_value: u32,
    pub discovery_callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>,
    pub storagepath: PathBuf,
    pub monitor_interval: Duration,
    pub detach_threshold: Duration,
    initial_autoconnect_ran: AtomicBool,
    monitoring_autoconnects: AtomicBool,
    stopped: AtomicBool,
    autoconnects: Mutex<Autoconnects>,
    blackholed: Mutex<Option<(Instant, HashSet<Vec<u8>>)>>,
}

impl InterfaceDiscovery {
    pub const THRESHOLD_UNKNOWN: u64 = 24 * 60 * 60;  // 1 day
    pub const THRESHOLD_STALE: u64 = 3 * 24 * 60 * 60;  // 3 days
    pub const THRESHOLD_REMOVE: u64 = 7 * 24 * 60 * 60;  // 7 days

    pub const MONITOR_INTERVAL: u64 = 5;
    /// Seconds, as the reference compares it: an auto-connected interface
    /// down this long is detached at the next pass of the monitor.
    pub const DETACH_THRESHOLD: u64 = 12;

    pub const STATUS_STALE: u32 = 0;
    pub const STATUS_UNKNOWN: u32 = 100;
    pub const STATUS_AVAILABLE: u32 = 1000;

    pub const AUTOCONNECT_TYPES: &'static [&'static str] = &[
        "BackboneInterface",
        "TCPServerInterface",
    ];

    pub const DISCOVERABLE_TYPES: &'static [&'static str] = &[
        "BackboneInterface",
        "TCPServerInterface",
        "I2PInterface",
        "RNodeInterface",
        "WeaveInterface",
        "KISSInterface",
    ];

    /// The reference's AC_TRANSPORT_MODE, its `configured_bitrate` for an
    /// auto-connected interface, and Interface.DEFAULT_AR_* (RNS 1.5.2).
    const AC_TRANSPORT_MODE: InterfaceMode = InterfaceMode::Gateway;
    const AC_BITRATE: u64 = 5_000_000;
    const DEFAULT_AR_TARGET: f64 = 3600.0;
    const DEFAULT_AR_PENALTY: f64 = 0.0;
    const DEFAULT_AR_GRACE: f64 = 5.0;
    const DEFAULT_IFAC_SIZE: usize = 16;
    const BLACKHOLED_REFRESH: Duration = Duration::from_secs(60);

    pub fn new(
        required_value: Option<u32>,
        callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>,
    ) -> Result<Self, String> {
        let storagepath = crate::reticulum::storage_path().join("discovery").join("interfaces");
        Self::with_storagepath(required_value, callback, storagepath)
    }

    fn with_storagepath(
        required_value: Option<u32>,
        callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>,
        storagepath: PathBuf,
    ) -> Result<Self, String> {
        let required_value = required_value.unwrap_or(InterfaceAnnouncer::DEFAULT_STAMP_VALUE);

        if !storagepath.exists() {
            std::fs::create_dir_all(&storagepath)
                .map_err(|e| format!("Failed to create discovery storage path: {}", e))?;
        }

        Ok(Self {
            required_value,
            discovery_callback: callback,
            storagepath,
            monitor_interval: Duration::from_secs(Self::MONITOR_INTERVAL),
            detach_threshold: Duration::from_secs(Self::DETACH_THRESHOLD),
            initial_autoconnect_ran: AtomicBool::new(false),
            monitoring_autoconnects: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            autoconnects: Mutex::new(Autoconnects::default()),
            blackholed: Mutex::new(None),
        })
    }

    fn blackholed_identities(&self) -> HashSet<Vec<u8>> {
        let mut cache = self.blackholed.lock().unwrap();
        let stale = match cache.as_ref() {
            Some((updated, identities)) => identities.is_empty() || updated.elapsed() > Self::BLACKHOLED_REFRESH,
            None => true,
        };
        if stale {
            *cache = Some((Instant::now(), crate::transport::Transport::blackholed_identity_hashes()));
        }
        cache.as_ref().map(|(_, identities)| identities.clone()).unwrap_or_default()
    }

    /// List all discovered interfaces
    pub fn list_discovered_interfaces(&self, only_available: bool, only_transport: bool) -> Vec<InterfaceInfo> {
        let now = now();
        let mut discovered_interfaces = Vec::new();
        let discovery_sources = crate::reticulum::interface_discovery_sources();
        let blackholed_identities = self.blackholed_identities();
        let entries = match std::fs::read_dir(&self.storagepath) {
            Ok(entries) => entries,
            Err(e) => {
                log(&format!("Could not list discovered interfaces in {:?}: {}", self.storagepath, e), LOG_WARNING, false, false);
                return discovered_interfaces;
            }
        };

        for entry in entries.flatten() {
            let filepath = entry.path();
            if filepath.extension().map_or(false, |ext| ext == "tmp") {
                continue;
            }
            let loaded = {
                let _lock = DISCOVERY_LOCK.lock().unwrap();
                read_info(&filepath)
            };
            // The checks run in the reference's order, and its hex decoding
            // fails where it would, so a bad entry is kept or removed as there.
            let checked = loaded.and_then(|mut info| {
                let heard_delta = now - info.last_heard.unwrap_or(0.0);
                info.name = InterfaceAnnounceHandler::sanitize_name(&info.name).unwrap_or_default();
                let not_hex = |field: &str| format!("{} is not hex", field);
                let should_remove = if heard_delta > Self::THRESHOLD_REMOVE as f64
                    || info.transport_id.is_empty()
                    || info.network_id.is_empty()
                {
                    true
                } else if !discovery_sources.is_empty()
                    && !discovery_sources.contains(&hex_decode(&info.network_id).ok_or_else(|| not_hex("network_id"))?)
                {
                    true
                } else if !Self::DISCOVERABLE_TYPES.contains(&info.interface_type.as_str())
                    || blackholed_identities.contains(&hex_decode(&info.network_id).ok_or_else(|| not_hex("network_id"))?)
                    || blackholed_identities.contains(&hex_decode(&info.transport_id).ok_or_else(|| not_hex("transport_id"))?)
                {
                    true
                } else {
                    info.reachable_on.as_deref().map_or(false, |r| !(is_ip_address(r) || is_hostname(r)))
                };
                Ok((info, heard_delta, should_remove))
            });
            let (mut info, heard_delta) = match checked {
                Ok((_, _, true)) => {
                    let _ = std::fs::remove_file(&filepath);
                    continue;
                }
                Ok((info, heard_delta, false)) => (info, heard_delta),
                Err(e) => {
                    log(&format!("Error while loading discovered interface data: {}", e), LOG_WARNING, false, false);
                    log(&format!("The interface data file {:?} may be corrupt", filepath), LOG_WARNING, false, false);
                    continue;
                }
            };

            let (status, status_code) = if heard_delta > Self::THRESHOLD_STALE as f64 {
                ("stale", Self::STATUS_STALE)
            } else if heard_delta > Self::THRESHOLD_UNKNOWN as f64 {
                ("unknown", Self::STATUS_UNKNOWN)
            } else {
                ("available", Self::STATUS_AVAILABLE)
            };
            info.status = Some(status.to_string());
            info.status_code = Some(status_code);

            if only_available && status != "available" {
                continue;
            }
            if only_transport && !info.transport {
                continue;
            }
            discovered_interfaces.push(info);
        }

        // Sort by status_code, value, last_heard (descending)
        discovered_interfaces.sort_by(|a: &InterfaceInfo, b: &InterfaceInfo| {
            b.status_code.unwrap_or(0).cmp(&a.status_code.unwrap_or(0))
                .then(b.value.cmp(&a.value))
                .then(b.last_heard.unwrap_or(0.0).total_cmp(&a.last_heard.unwrap_or(0.0)))
        });

        discovered_interfaces
    }

    /// Handle a newly discovered interface
    pub fn interface_discovered(self: &Arc<Self>, mut info: InterfaceInfo) {
        if !Self::DISCOVERABLE_TYPES.contains(&info.interface_type.as_str()) {
            return;
        }
        let discovery_hash = match info.discovery_hash.clone() {
            Some(hash) => hash,
            None => {
                log("Error processing discovered interface data: it has no discovery hash", LOG_ERROR, false, false);
                return;
            }
        };
        let ms = if info.hops == 1 { "" } else { "s" };
        log(&format!("Discovered {} {} hop{} away with stamp value {}: {}",
            info.interface_type, info.hops, ms, info.value, info.name), LOG_DEBUG, false, false);

        let filepath = self.storagepath.join(crate::hexrep(&discovery_hash, false));
        {
            let _lock = DISCOVERY_LOCK.lock().unwrap();
            if !filepath.is_file() {
                info.discovered = Some(info.received);
                info.last_heard = Some(info.received);
                info.heard_count = Some(0);
            } else {
                // The reference reads `discovered`, then `heard_count`, and
                // keeps whichever it got before a read failed.
                let (discovered, heard_count) = match read_info(&filepath) {
                    Ok(last) => (last.discovered, last.discovered.and(last.heard_count)),
                    Err(_) => (None, None),
                };
                if heard_count.is_none() {
                    log("Error while reading existing data for discovered interface, re-creating data", LOG_ERROR, false, false);
                }
                info.discovered = Some(discovered.unwrap_or(info.received));
                info.last_heard = Some(info.received);
                info.heard_count = Some(heard_count.unwrap_or(0) + 1);
            }
            if let Err(e) = write_info(&filepath, &info) {
                log(&format!("Error while persisting discovered interface data: {}", e), LOG_ERROR, false, false);
                return;
            }
        }

        self.autoconnect(&info);

        if let Some(callback) = self.discovery_callback.as_ref() {
            callback(info);
        }
    }

    /// Start the monitor, once (the reference's `monitor_interface`, whose
    /// other half, adding to the monitored list, `autoconnect` does).
    fn monitor_interface(self: &Arc<Self>) {
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        if self.monitoring_autoconnects
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let discovery = Arc::clone(self);
            let started = thread::Builder::new()
                .name("discovery_monitor".to_string())
                .spawn(move || discovery.monitor_job());
            if let Err(e) = started {
                self.monitoring_autoconnects.store(false, Ordering::SeqCst);
                log(&format!("Could not start the auto-connect monitor: {}", e), LOG_ERROR, false, false);
            }
        }
    }

    fn monitor_job(self: Arc<Self>) {
        while self.monitoring_autoconnects.load(Ordering::SeqCst) {
            thread::sleep(self.monitor_interval);
            if !self.monitoring_autoconnects.load(Ordering::SeqCst) {
                break;
            }
            self.monitor_pass();
        }
    }

    fn monitor_pass(self: &Arc<Self>) {
        let now = now();
        let online_names: HashSet<String> = crate::transport::Transport::online_interface_names().into_iter().collect();
        let bootstrap = crate::transport::Transport::bootstrap_interfaces();
        let max_autoconnected = crate::reticulum::max_autoconnected_interfaces();

        let (pass, detached) = {
            let mut autoconnects = self.autoconnects.lock().unwrap();
            let autoconnected = autoconnects.monitored.len() + autoconnects.dialling.len();
            let seen: Vec<(bool, Option<f64>)> = autoconnects.monitored
                .iter()
                .map(|entry| (online_names.contains(&entry.name), entry.down_since))
                .collect();
            let pass = plan_monitor_pass(
                &seen,
                now,
                self.detach_threshold.as_secs_f64(),
                max_autoconnected,
                autoconnected,
                bootstrap.len(),
                self.initial_autoconnect_ran.load(Ordering::SeqCst),
            );
            let mut detached = Vec::new();
            for (entry, watch) in autoconnects.monitored.iter_mut().zip(&pass.watches) {
                match watch {
                    Watch::Reconnected => {
                        log(&format!("Auto-discovered interface {} reconnected", entry.repr), LOG_NOTICE, false, false);
                        entry.down_since = None;
                    }
                    Watch::Disconnected => {
                        log(&format!("Auto-discovered interface {} disconnected", entry.repr), LOG_DEBUG, false, false);
                        entry.down_since = Some(now);
                    }
                    Watch::Detach => {
                        let down_for = now - entry.down_since.unwrap_or(now);
                        log(&format!("Auto-discovered interface {} has been down for {}, detaching",
                            entry.repr, crate::prettytime(down_for, false, false)), LOG_DEBUG, false, false);
                        detached.push(entry.name.clone());
                    }
                    Watch::Online | Watch::Down => {}
                }
            }
            (pass, detached)
        };

        if pass.teardown_bootstrap {
            for (_, repr) in &bootstrap {
                log(&format!("Tearing down bootstrap-only {} since target connected auto-discovered interface count has been reached", repr),
                    LOG_INFO, false, false);
            }
        }

        if pass.restore_bootstrap {
            log("No auto-discovered interfaces connected, re-enabling bootstrap interfaces", LOG_NOTICE, false, false);
            crate::reticulum::Reticulum::restore_bootstrap_interfaces();
        }

        if pass.connect_candidate {
            let candidate_interfaces = self.list_discovered_interfaces(true, true);
            if let Some(selected_interface) = candidate_interfaces.choose(&mut rand::thread_rng()) {
                if !self.interface_exists(selected_interface) {
                    self.autoconnect(selected_interface);
                }
            }
        }

        for name in detached {
            self.teardown_interface(&name);
        }

        if pass.teardown_bootstrap {
            let names: Vec<String> = bootstrap.into_iter().map(|(name, _)| name).collect();
            for name in crate::reticulum::Reticulum::teardown_interfaces(&names) {
                log(&format!("Bootstrap-only interface {} could not be torn down on this pass", name), LOG_DEBUG, false, false);
            }
        }
    }

    /// Detach an auto-connected interface and remove it from Transport. If
    /// its writer holds it, nothing changes and the next pass tries again.
    pub fn teardown_interface(&self, interface_name: &str) {
        let mut autoconnects = self.autoconnects.lock().unwrap();
        let position = match autoconnects.monitored.iter().position(|entry| entry.name == interface_name) {
            Some(position) => position,
            None => return,
        };
        if !try_detach(&autoconnects.monitored[position].interface) {
            log(&format!("Auto-discovered interface {} is busy, detaching on the next pass",
                autoconnects.monitored[position].repr), LOG_DEBUG, false, false);
            return;
        }
        let entry = autoconnects.monitored.remove(position);
        drop(autoconnects);
        crate::transport::Transport::unregister_outbound_handler(&entry.name);
        crate::transport::Transport::deregister_interface_stub(&entry.name);
    }

    /// Sanitize strings by removing newlines and carriage returns
    pub fn sanitize(&self, in_str: &str) -> String {
        in_str
            .replace('\n', "")
            .replace('\r', "")
            .trim()
            .to_string()
    }

    /// Compute endpoint hash from reachable_on and port
    pub fn endpoint_hash(&self, info: &InterfaceInfo) -> Vec<u8> {
        let mut endpoint_specifier = String::new();
        if let Some(ref reachable_on) = info.reachable_on {
            endpoint_specifier.push_str(reachable_on);
        }
        if let Some(port) = info.port {
            endpoint_specifier.push_str(&format!(":{}", port));
        }
        identity::full_hash(endpoint_specifier.as_bytes())
    }

    /// Check if an interface with the given info already exists
    pub fn interface_exists(&self, info: &InterfaceInfo) -> bool {
        let endpoint_hash = self.endpoint_hash(info);
        let autoconnects = self.autoconnects.lock().unwrap();
        Self::exists_in(&autoconnects, info, &endpoint_hash)
    }

    /// An auto-connected interface on this endpoint, one being dialled, or
    /// any interface whose target is the announced address and port.
    fn exists_in(autoconnects: &Autoconnects, info: &InterfaceInfo, endpoint_hash: &[u8]) -> bool {
        if autoconnects.monitored.iter().any(|entry| entry.endpoint_hash == endpoint_hash)
            || autoconnects.dialling.iter().any(|(dialling, _)| dialling.as_slice() == endpoint_hash)
        {
            return true;
        }
        match info.reachable_on.as_deref() {
            Some(address) => crate::transport::Transport::has_interface_endpoint(address, info.port),
            None => false,
        }
    }

    /// Count currently autoconnected interfaces
    pub fn autoconnect_count(&self) -> usize {
        let autoconnects = self.autoconnects.lock().unwrap();
        autoconnects.monitored.len() + autoconnects.dialling.len()
    }

    /// Count bootstrap-only interfaces
    pub fn bootstrap_interface_count(&self) -> usize {
        crate::transport::Transport::bootstrap_interfaces().len()
    }

    /// Connect to all eligible discovered interfaces
    pub fn connect_discovered(self: &Arc<Self>) {
        if crate::reticulum::should_autoconnect_discovered_interfaces() {
            let discovered_interfaces = self.list_discovered_interfaces(false, true);
            for info in &discovered_interfaces {
                if self.autoconnect_count() >= crate::reticulum::max_autoconnected_interfaces() {
                    break;
                }
                self.autoconnect(info);
            }
            self.initial_autoconnect_ran.store(true, Ordering::SeqCst);
        }
    }

    /// Autoconnect to a specific discovered interface
    pub fn autoconnect(self: &Arc<Self>, info: &InterfaceInfo) {
        if let Err(e) = self.try_autoconnect(info) {
            log(&format!("Error while auto-connecting discovered interface: {}", e), LOG_ERROR, false, false);
        }
    }

    fn try_autoconnect(self: &Arc<Self>, info: &InterfaceInfo) -> Result<(), String> {
        if self.stopped.load(Ordering::SeqCst) || !crate::reticulum::should_autoconnect_discovered_interfaces() {
            return Ok(());
        }
        let interface_type = info.interface_type.as_str();
        let endpoint_hash = self.endpoint_hash(info);
        let (name, address, port) = {
            let mut autoconnects = self.autoconnects.lock().unwrap();
            if autoconnects.monitored.len() + autoconnects.dialling.len() >= crate::reticulum::max_autoconnected_interfaces() {
                return Ok(());
            }
            if !Self::AUTOCONNECT_TYPES.contains(&interface_type) {
                return Ok(());
            }
            if Self::exists_in(&autoconnects, info, &endpoint_hash) {
                log(&format!("Discovered {} already exists, not auto-connecting", interface_type), LOG_DEBUG, false, false);
                return Ok(());
            }
            let address = info.reachable_on.clone().ok_or("the discovered interface has no reachable_on")?;
            if is_ygg_ipv6(&address) || is_onion_address(&address) {
                return Ok(());
            }
            if is_ip_address(&address) && is_invalid_ip_address(&address) {
                log(&format!("Not auto-connecting discovered interface with invalid IP address: {}", address), LOG_DEBUG, false, false);
                return Ok(());
            }
            // The reference lists TCPServerInterface as auto-connectable but
            // creates an interface only for a BackboneInterface.
            if interface_type != "BackboneInterface" {
                return Ok(());
            }
            let port = info.port.ok_or("the discovered interface has no port")?;
            let name = Self::unique_interface_name(&autoconnects, &info.name, &address, port);
            autoconnects.dialling.push((endpoint_hash.clone(), name.clone()));
            (name, address, port)
        };

        let connected = self.connect_backbone(info, &name, &address, port, &endpoint_hash);
        let mut autoconnects = self.autoconnects.lock().unwrap();
        autoconnects.dialling.retain(|(dialling, _)| *dialling != endpoint_hash);
        let entry = connected?;
        if self.stopped.load(Ordering::SeqCst) {
            drop(autoconnects);
            if let Ok(mut client) = entry.interface.lock() {
                client.detach();
            }
            crate::transport::Transport::unregister_outbound_handler(&entry.name);
            crate::transport::Transport::deregister_interface_stub(&entry.name);
            return Ok(());
        }
        autoconnects.monitored.push(entry);
        drop(autoconnects);
        self.monitor_interface();
        Ok(())
    }

    /// The reference creates a BackboneClientInterface here. This port's
    /// TCPClientInterface is the same connection on the wire (HDLC framing
    /// over TCP), and like the reference's client, and unlike this port's
    /// BackboneClientInterface, it exists offline when its first dial fails,
    /// so the monitor can detach it.
    fn connect_backbone(&self, info: &InterfaceInfo, name: &str, address: &str, port: u16, endpoint_hash: &[u8]) -> Result<Autoconnected, String> {
        let mut config = HashMap::new();
        config.insert("name".to_string(), name.to_string());
        config.insert("target_host".to_string(), address.to_string());
        config.insert("target_port".to_string(), port.to_string());
        let interface = TcpClientInterface::new(&config)?;
        log(&format!("Auto-connecting discovered {} {}", info.interface_type, name), LOG_NOTICE, false, false);

        let transport_enabled = crate::reticulum::transport_enabled();
        let mode = crate::reticulum::autoconnect_interface_mode().unwrap_or(if transport_enabled {
            Self::AC_TRANSPORT_MODE
        } else {
            InterfaceMode::Full
        });
        let mut stub = crate::transport::InterfaceStubConfig::default();
        stub.name = name.to_string();
        stub.address = Some(address.to_string());
        stub.port = Some(port);
        stub.mode = crate::reticulum::interface_mode_to_stub(mode);
        stub.out = true;
        stub.bitrate = Some(Self::AC_BITRATE);
        stub.announce_cap = Some(crate::reticulum::ANNOUNCE_CAP / 100.0);
        if transport_enabled {
            stub.announce_rate_target = Some(Self::DEFAULT_AR_TARGET);
            stub.announce_rate_grace = Some(Self::DEFAULT_AR_GRACE);
            stub.announce_rate_penalty = Some(Self::DEFAULT_AR_PENALTY);
        }
        stub.ifac_size = Some(Self::DEFAULT_IFAC_SIZE);
        let (ifac_key, ifac_signature) = crate::reticulum::derive_ifac_material(
            info.ifac_netname.as_deref(),
            info.ifac_netkey.as_deref(),
        );
        stub.ifac_netname = info.ifac_netname.clone();
        stub.ifac_netkey = info.ifac_netkey.clone();
        stub.ifac_key = ifac_key;
        stub.ifac_signature = ifac_signature;

        let repr = interface.to_string();
        let interface = crate::reticulum::Reticulum::start_tcp_client(interface, mode, stub);
        Ok(Autoconnected {
            name: name.to_string(),
            repr,
            endpoint_hash: endpoint_hash.to_vec(),
            interface,
            down_since: None,
        })
    }

    /// Transport knows interfaces by name, and discovered names repeat
    /// ("Discovered BackboneInterface" for every unnamed one), so a taken name
    /// gets its endpoint added. No two dials share an endpoint, so that is unique.
    fn unique_interface_name(autoconnects: &Autoconnects, name: &str, address: &str, port: u16) -> String {
        let taken = crate::transport::Transport::interface_registered(name)
            || autoconnects.monitored.iter().any(|entry| entry.name == name)
            || autoconnects.dialling.iter().any(|(_, dialling)| dialling == name);
        if taken {
            format!("{} [{}:{}]", name, address, port)
        } else {
            name.to_string()
        }
    }

    /// Stop the monitor and detach every auto-connected interface (shutdown).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.monitoring_autoconnects.store(false, Ordering::SeqCst);
        let monitored = std::mem::take(&mut self.autoconnects.lock().unwrap().monitored);
        for entry in monitored {
            if let Ok(mut client) = entry.interface.lock() {
                client.detach();
            }
            crate::transport::Transport::unregister_outbound_handler(&entry.name);
            crate::transport::Transport::deregister_interface_stub(&entry.name);
        }
    }
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| hex.get(i..i + 2).and_then(|pair| u8::from_str_radix(pair, 16).ok()))
        .collect()
}

/// Updates blackhole lists from trusted sources
pub struct BlackholeUpdater {
    pub last_updates: Arc<Mutex<HashMap<Vec<u8>, f64>>>,
    pub should_run: Arc<Mutex<bool>>,
    pub job_interval: Duration,
}

impl BlackholeUpdater {
    pub const INITIAL_WAIT: u64 = 20;
    pub const JOB_INTERVAL: u64 = 60;
    pub const UPDATE_INTERVAL: u64 = 1 * 60 * 60;  // 1 hour
    pub const SOURCE_TIMEOUT: u64 = 25;
    
    pub fn new() -> Self {
        Self {
            last_updates: Arc::new(Mutex::new(HashMap::new())),
            should_run: Arc::new(Mutex::new(false)),
            job_interval: Duration::from_secs(Self::JOB_INTERVAL),
        }
    }
    
    /// Start the blackhole updater
    pub fn start(&self) {
        let mut should_run = self.should_run.lock().unwrap();
        if !*should_run {
            *should_run = true;
            drop(should_run);
            
            log("Starting blackhole updater", LOG_DEBUG, false, false);
            
            let should_run_clone = Arc::clone(&self.should_run);
            let job_interval = self.job_interval;
            let last_updates_clone = Arc::clone(&self.last_updates);
            
            thread::spawn(move || {
                Self::job(should_run_clone, job_interval, last_updates_clone);
            });
        }
    }
    
    /// Stop the blackhole updater
    pub fn stop(&self) {
        let mut should_run = self.should_run.lock().unwrap();
        *should_run = false;
    }

    /// Called when a link is established to a blackhole source
    pub fn update_link_established(&self, _link: &crate::link::Link) {
        log("Blackhole list update link established (stub)", LOG_DEBUG, false, false);
        // Would:
        // 1. Get remote identity from link
        // 2. Request "/list" from link
        // 3. Parse response as blackhole list
        // 4. Add new identities to Transport.blackholed_identities
        // 5. Persist to disk
        // 6. Teardown link
    }
    
    fn job(should_run: Arc<Mutex<bool>>, job_interval: Duration, _last_updates: Arc<Mutex<HashMap<Vec<u8>, f64>>>) {
        thread::sleep(Duration::from_secs(Self::INITIAL_WAIT));
        
        while *should_run.lock().unwrap() {
            // Check for blackhole list updates
            log("Blackhole updater job tick (stub)", LOG_DEBUG, false, false);
            
            thread::sleep(job_interval);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicUsize;

    /// Announces, stored entries and helper answers from RNS's own
    /// Discovery.py, written by tests/fixtures/discovery_vectors.py.
    const VECTORS: &str = include_str!("../tests/fixtures/discovery_vectors.json");

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn unhex(value: &Value) -> Vec<u8> {
        hex_decode(value.as_str().unwrap()).unwrap()
    }

    fn scratch_dir(label: &str) -> PathBuf {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "rns-discovery-test-{}-{}-{}", std::process::id(), label, COUNT.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An info in the fixture's form: bytes as {"hex": ...}, no `received`.
    fn as_fixture(info: &InterfaceInfo) -> Value {
        let mut value = serde_json::to_value(info).unwrap();
        let map = value.as_object_mut().unwrap();
        map.remove("received");
        map.insert("stamp".into(), json!({"hex": crate::hexrep(&info.stamp, false)}));
        if let Some(hash) = &info.discovery_hash {
            map.insert("discovery_hash".into(), json!({"hex": crate::hexrep(hash, false)}));
        }
        value
    }

    /// The reference writes a BackboneInterface entry where it supports one
    /// (not on Windows or macOS), a TCPClientInterface entry elsewhere.
    fn config_entry_here(entry: &str, generated_with_backbone: bool) -> String {
        let backbone_here = !cfg!(any(target_os = "windows", target_os = "macos"));
        let client = ("type = TCPClientInterface", "  target_host = ");
        let backbone = ("type = BackboneInterface", "  remote = ");
        let (from, to) = match (generated_with_backbone, backbone_here) {
            (false, true) => (client, backbone),
            (true, false) => (backbone, client),
            _ => return entry.to_string(),
        };
        entry.replace(from.0, to.0).replace(from.1, to.1)
    }

    fn collecting_handler() -> (InterfaceAnnounceHandler, Arc<Mutex<Vec<InterfaceInfo>>>) {
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let handler = InterfaceAnnounceHandler::new(None, Some(Box::new(move |info| sink.lock().unwrap().push(info))));
        (handler, received)
    }

    fn network_identity(vectors: &Value) -> Identity {
        let identity = Identity::from_public_key(&unhex(&vectors["network_identity_public_key"])).unwrap();
        assert_eq!(crate::hexrep(identity.hash.as_ref().unwrap(), false), vectors["network_id"]);
        identity
    }

    fn announce<'a>(vectors: &'a Value, label: &str) -> &'a Value {
        vectors["announces"].as_array().unwrap().iter().find(|a| a["label"] == label).unwrap()
    }

    #[test]
    fn names_are_sanitized_as_the_reference_does() {
        for case in vectors()["sanitize_name"].as_array().unwrap() {
            let name = case[0].as_str().unwrap();
            let expected = case[1].as_str().map(String::from);
            assert_eq!(InterfaceAnnounceHandler::sanitize_name(name), expected, "sanitize_name({:?})", name);
        }
    }

    #[test]
    fn addresses_are_checked_as_the_reference_does() {
        for case in vectors()["hosts"].as_array().unwrap() {
            let host = case[0].as_str().unwrap();
            // null: the reference raised, and its handler drops the announce.
            assert_eq!(is_ip_address(host), case[1].as_bool().unwrap_or(false), "is_ip_address({:?})", host);
            assert_eq!(is_hostname(host), case[2].as_bool().unwrap_or(false), "is_hostname({:?})", host);
        }
    }

    #[test]
    fn announces_decode_as_the_reference_decodes_them() {
        let vectors = vectors();
        let identity = network_identity(&vectors);
        let destination_hash = unhex(&vectors["destination_hash"]);
        let generated_with_backbone = vectors["backbone_support"].as_bool().unwrap();

        for announce in vectors["announces"].as_array().unwrap() {
            let label = announce["label"].as_str().unwrap();
            let (handler, received) = collecting_handler();
            handler.received_announce(&destination_hash, &identity, &unhex(&announce["app_data"]));
            let received = received.lock().unwrap();

            let mut expected = announce["expected"].clone();
            if expected.is_null() {
                assert!(received.is_empty(), "{}: the reference drops this announce", label);
                continue;
            }
            assert_eq!(received.len(), 1, "{}: the reference accepts this announce", label);
            let info = &received[0];

            // This port's Transport answers an unknown path with a different
            // hop count than the reference (no path is known here). A received
            // announce always has its path, so hold the field to Transport.
            assert_eq!(info.hops, crate::transport::Transport::hops_to(&destination_hash) as u32, "{}", label);
            expected["hops"] = json!(info.hops);
            if let Some(entry) = expected["config_entry"].as_str() {
                expected["config_entry"] = json!(config_entry_here(entry, generated_with_backbone));
            }
            assert_eq!(as_fixture(info), expected, "{}", label);
        }
    }

    #[test]
    fn repeated_announces_are_answered_from_the_caches() {
        let vectors = vectors();
        let identity = network_identity(&vectors);
        let destination_hash = unhex(&vectors["destination_hash"]);

        let (handler, received) = collecting_handler();
        let valid = unhex(&announce(&vectors, "backbone_hostname")["app_data"]);
        handler.received_announce(&destination_hash, &identity, &valid);
        handler.received_announce(&destination_hash, &identity, &valid);
        assert_eq!(received.lock().unwrap().len(), 2);
        assert_eq!(handler.valid_cache.lock().unwrap().entries.len(), 1);

        let low = unhex(&announce(&vectors, "low_stamp")["app_data"]);
        handler.received_announce(&destination_hash, &identity, &low);
        handler.received_announce(&destination_hash, &identity, &low);
        assert_eq!(received.lock().unwrap().len(), 2);
        assert_eq!(handler.invalid_cache.lock().unwrap().len(), 1);
    }

    #[test]
    fn the_valid_cache_drops_its_oldest_entry() {
        let mut cache = ValidCache::default();
        let check = StampCheck { valid: true, value: 16, packed: Vec::new(), stamp: Vec::new() };
        for i in 0..=InterfaceAnnounceHandler::VALID_CACHE_MAX as u32 {
            cache.insert(i.to_be_bytes().to_vec(), check.clone());
        }
        assert_eq!(cache.entries.len(), InterfaceAnnounceHandler::VALID_CACHE_MAX);
        assert!(!cache.entries.contains_key(&0u32.to_be_bytes().to_vec()));
        assert!(cache.entries.contains_key(&1u32.to_be_bytes().to_vec()));
    }

    #[test]
    fn entries_are_stored_as_the_reference_stores_them() {
        let vectors = vectors();
        let first = unhex(&vectors["stored"]["first_heard"]);
        let again = unhex(&vectors["stored"]["heard_again"]);

        // The reference's file reads back into the same bytes.
        let info = info_from_msgpack(&rmpv::decode::read_value(&mut &first[..]).unwrap()).unwrap();
        let mut written = Vec::new();
        rmpv::encode::write_value(&mut written, &info_to_msgpack(&info)).unwrap();
        assert_eq!(crate::hexrep(&written, false), crate::hexrep(&first, false));

        // Heard, then heard again a minute later: the files the reference wrote.
        let dir = scratch_dir("stored");
        let discovery = Arc::new(InterfaceDiscovery::with_storagepath(None, None, dir.clone()).unwrap());
        assert_eq!(crate::hexrep(&discovery.endpoint_hash(&info), false), vectors["stored"]["endpoint_hash"]);
        let mut heard = InterfaceInfo { discovered: None, last_heard: None, heard_count: None, ..info };
        let path = dir.join(crate::hexrep(heard.discovery_hash.as_ref().unwrap(), false));
        discovery.interface_discovered(heard.clone());
        assert_eq!(crate::hexrep(&std::fs::read(&path).unwrap(), false), crate::hexrep(&first, false));
        heard.received += 60.0;
        discovery.interface_discovered(heard);
        assert_eq!(crate::hexrep(&std::fs::read(&path).unwrap(), false), crate::hexrep(&again, false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn stored_entry(now: f64) -> InterfaceInfo {
        InterfaceInfo {
            interface_type: "BackboneInterface".to_string(),
            transport: true,
            name: "Entry".to_string(),
            received: now - 30.0,
            stamp: vec![0; 32],
            value: 16,
            transport_id: "11".repeat(16),
            network_id: "22".repeat(16),
            hops: 1,
            latitude: None,
            longitude: None,
            height: None,
            reachable_on: Some("198.51.100.1".to_string()),
            port: Some(4242),
            ifac_netname: None,
            ifac_netkey: None,
            frequency: None,
            bandwidth: None,
            sf: None,
            cr: None,
            channel: None,
            modulation: None,
            config_entry: None,
            discovery_hash: Some(vec![0x33; 32]),
            operator_lxmf_address: None,
            discovered: Some(now - 30.0),
            last_heard: Some(now - 30.0),
            heard_count: Some(0),
            status: None,
            status_code: None,
        }
    }

    #[test]
    fn listing_sorts_filters_and_removes_as_the_reference() {
        let dir = scratch_dir("listing");
        let discovery = InterfaceDiscovery::with_storagepath(None, None, dir.clone()).unwrap();
        let now = now();
        let day = 24.0 * 60.0 * 60.0;
        let base = stored_entry(now);
        let ago = |seconds: f64| Some(now - seconds);
        let entries = [
            ("a", InterfaceInfo { name: "Available 16".into(), last_heard: ago(60.0), ..base.clone() }),
            ("b", InterfaceInfo { name: "Available 20".into(), value: 20, last_heard: ago(120.0), ..base.clone() }),
            ("c", InterfaceInfo { name: "Available 16 newer".into(), last_heard: ago(10.0), ..base.clone() }),
            ("d", InterfaceInfo { name: "Unknown 30".into(), value: 30, last_heard: ago(2.0 * day), ..base.clone() }),
            ("e", InterfaceInfo { name: "Stale".into(), last_heard: ago(4.0 * day), ..base.clone() }),
            ("f", InterfaceInfo { name: "No transport".into(), transport: false, ..base.clone() }),
            // Removed, as the reference removes them.
            ("g", InterfaceInfo { name: "Too old".into(), last_heard: ago(8.0 * day), ..base.clone() }),
            ("h", InterfaceInfo { name: "Client".into(), interface_type: "TCPClientInterface".into(), ..base.clone() }),
            ("i", InterfaceInfo { name: "Bad host".into(), reachable_on: Some("not a host!".into()), ..base.clone() }),
            ("j", InterfaceInfo { name: "No transport id".into(), transport_id: String::new(), ..base.clone() }),
            ("k", InterfaceInfo { name: "Old bad hex".into(), network_id: "zz".into(), last_heard: ago(8.0 * day), ..base.clone() }),
            // Kept but never listed: the reference fails on its hex.
            ("l", InterfaceInfo { name: "Bad hex".into(), network_id: "zz".into(), ..base.clone() }),
        ];
        for (file, info) in &entries {
            write_info(&dir.join(file), info).unwrap();
        }
        std::fs::write(dir.join("m.tmp"), b"half an entry").unwrap();

        let names = |listed: Vec<InterfaceInfo>| listed.into_iter().map(|info| info.name).collect::<Vec<_>>();
        let listed = discovery.list_discovered_interfaces(false, false);
        let statuses: Vec<(Option<String>, Option<u32>)> =
            listed.iter().map(|info| (info.status.clone(), info.status_code)).collect();
        assert_eq!(names(listed),
                   ["Available 20", "Available 16 newer", "No transport", "Available 16", "Unknown 30", "Stale"]);
        let available = (Some("available".to_string()), Some(InterfaceDiscovery::STATUS_AVAILABLE));
        assert_eq!(statuses, [available.clone(), available.clone(), available.clone(), available,
                              (Some("unknown".to_string()), Some(InterfaceDiscovery::STATUS_UNKNOWN)),
                              (Some("stale".to_string()), Some(InterfaceDiscovery::STATUS_STALE))]);

        let mut left: Vec<String> = std::fs::read_dir(&dir).unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["a", "b", "c", "d", "e", "f", "l", "m.tmp"]);

        assert_eq!(names(discovery.list_discovered_interfaces(false, true)),
                   ["Available 20", "Available 16 newer", "Available 16", "Unknown 30", "Stale"]);
        assert_eq!(names(discovery.list_discovered_interfaces(true, true)),
                   ["Available 20", "Available 16 newer", "Available 16"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_heard_again_keeps_what_it_could_read() {
        let dir = scratch_dir("reheard");
        let discovery = Arc::new(InterfaceDiscovery::with_storagepath(None, None, dir.clone()).unwrap());
        let now = now();
        let info = InterfaceInfo { discovered: None, last_heard: None, heard_count: None, received: now, ..stored_entry(now) };
        let path = dir.join(crate::hexrep(info.discovery_hash.as_ref().unwrap(), false));

        // `discovered` was read but `heard_count` was not: the count starts again.
        write_info(&path, &InterfaceInfo { discovered: Some(now - 500.0), heard_count: None, ..stored_entry(now) }).unwrap();
        discovery.interface_discovered(info.clone());
        let stored = read_info(&path).unwrap();
        assert_eq!((stored.discovered, stored.heard_count, stored.last_heard), (Some(now - 500.0), Some(1), Some(now)));

        // Nothing could be read: it is recorded as first discovered now.
        std::fs::write(&path, b"not msgpack").unwrap();
        discovery.interface_discovered(info);
        let stored = read_info(&path).unwrap();
        assert_eq!((stored.discovered, stored.heard_count), (Some(now), Some(1)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_monitor_detaches_an_interface_down_for_twelve_seconds() {
        let threshold = InterfaceDiscovery::DETACH_THRESHOLD as f64;
        let now = 1000.0;
        let seen = [(true, None), (true, Some(now - 30.0)), (false, None), (false, Some(now - 11.9)), (false, Some(now - 12.0))];
        let pass = plan_monitor_pass(&seen, now, threshold, 2, 5, 0, true);
        assert_eq!(pass.watches, [Watch::Online, Watch::Reconnected, Watch::Disconnected, Watch::Down, Watch::Detach]);
        assert_eq!(pass.online, 2);
    }

    #[test]
    fn the_monitor_dials_into_free_slots_beyond_the_reserved_quarter() {
        let plan = |seen: &[(bool, Option<f64>)], max, autoconnected, initial_ran| {
            plan_monitor_pass(seen, 100.0, 12.0, max, autoconnected, 0, initial_ran).connect_candidate
        };
        // Two allowed, none reserved: one free slot dials a candidate.
        assert!(plan(&[(true, None)], 2, 1, true));
        assert!(!plan(&[(true, None), (true, None)], 2, 2, true));
        // A dead interface keeps its slot until it is detached.
        assert!(!plan(&[(true, None), (false, Some(95.0))], 2, 2, true));
        // Four allowed: one slot is held back.
        assert!(!plan(&[], 4, 3, true));
        assert!(plan(&[], 4, 2, true));
        // Nothing is dialled before the first round of auto-connects ran.
        assert!(!plan(&[], 2, 0, false));
        // More than allowed leaves no free slot.
        assert!(!plan(&[], 2, 3, true));
    }

    #[test]
    fn the_monitor_tears_down_and_restores_bootstrap_interfaces() {
        let both_up = plan_monitor_pass(&[(true, None), (true, None)], 0.0, 12.0, 2, 2, 3, true);
        assert!(both_up.teardown_bootstrap && !both_up.restore_bootstrap);
        let one_up = plan_monitor_pass(&[(true, None), (false, None)], 0.0, 12.0, 2, 2, 3, true);
        assert!(!one_up.teardown_bootstrap && !one_up.restore_bootstrap);
        let none_up_none_left = plan_monitor_pass(&[(false, Some(0.0))], 5.0, 12.0, 2, 1, 0, true);
        assert!(none_up_none_left.restore_bootstrap && !none_up_none_left.teardown_bootstrap);
        let none_up_still_there = plan_monitor_pass(&[(false, None)], 0.0, 12.0, 2, 1, 3, true);
        assert!(!none_up_still_there.restore_bootstrap);
    }

    #[test]
    fn a_dial_in_progress_holds_its_endpoint_and_its_name() {
        let dir = scratch_dir("dialling");
        let discovery = InterfaceDiscovery::with_storagepath(None, None, dir.clone()).unwrap();
        let info = InterfaceInfo {
            name: "Discovery Test Dial".into(),
            reachable_on: Some("198.51.100.77".into()),
            ..stored_entry(0.0)
        };
        assert!(!discovery.interface_exists(&info));
        discovery.autoconnects.lock().unwrap().dialling.push((discovery.endpoint_hash(&info), info.name.clone()));
        assert!(discovery.interface_exists(&info));
        assert_eq!(discovery.autoconnect_count(), 1);

        let autoconnects = discovery.autoconnects.lock().unwrap();
        assert_eq!(InterfaceDiscovery::unique_interface_name(&autoconnects, "Discovery Test Dial", "198.51.100.78", 4243),
                   "Discovery Test Dial [198.51.100.78:4243]");
        assert_eq!(InterfaceDiscovery::unique_interface_name(&autoconnects, "Discovery Test Other", "198.51.100.78", 4243),
                   "Discovery Test Other");
        drop(autoconnects);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
