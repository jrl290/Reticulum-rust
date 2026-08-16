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

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use crate::{log, LOG_DEBUG, LOG_WARNING};
use crate::identity::{self, Identity};
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

pub const APP_NAME: &str = "rnstransport";

/// Helper function to check if a string is a valid IP address
pub fn is_ip_address(address_string: &str) -> bool {
    address_string.parse::<IpAddr>().is_ok()
}

/// Helper function to check if a string is a valid hostname
pub fn is_hostname(hostname: &str) -> bool {
    let hostname = hostname.trim_end_matches('.');
    
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
    pub const DEFAULT_STAMP_VALUE: u32 = 14;
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
        let mut discovery_dest = Destination::new_inbound(
            identity,
            DestinationType::Plain,
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
                // Generate LXMF proof-of-work stamp
                let (generated_stamp, _value) = LXStamper::generate_stamp(
                    &infohash,
                    stamp_value,
                    Self::WORKBLOCK_EXPAND_ROUNDS
                );
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
}

impl InterfaceAnnounceHandler {
    pub const FLAG_SIGNED: u8 = 0b00000001;
    pub const FLAG_ENCRYPTED: u8 = 0b00000010;
    
    pub fn new(required_value: Option<u32>, callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>) -> Self {
        let required_value = required_value.unwrap_or(InterfaceAnnouncer::DEFAULT_STAMP_VALUE);
        
        Self {
            aspect_filter: format!("{}.discovery.interface", APP_NAME),
            required_value,
            callback,
        }
    }
    
    /// Process a received announce
    pub fn received_announce(&self, _destination_hash: &[u8], _announced_identity: &Identity, app_data: &[u8]) {
        if app_data.len() <= LXStamper::STAMP_SIZE + 1 {
            return;
        }
        
        let flags = app_data[0];
        let app_data = &app_data[1..];
        let _signed = (flags & Self::FLAG_SIGNED) != 0;
        let encrypted = (flags & Self::FLAG_ENCRYPTED) != 0;
        
        if encrypted {
            // Would need to decrypt with network identity
            log("Encrypted discovery announce - decryption not yet implemented", LOG_DEBUG, false, false);
            return;
        }
        
        let stamp = &app_data[app_data.len() - LXStamper::STAMP_SIZE..];
        let packed = &app_data[..app_data.len() - LXStamper::STAMP_SIZE];
        
        let infohash = identity::full_hash(packed);
        let workblock = LXStamper::stamp_workblock(&infohash, InterfaceAnnouncer::WORKBLOCK_EXPAND_ROUNDS);
        let value = LXStamper::stamp_value(&workblock, stamp);
        let valid = LXStamper::stamp_valid(stamp, self.required_value, &workblock);
        
        if !valid {
            // RNS.Discovery on the Python side validates these with
            // LXMF.LXStamper, so this path is a direct interop surface. Call out
            // the pre-parity workblock by name: while it was in use, every
            // announce exchanged with a reference node failed here, in both
            // directions, and looked indistinguishable from an empty network.
            if LXStamper::is_legacy_stamp(&infohash, stamp, self.required_value,
                                          InterfaceAnnouncer::WORKBLOCK_EXPAND_ROUNDS) {
                log("Ignored discovered interface: announcer is using the pre-parity stamp \
                     workblock (iterated digest instead of LXMF HKDF expansion)",
                    LOG_WARNING, false, false);
            } else {
                log("Ignored discovered interface with invalid stamp", LOG_DEBUG, false, false);
            }
            return;
        }
        
        if value < self.required_value {
            log(&format!("Ignored discovered interface with stamp value {}", value), LOG_DEBUG, false, false);
            return;
        }
        
        // Unpack msgpack data
        // This is a stub - would need proper msgpack deserialization
        log(&format!("Received valid interface discovery announce with value {}", value), LOG_DEBUG, false, false);
        
        // Call callback if provided
        // if let Some(ref callback) = self.callback {
        //     callback(info);
        // }
    }
}

/// Manages discovered interfaces
pub struct InterfaceDiscovery {
    pub required_value: u32,
    pub discovery_callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>,
    pub storagepath: PathBuf,
    pub monitored_interfaces: Arc<Mutex<Vec<String>>>,
    pub monitoring_autoconnects: Arc<Mutex<bool>>,
    pub monitor_interval: Duration,
    pub detach_threshold: Duration,
    pub initial_autoconnect_ran: Arc<Mutex<bool>>,
}

impl InterfaceDiscovery {
    pub const THRESHOLD_UNKNOWN: u64 = 24 * 60 * 60;  // 1 day
    pub const THRESHOLD_STALE: u64 = 3 * 24 * 60 * 60;  // 3 days
    pub const THRESHOLD_REMOVE: u64 = 7 * 24 * 60 * 60;  // 7 days
    
    pub const MONITOR_INTERVAL: u64 = 5;
    pub const DETACH_THRESHOLD: u64 = 12;
    
    pub const STATUS_STALE: u32 = 0;
    pub const STATUS_UNKNOWN: u32 = 100;
    pub const STATUS_AVAILABLE: u32 = 1000;
    
    pub const AUTOCONNECT_TYPES: &'static [&'static str] = &[
        "BackboneInterface",
        "TCPServerInterface",
    ];
    
    pub fn new(
        required_value: Option<u32>,
        callback: Option<Box<dyn Fn(InterfaceInfo) + Send + Sync>>,
        discover_interfaces: bool,
    ) -> Result<Self, String> {
        let required_value = required_value.unwrap_or(InterfaceAnnouncer::DEFAULT_STAMP_VALUE);
        
        let storagepath = crate::reticulum::storage_path().join("discovery").join("interfaces");
        
        if !storagepath.exists() {
            std::fs::create_dir_all(&storagepath)
                .map_err(|e| format!("Failed to create discovery storage path: {}", e))?;
        }
        
        let discovery = Self {
            required_value,
            discovery_callback: callback,
            storagepath,
            monitored_interfaces: Arc::new(Mutex::new(Vec::new())),
            monitoring_autoconnects: Arc::new(Mutex::new(false)),
            monitor_interval: Duration::from_secs(Self::MONITOR_INTERVAL),
            detach_threshold: Duration::from_secs(Self::DETACH_THRESHOLD),
            initial_autoconnect_ran: Arc::new(Mutex::new(false)),
        };
        
        if discover_interfaces {
            // Register announce handler
            log("Registered interface discovery handler", LOG_DEBUG, false, false);
            
            // Start connect_discovered thread
            let storagepath_clone = discovery.storagepath.clone();
            thread::spawn(move || {
                Self::connect_discovered_thread(storagepath_clone);
            });
        }
        
        Ok(discovery)
    }
    
    fn connect_discovered_thread(_storagepath: PathBuf) {
        log("Interface discovery autoconnect thread started", LOG_DEBUG, false, false);
        // Would check if autoconnect is enabled and connect to discovered interfaces
    }
    
    /// List all discovered interfaces
    pub fn list_discovered_interfaces(&self, _only_available: bool, _only_transport: bool) -> Vec<InterfaceInfo> {
        let mut discovered_interfaces = Vec::new();
        let _now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        
        if let Ok(entries) = std::fs::read_dir(&self.storagepath) {
            for entry in entries.flatten() {
                let filepath = entry.path();
                
                if let Ok(_data) = std::fs::read(&filepath) {
                    // Would deserialize msgpack data here
                    // For now, stub implementation
                    log(&format!("Found discovered interface at {:?}", filepath), LOG_DEBUG, false, false);
                }
            }
        }
        
        // Sort by status_code, value, last_heard (descending)
        discovered_interfaces.sort_by(|a: &InterfaceInfo, b: &InterfaceInfo| {
            let a_status = a.status_code.unwrap_or(0);
            let b_status = b.status_code.unwrap_or(0);
            let a_value = a.value;
            let b_value = b.value;
            let a_heard = a.last_heard.unwrap_or(0.0);
            let b_heard = b.last_heard.unwrap_or(0.0);
            
            b_status.cmp(&a_status)
                .then(b_value.cmp(&a_value))
                .then(b_heard.partial_cmp(&a_heard).unwrap())
        });
        
        discovered_interfaces
    }
    
    /// Handle a newly discovered interface
    pub fn interface_discovered(&self, info: InterfaceInfo) {
        log(&format!("Interface discovered: {}", info.name), LOG_DEBUG, false, false);
        
        // Would persist to storage and potentially autoconnect
    }
    
    /// Monitor an interface for connectivity
    pub fn monitor_interface(&self, interface_name: String) {
        let mut monitored = self.monitored_interfaces.lock().unwrap();
        if !monitored.contains(&interface_name) {
            monitored.push(interface_name);
        }
        drop(monitored);
        
        let mut monitoring = self.monitoring_autoconnects.lock().unwrap();
        if !*monitoring {
            *monitoring = true;
            drop(monitoring);
            
            log("Starting interface monitoring job", LOG_DEBUG, false, false);
            // Start monitoring thread
            self.start_monitor_job();
        }
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
    pub fn interface_exists(&self, _info: &InterfaceInfo) -> bool {
        // Would check RNS.Transport.interfaces for matching interface
        // For now, stub implementation
        false
    }

    /// Count currently autoconnected interfaces
    pub fn autoconnect_count(&self) -> usize {
        // Would count interfaces with autoconnect_hash attribute
        // For now, stub implementation
        0
    }

    /// Count bootstrap-only interfaces
    pub fn bootstrap_interface_count(&self) -> usize {
        // Would count interfaces with bootstrap_only=true
        // For now, stub implementation
        0
    }

    /// Connect to all eligible discovered interfaces
    pub fn connect_discovered(&self) {
        // Would check if autoconnect is enabled and connect to discovered interfaces
        log("Connecting to discovered interfaces (stub)", LOG_DEBUG, false, false);
        let mut initial = self.initial_autoconnect_ran.lock().unwrap();
        *initial = true;
    }

    /// Autoconnect to a specific discovered interface
    pub fn autoconnect(&self, info: &InterfaceInfo) {
        log(&format!("Auto-connecting to interface: {} (stub)", info.name), LOG_DEBUG, false, false);
        // Would create BackboneInterface or other interface type and add to Transport
    }

    /// Teardown an interface
    pub fn teardown_interface(&self, interface_name: &str) {
        log(&format!("Tearing down interface: {} (stub)", interface_name), LOG_DEBUG, false, false);
        // Would detach interface and remove from Transport.interfaces and monitored_interfaces
    }

    /// Start the monitoring job
    fn start_monitor_job(&self) {
        let monitoring = Arc::clone(&self.monitoring_autoconnects);
        let monitored = Arc::clone(&self.monitored_interfaces);
        let monitor_interval = self.monitor_interval;
        let detach_threshold = self.detach_threshold;
        
        thread::spawn(move || {
            Self::monitor_job(monitoring, monitored, monitor_interval, detach_threshold);
        });
    }

    /// Background job to monitor autoconnected interfaces
    fn monitor_job(
        monitoring: Arc<Mutex<bool>>,
        _monitored_interfaces: Arc<Mutex<Vec<String>>>,
        monitor_interval: Duration,
        _detach_threshold: Duration,
    ) {
        while *monitoring.lock().unwrap() {
            thread::sleep(monitor_interval);
            
            // Would check interface status, detach dead interfaces, autoconnect new ones
            log("Interface monitoring job tick (stub)", LOG_DEBUG, false, false);
        }
    }
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
