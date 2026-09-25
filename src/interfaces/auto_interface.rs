// AutoInterface - Automatic local network peer discovery via IPv6 multicast
// Implements full discovery and peer management parity with Python.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::net::{Ipv6Addr, SocketAddrV6, UdpSocket};
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use if_addrs::{get_if_addrs, IfAddr};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[cfg(windows)]
use std::ffi::CStr;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};

#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
};

use crate::identity;
use crate::log;
use crate::transport::{InterfaceStubConfig, Transport};

// Constants
pub const HW_MTU: usize = 1196;
pub const FIXED_MTU: bool = true;

pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;
pub const DEFAULT_DATA_PORT: u16 = 42671;
pub const DEFAULT_GROUP_ID: &str = "reticulum";
pub const DEFAULT_IFAC_SIZE: usize = 16;

// Multicast scope values
pub const SCOPE_LINK: &str = "2";
pub const SCOPE_ADMIN: &str = "4";
pub const SCOPE_SITE: &str = "5";
pub const SCOPE_ORGANISATION: &str = "8";
pub const SCOPE_GLOBAL: &str = "e";

// Multicast address types
pub const MULTICAST_PERMANENT_ADDRESS_TYPE: &str = "0";
pub const MULTICAST_TEMPORARY_ADDRESS_TYPE: &str = "1";

// Timing constants
pub const PEERING_TIMEOUT: f64 = 22.0;
pub const ANNOUNCE_INTERVAL: f64 = 1.6;
pub const PEER_JOB_INTERVAL: f64 = 4.0;
pub const MCAST_ECHO_TIMEOUT: f64 = 6.5;

// Platform-specific interface filters
pub const ALL_IGNORE_IFS: &[&str] = &["lo0"];
pub const DARWIN_IGNORE_IFS: &[&str] = &["awdl0", "llw0", "lo0", "en5"];
pub const ANDROID_IGNORE_IFS: &[&str] = &["dummy0", "lo", "tun0"];

pub const BITRATE_GUESS: u64 = 10_000_000;

pub const MULTI_IF_DEQUE_LEN: usize = 48;
pub const MULTI_IF_DEQUE_TTL: f64 = 0.75;

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub ifname: String,
    pub last_heard: f64,
    pub last_outbound: f64,
}

#[derive(Clone, Debug)]
pub struct AutoInterfaceConfig {
    pub name: String,
    pub group_id: Option<String>,
    pub discovery_scope: Option<String>,
    pub discovery_port: Option<u16>,
    pub multicast_address_type: Option<String>,
    pub data_port: Option<u16>,
    pub allowed_interfaces: Option<Vec<String>>,
    pub ignored_interfaces: Option<Vec<String>>,
    pub configured_bitrate: Option<u64>,
    pub stub_config: InterfaceStubConfig,
}

struct ListenerHandle {
    stop: Arc<AtomicBool>,
    socket: Arc<Socket>,
}

pub struct AutoInterface {
    pub name: String,
    pub hw_mtu: usize,
    pub online: Arc<AtomicBool>,
    pub final_init_done: Arc<AtomicBool>,

    // Configuration
    pub group_id: Vec<u8>,
    pub group_hash: Vec<u8>,
    pub discovery_port: u16,
    pub unicast_discovery_port: u16,
    pub data_port: u16,
    pub discovery_scope: String,
    pub multicast_address_type: String,
    pub mcast_discovery_address: String,
    pub allowed_interfaces: Vec<String>,
    pub ignored_interfaces: Vec<String>,
    pub stub_config_template: InterfaceStubConfig,

    // Peer management
    pub peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    pub spawned_interfaces: Arc<Mutex<HashMap<String, AutoInterfacePeer>>>,
    pub link_local_addresses: Arc<Mutex<Vec<String>>>,
    pub adopted_interfaces: Arc<Mutex<HashMap<String, String>>>,

    // Echo tracking for carrier detection
    pub multicast_echoes: Arc<Mutex<HashMap<String, f64>>>,
    pub initial_echoes: Arc<Mutex<HashMap<String, f64>>>,
    pub timed_out_interfaces: Arc<Mutex<HashMap<String, bool>>>,
    pub carrier_changed: Arc<AtomicBool>,

    // Duplicate packet detection across multiple interfaces
    pub mif_deque: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub mif_deque_times: Arc<Mutex<VecDeque<(Vec<u8>, f64)>>>,

    // Timing
    pub announce_interval: f64,
    pub peer_job_interval: f64,
    pub peering_timeout: f64,
    pub multicast_echo_timeout: f64,
    pub reverse_peering_interval: f64,

    // Interface properties
    pub bitrate: Option<u64>,
    pub mode: u8,
    pub announce_rate_target: Option<f64>,
    pub announce_rate_grace: Option<f64>,
    pub announce_rate_penalty: Option<f64>,

    // Outbound socket (shared for peers)
    pub outbound_udp_socket: Arc<Mutex<Option<UdpSocket>>>,

    // Data listeners per interface
    interface_listeners: Arc<Mutex<HashMap<String, ListenerHandle>>>,
}

impl AutoInterface {
    pub fn new(config: AutoInterfaceConfig) -> Result<Arc<Self>, String> {
        let interface = Self::from_config(config);

        let suitable_interfaces = interface.configure_interfaces()?;
        if suitable_interfaces == 0 {
            log(
                &format!("{} could not autoconfigure. This interface currently provides no connectivity.", interface),
                crate::LOG_WARNING,
                false,
                false,
            );
        }

        Ok(interface)
    }

    /// The interface before `configure_interfaces`: no socket bound and no
    /// thread started, so tests can drive peer handling without a network.
    pub(crate) fn from_config(config: AutoInterfaceConfig) -> Arc<Self> {
        // Parse configuration
        let group_id = config.group_id
            .unwrap_or_else(|| DEFAULT_GROUP_ID.to_string())
            .into_bytes();

        let group_hash = identity::full_hash(&group_id);

        // Build multicast discovery address from group hash
        let discovery_scope = config.discovery_scope
            .unwrap_or_else(|| SCOPE_LINK.to_string());

        let multicast_address_type = config.multicast_address_type
            .unwrap_or_else(|| MULTICAST_TEMPORARY_ADDRESS_TYPE.to_string());

        let mcast_discovery_address = Self::build_multicast_address(
            &group_hash,
            &discovery_scope,
            &multicast_address_type,
        );

        let discovery_port = config.discovery_port.unwrap_or(DEFAULT_DISCOVERY_PORT);
        let data_port = config.data_port.unwrap_or(DEFAULT_DATA_PORT);

        let announce_interval = ANNOUNCE_INTERVAL;
        let peering_timeout = if cfg!(target_os = "android") {
            PEERING_TIMEOUT * 1.25
        } else {
            PEERING_TIMEOUT
        };

        let stub_config = config.stub_config.clone();

        Arc::new(AutoInterface {
            name: config.name,
            hw_mtu: HW_MTU,
            online: Arc::new(AtomicBool::new(false)),
            final_init_done: Arc::new(AtomicBool::new(false)),

            group_id,
            group_hash,
            discovery_port,
            unicast_discovery_port: discovery_port + 1,
            data_port,
            discovery_scope,
            multicast_address_type,
            mcast_discovery_address,
            allowed_interfaces: config.allowed_interfaces.unwrap_or_default(),
            ignored_interfaces: config.ignored_interfaces.unwrap_or_default(),
            stub_config_template: stub_config.clone(),

            peers: Arc::new(Mutex::new(HashMap::new())),
            spawned_interfaces: Arc::new(Mutex::new(HashMap::new())),
            link_local_addresses: Arc::new(Mutex::new(Vec::new())),
            adopted_interfaces: Arc::new(Mutex::new(HashMap::new())),

            multicast_echoes: Arc::new(Mutex::new(HashMap::new())),
            initial_echoes: Arc::new(Mutex::new(HashMap::new())),
            timed_out_interfaces: Arc::new(Mutex::new(HashMap::new())),
            carrier_changed: Arc::new(AtomicBool::new(false)),

            mif_deque: Arc::new(Mutex::new(VecDeque::with_capacity(MULTI_IF_DEQUE_LEN))),
            mif_deque_times: Arc::new(Mutex::new(VecDeque::with_capacity(MULTI_IF_DEQUE_LEN))),

            announce_interval,
            peer_job_interval: PEER_JOB_INTERVAL,
            peering_timeout,
            multicast_echo_timeout: MCAST_ECHO_TIMEOUT,
            reverse_peering_interval: announce_interval * 3.25,

            bitrate: config.configured_bitrate.or(Some(BITRATE_GUESS)),
            mode: stub_config.mode,
            announce_rate_target: stub_config.announce_rate_target,
            announce_rate_grace: stub_config.announce_rate_grace,
            announce_rate_penalty: stub_config.announce_rate_penalty,

            outbound_udp_socket: Arc::new(Mutex::new(None)),
            interface_listeners: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn configure_interfaces(self: &Arc<Self>) -> Result<usize, String> {
        let if_addrs = get_if_addrs()
            .map_err(|e| format!("Failed to enumerate interfaces: {}", e))?;

        let mut interface_names: HashSet<String> = HashSet::new();
        let mut link_local_map: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();

        for if_addr in if_addrs {
            let ifname = if_addr.name;
            interface_names.insert(ifname.clone());
            if let IfAddr::V6(v6) = if_addr.addr {
                if Self::is_link_local(&v6.ip) {
                    link_local_map.entry(ifname).or_default().push(v6.ip);
                }
            }
        }

        let mut suitable_interfaces = 0;
        let now = Self::now();

        for ifname in interface_names.iter() {
            if self.should_ignore_interface(ifname) {
                continue;
            }

            let link_locals = link_local_map.get(ifname).cloned().unwrap_or_default();
            if link_locals.is_empty() {
                log(
                    &format!("{} No link-local IPv6 address configured for {}, skipping interface", self, ifname),
                    crate::LOG_EXTREME,
                    false,
                    false,
                );
                continue;
            }

            let link_local_addr = self.descope_linklocal(&link_locals[link_locals.len() - 1].to_string());
            {
                let mut adopted = self.adopted_interfaces.lock().unwrap();
                let mut locals = self.link_local_addresses.lock().unwrap();
                let mut echoes = self.multicast_echoes.lock().unwrap();

                adopted.insert(ifname.clone(), link_local_addr.clone());
                if !locals.contains(&link_local_addr) {
                    locals.push(link_local_addr.clone());
                }
                echoes.insert(ifname.clone(), now);
            }

            log(
                &format!("{} Selecting link-local address {} for interface {}", self, link_local_addr, ifname),
                crate::LOG_EXTREME,
                false,
                false,
            );

            if let Err(err) = self.setup_discovery_sockets(ifname, &link_local_addr) {
                log(
                    &format!("{} Could not configure the system interface {} for discovery: {}", self, ifname, err),
                    crate::LOG_ERROR,
                    false,
                    false,
                );
                continue;
            }

            suitable_interfaces += 1;
        }

        Ok(suitable_interfaces)
    }

    fn setup_discovery_sockets(self: &Arc<Self>, ifname: &str, link_local_addr: &str) -> Result<(), String> {
        let if_index = self.interface_name_to_index(ifname);
        let scope_id = if_index;

        // Unicast discovery socket
        let unicast_socket = Self::create_udp_socket_v6()?;
        let unicast_addr = if cfg!(windows) {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, self.unicast_discovery_port, 0, 0)
        } else {
            let ip = link_local_addr.parse::<Ipv6Addr>()
                .map_err(|e| format!("Invalid link-local address {}: {}", link_local_addr, e))?;
            SocketAddrV6::new(ip, self.unicast_discovery_port, 0, scope_id)
        };
        unicast_socket
            .bind(&SockAddr::from(unicast_addr))
            .map_err(|e| format!("Failed to bind unicast discovery socket: {}", e))?;

        let unicast_udp: UdpSocket = unicast_socket.into();
        let unicast_iface = Arc::clone(self);
        let ifname_unicast = ifname.to_string();
        thread::spawn(move || {
            AutoInterface::discovery_handler(unicast_iface, unicast_udp, ifname_unicast, false);
        });

        // Multicast discovery socket
        let mcast_socket = Self::create_udp_socket_v6()?;
        if if_index > 0 {
            mcast_socket
                .set_multicast_if_v6(if_index)
                .map_err(|e| format!("Failed to set multicast interface: {}", e))?;
        }

        let mcast_ip = self.mcast_discovery_address.parse::<Ipv6Addr>()
            .map_err(|e| format!("Invalid multicast address {}: {}", self.mcast_discovery_address, e))?;

        if if_index > 0 {
            mcast_socket
                .join_multicast_v6(&mcast_ip, if_index)
                .map_err(|e| format!("Failed to join multicast group: {}", e))?;
        }

        let mcast_addr = if cfg!(windows) {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, self.discovery_port, 0, 0)
        } else if self.discovery_scope == SCOPE_LINK {
            SocketAddrV6::new(mcast_ip, self.discovery_port, 0, scope_id)
        } else {
            SocketAddrV6::new(mcast_ip, self.discovery_port, 0, 0)
        };

        mcast_socket
            .bind(&SockAddr::from(mcast_addr))
            .map_err(|e| format!("Failed to bind multicast discovery socket: {}", e))?;

        let mcast_udp: UdpSocket = mcast_socket.into();
        let mcast_iface = Arc::clone(self);
        let ifname_mcast = ifname.to_string();
        thread::spawn(move || {
            AutoInterface::discovery_handler(mcast_iface, mcast_udp, ifname_mcast, true);
        });

        Ok(())
    }

    fn create_udp_socket_v6() -> Result<Socket, String> {
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| format!("Failed to create IPv6 UDP socket: {}", e))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| format!("Failed to set SO_REUSEADDR: {}", e))?;
        Ok(socket)
    }

    fn build_multicast_address(group_hash: &[u8], scope: &str, addr_type: &str) -> String {
        let g = group_hash;
        let mut addr = format!("ff{}{}:0", addr_type, scope);

        let mut idx = 2usize;
        while idx + 1 < g.len() && idx <= 12 {
            let value = (g[idx + 1] as u16) + ((g[idx] as u16) << 8);
            addr.push_str(&format!(":{:02x}", value));
            idx += 2;
        }

        addr
    }

    #[allow(dead_code)]
    fn list_interfaces(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(if_addrs) = get_if_addrs() {
            let mut set = HashSet::new();
            for if_addr in if_addrs {
                if set.insert(if_addr.name.clone()) {
                    names.push(if_addr.name);
                }
            }
        }
        names
    }

    fn interface_name_to_index(&self, ifname: &str) -> u32 {
        #[cfg(unix)]
        {
            if let Ok(cstr) = CString::new(ifname) {
                let index = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
                if index > 0 {
                    return index;
                }
            }
        }

        #[cfg(windows)]
        {
            if let Some(index) = Self::windows_interface_index(ifname) {
                return index;
            }
        }

        0
    }

    #[cfg(windows)]
    fn windows_interface_index(ifname: &str) -> Option<u32> {
        unsafe {
            let mut buffer_len: u32 = 0;
            let mut ret = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut buffer_len,
            );

            if ret != ERROR_BUFFER_OVERFLOW {
                return None;
            }

            let mut buffer = vec![0u8; buffer_len as usize];
            let adapters_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            ret = GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                std::ptr::null_mut(),
                adapters_ptr,
                &mut buffer_len,
            );

            if ret != NO_ERROR {
                return None;
            }

            let mut current = adapters_ptr;
            while !current.is_null() {
                let adapter = &*current;

                if let Some(name) = Self::windows_pstr_to_string(adapter.AdapterName) {
                    if name == ifname {
                        let idx = if adapter.Ipv6IfIndex != 0 { adapter.Ipv6IfIndex } else { adapter.IfIndex };
                        if idx != 0 {
                            return Some(idx);
                        }
                    }
                }

                if let Some(friendly) = Self::windows_pwstr_to_string(adapter.FriendlyName) {
                    if friendly == ifname {
                        let idx = if adapter.Ipv6IfIndex != 0 { adapter.Ipv6IfIndex } else { adapter.IfIndex };
                        if idx != 0 {
                            return Some(idx);
                        }
                    }
                }

                current = adapter.Next;
            }
        }

        None
    }

    #[cfg(windows)]
    fn windows_pstr_to_string(ptr: *const i8) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string()) }
    }

    #[cfg(windows)]
    fn windows_pwstr_to_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        unsafe {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            String::from_utf16(slice).ok()
        }
    }

    fn descope_linklocal(&self, addr: &str) -> String {
        let addr = addr.split('%').next().unwrap_or(addr);
        if addr.starts_with("fe80:") {
            if let Some(pos) = addr.find("::") {
                let suffix = &addr[pos + 2..];
                if suffix.is_empty() {
                    return "fe80::".to_string();
                }
                return format!("fe80::{}", suffix);
            }
        }
        addr.to_string()
    }

    fn should_ignore_interface(&self, ifname: &str) -> bool {
        if !self.allowed_interfaces.is_empty() && !self.allowed_interfaces.contains(&ifname.to_string()) {
            log(
                &format!("{} ignoring interface {} since it was not allowed", self, ifname),
                crate::LOG_EXTREME,
                false,
                false,
            );
            return true;
        }

        if self.ignored_interfaces.contains(&ifname.to_string()) {
            log(
                &format!("{} ignoring disallowed interface {}", self, ifname),
                crate::LOG_EXTREME,
                false,
                false,
            );
            return true;
        }

        if ALL_IGNORE_IFS.contains(&ifname) {
            log(
                &format!("{} skipping interface {}", self, ifname),
                crate::LOG_EXTREME,
                false,
                false,
            );
            return true;
        }

        #[cfg(target_os = "macos")]
        if DARWIN_IGNORE_IFS.contains(&ifname) && !self.allowed_interfaces.contains(&ifname.to_string()) {
            log(
                &format!("{} skipping Darwin AWDL or tethering interface {}", self, ifname),
                crate::LOG_EXTREME,
                false,
                false,
            );
            return true;
        }

        #[cfg(target_os = "android")]
        if ANDROID_IGNORE_IFS.contains(&ifname) && !self.allowed_interfaces.contains(&ifname.to_string()) {
            log(
                &format!("{} skipping Android system interface {}", self, ifname),
                crate::LOG_EXTREME,
                false,
                false,
            );
            return true;
        }

        false
    }

    pub fn final_init(self: &Arc<Self>) {
        let peering_wait = self.announce_interval * 1.2;
        log(
            &format!("{} discovering peers for {} seconds...", self, peering_wait),
            crate::LOG_VERBOSE,
            false,
            false,
        );

        let adopted_snapshot = self.adopted_interfaces.lock().unwrap().clone();
        for (ifname, link_local_addr) in adopted_snapshot {
            if let Err(err) = self.start_data_listener(&ifname, &link_local_addr) {
                log(
                    &format!("{} Failed to start data listener on {}: {}", self, ifname, err),
                    crate::LOG_ERROR,
                    false,
                    false,
                );
            }
        }

        let peer_iface = Arc::clone(self);
        thread::spawn(move || peer_iface.peer_jobs());

        thread::sleep(Duration::from_secs_f64(peering_wait));

        self.online.store(true, Ordering::SeqCst);
        self.final_init_done.store(true, Ordering::SeqCst);
    }

    fn start_data_listener(self: &Arc<Self>, ifname: &str, link_local_addr: &str) -> Result<(), String> {
        let if_index = self.interface_name_to_index(ifname);
        let ip = link_local_addr.parse::<Ipv6Addr>()
            .map_err(|e| format!("Invalid link-local address {}: {}", link_local_addr, e))?;
        let bind_addr = if cfg!(windows) {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, self.data_port, 0, 0)
        } else {
            SocketAddrV6::new(ip, self.data_port, 0, if_index)
        };

        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| format!("Failed to create data socket: {}", e))?;
        socket
            .set_reuse_address(true)
            .map_err(|e| format!("Failed to set SO_REUSEADDR on data socket: {}", e))?;
        socket
            .bind(&SockAddr::from(bind_addr))
            .map_err(|e| format!("Failed to bind data socket: {}", e))?;
        let socket = Arc::new(socket);

        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_flag);
        let iface = Arc::clone(self);
        let ifname_str = ifname.to_string();

        let socket_clone = Arc::clone(&socket);
        thread::spawn(move || {
            let mut buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); 65536];
            while !stop_clone.load(Ordering::SeqCst) {
                match socket_clone.recv_from(&mut buf) {
                    Ok((size, addr)) => {
                        if let Some(std::net::SocketAddr::V6(src)) = addr.as_socket() {
                            let data = unsafe {
                                std::slice::from_raw_parts(buf.as_ptr() as *const u8, size).to_vec()
                            };
                            iface.process_incoming(data, src, &ifname_str);
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        self.interface_listeners.lock().unwrap().insert(
            ifname.to_string(),
            ListenerHandle { stop: stop_flag, socket },
        );

        Ok(())
    }

    fn stop_data_listener(&self, ifname: &str) {
        if let Some(handle) = self.interface_listeners.lock().unwrap().remove(ifname) {
            handle.stop.store(true, Ordering::SeqCst);
            let _ = handle.socket.shutdown(std::net::Shutdown::Both);
        }
    }

    fn restart_data_listener(self: &Arc<Self>, ifname: &str, link_local_addr: &str) {
        self.stop_data_listener(ifname);
        let _ = self.start_data_listener(ifname, link_local_addr);
    }

    fn process_incoming(&self, data: Vec<u8>, addr: SocketAddrV6, ifname: &str) {
        if !self.online.load(Ordering::SeqCst) {
            return;
        }

        let addr_str = addr.ip().to_string();
        let mut spawned = self.spawned_interfaces.lock().unwrap();
        if let Some(peer) = spawned.get_mut(&addr_str) {
            peer.process_incoming(&data, Some(ifname));
        }
    }

    fn discovery_handler(self: Arc<Self>, socket: UdpSocket, ifname: String, announce: bool) {
        if announce {
            let announce_iface = Arc::clone(&self);
            let ifname_clone = ifname.clone();
            thread::spawn(move || announce_iface.announce_handler(&ifname_clone));
        }

        let mut buf = [0u8; 1024];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((size, addr)) => {
                    if !self.final_init_done.load(Ordering::SeqCst) {
                        continue;
                    }

                    let src_ip = match addr {
                        std::net::SocketAddr::V6(v6) => v6.ip().to_string(),
                        _ => continue,
                    };

                    let hash_len = crate::identity::HASHLENGTH / 8;
                    if size < hash_len {
                        continue;
                    }

                    let peering_hash = &buf[..hash_len];
                    let expected_hash = identity::full_hash(
                        &[&self.group_id[..], src_ip.as_bytes()].concat(),
                    );

                    if peering_hash == expected_hash.as_slice() {
                        self.add_peer(&src_ip, &ifname);
                    } else {
                        log(
                            &format!("{} received peering packet on {} from {}, but authentication hash was incorrect.", self, ifname, src_ip),
                            crate::LOG_DEBUG,
                            false,
                            false,
                        );
                    }
                }
                Err(_) => break,
            }
        }
    }

    fn announce_handler(self: &Arc<Self>, ifname: &str) {
        loop {
            self.peer_announce(ifname);
            thread::sleep(Duration::from_secs_f64(self.announce_interval));
        }
    }

    fn reverse_announce(&self, ifname: &str, peer_addr: &str) {
        let link_local_addr = {
            let adopted = self.adopted_interfaces.lock().unwrap();
            adopted.get(ifname).cloned()
        };

        if let Some(link_local) = link_local_addr {
            let discovery_token = identity::full_hash(
                &[&self.group_id[..], link_local.as_bytes()].concat(),
            );

            let if_index = self.interface_name_to_index(ifname);
            let peer_ip = match peer_addr.parse::<Ipv6Addr>() {
                Ok(ip) => ip,
                Err(e) => {
                    log(
                        &format!("{} Invalid peer address {}: {}", self, peer_addr, e),
                        crate::LOG_ERROR,
                        false,
                        false,
                    );
                    return;
                }
            };

            let addr = SocketAddrV6::new(peer_ip, self.unicast_discovery_port, 0, if_index);
            if let Ok(socket) = Self::create_udp_socket_v6() {
                let _ = socket.send_to(&discovery_token, &SockAddr::from(addr));
            }
        }
    }

    fn peer_announce(&self, ifname: &str) {
        let link_local_addr = {
            let adopted = self.adopted_interfaces.lock().unwrap();
            adopted.get(ifname).cloned()
        };

        if let Some(link_local) = link_local_addr {
            let discovery_token = identity::full_hash(
                &[&self.group_id[..], link_local.as_bytes()].concat(),
            );

            let if_index = self.interface_name_to_index(ifname);
            let mcast_ip = match self.mcast_discovery_address.parse::<Ipv6Addr>() {
                Ok(ip) => ip,
                Err(e) => {
                    log(
                        &format!("{} Invalid multicast address {}: {}", self, self.mcast_discovery_address, e),
                        crate::LOG_ERROR,
                        false,
                        false,
                    );
                    return;
                }
            };

            let addr = if self.discovery_scope == SCOPE_LINK {
                SocketAddrV6::new(mcast_ip, self.discovery_port, 0, if_index)
            } else {
                SocketAddrV6::new(mcast_ip, self.discovery_port, 0, 0)
            };

            match Self::create_udp_socket_v6() {
                Ok(socket) => {
                    if if_index > 0 {
                        let _ = socket.set_multicast_if_v6(if_index);
                    }
                    if socket.send_to(&discovery_token, &SockAddr::from(addr)).is_err() {
                        let timeouts = self.timed_out_interfaces.lock().unwrap();
                        let timed_out = timeouts.get(ifname).cloned().unwrap_or(false);
                        if !timed_out {
                            log(
                                &format!("{} Detected possible carrier loss on {}", self, ifname),
                                crate::LOG_WARNING,
                                false,
                                false,
                            );
                        }
                    }
                }
                Err(err) => {
                    log(
                        &format!("{} Could not send peer announce on {}: {}", self, ifname, err),
                        crate::LOG_WARNING,
                        false,
                        false,
                    );
                }
            }
        }
    }

    fn peer_jobs(self: &Arc<Self>) {
        loop {
            thread::sleep(Duration::from_secs_f64(self.peer_job_interval));
            let now = Self::now();

            // Check for timed out peers
            let timed_out: Vec<String> = {
                let peers = self.peers.lock().unwrap();
                peers
                    .iter()
                    .filter(|(_, info)| now > info.last_heard + self.peering_timeout)
                    .map(|(addr, _)| addr.clone())
                    .collect()
            };

            // Remove timed out peers
            for peer_addr in timed_out {
                self.remove_peer(&peer_addr);
            }

            // Send reverse peering packets
            {
                let mut peers = self.peers.lock().unwrap();
                for (peer_addr, info) in peers.iter_mut() {
                    if now > info.last_outbound + self.reverse_peering_interval {
                        self.reverse_announce(&info.ifname, peer_addr);
                        info.last_outbound = now;
                    }
                }
            }

            // Check for link-local address changes
            let adopted_snapshot = self.adopted_interfaces.lock().unwrap().clone();
            for (ifname, old_addr) in adopted_snapshot {
                if let Some(new_addr) = self.find_link_local(&ifname) {
                    if new_addr != old_addr {
                        log(
                            &format!("Replacing link-local address {} for {} with {}", old_addr, ifname, new_addr),
                            crate::LOG_DEBUG,
                            false,
                            false,
                        );

                        {
                            let mut adopted = self.adopted_interfaces.lock().unwrap();
                            adopted.insert(ifname.clone(), new_addr.clone());
                        }
                        {
                            let mut locals = self.link_local_addresses.lock().unwrap();
                            locals.retain(|a| a != &old_addr);
                            if !locals.contains(&new_addr) {
                                locals.push(new_addr.clone());
                            }
                        }

                        self.restart_data_listener(&ifname, &new_addr);
                        self.carrier_changed.store(true, Ordering::SeqCst);
                    }
                }
            }

            // Check multicast echo timeouts
            let adopted_snapshot = self.adopted_interfaces.lock().unwrap().clone();
            for ifname in adopted_snapshot.keys() {
                let last_echo = {
                    let echoes = self.multicast_echoes.lock().unwrap();
                    echoes.get(ifname).cloned().unwrap_or(0.0)
                };
                let multicast_echo_received = {
                    let initial = self.initial_echoes.lock().unwrap();
                    initial.contains_key(ifname)
                };

                if now - last_echo > self.multicast_echo_timeout {
                    let mut timeouts = self.timed_out_interfaces.lock().unwrap();
                    let prev = timeouts.get(ifname).cloned().unwrap_or(false);
                    if !prev {
                        self.carrier_changed.store(true, Ordering::SeqCst);
                        log(
                            &format!("Multicast echo timeout for {}. Carrier lost.", ifname),
                            crate::LOG_WARNING,
                            false,
                            false,
                        );
                    }
                    timeouts.insert(ifname.clone(), true);
                } else {
                    let mut timeouts = self.timed_out_interfaces.lock().unwrap();
                    let prev = timeouts.get(ifname).cloned().unwrap_or(false);
                    if prev {
                        self.carrier_changed.store(true, Ordering::SeqCst);
                        log(
                            &format!("{} Carrier recovered on {}", self, ifname),
                            crate::LOG_WARNING,
                            false,
                            false,
                        );
                    }
                    timeouts.insert(ifname.clone(), false);
                }

                if !multicast_echo_received {
                    log(
                        &format!("{} No multicast echoes received on {}. The networking hardware or a firewall may be blocking multicast traffic.", self, ifname),
                        crate::LOG_ERROR,
                        false,
                        false,
                    );
                }
            }
        }
    }

    /// Forget a peer that was not heard within the peering timeout: its
    /// spawned interface goes offline and leaves Transport
    /// (AutoInterface.py peer_jobs: detach, then teardown).
    pub(crate) fn remove_peer(&self, peer_addr: &str) {
        let mut peers = self.peers.lock().unwrap();
        let peer_ifname = peers.get(peer_addr).map(|info| info.ifname.clone());
        peers.remove(peer_addr);
        drop(peers);

        let mut spawned = self.spawned_interfaces.lock().unwrap();
        if let Some(mut spawned_if) = spawned.remove(peer_addr) {
            spawned_if.detach();
            spawned_if.teardown();
        }
        if let Some(ifname) = peer_ifname {
            log(
                &format!("{} removed peer {} on {}", self, peer_addr, ifname),
                crate::LOG_DEBUG,
                false,
                false,
            );
        }
    }

    fn find_link_local(&self, ifname: &str) -> Option<String> {
        if let Ok(if_addrs) = get_if_addrs() {
            for if_addr in if_addrs {
                if if_addr.name != ifname {
                    continue;
                }
                if let IfAddr::V6(v6) = if_addr.addr {
                    if Self::is_link_local(&v6.ip) {
                        return Some(self.descope_linklocal(&v6.ip.to_string()));
                    }
                }
            }
        }
        None
    }

    fn is_link_local(addr: &Ipv6Addr) -> bool {
        let segments = addr.segments();
        (segments[0] & 0xffc0) == 0xfe80
    }

    pub fn add_peer(&self, addr: &str, ifname: &str) {
        // Check if this is our own multicast echo
        if self.link_local_addresses.lock().unwrap().contains(&addr.to_string()) {
            let mut matched_if = None;
            {
                let adopted = self.adopted_interfaces.lock().unwrap();
                for (if_name, if_addr) in adopted.iter() {
                    if if_addr == addr {
                        matched_if = Some(if_name.clone());
                        break;
                    }
                }
            }

            if let Some(if_name) = matched_if {
                let now = Self::now();
                self.multicast_echoes.lock().unwrap().insert(if_name.clone(), now);
                let mut initial = self.initial_echoes.lock().unwrap();
                initial.entry(if_name).or_insert(now);
                return;
            } else {
                log(
                    &format!("{} received multicast echo on unexpected interface {}", self, ifname),
                    crate::LOG_WARNING,
                    false,
                    false,
                );
                return;
            }
        }

        let mut peers = self.peers.lock().unwrap();
        if peers.contains_key(addr) {
            if let Some(peer_info) = peers.get_mut(addr) {
                peer_info.last_heard = Self::now();
            }
            return;
        }

        let peer_info = PeerInfo {
            ifname: ifname.to_string(),
            last_heard: Self::now(),
            last_outbound: Self::now(),
        };
        peers.insert(addr.to_string(), peer_info);
        drop(peers);

        // Remove existing spawned interface if any
        {
            let mut spawned = self.spawned_interfaces.lock().unwrap();
            if let Some(mut existing) = spawned.remove(addr) {
                existing.detach();
                existing.teardown();
            }
        }

        let if_index = self.interface_name_to_index(ifname);
        let peer_name = format!("AutoInterfacePeer[{}/{}]", ifname, addr);
        let peer_interface = AutoInterfacePeer::new(
            peer_name.clone(),
            addr.to_string(),
            ifname.to_string(),
            if_index,
            self.clone_for_peer(),
        );

        self.spawned_interfaces
            .lock()
            .unwrap()
            .insert(addr.to_string(), peer_interface);

        // The send path exists before the stub: registering the stub online
        // is an up-edge, and an up-listener may send through the peer at once.
        let peers_map = Arc::clone(&self.spawned_interfaces);
        let addr_key = addr.to_string();
        Transport::register_outbound_handler(
            &peer_name,
            Arc::new(move |raw| {
                let mut map = peers_map.lock().unwrap();
                if let Some(peer) = map.get_mut(&addr_key) {
                    peer.process_outgoing(raw);
                    true
                } else {
                    false
                }
            }),
        );

        // A peer exists because it was just heard, so it is online
        // (AutoInterface.py:585). Until 2026-09-25 the stub was registered
        // offline: Transport dropped every send to it and routes through it
        // were unusable, so the LAN was receive-only.
        let mut cfg = self.stub_config_template.clone();
        cfg.name = peer_name.clone();
        cfg.online = Some(true);
        Transport::register_auto_interface_peer(cfg);

        log(
            &format!("{} added peer {} on {}", self, addr, ifname),
            crate::LOG_DEBUG,
            false,
            false,
        );
    }

    fn clone_for_peer(&self) -> AutoInterfaceShared {
        AutoInterfaceShared {
            mif_deque: Arc::clone(&self.mif_deque),
            mif_deque_times: Arc::clone(&self.mif_deque_times),
            peers: Arc::clone(&self.peers),
            outbound_udp_socket: Arc::clone(&self.outbound_udp_socket),
            data_port: self.data_port,
            bitrate: self.bitrate,
            mode: self.mode,
            hw_mtu: self.hw_mtu,
            online: Arc::clone(&self.online),
        }
    }

    fn now() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    }
}

/// Shared state passed to spawned peer interfaces
#[derive(Clone)]
pub struct AutoInterfaceShared {
    pub mif_deque: Arc<Mutex<VecDeque<Vec<u8>>>>,
    pub mif_deque_times: Arc<Mutex<VecDeque<(Vec<u8>, f64)>>>,
    pub peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    pub outbound_udp_socket: Arc<Mutex<Option<UdpSocket>>>,
    pub data_port: u16,
    pub bitrate: Option<u64>,
    pub mode: u8,
    pub hw_mtu: usize,
    pub online: Arc<AtomicBool>,
}

/// Per-peer spawned interface
pub struct AutoInterfacePeer {
    pub name: String,
    pub addr: String,
    pub ifname: String,
    pub if_index: u32,
    pub online: bool,
    pub detached: bool,
    pub rxb: u64,
    pub txb: u64,
    pub parent: AutoInterfaceShared,
    /// Experimental: force bitrate throttle on outgoing data
    pub _force_bitrate: bool,
}

impl AutoInterfacePeer {
    pub fn new(
        name: String,
        addr: String,
        ifname: String,
        if_index: u32,
        parent: AutoInterfaceShared,
    ) -> Self {
        AutoInterfacePeer {
            name,
            addr,
            ifname,
            if_index,
            online: true,
            detached: false,
            rxb: 0,
            txb: 0,
            parent,
            _force_bitrate: false,
        }
    }

    pub fn process_incoming(&mut self, data: &[u8], _ifname: Option<&str>) {
        if !self.online || !self.parent.online.load(Ordering::SeqCst) {
            return;
        }

        let data_hash = identity::full_hash(data);
        let now = AutoInterface::now();

        let mut deque = self.parent.mif_deque.lock().unwrap();
        let mut deque_times = self.parent.mif_deque_times.lock().unwrap();

        let mut is_duplicate = false;
        for (hash, time) in deque_times.iter() {
            if hash == &data_hash && now < time + MULTI_IF_DEQUE_TTL {
                is_duplicate = true;
                break;
            }
        }

        if is_duplicate {
            return;
        }

        deque.push_back(data_hash.clone());
        if deque.len() > MULTI_IF_DEQUE_LEN {
            deque.pop_front();
        }

        deque_times.push_back((data_hash, now));
        if deque_times.len() > MULTI_IF_DEQUE_LEN {
            deque_times.pop_front();
        }

        drop(deque);
        drop(deque_times);

        if let Some(peer_info) = self.parent.peers.lock().unwrap().get_mut(&self.addr) {
            peer_info.last_heard = now;
        }

        self.rxb += data.len() as u64;
        let _ = Transport::inbound(data.to_vec(), Some(self.name.clone()));
    }

    pub fn process_outgoing(&mut self, data: &[u8]) {
        if !self.online {
            return;
        }

        // Apply forced bitrate delay if set
        if self._force_bitrate {
            if let Some(bitrate) = self.parent.bitrate {
                if bitrate > 0 {
                    let delay_secs = (data.len() as f64 / bitrate as f64) * 8.0;
                    std::thread::sleep(std::time::Duration::from_secs_f64(delay_secs));
                }
            }
        }

        let peer_ip = match self.addr.parse::<Ipv6Addr>() {
            Ok(ip) => ip,
            Err(_) => return,
        };

        let addr = SocketAddrV6::new(peer_ip, self.parent.data_port, 0, self.if_index);
        let mut socket_guard = self.parent.outbound_udp_socket.lock().unwrap();
        if socket_guard.is_none() {
            if let Ok(socket) = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)) {
                let _ = socket.set_nonblocking(false);
                *socket_guard = Some(socket);
            }
        }

        if let Some(socket) = socket_guard.as_ref() {
            let _ = socket.send_to(data, addr);
            self.txb += data.len() as u64;
        }
    }

    pub fn detach(&mut self) {
        self.online = false;
        self.detached = true;
    }

    pub fn teardown(&mut self) {
        if !self.detached {
            log(
                &format!("The interface {} experienced an unrecoverable error and is being torn down.", self),
                crate::LOG_ERROR,
                false,
                false,
            );
        } else {
            log(
                &format!("The interface {} is being torn down.", self),
                crate::LOG_VERBOSE,
                false,
                false,
            );
        }

        self.online = false;
        Transport::deregister_auto_interface_peer(&self.name);
        Transport::unregister_outbound_handler(&self.name);
    }
}

impl std::fmt::Display for AutoInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AutoInterface[{}]", self.name)
    }
}

impl std::fmt::Display for AutoInterfacePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AutoInterfacePeer[{}/{}]", self.ifname, self.addr)
    }
}
