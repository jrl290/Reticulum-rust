use super::interface::Interface;
use crate::identity::Identity;
use crate::log;
use crate::transport::Transport as RnsTransport;
use if_addrs::{get_if_addrs, IfAddr};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Hdlc;

impl Hdlc {
    pub const FLAG: u8 = 0x7E;
    pub const ESC: u8 = 0x7D;
    pub const ESC_MASK: u8 = 0x20;

    pub fn escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() + 10);
        for &byte in data {
            if byte == Self::ESC {
                escaped.push(Self::ESC);
                escaped.push(Self::ESC ^ Self::ESC_MASK);
            } else if byte == Self::FLAG {
                escaped.push(Self::ESC);
                escaped.push(Self::FLAG ^ Self::ESC_MASK);
            } else {
                escaped.push(byte);
            }
        }
        escaped
    }
}

/// BackboneInterface - High-speed TCP server interface
///
/// Implemented for Linux-based systems. Provides a single listener socket
/// that spawns BackboneClientInterface instances for each incoming connection.
/// This is intended for high-speed, high-MTU backbone links.
pub struct BackboneInterface {
    pub base: Interface,
    pub bind_ip: String,
    pub bind_port: u16,
    pub spawned_interfaces: Arc<Mutex<Vec<Arc<Mutex<BackboneClientInterface>>>>>,
}

impl BackboneInterface {
    pub const HW_MTU: usize = 1048576;
    pub const BITRATE_GUESS: u64 = 1_000_000_000; // 1 Gbps
    pub const DEFAULT_IFAC_SIZE: usize = 16;

    /// Create a new BackboneInterface from configuration
    pub fn new(_config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err("BackboneInterface is only supported on Linux-based operating systems".to_string());
        }

        #[cfg(target_os = "linux")]
        {
            let mut base = Interface::new();
            let name = _config
                .get("name")
                .ok_or("BackboneInterface requires 'name' in config")?
                .clone();

            let device = _config.get("device").cloned();
            let port = _config.get("port").and_then(|p| p.parse::<u16>().ok());
            let listen_ip = _config.get("listen_ip").cloned();
            let listen_port = _config.get("listen_port").and_then(|p| p.parse::<u16>().ok());
            let prefer_ipv6 = _config
                .get("prefer_ipv6")
                .map(|v| parse_bool(v))
                .unwrap_or(false);

            let bind_port = listen_port.or(port).ok_or("No TCP port configured for BackboneInterface")?;

            let bind_address = if let Some(ref dev) = device {
                Self::get_address_for_if(dev, bind_port, prefer_ipv6)?
            } else {
                let ip = listen_ip.ok_or("No TCP bind IP configured for BackboneInterface")?;
                Self::get_address_for_host(&ip, bind_port, prefer_ipv6)?
            };

            base.name = Some(name);
            base.in_enabled = true;
            base.out_enabled = false;
            base.hw_mtu = Some(Self::HW_MTU);
            base.bitrate = Self::BITRATE_GUESS;
            base.autoconfigure_mtu = true;
            base.supports_discovery = true;
            base.online = false;

            let interface = BackboneInterface {
                base,
                bind_ip: bind_address.0,
                bind_port: bind_address.1,
                spawned_interfaces: Arc::new(Mutex::new(Vec::new())),
            };

            Ok(interface)
        }
    }

    /// Start the BackboneInterface listener thread
    pub fn start_listener(iface: Arc<Mutex<BackboneInterface>>) {
        let bind_addr = {
            let guard = iface.lock().unwrap();
            format!("{}:{}", guard.bind_ip, guard.bind_port)
        };

        thread::spawn(move || {
            let listener = match TcpListener::bind(&bind_addr) {
                Ok(l) => l,
                Err(e) => {
                    log(
                        &format!("Failed to bind BackboneInterface to {}: {}", bind_addr, e),
                        crate::LOG_ERROR,
                        false,
                        false,
                    );
                    return;
                }
            };

            {
                let mut guard = iface.lock().unwrap();
                guard.base.online = true;
            }

            log(
                &format!("BackboneInterface listening on {}", bind_addr),
                crate::LOG_VERBOSE,
                false,
                false,
            );

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let iface_clone = Arc::clone(&iface);
                        thread::spawn(move || {
                            BackboneInterface::handle_incoming_connection(iface_clone, stream);
                        });
                    }
                    Err(e) => {
                        log(
                            &format!("BackboneInterface accept error: {}", e),
                            crate::LOG_ERROR,
                            false,
                            false,
                        );
                    }
                }
            }
        });
    }

    fn handle_incoming_connection(
        parent: Arc<Mutex<BackboneInterface>>,
        stream: TcpStream,
    ) {
        log("Accepting incoming connection", crate::LOG_VERBOSE, false, false);

        let (parent_name, parent_mode, parent_bitrate, parent_ifac_size, parent_ifac_netname, parent_ifac_netkey, parent_announce_rate_target, parent_announce_rate_grace, parent_announce_rate_penalty) = {
            let guard = parent.lock().unwrap();
            (
                guard.base.name.clone().unwrap_or_default(),
                guard.base.mode,
                guard.base.bitrate,
                guard.base.ifac_size,
                guard.base.ifac_netname.clone(),
                guard.base.ifac_netkey.clone(),
                guard.base.announce_rate_target,
                guard.base.announce_rate_grace,
                guard.base.announce_rate_penalty,
            )
        };

        let peer_addr = stream.peer_addr().ok();
        let target_ip = peer_addr.as_ref().map(|a| a.ip().to_string()).unwrap_or_default();
        let target_port = peer_addr.as_ref().map(|a| a.port()).unwrap_or(0);

        let mut config = HashMap::new();
        config.insert("name".to_string(), format!("Client on {}", parent_name));
        config.insert("target_host".to_string(), target_ip.clone());
        config.insert("target_port".to_string(), target_port.to_string());

        match BackboneClientInterface::from_socket(config, stream, Some(parent_mode)) {
            Ok(mut spawned) => {
                spawned.base.bitrate = parent_bitrate;
                spawned.base.optimise_mtu();

                spawned.base.ifac_size = parent_ifac_size;
                spawned.base.ifac_netname = parent_ifac_netname.clone();
                spawned.base.ifac_netkey = parent_ifac_netkey.clone();

                if parent_ifac_netname.is_some() || parent_ifac_netkey.is_some() {
                    let mut ifac_origin = Vec::new();
                    if let Some(ref netname) = parent_ifac_netname {
                        ifac_origin.extend_from_slice(&Identity::full_hash(netname.as_bytes()));
                    }
                    if let Some(ref netkey) = parent_ifac_netkey {
                        ifac_origin.extend_from_slice(&Identity::full_hash(netkey.as_bytes()));
                    }

                    let ifac_origin_hash = Identity::full_hash(&ifac_origin);
                    use hkdf::Hkdf;
                    use sha2::Sha256;
                    let hkdf = Hkdf::<Sha256>::new(Some(&crate::reticulum::IFAC_SALT), &ifac_origin_hash);
                    let mut derived = vec![0u8; 64];
                    if hkdf.expand(&[], &mut derived).is_ok() {
                        spawned.base.ifac_key = Some(derived.clone());
                        if let Ok(identity) = Identity::from_bytes(&derived) {
                            spawned.base.ifac_signature = Some(identity.sign(&Identity::full_hash(&derived)));
                            spawned.base.ifac_identity = Some(identity);
                        }
                    }
                }

                spawned.base.announce_rate_target = parent_announce_rate_target;
                spawned.base.announce_rate_grace = parent_announce_rate_grace;
                spawned.base.announce_rate_penalty = parent_announce_rate_penalty;
                spawned.base.mode = parent_mode;

                let spawned_arc = Arc::new(Mutex::new(spawned));

                {
                    let handler_iface = Arc::clone(&spawned_arc);
                    let name = handler_iface.lock().unwrap().base.name.clone().unwrap_or_default();
                    RnsTransport::register_outbound_handler(
                        &name,
                        Arc::new(move |raw| {
                            let mut iface = handler_iface.lock().unwrap();
                            iface.process_outgoing(raw.to_vec()).is_ok()
                        }),
                    );
                }

                BackboneClientInterface::start_read_loop(Arc::clone(&spawned_arc));

                {
                    let parent_guard = parent.lock().unwrap();
                    parent_guard.spawned_interfaces.lock().unwrap().push(Arc::clone(&spawned_arc));
                }

                log(
                    &format!("Spawned new BackboneClient Interface: {}", spawned_arc.lock().unwrap()),
                    crate::LOG_VERBOSE,
                    false,
                    false,
                );

                let stub_config = {
                    let spawned_guard = spawned_arc.lock().unwrap();
                    crate::transport::InterfaceStubConfig {
                        name: spawned_guard.base.name.clone().unwrap_or_default(),
                        mode: spawned_guard.base.mode as u8,
                        out: true,
                        online: Some(spawned_guard.base.online && !spawned_guard.detached),
                        bitrate: Some(spawned_guard.base.bitrate),
                        announce_cap: Some(spawned_guard.base.announce_cap),
                        announce_rate_target: spawned_guard.base.announce_rate_target,
                        announce_rate_grace: spawned_guard.base.announce_rate_grace,
                        announce_rate_penalty: spawned_guard.base.announce_rate_penalty,
                        ..Default::default()
                    }
                };
                RnsTransport::register_interface_stub_config(stub_config);
            }
            Err(e) => {
                log(
                    &format!("Failed to create spawned BackboneClient: {}", e),
                    crate::LOG_ERROR,
                    false,
                    false,
                );
            }
        }
    }

    #[allow(dead_code)]
    fn get_address_for_if(name: &str, port: u16, prefer_ipv6: bool) -> Result<(String, u16), String> {
        let if_addrs = get_if_addrs()
            .map_err(|e| format!("Failed to get interface addresses: {}", e))?;

        for if_addr in &if_addrs {
            if if_addr.name != name {
                continue;
            }

            match &if_addr.addr {
                IfAddr::V6(addr) if prefer_ipv6 || !if_addrs.iter().any(|a| a.name == name && matches!(a.addr, IfAddr::V4(_))) => {
                    let ip = addr.ip;
                    if ip.is_loopback() || ip.is_unspecified() {
                        continue;
                    }
                    return Ok((ip.to_string(), port));
                }
                IfAddr::V4(addr) if !prefer_ipv6 => {
                    let ip = addr.ip;
                    if ip.is_loopback() || ip.is_unspecified() {
                        continue;
                    }
                    return Ok((ip.to_string(), port));
                }
                _ => {}
            }
        }

        Err(format!("No addresses available on specified kernel interface \"{}\" for BackboneInterface to bind to", name))
    }

    #[allow(dead_code)]
    fn get_address_for_host(name: &str, port: u16, prefer_ipv6: bool) -> Result<(String, u16), String> {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", name, port);
        let addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve address {}: {}", name, e))?
            .collect();

        if addrs.is_empty() {
            return Err(format!("No suitable kernel interface available for address \"{}\" for BackboneInterface to bind to", name));
        }

        for addr in &addrs {
            if prefer_ipv6 && addr.is_ipv6() {
                return Ok((addr.ip().to_string(), port));
            } else if !prefer_ipv6 && addr.is_ipv4() {
                return Ok((addr.ip().to_string(), port));
            }
        }

        Ok((addrs[0].ip().to_string(), port))
    }

    pub fn clients(&self) -> usize {
        self.spawned_interfaces.lock().unwrap().len()
    }

    pub fn to_string(&self) -> String {
        let ip_str = if self.bind_ip.contains(':') {
            format!("[{}]", self.bind_ip)
        } else {
            self.bind_ip.clone()
        };
        format!("BackboneInterface[{}/{}:{}]", self.base.name.as_ref().unwrap_or(&"unnamed".to_string()), ip_str, self.bind_port)
    }
}

impl std::fmt::Display for BackboneInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// BackboneClientInterface - Per-connection handler for BackboneInterface
///
/// Spawned by BackboneInterface for each incoming connection.
/// Can also be used standalone as a client (initiator).
pub struct BackboneClientInterface {
    pub base: Interface,
    pub target_ip: String,
    pub target_port: u16,
    pub initiator: bool,
    pub reconnecting: bool,
    pub never_connected: bool,
    pub detached: bool,
    pub max_reconnect_tries: Option<usize>,
    pub connect_timeout: u64,
    pub prefer_ipv6: bool,
    pub i2p_tunneled: bool,
    socket: Option<Arc<Mutex<TcpStream>>>,
    frame_buffer: Vec<u8>,
    transmit_buffer: Arc<Mutex<Vec<u8>>>,
    force_read_exit: Arc<AtomicBool>,
    pub heartbeat_running: bool,
}

impl BackboneClientInterface {
    pub const HW_MTU: usize = BackboneInterface::HW_MTU;
    pub const BITRATE_GUESS: u64 = 100_000_000; // 100 Mbps
    pub const DEFAULT_IFAC_SIZE: usize = 16;
    pub const RECONNECT_WAIT_BASE: u64 = 5;
    pub const RECONNECT_WAIT_MAX: u64 = 300;
    pub const INITIAL_CONNECT_TIMEOUT: u64 = 5;
    pub const READ_WAKE_INTERVAL: u64 = 2;
    pub const HEARTBEAT_INTERVAL: u64 = 60;

    pub const TCP_USER_TIMEOUT: u64 = 24;
    pub const TCP_PROBE_AFTER: u64 = 5;
    pub const TCP_PROBE_INTERVAL: u64 = 2;
    pub const TCP_PROBES: u64 = 12;

    /// Create from existing socket (spawned from server)
    pub fn from_socket(
        config: HashMap<String, String>,
        stream: TcpStream,
        mode: Option<super::interface::InterfaceMode>,
    ) -> Result<Self, String> {
        let mut base = Interface::new();
        let name = config.get("name").cloned().unwrap_or_else(|| "BackboneClient".to_string());
        let target_ip = config.get("target_host").cloned().unwrap_or_default();
        let target_port = config.get("target_port").and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);

        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(Self::HW_MTU);
        base.bitrate = Self::BITRATE_GUESS;
        base.autoconfigure_mtu = true;
        base.online = true;
        if let Some(m) = mode {
            base.mode = m;
        }

        let _ = stream.set_nodelay(true);
        #[cfg(target_os = "linux")]
        Self::set_timeouts_linux(&stream)?;

        Ok(BackboneClientInterface {
            base,
            target_ip,
            target_port,
            initiator: false,
            reconnecting: false,
            never_connected: false,
            detached: false,
            max_reconnect_tries: None,
            connect_timeout: Self::INITIAL_CONNECT_TIMEOUT,
            prefer_ipv6: false,
            i2p_tunneled: false,
            socket: Some(Arc::new(Mutex::new(stream))),
            frame_buffer: Vec::new(),
            transmit_buffer: Arc::new(Mutex::new(Vec::new())),
            force_read_exit: Arc::new(AtomicBool::new(false)),
            heartbeat_running: false,
        })
    }

    /// Create as initiator (client)
    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let mut base = Interface::new();
        let name = config.get("name").ok_or("BackboneClientInterface requires 'name' in config")?.clone();
        let target_ip = config.get("target_host").ok_or("BackboneClientInterface requires 'target_host'")?.clone();
        let target_port = config.get("target_port").and_then(|p| p.parse::<u16>().ok()).ok_or("Missing/invalid target_port")?;

        let prefer_ipv6 = config.get("prefer_ipv6").map(|v| parse_bool(v)).unwrap_or(false);
        let i2p_tunneled = config.get("i2p_tunneled").map(|v| parse_bool(v)).unwrap_or(false);
        let connect_timeout = config.get("connect_timeout").and_then(|v| v.parse::<u64>().ok()).unwrap_or(Self::INITIAL_CONNECT_TIMEOUT);
        let max_reconnect_tries = config.get("max_reconnect_tries").and_then(|v| v.parse::<usize>().ok());

        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(Self::HW_MTU);
        base.bitrate = Self::BITRATE_GUESS;
        base.autoconfigure_mtu = true;
        base.online = false;

        let mut interface = BackboneClientInterface {
            base,
            target_ip,
            target_port,
            initiator: true,
            reconnecting: false,
            never_connected: true,
            detached: false,
            max_reconnect_tries,
            connect_timeout,
            prefer_ipv6,
            i2p_tunneled,
            socket: None,
            frame_buffer: Vec::new(),
            transmit_buffer: Arc::new(Mutex::new(Vec::new())),
            force_read_exit: Arc::new(AtomicBool::new(false)),
            heartbeat_running: false,
        };

        interface.initial_connect()?;

        Ok(interface)
    }

    fn initial_connect(&mut self) -> Result<(), String> {
        log(
            &format!("Establishing TCP connection for {}...", self.to_string()),
            crate::LOG_DEBUG,
            false,
            false,
        );

        self.connect(true)?;

        log(
            &format!("TCP connection for {} established", self.to_string()),
            crate::LOG_DEBUG,
            false,
            false,
        );

        Ok(())
    }

    fn resolve_target_addr(target_ip: &str, target_port: u16) -> Result<SocketAddr, String> {
        let addr_str = format!("{}:{}", target_ip, target_port);
        addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}: {}", addr_str, e))?
            .next()
            .ok_or_else(|| format!("No addresses found for {}", addr_str))
    }

    fn connect(&mut self, _initial: bool) -> Result<(), String> {
        let addr = Self::resolve_target_addr(&self.target_ip, self.target_port)?;
        let stream = TcpStream::connect_timeout(
            &addr,
            Duration::from_secs(self.connect_timeout),
        ).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_nodelay(true).map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;

        #[cfg(target_os = "linux")]
        Self::set_timeouts_linux(&stream)?;

        self.socket = Some(Arc::new(Mutex::new(stream)));
        self.base.online = true;
        self.force_read_exit.store(false, Ordering::Relaxed);
        if let Some(name) = &self.base.name {
            crate::transport::Transport::set_interface_online(name, true);
        }
        self.never_connected = false;

        Ok(())
    }

    fn reconnect_until_success(iface: &Arc<Mutex<BackboneClientInterface>>) -> bool {
        let mut attempts = 0u32;
        loop {
            let (detached, max_tries) = {
                let guard = iface.lock().unwrap();
                (guard.detached, guard.max_reconnect_tries)
            };

            if detached {
                crate::log(
                    "Backbone reconnect: interface detached, giving up",
                    crate::LOG_NOTICE,
                    false,
                    false,
                );
                return false;
            }

            if let Some(max) = max_tries {
                if attempts as usize >= max {
                    crate::log(
                        &format!("Backbone reconnect: max attempts ({}) reached, giving up", max),
                        crate::LOG_ERROR,
                        false,
                        false,
                    );
                    return false;
                }
            }

            let shift = attempts.min(6) as u64;
            let wait_secs = (Self::RECONNECT_WAIT_BASE << shift).min(Self::RECONNECT_WAIT_MAX);
            thread::sleep(Duration::from_secs(wait_secs));
            attempts += 1;

            crate::log(
                &format!("Backbone reconnect attempt {}...", attempts),
                crate::LOG_NOTICE,
                false,
                false,
            );
            let ok = {
                let mut guard = iface.lock().unwrap();
                guard.connect(false).is_ok()
            };

            if ok {
                crate::log(
                    "Backbone reconnected successfully, restarting read loop",
                    crate::LOG_NOTICE,
                    false,
                    false,
                );
                return true;
            }

            crate::log(
                &format!("Backbone reconnect attempt {} failed", attempts),
                crate::LOG_WARNING,
                false,
                false,
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn set_timeouts_linux(stream: &TcpStream) -> Result<(), String> {
        Self::apply_tcp_keepalive(stream, Self::TCP_PROBE_AFTER, Self::TCP_PROBE_INTERVAL, Self::TCP_PROBES, Self::TCP_USER_TIMEOUT)
    }

    /// Apply TCP keepalive parameters to a raw socket.
    #[cfg(target_os = "linux")]
    fn apply_tcp_keepalive(stream: &TcpStream, probe_after: u64, probe_interval: u64, probes: u64, user_timeout: u64) -> Result<(), String> {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_KEEPALIVE, IPPROTO_TCP, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT, TCP_USER_TIMEOUT};

        unsafe {
            let fd = stream.as_raw_fd();
            let user_timeout_ms = (user_timeout * 1000) as i32;
            let keepalive: i32 = 1;
            let keepidle = probe_after as i32;
            let keepintvl = probe_interval as i32;
            let keepcnt = probes as i32;

            setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout_ms as *const _ as *const _, std::mem::size_of::<i32>() as u32);
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive as *const _ as *const _, std::mem::size_of::<i32>() as u32);
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle as *const _ as *const _, std::mem::size_of::<i32>() as u32);
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl as *const _ as *const _, std::mem::size_of::<i32>() as u32);
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt as *const _ as *const _, std::mem::size_of::<i32>() as u32);
        }

        Ok(())
    }

    /// Re-apply TCP keepalive settings on the live socket with a custom probe-after interval.
    /// Uses `probe_after_secs` as the idle time before first probe, derives other values proportionally.
    #[cfg(target_os = "linux")]
    pub fn set_tcp_keepalive(&self, probe_after_secs: u64) {
        if let Some(ref sock) = self.socket {
            let stream = sock.lock().unwrap();
            // Scale user_timeout proportionally: default ratio is 24/5 ≈ 4.8x probe_after
            let user_timeout = probe_after_secs * 5;
            let probe_interval = std::cmp::max(probe_after_secs / 5, 1);
            let probes = Self::TCP_PROBES;
            if let Err(e) = Self::apply_tcp_keepalive(&stream, probe_after_secs, probe_interval, probes, user_timeout) {
                crate::log(&format!("Failed to update TCP keepalive: {}", e), crate::LOG_ERROR, false, false);
            } else {
                crate::log(&format!("TCP keepalive updated: probe_after={}s interval={}s timeout={}s", probe_after_secs, probe_interval, user_timeout), crate::LOG_DEBUG, false, false);
            }
        }
    }

    /// Stub for non-Linux platforms.
    #[cfg(not(target_os = "linux"))]
    pub fn set_tcp_keepalive(&self, _probe_after_secs: u64) {}

    pub fn start_read_loop(iface: Arc<Mutex<BackboneClientInterface>>) {
        {
            let mut guard = iface.lock().unwrap();
            if guard.reconnecting {
                crate::log(
                    "Backbone start_read_loop: loop already active for this interface, ignoring duplicate call",
                    crate::LOG_WARNING,
                    false,
                    false,
                );
                return;
            }
            guard.reconnecting = true;
        }

        thread::spawn(move || {
            let mut first_iter = true;

            'running: loop {
                let socket_result = {
                    let (socket_ref, interface_name, is_initiator, force_read_exit) = {
                        let guard = iface.lock().unwrap();
                        match guard.socket.as_ref().cloned() {
                            Some(socket_ref) => (
                                socket_ref,
                                guard.base.name.clone(),
                                guard.initiator,
                                Arc::clone(&guard.force_read_exit),
                            ),
                            None => {
                                crate::log(
                                    "Backbone read loop: no socket, entering reconnect",
                                    crate::LOG_NOTICE,
                                    false,
                                    false,
                                );
                                if Self::reconnect_until_success(&iface) {
                                    continue 'running;
                                }
                                break 'running;
                            }
                        }
                    };

                    let cloned_socket = match socket_ref.lock().unwrap().try_clone() {
                        Ok(socket) => socket,
                        Err(e) => {
                            crate::log(
                                &format!("Backbone read loop: socket clone failed: {}", e),
                                crate::LOG_WARNING,
                                false,
                                false,
                            );
                            continue 'running;
                        }
                    };

                    Some((cloned_socket, interface_name, is_initiator, force_read_exit))
                };

                let (mut socket, interface_name, is_initiator, force_read_exit) =
                    socket_result.unwrap();

                if is_initiator {
                    if first_iter {
                        first_iter = false;
                    } else if let Some(name) = interface_name.as_ref() {
                        let interface_repr = iface.lock().unwrap().to_string();
                        crate::transport::Transport::synthesize_tunnel(name, &interface_repr);
                    }
                }

                if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(Self::READ_WAKE_INTERVAL))) {
                    crate::log(
                        &format!("Backbone read loop: set_read_timeout failed: {}", e),
                        crate::LOG_WARNING,
                        false,
                        false,
                    );
                }

                let mut buf = [0u8; 65536];

                'reading: loop {
                    match socket.read(&mut buf) {
                        Ok(0) => {
                            crate::log(
                                "Backbone read loop: connection closed (read 0)",
                                crate::LOG_NOTICE,
                                false,
                                false,
                            );
                            break 'reading;
                        }
                        Ok(n) => {
                            let mut guard = iface.lock().unwrap();
                            guard.receive(&buf[..n]);
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            if force_read_exit.load(Ordering::Relaxed) {
                                crate::log(
                                    "Backbone read loop: force_read_exit set by writer — exiting to reconnect",
                                    crate::LOG_WARNING,
                                    false,
                                    false,
                                );
                                break 'reading;
                            }
                        }
                        Err(e) => {
                            crate::log(
                                &format!("Read error on {}: {}", iface.lock().unwrap(), e),
                                crate::LOG_ERROR,
                                false,
                                false,
                            );
                            break 'reading;
                        }
                    }
                }

                {
                    let mut guard = iface.lock().unwrap();
                    guard.base.online = false;
                    if let Some(name) = &guard.base.name {
                        crate::transport::Transport::set_interface_online(name, false);
                    }
                    guard.socket = None;
                }

                if !is_initiator {
                    let iface_name = iface.lock().unwrap().base.name.clone();
                    if let Some(ref name) = iface_name {
                        crate::transport::Transport::deregister_interface_stub(name);
                        crate::transport::Transport::unregister_outbound_handler(name);
                        crate::log(
                            &format!("Backbone server client disconnected, deregistered interface {}", name),
                            crate::LOG_NOTICE,
                            false,
                            false,
                        );
                    }
                    break 'running;
                }

                if !Self::reconnect_until_success(&iface) {
                    break 'running;
                }
            }

            iface.lock().unwrap().reconnecting = false;
        });
    }

    fn receive(&mut self, data: &[u8]) {
        if data.is_empty() {
            self.base.online = false;
            if let Some(name) = &self.base.name {
                crate::transport::Transport::set_interface_online(name, false);
            }
            return;
        }

        self.frame_buffer.extend_from_slice(data);
        self.base.rxb += data.len() as u64;

        loop {
            let frame_start = self.frame_buffer.iter().position(|&b| b == Hdlc::FLAG);
            if frame_start.is_none() {
                break;
            }
            let frame_start = frame_start.unwrap();

            let frame_end = self.frame_buffer[frame_start + 1..].iter().position(|&b| b == Hdlc::FLAG);
            if frame_end.is_none() {
                break;
            }
            let frame_end = frame_start + 1 + frame_end.unwrap();

            let frame = self.frame_buffer[frame_start + 1..frame_end].to_vec();
            self.frame_buffer = self.frame_buffer[frame_end..].to_vec();

            let mut unescaped = Vec::new();
            let mut i = 0;
            while i < frame.len() {
                if frame[i] == Hdlc::ESC && i + 1 < frame.len() {
                    if frame[i + 1] == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                        unescaped.push(Hdlc::FLAG);
                        i += 2;
                    } else if frame[i + 1] == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                        unescaped.push(Hdlc::ESC);
                        i += 2;
                    } else {
                        unescaped.push(frame[i]);
                        i += 1;
                    }
                } else {
                    unescaped.push(frame[i]);
                    i += 1;
                }
            }

            if unescaped.len() > crate::reticulum::HEADER_MINSIZE {
                let interface_name = self.base.name.clone();
                let _ = RnsTransport::inbound(unescaped, interface_name);
            }
        }
    }

    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        if !self.base.online || self.detached {
            return Err("Interface offline or detached".to_string());
        }

        // Apply forced bitrate delay if set
        self.base.enforce_bitrate(data.len());

        let escaped = Hdlc::escape(&data);
        let mut framed = Vec::with_capacity(escaped.len() + 2);
        framed.push(Hdlc::FLAG);
        framed.extend_from_slice(&escaped);
        framed.push(Hdlc::FLAG);

        let mut transmit = self.transmit_buffer.lock().unwrap();
        transmit.extend_from_slice(&framed);

        let socket = self
            .socket
            .as_ref()
            .cloned()
            .ok_or_else(|| "No socket connection".to_string())?;

        let write_result = {
            let mut stream_guard = socket.lock().unwrap();
            match stream_guard.write(&transmit) {
                Ok(written) => {
                    self.base.txb += written as u64;
                    transmit.drain(..written);
                    Ok(())
                }
                Err(e) => {
                    let _ = stream_guard.shutdown(std::net::Shutdown::Both);
                    Err(e)
                }
            }
        };

        if let Err(e) = write_result {
            self.base.online = false;
            if let Some(name) = &self.base.name {
                crate::transport::Transport::set_interface_online(name, false);
            }
            self.force_read_exit.store(true, Ordering::Relaxed);
            transmit.clear();
            self.socket = None;
            return Err(format!("Failed to send data: {}", e));
        }

        Ok(())
    }

    pub fn start_heartbeat_loop(interface: Arc<Mutex<BackboneClientInterface>>) {
        {
            let mut iface = interface.lock().unwrap();
            if iface.heartbeat_running || !iface.initiator {
                return;
            }
            iface.heartbeat_running = true;
        }

        thread::spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(Self::HEARTBEAT_INTERVAL));

                let (detached, online, initiator, iname, irepr) = {
                    let iface = match interface.lock() {
                        Ok(guard) => guard,
                        Err(_) => break,
                    };
                    (
                        iface.detached,
                        iface.base.online,
                        iface.initiator,
                        iface.base.name.clone().unwrap_or_default(),
                        iface.to_string(),
                    )
                };

                if detached || !initiator {
                    break;
                }
                if !online {
                    continue;
                }

                crate::log(
                    &format!("[HEARTBEAT] iface={} synthesize_tunnel", iname),
                    crate::LOG_DEBUG,
                    false,
                    false,
                );
                crate::transport::Transport::synthesize_tunnel(&iname, &irepr);
            }

            if let Ok(mut iface) = interface.lock() {
                iface.heartbeat_running = false;
            }
        });
    }

    pub fn detach(&mut self) {
        self.base.online = false;
        if let Some(name) = &self.base.name {
            crate::transport::Transport::set_interface_online(name, false);
        }
        self.detached = true;
        self.force_read_exit.store(true, Ordering::Relaxed);

        if let Some(socket) = self.socket.as_ref().cloned() {
            let _ = socket.lock().unwrap().shutdown(std::net::Shutdown::Both);
        }
        self.socket = None;
    }

    pub fn to_string(&self) -> String {
        let ip_str = if self.target_ip.contains(':') {
            format!("[{}]", self.target_ip)
        } else {
            self.target_ip.clone()
        };
        format!("BackboneClientInterface[{}/{}:{}]", self.base.name.as_ref().unwrap_or(&"unnamed".to_string()), ip_str, self.target_port)
    }
}

impl std::fmt::Display for BackboneClientInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "true" | "yes" | "1" | "on"
    )
}

fn _now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::BackboneClientInterface;

    #[test]
    fn resolve_target_addr_accepts_ip_literals() {
        let addr = BackboneClientInterface::resolve_target_addr("127.0.0.1", 4242)
            .expect("resolve ip literal");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), 4242);
    }

    #[test]
    fn resolve_target_addr_accepts_hostnames() {
        let addr = BackboneClientInterface::resolve_target_addr("localhost", 4242)
            .expect("resolve hostname");
        assert_eq!(addr.port(), 4242);
    }
}
