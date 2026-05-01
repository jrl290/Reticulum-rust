use crate::config::{default_config_lines, Config, ConfigSection};
use crate::identity::Identity;
use crate::interfaces::interface::InterfaceMode;
use crate::interfaces::Interface;
#[cfg(feature = "serial")]
use crate::interfaces::RNodeInterface;
use crate::{log, LOG_DEBUG, LOG_ERROR, LOG_NOTICE, LOG_VERBOSE, LOG_WARNING};
use hkdf::Hkdf;
use once_cell::sync::Lazy;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use rmp_serde::{decode::from_slice, encode::to_vec_named};
use serde::{Deserialize, Serialize};

pub const MTU: usize = 500;
pub const TRUNCATED_HASHLENGTH: usize = 128;

pub const HEADER_MINSIZE: usize = 2 + 1 + (TRUNCATED_HASHLENGTH / 8) * 1;
pub const HEADER_MAXSIZE: usize = 2 + 1 + (TRUNCATED_HASHLENGTH / 8) * 2;
pub const IFAC_MIN_SIZE: usize = 1;
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
    0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f,
    0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

pub const MDU: usize = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE;
pub const DEFAULT_PER_HOP_TIMEOUT: f64 = 6.0;

pub const LINK_MTU_DISCOVERY: bool = true;
pub const MAX_QUEUED_ANNOUNCES: usize = 16384;
pub const QUEUED_ANNOUNCE_LIFE: f64 = 60.0 * 60.0 * 24.0;
pub const ANNOUNCE_CAP: f64 = 2.0;
pub const MINIMUM_BITRATE: u64 = 5;

pub const RESOURCE_CACHE: f64 = 24.0 * 60.0 * 60.0;
pub const JOB_INTERVAL: f64 = 5.0 * 60.0;
pub const CLEAN_INTERVAL: f64 = 15.0 * 60.0;
pub const PERSIST_INTERVAL: f64 = 60.0 * 60.0 * 12.0;
pub const GRACIOUS_PERSIST_INTERVAL: f64 = 60.0 * 5.0;

// Temporary storage path placeholder for resource transfers.
pub const RESOURCE_PATH: &str = "/tmp/reticulum/resources";

// Temporary storage path placeholders for transport persistence.
pub const STORAGE_PATH: &str = "/tmp/reticulum/storage";
pub const CACHE_PATH: &str = "/tmp/reticulum/cache";
pub const BLACKHOLE_PATH: &str = "/tmp/reticulum/blackhole";
pub const IDENTITY_PATH: &str = "/tmp/reticulum/identities";
pub const INTERFACE_PATH: &str = "/tmp/reticulum/interfaces";

#[derive(Clone, Debug)]
struct PathConfig {
    storage_path: PathBuf,
    cache_path: PathBuf,
    resource_path: PathBuf,
    identity_path: PathBuf,
    blackhole_path: PathBuf,
    interface_path: PathBuf,
}

impl Default for PathConfig {
    fn default() -> Self {
        PathConfig {
            storage_path: PathBuf::from(STORAGE_PATH),
            cache_path: PathBuf::from(CACHE_PATH),
            resource_path: PathBuf::from(RESOURCE_PATH),
            identity_path: PathBuf::from(IDENTITY_PATH),
            blackhole_path: PathBuf::from(BLACKHOLE_PATH),
            interface_path: PathBuf::from(INTERFACE_PATH),
        }
    }
}

fn handle_rpc_connection(stream: &mut RpcStream, rpc_key: &[u8]) {
    let auth_payload = match Reticulum::read_frame(stream) {
        Ok(payload) => payload,
        Err(_) => return,
    };

    let auth = match from_slice::<Vec<u8>>(&auth_payload) {
        Ok(auth) => auth,
        Err(_) => return,
    };

    if auth != rpc_key {
        let response = RpcResponse::Error("Invalid RPC key".to_string());
        if let Ok(payload) = to_vec_named(&response) {
            let _ = Reticulum::write_frame(stream, &payload);
        }
        return;
    }

    let request_payload = match Reticulum::read_frame(stream) {
        Ok(payload) => payload,
        Err(_) => return,
    };

    let request = match from_slice::<RpcRequest>(&request_payload) {
        Ok(request) => request,
        Err(_) => {
            let response = RpcResponse::Error("Invalid RPC request".to_string());
            if let Ok(payload) = to_vec_named(&response) {
                let _ = Reticulum::write_frame(stream, &payload);
            }
            return;
        }
    };

    let response = Reticulum::handle_rpc_request(request);
    if let Ok(payload) = to_vec_named(&response) {
        let _ = Reticulum::write_frame(stream, &payload);
    }
}

static PATHS: Lazy<Mutex<PathConfig>> = Lazy::new(|| Mutex::new(PathConfig::default()));

pub fn storage_path() -> PathBuf {
    PATHS.lock().unwrap().storage_path.clone()
}

pub fn cache_path() -> PathBuf {
    PATHS.lock().unwrap().cache_path.clone()
}

pub fn resource_path() -> PathBuf {
    PATHS.lock().unwrap().resource_path.clone()
}

pub fn identity_path() -> PathBuf {
    PATHS.lock().unwrap().identity_path.clone()
}

pub fn blackhole_path() -> PathBuf {
    PATHS.lock().unwrap().blackhole_path.clone()
}

pub fn interface_path() -> PathBuf {
    PATHS.lock().unwrap().interface_path.clone()
}

#[derive(Clone, Debug)]
struct ReticulumFlags {
    transport_enabled: bool,
    link_mtu_discovery: bool,
    remote_management_enabled: bool,
    allow_probes: bool,
    use_implicit_proof: bool,
    panic_on_interface_error: bool,
    discovery_enabled: bool,
    discover_interfaces: bool,
    autoconnect_discovered_interfaces: usize,
    required_discovery_value: Option<u32>,
    publish_blackhole: bool,
    blackhole_sources: Vec<Vec<u8>>,
    interface_sources: Vec<Vec<u8>>,
}

impl Default for ReticulumFlags {
    fn default() -> Self {
        ReticulumFlags {
            transport_enabled: false,
            link_mtu_discovery: LINK_MTU_DISCOVERY,
            remote_management_enabled: false,
            allow_probes: false,
            use_implicit_proof: true,
            panic_on_interface_error: false,
            discovery_enabled: false,
            discover_interfaces: false,
            autoconnect_discovered_interfaces: 0,
            required_discovery_value: None,
            publish_blackhole: false,
            blackhole_sources: Vec::new(),
            interface_sources: Vec::new(),
        }
    }
}

static FLAGS: Lazy<Mutex<ReticulumFlags>> = Lazy::new(|| Mutex::new(ReticulumFlags::default()));

#[allow(dead_code)]
pub struct Reticulum {
    pub config_dir: PathBuf,
    pub config_path: PathBuf,
    pub storage_path: PathBuf,
    pub cache_path: PathBuf,
    pub resource_path: PathBuf,
    pub identity_path: PathBuf,
    pub blackhole_path: PathBuf,
    pub interface_path: PathBuf,
    system_interfaces: Vec<SystemInterface>,
    pub config: Config,
    pub share_instance: bool,
    pub require_shared: bool,
    pub shared_instance_type: Option<String>,
    pub use_af_unix: bool,
    pub is_shared_instance: bool,
    pub is_connected_to_shared_instance: bool,
    pub is_standalone_instance: bool,
    pub local_interface_port: u16,
    pub local_control_port: u16,
    pub local_socket_path: Option<String>,
    pub rpc_key: Option<Vec<u8>>,
    pub rpc_addr: Option<String>,
    pub jobs_thread_running: bool,
    pub last_data_persist: f64,
    pub last_cache_clean: f64,
    pub bootstrap_configs: Vec<HashMap<String, String>>,
    pub requested_loglevel: Option<i32>,
    pub requested_verbosity: Option<i32>,
}

#[allow(dead_code)]
enum SystemInterface {
    Udp(Arc<Mutex<crate::interfaces::udp_interface::UdpInterface>>),
    TcpServer(Arc<Mutex<crate::interfaces::tcp_interface::TcpServerInterface>>),
    TcpClient(Arc<Mutex<crate::interfaces::tcp_interface::TcpClientInterface>>),
    Pipe(Arc<Mutex<crate::interfaces::pipe_interface::PipeInterface>>),
    Auto(Arc<crate::interfaces::auto_interface::AutoInterface>),
    #[cfg(feature = "serial")]
    Serial(Arc<Mutex<crate::interfaces::serial_interface::SerialInterface>>),
    #[cfg(feature = "serial")]
    Kiss(Arc<Mutex<crate::interfaces::kiss_interface::KissInterface>>),
    Backbone(Arc<Mutex<crate::interfaces::backbone_interface::BackboneInterface>>),
    BackboneClient(Arc<Mutex<crate::interfaces::backbone_interface::BackboneClientInterface>>),
    I2P(Arc<Mutex<crate::interfaces::i2p::I2PInterface>>),
    I2PPeer(Arc<Mutex<crate::interfaces::i2p::I2PInterfacePeer>>),
    #[cfg(feature = "serial")]
    RNode(Arc<Mutex<RNodeInterface>>),
}

#[derive(Serialize, Deserialize)]
enum RpcRequest {
    Get {
        path: String,
        max_hops: Option<u8>,
        destination_hash: Option<Vec<u8>>,
        packet_hash: Option<Vec<u8>>,
    },
    Drop {
        path: String,
        destination_hash: Option<Vec<u8>>,
    },
    BlackholeIdentity {
        identity_hash: Vec<u8>,
        until: Option<f64>,
        reason: Option<String>,
    },
    UnblackholeIdentity {
        identity_hash: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize)]
enum RpcResponse {
    InterfaceStats(HashMap<String, String>),
    PathTable(Vec<HashMap<String, String>>),
    RateTable(Vec<HashMap<String, String>>),
    NextHopIfName(Option<String>),
    NextHop(Option<Vec<u8>>),
    FirstHopTimeout(f64),
    LinkCount(usize),
    PacketRssi(Option<f64>),
    PacketSnr(Option<f64>),
    PacketQ(Option<f64>),
    BlackholedIdentities(HashMap<Vec<u8>, crate::transport::BlackholeEntry>),
    DropPath(bool),
    DropAllVia(usize),
    DropAnnounceQueues(usize),
    BlackholeResult(bool),
    UnblackholeResult(bool),
    Error(String),
}

enum RpcStream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl RpcStream {
    fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            RpcStream::Tcp(stream) => stream.read_exact(buf),
            RpcStream::Unix(stream) => stream.read_exact(buf),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            RpcStream::Tcp(stream) => stream.write_all(buf),
            RpcStream::Unix(stream) => stream.write_all(buf),
        }
    }
}

static INSTANCE: Lazy<Mutex<Option<Arc<Mutex<Reticulum>>>>> = Lazy::new(|| Mutex::new(None));
static LOCAL_SERVER: Lazy<Mutex<Option<crate::interfaces::local_interface::LocalServerInterface>>> =
    Lazy::new(|| Mutex::new(None));
static LOCAL_CLIENT: Lazy<Mutex<Option<Arc<Mutex<crate::interfaces::local_interface::LocalClientInterface>>>>> =
    Lazy::new(|| Mutex::new(None));

#[allow(dead_code)]
impl Reticulum {
    pub fn init_default() -> Result<(), String> {
        Self::init(None, None, None, None, false, None)
    }

    pub fn init(
        config_dir: Option<PathBuf>,
        loglevel: Option<i32>,
        _logdest: Option<i32>,
        verbosity: Option<i32>,
        require_shared_instance: bool,
        shared_instance_type: Option<String>,
    ) -> Result<(), String> {
        let mut instance = INSTANCE.lock().unwrap();
        if instance.is_some() {
            return Err("Reticulum is already initialised".to_string());
        }

        let mut reticulum = Reticulum::new(
            config_dir,
            loglevel,
            verbosity,
            require_shared_instance,
            shared_instance_type,
        )?;
        reticulum.start();
        *instance = Some(Arc::new(Mutex::new(reticulum)));
        Ok(())
    }

    pub fn get_instance() -> Option<Arc<Mutex<Reticulum>>> {
        INSTANCE.lock().unwrap().clone()
    }

    fn get_interface_stats_local() -> HashMap<String, String> {
        let snapshot = crate::transport::get_state_snapshot();
        let mut stats = HashMap::new();
        stats.insert("interfaces".to_string(), snapshot.interfaces.len().to_string());
        stats.insert("rxb".to_string(), snapshot.traffic_rxb.to_string());
        stats.insert("txb".to_string(), snapshot.traffic_txb.to_string());
        stats.insert("rxs".to_string(), snapshot.speed_rx.to_string());
        stats.insert("txs".to_string(), snapshot.speed_tx.to_string());
        stats
    }

    fn get_path_table_local(max_hops: Option<u8>) -> Vec<HashMap<String, String>> {
        let snapshot = crate::transport::get_state_snapshot();
        let mut out = Vec::new();
        for (hash, entry) in snapshot.path_table {
            if let Some(limit) = max_hops {
                if let Some(crate::transport::PathEntryValue::Hops(hops)) = entry.get(crate::transport::IDX_PT_HOPS) {
                    if *hops > limit {
                        continue;
                    }
                }
            }
            let mut map = HashMap::new();
            map.insert("hash".to_string(), crate::hexrep(&hash, false));
            if let Some(crate::transport::PathEntryValue::Timestamp(ts)) = entry.get(crate::transport::IDX_PT_TIMESTAMP) {
                map.insert("timestamp".to_string(), ts.to_string());
            }
            if let Some(crate::transport::PathEntryValue::NextHop(next)) = entry.get(crate::transport::IDX_PT_NEXT_HOP) {
                map.insert("via".to_string(), crate::hexrep(next, false));
            }
            if let Some(crate::transport::PathEntryValue::Hops(hops)) = entry.get(crate::transport::IDX_PT_HOPS) {
                map.insert("hops".to_string(), hops.to_string());
            }
            if let Some(crate::transport::PathEntryValue::Expires(expires)) = entry.get(crate::transport::IDX_PT_EXPIRES) {
                map.insert("expires".to_string(), expires.to_string());
            }
            out.push(map);
        }
        out
    }

    fn get_rate_table_local() -> Vec<HashMap<String, String>> {
        let snapshot = crate::transport::get_state_snapshot();
        let mut out = Vec::new();
        for (hash, entry) in snapshot.announce_rate_table {
            let mut map = HashMap::new();
            map.insert("hash".to_string(), crate::hexrep(&hash, false));
            map.insert("last".to_string(), entry.last.to_string());
            map.insert("rate_violations".to_string(), entry.rate_violations.to_string());
            map.insert("blocked_until".to_string(), entry.blocked_until.to_string());
            out.push(map);
        }
        out
    }

    fn drop_all_via_local(transport_hash: &[u8]) -> usize {
        let snapshot = crate::transport::get_state_snapshot();
        let mut dropped = 0;
        for (dest_hash, entry) in snapshot.path_table {
            if let Some(crate::transport::PathEntryValue::NextHop(next)) = entry.get(crate::transport::IDX_PT_NEXT_HOP) {
                if next == transport_hash {
                    if crate::transport::Transport::expire_path(&dest_hash) {
                        dropped += 1;
                    }
                }
            }
        }
        dropped
    }

    fn get_link_count_local() -> usize {
        let snapshot = crate::transport::get_state_snapshot();
        snapshot.link_table_len
    }

    fn get_packet_rssi_local(packet_hash: &[u8]) -> Option<f64> {
        let snapshot = crate::transport::get_state_snapshot();
        snapshot
            .local_client_rssi_cache
            .iter()
            .find(|(hash, _)| hash.as_slice() == packet_hash)
            .map(|(_, rssi)| *rssi)
    }

    fn get_packet_snr_local(packet_hash: &[u8]) -> Option<f64> {
        let snapshot = crate::transport::get_state_snapshot();
        snapshot
            .local_client_snr_cache
            .iter()
            .find(|(hash, _)| hash.as_slice() == packet_hash)
            .map(|(_, snr)| *snr)
    }

    fn get_packet_q_local(packet_hash: &[u8]) -> Option<f64> {
        let snapshot = crate::transport::get_state_snapshot();
        snapshot
            .local_client_q_cache
            .iter()
            .find(|(hash, _)| hash.as_slice() == packet_hash)
            .map(|(_, q)| *q)
    }

    fn get_blackholed_identities_local() -> HashMap<Vec<u8>, crate::transport::BlackholeEntry> {
        let snapshot = crate::transport::get_state_snapshot();
        snapshot.blackholed_identities
    }

    fn rpc_socket_path(&self) -> Option<String> {
        let name = self.local_socket_path.as_deref().unwrap_or("default");
        Some(self.config_dir.join(format!("rns_{}_rpc.sock", name)).to_string_lossy().to_string())
    }

    fn write_frame(stream: &mut RpcStream, data: &[u8]) -> std::io::Result<()> {
        let len = (data.len() as u32).to_be_bytes();
        stream.write_all(&len)?;
        stream.write_all(data)
    }

    fn read_frame(stream: &mut RpcStream) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 16 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "RPC frame too large"));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn rpc_call(&self, request: RpcRequest) -> Option<RpcResponse> {
        let mut stream = if self.use_af_unix {
            let path = self.rpc_socket_path()?;
            let socket = UnixStream::connect(path).ok()?;
            RpcStream::Unix(socket)
        } else {
            let addr = format!("127.0.0.1:{}", self.local_control_port);
            let socket = TcpStream::connect(addr).ok()?;
            RpcStream::Tcp(socket)
        };

        let auth = self.rpc_key.clone().unwrap_or_default();
        let auth_payload = to_vec_named(&auth).ok()?;
        Self::write_frame(&mut stream, &auth_payload).ok()?;

        let payload = to_vec_named(&request).ok()?;
        Self::write_frame(&mut stream, &payload).ok()?;

        let response_payload = Self::read_frame(&mut stream).ok()?;
        from_slice::<RpcResponse>(&response_payload).ok()
    }

    fn handle_rpc_request(request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::Get {
                path,
                max_hops,
                destination_hash,
                packet_hash,
            } => match path.as_str() {
                "path_table" => RpcResponse::PathTable(Self::get_path_table_local(max_hops)),
                "interface_stats" => RpcResponse::InterfaceStats(Self::get_interface_stats_local()),
                "rate_table" => RpcResponse::RateTable(Self::get_rate_table_local()),
                "next_hop_if_name" => RpcResponse::NextHopIfName(
                    destination_hash
                        .as_deref()
                        .and_then(crate::transport::Transport::next_hop_interface),
                ),
                "next_hop" => RpcResponse::NextHop(
                    destination_hash
                        .as_deref()
                        .and_then(crate::transport::Transport::next_hop),
                ),
                "first_hop_timeout" => RpcResponse::FirstHopTimeout(
                    destination_hash
                        .as_deref()
                        .map(crate::transport::Transport::first_hop_timeout)
                        .unwrap_or(DEFAULT_PER_HOP_TIMEOUT),
                ),
                "link_count" => RpcResponse::LinkCount(Self::get_link_count_local()),
                "packet_rssi" => RpcResponse::PacketRssi(
                    packet_hash
                        .as_deref()
                        .and_then(Self::get_packet_rssi_local),
                ),
                "packet_snr" => RpcResponse::PacketSnr(
                    packet_hash
                        .as_deref()
                        .and_then(Self::get_packet_snr_local),
                ),
                "packet_q" => RpcResponse::PacketQ(
                    packet_hash
                        .as_deref()
                        .and_then(Self::get_packet_q_local),
                ),
                "blackholed_identities" => {
                    RpcResponse::BlackholedIdentities(Self::get_blackholed_identities_local())
                }
                _ => RpcResponse::Error(format!("Unknown RPC get path {}", path)),
            },
            RpcRequest::Drop { path, destination_hash } => match path.as_str() {
                "path" => RpcResponse::DropPath(
                    destination_hash
                        .as_deref()
                        .map(crate::transport::Transport::expire_path)
                        .unwrap_or(false),
                ),
                "all_via" => RpcResponse::DropAllVia(
                    destination_hash
                        .as_deref()
                        .map(Self::drop_all_via_local)
                        .unwrap_or(0),
                ),
                "announce_queues" => {
                    RpcResponse::DropAnnounceQueues(crate::transport::Transport::drop_announce_queues())
                }
                _ => RpcResponse::Error(format!("Unknown RPC drop path {}", path)),
            },
            RpcRequest::BlackholeIdentity {
                identity_hash,
                until,
                reason,
            } => RpcResponse::BlackholeResult(crate::transport::Transport::blackhole_identity(
                identity_hash,
                until,
                reason,
            )),
            RpcRequest::UnblackholeIdentity { identity_hash } => {
                RpcResponse::UnblackholeResult(crate::transport::Transport::unblackhole_identity(
                    identity_hash,
                ))
            }
        }
    }

    pub fn get_interface_stats(&self) -> HashMap<String, String> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::InterfaceStats(stats)) = self.rpc_call(RpcRequest::Get {
                path: "interface_stats".to_string(),
                max_hops: None,
                destination_hash: None,
                packet_hash: None,
            }) {
                return stats;
            }
            return HashMap::new();
        }
        Self::get_interface_stats_local()
    }

    pub fn get_path_table(&self, max_hops: Option<u8>) -> Vec<HashMap<String, String>> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::PathTable(table)) = self.rpc_call(RpcRequest::Get {
                path: "path_table".to_string(),
                max_hops,
                destination_hash: None,
                packet_hash: None,
            }) {
                return table;
            }
            return Vec::new();
        }
        Self::get_path_table_local(max_hops)
    }

    pub fn get_rate_table(&self) -> Vec<HashMap<String, String>> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::RateTable(table)) = self.rpc_call(RpcRequest::Get {
                path: "rate_table".to_string(),
                max_hops: None,
                destination_hash: None,
                packet_hash: None,
            }) {
                return table;
            }
            return Vec::new();
        }
        Self::get_rate_table_local()
    }

    pub fn drop_path(&self, destination: &[u8]) -> bool {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::DropPath(result)) = self.rpc_call(RpcRequest::Drop {
                path: "path".to_string(),
                destination_hash: Some(destination.to_vec()),
            }) {
                return result;
            }
            return false;
        }
        crate::transport::Transport::expire_path(destination)
    }

    pub fn drop_all_via(&self, transport_hash: &[u8]) -> usize {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::DropAllVia(result)) = self.rpc_call(RpcRequest::Drop {
                path: "all_via".to_string(),
                destination_hash: Some(transport_hash.to_vec()),
            }) {
                return result;
            }
            return 0;
        }
        Self::drop_all_via_local(transport_hash)
    }

    pub fn drop_announce_queues(&self) -> usize {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::DropAnnounceQueues(result)) = self.rpc_call(RpcRequest::Drop {
                path: "announce_queues".to_string(),
                destination_hash: None,
            }) {
                return result;
            }
            return 0;
        }
        crate::transport::Transport::drop_announce_queues()
    }

    pub fn get_next_hop_if_name(&self, destination: &[u8]) -> Option<String> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::NextHopIfName(name)) = self.rpc_call(RpcRequest::Get {
                path: "next_hop_if_name".to_string(),
                max_hops: None,
                destination_hash: Some(destination.to_vec()),
                packet_hash: None,
            }) {
                return name;
            }
            return None;
        }
        crate::transport::Transport::next_hop_interface(destination)
    }

    pub fn get_first_hop_timeout(&self, destination: &[u8]) -> f64 {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::FirstHopTimeout(timeout)) = self.rpc_call(RpcRequest::Get {
                path: "first_hop_timeout".to_string(),
                max_hops: None,
                destination_hash: Some(destination.to_vec()),
                packet_hash: None,
            }) {
                return timeout;
            }
            return crate::reticulum::DEFAULT_PER_HOP_TIMEOUT;
        }
        crate::transport::Transport::first_hop_timeout(destination)
    }

    pub fn get_next_hop(&self, destination: &[u8]) -> Option<Vec<u8>> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::NextHop(next)) = self.rpc_call(RpcRequest::Get {
                path: "next_hop".to_string(),
                max_hops: None,
                destination_hash: Some(destination.to_vec()),
                packet_hash: None,
            }) {
                return next;
            }
            return None;
        }
        crate::transport::Transport::next_hop(destination)
    }

    pub fn get_link_count(&self) -> usize {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::LinkCount(count)) = self.rpc_call(RpcRequest::Get {
                path: "link_count".to_string(),
                max_hops: None,
                destination_hash: None,
                packet_hash: None,
            }) {
                return count;
            }
            return 0;
        }
        Self::get_link_count_local()
    }

    pub fn get_packet_rssi(&self, packet_hash: &[u8]) -> Option<f64> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::PacketRssi(rssi)) = self.rpc_call(RpcRequest::Get {
                path: "packet_rssi".to_string(),
                max_hops: None,
                destination_hash: None,
                packet_hash: Some(packet_hash.to_vec()),
            }) {
                return rssi;
            }
            return None;
        }
        Self::get_packet_rssi_local(packet_hash)
    }

    pub fn get_packet_snr(&self, packet_hash: &[u8]) -> Option<f64> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::PacketSnr(snr)) = self.rpc_call(RpcRequest::Get {
                path: "packet_snr".to_string(),
                max_hops: None,
                destination_hash: None,
                packet_hash: Some(packet_hash.to_vec()),
            }) {
                return snr;
            }
            return None;
        }
        Self::get_packet_snr_local(packet_hash)
    }

    pub fn get_packet_q(&self, packet_hash: &[u8]) -> Option<f64> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::PacketQ(q)) = self.rpc_call(RpcRequest::Get {
                path: "packet_q".to_string(),
                max_hops: None,
                destination_hash: None,
                packet_hash: Some(packet_hash.to_vec()),
            }) {
                return q;
            }
            return None;
        }
        Self::get_packet_q_local(packet_hash)
    }

    pub fn get_blackholed_identities(&self) -> HashMap<Vec<u8>, crate::transport::BlackholeEntry> {
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::BlackholedIdentities(identities)) = self.rpc_call(RpcRequest::Get {
                path: "blackholed_identities".to_string(),
                max_hops: None,
                destination_hash: None,
                packet_hash: None,
            }) {
                return identities;
            }
            return HashMap::new();
        }
        Self::get_blackholed_identities_local()
    }

    pub fn blackhole_identity(&self, identity_hash: Vec<u8>, until: Option<f64>, reason: Option<String>) -> bool {
        if identity_hash.len() != crate::reticulum::TRUNCATED_HASHLENGTH / 8 {
            return false;
        }
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::BlackholeResult(result)) = self.rpc_call(RpcRequest::BlackholeIdentity {
                identity_hash,
                until,
                reason,
            }) {
                return result;
            }
            return false;
        }
        crate::transport::Transport::blackhole_identity(identity_hash, until, reason)
    }

    pub fn unblackhole_identity(&self, identity_hash: Vec<u8>) -> bool {
        if identity_hash.len() != crate::reticulum::TRUNCATED_HASHLENGTH / 8 {
            return false;
        }
        if self.is_connected_to_shared_instance {
            if let Some(RpcResponse::UnblackholeResult(result)) = self.rpc_call(RpcRequest::UnblackholeIdentity {
                identity_hash,
            }) {
                return result;
            }
            return false;
        }
        crate::transport::Transport::unblackhole_identity(identity_hash)
    }

    pub fn discovered_interfaces() -> Vec<crate::discovery::InterfaceInfo> {
        let required = required_discovery_value();
        let discovery = crate::discovery::InterfaceDiscovery::new(required, None, false);
        if let Ok(discovery) = discovery {
            discovery.list_discovered_interfaces(false, false)
        } else {
            Vec::new()
        }
    }

    fn new(
        config_dir: Option<PathBuf>,
        loglevel: Option<i32>,
        verbosity: Option<i32>,
        require_shared_instance: bool,
        shared_instance_type: Option<String>,
    ) -> Result<Self, String> {
        let config_dir = config_dir.unwrap_or_else(default_config_dir);
        let config_path = config_dir.join("config");
        let storage_path = config_dir.join("storage");
        let cache_path = storage_path.join("cache");
        let resource_path = storage_path.join("resources");
        let identity_path = storage_path.join("identities");
        let blackhole_path = storage_path.join("blackhole");
        let interface_path = config_dir.join("interfaces");

        ensure_dir(&storage_path)?;
        ensure_dir(&cache_path)?;
        ensure_dir(&resource_path)?;
        ensure_dir(&identity_path)?;
        ensure_dir(&blackhole_path)?;
        ensure_dir(&cache_path.join("announces"))?;

        let config = if config_path.exists() {
            Config::from_file(&config_path)?
        } else {
            create_default_config(&config_path, &config_dir)?;
            Config::from_file(&config_path)?
        };

        let mut reticulum = Reticulum {
            config_dir,
            config_path,
            storage_path,
            cache_path,
            resource_path,
            identity_path,
            blackhole_path,
            interface_path,
            system_interfaces: Vec::new(),
            config,
            share_instance: true,
            require_shared: require_shared_instance,
            shared_instance_type,
            use_af_unix: false,
            is_shared_instance: false,
            is_connected_to_shared_instance: false,
            is_standalone_instance: false,
            local_interface_port: 37428,
            local_control_port: 37429,
            local_socket_path: None,
            rpc_key: None,
            rpc_addr: None,
            jobs_thread_running: false,
            last_data_persist: now(),
            last_cache_clean: 0.0,
            bootstrap_configs: Vec::new(),
            requested_loglevel: loglevel,
            requested_verbosity: verbosity,
        };

        reticulum.apply_config()?;
        reticulum.configure_paths();

        Ok(reticulum)
    }

    fn start(&mut self) {
        crate::transport::Transport::start(self.is_connected_to_shared_instance, transport_enabled());
        self.start_local_interface();
        self.load_system_interfaces();

        if self.rpc_key.is_none() {
            self.rpc_key = crate::transport::Transport::rpc_key();
        }

        if self.is_shared_instance {
            self.start_rpc_listener();
        }

        if self.is_shared_instance || self.is_standalone_instance {
            self.start_jobs();
        }

        if self.is_shared_instance || self.is_standalone_instance {
            if discovery_enabled() {
                crate::transport::Transport::enable_discovery();
            }
            if discover_interfaces_enabled() {
                crate::transport::Transport::discover_interfaces();
            }
            if publish_blackhole_enabled() {
                crate::transport::Transport::enable_blackhole_updater();
            }
        }
    }

    fn apply_config(&mut self) -> Result<(), String> {
        if let Some(logging) = self.config.get_section("logging") {
            if let Some(level) = logging.get_int("loglevel") {
                if self.requested_loglevel.is_none() {
                    let mut loglevel = level as i32;
                    if let Some(verbosity) = self.requested_verbosity {
                        loglevel += verbosity;
                    }
                    if loglevel < 0 {
                        loglevel = 0;
                    }
                    if loglevel > 7 {
                        loglevel = 7;
                    }
                    crate::set_loglevel(loglevel);
                }
            }
        }

        if let Some(level) = self.requested_loglevel {
            let mut loglevel = level;
            if let Some(verbosity) = self.requested_verbosity {
                loglevel += verbosity;
            }
            if loglevel < crate::LOG_CRITICAL {
                loglevel = crate::LOG_CRITICAL;
            }
            if loglevel > crate::LOG_EXTREME {
                loglevel = crate::LOG_EXTREME;
            }
            crate::set_loglevel(loglevel);
        }

        if let Some(reticulum) = self.config.get_section("reticulum") {
            if let Some(share) = reticulum.get_bool("share_instance") {
                self.share_instance = share;
            }

            if let Some(instance_name) = reticulum.get("instance_name") {
                if !instance_name.is_empty() {
                    self.local_socket_path = Some(instance_name.to_string());
                }
            }

            if let Some(value) = reticulum.get("shared_instance_type") {
                if self.shared_instance_type.is_none() {
                    self.shared_instance_type = Some(value.to_lowercase());
                }
            }

            if let Some(port) = reticulum.get_int("shared_instance_port") {
                if port > 0 {
                    self.local_interface_port = port as u16;
                }
            }

            if let Some(port) = reticulum.get_int("instance_control_port") {
                if port > 0 {
                    self.local_control_port = port as u16;
                }
            }

            if let Some(key) = reticulum.get("rpc_key") {
                if let Some(bytes) = hex_to_bytes(key) {
                    self.rpc_key = Some(bytes);
                } else {
                    log("Invalid shared instance RPC key specified, falling back to default key", LOG_ERROR, false, false);
                    self.rpc_key = None;
                }
            }

            if reticulum.get_bool("enable_transport").unwrap_or(false) {
                FLAGS.lock().unwrap().transport_enabled = true;
            }

            if let Some(path) = reticulum.get("network_identity") {
                if !crate::transport::Transport::has_network_identity() {
                    let identity_path = expand_user_path(path);
                    let identity = if identity_path.exists() {
                        Identity::from_file(&identity_path)
                            .map_err(|err| format!("Could not load network identity: {}", err))?
                    } else {
                        let identity = Identity::new(true);
                        identity.to_file(&identity_path)
                            .map_err(|err| format!("Could not persist network identity: {}", err))?;
                        identity
                    };
                    crate::transport::Transport::set_network_identity(identity);
                }
            }

            if reticulum.get_bool("link_mtu_discovery").unwrap_or(false) {
                FLAGS.lock().unwrap().link_mtu_discovery = true;
            }

            if reticulum.get_bool("enable_remote_management").unwrap_or(false) {
                FLAGS.lock().unwrap().remote_management_enabled = true;
            }

            if let Some(allowed) = reticulum.get_list("remote_management_allowed") {
                for hexhash in allowed {
                    if let Some(bytes) = hex_to_bytes(&hexhash) {
                        crate::transport::Transport::add_remote_management_allowed(bytes);
                    } else {
                        return Err(format!("Invalid identity hash for remote management ACL: {}", hexhash));
                    }
                }
            }

            if reticulum.get_bool("respond_to_probes").unwrap_or(false) {
                FLAGS.lock().unwrap().allow_probes = true;
            }

            if let Some(value) = reticulum.get_int("force_shared_instance_bitrate") {
                crate::transport::Transport::set_forced_shared_bitrate(value as u64);
            }

            if reticulum.get_bool("panic_on_interface_error").unwrap_or(false) {
                FLAGS.lock().unwrap().panic_on_interface_error = true;
            }

            if let Some(value) = reticulum.get_bool("use_implicit_proof") {
                FLAGS.lock().unwrap().use_implicit_proof = value;
            }

            if let Some(value) = reticulum.get_bool("discover_interfaces") {
                FLAGS.lock().unwrap().discover_interfaces = value;
            }

            if let Some(value) = reticulum.get_int("required_discovery_value") {
                if value > 0 {
                    FLAGS.lock().unwrap().required_discovery_value = Some(value as u32);
                }
            }

            if let Some(value) = reticulum.get_bool("publish_blackhole") {
                FLAGS.lock().unwrap().publish_blackhole = value;
            }

            if let Some(list) = reticulum.get_list("blackhole_sources") {
                for hexhash in list {
                    if let Some(bytes) = hex_to_bytes(&hexhash) {
                        FLAGS.lock().unwrap().blackhole_sources.push(bytes);
                    } else {
                        return Err(format!("Invalid identity hash for blackhole source: {}", hexhash));
                    }
                }
            }

            if let Some(list) = reticulum.get_list("interface_discovery_sources") {
                for hexhash in list {
                    if let Some(bytes) = hex_to_bytes(&hexhash) {
                        FLAGS.lock().unwrap().interface_sources.push(bytes);
                    } else {
                        return Err(format!("Invalid identity hash for interface discovery source: {}", hexhash));
                    }
                }
            }

            if let Some(value) = reticulum.get_int("autoconnect_discovered_interfaces") {
                if value > 0 {
                    FLAGS.lock().unwrap().autoconnect_discovered_interfaces = value as usize;
                }
            }
        }

        self.configure_shared_instance_defaults();
        Ok(())
    }

    fn configure_shared_instance_defaults(&mut self) {
        if supports_af_unix() {
            if self.shared_instance_type.as_deref() == Some("tcp") {
                self.use_af_unix = false;
            } else {
                self.use_af_unix = true;
            }
        } else {
            self.shared_instance_type = Some("tcp".to_string());
            self.use_af_unix = false;
        }

        if self.local_socket_path.is_none() && self.use_af_unix {
            self.local_socket_path = Some("default".to_string());
        }
    }

    fn configure_paths(&self) {
        let mut paths = PATHS.lock().unwrap();
        *paths = PathConfig {
            storage_path: self.storage_path.clone(),
            cache_path: self.cache_path.clone(),
            resource_path: self.resource_path.clone(),
            identity_path: self.identity_path.clone(),
            blackhole_path: self.blackhole_path.clone(),
            interface_path: self.interface_path.clone(),
        };
    }

    fn start_jobs(&mut self) {
        if self.jobs_thread_running {
            return;
        }
        self.jobs_thread_running = true;
        let storage_path = self.storage_path.clone();
        let resource_path = self.resource_path.clone();
        let cache_path = self.cache_path.clone();
        let job_interval = JOB_INTERVAL;
        let clean_interval = CLEAN_INTERVAL;
        let persist_interval = GRACIOUS_PERSIST_INTERVAL;

        thread::spawn(move || {
            let mut last_cache_clean = 0.0;
            let mut last_persist = now();
            loop {
                let now_ts = now();
                if now_ts > last_cache_clean + clean_interval {
                    clean_caches(&resource_path, &cache_path);
                    last_cache_clean = now();
                }

                if now_ts > last_persist + persist_interval {
                    crate::transport::Transport::persist_data();
                    crate::identity::persist_data();
                    last_persist = now();
                }

                let _ = &storage_path;
                thread::sleep(Duration::from_secs_f64(job_interval));
            }
        });
    }

    fn start_local_interface(&mut self) {
        if !self.share_instance {
            self.is_shared_instance = false;
            self.is_standalone_instance = true;
            self.is_connected_to_shared_instance = false;
            return;
        }

        if self.use_af_unix {
            if let Some(ref path) = self.local_socket_path {
                let socket_path = self.local_socket_full_path(path);
                if let Ok(mut interface) = crate::interfaces::local_interface::LocalServerInterface::on_socket(socket_path.clone()) {
                    interface.base.out_enabled = true;
                    if let Some(bitrate) = crate::transport::Transport::forced_shared_bitrate() {
                        interface.base.bitrate = bitrate;
                        interface.base.optimise_mtu();
                    }
                    self.is_shared_instance = true;
                    self.is_standalone_instance = false;
                    self.is_connected_to_shared_instance = false;
                    crate::transport::Transport::register_local_server_interface(&interface.to_string());
                    *LOCAL_SERVER.lock().unwrap() = Some(interface);
                    if self.require_shared {
                        return;
                    }
                } else if let Ok(mut client) = crate::interfaces::local_interface::LocalClientInterface::connect_to_socket(
                    "Local shared instance".to_string(),
                    socket_path,
                ) {
                    client.base.out_enabled = true;
                    if let Some(bitrate) = crate::transport::Transport::forced_shared_bitrate() {
                        client.base.bitrate = bitrate;
                        client.base._force_bitrate = true;
                        client.base.optimise_mtu();
                    }
                    self.is_shared_instance = false;
                    self.is_standalone_instance = false;
                    self.is_connected_to_shared_instance = true;
                    FLAGS.lock().unwrap().transport_enabled = false;
                    FLAGS.lock().unwrap().remote_management_enabled = false;
                    FLAGS.lock().unwrap().allow_probes = false;
                    let client = Arc::new(Mutex::new(client));
                    let name = client.lock().unwrap().to_string();
                    let handler_iface = Arc::clone(&client);
                    crate::transport::Transport::register_outbound_handler(
                        &name,
                        Arc::new(move |raw| {
                            let mut iface = handler_iface.lock().unwrap();
                            iface.process_outgoing(raw.to_vec()).is_ok()
                        }),
                    );
                    crate::transport::Transport::register_local_client_interface(&name);
                    crate::interfaces::local_interface::LocalClientInterface::start_read_loop(Arc::clone(&client));
                    *LOCAL_CLIENT.lock().unwrap() = Some(client);
                } else {
                    self.is_shared_instance = false;
                    self.is_standalone_instance = true;
                    self.is_connected_to_shared_instance = false;
                }
            }
        } else {
            if let Ok(mut interface) = crate::interfaces::local_interface::LocalServerInterface::on_port(self.local_interface_port) {
                interface.base.out_enabled = true;
                if let Some(bitrate) = crate::transport::Transport::forced_shared_bitrate() {
                    interface.base.bitrate = bitrate;
                    interface.base.optimise_mtu();
                }
                self.is_shared_instance = true;
                self.is_standalone_instance = false;
                self.is_connected_to_shared_instance = false;
                crate::transport::Transport::register_local_server_interface(&interface.to_string());
                *LOCAL_SERVER.lock().unwrap() = Some(interface);
                if self.require_shared {
                    return;
                }
                } else if let Ok(mut client) = crate::interfaces::local_interface::LocalClientInterface::connect_to_port(
                "Local shared instance".to_string(),
                self.local_interface_port,
            ) {
                client.base.out_enabled = true;
                if let Some(bitrate) = crate::transport::Transport::forced_shared_bitrate() {
                    client.base.bitrate = bitrate;
                    client.base._force_bitrate = true;
                    client.base.optimise_mtu();
                }
                self.is_shared_instance = false;
                self.is_standalone_instance = false;
                self.is_connected_to_shared_instance = true;
                FLAGS.lock().unwrap().transport_enabled = false;
                FLAGS.lock().unwrap().remote_management_enabled = false;
                FLAGS.lock().unwrap().allow_probes = false;
                let client = Arc::new(Mutex::new(client));
                let name = client.lock().unwrap().to_string();
                let handler_iface = Arc::clone(&client);
                crate::transport::Transport::register_outbound_handler(
                    &name,
                    Arc::new(move |raw| {
                        let mut iface = handler_iface.lock().unwrap();
                        iface.process_outgoing(raw.to_vec()).is_ok()
                    }),
                );
                crate::transport::Transport::register_local_client_interface(&name);
                crate::interfaces::local_interface::LocalClientInterface::start_read_loop(Arc::clone(&client));
                *LOCAL_CLIENT.lock().unwrap() = Some(client);
            } else {
                self.is_shared_instance = false;
                self.is_standalone_instance = true;
                self.is_connected_to_shared_instance = false;
            }
        }

        if self.is_shared_instance && self.require_shared {
            panic!("No shared instance available, but application required it");
        }
    }

    fn local_socket_full_path(&self, instance_name: &str) -> String {
        let name = if instance_name.is_empty() { "default" } else { instance_name };
        let filename = format!("rns_{}.sock", name);
        self.config_dir.join(filename).to_string_lossy().to_string()
    }

    fn start_rpc_listener(&self) {
        let rpc_key = match self.rpc_key.clone() {
            Some(key) => key,
            None => return,
        };

        let use_af_unix = self.use_af_unix;
        let control_port = self.local_control_port;
        let socket_path = self.rpc_socket_path();

        thread::spawn(move || {
            if use_af_unix {
                if let Some(path) = socket_path {
                    let path_buf = PathBuf::from(&path);
                    if path_buf.exists() {
                        let _ = fs::remove_file(&path_buf);
                    }

                    let listener = match UnixListener::bind(&path) {
                        Ok(listener) => listener,
                        Err(err) => {
                            log(
                                &format!("Failed to bind RPC Unix socket {}: {}", path, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            return;
                        }
                    };

                    for stream in listener.incoming() {
                        if let Ok(stream) = stream {
                            let key = rpc_key.clone();
                            thread::spawn(move || {
                                let mut rpc_stream = RpcStream::Unix(stream);
                                handle_rpc_connection(&mut rpc_stream, &key);
                            });
                        }
                    }
                }
            } else {
                let addr = format!("127.0.0.1:{}", control_port);
                let listener = match TcpListener::bind(&addr) {
                    Ok(listener) => listener,
                    Err(err) => {
                        log(
                            &format!("Failed to bind RPC TCP listener {}: {}", addr, err),
                            LOG_ERROR,
                            false,
                            false,
                        );
                        return;
                    }
                };

                for stream in listener.incoming() {
                    if let Ok(stream) = stream {
                        let key = rpc_key.clone();
                        thread::spawn(move || {
                            let mut rpc_stream = RpcStream::Tcp(stream);
                            handle_rpc_connection(&mut rpc_stream, &key);
                        });
                    }
                }
            }
        });
    }

    fn load_system_interfaces(&mut self) {
        if !(self.is_shared_instance || self.is_standalone_instance) {
            return;
        }

        log("Bringing up system interfaces...", LOG_VERBOSE, false, false);
        if let Some(interfaces) = self.config.get_section("interfaces") {
            let entries: Vec<(String, ConfigSection)> = interfaces
                .subsections()
                .iter()
                .map(|(name, section)| (name.clone(), section.clone()))
                .collect();
            for (name, section) in entries {
                self.synthesize_interface(&section, &name, true);
            }
        }
        log("System interfaces are ready", LOG_VERBOSE, false, false);
    }

    fn apply_interface_stub_to_base(
        base: &mut Interface,
        mode: InterfaceMode,
        stub: &crate::transport::InterfaceStubConfig,
    ) {
        base.mode = mode;
        base.out_enabled = stub.out;
        if let Some(bitrate) = stub.bitrate {
            base.bitrate = bitrate;
        }
        base.announce_cap = stub.announce_cap.unwrap_or(ANNOUNCE_CAP / 100.0);
        base.announce_rate_target = stub.announce_rate_target;
        base.announce_rate_grace = stub.announce_rate_grace;
        base.announce_rate_penalty = stub.announce_rate_penalty;

        base.ingress_control = stub.ingress_control.unwrap_or(true);
        base.ic_max_held_announces = stub
            .ic_max_held_announces
            .unwrap_or(Interface::MAX_HELD_ANNOUNCES);
        base.ic_burst_hold = stub.ic_burst_hold.unwrap_or(Interface::IC_BURST_HOLD);
        base.ic_burst_freq_new = stub
            .ic_burst_freq_new
            .unwrap_or(Interface::IC_BURST_FREQ_NEW);
        base.ic_burst_freq = stub.ic_burst_freq.unwrap_or(Interface::IC_BURST_FREQ);
        base.ic_new_time = stub.ic_new_time.unwrap_or(Interface::IC_NEW_TIME);
        base.ic_burst_penalty = stub
            .ic_burst_penalty
            .unwrap_or(Interface::IC_BURST_PENALTY);
        base.ic_held_release_interval = stub
            .ic_held_release_interval
            .unwrap_or(Interface::IC_HELD_RELEASE_INTERVAL);

        base.bootstrap_only = stub.bootstrap_only.unwrap_or(false);
        base.discoverable = stub.discoverable.unwrap_or(false);

        base.discovery_announce_interval = stub.discovery_announce_interval;
        base.discovery_publish_ifac = stub.discovery_publish_ifac.unwrap_or(false);
        base.reachable_on = stub.reachable_on.clone();
        base.discovery_name = stub.discovery_name.clone();
        base.discovery_encrypt = stub.discovery_encrypt.unwrap_or(false);
        base.discovery_stamp_value = stub.discovery_stamp_value;
        base.discovery_latitude = stub.discovery_latitude;
        base.discovery_longitude = stub.discovery_longitude;
        base.discovery_height = stub.discovery_height;
        base.discovery_frequency = stub.discovery_frequency;
        base.discovery_bandwidth = stub.discovery_bandwidth;
        base.discovery_modulation = stub.discovery_modulation.clone();

        if let Some(ifac_size) = stub.ifac_size {
            base.ifac_size = ifac_size;
        }
        base.ifac_netname = stub.ifac_netname.clone();
        base.ifac_netkey = stub.ifac_netkey.clone();
        base.ifac_key = stub.ifac_key.clone();
        base.ifac_signature = stub.ifac_signature.clone();
    }

    fn synthesize_interface(&mut self, config: &ConfigSection, name: &str, instance_init: bool) {
        let mut config_map = HashMap::new();
        for (key, value) in config.items() {
            config_map.insert(key.to_string(), value.to_string());
        }
        config_map.insert("name".to_string(), name.to_string());

        let enabled = config.get_bool("interface_enabled").unwrap_or(false)
            || config.get_bool("enabled").unwrap_or(false);
        if !enabled {
            log(&format!("Skipping disabled interface \"{}\"", name), LOG_DEBUG, false, false);
            return;
        }

        if config.get_bool("discoverable").unwrap_or(false) {
            FLAGS.lock().unwrap().discovery_enabled = true;
        }

        if let Some(typ) = config.get("type") {
            let ignore_config_warnings = config.get_bool("ignore_config_warnings").unwrap_or(false);
            let mode = parse_interface_mode(config, typ, ignore_config_warnings);
            let configured_bitrate = config
                .get_int("bitrate")
                .and_then(|v| if v >= MINIMUM_BITRATE as i64 { Some(v as u64) } else { None });

            let announce_rate_target = config.get_int("announce_rate_target").map(|v| v as f64);
            let mut announce_rate_grace = config.get_int("announce_rate_grace").map(|v| v as f64);
            let mut announce_rate_penalty = config.get_int("announce_rate_penalty").map(|v| v as f64);
            if announce_rate_target.is_some() && announce_rate_grace.is_none() {
                announce_rate_grace = Some(0.0);
            }
            if announce_rate_target.is_some() && announce_rate_penalty.is_none() {
                announce_rate_penalty = Some(0.0);
            }

            let announce_cap = config
                .get_float("announce_cap")
                .and_then(|v| if v > 0.0 && v <= 100.0 { Some(v / 100.0) } else { None })
                .unwrap_or(ANNOUNCE_CAP / 100.0);

            let ingress_control = config.get_bool("ingress_control");
            let ic_max_held_announces = config.get_int("ic_max_held_announces").map(|v| v as usize);
            let ic_burst_hold = config.get_float("ic_burst_hold");
            let ic_burst_freq_new = config.get_float("ic_burst_freq_new");
            let ic_burst_freq = config.get_float("ic_burst_freq");
            let ic_new_time = config.get_float("ic_new_time");
            let ic_burst_penalty = config.get_float("ic_burst_penalty");
            let ic_held_release_interval = config.get_float("ic_held_release_interval");

            let bootstrap_only = config.get_bool("bootstrap_only");
            let outgoing = config.get_bool("outgoing");

            let ifac_size = config.get_int("ifac_size")
                .and_then(|v| if v >= (IFAC_MIN_SIZE as i64) * 8 { Some((v as usize) / 8) } else { None })
                .or_else(|| default_ifac_size_for_type(typ));

            let ifac_netname = config.get("networkname").or_else(|| config.get("network_name")).map(|s| s.to_string());
            let ifac_netkey = config.get("passphrase").or_else(|| config.get("pass_phrase")).map(|s| s.to_string());
            let (ifac_key, ifac_signature) = derive_ifac_material(ifac_netname.as_deref(), ifac_netkey.as_deref());

            let discoverable = config.get_bool("discoverable").unwrap_or(false);
            let mut discovery_announce_interval = None;
            let mut discovery_stamp_value = config.get_int("discovery_stamp_value").map(|v| v as u32);
            let discovery_name = config.get("discovery_name").map(|s| s.to_string());
            let discovery_encrypt = config.get_bool("discovery_encrypt");
            let reachable_on = config.get("reachable_on").map(|s| s.to_string());
            let discovery_publish_ifac = config.get_bool("publish_ifac");
            let discovery_latitude = config.get_float("latitude");
            let discovery_longitude = config.get_float("longitude");
            let discovery_height = config.get_float("height");
            let discovery_frequency = config.get_int("discovery_frequency").map(|v| v as u64);
            let discovery_bandwidth = config.get_int("discovery_bandwidth").map(|v| v as u32);
            let discovery_modulation = config.get("discovery_modulation").map(|s| s.to_string());

            if discoverable {
                FLAGS.lock().unwrap().discovery_enabled = true;
                if let Some(interval_minutes) = config.get_int("announce_interval") {
                    let mut interval = (interval_minutes as f64) * 60.0;
                    if interval < 5.0 * 60.0 {
                        interval = 5.0 * 60.0;
                    }
                    discovery_announce_interval = Some(interval);
                }
                if discovery_announce_interval.is_none() {
                    discovery_announce_interval = Some(6.0 * 60.0 * 60.0);
                }
                if discovery_stamp_value.is_none() {
                    discovery_stamp_value = None;
                }
            }

            let mut stub_config = crate::transport::InterfaceStubConfig::default();
            stub_config.name = name.to_string();
            stub_config.mode = interface_mode_to_stub(mode);
            stub_config.out = outgoing.unwrap_or(true);
            stub_config.bitrate = configured_bitrate;
            stub_config.announce_cap = Some(announce_cap);
            stub_config.announce_rate_target = announce_rate_target;
            stub_config.announce_rate_grace = announce_rate_grace;
            stub_config.announce_rate_penalty = announce_rate_penalty;
            stub_config.ingress_control = ingress_control;
            stub_config.ic_max_held_announces = ic_max_held_announces;
            stub_config.ic_burst_hold = ic_burst_hold;
            stub_config.ic_burst_freq_new = ic_burst_freq_new;
            stub_config.ic_burst_freq = ic_burst_freq;
            stub_config.ic_new_time = ic_new_time;
            stub_config.ic_burst_penalty = ic_burst_penalty;
            stub_config.ic_held_release_interval = ic_held_release_interval;
            stub_config.bootstrap_only = bootstrap_only;
            stub_config.discoverable = Some(discoverable);
            stub_config.discovery_announce_interval = discovery_announce_interval;
            stub_config.discovery_publish_ifac = discovery_publish_ifac;
            stub_config.reachable_on = reachable_on;
            stub_config.discovery_name = discovery_name;
            stub_config.discovery_encrypt = discovery_encrypt;
            stub_config.discovery_stamp_value = discovery_stamp_value;
            stub_config.discovery_latitude = discovery_latitude;
            stub_config.discovery_longitude = discovery_longitude;
            stub_config.discovery_height = discovery_height;
            stub_config.discovery_frequency = discovery_frequency;
            stub_config.discovery_bandwidth = discovery_bandwidth;
            stub_config.discovery_modulation = discovery_modulation;
            stub_config.ifac_size = ifac_size;
            stub_config.ifac_netname = ifac_netname;
            stub_config.ifac_netkey = ifac_netkey;
            stub_config.ifac_key = ifac_key;
            stub_config.ifac_signature = ifac_signature;

            // Extract address and port for TCP interfaces
            match typ {
                "TCPClientInterface" => {
                    stub_config.address = config_map.get("target_host").map(|h| h.to_string());
                    stub_config.port = config_map.get("target_port")
                        .and_then(|p| p.parse::<u16>().ok());
                }
                "TCPServerInterface" => {
                    stub_config.address = config_map.get("listen_ip").map(|a| a.to_string())
                        .or_else(|| config_map.get("bind_ip").map(|a| a.to_string()));
                    stub_config.port = config_map.get("listen_port")
                        .and_then(|p| p.parse::<u16>().ok());
                }
                _ => {}
            }

            match typ {
                "UDPInterface" => {
                    match crate::interfaces::udp_interface::UdpInterface::new(None, &config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            let interface = Arc::new(Mutex::new(interface));
                            let handler_iface = Arc::clone(&interface);
                            let name = handler_iface.lock().unwrap().base.name.clone().unwrap_or_default();
                            crate::transport::Transport::register_outbound_handler(
                                &name,
                                Arc::new(move |raw| {
                                    let mut iface = handler_iface.lock().unwrap();
                                    iface.process_outgoing(raw.to_vec()).is_ok()
                                }),
                            );
                            self.system_interfaces.push(SystemInterface::Udp(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create UDP interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create UDP interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                "TCPServerInterface" => {
                    match crate::interfaces::tcp_interface::TcpServerInterface::new(&config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            stub_config.online = Some(interface.base.online);
                            interface.update_spawn_config();
                            let interface = Arc::new(Mutex::new(interface));
                            self.system_interfaces.push(SystemInterface::TcpServer(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create TCP server interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create TCP server interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                "TCPClientInterface" => {
                    match crate::interfaces::tcp_interface::TcpClientInterface::new(&config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            stub_config.online = Some(interface.base.online && !interface.detached);
                            let kiss_framing = interface.kiss_framing;
                            let is_online = interface.base.online;
                            let interface_repr = interface.to_string();
                            let interface = Arc::new(Mutex::new(interface));
                            let handler_iface = Arc::clone(&interface);
                            let name = handler_iface.lock().unwrap().base.name.clone().unwrap_or_default();
                            crate::transport::Transport::register_outbound_handler(
                                &name,
                                Arc::new(move |raw| {
                                    let mut iface = handler_iface.lock().unwrap();
                                    iface.process_outgoing(raw.to_vec()).is_ok()
                                }),
                            );
                            crate::interfaces::tcp_interface::TcpClientInterface::start_read_loop(Arc::clone(&interface));
                            // STRICT ORDERING (DESIGN_PRINCIPLES.md §3 + §4):
                            // `register_interface_stub_config` MUST run before
                            // `synthesize_tunnel`. The latter calls
                            // `Transport::outbound`, which iterates
                            // `state.interfaces` to broadcast the tunnel
                            // synthesis packet. If the stub isn't there
                            // yet, the broadcast loop finds zero matching
                            // interfaces, returns sent=false, and THE
                            // TUNNEL SYNTHESIS NEVER REACHES THE WIRE.
                            //
                            // The downstream consequence is catastrophic:
                            // the upstream rnsd has no mapping from this
                            // TCP connection back to our transport identity,
                            // so it will not route PATH_RESPONSE packets
                            // back to us. PATH_REQUESTs we send go
                            // unanswered (or only "answered" when an
                            // organic broadcast announce happens to pass
                            // through carrying the path we asked for —
                            // observed at 22 seconds in retichat.log on
                            // 2026-04-30 for dest 2b8f4b46).
                            //
                            // NEVER REMOVE EVER. NEVER REORDER. The fix
                            // for "synthesize_tunnel: sent=false" is to
                            // ensure the stub is registered first, NOT to
                            // sleep, NOT to retry, NOT to defer.
                            crate::transport::Transport::register_interface_stub_config(stub_config.clone());
                            // For non-KISS TCP client interfaces, synthesize a
                            // tunnel so the remote transport daemon associates
                            // this connection with our transport identity.
                            //
                            // Runs inline, before `Reticulum::new()` returns.
                            // The race the previously-deferred call masked:
                            // the iOS / Android host calls
                            // `requestEssentialPaths()` immediately after
                            // `Reticulum::new()` returns. If `synthesize_tunnel`
                            // hasn't yet been written to the wire when those
                            // PATH_REQUESTs go out, the upstream rnsd has no
                            // mapping from this TCP connection back to our
                            // transport identity, so it will not route the
                            // PATH_RESPONSE / announce reply back to us. The
                            // observable failure mode was minute-scale "no
                            // path" gaps after every cold start.
                            //
                            // NEVER REMOVE EVER — this is the load-bearing
                            // ordering guarantee for the cold-start launch
                            // budget. If you re-introduce a sleep here, you
                            // will re-introduce the cold-start stall.
                            if !kiss_framing && is_online {
                                crate::transport::Transport::synthesize_tunnel(&name, &interface_repr);
                            }
                            self.system_interfaces.push(SystemInterface::TcpClient(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create TCP client interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create TCP client interface");
                            }
                        }
                    }
                    // Defensive: ensures a stub exists even on the error
                    // path above (where the inline registration in the Ok
                    // arm did not run). On the success path this is a
                    // no-op because `register_interface_stub_config`
                    // checks `state.interfaces.iter().any(|i| i.name == config.name)`
                    // and returns early when the stub is already present.
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                "PipeInterface" => {
                    match crate::interfaces::pipe_interface::PipeInterface::new(&config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            let interface = Arc::new(Mutex::new(interface));
                            let handler_iface = Arc::clone(&interface);
                            let name = handler_iface.lock().unwrap().base.name.clone().unwrap_or_default();
                            crate::transport::Transport::register_outbound_handler(
                                &name,
                                Arc::new(move |raw| {
                                    let mut iface = handler_iface.lock().unwrap();
                                    iface.process_outgoing(raw.to_vec()).is_ok()
                                }),
                            );
                            self.system_interfaces.push(SystemInterface::Pipe(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create pipe interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create pipe interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                #[cfg(feature = "serial")]
                "SerialInterface" => {
                    match crate::interfaces::serial_interface::SerialInterface::new(&config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            let interface = Arc::new(Mutex::new(interface));
                            let handler_iface = Arc::clone(&interface);
                            let name = handler_iface.lock().unwrap().base.name.clone().unwrap_or_default();
                            crate::transport::Transport::register_outbound_handler(
                                &name,
                                Arc::new(move |raw| {
                                    let mut iface = handler_iface.lock().unwrap();
                                    iface.process_outgoing(raw.to_vec()).is_ok()
                                }),
                            );
                            crate::interfaces::serial_interface::SerialInterface::start_read_loop(Arc::clone(&interface));
                            self.system_interfaces.push(SystemInterface::Serial(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create serial interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create serial interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                #[cfg(feature = "serial")]
                "KISSInterface" => {
                    match crate::interfaces::kiss_interface::KissInterface::new(&config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            let interface = Arc::new(Mutex::new(interface));
                            let handler_iface = Arc::clone(&interface);
                            let name = handler_iface.lock().unwrap().base.name.clone().unwrap_or_default();
                            crate::transport::Transport::register_outbound_handler(
                                &name,
                                Arc::new(move |raw| {
                                    let mut iface = handler_iface.lock().unwrap();
                                    iface.process_outgoing(raw.to_vec()).is_ok()
                                }),
                            );
                            crate::interfaces::kiss_interface::KissInterface::start_read_loop(Arc::clone(&interface));
                            self.system_interfaces.push(SystemInterface::Kiss(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create KISS interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create KISS interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                #[cfg(feature = "serial")]
                "RNodeInterface" => {
                    let port = config.get("port").unwrap_or("/dev/ttyUSB0").to_string();
                    let frequency = config.get_int("frequency").unwrap_or(0) as u64;
                    let bandwidth = config.get_int("bandwidth").unwrap_or(125000) as u32;
                    let txpower = config.get_int("txpower").unwrap_or(7) as u8;
                    let sf = config.get_int("spreadingfactor").unwrap_or(7) as u8;
                    let cr = config.get_int("codingrate").unwrap_or(5) as u8;
                    let flow_control = config.get_bool("flow_control").unwrap_or(false);
                    let st_alock = config.get_float("airtime_limit_short").map(|v| v as f32);
                    let lt_alock = config.get_float("airtime_limit_long").map(|v| v as f32);
                    let id_interval = config.get_int("id_interval").map(|v| Duration::from_secs(v as u64));
                    let id_callsign = config.get("id_callsign").map(|s| s.as_bytes().to_vec());

                    match RNodeInterface::new(
                        name,
                        &port,
                        frequency,
                        bandwidth,
                        txpower,
                        sf,
                        cr,
                        flow_control,
                        st_alock,
                        lt_alock,
                        id_interval,
                        id_callsign,
                    ) {
                        Ok(interface) => {
                            let interface = Arc::new(Mutex::new(interface));

                            // Start read loop FIRST so it can process detect/config responses
                            RNodeInterface::start_read_loop(
                                Arc::clone(&interface),
                                Arc::new(Mutex::new(crate::transport::Transport)),
                            );

                            // Configure the radio (detect, set params, go online)
                            // Uses _shared variant that releases the outer lock between
                            // steps so the read loop can process serial responses.
                            if let Err(err) = RNodeInterface::configure_device_shared(&interface) {
                                log(
                                    &format!("Failed to configure RNode device {}: {}", name, err),
                                    LOG_ERROR,
                                    false,
                                    false,
                                );
                                if instance_init && panic_on_interface_error_enabled() {
                                    panic!("Failed to configure RNode device");
                                }
                            }

                            // Register outbound handler
                            let handler_iface = Arc::clone(&interface);
                            crate::transport::Transport::register_outbound_handler(
                                name,
                                Arc::new(move |raw| {
                                    let iface = handler_iface.lock().unwrap();
                                    iface.process_outgoing(raw.to_vec()).is_ok()
                                }),
                            );

                            self.system_interfaces.push(SystemInterface::RNode(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create RNode interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create RNode interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                "BackboneInterface" => {
                    match crate::interfaces::backbone_interface::BackboneInterface::new(&config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            let interface = Arc::new(Mutex::new(interface));
                            crate::interfaces::backbone_interface::BackboneInterface::start_listener(Arc::clone(&interface));
                            self.system_interfaces.push(SystemInterface::Backbone(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create Backbone interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create Backbone interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                "BackboneClientInterface" => {
                    match crate::interfaces::backbone_interface::BackboneClientInterface::new(&config_map) {
                        Ok(mut interface) => {
                            Self::apply_interface_stub_to_base(&mut interface.base, mode, &stub_config);
                            let interface = Arc::new(Mutex::new(interface));
                            let handler_iface = Arc::clone(&interface);
                            let name = handler_iface.lock().unwrap().base.name.clone().unwrap_or_default();
                            crate::transport::Transport::register_outbound_handler(
                                &name,
                                Arc::new(move |raw| {
                                    let mut iface = handler_iface.lock().unwrap();
                                    iface.process_outgoing(raw.to_vec()).is_ok()
                                }),
                            );
                            crate::interfaces::backbone_interface::BackboneClientInterface::start_read_loop(Arc::clone(&interface));
                            self.system_interfaces.push(SystemInterface::BackboneClient(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create BackboneClient interface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create BackboneClient interface");
                            }
                        }
                    }
                    crate::transport::Transport::register_interface_stub_config(stub_config);
                }
                "AutoInterface" => {
                    let ai_group_id = config.get("group_id").map(|s| s.to_string());
                    let ai_discovery_scope = config.get("discovery_scope").map(|s| s.to_string());
                    let ai_discovery_port = config.get_int("discovery_port").map(|v| v as u16);
                    let ai_multicast_address_type = config.get("multicast_address_type").map(|s| s.to_string());
                    let ai_data_port = config.get_int("data_port").map(|v| v as u16);
                    let ai_allowed_interfaces = config.get_list("devices");
                    let ai_ignored_interfaces = config.get_list("ignored_devices");
                    let ai_configured_bitrate = config
                        .get_int("configured_bitrate")
                        .or_else(|| config.get_int("bitrate"))
                        .map(|v| v as u64);

                    let ai_config = crate::interfaces::auto_interface::AutoInterfaceConfig {
                        name: name.to_string(),
                        group_id: ai_group_id,
                        discovery_scope: ai_discovery_scope,
                        discovery_port: ai_discovery_port,
                        multicast_address_type: ai_multicast_address_type,
                        data_port: ai_data_port,
                        allowed_interfaces: ai_allowed_interfaces,
                        ignored_interfaces: ai_ignored_interfaces,
                        configured_bitrate: ai_configured_bitrate,
                        stub_config: stub_config.clone(),
                    };

                    match crate::interfaces::auto_interface::AutoInterface::new(ai_config) {
                        Ok(interface) => {
                            interface.final_init();
                            self.system_interfaces.push(SystemInterface::Auto(interface));
                        }
                        Err(err) => {
                            log(
                                &format!("Failed to create AutoInterface {}: {}", name, err),
                                LOG_ERROR,
                                false,
                                false,
                            );
                            if instance_init && panic_on_interface_error_enabled() {
                                panic!("Failed to create AutoInterface");
                            }
                        }
                    }
                }
                _ => {
                    log(
                        &format!(
                            "Unsupported interface type \"{}\" for interface \"{}\"",
                            typ, name
                        ),
                        LOG_ERROR,
                        false,
                        false,
                    );
                    log(
                        "External interfaces (Python plugins) are not supported in the Rust implementation",
                        LOG_WARNING,
                        false,
                        false,
                    );
                    log(
                        &format!("Interface \"{}\" will not be loaded", name),
                        LOG_WARNING,
                        false,
                        false,
                    );
                }
            }
        }
    }

    /// Adjust the keepalive interval (in seconds) for all active links and
    /// TCP backbone connections.  Pass `0.0` to restore the compiled-in
    /// defaults.
    ///
    /// This is intended to be called when the host application transitions
    /// between foreground and background modes so that power usage can be
    /// reduced while the app is not actively in use.
    pub fn set_keepalive_interval(&self, secs: f64) {
        let link_keepalive;
        let link_stale_time;
        let tcp_probe_after: u64;

        if secs <= 0.0 {
            // Restore defaults
            link_keepalive = crate::link::KEEPALIVE;
            link_stale_time = crate::link::STALE_TIME;
            tcp_probe_after = crate::interfaces::backbone_interface::BackboneClientInterface::TCP_PROBE_AFTER;
        } else {
            link_keepalive = secs;
            link_stale_time = secs * crate::link::STALE_FACTOR;
            tcp_probe_after = secs as u64;
        }

        // --- Update active + pending links ---
        {
            let mut transport = crate::transport::TRANSPORT.lock().unwrap();
            let mut updated = 0usize;
            for link in transport.active_links.iter_mut() {
                link.keepalive = link_keepalive;
                link.stale_time = link_stale_time;
                updated += 1;
            }
            for link in transport.pending_links.iter_mut() {
                link.keepalive = link_keepalive;
                link.stale_time = link_stale_time;
                updated += 1;
            }
            if updated > 0 {
                log(
                    &format!("Updated keepalive to {}s on {} link(s)", link_keepalive, updated),
                    LOG_DEBUG,
                    false,
                    false,
                );
            }
        }

        // --- Update TCP backbone connections ---
        for iface in &self.system_interfaces {
            if let SystemInterface::BackboneClient(ref arc) = iface {
                let guard = arc.lock().unwrap();
                guard.set_tcp_keepalive(tcp_probe_after);
            }
        }

        log(
            &format!("Keepalive interval set to {}s (link={}s stale={}s tcp_probe={}s)",
                secs, link_keepalive, link_stale_time, tcp_probe_after),
            LOG_VERBOSE,
            false,
            false,
        );
    }
}

fn ensure_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        if let Err(e) = fs::create_dir_all(path) {
            // On Docker hosts with userns-remap (e.g. Synology NAS), the
            // container's root uid is remapped and may lack permission to
            // create directories inside bind mounts.  If the path appeared
            // between our exists-check and now (race), or the create failed
            // but the dir is somehow present, carry on.
            if !path.is_dir() {
                return Err(format!(
                    "Failed to create {}: {}\n\
                     Hint: pre-create this directory on the Docker host and chmod 777.",
                    path.display(),
                    e
                ));
            }
        }
    }
    Ok(())
}

fn default_config_dir() -> PathBuf {
    if Path::new("/etc/reticulum").is_dir() && Path::new("/etc/reticulum/config").is_file() {
        return PathBuf::from("/etc/reticulum");
    }

    if let Some(home) = std::env::var_os("HOME") {
        let config_home = PathBuf::from(home).join(".config/reticulum");
        if config_home.is_dir() && config_home.join("config").is_file() {
            return config_home;
        }
        return PathBuf::from(std::env::var_os("HOME").unwrap()).join(".reticulum");
    }

    PathBuf::from("/tmp/reticulum")
}

pub fn exit_handler() {
    crate::log("Reticulum exit handler invoked", crate::LOG_DEBUG, false, false);
    crate::transport::Transport::exit_handler();
    crate::identity::exit_handler();
    if crate::Profiler::ran() {
        crate::Profiler::results();
    }
    crate::set_loglevel(-1);

    // Detach all TCP client interfaces before clearing the instance.
    //
    // Each TcpClientInterface read-loop thread holds its own Arc clone and
    // will outlive the Reticulum instance unless we explicitly signal it to
    // stop.  Calling detach() sets detached=true and shuts down the socket,
    // which causes any blocked read() to return an error immediately;  the
    // thread then sees detached=true in the reconnect check and exits cleanly
    // without opening a new connection.  This prevents the "ghost loop"
    // accumulation that produces duplicate TCP connections on library restart.
    if let Ok(instance_guard) = INSTANCE.try_lock() {
        if let Some(ref rns_arc) = *instance_guard {
            if let Ok(rns) = rns_arc.try_lock() {
                for iface in &rns.system_interfaces {
                    if let SystemInterface::TcpClient(ref tcp_arc) = iface {
                        if let Ok(mut tcp) = tcp_arc.lock() {
                            tcp.detach();
                        }
                    }
                }
            }
        }
    }

    // Clear the singleton so init() can be called again (needed for Android service restart)
    if let Ok(mut instance) = INSTANCE.lock() {
        *instance = None;
    }
}

pub fn should_use_implicit_proof() -> bool {
    FLAGS.lock().unwrap().use_implicit_proof
}

pub fn transport_enabled() -> bool {
    FLAGS.lock().unwrap().transport_enabled
}

pub fn discovery_enabled() -> bool {
    FLAGS.lock().unwrap().discovery_enabled
}

pub fn discover_interfaces_enabled() -> bool {
    FLAGS.lock().unwrap().discover_interfaces
}

pub fn link_mtu_discovery() -> bool {
    FLAGS.lock().unwrap().link_mtu_discovery
}

pub fn remote_management_enabled() -> bool {
    FLAGS.lock().unwrap().remote_management_enabled
}

pub fn probe_destination_enabled() -> bool {
    FLAGS.lock().unwrap().allow_probes
}

pub fn required_discovery_value() -> Option<u32> {
    FLAGS.lock().unwrap().required_discovery_value
}

pub fn publish_blackhole_enabled() -> bool {
    FLAGS.lock().unwrap().publish_blackhole
}

pub fn panic_on_interface_error_enabled() -> bool {
    FLAGS.lock().unwrap().panic_on_interface_error
}

pub fn blackhole_sources() -> Vec<Vec<u8>> {
    FLAGS.lock().unwrap().blackhole_sources.clone()
}

pub fn interface_discovery_sources() -> Vec<Vec<u8>> {
    FLAGS.lock().unwrap().interface_sources.clone()
}

pub fn should_autoconnect_discovered_interfaces() -> bool {
    FLAGS.lock().unwrap().autoconnect_discovered_interfaces > 0
}

pub fn max_autoconnected_interfaces() -> usize {
    FLAGS.lock().unwrap().autoconnect_discovered_interfaces
}

fn create_default_config(config_path: &Path, config_dir: &Path) -> Result<(), String> {
    ensure_dir(config_dir)?;
    let mut file = fs::File::create(config_path)
        .map_err(|err| format!("Could not create default config: {}", err))?;
    for line in default_config_lines() {
        writeln!(file, "{}", line).map_err(|err| format!("Failed to write config: {}", err))?;
    }
    Ok(())
}

fn expand_user_path(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    PathBuf::from(path)
}

fn supports_af_unix() -> bool {
    cfg!(unix)
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn clean_caches(resource_path: &Path, cache_path: &Path) {
    let now_ts = now();
    if let Ok(entries) = fs::read_dir(resource_path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let age = now_ts - modified
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs_f64();
                    if age > RESOURCE_CACHE {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }

    if let Ok(entries) = fs::read_dir(cache_path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let age = now_ts - modified
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs_f64();
                    if age > crate::transport::DESTINATION_TIMEOUT {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

fn hex_to_bytes(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn parse_interface_mode(config: &ConfigSection, interface_type: &str, ignore_warnings: bool) -> InterfaceMode {
    let raw = config
        .get("interface_mode")
        .or_else(|| config.get("mode"))
        .unwrap_or("full")
        .to_lowercase();

    let mut mode = match raw.as_str() {
        "full" => InterfaceMode::Full,
        "access_point" | "accesspoint" | "ap" => InterfaceMode::AccessPoint,
        "pointtopoint" | "ptp" => InterfaceMode::PointToPoint,
        "roaming" => InterfaceMode::Roaming,
        "boundary" => InterfaceMode::Boundary,
        "gateway" | "gw" => InterfaceMode::Gateway,
        _ => InterfaceMode::Full,
    };

    let discoverable = config.get_bool("discoverable").unwrap_or(false);
    if discoverable && !matches!(mode, InterfaceMode::Gateway | InterfaceMode::AccessPoint) {
        if interface_type == "RNodeInterface" || interface_type == "RNodeMultiInterface" {
            mode = InterfaceMode::AccessPoint;
        } else {
            mode = InterfaceMode::Gateway;
        }

        if !ignore_warnings {
            log(
                &format!("Discovery enabled on interface {} without gateway/AP mode. Auto-configured mode.", interface_type),
                LOG_NOTICE,
                false,
                false,
            );
        }
    }

    mode
}

fn interface_mode_to_stub(mode: InterfaceMode) -> u8 {
    match mode {
        InterfaceMode::Full => crate::transport::InterfaceStub::MODE_FULL,
        InterfaceMode::PointToPoint => crate::transport::InterfaceStub::MODE_POINT_TO_POINT,
        InterfaceMode::AccessPoint => crate::transport::InterfaceStub::MODE_ACCESS_POINT,
        InterfaceMode::Roaming => crate::transport::InterfaceStub::MODE_ROAMING,
        InterfaceMode::Boundary => crate::transport::InterfaceStub::MODE_BOUNDARY,
        InterfaceMode::Gateway => crate::transport::InterfaceStub::MODE_GATEWAY,
    }
}

fn default_ifac_size_for_type(interface_type: &str) -> Option<usize> {
    match interface_type {
        "PipeInterface" | "SerialInterface" | "KISSInterface" => Some(8),
        "UDPInterface" | "TCPClientInterface" | "TCPServerInterface" | "AutoInterface" | "BackboneInterface" | "BackboneClientInterface" => Some(16),
        _ => Some(16),
    }
}

fn derive_ifac_material(netname: Option<&str>, netkey: Option<&str>) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    if netname.is_none() && netkey.is_none() {
        return (None, None);
    }

    let mut origin = Vec::new();
    if let Some(name) = netname {
        origin.extend_from_slice(&Identity::full_hash(name.as_bytes()));
    }
    if let Some(key) = netkey {
        origin.extend_from_slice(&Identity::full_hash(key.as_bytes()));
    }

    let origin_hash = Identity::full_hash(&origin);
    let hkdf = Hkdf::<Sha256>::new(Some(&IFAC_SALT), &origin_hash);
    let mut derived = vec![0u8; 64];
    if hkdf.expand(&[], &mut derived).is_err() {
        return (None, None);
    }

    let identity = Identity::from_bytes(&derived).ok();
    let signature = identity.as_ref().map(|id| id.sign(&Identity::full_hash(&derived)));

    (Some(derived), signature)
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
