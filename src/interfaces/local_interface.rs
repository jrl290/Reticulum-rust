use super::interface::Interface;
use crate::transport::Transport;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::os::unix::net::UnixStream;

/// HDLC framing for Local Interface
/// Same as PipeInterface - simplified HDLC for packet boundaries
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

/// Local Client Interface
/// 
/// Connects to a shared Reticulum instance either via AF_UNIX socket
/// or localhost TCP socket. Automatically reconnects on disconnection.
pub struct LocalClientInterface {
    pub base: Interface,
    pub target_ip: Option<String>,
    pub target_port: Option<u16>,
    pub socket_path: Option<String>,
    pub is_connected_to_shared_instance: bool,
    pub reconnecting: bool,
    pub never_connected: bool,
    pub detached: bool,
    pub mode: u8,
    frame_buffer: Vec<u8>,
    #[allow(dead_code)]
    transmit_buffer: Vec<u8>,
    socket: Option<Box<dyn SocketTrait>>,
    writing: bool,
}

// Socket trait to abstract over TCP and Unix sockets
trait SocketTrait: Send {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize>;
    fn shutdown(&mut self) -> std::io::Result<()>;
}

impl SocketTrait for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(self, buf)
    }
    
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(self, buf)
    }
    
    fn shutdown(&mut self) -> std::io::Result<()> {
        TcpStream::shutdown(self, std::net::Shutdown::Both)
    }
}

impl SocketTrait for UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(self, buf)
    }
    
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(self, buf)
    }
    
    fn shutdown(&mut self) -> std::io::Result<()> {
        UnixStream::shutdown(self, std::net::Shutdown::Both)
    }
}

impl LocalClientInterface {
    pub const RECONNECT_WAIT: u64 = 8; // seconds

    /// Create new local client interface connecting to existing socket
    pub fn from_socket(name: String, socket: TcpStream) -> Self {
        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(262144);
        base.bitrate = 1_000_000_000; // 1 Gbps
        base.online = true;
        base.autoconfigure_mtu = true;

        LocalClientInterface {
            base,
            target_ip: None,
            target_port: None,
            socket_path: None,
            is_connected_to_shared_instance: false,
            reconnecting: false,
            never_connected: false,
            detached: false,
            mode: 0x01, // MODE_FULL
            frame_buffer: Vec::new(),
            transmit_buffer: Vec::new(),
            socket: Some(Box::new(socket)),
            writing: false,
        }
    }

    /// Create new local client interface connecting to existing Unix socket
    pub fn from_unix_socket(name: String, socket: UnixStream) -> Self {
        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(262144);
        base.bitrate = 1_000_000_000;
        base.online = true;
        base.autoconfigure_mtu = true;

        LocalClientInterface {
            base,
            target_ip: None,
            target_port: None,
            socket_path: None,
            is_connected_to_shared_instance: false,
            reconnecting: false,
            never_connected: false,
            detached: false,
            mode: 0x01,
            frame_buffer: Vec::new(),
            transmit_buffer: Vec::new(),
            socket: Some(Box::new(socket)),
            writing: false,
        }
    }

    /// Create new local client interface connecting to port
    pub fn connect_to_port(name: String, port: u16) -> Result<Self, String> {
        let mut interface = Self::new_disconnected(name);
        interface.target_ip = Some("127.0.0.1".to_string());
        interface.target_port = Some(port);
        interface.connect()?;
        Ok(interface)
    }

    /// Create new local client interface connecting to Unix socket
    pub fn connect_to_socket(name: String, socket_path: String) -> Result<Self, String> {
        let mut interface = Self::new_disconnected(name);
        interface.socket_path = Some(socket_path);
        interface.connect()?;
        Ok(interface)
    }

    fn new_disconnected(name: String) -> Self {
        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(262144);
        base.bitrate = 1_000_000_000;
        base.online = false;
        base.autoconfigure_mtu = true;

        LocalClientInterface {
            base,
            target_ip: None,
            target_port: None,
            socket_path: None,
            is_connected_to_shared_instance: true,
            reconnecting: false,
            never_connected: true,
            detached: false,
            mode: 0x01,
            frame_buffer: Vec::new(),
            transmit_buffer: Vec::new(),
            socket: None,
            writing: false,
        }
    }

    /// Connect to the shared instance
    fn connect(&mut self) -> Result<(), String> {
        if let Some(ref socket_path) = self.socket_path {
            let stream = UnixStream::connect(socket_path)
                .map_err(|e| format!("Failed to connect to Unix socket {}: {}", socket_path, e))?;
            self.socket = Some(Box::new(stream));
        } else if let (Some(ref ip), Some(port)) = (&self.target_ip, self.target_port) {
            let addr = format!("{}:{}", ip, port);
            let stream = TcpStream::connect(&addr)
                .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
            
            stream.set_nodelay(true)
                .map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;
            
            self.socket = Some(Box::new(stream));
        } else {
            return Err("No connection parameters specified".to_string());
        }

        self.base.online = true;
        self.is_connected_to_shared_instance = true;
        self.never_connected = false;

        Ok(())
    }

    /// Reconnect to shared instance
    pub fn reconnect(&mut self) {
        if !self.is_connected_to_shared_instance {
            eprintln!("Attempt to reconnect on a non-initiator shared local interface");
            return;
        }

        if self.reconnecting {
            return;
        }

        self.reconnecting = true;
        let mut attempts = 0;

        while !self.base.online {
            thread::sleep(Duration::from_secs(Self::RECONNECT_WAIT));
            attempts += 1;

            match self.connect() {
                Ok(_) => {
                    if !self.never_connected {
                        println!("Reconnected socket for {}", self.to_string());
                    }
                    break;
                }
                Err(e) => {
                    eprintln!("Connection attempt {} for {} failed: {}", attempts, self.to_string(), e);
                }
            }
        }

        self.reconnecting = false;
        
        // Restart read loop
        // TODO: spawn read_loop thread
    }

    /// Check if ingress limiting should be applied (always false for local interface)
    pub fn should_ingress_limit(&self) -> bool {
        false
    }

    /// Process incoming data
    fn process_incoming(&mut self, data: Vec<u8>) {
        self.base.rxb += data.len() as u64;
        let interface_name = self.base.name.clone();
        let _ = Transport::inbound(data, interface_name);
    }

    /// Process outgoing data
    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        if !self.base.online {
            return Err("Interface offline".to_string());
        }

        self.writing = true;

        // Apply forced bitrate delay if set
        self.base.enforce_bitrate(data.len());

        // Frame data with HDLC
        let mut framed = vec![Hdlc::FLAG];
        framed.extend_from_slice(&Hdlc::escape(&data));
        framed.push(Hdlc::FLAG);

        if let Some(ref mut socket) = self.socket {
            socket.write(&framed)
                .map_err(|e| format!("Failed to write to socket: {}", e))?;
            
            self.base.txb += framed.len() as u64;
        } else {
            return Err("No socket connection".to_string());
        }

        self.writing = false;
        Ok(())
    }

    /// Handle HDLC framing
    fn handle_hdlc(&mut self) {
        for frame in self.drain_frames() {
            self.process_incoming(frame);
        }
    }

    /// Decode every complete HDLC frame currently buffered, dropping the ones
    /// the frame bounds reject.
    ///
    /// Split out of `handle_hdlc` so the bounds can be exercised without a
    /// socket. Buffer handling is unchanged: a complete frame is removed up
    /// to and including its closing flag.
    fn drain_frames(&mut self) -> Vec<Vec<u8>> {
        let hw_mtu = self.base.hw_mtu.unwrap_or(crate::reticulum::MTU);
        let ifac_size = self.base.ifac_size;
        let mut frames: Vec<Vec<u8>> = Vec::new();
        loop {
            if let Some(frame_start) = self.frame_buffer.iter().position(|&b| b == Hdlc::FLAG) {
                if let Some(frame_end) = self.frame_buffer[frame_start + 1..].iter().position(|&b| b == Hdlc::FLAG) {
                    let frame_end = frame_start + 1 + frame_end;
                    let frame = self.frame_buffer[frame_start + 1..frame_end].to_vec();

                    // Unescape frame
                    let mut unescaped = Vec::new();
                    let mut escape_next = false;
                    for &byte in &frame {
                        if escape_next {
                            if byte == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                                unescaped.push(Hdlc::FLAG);
                            } else if byte == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                                unescaped.push(Hdlc::ESC);
                            }
                            escape_next = false;
                        } else if byte == Hdlc::ESC {
                            escape_next = true;
                        } else {
                            unescaped.push(byte);
                        }
                    }

                    // RNS/Interfaces/TCPInterface.py:337-340 check_frame_len().
                    // Until 2026-09-22 this was a `HEADER_MINSIZE = 2`
                    // placeholder with no upper bound, so stub frames and
                    // arbitrarily large frames both reached Transport.
                    if crate::interfaces::interface::check_frame_len(unescaped.len(), hw_mtu, ifac_size) {
                        frames.push(unescaped);
                    }

                    self.frame_buffer.drain(..frame_end + 1);
                } else {
                    self.discard_overlong_frame_buffer(hw_mtu);
                    break;
                }
            } else {
                self.discard_overlong_frame_buffer(hw_mtu);
                break;
            }
        }
        frames
    }

    /// RNS/Interfaces/TCPInterface.py:408 — a buffer that has grown past
    /// `HW_MTU*2` without a closing flag is never going to produce a frame.
    fn discard_overlong_frame_buffer(&mut self, hw_mtu: usize) {
        if crate::interfaces::interface::frame_buffer_exceeded(self.frame_buffer.len(), hw_mtu) {
            crate::log(
                &format!(
                    "Dropping {} B of unterminated frame data on {}",
                    self.frame_buffer.len(),
                    self.base.name.as_deref().unwrap_or("LocalInterface")
                ),
                crate::LOG_DEBUG,
                false,
                false,
            );
            self.frame_buffer.clear();
        }
    }

    /// Read loop (to be run in thread)
    pub fn read_loop(&mut self) -> Result<(), String> {
        let mut buf = [0u8; 4096];
        
        loop {
            if let Some(ref mut socket) = self.socket {
                match socket.read(&mut buf) {
                    Ok(0) => {
                        // Connection closed
                        self.base.online = false;
                        if self.is_connected_to_shared_instance && !self.detached {
                            println!("Socket for {} was closed, attempting to reconnect...", self.to_string());
                            // TODO: call RNS.Transport.shared_connection_disappeared()
                            self.reconnect();
                            // Continue loop to read from reconnected socket
                            continue;
                        } else {
                            // TODO: call self.teardown(nowarning=true)
                            break;
                        }
                    }
                    Ok(n) => {
                        self.frame_buffer.extend_from_slice(&buf[..n]);
                        self.handle_hdlc();
                    }
                    Err(e) => {
                        self.base.online = false;
                        eprintln!("Interface error: {}", e);
                        if self.is_connected_to_shared_instance && !self.detached {
                            println!("Socket for {} had error ({}), attempting to reconnect...", self.to_string(), e);
                            self.reconnect();
                        } else {
                            return Err(format!("Read error: {}", e));
                        }
                    }
                }
            } else {
                return Err("No socket".to_string());
            }
        }

        Ok(())
    }

    pub fn start_read_loop(interface: Arc<Mutex<LocalClientInterface>>) {
        thread::spawn(move || {
            let mut iface = interface.lock().unwrap();
            let _ = iface.read_loop();
        });
    }

    /// Detach interface
    pub fn detach(&mut self) {
        self.detached = true;
        if let Some(ref mut socket) = self.socket {
            let _ = socket.shutdown();
        }
        self.socket = None;
    }

    /// Get string representation
    pub fn to_string(&self) -> String {
        if let Some(ref path) = self.socket_path {
            format!("LocalInterface[{}]", path.trim_start_matches('\0'))
        } else if let Some(port) = self.target_port {
            format!("LocalInterface[{}]", port)
        } else {
            "LocalInterface[unknown]".to_string()
        }
    }
}

/// Local Server Interface
/// 
/// Listens for connections from local clients and spawns LocalClientInterface
/// for each connection. Used for shared Reticulum instances.
pub struct LocalServerInterface {
    pub base: Interface,
    pub bind_ip: Option<String>,
    pub bind_port: Option<u16>,
    pub socket_path: Option<String>,
    pub clients: Arc<Mutex<usize>>,
    pub is_local_shared_instance: bool,
    #[allow(dead_code)]
    listener: Option<LocalListener>,
}

#[allow(dead_code)]
pub enum LocalListener {
    Tcp(Arc<TcpListener>),
    Unix(Arc<UnixListener>),
}

impl LocalServerInterface {
    /// Create new local server interface on TCP port
    pub fn on_port(port: u16) -> Result<Self, String> {
        let mut base = Interface::new();
        base.name = Some("Reticulum".to_string());
        base.in_enabled = true;
        base.out_enabled = false;
        base.bitrate = 1_000_000_000;
        base.online = false;
        base.autoconfigure_mtu = true;

        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr)
            .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

        let listener_arc = Arc::new(listener);
        let clients = Arc::new(Mutex::new(0));

        // Spawn accept loop
        let listener_clone = LocalListener::Tcp(listener_arc.clone());
        let clients_clone = clients.clone();
        thread::spawn(move || {
            Self::accept_loop(listener_clone, clients_clone);
        });

        base.online = true;

        Ok(LocalServerInterface {
            base,
            bind_ip: Some("127.0.0.1".to_string()),
            bind_port: Some(port),
            socket_path: None,
            clients,
            is_local_shared_instance: true,
            listener: Some(LocalListener::Tcp(listener_arc)),
        })
    }

    /// Create new local server interface on Unix socket path
    pub fn on_socket(socket_path: String) -> Result<Self, String> {
        let mut base = Interface::new();
        base.name = Some("Reticulum".to_string());
        base.in_enabled = true;
        base.out_enabled = false;
        base.bitrate = 1_000_000_000;
        base.online = false;
        base.autoconfigure_mtu = true;

        let path = if socket_path.starts_with('\0') {
            return Err("Abstract Unix sockets are not supported".to_string());
        } else {
            socket_path.clone()
        };

        let path_buf = std::path::PathBuf::from(&path);
        if path_buf.exists() {
            let _ = std::fs::remove_file(&path_buf);
        }

        let listener = UnixListener::bind(&path)
            .map_err(|e| format!("Failed to bind to {}: {}", path, e))?;

        let listener_arc = Arc::new(listener);
        let clients = Arc::new(Mutex::new(0));

        let listener_clone = LocalListener::Unix(listener_arc.clone());
        let clients_clone = clients.clone();
        thread::spawn(move || {
            Self::accept_loop(listener_clone, clients_clone);
        });

        base.online = true;

        Ok(LocalServerInterface {
            base,
            bind_ip: None,
            bind_port: None,
            socket_path: Some(path),
            clients,
            is_local_shared_instance: true,
            listener: Some(LocalListener::Unix(listener_arc)),
        })
    }

    /// Accept loop for incoming connections
    fn accept_loop(listener: LocalListener, clients: Arc<Mutex<usize>>) {
        match listener {
            LocalListener::Tcp(listener) => {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            let peer_addr = stream.peer_addr().ok();
                            let interface_name = if let Some(addr) = peer_addr {
                                format!("{}", addr.port())
                            } else {
                                "unknown".to_string()
                            };

                            let mut spawned = LocalClientInterface::from_socket(interface_name, stream);
                            spawned.base.out_enabled = false;
                            spawned.base.in_enabled = true;

                            if let Some(addr) = peer_addr {
                                spawned.target_ip = Some(addr.ip().to_string());
                                spawned.target_port = Some(addr.port());
                            }

                            *clients.lock().unwrap() += 1;
                            thread::spawn(move || {
                                let _ = spawned.read_loop();
                            });
                        }
                        Err(e) => {
                            eprintln!("Failed to accept connection: {}", e);
                        }
                    }
                }
            }
            LocalListener::Unix(listener) => {
                for stream in listener.incoming() {
                    match stream {
                        Ok(stream) => {
                            let interface_name = "local".to_string();
                            let mut spawned = LocalClientInterface::from_unix_socket(interface_name, stream);
                            spawned.base.out_enabled = false;
                            spawned.base.in_enabled = true;

                            *clients.lock().unwrap() += 1;
                            thread::spawn(move || {
                                let _ = spawned.read_loop();
                            });
                        }
                        Err(e) => {
                            eprintln!("Failed to accept connection: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Handle incoming connection (called from accept loop)
    pub fn incoming_connection(&mut self, _stream: TcpStream) {
        // This is handled in accept_loop above
    }

    /// Process outgoing data (no-op for server)
    pub fn process_outgoing(&self, _data: Vec<u8>) {
        // Server interface doesn't send data directly
    }

    /// Track received announce from spawned interface
    pub fn received_announce(&mut self, from_spawned: bool) {
        if from_spawned {
            self.base.received_announce(false);
        }
    }

    /// Track sent announce from spawned interface
    pub fn sent_announce(&mut self, from_spawned: bool) {
        if from_spawned {
            self.base.sent_announce(false);
        }
    }

    /// Get string representation
    pub fn to_string(&self) -> String {
        if let Some(ref path) = self.socket_path {
            format!("Shared Instance[{}]", path.trim_start_matches('\0'))
        } else if let Some(port) = self.bind_port {
            format!("Shared Instance[{}]", port)
        } else {
            "Shared Instance[unknown]".to_string()
        }
    }
}

impl std::fmt::Display for LocalClientInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Display for LocalServerInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![Hdlc::FLAG];
        frame.extend_from_slice(&Hdlc::escape(payload));
        frame.push(Hdlc::FLAG);
        frame
    }

    /// B12: RNS/Interfaces/TCPInterface.py:337-340 — this read loop carried a
    /// `HEADER_MINSIZE = 2` placeholder and no upper bound at all, so stub
    /// frames and arbitrarily large frames both reached `Transport::inbound`.
    #[test]
    fn local_frame_bounds_reject_stub_and_oversized_frames() {
        let mut iface = LocalClientInterface::new_disconnected("test-local-bounds".to_string());
        iface.base.hw_mtu = Some(64);
        iface.base.ifac_size = 0;
        let min = crate::reticulum::HEADER_MINSIZE;

        // A 3-byte frame passed the placeholder; it must not now.
        iface.frame_buffer.extend_from_slice(&framed(&[0x41u8; 3]));
        iface.frame_buffer.extend_from_slice(&framed(&vec![0x41u8; min]));
        iface.frame_buffer.extend_from_slice(&framed(&vec![0x42u8; min + 1]));
        iface.frame_buffer.extend_from_slice(&framed(&vec![0x43u8; 64]));
        iface.frame_buffer.extend_from_slice(&framed(&vec![0x44u8; 65]));

        let frames = iface.drain_frames();
        assert_eq!(
            frames,
            vec![vec![0x42u8; min + 1], vec![0x43u8; 64]],
            "only frames larger than HEADER_MINSIZE and no larger than hw_mtu + ifac_size \
             may reach Transport"
        );
        assert!(iface.frame_buffer.is_empty(), "every complete frame is consumed");
    }

    /// B12: RNS/Interfaces/TCPInterface.py:408 — an unterminated buffer is
    /// dropped once it passes HW_MTU*2 instead of growing without bound.
    #[test]
    fn local_unterminated_frame_buffer_is_dropped_past_twice_hw_mtu() {
        let mut iface = LocalClientInterface::new_disconnected("test-local-buffer".to_string());
        iface.base.hw_mtu = Some(64);

        iface.frame_buffer = vec![0x41u8; 128];
        assert!(iface.drain_frames().is_empty());
        assert_eq!(iface.frame_buffer.len(), 128, "exactly HW_MTU*2 is still kept");

        iface.frame_buffer.push(0x41);
        assert!(iface.drain_frames().is_empty());
        assert!(
            iface.frame_buffer.is_empty(),
            "one byte past HW_MTU*2 without a closing flag must be dropped"
        );
    }

    #[test]
    fn test_hdlc_escape() {
        let data = vec![0x12, Hdlc::FLAG, 0x34, Hdlc::ESC, 0x56];
        let escaped = Hdlc::escape(&data);
        assert!(escaped.len() > data.len());
        assert!(!escaped.contains(&Hdlc::FLAG));
    }
}
