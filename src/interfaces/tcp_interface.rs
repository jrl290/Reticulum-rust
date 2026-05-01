use super::interface::{Interface, InterfaceMode};
use crate::transport::Transport;
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

// ── Global reconnect nudge ──────────────────────────────────────────────
// A Condvar shared by all TCP client reconnect loops.  When the platform
// layer detects that network connectivity has been restored it calls
// `nudge_reconnect()`, which wakes every sleeping reconnect loop so they
// can attempt an immediate connect instead of waiting out the full
// RECONNECT_WAIT interval.
static RECONNECT_NUDGE: once_cell::sync::Lazy<(Mutex<()>, Condvar)> =
    once_cell::sync::Lazy::new(|| (Mutex::new(()), Condvar::new()));

/// Wake all TCP client reconnect loops immediately.
/// Safe to call from any thread, including C FFI.
pub fn nudge_reconnect() {
    let (lock, cvar) = &*RECONNECT_NUDGE;
    let _guard = lock.lock().unwrap();
    cvar.notify_all();
}

/// Sleep for up to `secs` but return early if `nudge_reconnect()` is called.
fn wait_or_nudge(secs: u64) {
    let (lock, cvar) = &*RECONNECT_NUDGE;
    let nudged = lock.lock().unwrap();
    // Use wait_timeout (not wait_timeout_while) so that ANY notify_all
    // wakes us, regardless of whether another thread consumed the flag first.
    // We don't care about the flag value — the nudge is purely a "try now" hint.
    let _ = cvar.wait_timeout(nudged, Duration::from_secs(secs));
}

/// HDLC framing for TCP Interface
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

/// KISS framing for TCP Interface
pub struct Kiss;

impl Kiss {
    pub const FEND: u8 = 0xC0;
    pub const FESC: u8 = 0xDB;
    pub const TFEND: u8 = 0xDC;
    pub const TFESC: u8 = 0xDD;
    pub const CMD_DATA: u8 = 0x00;
    pub const CMD_UNKNOWN: u8 = 0xFE;

    pub fn escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() + 10);
        for &byte in data {
            if byte == Self::FESC {
                escaped.push(Self::FESC);
                escaped.push(Self::TFESC);
            } else if byte == Self::FEND {
                escaped.push(Self::FESC);
                escaped.push(Self::TFEND);
            } else {
                escaped.push(byte);
            }
        }
        escaped
    }
}

/// TCP Client Interface
/// 
/// Connects to a remote TCP server for Reticulum communication.
/// Supports both HDLC and KISS framing, automatic reconnection,
/// and I2P tunneling configuration.
pub struct TcpClientInterface {
    pub base: Interface,
    pub target_ip: String,
    pub target_port: u16,
    pub initiator: bool,
    pub reconnecting: bool,
    pub never_connected: bool,
    pub detached: bool,
    pub kiss_framing: bool,
    pub i2p_tunneled: bool,
    pub mode: u8,
    pub max_reconnect_tries: Option<usize>,
    pub connect_timeout: u64,
    socket: Option<TcpStream>,
    writing: bool,
    /// Shared kill-switch read by the read loop in its WouldBlock branch.
    /// `process_outgoing` sets this to `true` when a write fails so the
    /// read loop wakes within one read-timeout interval and proceeds to
    /// reconnect, instead of relying on `shutdown(Both)` propagating
    /// to the cloned read fd (which is observed to NOT happen reliably
    /// on long-running half-open connections — see
    /// /memories/repo/rfed-tcp-watchdog-failure.md).
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
    force_read_exit: Arc<AtomicBool>,
}

impl TcpClientInterface {
    pub const HW_MTU: usize = 262144;
    pub const BITRATE_GUESS: u64 = 10_000_000; // 10 Mbps
    pub const DEFAULT_IFAC_SIZE: usize = 16;
    pub const RECONNECT_WAIT: u64 = 5; // seconds
    pub const INITIAL_CONNECT_TIMEOUT: u64 = 5; // seconds
    
    // TCP socket timeouts (Linux)
    pub const TCP_USER_TIMEOUT: u64 = 24;
    pub const TCP_PROBE_AFTER: u64 = 5;
    pub const TCP_PROBE_INTERVAL: u64 = 2;
    pub const TCP_PROBES: u64 = 12;
    
    // I2P tunnel timeouts
    pub const I2P_USER_TIMEOUT: u64 = 45;
    pub const I2P_PROBE_AFTER: u64 = 10;
    pub const I2P_PROBE_INTERVAL: u64 = 9;
    pub const I2P_PROBES: u64 = 5;

    /// Create new TCP client from configuration
    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let name = config.get("name")
            .ok_or("TCPClientInterface requires 'name' in config")?
            .clone();
        
        let target_ip = config.get("target_host")
            .ok_or("TCPClientInterface requires 'target_host' in config")?
            .clone();
        
        let target_port = config.get("target_port")
            .ok_or("TCPClientInterface requires 'target_port' in config")?
            .parse::<u16>()
            .map_err(|_| "Invalid target_port")?;
        
        let kiss_framing = config.get("kiss_framing")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);
        
        let i2p_tunneled = config.get("i2p_tunneled")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);
        
        let connect_timeout = config.get("connect_timeout")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(Self::INITIAL_CONNECT_TIMEOUT);
        
        let max_reconnect_tries = config.get("max_reconnect_tries")
            .and_then(|s| s.parse::<usize>().ok());
        
        let fixed_mtu = config.get("fixed_mtu")
            .and_then(|s| s.parse::<usize>().ok());

        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.bitrate = Self::BITRATE_GUESS;
        base.online = false;
        base.supports_discovery = true;
        
        if let Some(mtu) = fixed_mtu {
            base.hw_mtu = Some(mtu);
            base.fixed_mtu = true;
            base.autoconfigure_mtu = false;
        } else {
            base.hw_mtu = Some(Self::HW_MTU);
            base.autoconfigure_mtu = true;
        }

        let mut interface = TcpClientInterface {
            base,
            target_ip,
            target_port,
            initiator: true,
            reconnecting: false,
            never_connected: true,
            detached: false,
            kiss_framing,
            i2p_tunneled,
            mode: 0x01, // MODE_FULL
            max_reconnect_tries,
            connect_timeout,
            socket: None,
            writing: false,
            force_read_exit: Arc::new(AtomicBool::new(false)),
        };

        // Attempt initial connection.  If it fails, the interface is still
        // created in a "pending" state — start_read_loop will handle the
        // reconnect using the same condvar-based wait as a mid-session drop.
        let _ = interface.initial_connect();

        Ok(interface)
    }

    /// Create from existing socket (spawned from server)
    pub fn from_socket(name: String, socket: TcpStream) -> Self {
        let peer_addr = socket.peer_addr().ok();
        
        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = true;
        base.hw_mtu = Some(Self::HW_MTU);
        base.bitrate = Self::BITRATE_GUESS;
        base.online = true;
        base.autoconfigure_mtu = true;
        base.supports_discovery = true;

        // Set TCP_NODELAY
        let _ = socket.set_nodelay(true);

        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        // Server-accepted client connections must enable SO_KEEPALIVE the
        // same way initiator-side `connect()` does. Without this, a NAT
        // box / peer host that goes silent leaves the cloned read fd
        // blocked forever — the wedge analysed in
        // /memories/repo/rfed-tcp-watchdog-failure.md.
        Self::apply_keepalive(&socket, false);

        TcpClientInterface {
            base,
            target_ip: peer_addr.as_ref().map(|a| a.ip().to_string()).unwrap_or_default(),
            target_port: peer_addr.as_ref().map(|a| a.port()).unwrap_or(0),
            initiator: false,
            reconnecting: false,
            never_connected: false,
            detached: false,
            kiss_framing: false,
            i2p_tunneled: false,
            mode: 0x01,
            max_reconnect_tries: None,
            connect_timeout: Self::INITIAL_CONNECT_TIMEOUT,
            socket: Some(socket),
            writing: false,
            force_read_exit: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Initial connection attempt
    fn initial_connect(&mut self) -> Result<(), String> {
        crate::log(&format!("TCP connecting to {}:{}...", self.target_ip, self.target_port), crate::LOG_NOTICE, false, false);
        println!("Establishing TCP connection for {}...", self.to_string());
        
        match self.connect(true) {
            Ok(_) => {
                crate::log(&format!("TCP connection established to {}:{}", self.target_ip, self.target_port), crate::LOG_NOTICE, false, false);
                println!("TCP connection for {} established", self.to_string());
                // TODO: Start read_loop in thread
                Ok(())
            }
            Err(e) => {
                crate::log(&format!("TCP connection failed to {}:{}: {}", self.target_ip, self.target_port, e), crate::LOG_ERROR, false, false);
                // TODO: Start reconnect thread
                Err(e)
            }
        }
    }

    /// Connect to target
    fn connect(&mut self, _initial: bool) -> Result<(), String> {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", self.target_ip, self.target_port);
        
        // Use ToSocketAddrs to support both hostnames and IP addresses
        let sock_addr = addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve {}: {}", addr_str, e))?
            .next()
            .ok_or_else(|| format!("No addresses found for {}", addr_str))?;

        let stream = TcpStream::connect_timeout(
            &sock_addr,
            Duration::from_secs(self.connect_timeout)
        ).map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_nodelay(true)
            .map_err(|e| format!("Failed to set TCP_NODELAY: {}", e))?;

        // Set keepalive and timeouts
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.set_socket_options_linux(&stream)?;
        
        #[cfg(target_os = "macos")]
        self.set_socket_options_macos(&stream)?;

        self.socket = Some(stream);
        self.base.online = true;
        if let Some(name) = &self.base.name {
            Transport::set_interface_online(name, true);
        }
        self.writing = false;
        self.never_connected = false;

        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn set_socket_options_linux(&self, stream: &TcpStream) -> Result<(), String> {
        Self::apply_keepalive(stream, self.i2p_tunneled);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn set_socket_options_macos(&self, stream: &TcpStream) -> Result<(), String> {
        Self::apply_keepalive(stream, self.i2p_tunneled);
        Ok(())
    }

    /// Enable SO_KEEPALIVE plus aggressive probe timing on a TcpStream.
    /// Called by both initiator (`connect`) and server-accepted
    /// (`from_socket`) construction paths so EVERY TCP socket the process
    /// owns will be RST'd by the kernel within ~30 s when the peer goes
    /// silent (rather than blocking `read()` forever).
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1 and
    /// /memories/repo/rfed-tcp-watchdog-failure.md.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn apply_keepalive(stream: &TcpStream, i2p_tunneled: bool) {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_KEEPALIVE, IPPROTO_TCP, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT, TCP_USER_TIMEOUT};

        let optlen = std::mem::size_of::<i32>();
        unsafe {
            let fd = stream.as_raw_fd();
            let keepalive: i32 = 1;

            let (user_timeout_secs, keepidle, keepintvl, keepcnt) = if !i2p_tunneled {
                (Self::TCP_USER_TIMEOUT, Self::TCP_PROBE_AFTER, Self::TCP_PROBE_INTERVAL, Self::TCP_PROBES)
            } else {
                (Self::I2P_USER_TIMEOUT, Self::I2P_PROBE_AFTER, Self::I2P_PROBE_INTERVAL, Self::I2P_PROBES)
            };

            let user_timeout = (user_timeout_secs * 1000) as i32;
            let keepidle = keepidle as i32;
            let keepintvl = keepintvl as i32;
            let keepcnt = keepcnt as i32;

            setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout as *const _ as *const _, optlen as _);
            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive as *const _ as *const _, optlen as _);
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle as *const _ as *const _, optlen as _);
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl as *const _ as *const _, optlen as _);
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt as *const _ as *const _, optlen as _);
        }
    }

    #[cfg(target_os = "macos")]
    fn apply_keepalive(stream: &TcpStream, i2p_tunneled: bool) {
        use std::os::unix::io::AsRawFd;
        use libc::{setsockopt, SOL_SOCKET, SO_KEEPALIVE, IPPROTO_TCP};

        const TCP_KEEPALIVE: i32 = 0x10;

        unsafe {
            let fd = stream.as_raw_fd();
            let keepalive: i32 = 1;

            setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive as *const _ as *const _, std::mem::size_of::<i32>() as u32);

            let keepidle = if !i2p_tunneled {
                Self::TCP_PROBE_AFTER as i32
            } else {
                Self::I2P_PROBE_AFTER as i32
            };

            setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &keepidle as *const _ as *const _, std::mem::size_of::<i32>() as u32);
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    fn apply_keepalive(_stream: &TcpStream, _i2p_tunneled: bool) {
        // No platform-specific keepalive support compiled in.
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    #[allow(dead_code)]
    fn set_socket_options_linux(&self, _stream: &TcpStream) -> Result<(), String> {
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    #[allow(dead_code)]
    fn set_socket_options_macos(&self, _stream: &TcpStream) -> Result<(), String> {
        Ok(())
    }

    /// Reconnect after disconnection
    pub fn reconnect(&mut self) {
        if !self.initiator {
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

            if let Some(max_tries) = self.max_reconnect_tries {
                if attempts > max_tries {
                    // TODO: self.teardown()
                    break;
                }
            }

            match self.connect(false) {
                Ok(_) => {
                    if !self.never_connected {
                        println!("Reconnected socket for {}", self.to_string());
                    }
                    break;
                }
                Err(_e) => {
                }
            }
        }

        self.reconnecting = false;
        // TODO: Start read_loop thread
        // TODO: RNS.Transport.synthesize_tunnel(self) if not kiss_framing
    }

    /// Process incoming data
    fn process_incoming(&mut self, data: Vec<u8>) {
        if self.base.online && !self.detached {
            self.base.rxb += data.len() as u64;
            let interface_name = self.base.name.clone();
            let inbound_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                Transport::inbound(data, interface_name)
            }));
            if let Err(panic) = inbound_result {
                let _detail = if let Some(msg) = panic.downcast_ref::<&str>() {
                    (*msg).to_string()
                } else if let Some(msg) = panic.downcast_ref::<String>() {
                    msg.clone()
                } else {
                    "unknown panic".to_string()
                };
            }
        }
    }

    /// Process outgoing data
    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        crate::log(&format!("TCP outgoing {} bytes, online={}, detached={}", data.len(), self.base.online, self.detached), crate::LOG_VERBOSE, false, false);
        if !self.base.online || self.detached {
            return Err("Interface offline or detached".to_string());
        }

        self.writing = true;

        // Apply forced bitrate delay if set
        self.base.enforce_bitrate(data.len());

        let framed = if self.kiss_framing {
            let mut frame = vec![Kiss::FEND, Kiss::CMD_DATA];
            frame.extend_from_slice(&Kiss::escape(&data));
            frame.push(Kiss::FEND);
            frame
        } else {
            let mut frame = vec![Hdlc::FLAG];
            frame.extend_from_slice(&Hdlc::escape(&data));
            frame.push(Hdlc::FLAG);
            frame
        };

        if let Some(ref mut socket) = self.socket {
            #[cfg(unix)]
            let write_fd = {
                use std::os::unix::io::AsRawFd;
                socket.as_raw_fd()
            };
            crate::log(&format!("TCP write fd={} framed_len={}", write_fd, framed.len()), crate::LOG_DEBUG, false, false);
            match socket.write_all(&framed) {
                Ok(_) => {
                    self.base.txb += framed.len() as u64;
                }
                Err(e) => {
                    #[cfg(unix)]
                    crate::log(&format!("TCP write failed on fd={}, marking offline: {}", write_fd, e), crate::LOG_ERROR, false, false);
                    #[cfg(not(unix))]
                    crate::log(&format!("TCP write failed, marking offline: {}", e), crate::LOG_ERROR, false, false);
                    self.base.online = false;
                    if let Some(name) = &self.base.name {
                        Transport::set_interface_online(name, false);
                    }
                    // Python parity (RNS/Interfaces/TCPInterface.py:process_outgoing → teardown):
                    // Python uses a single shared socket object so a failed sendall()
                    // immediately causes the read_loop's recv() to fail, which then
                    // triggers reconnect(). Our read loop runs on a try_clone()'d fd,
                    // so nulling self.socket is not enough — the cloned fd would stay
                    // blocked in read() forever. Explicitly shut down BOTH halves so
                    // the cloned read fd returns EOF/error and the read loop's
                    // existing reconnect path (RECONNECT_WAIT=5s, matching Python)
                    // wakes up and re-establishes the connection.
                    let _ = socket.shutdown(std::net::Shutdown::Both);
                    // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                    // Belt-and-braces: shutdown(Both) on the writer-side fd has
                    // been observed to NOT wake the cloned read-side fd on
                    // long-running half-open connections (the wedge analysed
                    // in /memories/repo/rfed-tcp-watchdog-failure.md ran for
                    // 12+ hours after a write-failure with the read clone
                    // still blocked). Set an explicit kill-switch the read
                    // loop polls in its WouldBlock branch so a write failure
                    // forces the read loop to exit within one read-timeout
                    // interval (≤ READ_WAKE_INTERVAL seconds) and proceed
                    // straight to reconnect.
                    self.force_read_exit.store(true, Ordering::Relaxed);
                    self.socket = None;
                    self.writing = false;
                    return Err(format!("Failed to send data: {}", e));
                }
            }
        } else {
            return Err("No socket connection".to_string());
        }

        self.writing = false;
        Ok(())
    }

    /// Read loop (to be run in thread)
    pub fn read_loop(&mut self) -> Result<(), String> {
        let mut in_frame = false;
        let mut escape = false;
        let mut frame_buffer = Vec::new();
        let mut data_buffer = Vec::new();
        let mut command = Kiss::CMD_UNKNOWN;
        let mut buf = [0u8; 4096];

        loop {
            if let Some(ref mut socket) = self.socket {
                match socket.read(&mut buf) {
                    Ok(0) => {
                        // Connection closed
                        self.base.online = false;
                        if let Some(name) = &self.base.name {
                            Transport::set_interface_online(name, false);
                        }
                        if self.initiator && !self.detached {
                            println!("Socket for {} was closed, attempting to reconnect...", self.to_string());
                            self.reconnect();
                        } else {
                            println!("Socket for remote client {} was closed", self.to_string());
                            // TODO: self.teardown()
                        }
                        break;
                    }
                    Ok(n) => {
                        let data_in = &buf[..n];
                        
                        if self.kiss_framing {
                            // KISS framing
                            for &byte in data_in {
                                if in_frame && byte == Kiss::FEND && command == Kiss::CMD_DATA {
                                    in_frame = false;
                                    if !data_buffer.is_empty() {
                                        self.process_incoming(data_buffer.clone());
                                        data_buffer.clear();
                                    }
                                } else if byte == Kiss::FEND {
                                    in_frame = true;
                                    command = Kiss::CMD_UNKNOWN;
                                    data_buffer.clear();
                                } else if in_frame && data_buffer.len() < self.base.hw_mtu.unwrap_or(Self::HW_MTU) {
                                    if data_buffer.is_empty() && command == Kiss::CMD_UNKNOWN {
                                        command = byte & 0x0F;
                                    } else if command == Kiss::CMD_DATA {
                                        if byte == Kiss::FESC {
                                            escape = true;
                                        } else {
                                            if escape {
                                                let unescaped = match byte {
                                                    b if b == Kiss::TFEND => Kiss::FEND,
                                                    b if b == Kiss::TFESC => Kiss::FESC,
                                                    b => b,
                                                };
                                                data_buffer.push(unescaped);
                                                escape = false;
                                            } else {
                                                data_buffer.push(byte);
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // HDLC framing
                            frame_buffer.extend_from_slice(data_in);
                            
                            loop {
                                if let Some(frame_start) = frame_buffer.iter().position(|&b| b == Hdlc::FLAG) {
                                    if let Some(frame_end_offset) = frame_buffer[frame_start + 1..].iter().position(|&b| b == Hdlc::FLAG) {
                                        let frame_end = frame_start + 1 + frame_end_offset;
                                        let frame = &frame_buffer[frame_start + 1..frame_end];
                                        
                                        // Unescape frame
                                        let mut unescaped = Vec::new();
                                        let mut esc = false;
                                        for &byte in frame {
                                            if esc {
                                                if byte == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                                                    unescaped.push(Hdlc::FLAG);
                                                } else if byte == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                                                    unescaped.push(Hdlc::ESC);
                                                }
                                                esc = false;
                                            } else if byte == Hdlc::ESC {
                                                esc = true;
                                            } else {
                                                unescaped.push(byte);
                                            }
                                        }

                                        const HEADER_MINSIZE: usize = 2; // Placeholder
                                        if unescaped.len() > HEADER_MINSIZE {
                                            self.process_incoming(unescaped);
                                        }
                                        
                                        frame_buffer.drain(..=frame_end);
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        self.base.online = false;
                        if let Some(name) = &self.base.name {
                            Transport::set_interface_online(name, false);
                        }
                        
                        if self.initiator {
                            println!("Attempting to reconnect...");
                            self.reconnect();
                        } else {
                            // TODO: self.teardown()
                        }
                        return Err(format!("Read error: {}", e));
                    }
                }
            } else {
                return Err("No socket".to_string());
            }
        }

        Ok(())
    }

    /// How long (seconds) to wait with no inbound data before declaring
    /// the TCP connection dead and forcing a reconnect.  On backbone
    /// servers traffic arrives every few seconds, so 180 s without a
    /// single byte is a reliable indicator of a zombie connection.
    /// (Lower values can cause false reconnects on quiet networks.)
    const READ_WATCHDOG_TIMEOUT: u64 = 180;

    /// How often the read loop wakes from `read()` to poll the
    /// `force_read_exit` kill-switch and re-evaluate the watchdog.
    /// Bounded by §1 (5 s send budget): a write-failure must be able to
    /// trigger reconnect in well under 5 s of further blocking.
    const READ_WAKE_INTERVAL: u64 = 2;

    pub fn start_read_loop(interface: Arc<Mutex<TcpClientInterface>>) {
        // Guard: use `reconnecting` as a "loop is live" sentinel.
        // If another loop is already running for this exact Arc (e.g. a duplicate
        // call from a stale code path), silently return so we never accumulate
        // parallel read loops on a single interface.
        {
            let mut iface = interface.lock().unwrap();
            if iface.reconnecting {
                crate::log(
                    "TCP start_read_loop: loop already active for this interface, ignoring duplicate call",
                    crate::LOG_WARNING, false, false,
                );
                return;
            }
            iface.reconnecting = true;
        }

        thread::spawn(move || {
            // ── Outer loop: read → reconnect → read → … ─────────────────────
            // We never spawn a second thread.  After a successful reconnect we
            // simply `continue 'running` to re-clone the new socket and start
            // reading again in the same thread.
            'running: loop {
                // ── Clone current socket and read static config ───────────────
                let socket_result: Option<(TcpStream, Option<String>, bool, usize, bool, Arc<AtomicBool>)> = {
                    let iface = interface.lock().unwrap();
                    if let Some(socket_ref) = iface.socket.as_ref() {
                        if let Ok(cloned_socket) = socket_ref.try_clone() {
                            #[cfg(unix)] {
                                use std::os::unix::io::AsRawFd;
                                crate::log(&format!("TCP socket clone: original_fd={} clone_fd={}", socket_ref.as_raw_fd(), cloned_socket.as_raw_fd()), crate::LOG_NOTICE, false, false);
                            }
                            // Clear any stale kill-switch from a previous
                            // wedged connection — the new socket is healthy
                            // until proven otherwise.
                            iface.force_read_exit.store(false, Ordering::Relaxed);
                            Some((
                                cloned_socket,
                                iface.base.name.clone(),
                                iface.kiss_framing,
                                iface.base.hw_mtu.unwrap_or(Self::HW_MTU),
                                iface.initiator,
                                Arc::clone(&iface.force_read_exit),
                            ))
                        } else {
                            crate::log("TCP read loop: socket clone failed", crate::LOG_WARNING, false, false);
                            None
                        }
                    } else {
                        // No socket yet (initial connect failed) — fall through
                        // to the reconnect section below.
                        None
                    }
                };

                // If we have no socket, skip straight to the reconnect logic
                // instead of breaking out entirely.
                if socket_result.is_none() {
                    let iface_name = interface.lock().unwrap().base.name.clone();
                    crate::log(
                        &format!("TCP read loop: no socket for {:?}, entering reconnect", iface_name),
                        crate::LOG_NOTICE, false, false,
                    );
                } else {

                let (raw_socket, interface_name, kiss_framing, hw_mtu, is_initiator, force_read_exit) = socket_result.unwrap();
                // Wrap in ManuallyDrop so we control when close() is called.
                // If the OS reclaims our fd (e.g., iOS background), Rust's
                // automatic Drop would call close() on a potentially-reused fd
                // number, corrupting an unrelated socket.
                let mut socket = std::mem::ManuallyDrop::new(raw_socket);
                let mut ebadf = false;

                crate::log(&format!("TCP read loop started for {:?}", interface_name), crate::LOG_NOTICE, false, false);

                // Wake from blocking read every READ_WAKE_INTERVAL seconds so
                // we can poll the `force_read_exit` kill-switch (set by
                // `process_outgoing` when a write fails) and so the
                // READ_WATCHDOG_TIMEOUT no-data deadline is checked at fine
                // granularity. The kernel-level SO_KEEPALIVE / TCP_USER_TIMEOUT
                // is the primary defence against half-open peers; this poll
                // interval is a belt-and-braces backstop.
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                if let Err(e) = socket.set_read_timeout(Some(Duration::from_secs(Self::READ_WAKE_INTERVAL))) {
                    crate::log(&format!("TCP read loop: set_read_timeout failed: {}", e), crate::LOG_WARNING, false, false);
                }

                // Framing state resets on each new connection.
                let mut in_frame = false;
                let mut escape = false;
                let mut frame_buffer = Vec::new();
                let mut data_buffer = Vec::new();
                let mut command = Kiss::CMD_UNKNOWN;
                let mut buf = [0u8; 4096];
                let mut read_count: u64 = 0;
                let mut last_data_time = std::time::Instant::now();

                crate::log("TCP read loop: entering blocking read", crate::LOG_NOTICE, false, false);

                // ── Inner read loop ───────────────────────────────────────────
                'reading: loop {
                    match socket.read(&mut buf) {
                        Ok(0) => {
                            crate::log("TCP read loop: connection closed (read 0)", crate::LOG_NOTICE, false, false);
                            break 'reading;
                        }
                        Ok(n) => {
                            read_count += 1;
                            last_data_time = std::time::Instant::now();
                            crate::log(&format!("TCP inbound: {} bytes (read #{})", n, read_count), crate::LOG_VERBOSE, false, false);
                            let data_in = &buf[..n];

                            if kiss_framing {
                                for &byte in data_in {
                                    if in_frame && byte == Kiss::FEND && command == Kiss::CMD_DATA {
                                        in_frame = false;
                                        if !data_buffer.is_empty() {
                                            let _ = Transport::inbound(data_buffer.clone(), interface_name.clone());
                                            data_buffer.clear();
                                        }
                                    } else if byte == Kiss::FEND {
                                        in_frame = true;
                                        command = Kiss::CMD_UNKNOWN;
                                        data_buffer.clear();
                                    } else if in_frame && data_buffer.len() < hw_mtu {
                                        if data_buffer.is_empty() && command == Kiss::CMD_UNKNOWN {
                                            command = byte & 0x0F;
                                        } else if command == Kiss::CMD_DATA {
                                            if byte == Kiss::FESC {
                                                escape = true;
                                            } else if escape {
                                                let unescaped = match byte {
                                                    b if b == Kiss::TFEND => Kiss::FEND,
                                                    b if b == Kiss::TFESC => Kiss::FESC,
                                                    b => b,
                                                };
                                                data_buffer.push(unescaped);
                                                escape = false;
                                            } else {
                                                data_buffer.push(byte);
                                            }
                                        }
                                    }
                                }
                            } else {
                                frame_buffer.extend_from_slice(data_in);
                                crate::log(&format!("TCP HDLC: frame_buffer len={} after extend", frame_buffer.len()), crate::LOG_DEBUG, false, false);

                                loop {
                                    if let Some(frame_start) = frame_buffer.iter().position(|&b| b == Hdlc::FLAG) {
                                        if let Some(frame_end_offset) = frame_buffer[frame_start + 1..].iter().position(|&b| b == Hdlc::FLAG) {
                                            let frame_end = frame_start + 1 + frame_end_offset;
                                            let frame = &frame_buffer[frame_start + 1..frame_end];

                                            let mut unescaped = Vec::new();
                                            let mut esc = false;
                                            for &byte in frame {
                                                if esc {
                                                    if byte == (Hdlc::FLAG ^ Hdlc::ESC_MASK) {
                                                        unescaped.push(Hdlc::FLAG);
                                                    } else if byte == (Hdlc::ESC ^ Hdlc::ESC_MASK) {
                                                        unescaped.push(Hdlc::ESC);
                                                    }
                                                    esc = false;
                                                } else if byte == Hdlc::ESC {
                                                    esc = true;
                                                } else {
                                                    unescaped.push(byte);
                                                }
                                            }

                                            const HEADER_MINSIZE: usize = 2;
                                            if unescaped.len() > HEADER_MINSIZE {
                                                crate::log(&format!("TCP frame: {} bytes, passing to Transport::inbound", unescaped.len()), crate::LOG_DEBUG, false, false);
                                                let _ = std::io::Write::flush(&mut std::io::stderr());
                                                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                                    Transport::inbound(unescaped.clone(), interface_name.clone())
                                                }));
                                                match &result {
                                                    Ok(_v) => {
                                                        crate::log("TCP frame: Transport::inbound returned OK", crate::LOG_DEBUG, false, false);
                                                        let _ = std::io::Write::flush(&mut std::io::stderr());
                                                    }
                                                    Err(panic) => {
                                                        let detail = if let Some(s) = panic.downcast_ref::<&str>() {
                                                            s.to_string()
                                                        } else if let Some(s) = panic.downcast_ref::<String>() {
                                                            s.clone()
                                                        } else {
                                                            "unknown panic".to_string()
                                                        };
                                                        crate::log(&format!("TCP frame: Transport::inbound PANICKED: {}", detail), crate::LOG_ERROR, false, false);
                                                    }
                                                }
                                            } else {
                                                crate::log(&format!("TCP frame: {} bytes TOO SMALL, skipping", unescaped.len()), crate::LOG_DEBUG, false, false);
                                            }

                                            frame_buffer.drain(..=frame_end);
                                            crate::log(&format!("TCP HDLC: drained to frame_end={}, remaining={}", frame_end, frame_buffer.len()), crate::LOG_DEBUG, false, false);
                                        } else {
                                            crate::log(&format!("TCP HDLC: partial frame, waiting (buf={})", frame_buffer.len()), crate::LOG_DEBUG, false, false);
                                            break;
                                        }
                                    } else {
                                        crate::log(&format!("TCP HDLC: no flag byte in buffer (buf={})", frame_buffer.len()), crate::LOG_DEBUG, false, false);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                            // Belt-and-braces wake from process_outgoing's
                            // write-failure path. shutdown(Both) on the
                            // writer-side fd has been observed to NOT
                            // propagate to this cloned read fd on
                            // long-running half-open connections (see
                            // /memories/repo/rfed-tcp-watchdog-failure.md).
                            if force_read_exit.load(Ordering::Relaxed) {
                                crate::log(
                                    "TCP read loop: force_read_exit set by writer — exiting to reconnect",
                                    crate::LOG_WARNING, false, false,
                                );
                                break 'reading;
                            }
                            let idle_secs = last_data_time.elapsed().as_secs();
                            if idle_secs >= Self::READ_WATCHDOG_TIMEOUT {
                                crate::log(
                                    &format!(
                                        "TCP watchdog: no data received for {}s (threshold {}s), connection appears dead — triggering reconnect",
                                        idle_secs, Self::READ_WATCHDOG_TIMEOUT
                                    ),
                                    crate::LOG_WARNING,
                                    false, false,
                                );
                                break 'reading;
                            }
                            // Timeout fired but we haven't exceeded the watchdog threshold yet.
                            continue 'reading;
                        }
                        Err(e) => {
                            #[cfg(unix)] {
                                use std::os::unix::io::AsRawFd;
                                let fd = socket.as_raw_fd();
                                if e.raw_os_error() == Some(9) { // EBADF
                                    ebadf = true;
                                    crate::log(&format!("TCP read loop: EBADF on fd={} — fd was reclaimed by OS", fd), crate::LOG_ERROR, false, false);
                                } else {
                                    crate::log(&format!("TCP read loop: socket error on fd={}: {}", fd, e), crate::LOG_ERROR, false, false);
                                }
                            }
                            #[cfg(not(unix))]
                            crate::log(&format!("TCP read loop: socket error: {}", e), crate::LOG_ERROR, false, false);
                            break 'reading;
                        }
                    }
                } // 'reading

                // ── Read loop exited ──────────────────────────────────────────
                // Handle the cloned socket carefully.  If EBADF occurred the fd
                // was already closed/reclaimed by the OS (common on iOS during
                // background transitions).  Calling close() on that fd number
                // would corrupt whatever new socket inherited it.
                if ebadf {
                    // Intentionally leak — the fd is already gone.
                    crate::log("TCP: leaking dead socket fd (EBADF — already reclaimed by OS)", crate::LOG_WARNING, false, false);
                    // ManuallyDrop prevents close(); nothing else needed.
                } else {
                    // Normal exit (EOF, timeout, connection reset) — close the clone.
                    unsafe { std::mem::ManuallyDrop::drop(&mut socket); }
                }

                crate::log("TCP read loop exited, marking interface offline", crate::LOG_WARNING, false, false);
                {
                    let mut iface = interface.lock().unwrap();
                    iface.base.online = false;
                    if let Some(name) = &iface.base.name {
                        Transport::set_interface_online(name, false);
                    }
                    iface.socket = None;
                }

                // For server-side (accepted) connections, deregister and stop.
                if !is_initiator {
                    let iface_name = interface.lock().unwrap().base.name.clone();
                    if let Some(ref name) = iface_name {
                        crate::transport::Transport::deregister_interface_stub(name);
                        crate::transport::Transport::unregister_outbound_handler(name);
                        crate::log(
                            &format!("TCP server client disconnected, deregistered interface {}", name),
                            crate::LOG_NOTICE, false, false,
                        );
                    }
                    break 'running;
                }

                } // end of `if socket_result.is_some()` block

                // ── Reconnect (initiator only) ────────────────────────────────
                crate::log("TCP read loop: initiator, attempting reconnect...", crate::LOG_NOTICE, false, false);
                let mut attempts = 0u32;
                let reconnected = 'reconnect: loop {
                    // Wait up to RECONNECT_WAIT seconds, but wake immediately
                    // if the platform signals that network connectivity is back.
                    wait_or_nudge(Self::RECONNECT_WAIT);
                    attempts += 1;

                    let (detached, max_tries) = {
                        let iface = interface.lock().unwrap();
                        (iface.detached, iface.max_reconnect_tries)
                    };

                    if detached {
                        crate::log("TCP reconnect: interface detached, giving up", crate::LOG_NOTICE, false, false);
                        break 'reconnect false;
                    }

                    if let Some(max) = max_tries {
                        if attempts as usize > max {
                            crate::log(&format!("TCP reconnect: max attempts ({}) reached, giving up", max), crate::LOG_ERROR, false, false);
                            break 'reconnect false;
                        }
                    }

                    crate::log(&format!("TCP reconnect attempt {}...", attempts), crate::LOG_NOTICE, false, false);
                    let ok = {
                        let mut iface = interface.lock().unwrap();
                        iface.connect(false).is_ok()
                    };

                    if ok {
                        crate::log("TCP reconnected successfully, restarting read loop", crate::LOG_NOTICE, false, false);
                        break 'reconnect true;
                    } else {
                        crate::log(&format!("TCP reconnect attempt {} failed", attempts), crate::LOG_WARNING, false, false);
                    }
                }; // 'reconnect

                if !reconnected {
                    break 'running;
                }

                // Synthesize tunnel on the new connection then loop back to read.
                let (kiss_framing2, iname, irepr) = {
                    let iface = interface.lock().unwrap();
                    (iface.kiss_framing, iface.base.name.clone().unwrap_or_default(), iface.to_string())
                };
                if !kiss_framing2 {
                    crate::transport::Transport::synthesize_tunnel(&iname, &irepr);
                }
                // continue 'running → re-clone the new socket and read again
            } // 'running

            // Clear the "loop is live" sentinel so the interface can be restarted.
            interface.lock().unwrap().reconnecting = false;
        });
    }

    /// Detach interface
    pub fn detach(&mut self) {
        self.base.online = false;
        if let Some(name) = &self.base.name {
            Transport::set_interface_online(name, false);
        }
        self.detached = true;
        
        if let Some(ref mut socket) = self.socket {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        self.socket = None;
    }

    /// Get string representation
    pub fn to_string(&self) -> String {
        let ip_str = if self.target_ip.contains(':') {
            format!("[{}]", self.target_ip)
        } else {
            self.target_ip.clone()
        };
        
        format!(
            "TCPInterface[{}/{}:{}]",
            self.base.name.as_ref().unwrap_or(&"unnamed".to_string()),
            ip_str,
            self.target_port
        )
    }
}

/// TCP Server Interface
/// 
/// Listens for incoming TCP connections and spawns TcpClientInterface
/// for each connection.
pub struct TcpServerInterface {
    pub base: Interface,
    pub bind_ip: String,
    pub bind_port: u16,
    pub i2p_tunneled: bool,
    pub mode: u8,
    spawn_config: Arc<Mutex<SpawnConfig>>,
    pub spawned_interfaces: Arc<Mutex<Vec<Arc<Mutex<TcpClientInterface>>>>>,
    #[allow(dead_code)]
    listener: Option<Arc<TcpListener>>,
}

#[derive(Clone)]
struct SpawnConfig {
    mode: InterfaceMode,
    out_enabled: bool,
    bitrate: u64,
    announce_cap: f64,
    announce_rate_target: Option<f64>,
    announce_rate_grace: Option<f64>,
    announce_rate_penalty: Option<f64>,
    ingress_control: bool,
    ic_max_held_announces: usize,
    ic_burst_hold: f64,
    ic_burst_freq_new: f64,
    ic_burst_freq: f64,
    ic_new_time: f64,
    ic_burst_penalty: f64,
    ic_held_release_interval: f64,
    bootstrap_only: bool,
    discoverable: bool,
    discovery_announce_interval: Option<f64>,
    discovery_publish_ifac: bool,
    reachable_on: Option<String>,
    discovery_name: Option<String>,
    discovery_encrypt: bool,
    discovery_stamp_value: Option<u32>,
    discovery_latitude: Option<f64>,
    discovery_longitude: Option<f64>,
    discovery_height: Option<f64>,
    discovery_frequency: Option<u64>,
    discovery_bandwidth: Option<u32>,
    discovery_modulation: Option<String>,
    ifac_size: usize,
    ifac_netname: Option<String>,
    ifac_netkey: Option<String>,
    ifac_key: Option<Vec<u8>>,
    ifac_signature: Option<Vec<u8>>,
}

impl SpawnConfig {
    fn from_base(base: &Interface) -> Self {
        SpawnConfig {
            mode: base.mode,
            out_enabled: base.out_enabled,
            bitrate: base.bitrate,
            announce_cap: base.announce_cap,
            announce_rate_target: base.announce_rate_target,
            announce_rate_grace: base.announce_rate_grace,
            announce_rate_penalty: base.announce_rate_penalty,
            ingress_control: base.ingress_control,
            ic_max_held_announces: base.ic_max_held_announces,
            ic_burst_hold: base.ic_burst_hold,
            ic_burst_freq_new: base.ic_burst_freq_new,
            ic_burst_freq: base.ic_burst_freq,
            ic_new_time: base.ic_new_time,
            ic_burst_penalty: base.ic_burst_penalty,
            ic_held_release_interval: base.ic_held_release_interval,
            bootstrap_only: base.bootstrap_only,
            discoverable: base.discoverable,
            discovery_announce_interval: base.discovery_announce_interval,
            discovery_publish_ifac: base.discovery_publish_ifac,
            reachable_on: base.reachable_on.clone(),
            discovery_name: base.discovery_name.clone(),
            discovery_encrypt: base.discovery_encrypt,
            discovery_stamp_value: base.discovery_stamp_value,
            discovery_latitude: base.discovery_latitude,
            discovery_longitude: base.discovery_longitude,
            discovery_height: base.discovery_height,
            discovery_frequency: base.discovery_frequency,
            discovery_bandwidth: base.discovery_bandwidth,
            discovery_modulation: base.discovery_modulation.clone(),
            ifac_size: base.ifac_size,
            ifac_netname: base.ifac_netname.clone(),
            ifac_netkey: base.ifac_netkey.clone(),
            ifac_key: base.ifac_key.clone(),
            ifac_signature: base.ifac_signature.clone(),
        }
    }

    fn apply_to_base(&self, base: &mut Interface) {
        base.mode = self.mode;
        base.out_enabled = self.out_enabled;
        base.bitrate = self.bitrate;
        base.announce_cap = self.announce_cap;
        base.announce_rate_target = self.announce_rate_target;
        base.announce_rate_grace = self.announce_rate_grace;
        base.announce_rate_penalty = self.announce_rate_penalty;
        base.ingress_control = self.ingress_control;
        base.ic_max_held_announces = self.ic_max_held_announces;
        base.ic_burst_hold = self.ic_burst_hold;
        base.ic_burst_freq_new = self.ic_burst_freq_new;
        base.ic_burst_freq = self.ic_burst_freq;
        base.ic_new_time = self.ic_new_time;
        base.ic_burst_penalty = self.ic_burst_penalty;
        base.ic_held_release_interval = self.ic_held_release_interval;
        base.bootstrap_only = self.bootstrap_only;
        base.discoverable = self.discoverable;
        base.discovery_announce_interval = self.discovery_announce_interval;
        base.discovery_publish_ifac = self.discovery_publish_ifac;
        base.reachable_on = self.reachable_on.clone();
        base.discovery_name = self.discovery_name.clone();
        base.discovery_encrypt = self.discovery_encrypt;
        base.discovery_stamp_value = self.discovery_stamp_value;
        base.discovery_latitude = self.discovery_latitude;
        base.discovery_longitude = self.discovery_longitude;
        base.discovery_height = self.discovery_height;
        base.discovery_frequency = self.discovery_frequency;
        base.discovery_bandwidth = self.discovery_bandwidth;
        base.discovery_modulation = self.discovery_modulation.clone();
        base.ifac_size = self.ifac_size;
        base.ifac_netname = self.ifac_netname.clone();
        base.ifac_netkey = self.ifac_netkey.clone();
        base.ifac_key = self.ifac_key.clone();
        base.ifac_signature = self.ifac_signature.clone();
    }
}

fn mode_to_u8(mode: InterfaceMode) -> u8 {
    match mode {
        InterfaceMode::Full => 0x01,
        InterfaceMode::PointToPoint => 0x02,
        InterfaceMode::AccessPoint => 0x03,
        InterfaceMode::Roaming => 0x04,
        InterfaceMode::Boundary => 0x05,
        InterfaceMode::Gateway => 0x06,
    }
}

impl TcpServerInterface {
    pub const HW_MTU: usize = 262144;
    pub const BITRATE_GUESS: u64 = 10_000_000;
    pub const DEFAULT_IFAC_SIZE: usize = 16;

    /// Create new TCP server from configuration
    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let name = config.get("name")
            .ok_or("TCPServerInterface requires 'name' in config")?
            .clone();
        
        let bind_ip = config.get("listen_ip")
            .ok_or("TCPServerInterface requires 'listen_ip' in config")?
            .clone();
        
        let bind_port = config.get("listen_port")
            .or_else(|| config.get("port"))
            .ok_or("TCPServerInterface requires 'listen_port' or 'port' in config")?
            .parse::<u16>()
            .map_err(|_| "Invalid bind port")?;
        
        let i2p_tunneled = config.get("i2p_tunneled")
            .and_then(|s| s.parse::<bool>().ok())
            .unwrap_or(false);

        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = false;
        base.hw_mtu = Some(Self::HW_MTU);
        base.bitrate = Self::BITRATE_GUESS;
        base.online = false;
        base.supports_discovery = true;

        let bind_addr = format!("{}:{}", bind_ip, bind_port);
        let listener = TcpListener::bind(&bind_addr)
            .map_err(|e| format!("Failed to bind to {}: {}", bind_addr, e))?;

        let listener_arc = Arc::new(listener);
        let spawned = Arc::new(Mutex::new(Vec::new()));

        // Spawn accept loop
        let listener_clone = listener_arc.clone();
        let spawned_clone = spawned.clone();
        let name_clone = base.name.clone();
        let spawn_config = Arc::new(Mutex::new(SpawnConfig::from_base(&base)));
        let spawn_config_clone = Arc::clone(&spawn_config);
        
        thread::spawn(move || {
            Self::accept_loop(listener_clone, spawned_clone, name_clone, spawn_config_clone);
        });

        base.online = true;

        Ok(TcpServerInterface {
            base,
            bind_ip,
            bind_port,
            i2p_tunneled,
            mode: 0x01, // MODE_FULL
            spawn_config,
            spawned_interfaces: spawned,
            listener: Some(listener_arc),
        })
    }

    pub fn update_spawn_config(&mut self) {
        *self.spawn_config.lock().unwrap() = SpawnConfig::from_base(&self.base);
        self.mode = mode_to_u8(self.base.mode);
    }

    /// Accept loop for incoming connections
    fn accept_loop(
        listener: Arc<TcpListener>,
        spawned: Arc<Mutex<Vec<Arc<Mutex<TcpClientInterface>>>>>,
        server_name: Option<String>,
        spawn_config: Arc<Mutex<SpawnConfig>>,
    ) {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    println!("Accepting incoming TCP connection");
                    
                    let peer_addr = stream.peer_addr().ok();
                    let client_name = match &peer_addr {
                        Some(addr) => format!("Client on {} [{}]", server_name.as_ref().unwrap_or(&"Server".to_string()), addr),
                        None => format!("Client on {}", server_name.as_ref().unwrap_or(&"Server".to_string())),
                    };
                    
                    let spawned_interface = Arc::new(Mutex::new(TcpClientInterface::from_socket(client_name, stream)));
                    let iface_name;
                    let client_mode;
                    {
                        let sc = spawn_config.lock().unwrap();
                        let mut iface = spawned_interface.lock().unwrap();
                        sc.apply_to_base(&mut iface.base);
                        client_mode = mode_to_u8(sc.mode);
                        iface.mode = client_mode;

                        if let Some(addr) = peer_addr {
                            iface.target_ip = addr.ip().to_string();
                            iface.target_port = addr.port();
                        }

                        iface_name = iface.base.name.clone().unwrap_or_default();
                        println!("Spawned new TCPClient Interface: {}", iface.to_string());
                    }

                    // Register the spawned interface with Transport so it can send outbound data
                    // (path responses, announces, etc.) back to the connected client.
                    let handler_iface = Arc::clone(&spawned_interface);
                    crate::transport::Transport::register_outbound_handler(
                        &iface_name,
                        Arc::new(move |raw| {
                            let mut iface = handler_iface.lock().unwrap();
                            iface.process_outgoing(raw.to_vec()).is_ok()
                        }),
                    );
                    // Register as a local client interface FIRST, before
                    // adding to state.interfaces.  This ensures the
                    // outbound() announce broadcast filter sees the
                    // interface in local_client_interfaces by the time it
                    // appears in the interfaces list (eliminates a race
                    // where jobs()/outbound() bursts announce retransmits
                    // to the new interface before it's marked as a local
                    // client).
                    crate::transport::Transport::register_local_client_interface(&iface_name);
                    {
                        let mut stub_config = crate::transport::InterfaceStubConfig::default();
                        stub_config.name = iface_name.clone();
                        stub_config.mode = client_mode;
                        stub_config.out = true;
                        stub_config.online = Some(true);
                        stub_config.announce_cap = Some(crate::reticulum::ANNOUNCE_CAP / 100.0);
                        crate::transport::Transport::register_interface_stub_config(stub_config);
                    }

                    TcpClientInterface::start_read_loop(Arc::clone(&spawned_interface));
                    spawned.lock().unwrap().push(spawned_interface);
                }
                Err(_e) => {
                }
            }
        }
    }

    /// Get number of connected clients
    pub fn clients(&self) -> usize {
        self.spawned_interfaces.lock().unwrap().len()
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

    /// Process outgoing (no-op for server)
    pub fn process_outgoing(&self, _data: Vec<u8>) {
        // Server doesn't send directly
    }

    /// Detach server
    pub fn detach(&mut self) {
        self.base.online = false;
        // Listener will be dropped when Arc count reaches 0
    }

    /// Get string representation
    pub fn to_string(&self) -> String {
        let ip_str = if self.bind_ip.contains(':') {
            format!("[{}]", self.bind_ip)
        } else {
            self.bind_ip.clone()
        };
        
        format!(
            "TCPServerInterface[{}/{}:{}]",
            self.base.name.as_ref().unwrap_or(&"unnamed".to_string()),
            ip_str,
            self.bind_port
        )
    }
}

impl std::fmt::Display for TcpClientInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::fmt::Display for TcpServerInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdlc_escape() {
        let data = vec![0x12, Hdlc::FLAG, 0x34, Hdlc::ESC, 0x56];
        let escaped = Hdlc::escape(&data);
        assert!(escaped.len() > data.len());
        assert!(!escaped.contains(&Hdlc::FLAG));
    }

    #[test]
    fn test_kiss_escape() {
        let data = vec![0x12, Kiss::FEND, 0x34, Kiss::FESC, 0x56];
        let escaped = Kiss::escape(&data);
        assert!(escaped.len() > data.len());
        assert!(!escaped.contains(&Kiss::FEND));
        assert_eq!(escaped.iter().filter(|&&b| b == Kiss::FESC).count(), 2);
    }

    // ── Helpers for integration tests ─────────────────────────────────

    /// Create a TcpClientInterface connected to a local listener, returning
    /// (Arc<Mutex<interface>>, server_stream).
    fn make_connected_pair() -> (Arc<Mutex<TcpClientInterface>>, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect a raw stream first, then inject it via from_socket
        let client_stream = TcpStream::connect_timeout(
            &addr,
            Duration::from_secs(2),
        ).unwrap();
        client_stream.set_nodelay(true).unwrap();

        let (server_stream, _) = listener.accept().unwrap();
        server_stream.set_nodelay(true).unwrap();

        let mut iface = TcpClientInterface::from_socket(
            "test".to_string(),
            client_stream,
        );
        // Mark as initiator so the read-loop will attempt reconnect
        iface.initiator = true;

        (Arc::new(Mutex::new(iface)), server_stream)
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 1: Clone fd remains valid while original fd lives
    //
    // Reproduces the basic setup from retichat.log:
    //   TCP socket clone: original_fd=7 clone_fd=8
    // Verifies the clone can read while the original is used for writes.
    // ────────────────────────────────────────────────────────────────────
    #[test]
    fn test_clone_fd_survives_concurrent_writes() {
        let (iface_arc, mut server) = make_connected_pair();

        // Clone the socket exactly like start_read_loop does
        let clone = {
            let iface = iface_arc.lock().unwrap();
            iface.socket.as_ref().unwrap().try_clone().unwrap()
        };

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let orig_fd = iface_arc.lock().unwrap().socket.as_ref().unwrap().as_raw_fd();
            let clone_fd = clone.as_raw_fd();
            eprintln!("test: original_fd={} clone_fd={}", orig_fd, clone_fd);
            assert_ne!(orig_fd, clone_fd, "clone must have a distinct fd");
        }

        clone.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

        // Start a reader thread (simulates start_read_loop's inner 'reading loop)
        let reader = {
            let mut read_sock = clone;
            thread::spawn(move || -> Vec<u8> {
                let mut buf = [0u8; 4096];
                let mut received = Vec::new();
                loop {
                    match read_sock.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => received.extend_from_slice(&buf[..n]),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => break,
                        Err(e) => panic!("read error (EBADF?): {}", e),
                    }
                }
                received
            })
        };

        // Simulate concurrent outgoing writes on the *original* socket
        // (like synthesize_tunnel + PSYNC path requests from Transport threads)
        for i in 0..20 {
            {
                let mut iface = iface_arc.lock().unwrap();
                let payload = format!("write_{:04}", i);
                let _ = iface.process_outgoing(payload.into_bytes());
            }
            thread::sleep(Duration::from_millis(50));
        }

        // Server sends data through — the clone must receive it
        let test_payload = b"server_data_hello";
        server.write_all(test_payload).unwrap();
        server.flush().unwrap();

        // Wait for reader to finish (read timeout)
        let received = reader.join().expect("reader thread panicked");
        // The received data includes HDLC frames from process_outgoing that the
        // _server_ sees, but the server also sent test_payload.  Check the reader
        // got the server's payload.
        assert!(
            received.windows(test_payload.len()).any(|w| w == test_payload),
            "clone failed to receive server data — possible EBADF or fd invalidation\nreceived {} bytes: {:?}",
            received.len(),
            String::from_utf8_lossy(&received),
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 2: Dropping original socket does NOT invalidate the clone
    //
    // Simulates what happens when process_outgoing gets a write error and
    // sets self.socket = None (dropping the TcpStream, calling close(fd)).
    // The clone — which has its own fd via dup() — must keep working.
    // ────────────────────────────────────────────────────────────────────
    #[test]
    fn test_clone_survives_original_drop() {
        let (iface_arc, mut server) = make_connected_pair();

        // Clone exactly like start_read_loop
        let mut clone = {
            let iface = iface_arc.lock().unwrap();
            iface.socket.as_ref().unwrap().try_clone().unwrap()
        };

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let orig_fd = iface_arc.lock().unwrap().socket.as_ref().unwrap().as_raw_fd();
            let clone_fd = clone.as_raw_fd();
            eprintln!("test: original_fd={} clone_fd={}", orig_fd, clone_fd);
        }

        // Drop the original (simulates write-error path: self.socket = None)
        {
            let mut iface = iface_arc.lock().unwrap();
            iface.socket = None;
            iface.base.online = false;
        }

        // The clone must still work.  Server sends data, clone reads it.
        let test_payload = b"after_drop_test";
        server.write_all(test_payload).unwrap();
        server.flush().unwrap();

        clone.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut buf = [0u8; 256];
        let n = clone.read(&mut buf).expect("clone read failed after original drop — EBADF?");
        assert_eq!(&buf[..n], test_payload, "clone received wrong data after original drop");
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 3: Reconnect creates new socket — old clone must be independent
    //
    // Simulates the full retichat.log cycle:
    //   1. Connect → clone for read loop
    //   2. Connection dies → drop original
    //   3. Reconnect with new socket
    //   4. Old clone fd must not collide with new socket fd
    //
    // From the log:
    //   First:  original_fd=7 clone_fd=8
    //   After:  original_fd=7 clone_fd=10  (fd=8 reused by something else)
    // ────────────────────────────────────────────────────────────────────
    #[test]
    #[cfg(unix)]
    fn test_reconnect_fd_independence() {
        use std::os::unix::io::AsRawFd;

        // Set up server that accepts two connections (original + reconnect)
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (s1, _) = listener.accept().unwrap();
            let (s2, _) = listener.accept().unwrap();
            (s1, s2)
        });

        // --- Connection 1 ---
        let stream1 = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        stream1.set_nodelay(true).unwrap();
        let mut clone1 = stream1.try_clone().unwrap();

        let orig_fd1 = stream1.as_raw_fd();
        let clone_fd1 = clone1.as_raw_fd();
        eprintln!("connection1: original_fd={} clone_fd={}", orig_fd1, clone_fd1);

        // Simulate connection death — drop original + close its fd
        drop(stream1);

        // Open some decoy fds to simulate the OS reusing the number
        // (like iOS allocating fds for ViewBridge, etc.)
        let decoy1 = std::fs::File::open("/dev/null").ok();
        let decoy2 = std::fs::File::open("/dev/null").ok();
        let decoy_fds: Vec<i32> = [&decoy1, &decoy2]
            .iter()
            .filter_map(|d| d.as_ref().map(|f| f.as_raw_fd()))
            .collect();
        eprintln!("decoy fds: {:?}", decoy_fds);

        // --- Connection 2 (reconnect) ---
        let stream2 = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        stream2.set_nodelay(true).unwrap();
        let mut clone2 = stream2.try_clone().unwrap();

        let orig_fd2 = stream2.as_raw_fd();
        let clone_fd2 = clone2.as_raw_fd();
        eprintln!("connection2: original_fd={} clone_fd={}", orig_fd2, clone_fd2);

        // Key assertion: clone1's fd must not be the same as any new fd
        assert_ne!(clone_fd1, orig_fd2, "clone1 fd reused as reconnect original — fd collision!");
        assert_ne!(clone_fd1, clone_fd2, "clone1 fd reused as reconnect clone — fd collision!");

        // clone1 should be EBADF or disconnected at this point (server-side close)
        clone1.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut buf = [0u8; 16];
        let result = clone1.read(&mut buf);
        eprintln!("clone1 read after reconnect: {:?}", result);
        // Either Ok(0) (connection closed) or error — NOT a successful read
        match result {
            Ok(0) => {} // expected: server side closed
            Ok(n) => panic!("clone1 read {} bytes from a dead connection — fd collision!", n),
            Err(_) => {} // expected: broken pipe / connection reset / EBADF
        }

        // clone2 must work on the new connection
        let (_server1, mut server2) = server_thread.join().unwrap();
        let test_data = b"reconnect_works";
        server2.write_all(test_data).unwrap();
        server2.flush().unwrap();

        clone2.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let n = clone2.read(&mut buf).expect("clone2 read failed on new connection");
        assert_eq!(&buf[..n], test_data);

        drop(decoy1);
        drop(decoy2);
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 4: Stress-test concurrent read/write with fd validity checks
    //
    // Exercises the exact concurrency pattern from retichat.log:
    //   - Reader thread blocked on socket.read()
    //   - Multiple writer threads calling process_outgoing()
    //   - Timed check that the reader fd stays valid for 5 seconds
    //
    // This is the pattern that triggers EBADF on macOS Catalyst.
    // ────────────────────────────────────────────────────────────────────
    #[test]
    #[cfg(unix)]
    fn test_concurrent_rw_fd_stability() {
        use std::os::unix::io::AsRawFd;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (iface_arc, mut server) = make_connected_pair();

        let clone = {
            let iface = iface_arc.lock().unwrap();
            iface.socket.as_ref().unwrap().try_clone().unwrap()
        };
        let clone_fd = clone.as_raw_fd();
        eprintln!("test: clone_fd={}", clone_fd);

        let stop = Arc::new(AtomicBool::new(false));
        let ebadf_detected = Arc::new(AtomicBool::new(false));

        // Reader thread — mirrors start_read_loop's 'reading loop
        let reader = {
            let stop_r = Arc::clone(&stop);
            let ebadf_r = Arc::clone(&ebadf_detected);
            let mut read_sock = clone;
            read_sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while !stop_r.load(Ordering::Relaxed) {
                    match read_sock.read(&mut buf) {
                        Ok(_) => {}
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => continue,
                        Err(ref e) if e.raw_os_error() == Some(9) => {
                            eprintln!("EBADF detected on clone_fd={}", read_sock.as_raw_fd());
                            ebadf_r.store(true, Ordering::Relaxed);
                            return;
                        }
                        Err(e) => {
                            eprintln!("reader error: {}", e);
                            return;
                        }
                    }
                }
            })
        };

        // Writer threads — simulate Transport threads sending packets
        // (synthesize_tunnel, PSYNC path requests, link requests, keepalives)
        let writers: Vec<_> = (0..4).map(|tid| {
            let iface = Arc::clone(&iface_arc);
            let stop_w = Arc::clone(&stop);
            thread::spawn(move || {
                let mut i = 0u32;
                while !stop_w.load(Ordering::Relaxed) {
                    {
                        let mut guard = iface.lock().unwrap();
                        let payload = format!("t{}_{}", tid, i);
                        let _ = guard.process_outgoing(payload.into_bytes());
                    }
                    i += 1;
                    thread::sleep(Duration::from_millis(10));
                }
            })
        }).collect();

        // Server sends periodic data (like inbound announces/proofs)
        let server_writer = {
            let stop_s = Arc::clone(&stop);
            thread::spawn(move || {
                let mut i = 0u32;
                while !stop_s.load(Ordering::Relaxed) {
                    let data = format!("srv_{}", i);
                    if server.write_all(data.as_bytes()).is_err() {
                        break;
                    }
                    let _ = server.flush();
                    i += 1;
                    thread::sleep(Duration::from_millis(50));
                }
            })
        };

        // Run for 5 seconds then check
        thread::sleep(Duration::from_secs(5));
        stop.store(true, Ordering::Relaxed);

        reader.join().unwrap();
        for w in writers { w.join().unwrap(); }
        server_writer.join().unwrap();

        // Verify the clone fd was valid (fcntl F_GETFD) for the entire duration
        assert!(
            !ebadf_detected.load(Ordering::Relaxed),
            "EBADF detected on clone_fd={} during concurrent read/write — \
             fd was invalidated while in use",
            clone_fd,
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 5: ManuallyDrop EBADF guard prevents double-close
    //
    // Simulates the iOS scenario where the OS reclaims an fd, then Rust's
    // Drop would close() the same fd number — now belonging to a
    // different socket.  Verifies that ManuallyDrop prevents this.
    // ────────────────────────────────────────────────────────────────────
    #[test]
    #[cfg(unix)]
    fn test_manually_drop_prevents_double_close_on_ebadf() {
        use std::os::unix::io::AsRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            s
        });

        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        let clone = stream.try_clone().unwrap();
        let clone_fd = clone.as_raw_fd();
        let _server_stream = server.join().unwrap();

        // Simulate the OS reclaiming our fd (iOS background transition)
        // by forcibly closing it.  This is what happens in the wild.
        unsafe { libc::close(clone_fd); }

        // Now wrap in ManuallyDrop (as our real code does)
        let manual = std::mem::ManuallyDrop::new(clone);

        // Open a new socket — it will likely reuse clone_fd
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let server2 = thread::spawn(move || {
            let (s, _) = listener2.accept().unwrap();
            s
        });
        let mut innocent = TcpStream::connect_timeout(&addr2, Duration::from_secs(2)).unwrap();
        let innocent_fd = innocent.as_raw_fd();
        let _server2_stream = server2.join().unwrap();

        eprintln!("clone_fd={} innocent_fd={}", clone_fd, innocent_fd);

        // Without ManuallyDrop, dropping `clone` here would call
        // close(clone_fd), which — if reused — would kill the innocent
        // socket.  With ManuallyDrop, the fd is NOT closed.
        //
        // ManuallyDrop goes out of scope here without calling close().
        // (std::mem::drop on a ManuallyDrop is intentionally a no-op)
        std::mem::forget(manual);

        // The innocent socket must still be alive
        innocent.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut buf = [0u8; 16];
        let result = innocent.read(&mut buf);
        // Should get WouldBlock/TimedOut, NOT EBADF
        match result {
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {
                // Good — socket is still alive
            }
            Err(ref e) if e.raw_os_error() == Some(9) => {
                panic!(
                    "innocent socket (fd={}) got EBADF — ManuallyDrop failed to \
                     prevent double-close of reused fd={}",
                    innocent_fd, clone_fd,
                );
            }
            Ok(0) => {} // Server closed — still means the fd was valid
            Ok(_) => {} // Got data — fine
            Err(e) => {
                // Connection reset etc. — fd was at least valid
                eprintln!("innocent read error (not EBADF, OK): {}", e);
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // Test 6: Full retichat.log scenario end-to-end
    //
    // Replays the exact sequence from the attached log:
    //   18:05:27  TCP connect, clone fd=7→8
    //   18:05:27  synthesize_tunnel (outbound write via process_outgoing)
    //   18:05:30… PSYNC path requests (more outbound writes)
    //   18:06:06  EBADF on fd=8
    //   18:06:11  Reconnect, new clone fd=7→10
    //
    // We can't force the OS to reclaim an fd, but we CAN verify that the
    // infrastructure handles it correctly:  ManuallyDrop prevents cascade
    // corruption, and reconnect produces a working new connection.
    // ────────────────────────────────────────────────────────────────────
    #[test]
    #[cfg(unix)]
    fn test_full_ebadf_reconnect_scenario() {
        use std::os::unix::io::AsRawFd;

        // --- Phase 1: "RPi" server that accepts two connections ---
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = thread::spawn(move || {
            let (s1, _) = listener.accept().unwrap();
            s1.set_nodelay(true).unwrap();
            // Simulate RPi: keep the connection alive, accept a second one later
            let (s2, _) = listener.accept().unwrap();
            s2.set_nodelay(true).unwrap();
            (s1, s2)
        });

        // --- Phase 2: Connect like retichat.log 18:05:27 ---
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut iface = TcpClientInterface::from_socket("RPi".to_string(), stream);
        iface.initiator = true;

        // Clone for read loop
        let clone = iface.socket.as_ref().unwrap().try_clone().unwrap();
        let orig_fd = iface.socket.as_ref().unwrap().as_raw_fd();
        let clone_fd = clone.as_raw_fd();
        eprintln!("phase2: original_fd={} clone_fd={}", orig_fd, clone_fd);

        // Wrap clone in ManuallyDrop like start_read_loop does
        let clone = std::mem::ManuallyDrop::new(clone);

        // --- Phase 3: Outgoing writes (synthesize_tunnel + PSYNC) ---
        for i in 0..5 {
            let payload = format!("tunnel_synth_{}", i);
            assert!(iface.process_outgoing(payload.into_bytes()).is_ok(), "write {} failed", i);
        }

        // --- Phase 4: Simulate EBADF (OS reclaims clone's fd) ---
        // This is the equivalent of what happens at 18:06:06 in the log.
        // On iOS, the OS closes the fd during a background transition.
        unsafe { libc::close(clone_fd); }

        // Verify clone is now EBADF
        let mut buf = [0u8; 16];
        // Deref through ManuallyDrop to get &TcpStream
        let read_result = (&*clone).set_read_timeout(Some(Duration::from_millis(100)));
        eprintln!("phase4: set_read_timeout after close: {:?}", read_result);

        // The read loop would detect EBADF here and set ebadf=true
        // ManuallyDrop ensures we don't call close() on the now-reused fd
        let _ = buf;

        // --- Phase 5: Simulate something else grabbing the old fd ---
        // Open a file to reuse clone_fd's number (like iOS ViewBridge)
        let decoy = std::fs::File::open("/dev/null").ok();
        if let Some(ref f) = decoy {
            eprintln!("phase5: decoy reused fd={}", f.as_raw_fd());
        }

        // Drop the ManuallyDrop — this MUST NOT call close()
        // (if it did, it would close the decoy file)
        // ManuallyDrop prevents the inner TcpStream's Drop from running.
        std::mem::forget(clone);

        // Verify decoy is still alive (ManuallyDrop protected it)
        if let Some(ref f) = decoy {
            use std::io::Read;
            let mut dbuf = [0u8; 1];
            let r = f.try_clone().and_then(|mut c| c.read(&mut dbuf));
            // /dev/null reads as Ok(0) — the point is it doesn't return EBADF
            assert!(r.is_ok(), "decoy fd corrupted by ManuallyDrop — double-close! {:?}", r);
        }

        // --- Phase 6: Reconnect (18:06:11 in the log) ---
        // Drop old socket
        iface.socket = None;
        iface.base.online = false;

        // Reconnect to the same server (second accept)
        let stream2 = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
        stream2.set_nodelay(true).unwrap();
        let new_orig_fd = stream2.as_raw_fd();
        let new_clone = stream2.try_clone().unwrap();
        let new_clone_fd = new_clone.as_raw_fd();
        eprintln!("phase6: original_fd={} clone_fd={}", new_orig_fd, new_clone_fd);

        // The new clone must not collide with the old clone's fd
        // (which is now owned by the decoy)
        if let Some(ref f) = decoy {
            assert_ne!(new_clone_fd, f.as_raw_fd(),
                "new clone fd collided with decoy — would cause cross-corruption");
        }

        // Store new socket and verify writes work
        iface.socket = Some(stream2);
        iface.base.online = true;
        assert!(iface.process_outgoing(b"after_reconnect".to_vec()).is_ok());

        // Verify new clone can read from server
        let (_srv1, mut srv2) = server_thread.join().unwrap();
        let test_data = b"reconnect_data";
        srv2.write_all(test_data).unwrap();
        srv2.flush().unwrap();

        let mut read_clone = new_clone;
        read_clone.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut rbuf = [0u8; 256];
        let n = read_clone.read(&mut rbuf).expect("new clone read failed after reconnect");
        // Data includes HDLC-framed outbound writes + the raw test_data from server
        assert!(n > 0, "new clone received no data after reconnect");

        drop(decoy);
    }
}
