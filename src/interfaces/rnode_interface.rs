use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::AsRawFd;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter, WriteType};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::StreamExt;
use serialport::SerialPort;
use socket2::{SockRef, TcpKeepalive};
use tokio::runtime::Runtime;
use tokio::sync::mpsc as tokio_mpsc;
use uuid::Uuid;

use crate::interfaces::interface::InterfaceMode;
use crate::transport::Transport as RnsTransport;

// KISS Protocol Constants - Complete Set
const KISS_FEND: u8 = 0xC0;
const KISS_FESC: u8 = 0xDB;
const KISS_TFEND: u8 = 0xDC;
const KISS_TFESC: u8 = 0xDD;

const CMD_UNKNOWN: u8 = 0xFE;
const CMD_DATA: u8 = 0x00;
const CMD_FREQUENCY: u8 = 0x01;
const CMD_BANDWIDTH: u8 = 0x02;
const CMD_TXPOWER: u8 = 0x03;
const CMD_SF: u8 = 0x04;
const CMD_CR: u8 = 0x05;
const CMD_RADIO_STATE: u8 = 0x06;
const CMD_RADIO_LOCK: u8 = 0x07;
const CMD_ST_ALOCK: u8 = 0x0B;
const CMD_LT_ALOCK: u8 = 0x0C;
const CMD_DETECT: u8 = 0x08;
const CMD_LEAVE: u8 = 0x0A;
const CMD_READY: u8 = 0x0F;
const CMD_STAT_RX: u8 = 0x21;
const CMD_STAT_TX: u8 = 0x22;
const CMD_STAT_RSSI: u8 = 0x23;
const CMD_STAT_SNR: u8 = 0x24;
const CMD_STAT_CHTM: u8 = 0x25;
const CMD_STAT_PHYPRM: u8 = 0x26;
const CMD_STAT_BAT: u8 = 0x27;
const CMD_STAT_CSMA: u8 = 0x28;
const CMD_STAT_TEMP: u8 = 0x29;
#[allow(dead_code)]
const CMD_BLINK: u8 = 0x30;
const CMD_RANDOM: u8 = 0x40;
const CMD_FB_EXT: u8 = 0x41;
const CMD_FB_READ: u8 = 0x42;
const CMD_DISP_READ: u8 = 0x66;
const CMD_FB_WRITE: u8 = 0x43;
#[allow(dead_code)]
const CMD_BT_CTRL: u8 = 0x46;
const CMD_PLATFORM: u8 = 0x48;
const CMD_MCU: u8 = 0x49;
const CMD_FW_VERSION: u8 = 0x50;
#[allow(dead_code)]
const CMD_ROM_READ: u8 = 0x51;
const CMD_RESET: u8 = 0x55;
const CMD_ERROR: u8 = 0x90;

const DETECT_REQ: u8 = 0x73;
const DETECT_RESP: u8 = 0x46;

const RADIO_STATE_OFF: u8 = 0x00;
const RADIO_STATE_ON: u8 = 0x01;
#[allow(dead_code)]
const RADIO_STATE_ASK: u8 = 0xFF;

// Error codes
const ERROR_INITRADIO: u8 = 0x01;
const ERROR_TXFAILED: u8 = 0x02;
const ERROR_EEPROM_LOCKED: u8 = 0x03;
const ERROR_QUEUE_FULL: u8 = 0x04;
const ERROR_MEMORY_LOW: u8 = 0x05;
const ERROR_MODEM_TIMEOUT: u8 = 0x06;

// Platform constants
#[allow(dead_code)]
const PLATFORM_AVR: u8 = 0x90;
const PLATFORM_ESP32: u8 = 0x80;
const PLATFORM_NRF52: u8 = 0x70;

// RNode Interface Constants
const FREQ_MIN: u64 = 137_000_000;
const FREQ_MAX: u64 = 3_000_000_000;
const REQUIRED_FW_VER_MAJ: u8 = 1;
const REQUIRED_FW_VER_MIN: u8 = 52;
const RSSI_OFFSET: i16 = 157;
const CALLSIGN_MAX_LEN: usize = 32;
const RECONNECT_WAIT: Duration = Duration::from_secs(5);
const TCP_ACTIVITY_TIMEOUT: Duration = Duration::from_millis(6000);
const TCP_ACTIVITY_KEEPALIVE: Duration = Duration::from_millis(3500);
const Q_SNR_MIN_BASE: f32 = -9.0;
const Q_SNR_MAX: f32 = 6.0;
const Q_SNR_STEP: f32 = 2.0;
const DISPLAY_READ_INTERVAL: Duration = Duration::from_millis(1000);
const FB_PIXEL_WIDTH: usize = 64;
const FB_BITS_PER_PIXEL: usize = 1;
const FB_PIXELS_PER_BYTE: usize = 8 / FB_BITS_PER_PIXEL;
const FB_BYTES_PER_LINE: usize = FB_PIXEL_WIDTH / FB_PIXELS_PER_BYTE;
const BLE_UART_SERVICE_UUID: Uuid = Uuid::from_u128(0x6e400001b5a3f393e0a9e50e24dcca9e);
const BLE_UART_RX_UUID: Uuid = Uuid::from_u128(0x6e400002b5a3f393e0a9e50e24dcca9e);
const BLE_UART_TX_UUID: Uuid = Uuid::from_u128(0x6e400003b5a3f393e0a9e50e24dcca9e);
const BLE_SCAN_TIMEOUT: Duration = Duration::from_millis(2000);
const BLE_CONNECT_TIMEOUT: Duration = Duration::from_millis(5000);
const BLE_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const BLE_WRITE_CHUNK: usize = 20;

// Battery states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BatteryState {
	Unknown = 0x00,
	Discharging = 0x01,
	Charging = 0x02,
	Charged = 0x03,
}

#[derive(Debug, Clone)]
pub struct HardwareError {
	pub error_code: u8,
	pub description: String,
}

#[derive(Debug, Clone)]
pub enum BleTarget {
	Name(String),
	Address(String),
}

#[derive(Debug, Clone)]
pub enum ConnectionInfo {
	Serial(String),
	Tcp { host: String, port: u16 },
	Ble { target: BleTarget },
}

struct BLEConnection {
	write_tx: tokio_mpsc::UnboundedSender<Vec<u8>>,
	read_rx: Receiver<u8>,
	state: Arc<Mutex<BleState>>,
	_runtime: Arc<Runtime>,
}

#[derive(Debug)]
struct BleState {
	connected: bool,
	device_disappeared: bool,
	should_run: bool,
	must_disconnect: bool,
}

impl BLEConnection {
	fn new(target: BleTarget) -> io::Result<Self> {
		let runtime = Runtime::new().map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
		let (read_tx, read_rx) = mpsc::channel();
		let (write_tx, write_rx) = tokio_mpsc::unbounded_channel();
		let state = Arc::new(Mutex::new(BleState {
			connected: false,
			device_disappeared: false,
			should_run: true,
			must_disconnect: false,
		}));

		let state_clone = Arc::clone(&state);
		let runtime_arc = Arc::new(runtime);
		let runtime_handle = runtime_arc.handle().clone();

		runtime_handle.spawn(Self::run_ble(target, read_tx, write_rx, state_clone));

		Ok(Self {
			write_tx,
			read_rx,
			state,
			_runtime: runtime_arc,
		})
	}

	async fn run_ble(
		target: BleTarget,
		read_tx: Sender<u8>,
		mut write_rx: tokio_mpsc::UnboundedReceiver<Vec<u8>>,
		state: Arc<Mutex<BleState>>,
	) {
		if let Err(err) = Self::run_ble_inner(target, read_tx, &mut write_rx, state).await {
			eprintln!("BLE connection error: {}", err);
		}
	}

	async fn run_ble_inner(
		target: BleTarget,
		read_tx: Sender<u8>,
		write_rx: &mut tokio_mpsc::UnboundedReceiver<Vec<u8>>,
		state: Arc<Mutex<BleState>>,
	) -> io::Result<()> {
		let manager = Manager::new().await.map_err(to_io_err)?;
		let adapters = manager.adapters().await.map_err(to_io_err)?;
		let adapter = adapters.into_iter().next().ok_or_else(|| {
			io::Error::new(io::ErrorKind::NotFound, "No BLE adapters found")
		})?;

		let mut had_connection = false;
		loop {
			let should_run = { state.lock().unwrap().should_run };
			if !should_run {
				break;
			}

			adapter
				.start_scan(ScanFilter {
					services: vec![BLE_UART_SERVICE_UUID],
					..Default::default()
				})
				.await
				.map_err(to_io_err)?;
			tokio::time::sleep(BLE_SCAN_TIMEOUT).await;

			let peripheral = match find_ble_peripheral(&adapter, &target).await {
				Ok(peripheral) => peripheral,
				Err(_) => {
					if had_connection {
						state.lock().unwrap().device_disappeared = true;
					}
					tokio::time::sleep(BLE_RECONNECT_DELAY).await;
					continue;
				}
			};

			let connect_result = tokio::time::timeout(BLE_CONNECT_TIMEOUT, peripheral.connect()).await;
			match connect_result {
				Ok(Ok(_)) => {}
				Ok(Err(e)) => {
					eprintln!("BLE connect error: {}", e);
					tokio::time::sleep(BLE_RECONNECT_DELAY).await;
					continue;
				}
				Err(_) => {
					tokio::time::sleep(BLE_RECONNECT_DELAY).await;
					continue;
				}
			}

			peripheral.discover_services().await.map_err(to_io_err)?;

			let chars = peripheral.characteristics();
			let rx_char = chars.iter().find(|c| c.uuid == BLE_UART_RX_UUID).cloned();
			let tx_char = chars.iter().find(|c| c.uuid == BLE_UART_TX_UUID).cloned();

			let rx_char = rx_char.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "BLE RX characteristic not found"))?;
			let tx_char = tx_char.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "BLE TX characteristic not found"))?;

			peripheral.subscribe(&tx_char).await.map_err(to_io_err)?;
			{
				let mut guard = state.lock().unwrap();
				guard.connected = true;
				guard.device_disappeared = false;
			}
			had_connection = true;

			let mut notifications = peripheral.notifications().await.map_err(to_io_err)?;
			loop {
				let must_disconnect = { state.lock().unwrap().must_disconnect };
				if must_disconnect {
					let _ = peripheral.disconnect().await;
					state.lock().unwrap().must_disconnect = false;
					break;
				}

				tokio::select! {
					maybe = notifications.next() => {
						if let Some(data) = maybe {
							for b in data.value {
								let _ = read_tx.send(b);
							}
						} else {
							state.lock().unwrap().connected = false;
							break;
						}
					}
					Some(payload) = write_rx.recv() => {
						for chunk in payload.chunks(BLE_WRITE_CHUNK) {
							let _ = peripheral.write(&rx_char, chunk, WriteType::WithoutResponse).await;
						}
					}
				}
			}

			state.lock().unwrap().connected = false;
			tokio::time::sleep(BLE_RECONNECT_DELAY).await;
		}

		Ok(())
	}

	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self.read_rx.recv_timeout(Duration::from_millis(100)) {
			Ok(byte) => {
				buf[0] = byte;
				Ok(1)
			}
			Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(io::ErrorKind::TimedOut, "BLE read timeout")),
			Err(_) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "BLE read channel closed")),
		}
	}

	fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
		self.write_tx
			.send(data.to_vec())
			.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "BLE write channel closed"))
	}

	fn close(&self) {
		let mut guard = self.state.lock().unwrap();
		guard.must_disconnect = true;
		guard.should_run = false;
	}

	fn connected(&self) -> bool {
		self.state.lock().unwrap().connected
	}

	fn device_disappeared(&self) -> bool {
		self.state.lock().unwrap().device_disappeared
	}
}

struct TCPConnection {
	stream: Arc<Mutex<TcpStream>>,
	read_rx: Receiver<u8>,
	connected: Arc<Mutex<bool>>,
	last_activity: Arc<Mutex<Instant>>,
	last_write: Arc<Mutex<Instant>>,
	tx_queue: Arc<Mutex<Vec<u8>>>,
}

impl TCPConnection {
	fn new(host: &str, port: u16) -> io::Result<Self> {
		let addr = resolve_tcp_addr(host, port)?;
		let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
		stream.set_nodelay(true)?;
		configure_tcp_socket(&stream)?;

		let (read_tx, read_rx) = mpsc::channel();
		let connected = Arc::new(Mutex::new(true));
		let last_activity = Arc::new(Mutex::new(Instant::now()));
		let last_write = Arc::new(Mutex::new(Instant::now()));
		let tx_queue = Arc::new(Mutex::new(Vec::new()));
		let stream = Arc::new(Mutex::new(stream));

		let stream_clone = Arc::clone(&stream);
		let connected_clone = Arc::clone(&connected);
		let last_activity_clone = Arc::clone(&last_activity);

		thread::spawn(move || {
			let mut buf = [0u8; 4096];
			loop {
				let read_result = {
					let mut locked = stream_clone.lock().unwrap();
					locked.read(&mut buf)
				};

				match read_result {
					Ok(0) => {
						*connected_clone.lock().unwrap() = false;
						break;
					}
					Ok(n) => {
						*last_activity_clone.lock().unwrap() = Instant::now();
						for b in &buf[..n] {
							let _ = read_tx.send(*b);
						}
					}
					Err(ref e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
						thread::sleep(Duration::from_millis(10));
					}
					Err(_) => {
						*connected_clone.lock().unwrap() = false;
						break;
					}
				}
			}
		});

		Ok(Self {
			stream,
			read_rx,
			connected,
			last_activity,
			last_write,
			tx_queue,
		})
	}

	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self.read_rx.recv_timeout(Duration::from_millis(100)) {
			Ok(byte) => {
				buf[0] = byte;
				Ok(1)
			}
			Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(io::ErrorKind::TimedOut, "TCP read timeout")),
			Err(_) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TCP read channel closed")),
		}
	}

	fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
		if !self.connected() {
			self.tx_queue.lock().unwrap().extend_from_slice(data);
			return Ok(());
		}

		let mut locked = self.stream.lock().unwrap();
		let mut queued = self.tx_queue.lock().unwrap();
		if !queued.is_empty() {
			locked.write_all(&queued[..])?;
			queued.clear();
		}
		locked.write_all(data)?;
		*self.last_write.lock().unwrap() = Instant::now();
		Ok(())
	}

	fn connected(&self) -> bool {
		*self.connected.lock().unwrap()
	}

	fn last_activity(&self) -> Instant {
		*self.last_activity.lock().unwrap()
	}

	fn last_write(&self) -> Instant {
		*self.last_write.lock().unwrap()
	}

	fn close(&self) {
		let _ = self.stream.lock().unwrap().shutdown(Shutdown::Both);
		*self.connected.lock().unwrap() = false;
	}
}

fn resolve_tcp_addr(host: &str, port: u16) -> io::Result<SocketAddr> {
	let mut addrs = (host, port).to_socket_addrs()?;
	addrs
		.next()
		.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No TCP address resolved"))
}

fn configure_tcp_socket(stream: &TcpStream) -> io::Result<()> {
	let sock_ref = SockRef::from(stream);
	let keepalive = TcpKeepalive::new()
		.with_time(Duration::from_secs(5))
		.with_interval(Duration::from_secs(2));
	let _ = sock_ref.set_tcp_keepalive(&keepalive);

	#[cfg(target_os = "linux")]
	unsafe {
		let fd = stream.as_raw_fd();
		let user_timeout: libc::c_int = 24_000;
		libc::setsockopt(
			fd,
			libc::IPPROTO_TCP,
			libc::TCP_USER_TIMEOUT,
			&user_timeout as *const _ as *const libc::c_void,
			std::mem::size_of_val(&user_timeout) as libc::socklen_t,
		);
		let keep_idle: libc::c_int = 5;
		libc::setsockopt(
			fd,
			libc::IPPROTO_TCP,
			libc::TCP_KEEPIDLE,
			&keep_idle as *const _ as *const libc::c_void,
			std::mem::size_of_val(&keep_idle) as libc::socklen_t,
		);
		let keep_intvl: libc::c_int = 2;
		libc::setsockopt(
			fd,
			libc::IPPROTO_TCP,
			libc::TCP_KEEPINTVL,
			&keep_intvl as *const _ as *const libc::c_void,
			std::mem::size_of_val(&keep_intvl) as libc::socklen_t,
		);
		let keep_cnt: libc::c_int = 12;
		libc::setsockopt(
			fd,
			libc::IPPROTO_TCP,
			libc::TCP_KEEPCNT,
			&keep_cnt as *const _ as *const libc::c_void,
			std::mem::size_of_val(&keep_cnt) as libc::socklen_t,
		);
	}

	#[cfg(target_os = "macos")]
	unsafe {
		let fd = stream.as_raw_fd();
		let keepalive: libc::c_int = 5;
		libc::setsockopt(
			fd,
			libc::IPPROTO_TCP,
			libc::TCP_KEEPALIVE,
			&keepalive as *const _ as *const libc::c_void,
			std::mem::size_of_val(&keepalive) as libc::socklen_t,
		);
	}

	Ok(())
}

async fn find_ble_peripheral(adapter: &Adapter, target: &BleTarget) -> io::Result<Peripheral> {
	let peripherals = adapter.peripherals().await.map_err(to_io_err)?;
	for peripheral in peripherals {
		let matches = match target {
			BleTarget::Name(name) => {
				if let Ok(Some(props)) = peripheral.properties().await {
					if let Some(local_name) = props.local_name {
						local_name == *name
					} else {
						false
					}
				} else {
					false
				}
			}
			BleTarget::Address(addr) => peripheral.address().to_string() == *addr,
		};

		if matches {
			return Ok(peripheral);
		}
	}

	Err(io::Error::new(
		io::ErrorKind::NotFound,
		"No matching BLE peripheral found",
	))
}

fn to_io_err<E: std::error::Error>(err: E) -> io::Error {
	io::Error::new(io::ErrorKind::Other, err.to_string())
}

/// Byte-stream connection driven by an externally-supplied TX callback (e.g.
/// a CoreBluetooth/JNI bridge that owns the actual radio link).
///
/// RX bytes are pushed into [`feed_sender`] from the FFI layer; the read loop
/// drains them through `read_rx`. TX bytes are forwarded synchronously to the
/// caller-supplied `send_fn`, which is responsible for chunking to the radio's
/// MTU (e.g. 20-byte BLE writes).
pub(crate) struct CallbackConnection {
	send_fn: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
	read_rx: Receiver<u8>,
	read_tx: Sender<u8>,
	connected: Arc<Mutex<bool>>,
}

impl CallbackConnection {
	fn new(send_fn: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>) -> Self {
		let (read_tx, read_rx) = mpsc::channel();
		Self {
			send_fn,
			read_rx,
			read_tx,
			connected: Arc::new(Mutex::new(true)),
		}
	}

	/// Clone the byte sender so external code (FFI) can feed RX bytes into the
	/// read loop.
	fn feed_sender(&self) -> Sender<u8> {
		self.read_tx.clone()
	}

	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self.read_rx.recv_timeout(Duration::from_millis(100)) {
			Ok(byte) => {
				buf[0] = byte;
				Ok(1)
			}
			Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
				io::ErrorKind::TimedOut,
				"callback read timeout",
			)),
			Err(_) => Err(io::Error::new(
				io::ErrorKind::UnexpectedEof,
				"callback read channel closed",
			)),
		}
	}

	fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
		if !*self.connected.lock().unwrap() {
			return Err(io::Error::new(
				io::ErrorKind::NotConnected,
				"callback connection closed",
			));
		}
		if (self.send_fn)(data) {
			Ok(())
		} else {
			Err(io::Error::new(
				io::ErrorKind::BrokenPipe,
				"callback send_fn returned false",
			))
		}
	}

	fn close(&self) {
		*self.connected.lock().unwrap() = false;
	}

	fn connected(&self) -> bool {
		*self.connected.lock().unwrap()
	}
}

/// Connection type for RNode
enum ConnectionType {
	Serial(Box<dyn SerialPort>),
	Ble(BLEConnection),
	Tcp(TCPConnection),
	Callback(CallbackConnection),
}

impl ConnectionType {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self {
			ConnectionType::Serial(port) => port.read(buf),
			ConnectionType::Ble(conn) => conn.read(buf),
			ConnectionType::Tcp(conn) => conn.read(buf),
			ConnectionType::Callback(conn) => conn.read(buf),
		}
	}

	fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
		match self {
			ConnectionType::Serial(port) => port.write_all(data),
			ConnectionType::Ble(conn) => conn.write_all(data),
			ConnectionType::Tcp(conn) => conn.write_all(data),
			ConnectionType::Callback(conn) => conn.write_all(data),
		}
	}

	fn is_tcp(&self) -> bool {
		matches!(self, ConnectionType::Tcp(_))
	}

	fn is_ble(&self) -> bool {
		matches!(self, ConnectionType::Ble(_))
	}

	#[allow(dead_code)]
	fn is_callback(&self) -> bool {
		matches!(self, ConnectionType::Callback(_))
	}

	fn tcp_last_activity(&self) -> Option<Instant> {
		match self {
			ConnectionType::Tcp(conn) => Some(conn.last_activity()),
			_ => None,
		}
	}

	fn tcp_last_write(&self) -> Option<Instant> {
		match self {
			ConnectionType::Tcp(conn) => Some(conn.last_write()),
			_ => None,
		}
	}

	fn tcp_connected(&self) -> bool {
		match self {
			ConnectionType::Tcp(conn) => conn.connected(),
			_ => true,
		}
	}

	fn ble_connected(&self) -> bool {
		match self {
			ConnectionType::Ble(conn) => conn.connected(),
			_ => true,
		}
	}

	fn ble_device_disappeared(&self) -> bool {
		match self {
			ConnectionType::Ble(conn) => conn.device_disappeared(),
			_ => false,
		}
	}

	fn close(&mut self) {
		match self {
			ConnectionType::Serial(_) => {}
			ConnectionType::Ble(conn) => conn.close(),
			ConnectionType::Tcp(conn) => conn.close(),
			ConnectionType::Callback(conn) => conn.close(),
		}
	}
}

struct RNodeInner {
	connection: ConnectionType,
	online: bool,
	detected: bool,
	detached: bool,
	reconnecting: bool,
	interface_ready: bool,
	flow_control: bool,

	// Radio parameters (configured)
	frequency: u64,
	bandwidth: u32,
	txpower: u8,
	sf: u8,
	cr: u8,
	state: u8,
	st_alock: Option<f32>,
	lt_alock: Option<f32>,

	// Radio parameters (reported from device)
	r_frequency: Option<u64>,
	r_bandwidth: Option<u32>,
	r_txpower: Option<u8>,
	r_sf: Option<u8>,
	r_cr: Option<u8>,
	r_state: Option<u8>,
	r_lock: Option<u8>,
	r_st_alock: Option<f32>,
	r_lt_alock: Option<f32>,

	// Statistics
	r_stat_rx: Option<u32>,
	r_stat_tx: Option<u32>,
	r_stat_rssi: Option<i16>,
	r_stat_snr: Option<f32>,
	r_stat_q: Option<f32>,
	r_random: Option<u8>,

	// Airtime and channel load
	r_airtime_short: f32,
	r_airtime_long: f32,
	r_channel_load_short: f32,
	r_channel_load_long: f32,

	// Physical layer parameters
	r_symbol_time_ms: Option<f32>,
	r_symbol_rate: Option<f32>,
	r_preamble_symbols: Option<u16>,
	r_preamble_time_ms: Option<f32>,
	r_csma_slot_time_ms: Option<f32>,
	r_csma_difs_ms: Option<f32>,

	// CSMA parameters
	r_csma_cw_band: Option<u8>,
	r_csma_cw_min: Option<u8>,
	r_csma_cw_max: Option<u8>,
	r_current_rssi: Option<i16>,
	r_noise_floor: Option<i16>,
	r_interference: Option<f32>,
	r_interference_l: Option<(Instant, f32)>,

	// Battery and temperature
	r_battery_state: BatteryState,
	r_battery_percent: u8,
	r_temperature: Option<i8>,
	cpu_temp: Option<i8>,

	// Framebuffer
	r_framebuffer: Vec<u8>,
	r_framebuffer_readtime: Instant,
	r_framebuffer_latency: Duration,
	r_disp: Vec<u8>,
	r_disp_readtime: Instant,
	r_disp_latency: Duration,
	should_read_display: bool,
	read_display_interval: Duration,

	// Hardware info
	platform: Option<u8>,
	mcu: Option<u8>,
	display: Option<bool>,
	maj_version: u8,
	min_version: u8,
	firmware_ok: bool,

	// ID/Callsign beaconing
	id_callsign: Option<Vec<u8>>,
	id_interval: Option<Duration>,
	_last_id: Instant,
	first_tx: Option<Instant>,
	last_detect: Instant,

	// Packet queue for flow control
	packet_queue: VecDeque<Vec<u8>>,

	// Error tracking
	hw_errors: Vec<HardwareError>,
	last_error: Option<HardwareError>,
	fatal_error: bool,
}

pub struct RNodeInterface {
	pub name: String,
	pub hw_mtu: usize,
	pub mode: InterfaceMode,
	pub bitrate: u64,
	pub supports_discovery: bool,
	/// Experimental: force bitrate throttle on outgoing data
	pub _force_bitrate: bool,

	pub rxb: Arc<Mutex<u64>>,
	pub txb: Arc<Mutex<u64>>,

	inner: Arc<Mutex<RNodeInner>>,
	_port_name: String,
	connection_info: ConnectionInfo,
}

impl RNodeInterface {
	pub fn new(
		name: &str,
		port_name: &str,
		frequency: u64,
		bandwidth: u32,
		txpower: u8,
		sf: u8,
		cr: u8,
		flow_control: bool,
		st_alock: Option<f32>,
		lt_alock: Option<f32>,
		id_interval: Option<Duration>,
		id_callsign: Option<Vec<u8>>,
	) -> io::Result<Self> {
		// Validate configuration
		Self::validate_config(frequency, bandwidth, txpower, sf, cr, st_alock, lt_alock, &id_callsign)?;

		let (connection, connection_info) = if port_name.starts_with("tcp://") {
			let addr = port_name.trim_start_matches("tcp://");
			if addr.is_empty() {
				return Err(io::Error::new(io::ErrorKind::InvalidInput, "TCP address is empty"));
			}
			let (host, port) = if let Some((host_part, port_part)) = addr.rsplit_once(':') {
				if let Ok(parsed_port) = port_part.parse::<u16>() {
					(host_part, parsed_port)
				} else {
					(addr, 7633)
				}
			} else {
				(addr, 7633)
			};
			let host = host.trim_start_matches('[').trim_end_matches(']');
			let tcp = TCPConnection::new(host, port)?;
			(
				ConnectionType::Tcp(tcp),
				ConnectionInfo::Tcp { host: host.to_string(), port },
			)
		} else if port_name.starts_with("ble://") {
			let target = port_name.trim_start_matches("ble://");
			if target.is_empty() {
				return Err(io::Error::new(io::ErrorKind::InvalidInput, "BLE target is empty"));
			}
			let is_address = target.matches(':').count() >= 2;
			let ble_target = if is_address {
				BleTarget::Address(target.to_string())
			} else {
				BleTarget::Name(target.to_string())
			};
			let ble = BLEConnection::new(ble_target.clone())?;
			(
				ConnectionType::Ble(ble),
				ConnectionInfo::Ble { target: ble_target },
			)
		} else {
			let port = serialport::new(port_name, 115200)
				.timeout(Duration::from_millis(100))
				.data_bits(serialport::DataBits::Eight)
				.stop_bits(serialport::StopBits::One)
				.parity(serialport::Parity::None)
				.flow_control(serialport::FlowControl::None)
				.open()?;
			(
				ConnectionType::Serial(port),
				ConnectionInfo::Serial(port_name.to_string()),
			)
		};

		let inner = RNodeInner {
			connection,
			online: false,
			detected: false,
			detached: false,
			reconnecting: false,
			interface_ready: false,
			flow_control,
			frequency,
			bandwidth,
			txpower,
			sf,
			cr,
			state: RADIO_STATE_ON,
			st_alock,
			lt_alock,
			r_frequency: None,
			r_bandwidth: None,
			r_txpower: None,
			r_sf: None,
			r_cr: None,
			r_state: None,
			r_lock: None,
			r_st_alock: None,
			r_lt_alock: None,
			r_stat_rx: None,
			r_stat_tx: None,
			r_stat_rssi: None,
			r_stat_snr: None,
			r_stat_q: None,
			r_random: None,
			r_airtime_short: 0.0,
			r_airtime_long: 0.0,
			r_channel_load_short: 0.0,
			r_channel_load_long: 0.0,
			r_symbol_time_ms: None,
			r_symbol_rate: None,
			r_preamble_symbols: None,
			r_preamble_time_ms: None,
			r_csma_slot_time_ms: None,
			r_csma_difs_ms: None,
			r_csma_cw_band: None,
			r_csma_cw_min: None,
			r_csma_cw_max: None,
			r_current_rssi: None,
			r_noise_floor: None,
			r_interference: None,
			r_interference_l: None,
			r_battery_state: BatteryState::Unknown,
			r_battery_percent: 0,
			r_temperature: None,
			cpu_temp: None,
			r_framebuffer: vec![0; 512],
			r_framebuffer_readtime: Instant::now(),
			r_framebuffer_latency: Duration::ZERO,
			r_disp: vec![0; 1024],
			r_disp_readtime: Instant::now(),
			r_disp_latency: Duration::ZERO,
			should_read_display: false,
			read_display_interval: DISPLAY_READ_INTERVAL,
			platform: None,
			mcu: None,
			display: None,
			maj_version: 0,
			min_version: 0,
			firmware_ok: false,
			id_callsign,
			id_interval,
			_last_id: Instant::now(),
			first_tx: None,
			last_detect: Instant::now(),
			packet_queue: VecDeque::new(),
			hw_errors: Vec::new(),
			last_error: None,
			fatal_error: false,
		};

		Ok(RNodeInterface {
			name: name.to_string(),
			hw_mtu: 508,
			mode: InterfaceMode::Full,
			bitrate: 0,
			supports_discovery: true,
			_force_bitrate: false,
			rxb: Arc::new(Mutex::new(0)),
			txb: Arc::new(Mutex::new(0)),
			inner: Arc::new(Mutex::new(inner)),
			_port_name: port_name.to_string(),
			connection_info,
		})
	}

	fn validate_config(
		frequency: u64,
		bandwidth: u32,
		txpower: u8,
		sf: u8,
		cr: u8,
		st_alock: Option<f32>,
		lt_alock: Option<f32>,
		id_callsign: &Option<Vec<u8>>,
	) -> io::Result<()> {
		if frequency < FREQ_MIN || frequency > FREQ_MAX {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Invalid frequency: {} (must be {}-{})", frequency, FREQ_MIN, FREQ_MAX),
			));
		}

		if txpower > 37 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Invalid TX power: {} (must be 0-37)", txpower),
			));
		}

		if bandwidth < 7800 || bandwidth > 1_625_000 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Invalid bandwidth: {} (must be 7800-1625000)", bandwidth),
			));
		}

		if sf < 5 || sf > 12 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Invalid spreading factor: {} (must be 5-12)", sf),
			));
		}

		if cr < 5 || cr > 8 {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Invalid coding rate: {} (must be 5-8)", cr),
			));
		}

		if let Some(st) = st_alock {
			if st < 0.0 || st > 100.0 {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("Invalid short-term airtime limit: {} (must be 0.0-100.0)", st),
				));
			}
		}

		if let Some(lt) = lt_alock {
			if lt < 0.0 || lt > 100.0 {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("Invalid long-term airtime limit: {} (must be 0.0-100.0)", lt),
				));
			}
		}

		if let Some(callsign) = id_callsign {
			if callsign.len() > CALLSIGN_MAX_LEN {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("ID callsign too long: {} bytes (max {})", callsign.len(), CALLSIGN_MAX_LEN),
				));
			}
		}

		Ok(())
	}

	fn kiss_escape(data: &[u8]) -> Vec<u8> {
		let mut escaped = Vec::with_capacity(data.len() + 16);
		for &byte in data {
			match byte {
				KISS_FEND => {
					escaped.push(KISS_FESC);
					escaped.push(KISS_TFEND);
				}
				KISS_FESC => {
					escaped.push(KISS_FESC);
					escaped.push(KISS_TFESC);
				}
				_ => escaped.push(byte),
			}
		}
		escaped
	}

	fn write_command(&self, command: &[u8]) -> io::Result<()> {
		let mut inner = self.inner.lock().unwrap();
		inner.connection.write_all(command)
	}

	pub fn detect(&self) -> io::Result<()> {
		let command = vec![
			KISS_FEND, CMD_DETECT, DETECT_REQ, KISS_FEND,
			CMD_FW_VERSION, 0x00, KISS_FEND,
			CMD_PLATFORM, 0x00, KISS_FEND,
			CMD_MCU, 0x00, KISS_FEND,
		];
		self.write_command(&command)
	}

	pub fn leave(&self) -> io::Result<()> {
		let command = vec![KISS_FEND, CMD_LEAVE, 0xFF, KISS_FEND];
		self.write_command(&command)
	}

	pub fn hard_reset(&self) -> io::Result<()> {
		let command = vec![KISS_FEND, CMD_RESET, 0xF8, KISS_FEND];
		self.write_command(&command)?;
		thread::sleep(Duration::from_millis(2250));
		Ok(())
	}

	pub fn enable_external_framebuffer(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		if inner.display.unwrap_or(false) {
			drop(inner);
			let command = vec![KISS_FEND, CMD_FB_EXT, 0x01, KISS_FEND];
			self.write_command(&command)
		} else {
			Ok(())
		}
	}

	pub fn disable_external_framebuffer(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		if inner.display.unwrap_or(false) {
			drop(inner);
			let command = vec![KISS_FEND, CMD_FB_EXT, 0x00, KISS_FEND];
			self.write_command(&command)
		} else {
			Ok(())
		}
	}

	pub fn read_framebuffer(&self) -> io::Result<()> {
		let has_display = self.inner.lock().unwrap().display.unwrap_or(false);
		if !has_display {
			return Ok(());
		}
		let command = vec![KISS_FEND, CMD_FB_READ, 0x01, KISS_FEND];
		let mut inner = self.inner.lock().unwrap();
		inner.r_framebuffer_readtime = Instant::now();
		drop(inner);
		self.write_command(&command)
	}

	pub fn write_framebuffer_line(&self, line: u8, line_data: &[u8]) -> io::Result<()> {
		let has_display = self.inner.lock().unwrap().display.unwrap_or(false);
		if !has_display {
			return Ok(());
		}
		if line_data.len() != FB_BYTES_PER_LINE {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!("Framebuffer line must be {} bytes", FB_BYTES_PER_LINE),
			));
		}
		let mut payload = vec![line];
		payload.extend_from_slice(line_data);
		let mut frame = vec![KISS_FEND, CMD_FB_WRITE];
		frame.extend(Self::kiss_escape(&payload));
		frame.push(KISS_FEND);
		self.write_command(&frame)
	}

	pub fn display_image(&self, image_data: &[u8]) -> io::Result<()> {
		let has_display = self.inner.lock().unwrap().display.unwrap_or(false);
		if !has_display {
			return Ok(());
		}
		let lines = image_data.len() / FB_BYTES_PER_LINE;
		for line in 0..lines {
			let start = line * FB_BYTES_PER_LINE;
			let end = start + FB_BYTES_PER_LINE;
			self.write_framebuffer_line(line as u8, &image_data[start..end])?;
		}
		Ok(())
	}

	pub fn read_display(&self) -> io::Result<()> {
		let has_display = self.inner.lock().unwrap().display.unwrap_or(false);
		if !has_display {
			return Ok(());
		}
		let command = vec![KISS_FEND, CMD_DISP_READ, 0x01, KISS_FEND];
		let mut inner = self.inner.lock().unwrap();
		inner.r_disp_readtime = Instant::now();
		drop(inner);
		self.write_command(&command)
	}

	fn read_display_loop(inner: Arc<Mutex<RNodeInner>>) {
		loop {
			let (should_read, interval, has_display) = {
				let guard = inner.lock().unwrap();
				(
					guard.should_read_display,
					guard.read_display_interval,
					guard.display.unwrap_or(false),
				)
			};

			if !should_read {
				break;
			}

			if has_display {
				let command = vec![KISS_FEND, CMD_DISP_READ, 0x01, KISS_FEND];
				let mut guard = inner.lock().unwrap();
				guard.r_disp_readtime = Instant::now();
				let _ = guard.connection.write_all(&command);
			}

			thread::sleep(interval);
		}
	}

	pub fn start_display_updates(&self) {
		let mut inner = self.inner.lock().unwrap();
		if inner.should_read_display {
			return;
		}
		inner.should_read_display = true;
		let inner_clone = Arc::clone(&self.inner);
		drop(inner);
		thread::spawn(move || Self::read_display_loop(inner_clone));
	}

	pub fn stop_display_updates(&self) {
		self.inner.lock().unwrap().should_read_display = false;
	}

	pub fn configure_device(&self) -> io::Result<()> {
		// Reset state
		{
			let mut inner = self.inner.lock().unwrap();
			inner.r_frequency = None;
			inner.r_bandwidth = None;
			inner.r_txpower = None;
			inner.r_sf = None;
			inner.r_cr = None;
			inner.r_state = None;
			inner.detected = false;
		}

		thread::sleep(Duration::from_secs(2));

		// Send detect command
		self.detect()?;
		thread::sleep(Duration::from_millis(200));

		// Check if detected
		{
			let inner = self.inner.lock().unwrap();
			if !inner.detected {
				return Err(io::Error::new(
					io::ErrorKind::NotConnected,
					"Could not detect RNode device",
				));
			}

			if !inner.firmware_ok {
				return Err(io::Error::new(
					io::ErrorKind::Other,
					format!(
						"Firmware version {}.{} is too old (need {}.{})",
						inner.maj_version,
						inner.min_version,
						REQUIRED_FW_VER_MAJ,
						REQUIRED_FW_VER_MIN
					),
				));
			}

			let has_display = inner.platform == Some(PLATFORM_ESP32) || inner.platform == Some(PLATFORM_NRF52);
			drop(inner);
			self.inner.lock().unwrap().display = Some(has_display);
		}

		// Initialize radio
		self.init_radio()?;

		// Validate radio state
		let delay = {
			let inner = self.inner.lock().unwrap();
			match &inner.connection {
				ConnectionType::Ble(_) => Duration::from_secs_f32(1.0),
				ConnectionType::Tcp(_) => Duration::from_secs_f32(1.5),
				ConnectionType::Serial(_) => Duration::from_millis(250),
				ConnectionType::Callback(_) => Duration::from_secs_f32(1.0),
			}
		};
		thread::sleep(delay);
		if !self.validate_radio_state() {
			return Err(io::Error::new(
				io::ErrorKind::Other,
				"Radio parameters did not validate",
			));
		}

		// Mark as ready and online
		{
			let mut inner = self.inner.lock().unwrap();
			inner.interface_ready = true;
			inner.online = true;
		}
		println!("RNodeInterface[{}] is configured and powered up", self.name);
		// Notify Transport so the false→true online transition triggers an
		// automatic re-announce of all locally registered destinations on
		// this interface (covers post-handshake and post-reconnect).
		crate::transport::Transport::set_interface_online(&self.name, true);
		Ok(())
	}

	/// Configure device via the shared Arc, releasing the outer lock between
	/// steps so the read loop thread can process serial responses (detect,
	/// radio state, etc.).
	pub fn configure_device_shared(interface: &Arc<Mutex<RNodeInterface>>) -> io::Result<()> {
		// Reset state
		{
			let iface = interface.lock().unwrap();
			let mut inner = iface.inner.lock().unwrap();
			inner.r_frequency = None;
			inner.r_bandwidth = None;
			inner.r_txpower = None;
			inner.r_sf = None;
			inner.r_cr = None;
			inner.r_state = None;
			inner.detected = false;
		}

		// Wait for device to settle after serial open
		thread::sleep(Duration::from_secs(2));

		// Send detect command (lock briefly, then release)
		{
			let iface = interface.lock().unwrap();
			iface.detect()?;
		}

		// Give device time to respond — read loop processes bytes while we sleep
		thread::sleep(Duration::from_millis(200));

		// Check if detected
		{
			let iface = interface.lock().unwrap();
			let inner = iface.inner.lock().unwrap();
			if !inner.detected {
				return Err(io::Error::new(
					io::ErrorKind::NotConnected,
					"Could not detect RNode device",
				));
			}
			if !inner.firmware_ok {
				return Err(io::Error::new(
					io::ErrorKind::Other,
					format!(
						"Firmware version {}.{} is too old (need {}.{})",
						inner.maj_version,
						inner.min_version,
						REQUIRED_FW_VER_MAJ,
						REQUIRED_FW_VER_MIN
					),
				));
			}
			let has_display = inner.platform == Some(PLATFORM_ESP32)
				|| inner.platform == Some(PLATFORM_NRF52);
			drop(inner);
			iface.inner.lock().unwrap().display = Some(has_display);
		}

		// Initialize radio (lock briefly for each command)
		{
			let iface = interface.lock().unwrap();
			iface.init_radio()?;
		}

		// Validate radio state after a delay
		let delay = {
			let iface = interface.lock().unwrap();
			let inner = iface.inner.lock().unwrap();
			match &inner.connection {
				ConnectionType::Ble(_) => Duration::from_secs_f32(1.0),
				ConnectionType::Tcp(_) => Duration::from_secs_f32(1.5),
				ConnectionType::Serial(_) => Duration::from_millis(250),
				ConnectionType::Callback(_) => Duration::from_secs_f32(1.0),
			}
		};
		thread::sleep(delay);

		let iface_name = {
			let iface = interface.lock().unwrap();
			if !iface.validate_radio_state() {
				return Err(io::Error::new(
					io::ErrorKind::Other,
					"Radio parameters did not validate",
				));
			}
			let mut inner = iface.inner.lock().unwrap();
			inner.interface_ready = true;
			inner.online = true;
			drop(inner);
			println!(
				"RNodeInterface[{}] is configured and powered up",
				iface.name
			);
			iface.name.clone()
		};

		// Notify Transport so the false→true online transition triggers an
		// automatic re-announce of all locally registered destinations on
		// this interface (covers post-handshake and post-reconnect).
		crate::transport::Transport::set_interface_online(&iface_name, true);

		Ok(())
	}

	fn init_radio(&self) -> io::Result<()> {
		self.set_frequency()?;
		self.set_bandwidth()?;
		self.set_txpower()?;
		self.set_spreading_factor()?;
		self.set_coding_rate()?;
		self.set_st_alock()?;
		self.set_lt_alock()?;
		self.set_radio_state(RADIO_STATE_ON)?;
		Ok(())
	}

	fn set_frequency(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		let freq = inner.frequency;
		drop(inner);

		let c1 = (freq >> 24) as u8;
		let c2 = (freq >> 16) as u8;
		let c3 = (freq >> 8) as u8;
		let c4 = freq as u8;

		let data = Self::kiss_escape(&[c1, c2, c3, c4]);
		let mut command = vec![KISS_FEND, CMD_FREQUENCY];
		command.extend(data);
		command.push(KISS_FEND);

		self.write_command(&command)
	}

	fn set_bandwidth(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		let bw = inner.bandwidth;
		drop(inner);

		let c1 = (bw >> 24) as u8;
		let c2 = (bw >> 16) as u8;
		let c3 = (bw >> 8) as u8;
		let c4 = bw as u8;

		let data = Self::kiss_escape(&[c1, c2, c3, c4]);
		let mut command = vec![KISS_FEND, CMD_BANDWIDTH];
		command.extend(data);
		command.push(KISS_FEND);

		self.write_command(&command)
	}

	fn set_txpower(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		let power = inner.txpower;
		drop(inner);

		let command = vec![KISS_FEND, CMD_TXPOWER, power, KISS_FEND];
		self.write_command(&command)
	}

	fn set_spreading_factor(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		let sf = inner.sf;
		drop(inner);

		let command = vec![KISS_FEND, CMD_SF, sf, KISS_FEND];
		self.write_command(&command)
	}

	fn set_coding_rate(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		let cr = inner.cr;
		drop(inner);

		let command = vec![KISS_FEND, CMD_CR, cr, KISS_FEND];
		self.write_command(&command)
	}

	fn set_st_alock(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		if let Some(st_alock) = inner.st_alock {
			drop(inner);
			let at = (st_alock * 100.0) as u16;
			let c1 = (at >> 8) as u8;
			let c2 = at as u8;

			let data = Self::kiss_escape(&[c1, c2]);
			let mut command = vec![KISS_FEND, CMD_ST_ALOCK];
			command.extend(data);
			command.push(KISS_FEND);

			self.write_command(&command)
		} else {
			Ok(())
		}
	}

	fn set_lt_alock(&self) -> io::Result<()> {
		let inner = self.inner.lock().unwrap();
		if let Some(lt_alock) = inner.lt_alock {
			drop(inner);
			let at = (lt_alock * 100.0) as u16;
			let c1 = (at >> 8) as u8;
			let c2 = at as u8;

			let data = Self::kiss_escape(&[c1, c2]);
			let mut command = vec![KISS_FEND, CMD_LT_ALOCK];
			command.extend(data);
			command.push(KISS_FEND);

			self.write_command(&command)
		} else {
			Ok(())
		}
	}

	fn set_radio_state(&self, state: u8) -> io::Result<()> {
		let command = vec![KISS_FEND, CMD_RADIO_STATE, state, KISS_FEND];
		self.write_command(&command)?;
		self.inner.lock().unwrap().state = state;
		self.inner.lock().unwrap().r_state = Some(state);
		Ok(())
	}

	fn validate_radio_state(&self) -> bool {
		let inner = self.inner.lock().unwrap();
		if inner.connection.is_ble() && inner.connection.ble_device_disappeared() {
			println!("BLE device disappeared during radio state validation");
			return false;
		}

		if let Some(r_freq) = inner.r_frequency {
			if (inner.frequency as i64 - r_freq as i64).abs() > 100 {
				println!("Frequency mismatch");
				return false;
			}
		} else {
			println!("No frequency reported");
			return false;
		}

		if inner.r_bandwidth != Some(inner.bandwidth) {
			println!("Bandwidth mismatch");
			return false;
		}

		if inner.r_txpower != Some(inner.txpower) {
			println!("TX power mismatch");
			return false;
		}

		if inner.r_sf != Some(inner.sf) {
			println!("Spreading factor mismatch");
			return false;
		}

		if inner.r_state != Some(inner.state) {
			println!("Radio state mismatch");
			return false;
		}

		true
	}

	fn update_bitrate(&mut self) {
		let mut inner = self.inner.lock().unwrap();

		if let (Some(r_sf), Some(r_cr), Some(r_bandwidth)) = (inner.r_sf, inner.r_cr, inner.r_bandwidth) {
			let sf = r_sf as f64;
			let cr = r_cr as f64;
			let bw = r_bandwidth as f64;

			let bitrate = sf * ((4.0 / cr) / (f64::powf(2.0, sf) / (bw / 1000.0))) * 1000.0;
			inner.r_symbol_rate = Some(bitrate as f32);
			drop(inner);
			self.bitrate = bitrate as u64;
			println!(
				"RNodeInterface[{}] On-air bitrate is now {:.2} kbps",
				self.name,
				bitrate / 1000.0
			);
		}
	}

	pub fn process_outgoing(&self, data: Vec<u8>) -> io::Result<()> {
		// Apply forced bitrate delay if set
		if self._force_bitrate && self.bitrate > 0 {
			let delay_secs = (data.len() as f64 / self.bitrate as f64) * 8.0;
			std::thread::sleep(std::time::Duration::from_secs_f64(delay_secs));
		}

		let mut inner = self.inner.lock().unwrap();

		if !inner.online {
			return Err(io::Error::new(io::ErrorKind::NotConnected, "Interface not online"));
		}

		let is_id_callsign = if let Some(ref callsign) = inner.id_callsign {
			&data == callsign
		} else {
			false
		};

		if is_id_callsign {
			inner.first_tx = None;
		} else if inner.first_tx.is_none() {
			inner.first_tx = Some(Instant::now());
		}

		if inner.interface_ready {
			if inner.flow_control {
				inner.interface_ready = false;
			}

			// Build KISS frame in a single allocation: FEND + CMD_DATA + escaped data + FEND
			let mut frame = Vec::with_capacity(data.len() + 16 + 3);
			frame.push(KISS_FEND);
			frame.push(CMD_DATA);
			for &byte in &data {
				match byte {
					KISS_FEND => {
						frame.push(KISS_FESC);
						frame.push(KISS_TFEND);
					}
					KISS_FESC => {
						frame.push(KISS_FESC);
						frame.push(KISS_TFESC);
					}
					_ => frame.push(byte),
				}
			}
			frame.push(KISS_FEND);

			inner.connection.write_all(&frame)?;

			drop(inner);
			*self.txb.lock().unwrap() += data.len() as u64;
			Ok(())
		} else {
			inner.packet_queue.push_back(data);
			Ok(())
		}
	}

	pub fn process_queue(&self) {
		let mut inner = self.inner.lock().unwrap();
		if let Some(data) = inner.packet_queue.pop_front() {
			inner.interface_ready = true;
			drop(inner);
			let _ = self.process_outgoing(data);
		} else if inner.packet_queue.is_empty() {
			inner.interface_ready = true;
		}
	}

	pub fn start_read_loop(interface: Arc<Mutex<RNodeInterface>>, _transport: Arc<Mutex<RnsTransport>>) {
		thread::spawn(move || {
			Self::read_loop_impl(&interface);
		});
	}

	fn read_loop_impl(interface: &Arc<Mutex<RNodeInterface>>) {
		let mut in_frame = false;
		let mut escape = false;
		let mut command = CMD_UNKNOWN;
		let mut data_buffer = Vec::new();
		let mut command_buffer = Vec::new();
		let mut last_read = Instant::now();

		loop {
			let mut buffer = [0u8; 1];

			let read_result = {
				let iface = interface.lock().unwrap();
				let mut inner = iface.inner.lock().unwrap();
				inner.connection.read(&mut buffer)
			};

			match read_result {
				Ok(1) => {
					let byte = buffer[0];
					last_read = Instant::now();

					if in_frame && byte == KISS_FEND && command == CMD_DATA {
						in_frame = false;
						if !data_buffer.is_empty() {
							// Grab what we need then RELEASE the lock before
							// calling inbound — inbound can trigger prove()
							// → outbound → dispatch → handler closure which
							// re-locks this interface.
							let interface_name = {
								let iface = interface.lock().unwrap();
								*iface.rxb.lock().unwrap() += data_buffer.len() as u64;
								let name = iface.name.clone();
								let mut inner = iface.inner.lock().unwrap();
								inner.r_stat_rssi = None;
								inner.r_stat_snr = None;
								name
							}; // lock released here
							let _ = RnsTransport::inbound(data_buffer.clone(), Some(interface_name));
						}
						data_buffer.clear();
						command_buffer.clear();
					} else if byte == KISS_FEND {
						in_frame = true;
						command = CMD_UNKNOWN;
						data_buffer.clear();
						command_buffer.clear();
					} else if in_frame {
						if data_buffer.is_empty() && command == CMD_UNKNOWN {
							command = byte;
						} else {
							Self::process_command_byte(
								interface,
								command,
								byte,
								&mut escape,
								&mut data_buffer,
								&mut command_buffer,
							);
							let fatal_error = {
								let iface = interface.lock().unwrap();
								let inner = iface.inner.lock().unwrap();
								inner.fatal_error
							};
							if fatal_error {
								break;
							}
						}
					}
				}
				Ok(_) => {}
				Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
					let mut should_break = false;
					let mut send_id: Option<Vec<u8>> = None;
					let mut do_detect = false;

					{
						let iface = interface.lock().unwrap();
						let mut inner = iface.inner.lock().unwrap();

						if !data_buffer.is_empty() && last_read.elapsed().as_millis() > 100 {
							println!(
								"RNodeInterface[{}] device read timeout in command {:02x}",
								iface.name,
								command
							);
							data_buffer.clear();
							in_frame = false;
							command = CMD_UNKNOWN;
							escape = false;
						}

						if let (Some(id_interval), Some(ref id_callsign)) = (inner.id_interval, &inner.id_callsign) {
							if let Some(first_tx) = inner.first_tx {
								if first_tx.elapsed() >= id_interval {
									send_id = Some(id_callsign.clone());
									inner.first_tx = Some(Instant::now());
								}
							}
						}

						if inner.connection.is_ble() && !inner.connection.ble_connected() {
							inner.online = false;
							should_break = true;
						}

						if inner.connection.is_tcp() {
							if !inner.connection.tcp_connected() {
								inner.online = false;
								should_break = true;
							} else if let Some(last_activity) = inner.connection.tcp_last_activity() {
								if last_activity.elapsed() >= TCP_ACTIVITY_TIMEOUT {
									inner.online = false;
									should_break = true;
								}
							}

							let last_write = inner.connection.tcp_last_write().unwrap_or_else(Instant::now);
							if last_write.elapsed() >= TCP_ACTIVITY_KEEPALIVE {
								inner.last_detect = Instant::now();
								do_detect = true;
							}
						}
					}

					if let Some(callsign) = send_id {
						let iface2 = interface.lock().unwrap();
						let _ = iface2.process_outgoing(callsign);
					}

					if do_detect {
						let iface2 = interface.lock().unwrap();
						let _ = iface2.detect();
						if should_break {
							break;
						}
						thread::sleep(Duration::from_millis(80));
						continue;
					}

					if should_break {
						break;
					}

					thread::sleep(Duration::from_millis(80));
				}
				Err(e) => {
					eprintln!("RNode read error: {}", e);
					let iface = interface.lock().unwrap();
					iface.inner.lock().unwrap().online = false;
					break;
				}
			}
		}

		let iface = interface.lock().unwrap();
		let mut inner = iface.inner.lock().unwrap();
		// Callback-driven connections are reconnected by the native bridge
		// (e.g. CoreBluetooth), not by us. Just exit the read loop and let
		// the bridge deregister + re-register the interface as needed.
		let is_callback = matches!(inner.connection, ConnectionType::Callback(_));
		if !inner.detached && !inner.reconnecting && !is_callback {
			inner.reconnecting = true;
			drop(inner);
			drop(iface);
			Self::reconnect_port(interface);
		}
	}

	fn reconnect_port(interface: &Arc<Mutex<RNodeInterface>>) {
		loop {
			{
				let iface = interface.lock().unwrap();
				let inner = iface.inner.lock().unwrap();
				if inner.online || inner.detached {
					break;
				}
			}

			thread::sleep(RECONNECT_WAIT);
			println!("Attempting to reconnect RNode serial port...");

			match Self::try_reconnect(interface) {
				Ok(_) => {
					println!("Reconnected RNode port");
					break;
				}
				Err(e) => {
					eprintln!("Error while reconnecting port: {}", e);
				}
			}
		}

		let iface = interface.lock().unwrap();
		iface.inner.lock().unwrap().reconnecting = false;
	}

	fn try_reconnect(interface: &Arc<Mutex<RNodeInterface>>) -> io::Result<()> {
		let iface = interface.lock().unwrap();
		let connection_info = iface.connection_info.clone();
		drop(iface);

		let new_connection = match connection_info {
			ConnectionInfo::Serial(port_name) => {
				let port = serialport::new(port_name, 115200)
					.timeout(Duration::from_millis(100))
					.data_bits(serialport::DataBits::Eight)
					.stop_bits(serialport::StopBits::One)
					.parity(serialport::Parity::None)
					.flow_control(serialport::FlowControl::None)
					.open()?;
				ConnectionType::Serial(port)
			}
			ConnectionInfo::Tcp { host, port } => ConnectionType::Tcp(TCPConnection::new(&host, port)?),
			ConnectionInfo::Ble { target } => ConnectionType::Ble(BLEConnection::new(target)?),
		};

		let iface = interface.lock().unwrap();
		let mut inner = iface.inner.lock().unwrap();
		inner.connection = new_connection;
		drop(inner);
		drop(iface);

		let iface = interface.lock().unwrap();
		iface.configure_device()
	}

	fn process_command_byte(
		interface: &Arc<Mutex<RNodeInterface>>,
		command: u8,
		byte: u8,
		escape: &mut bool,
		data_buffer: &mut Vec<u8>,
		command_buffer: &mut Vec<u8>,
	) {
		let iface = interface.lock().unwrap();
		let mut inner = iface.inner.lock().unwrap();

		if byte == KISS_FESC && command != CMD_DATA {
			*escape = true;
			return;
		}

		let actual_byte = if *escape && command != CMD_DATA {
			*escape = false;
			match byte {
				KISS_TFEND => KISS_FEND,
				KISS_TFESC => KISS_FESC,
				_ => byte,
			}
		} else {
			if command == CMD_DATA {
				if *escape {
					*escape = false;
					match byte {
						KISS_TFEND => KISS_FEND,
						KISS_TFESC => KISS_FESC,
						_ => byte,
					}
				} else if byte == KISS_FESC {
					*escape = true;
					return;
				} else {
					byte
				}
			} else {
				byte
			}
		};

		match command {
			CMD_DATA => {
				if data_buffer.len() < 508 {
					data_buffer.push(actual_byte);
				}
			}
			CMD_FREQUENCY => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 4 {
					inner.r_frequency = Some(
						((command_buffer[0] as u64) << 24)
							| ((command_buffer[1] as u64) << 16)
							| ((command_buffer[2] as u64) << 8)
							| (command_buffer[3] as u64),
					);
					drop(inner);
					drop(iface);
					interface.lock().unwrap().update_bitrate();
				}
			}
			CMD_BANDWIDTH => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 4 {
					inner.r_bandwidth = Some(
						((command_buffer[0] as u32) << 24)
							| ((command_buffer[1] as u32) << 16)
							| ((command_buffer[2] as u32) << 8)
							| (command_buffer[3] as u32),
					);
					drop(inner);
					drop(iface);
					interface.lock().unwrap().update_bitrate();
				}
			}
			CMD_TXPOWER => {
				inner.r_txpower = Some(actual_byte);
			}
			CMD_SF => {
				inner.r_sf = Some(actual_byte);
				drop(inner);
				drop(iface);
				interface.lock().unwrap().update_bitrate();
			}
			CMD_CR => {
				inner.r_cr = Some(actual_byte);
				drop(inner);
				drop(iface);
				interface.lock().unwrap().update_bitrate();
			}
			CMD_RADIO_STATE => {
				inner.r_state = Some(actual_byte);
			}
			CMD_RADIO_LOCK => {
				inner.r_lock = Some(actual_byte);
			}
			CMD_ST_ALOCK => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 2 {
					let at = ((command_buffer[0] as u16) << 8) | (command_buffer[1] as u16);
					inner.r_st_alock = Some(at as f32 / 100.0);
				}
			}
			CMD_LT_ALOCK => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 2 {
					let at = ((command_buffer[0] as u16) << 8) | (command_buffer[1] as u16);
					inner.r_lt_alock = Some(at as f32 / 100.0);
				}
			}
			CMD_STAT_RX | CMD_STAT_TX => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 4 {
					let stat = ((command_buffer[0] as u32) << 24)
						| ((command_buffer[1] as u32) << 16)
						| ((command_buffer[2] as u32) << 8)
						| (command_buffer[3] as u32);
					if command == CMD_STAT_RX {
						inner.r_stat_rx = Some(stat);
					} else {
						inner.r_stat_tx = Some(stat);
					}
				}
			}
			CMD_STAT_RSSI => {
				inner.r_stat_rssi = Some(actual_byte as i16 - RSSI_OFFSET);
			}
			CMD_STAT_SNR => {
				let snr = (actual_byte as i8) as f32 / 4.0;
				inner.r_stat_snr = Some(snr);
				if let Some(r_sf) = inner.r_sf {
					let sfs = r_sf as f32 - 7.0;
					let q_snr_min = Q_SNR_MIN_BASE - sfs * Q_SNR_STEP;
					let q_snr_span = Q_SNR_MAX - q_snr_min;
					if q_snr_span > 0.0 {
						let mut quality = ((snr - q_snr_min) / q_snr_span) * 100.0;
						if quality > 100.0 {
							quality = 100.0;
						}
						if quality < 0.0 {
							quality = 0.0;
						}
						inner.r_stat_q = Some((quality * 10.0).round() / 10.0);
					}
				}
			}
			CMD_STAT_CHTM => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 11 {
					let airtime_short = ((command_buffer[0] as u16) << 8) | (command_buffer[1] as u16);
					let airtime_long = ((command_buffer[2] as u16) << 8) | (command_buffer[3] as u16);
					let ch_load_short = ((command_buffer[4] as u16) << 8) | (command_buffer[5] as u16);
					let ch_load_long = ((command_buffer[6] as u16) << 8) | (command_buffer[7] as u16);
					let current_rssi = command_buffer[8];
					let noise_floor = command_buffer[9];
					let interference = command_buffer[10];

					inner.r_airtime_short = airtime_short as f32 / 100.0;
					inner.r_airtime_long = airtime_long as f32 / 100.0;
					inner.r_channel_load_short = ch_load_short as f32 / 100.0;
					inner.r_channel_load_long = ch_load_long as f32 / 100.0;
					inner.r_current_rssi = Some(current_rssi as i16 - RSSI_OFFSET);
					inner.r_noise_floor = Some(noise_floor as i16 - RSSI_OFFSET);
					if interference == 0xFF {
						inner.r_interference = None;
					} else {
						let val = interference as i16 - RSSI_OFFSET;
						inner.r_interference = Some(val as f32);
						inner.r_interference_l = Some((Instant::now(), val as f32));
					}
				}
			}
			CMD_STAT_PHYPRM => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 12 {
					let st = ((command_buffer[0] as u16) << 8) | (command_buffer[1] as u16);
					let sr = ((command_buffer[2] as u16) << 8) | (command_buffer[3] as u16);
					let prs = ((command_buffer[4] as u16) << 8) | (command_buffer[5] as u16);
					let prt = ((command_buffer[6] as u16) << 8) | (command_buffer[7] as u16);
					let cst = ((command_buffer[8] as u16) << 8) | (command_buffer[9] as u16);
					let dft = ((command_buffer[10] as u16) << 8) | (command_buffer[11] as u16);

					inner.r_symbol_time_ms = Some(st as f32 / 1000.0);
					inner.r_symbol_rate = Some(sr as f32);
					inner.r_preamble_symbols = Some(prs);
					inner.r_preamble_time_ms = Some(prt as f32 / 1000.0);
					inner.r_csma_slot_time_ms = Some(cst as f32);
					inner.r_csma_difs_ms = Some(dft as f32);
				}
			}
			CMD_STAT_CSMA => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 3 {
					inner.r_csma_cw_band = Some(command_buffer[0]);
					inner.r_csma_cw_min = Some(command_buffer[1]);
					inner.r_csma_cw_max = Some(command_buffer[2]);
				}
			}
			CMD_STAT_BAT => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 2 {
					inner.r_battery_state = match command_buffer[0] {
						0x01 => BatteryState::Discharging,
						0x02 => BatteryState::Charging,
						0x03 => BatteryState::Charged,
						_ => BatteryState::Unknown,
					};
					inner.r_battery_percent = command_buffer[1].min(100);
				}
			}
			CMD_STAT_TEMP => {
				let temp = actual_byte as i8 - 120;
				if (-30..=90).contains(&temp) {
					inner.r_temperature = Some(temp);
					inner.cpu_temp = Some(temp);
				} else {
					inner.r_temperature = None;
					inner.cpu_temp = None;
				}
			}
			CMD_RANDOM => {
				inner.r_random = Some(actual_byte);
			}
			CMD_PLATFORM => {
				inner.platform = Some(actual_byte);
			}
			CMD_MCU => {
				inner.mcu = Some(actual_byte);
			}
			CMD_DETECT => {
				if actual_byte == DETECT_RESP {
					inner.detected = true;
				} else {
					inner.detected = false;
				}
			}
			CMD_FW_VERSION => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 2 {
					inner.maj_version = command_buffer[0];
					inner.min_version = command_buffer[1];

					inner.firmware_ok = inner.maj_version > REQUIRED_FW_VER_MAJ
						|| (inner.maj_version == REQUIRED_FW_VER_MAJ && inner.min_version >= REQUIRED_FW_VER_MIN);
				}
			}
			CMD_READY => {
				drop(inner);
				drop(iface);
				interface.lock().unwrap().process_queue();
			}
			CMD_FB_READ => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 512 {
					let now = Instant::now();
					inner.r_framebuffer_latency = now - inner.r_framebuffer_readtime;
					inner.r_framebuffer = command_buffer.clone();
				}
			}
			CMD_DISP_READ => {
				command_buffer.push(actual_byte);
				if command_buffer.len() == 1024 {
					let now = Instant::now();
					inner.r_disp_latency = now - inner.r_disp_readtime;
					inner.r_disp = command_buffer.clone();
				}
			}
			CMD_ERROR => {
				match actual_byte {
					ERROR_INITRADIO => {
						eprintln!("RNode hardware initialisation error");
						let err = HardwareError {
							error_code: ERROR_INITRADIO,
							description: "Radio initialisation failure".to_string(),
						};
						inner.hw_errors.push(err.clone());
						inner.last_error = Some(err);
						inner.fatal_error = true;
						inner.online = false;
					}
					ERROR_TXFAILED => {
						eprintln!("RNode hardware TX error");
						let err = HardwareError {
							error_code: ERROR_TXFAILED,
							description: "Hardware transmit failure".to_string(),
						};
						inner.hw_errors.push(err.clone());
						inner.last_error = Some(err);
						inner.fatal_error = true;
						inner.online = false;
					}
					ERROR_EEPROM_LOCKED => {
						eprintln!("RNode hardware error: EEPROM is locked");
						let err = HardwareError {
							error_code: ERROR_EEPROM_LOCKED,
							description: "EEPROM is locked on connected device".to_string(),
						};
						inner.hw_errors.push(err.clone());
						inner.last_error = Some(err);
					}
					ERROR_QUEUE_FULL => {
						eprintln!("RNode hardware error: Packet queue full");
						let err = HardwareError {
							error_code: ERROR_QUEUE_FULL,
							description: "Packet queue full on connected device".to_string(),
						};
						inner.hw_errors.push(err.clone());
						inner.last_error = Some(err);
					}
					ERROR_MEMORY_LOW => {
						eprintln!("RNode hardware error: Memory exhausted");
						let err = HardwareError {
							error_code: ERROR_MEMORY_LOW,
							description: "Memory exhausted on connected device".to_string(),
						};
						inner.hw_errors.push(err.clone());
						inner.last_error = Some(err);
					}
					ERROR_MODEM_TIMEOUT => {
						eprintln!("RNode hardware error: Modem communication timed out");
						let err = HardwareError {
							error_code: ERROR_MODEM_TIMEOUT,
							description: "Modem communication timed out on connected device".to_string(),
						};
						inner.hw_errors.push(err.clone());
						inner.last_error = Some(err);
					}
					_ => {
						eprintln!("RNode hardware error: {:02x}", actual_byte);
						let err = HardwareError {
							error_code: actual_byte,
							description: "Unknown hardware failure".to_string(),
						};
						inner.hw_errors.push(err.clone());
						inner.last_error = Some(err);
						inner.fatal_error = true;
						inner.online = false;
					}
				}
			}
			CMD_RESET => {
				if actual_byte == 0xF8 {
					if inner.platform == Some(PLATFORM_ESP32) && inner.online {
						eprintln!("Detected reset while device was online, reinitialising device...");
						let err = HardwareError {
							error_code: actual_byte,
							description: "ESP32 reset".to_string(),
						};
						inner.last_error = Some(err);
						inner.fatal_error = true;
						inner.online = false;
					}
				}
			}
			_ => {}
		}
	}

	pub fn detach(&self) -> io::Result<()> {
		let mut inner = self.inner.lock().unwrap();
		inner.detached = true;
		inner.connection.close();
		drop(inner);

		self.disable_external_framebuffer()?;
		self.set_radio_state(RADIO_STATE_OFF)?;
		self.leave()?;

		Ok(())
	}

	pub fn is_online(&self) -> bool {
		self.inner.lock().unwrap().online
	}

	pub fn get_battery_state(&self) -> BatteryState {
		self.inner.lock().unwrap().r_battery_state
	}

	pub fn get_battery_percent(&self) -> u8 {
		self.inner.lock().unwrap().r_battery_percent
	}

	pub fn get_temperature(&self) -> Option<i8> {
		self.inner.lock().unwrap().r_temperature
	}

	pub fn get_rssi(&self) -> Option<i16> {
		self.inner.lock().unwrap().r_stat_rssi
	}

	pub fn get_snr(&self) -> Option<f32> {
		self.inner.lock().unwrap().r_stat_snr
	}

	pub fn get_airtime_short(&self) -> f32 {
		self.inner.lock().unwrap().r_airtime_short
	}

	pub fn get_airtime_long(&self) -> f32 {
		self.inner.lock().unwrap().r_airtime_long
	}

	pub fn get_channel_load_short(&self) -> f32 {
		self.inner.lock().unwrap().r_channel_load_short
	}

	pub fn get_channel_load_long(&self) -> f32 {
		self.inner.lock().unwrap().r_channel_load_long
	}

	pub fn get_hw_errors(&self) -> Vec<HardwareError> {
		self.inner.lock().unwrap().hw_errors.clone()
	}

	pub fn take_hw_errors(&self) -> Vec<HardwareError> {
		let mut inner = self.inner.lock().unwrap();
		let out = inner.hw_errors.clone();
		inner.hw_errors.clear();
		out
	}

	pub fn get_last_error(&self) -> Option<HardwareError> {
		self.inner.lock().unwrap().last_error.clone()
	}

	pub fn clear_last_error(&self) {
		self.inner.lock().unwrap().last_error = None;
	}

	// -------------------------------------------------------------------
	// Callback-transport constructor (for FFI bridges that own the BLE/USB
	// link natively, e.g. CoreBluetooth on iOS).
	// -------------------------------------------------------------------

	/// Construct an RNodeInterface that delegates raw byte I/O to a caller-
	/// supplied `send_fn` (TX) and an externally-fed RX channel.
	///
	/// Returns `(interface, feed_sender)`. The caller must:
	///   1. Wrap `interface` in an `Arc<Mutex<_>>` and call
	///      `start_read_loop(...)`.
	///   2. Call `configure_device_shared(...)` to run the DETECT/init
	///      handshake (the read loop processes responses while it sleeps).
	///   3. Push every RX byte from the radio into `feed_sender` (one byte
	///      per `send`). The read loop drains it through KISS deframing.
	///   4. Register `process_outgoing` with Transport's outbound handler.
	///
	/// `send_fn` is invoked synchronously from `process_outgoing` with a
	/// fully-framed KISS payload. The bridge is responsible for any radio-
	/// link chunking (e.g. 20-byte BLE writes).
	pub fn new_with_callback(
		name: &str,
		send_fn: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
		config: RNodeRadioConfig,
	) -> io::Result<(Self, Sender<u8>)> {
		Self::validate_config(
			config.frequency,
			config.bandwidth,
			config.txpower,
			config.sf,
			config.cr,
			config.st_alock,
			config.lt_alock,
			&config.id_callsign,
		)?;

		let cb = CallbackConnection::new(send_fn);
		let feed = cb.feed_sender();
		let connection = ConnectionType::Callback(cb);

		// "callback://<name>" is a synthetic identifier kept only for log
		// messages and the (unused) reconnect path.
		let port_name = format!("callback://{}", name);
		let connection_info = ConnectionInfo::Serial(port_name.clone());

		let inner = RNodeInner {
			connection,
			online: false,
			detected: false,
			detached: false,
			reconnecting: false,
			interface_ready: false,
			flow_control: config.flow_control,
			frequency: config.frequency,
			bandwidth: config.bandwidth,
			txpower: config.txpower,
			sf: config.sf,
			cr: config.cr,
			state: RADIO_STATE_ON,
			st_alock: config.st_alock,
			lt_alock: config.lt_alock,
			r_frequency: None,
			r_bandwidth: None,
			r_txpower: None,
			r_sf: None,
			r_cr: None,
			r_state: None,
			r_lock: None,
			r_st_alock: None,
			r_lt_alock: None,
			r_stat_rx: None,
			r_stat_tx: None,
			r_stat_rssi: None,
			r_stat_snr: None,
			r_stat_q: None,
			r_random: None,
			r_airtime_short: 0.0,
			r_airtime_long: 0.0,
			r_channel_load_short: 0.0,
			r_channel_load_long: 0.0,
			r_symbol_time_ms: None,
			r_symbol_rate: None,
			r_preamble_symbols: None,
			r_preamble_time_ms: None,
			r_csma_slot_time_ms: None,
			r_csma_difs_ms: None,
			r_csma_cw_band: None,
			r_csma_cw_min: None,
			r_csma_cw_max: None,
			r_current_rssi: None,
			r_noise_floor: None,
			r_interference: None,
			r_interference_l: None,
			r_battery_state: BatteryState::Unknown,
			r_battery_percent: 0,
			r_temperature: None,
			cpu_temp: None,
			r_framebuffer: vec![0; 512],
			r_framebuffer_readtime: Instant::now(),
			r_framebuffer_latency: Duration::ZERO,
			r_disp: vec![0; 1024],
			r_disp_readtime: Instant::now(),
			r_disp_latency: Duration::ZERO,
			should_read_display: false,
			read_display_interval: DISPLAY_READ_INTERVAL,
			platform: None,
			mcu: None,
			display: None,
			maj_version: 0,
			min_version: 0,
			firmware_ok: false,
			id_callsign: config.id_callsign,
			id_interval: config.id_interval,
			_last_id: Instant::now(),
			first_tx: None,
			last_detect: Instant::now(),
			packet_queue: VecDeque::new(),
			hw_errors: Vec::new(),
			last_error: None,
			fatal_error: false,
		};

		Ok((
			RNodeInterface {
				name: name.to_string(),
				hw_mtu: 508,
				mode: InterfaceMode::Full,
				bitrate: 0,
				supports_discovery: true,
				_force_bitrate: false,
				rxb: Arc::new(Mutex::new(0)),
				txb: Arc::new(Mutex::new(0)),
				inner: Arc::new(Mutex::new(inner)),
				_port_name: port_name,
				connection_info,
			},
			feed,
		))
	}

	/// Snapshot of all device telemetry the read loop currently knows about.
	pub fn stats_snapshot(&self) -> RNodeStats {
		let inner = self.inner.lock().unwrap();
		RNodeStats {
			online: inner.online,
			detected: inner.detected,
			frequency: inner.r_frequency,
			bandwidth: inner.r_bandwidth,
			txpower: inner.r_txpower,
			sf: inner.r_sf,
			cr: inner.r_cr,
			rssi: inner.r_stat_rssi,
			snr: inner.r_stat_snr,
			q: inner.r_stat_q,
			rx_packets: inner.r_stat_rx,
			tx_packets: inner.r_stat_tx,
			airtime_short: inner.r_airtime_short,
			airtime_long: inner.r_airtime_long,
			channel_load_short: inner.r_channel_load_short,
			channel_load_long: inner.r_channel_load_long,
			battery_state: inner.r_battery_state,
			battery_percent: inner.r_battery_percent,
			temperature: inner.r_temperature,
			firmware_maj: inner.maj_version,
			firmware_min: inner.min_version,
		}
	}

	/// Mark detached and close the connection without issuing any radio
	/// commands. Used by FFI deregister paths where the underlying link
	/// (BLE/USB) may already be torn down.
	pub fn shutdown(&self) {
		let mut inner = self.inner.lock().unwrap();
		inner.detached = true;
		inner.online = false;
		inner.connection.close();
	}

	/// Return the configured ID-callsign bytes (if any).
	pub fn id_callsign_bytes(&self) -> Option<Vec<u8>> {
		self.inner.lock().unwrap().id_callsign.clone()
	}
}

// =====================================================================
// Public configuration & telemetry types (used by FFI)
// =====================================================================

/// All radio parameters needed to bring an RNode online.
///
/// Mirrors the positional arguments of [`RNodeInterface::new`] but in a form
/// that is easy to (de)serialise across an FFI boundary.
#[derive(Debug, Clone)]
pub struct RNodeRadioConfig {
	pub frequency: u64,
	pub bandwidth: u32,
	pub txpower: u8,
	pub sf: u8,
	pub cr: u8,
	pub flow_control: bool,
	pub st_alock: Option<f32>,
	pub lt_alock: Option<f32>,
	pub id_interval: Option<Duration>,
	pub id_callsign: Option<Vec<u8>>,
}

/// Snapshot of RNode runtime telemetry.
#[derive(Debug, Clone)]
pub struct RNodeStats {
	pub online: bool,
	pub detected: bool,
	pub frequency: Option<u64>,
	pub bandwidth: Option<u32>,
	pub txpower: Option<u8>,
	pub sf: Option<u8>,
	pub cr: Option<u8>,
	pub rssi: Option<i16>,
	pub snr: Option<f32>,
	pub q: Option<f32>,
	pub rx_packets: Option<u32>,
	pub tx_packets: Option<u32>,
	pub airtime_short: f32,
	pub airtime_long: f32,
	pub channel_load_short: f32,
	pub channel_load_long: f32,
	pub battery_state: BatteryState,
	pub battery_percent: u8,
	pub temperature: Option<i8>,
	pub firmware_maj: u8,
	pub firmware_min: u8,
}
