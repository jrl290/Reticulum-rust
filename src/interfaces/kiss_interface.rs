use super::interface::Interface;
use crate::log;
use crate::transport::Transport as RnsTransport;
use serialport::{DataBits, Parity, SerialPort, StopBits};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct Kiss;

impl Kiss {
    pub const FEND: u8 = 0xC0;
    pub const FESC: u8 = 0xDB;
    pub const TFEND: u8 = 0xDC;
    pub const TFESC: u8 = 0xDD;
    pub const CMD_UNKNOWN: u8 = 0xFE;
    pub const CMD_DATA: u8 = 0x00;
    pub const CMD_TXDELAY: u8 = 0x01;
    pub const CMD_P: u8 = 0x02;
    pub const CMD_SLOTTIME: u8 = 0x03;
    pub const CMD_TXTAIL: u8 = 0x04;
    pub const CMD_READY: u8 = 0x0F;

    pub fn escape(data: &[u8]) -> Vec<u8> {
        let mut escaped = Vec::with_capacity(data.len() + 8);
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

pub struct KissInterface {
    pub base: Interface,
    pub port: String,
    pub speed: u32,
    pub databits: u8,
    pub parity: Parity,
    pub stopbits: u8,
    pub timeout_ms: u64,
    pub online: bool,
    pub serial: Option<Arc<Mutex<Box<dyn SerialPort>>>>,
    pub preamble_ms: u32,
    pub txtail_ms: u32,
    pub persistence: u8,
    pub slottime_ms: u32,
    pub flow_control: bool,
    pub interface_ready: bool,
    pub flow_control_timeout: f64,
    pub flow_control_locked: f64,
    pub packet_queue: VecDeque<Vec<u8>>,
    pub beacon_interval: Option<f64>,
    pub beacon_data: Vec<u8>,
    pub first_tx: Option<f64>,
}

impl KissInterface {
    pub const MAX_CHUNK: usize = 32768;
    pub const BITRATE_GUESS: u64 = 1200;
    pub const DEFAULT_IFAC_SIZE: usize = 8;
    pub const HW_MTU: usize = 564;

    pub fn new(config: &std::collections::HashMap<String, String>) -> Result<Self, String> {
        let mut base = Interface::new();

        let name = config
            .get("name")
            .ok_or("KISSInterface requires 'name' in config")?
            .clone();

        let port = config
            .get("port")
            .ok_or("No port specified for KISS interface")?
            .clone();

        let speed = config
            .get("speed")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(9600);

        let databits = config
            .get("databits")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(8);

        let parity_str = config.get("parity").cloned().unwrap_or_else(|| "N".to_string());
        let stopbits = config
            .get("stopbits")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(1);

        let preamble_ms = config
            .get("preamble")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(350);

        let txtail_ms = config
            .get("txtail")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(20);

        let persistence = config
            .get("persistence")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(64);

        let slottime_ms = config
            .get("slottime")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(20);

        let flow_control = config
            .get("flow_control")
            .map(|v| parse_bool(v))
            .unwrap_or(false);

        let beacon_interval = config
            .get("id_interval")
            .or_else(|| config.get("beacon_interval"))
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v as f64);

        let beacon_data = config
            .get("id_callsign")
            .or_else(|| config.get("beacon_data"))
            .cloned()
            .unwrap_or_default();

        let parity = match parity_str.to_lowercase().as_str() {
            "e" | "even" => Parity::Even,
            "o" | "odd" => Parity::Odd,
            _ => Parity::None,
        };

        base.name = Some(name.clone());
        base.hw_mtu = Some(Self::HW_MTU);
        base.fixed_mtu = true;
        base.in_enabled = true;
        base.out_enabled = false;
        base.bitrate = Self::BITRATE_GUESS;
        base.online = false;
        base.ingress_control = false;

        let mut interface = KissInterface {
            base,
            port,
            speed,
            databits,
            parity,
            stopbits,
            timeout_ms: 100,
            online: false,
            serial: None,
            preamble_ms,
            txtail_ms,
            persistence,
            slottime_ms,
            flow_control,
            interface_ready: false,
            flow_control_timeout: 5.0,
            flow_control_locked: now(),
            packet_queue: VecDeque::new(),
            beacon_interval,
            beacon_data: beacon_data.into_bytes(),
            first_tx: None,
        };

        interface.open_port()?;

        Ok(interface)
    }

    pub fn start_read_loop(iface: Arc<Mutex<KissInterface>>) {
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(2));

            let (configured, iface_name) = {
                let mut iface_guard = iface.lock().unwrap();
                iface_guard.online = true;
                iface_guard.base.online = true;
                log(
                    &format!("Serial port {} is now open", iface_guard.port),
                    crate::LOG_VERBOSE,
                    false,
                    false,
                );
                log("Configuring KISS interface parameters...", crate::LOG_VERBOSE, false, false);
                let ok = match iface_guard.configure_device() {
                    Ok(()) => {
                        iface_guard.interface_ready = true;
                        log("KISS interface configured", crate::LOG_VERBOSE, false, false);
                        true
                    }
                    Err(err) => {
                        log(
                            &format!("Could not configure KISS interface: {}", err),
                            crate::LOG_ERROR,
                            false,
                            false,
                        );
                        false
                    }
                };
                (ok, iface_guard.base.name.clone())
            };

            if !configured {
                Self::handle_error_and_reconnect(iface);
                return;
            }

            // Notify Transport so the false→true transition triggers an
            // automatic re-announce of all locally registered destinations on
            // this interface (covers initial open and any later re-open
            // after a reconnect).
            if let Some(name) = iface_name {
                RnsTransport::set_interface_online(&name, true);
            }

            let mut in_frame = false;
            let mut escape = false;
            let mut command = Kiss::CMD_UNKNOWN;
            let mut data_buffer = Vec::new();
            let mut last_read_ms = now_ms();

            loop {
                let (serial, timeout_ms, hw_mtu) = {
                    let iface_guard = iface.lock().unwrap();
                    (
                        iface_guard.serial.clone(),
                        iface_guard.timeout_ms,
                        iface_guard.base.hw_mtu.unwrap_or(Self::HW_MTU),
                    )
                };

                let serial = match serial {
                    Some(port) => port,
                    None => {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };

                let bytes_available = {
                    let guard = serial.lock().unwrap();
                    guard.bytes_to_read().unwrap_or(0)
                };

                if bytes_available > 0 {
                    let mut byte = [0u8; 1];
                    let read_ok = {
                        let mut guard = serial.lock().unwrap();
                        guard.read_exact(&mut byte).is_ok()
                    };

                    if !read_ok {
                        break;
                    }

                    last_read_ms = now_ms();
                    let byte = byte[0];

                    if in_frame && byte == Kiss::FEND && command == Kiss::CMD_DATA {
                        in_frame = false;
                        let mut iface_guard = iface.lock().unwrap();
                        iface_guard.process_incoming(&data_buffer);
                        data_buffer.clear();
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
                            } else {
                                let mut out_byte = byte;
                                if escape {
                                    if byte == Kiss::TFEND {
                                        out_byte = Kiss::FEND;
                                    }
                                    if byte == Kiss::TFESC {
                                        out_byte = Kiss::FESC;
                                    }
                                    escape = false;
                                }
                                data_buffer.push(out_byte);
                            }
                        } else if command == Kiss::CMD_READY {
                            let mut iface_guard = iface.lock().unwrap();
                            iface_guard.process_queue();
                        }
                    }
                } else {
                    let time_since_last = now_ms().saturating_sub(last_read_ms);
                    if !data_buffer.is_empty() && time_since_last > timeout_ms {
                        data_buffer.clear();
                        in_frame = false;
                        command = Kiss::CMD_UNKNOWN;
                        escape = false;
                    }

                    thread::sleep(Duration::from_millis(50));

                    let mut iface_guard = iface.lock().unwrap();
                    if iface_guard.flow_control && !iface_guard.interface_ready {
                        if now() > iface_guard.flow_control_locked + iface_guard.flow_control_timeout {
                            log(
                                &format!(
                                    "Interface {} is unlocking flow control due to time-out. This should not happen. Your hardware might have missed a flow-control READY command, or maybe it does not support flow-control.",
                                    iface_guard
                                ),
                                crate::LOG_WARNING,
                                false,
                                false,
                            );
                            iface_guard.process_queue();
                        }
                    }

                    if let (Some(interval), Some(first_tx)) =
                        (iface_guard.beacon_interval, iface_guard.first_tx)
                    {
                        if now() > first_tx + interval {
                            let beacon_text = String::from_utf8_lossy(&iface_guard.beacon_data);
                            log(
                                &format!(
                                    "Interface {} is transmitting beacon data: {}",
                                    iface_guard, beacon_text
                                ),
                                crate::LOG_DEBUG,
                                false,
                                false,
                            );
                            iface_guard.first_tx = None;

                            let mut frame = iface_guard.beacon_data.clone();
                            while frame.len() < 15 {
                                frame.push(0x00);
                            }
                            let _ = iface_guard.process_outgoing(frame);
                        }
                    }
                }
            }

            Self::handle_error_and_reconnect(iface);
        });
    }

    fn handle_error_and_reconnect(iface: Arc<Mutex<KissInterface>>) {
        {
            let mut iface_guard = iface.lock().unwrap();
            iface_guard.online = false;
            iface_guard.base.online = false;
            iface_guard.serial = None;
            log(
                "A serial port error occurred, the interface is now offline.",
                crate::LOG_ERROR,
                false,
                false,
            );
            log(
                &format!(
                    "The interface {} experienced an unrecoverable error and is now offline.",
                    iface_guard
                ),
                crate::LOG_ERROR,
                false,
                false,
            );
        }

        if crate::reticulum::panic_on_interface_error_enabled() {
            panic!("KISS interface error");
        }

        log(
            "Reticulum will attempt to reconnect the interface periodically.",
            crate::LOG_ERROR,
            false,
            false,
        );

        Self::reconnect_port(iface);
    }

    fn open_port(&mut self) -> Result<(), String> {
        log(
            &format!("Opening serial port {}...", self.port),
            crate::LOG_VERBOSE,
            false,
            false,
        );

        let data_bits = match self.databits {
            5 => DataBits::Five,
            6 => DataBits::Six,
            7 => DataBits::Seven,
            _ => DataBits::Eight,
        };

        let stop_bits = match self.stopbits {
            2 => StopBits::Two,
            _ => StopBits::One,
        };

        let port = serialport::new(&self.port, self.speed)
            .data_bits(data_bits)
            .parity(self.parity)
            .stop_bits(stop_bits)
            .timeout(Duration::from_millis(0))
            .open()
            .map_err(|e| format!("Could not open serial port: {}", e))?;

        self.serial = Some(Arc::new(Mutex::new(port)));
        Ok(())
    }

    fn configure_device(&mut self) -> Result<(), String> {
        self.set_preamble(self.preamble_ms)?;
        self.set_txtail(self.txtail_ms)?;
        self.set_persistence(self.persistence)?;
        self.set_slottime(self.slottime_ms)?;
        self.set_flow_control(self.flow_control)?;
        Ok(())
    }

    fn set_preamble(&mut self, preamble_ms: u32) -> Result<(), String> {
        let mut preamble = (preamble_ms / 10) as u16;
        if preamble > 255 {
            preamble = 255;
        }
        self.send_command(Kiss::CMD_TXDELAY, preamble as u8)
            .map_err(|_| {
                format!(
                    "Could not configure KISS interface preamble to {} (command value {})",
                    preamble_ms, preamble
                )
            })
    }

    fn set_txtail(&mut self, txtail_ms: u32) -> Result<(), String> {
        let mut txtail = (txtail_ms / 10) as u16;
        if txtail > 255 {
            txtail = 255;
        }
        self.send_command(Kiss::CMD_TXTAIL, txtail as u8)
            .map_err(|_| {
                format!(
                    "Could not configure KISS interface TX tail to {} (command value {})",
                    txtail_ms, txtail
                )
            })
    }

    fn set_persistence(&mut self, persistence: u8) -> Result<(), String> {
        let persistence = persistence.min(255);
        self.send_command(Kiss::CMD_P, persistence)
            .map_err(|_| format!("Could not configure KISS interface persistence to {}", persistence))
    }

    fn set_slottime(&mut self, slottime_ms: u32) -> Result<(), String> {
        let mut slottime = (slottime_ms / 10) as u16;
        if slottime > 255 {
            slottime = 255;
        }
        self.send_command(Kiss::CMD_SLOTTIME, slottime as u8)
            .map_err(|_| {
                format!(
                    "Could not configure KISS interface slot time to {} (command value {})",
                    slottime_ms, slottime
                )
            })
    }

    fn set_flow_control(&mut self, _flow_control: bool) -> Result<(), String> {
        self.send_command(Kiss::CMD_READY, 0x01)
            .map_err(|_| "Could not enable KISS interface flow control".to_string())
    }

    fn send_command(&mut self, command: u8, value: u8) -> Result<(), String> {
        let frame = [Kiss::FEND, command, value, Kiss::FEND];
        let written = if let Some(port) = &self.serial {
            let mut guard = port.lock().unwrap();
            guard.write(&frame).unwrap_or(0)
        } else {
            0
        };

        if written != frame.len() {
            return Err("Short write when sending KISS command".to_string());
        }
        Ok(())
    }

    fn process_incoming(&mut self, data: &[u8]) {
        self.base.rxb += data.len() as u64;
        let interface_name = self.base.name.clone();
        let _ = RnsTransport::inbound(data.to_vec(), interface_name);
    }

    fn queue(&mut self, data: Vec<u8>) {
        self.packet_queue.push_back(data);
    }

    fn process_queue(&mut self) {
        if let Some(data) = self.packet_queue.pop_front() {
            self.interface_ready = true;
            let _ = self.process_outgoing(data);
        } else {
            self.interface_ready = true;
        }
    }

    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        if !self.online {
            return Ok(());
        }

        if !self.interface_ready {
            self.queue(data);
            return Ok(());
        }

        if self.flow_control {
            self.interface_ready = false;
            self.flow_control_locked = now();
        }

        // Apply forced bitrate delay if set
        self.base.enforce_bitrate(data.len());

        let escaped = Kiss::escape(&data);
        let mut frame = Vec::with_capacity(escaped.len() + 3);
        frame.push(Kiss::FEND);
        frame.push(Kiss::CMD_DATA);
        frame.extend_from_slice(&escaped);
        frame.push(Kiss::FEND);

        let written = if let Some(port) = &self.serial {
            let mut guard = port.lock().unwrap();
            guard.write(&frame).unwrap_or(0)
        } else {
            0
        };

        self.base.txb += data.len() as u64;

        if data == self.beacon_data {
            self.first_tx = None;
        } else if self.first_tx.is_none() {
            self.first_tx = Some(now());
        }

        if written != frame.len() {
            return Err(format!(
                "Serial interface only wrote {} bytes of {}",
                written,
                frame.len()
            ));
        }

        Ok(())
    }

    fn reconnect_port(iface: Arc<Mutex<KissInterface>>) {
        loop {
            {
                let iface_guard = iface.lock().unwrap();
                if iface_guard.online {
                    break;
                }
            }

            thread::sleep(Duration::from_secs(5));
            let port_name = {
                let iface_guard = iface.lock().unwrap();
                iface_guard.port.clone()
            };

            log(
                &format!("Attempting to reconnect serial port {} for {}...", port_name, iface.lock().unwrap()),
                crate::LOG_VERBOSE,
                false,
                false,
            );

            let result = {
                let mut iface_guard = iface.lock().unwrap();
                iface_guard.open_port()
            };

            if result.is_ok() {
                {
                    let mut iface_guard = iface.lock().unwrap();
                    iface_guard.online = true;
                    iface_guard.base.online = true;
                }
                Self::start_read_loop(Arc::clone(&iface));
                log(
                    &format!("Reconnected serial port for {}", iface.lock().unwrap()),
                    crate::LOG_VERBOSE,
                    false,
                    false,
                );
                break;
            }
        }
    }

    pub fn to_string(&self) -> String {
        format!("KISSInterface[{}]", self.base.name.as_ref().unwrap_or(&"unnamed".to_string()))
    }
}

impl std::fmt::Display for KissInterface {
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
