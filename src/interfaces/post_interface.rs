//! PostInterface — HTTP-based exchange client for Reticulum-PHP nodes.
//!
//! Implements the HTTP exchange protocol used by Reticulum-post PHP nodes:
//!
//! 1. **Registration**: POST to `/v1/interfaces/register` with name, bitrate,
//!    MTU, and metadata. Receives an `interface_id` and `session_token`.
//!
//! 2. **Exchange**: POST to `/v1/interfaces/exchange` with:
//!    - Base64-encoded outbound packets (raw RNS binary)
//!    - Batch ID for dedup
//!    - ACK batch IDs for received batches
//!    Receives base64-encoded inbound packets.
//!
//! 3. **Poll loop**: Periodically exchanges packets. In wake mode, idles
//!    until the remote node sends a wake notification.
//!
//! Protocol reverse-engineered from:
//!   ../Reticulum-post/php/src/post_interface.php
//!   ../Reticulum-post/php/src/index.php (TcpBridgeHttpClient)

use super::interface::Interface;
use crate::log;
use crate::transport::Transport as RnsTransport;
use base64::Engine;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize)]
struct RegisterRequest<'a> {
    name: &'a str,
    bitrate: u64,
    mtu: usize,
    metadata: RegisterMetadata,
}

#[derive(serde::Serialize)]
struct RegisterMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<&'static str>,
    implementation: &'static str,
    mode: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_interface_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wake_url: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct RegisterResponse {
    status: String,
    interface_id: String,
    session_token: String,
    #[serde(default)]
    idle_exchange_interval_ms: Option<u64>,
    #[serde(default)]
    max_batch_packets: Option<usize>,
    #[serde(default)]
    max_packet_bytes: Option<usize>,
}

#[derive(serde::Serialize)]
struct ExchangeRequest {
    interface_id: String,
    session_token: String,
    packets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_id: Option<String>,
    #[serde(default)]
    ack_batch_ids: Vec<String>,
    max_packets: usize,
}

#[derive(serde::Deserialize, Debug)]
struct ExchangeResponse {
    status: String,
    #[serde(default)]
    batch_id: Option<String>,
    #[serde(default)]
    duplicate_batch: Option<bool>,
    #[serde(default)]
    accepted_packets: Option<usize>,
    #[serde(default)]
    delivery_batch_id: Option<String>,
    #[serde(default)]
    delivery_packets: Option<Vec<String>>,
    #[serde(default)]
    delivery_more: Option<bool>,
    #[serde(default)]
    idle_exchange_interval_ms: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

pub struct PostInterface {
    pub base: Interface,
    pub node_url: String,
    pub wake_url: Option<String>,
    pub peer_interface_id: Option<String>,
    pub peer_session_token: Option<String>,
    pub poll_interval_secs: f64,
    pub interface_id: Option<String>,
    pub session_token: Option<String>,
    pub max_batch_packets: usize,
    pub max_packet_bytes: usize,
    pub idle_exchange_interval_ms: u64,
    pub outbound_queue: VecDeque<Vec<u8>>,
    batch_seq: u64,
    ack_batch_ids: Vec<String>,
    pub is_wake_mode: bool,
    pub running: Arc<AtomicBool>,
    client: reqwest::blocking::Client,
    pub wake_listen_host: Option<String>,
    pub wake_listen_port: Option<u16>,
    wake_signal: Arc<(Mutex<bool>, Condvar)>,
}

fn generate_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn requeue_packets(queue: &mut VecDeque<Vec<u8>>, packets: &mut Vec<Vec<u8>>) {
    for raw in packets.drain(..).rev() {
        queue.push_front(raw);
    }
}

impl PostInterface {
    pub const HW_MTU: usize = 500;
    pub const BITRATE_GUESS: u64 = 1_000_000_000;
    pub const DEFAULT_POLL_INTERVAL_SECS: f64 = 5.0;
    pub const MIN_POLL_INTERVAL_SECS: f64 = 2.0;
    pub const DEFAULT_MAX_BATCH_PACKETS: usize = 64;
    pub const DEFAULT_MAX_PACKET_BYTES: usize = 512;

    pub fn new(config: &HashMap<String, String>) -> Result<Self, String> {
        let node_url = config
            .get("node_url")
            .ok_or("PostInterface requires 'node_url' in config")?
            .trim_end_matches('/')
            .to_string();

        if node_url.is_empty()
            || !(node_url.starts_with("http://") || node_url.starts_with("https://"))
        {
            return Err(format!(
                "PostInterface 'node_url' must be a valid HTTP(S) URL, got: {}",
                node_url
            ));
        }

        let name = config
            .get("name")
            .ok_or("PostInterface requires 'name' in config")?
            .clone();

        let wake_url = config
            .get("wake_url")
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty());

        let poll_interval_secs = config
            .get("poll_interval_seconds")
            .and_then(|v| v.parse::<f64>().ok())
            .map(|v| v.max(Self::MIN_POLL_INTERVAL_SECS))
            .unwrap_or(Self::DEFAULT_POLL_INTERVAL_SECS);

        let bitrate = config
            .get("bitrate")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(Self::BITRATE_GUESS);

        let mtu = config
            .get("mtu")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(Self::HW_MTU);

        let is_wake_mode = wake_url.is_some();
        let wake_listen_host = config.get("wake_listen_host").map(|s| s.to_string());
        let wake_listen_port = config.get("wake_listen_port").and_then(|p| p.parse::<u16>().ok());

        let (peer_interface_id, peer_session_token) = if is_wake_mode {
            (Some(generate_hex(16)), Some(generate_hex(32)))
        } else {
            (None, None)
        };

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        let mut base = Interface::new();
        base.name = Some(name);
        base.in_enabled = true;
        base.out_enabled = true;
        base.hw_mtu = Some(mtu);
        base.bitrate = bitrate;
        base.online = false;
        base.autoconfigure_mtu = false;
        base.fixed_mtu = true;
        base.supports_discovery = false;

        Ok(PostInterface {
            base,
            node_url,
            wake_url,
            peer_interface_id,
            peer_session_token,
            poll_interval_secs,
            interface_id: None,
            session_token: None,
            max_batch_packets: Self::DEFAULT_MAX_BATCH_PACKETS,
            max_packet_bytes: Self::DEFAULT_MAX_PACKET_BYTES,
            idle_exchange_interval_ms: 1000,
            outbound_queue: VecDeque::new(),
            batch_seq: 0,
            ack_batch_ids: Vec::new(),
            is_wake_mode,
            running: Arc::new(AtomicBool::new(false)),
            client,
            wake_listen_host,
            wake_listen_port,
            wake_signal: Arc::new((Mutex::new(false), Condvar::new())),
        })
    }

    pub fn register_with_remote(&mut self) -> Result<(), String> {
        let register_url = format!("{}/v1/interfaces/register", self.node_url);

        let metadata = if let Some(ref wake_url) = self.wake_url {
            // Wake mode: register as PHP peer with pre-generated credentials
            let peer_url = wake_url
                .strip_suffix("/v1/wake")
                .unwrap_or(wake_url)
                .to_string();

            RegisterMetadata {
                client: Some("reticulum-php"),
                implementation: "PostInterface",
                mode: 6, // MODE_GATEWAY
                transport: None,
                peer_url: Some(peer_url),
                peer_interface_id: self.peer_interface_id.clone(),
                peer_session_token: self.peer_session_token.clone(),
                wake_url: None,
            }
        } else {
            // Poll mode: register as regular PostInterface client
            RegisterMetadata {
                client: Some("rns-post-interface"),
                implementation: "PostInterface",
                mode: 6,
                transport: Some("tcp-backbone-gateway"),
                peer_url: None,
                peer_interface_id: None,
                peer_session_token: None,
                wake_url: None,
            }
        };

        let request = RegisterRequest {
            name: &format!("RNS PostInterface ({})", self.base.name.as_deref().unwrap_or("post-interface")),
            bitrate: self.base.bitrate,
            mtu: self.base.hw_mtu.unwrap_or(Self::HW_MTU),
            metadata,
        };

        let body = serde_json::to_string(&request)
            .map_err(|e| format!("Failed to serialize register request: {}", e))?;

        log(
            &format!(
                "PostInterface registering at {} (name={}, bitrate={}, mtu={})",
                register_url, request.name, request.bitrate, request.mtu,
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );

        let response = self
            .client
            .post(&register_url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .map_err(|e| format!("Registration HTTP request failed: {}", e))?;

        let status = response.status();
        let response_text = response
            .text()
            .map_err(|e| format!("Failed to read registration response: {}", e))?;

        if !status.is_success() {
            return Err(format!(
                "Registration failed (HTTP {}): {}",
                status.as_u16(),
                response_text,
            ));
        }

        let register_response: RegisterResponse = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse registration response: {} (body: {})", e, response_text))?;

        if register_response.status != "registered" {
            return Err(format!(
                "Registration returned unexpected status: {}",
                register_response.status
            ));
        }

        self.interface_id = Some(register_response.interface_id.clone());
        self.session_token = Some(register_response.session_token.clone());
        self.max_batch_packets = register_response.max_batch_packets.unwrap_or(Self::DEFAULT_MAX_BATCH_PACKETS);
        self.max_packet_bytes = register_response.max_packet_bytes.unwrap_or(Self::DEFAULT_MAX_PACKET_BYTES);
        self.idle_exchange_interval_ms = register_response.idle_exchange_interval_ms.unwrap_or(1000);

        let remote_interval_secs = (self.idle_exchange_interval_ms as f64) / 1000.0;
        if remote_interval_secs > self.poll_interval_secs {
            self.poll_interval_secs = remote_interval_secs;
        }

        self.base.online = true;
        if let Some(ref name) = self.base.name {
            RnsTransport::set_interface_online(name, true);
        }

        let iface_short = self.interface_id.as_deref()
            .map(|id| &id[..8.min(id.len())])
            .unwrap_or("unknown");

        log(
            &format!(
                "PostInterface registered with {} (iface={}, max_batch={}, max_bytes={})",
                self.node_url, iface_short, self.max_batch_packets, self.max_packet_bytes,
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );

        Ok(())
    }

    fn exchange(&mut self) -> Result<ExchangeResult, String> {
        let interface_id = match &self.interface_id {
            Some(id) => id.clone(),
            None => return Err("PostInterface not registered".to_string()),
        };
        let session_token = match &self.session_token {
            Some(tok) => tok.clone(),
            None => return Err("PostInterface not registered".to_string()),
        };
        let node_url = self.node_url.clone();
        let max_batch = self.max_batch_packets;
        let max_bytes = self.max_packet_bytes;

        let exchange_url = format!("{}/v1/interfaces/exchange", node_url);

        // Collect packets from front of queue (up to max_batch)
        let mut raw_packets: Vec<Vec<u8>> = Vec::new();
        let mut b64_packets: Vec<String> = Vec::new();
        for _ in 0..max_batch {
            match self.outbound_queue.pop_front() {
                Some(raw) if raw.len() <= max_bytes => {
                    b64_packets.push(base64::engine::general_purpose::STANDARD.encode(&raw));
                    raw_packets.push(raw);
                }
                Some(raw) => {
                    log(
                        &format!("PostInterface dropped oversized outbound packet ({} > {} bytes)", raw.len(), max_bytes),
                        crate::LOG_WARNING, false, false,
                    );
                }
                None => break,
            }
        }

        let batch_id = if !b64_packets.is_empty() {
            Some(self.next_batch_id())
        } else {
            None
        };

        let ack_ids: Vec<String> = std::mem::take(&mut self.ack_batch_ids);

        let request = ExchangeRequest {
            interface_id,
            session_token,
            packets: b64_packets,
            batch_id: batch_id.clone(),
            ack_batch_ids: ack_ids,
            max_packets: max_batch,
        };

        let body = serde_json::to_string(&request)
            .map_err(|e| {
                requeue_packets(&mut self.outbound_queue, &mut raw_packets);
                format!("Failed to serialize exchange request: {}", e)
            })?;

        let response = match self.client
            .post(&exchange_url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                requeue_packets(&mut self.outbound_queue, &mut raw_packets);
                return Err(format!("Exchange HTTP request failed: {}", e));
            }
        };

        let status = response.status();

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            requeue_packets(&mut self.outbound_queue, &mut raw_packets);
            log(
                &format!("PostInterface session expired (HTTP {}), will re-register", status.as_u16()),
                crate::LOG_WARNING, false, false,
            );
            self.base.online = false;
            if let Some(ref name) = self.base.name {
                RnsTransport::set_interface_online(name, false);
            }
            self.interface_id = None;
            self.session_token = None;
            return Err("Session expired".to_string());
        }

        let response_text = match response.text() {
            Ok(t) => t,
            Err(e) => {
                requeue_packets(&mut self.outbound_queue, &mut raw_packets);
                return Err(format!("Failed to read exchange response: {}", e));
            }
        };

        if !status.is_success() {
            requeue_packets(&mut self.outbound_queue, &mut raw_packets);
            return Err(format!("Exchange failed (HTTP {}): {}", status.as_u16(), response_text));
        }

        let exchange_response: ExchangeResponse = match serde_json::from_str(&response_text) {
            Ok(r) => r,
            Err(e) => {
                requeue_packets(&mut self.outbound_queue, &mut raw_packets);
                return Err(format!("Failed to parse exchange response: {} (body: {})", e, response_text));
            }
        };

        if let Some(ref err) = exchange_response.error {
            requeue_packets(&mut self.outbound_queue, &mut raw_packets);
            return Err(format!("Exchange returned error: {}", err));
        }

        if let Some(ms) = exchange_response.idle_exchange_interval_ms {
            self.idle_exchange_interval_ms = ms;
            let remote_secs = (ms as f64) / 1000.0;
            if remote_secs > self.poll_interval_secs {
                self.poll_interval_secs = remote_secs;
            }
        }

        let mut recv_count: usize = 0;
        if let Some(delivery_packets) = exchange_response.delivery_packets {
            for b64_packet in &delivery_packets {
                match base64::engine::general_purpose::STANDARD.decode(b64_packet) {
                    Ok(raw) => {
                        self.process_incoming(raw);
                        recv_count += 1;
                    }
                    Err(e) => {
                        log(&format!("PostInterface failed to decode delivery packet: {}", e),
                            crate::LOG_WARNING, false, false);
                    }
                }
            }
        }

        if let Some(ref delivery_batch_id) = exchange_response.delivery_batch_id {
            if !delivery_batch_id.is_empty() {
                self.ack_batch_ids.push(delivery_batch_id.clone());
            }
        }

        let has_more = exchange_response.delivery_more.unwrap_or(false);
        let effective_interval = if has_more {
            (self.idle_exchange_interval_ms as f64 / 1000.0).max(0.1)
        } else {
            self.poll_interval_secs
        };

        Ok(ExchangeResult {
            sent_count: raw_packets.len(),
            recv_count,
            has_more,
            effective_interval_secs: effective_interval,
            batch_id,
        })
    }

    fn next_batch_id(&mut self) -> String {
        self.batch_seq += 1;
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("rns-post-{}-{}", ms, self.batch_seq)
    }

    fn process_incoming(&mut self, data: Vec<u8>) {
        if self.base.online && !self.base.detached {
            self.base.rxb += data.len() as u64;
            let interface_name = self.base.name.clone();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                RnsTransport::inbound(data, interface_name)
            }));
        }
    }

    pub fn process_outgoing(&mut self, data: Vec<u8>) -> Result<(), String> {
        if !self.base.online || self.base.detached {
            return Err("PostInterface offline or detached".to_string());
        }

        const MAX_QUEUE_LEN: usize = 1024;
        if self.outbound_queue.len() >= MAX_QUEUE_LEN {
            log("PostInterface outbound queue full, dropping oldest packet",
                crate::LOG_WARNING, false, false);
            self.outbound_queue.pop_front();
        }

        self.outbound_queue.push_back(data);
        Ok(())
    }

    pub fn start_poll_loop(iface: Arc<Mutex<PostInterface>>) {
        let running = {
            let guard = iface.lock().unwrap();
            guard.running.store(true, Ordering::SeqCst);
            Arc::clone(&guard.running)
        };
        let wake_signal = {
            let guard = iface.lock().unwrap();
            Arc::clone(&guard.wake_signal)
        };

        // Spawn wake HTTP server if configured
        {
            let (host, port, node_url) = {
                let guard = iface.lock().unwrap();
                (guard.wake_listen_host.clone(), guard.wake_listen_port, guard.node_url.clone())
            };
            if let (Some(h), Some(p)) = (host, port) {
                let signal = {
                    let guard = iface.lock().unwrap();
                    Arc::clone(&guard.wake_signal)
                };
                let running_clone = Arc::clone(&running);
                thread::spawn(move || {
                    Self::wake_server(h, p, signal, running_clone, node_url);
                });
            }
        }

        thread::spawn(move || {
            {
                let mut guard = iface.lock().unwrap();
                if let Err(e) = guard.register_with_remote() {
                    log(
                        &format!("PostInterface initial registration failed: {}. Will retry in poll loop.", e),
                        crate::LOG_ERROR, false, false,
                    );
                }
            }

            let mut consecutive_errors: u32 = 0;
            let mut last_exchange: f64 = 0.0;
            let min_interval = 3.0;
            let wake_fallback_interval = 60.0;

            while running.load(Ordering::SeqCst) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();

                // Check for pending wake — triggers immediate exchange
                let triggered = {
                    let (lock, _cvar) = &*wake_signal;
                    let mut woken = lock.lock().unwrap();
                    let was_woken = *woken;
                    *woken = false;
                    was_woken
                };

                if !triggered {
                    let interval = {
                        let guard = iface.lock().unwrap();
                        let registered = guard.interface_id.is_some();
                        if !registered {
                            5.0
                        } else if guard.wake_url.is_some() {
                            wake_fallback_interval
                        } else if guard.poll_interval_secs > 0.0 {
                            guard.poll_interval_secs.max(min_interval)
                        } else {
                            (guard.idle_exchange_interval_ms as f64 / 1000.0).max(min_interval)
                        }
                    };

                    if now - last_exchange < interval {
                        thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                }

                // Re-register if needed
                {
                    let mut guard = iface.lock().unwrap();
                    if guard.interface_id.is_none() {
                        match guard.register_with_remote() {
                            Ok(()) => consecutive_errors = 0,
                            Err(e) => {
                                consecutive_errors += 1;
                                log(&format!("PostInterface re-registration failed: {}", e),
                                    crate::LOG_ERROR, false, false);
                            }
                        }
                    }
                }

                // Do exchange
                {
                    let mut guard = iface.lock().unwrap();
                    if guard.interface_id.is_some() {
                        match guard.exchange() {
                            Ok(result) => {
                                consecutive_errors = 0;
                                last_exchange = now;
                                if result.sent_count > 0 || result.recv_count > 0 {
                                    let name = guard.base.name.as_deref().unwrap_or("post");
                                    log(
                                        &format!("PostInterface({}): sent={} recv={}{}",
                                            name, result.sent_count, result.recv_count,
                                            if result.has_more { " (more)" } else { "" }),
                                        crate::LOG_DEBUG, false, false,
                                    );
                                }
                            }
                            Err(e) => {
                                consecutive_errors += 1;
                                if consecutive_errors <= 3 || consecutive_errors % 10 == 0 {
                                    log(
                                        &format!("PostInterface exchange error ({} consecutive): {}", consecutive_errors, e),
                                        crate::LOG_ERROR, false, false,
                                    );
                                }
                            }
                        }
                    }
                }

                // No tight loop — already slept above if not triggered
                if triggered {
                    thread::sleep(Duration::from_millis(100));
                }
            }

            log("PostInterface poll loop shutting down", crate::LOG_NOTICE, false, false);
        });
    }

    /// Minimal HTTP server that listens for POST /v1/wake from the PHP node.
    /// Signals the poll loop to do an immediate exchange.
    fn wake_server(
        host: String,
        port: u16,
        wake_signal: Arc<(Mutex<bool>, Condvar)>,
        running: Arc<AtomicBool>,
        node_url: String,
    ) {
        let bind_addr = format!("{}:{}", host, port);
        let listener = match TcpListener::bind(&bind_addr) {
            Ok(l) => l,
            Err(e) => {
                log(
                    &format!("PostInterface wake server: failed to bind {}: {}", bind_addr, e),
                    crate::LOG_ERROR, false, false,
                );
                return;
            }
        };

        // Non-blocking so we can check the running flag
        let _ = listener.set_nonblocking(true);

        log(
            &format!("PostInterface wake server listening on {}", bind_addr),
            crate::LOG_NOTICE, false, false,
        );

        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = stream.read(&mut buf) {
                        let request = String::from_utf8_lossy(&buf[..n]);
                        // POST /v1/interfaces/exchange — PHP peer pushing exchange to us
                        // We trigger an immediate poll loop iteration instead of handling inline.
                        if request.starts_with("POST /v1/interfaces/exchange") || request.contains("POST /v1/interfaces/exchange") {
                            let (lock, cvar) = &*wake_signal;
                            let mut woken = lock.lock().unwrap();
                            *woken = true;
                            cvar.notify_one();
                            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"status\":\"ok\",\"mode\":\"wake\"}";
                            let _ = stream.write_all(response.as_bytes());
                        } else if request.starts_with("POST /v1/wake") || request.contains("POST /v1/wake") {
                            // Extract body (after \r\n\r\n)
                            let mut waker_url = String::new();
                            if let Some(body_start) = request.find("\r\n\r\n") {
                                let body = &request[body_start + 4..];
                                // Simple JSON parse for waker_url
                                if let Some(start) = body.find("\"waker_url\"") {
                                    if let Some(colon) = body[start..].find(':') {
                                        let val_start = start + colon + 1;
                                        if let Some(q1) = body[val_start..].find('"') {
                                            if let Some(q2) = body[val_start + q1 + 1..].find('"') {
                                                waker_url = body[val_start + q1 + 1..val_start + q1 + 1 + q2].to_string();
                                            }
                                        }
                                    }
                                }
                            }

                            // Security: only accept wakes from our configured PHP node
                            if !waker_url.is_empty() && waker_url.starts_with(&node_url) {
                                let (lock, cvar) = &*wake_signal;
                                let mut woken = lock.lock().unwrap();
                                *woken = true;
                                cvar.notify_one();

                                let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
                                let _ = stream.write_all(response.as_bytes());

                                log(
                                    &format!("PostInterface wake received from {}", waker_url),
                                    crate::LOG_NOTICE, false, false,
                                );
                            } else {
                                let response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                                let _ = stream.write_all(response.as_bytes());
                            }
                        } else if request.starts_with("GET /health") {
                            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"status\":\"ok\",\"mode\":\"wake\"}";
                            let _ = stream.write_all(response.as_bytes());
                        } else {
                            // 404 for anything else
                            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes());
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection waiting — sleep briefly to avoid busy-wait
                    thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }

        log("PostInterface wake server shutting down", crate::LOG_NOTICE, false, false);
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Drop for PostInterface {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Debug, Clone)]
pub struct ExchangeResult {
    pub sent_count: usize,
    pub recv_count: usize,
    pub has_more: bool,
    pub effective_interval_secs: f64,
    pub batch_id: Option<String>,
}
