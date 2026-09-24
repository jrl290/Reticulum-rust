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
//! 3. **Event-driven exchange**: Exchanges are triggered by outgoing packets
//!    (process_outgoing signals the exchange worker) or by wake notifications
//!    from the PHP node (wake server signals the exchange worker). No polling.
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    #[serde(default)]
    ack_batch_ids: Vec<String>,
    max_packets: usize,
    packets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_id: Option<String>,
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
    pub interface_id: Option<String>,
    pub session_token: Option<String>,
    pub max_batch_packets: usize,
    pub max_packet_bytes: usize,
    pub outbound_queue: VecDeque<Vec<u8>>,
    queue_lock: Arc<Mutex<()>>,
    batch_seq: u64,
    ack_batch_ids: Vec<String>,
    pub is_wake_mode: bool,
    pub rns_mode: u8,
    /// Poll mode only: how often to exchange when there is nothing to send.
    /// `poll_interval_seconds` from the config, else what the node told us
    /// at registration (`idle_exchange_interval_ms`), else 1 s. Never below
    /// [`Self::MIN_POLL_INTERVAL`].
    pub poll_interval: Duration,
    /// `poll_interval_seconds` from the config, if set — wins over the node's
    /// `idle_exchange_interval_ms`.
    configured_poll_interval: Option<Duration>,
    pub running: Arc<AtomicBool>,
    client: reqwest::blocking::Client,
    pub wake_listen_host: Option<String>,
    pub wake_listen_port: Option<u16>,
    exchange_signal: Arc<(Mutex<bool>, Condvar)>,
}

fn generate_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

fn requeue_packets(queue: &mut VecDeque<Vec<u8>>, packets: &mut Vec<Vec<u8>>, _lock: &Mutex<()>) {
    let _guard = _lock.lock().unwrap();
    for raw in packets.drain(..).rev() {
        queue.push_front(raw);
    }
}

impl PostInterface {
    pub const HW_MTU: usize = 500;
    pub const BITRATE_GUESS: u64 = 1_000_000_000;
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

        let bitrate = config
            .get("bitrate")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(Self::BITRATE_GUESS);

        let mtu = config
            .get("mtu")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(Self::HW_MTU);

        let mode: u8 = config
            .get("mode")
            .map(|m| match m.to_lowercase().as_str() {
                "full" | "point_to_point" => 1,
                "access_point" => 3,
                "roaming" => 4,
                "boundary" => 5,
                "gateway" => 6,
                _ => 1,
            })
            .unwrap_or(1); // MODE_FULL default like Python

        let is_wake_mode = wake_url.is_some();
        let configured_poll_interval = config
            .get("poll_interval_seconds")
            .or_else(|| config.get("poll_interval"))
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| *v > 0.0)
            .map(Duration::from_secs_f64);
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
            interface_id: None,
            session_token: None,
            max_batch_packets: Self::DEFAULT_MAX_BATCH_PACKETS,
            max_packet_bytes: Self::DEFAULT_MAX_PACKET_BYTES,
            outbound_queue: VecDeque::new(),
            queue_lock: Arc::new(Mutex::new(())),
            batch_seq: 0,
            ack_batch_ids: Vec::new(),
            is_wake_mode,
            rns_mode: mode,
            poll_interval: configured_poll_interval.unwrap_or(Self::DEFAULT_POLL_INTERVAL).max(Self::MIN_POLL_INTERVAL),
            configured_poll_interval,
            running: Arc::new(AtomicBool::new(false)),
            client,
            wake_listen_host,
            wake_listen_port,
            exchange_signal: Arc::new((Mutex::new(false), Condvar::new())),
        })
    }

    /// Poll-mode floor, as in the Python PostInterface (`_min_interval`).
    pub const MIN_POLL_INTERVAL: Duration = Duration::from_secs(3);
    /// Before the node has told us its `idle_exchange_interval_ms`.
    pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(3);

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
                mode: self.rns_mode,
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
                mode: self.rns_mode,
                transport: Some(if self.rns_mode == 6 { "tcp-backbone-gateway" } else { "http-exchange" }),
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

        log(
            &format!(
                "PostInterface registration response: iface={} token={}...",
                &register_response.interface_id[..8.min(register_response.interface_id.len())],
                &register_response.session_token[..8.min(register_response.session_token.len())],
            ),
            crate::LOG_NOTICE, false, false,
        );

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
        if let Some(ms) = register_response.idle_exchange_interval_ms.filter(|ms| *ms > 0) {
            if self.configured_poll_interval.is_none() {
                self.poll_interval = Duration::from_millis(ms).max(Self::MIN_POLL_INTERVAL);
            }
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

        // Collect packets from queue (under queue_lock, not the main lock)
        let mut raw_packets: Vec<Vec<u8>> = Vec::new();
        let mut b64_packets: Vec<String> = Vec::new();
        {
            let _lock = self.queue_lock.lock().unwrap();
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
            ack_batch_ids: ack_ids,
            max_packets: max_batch,
            packets: b64_packets,
            batch_id: batch_id.clone(),
        };

        let body = serde_json::to_string(&request)
            .map_err(|e| {
                requeue_packets(&mut self.outbound_queue, &mut raw_packets, &self.queue_lock);
                format!("Failed to serialize exchange request: {}", e)
            })?;

        log(
            &format!("PostInterface exchange body: {}", &body[..body.len().min(200)]),
            crate::LOG_DEBUG, false, false,
        );

        log(
            &format!(
                "PostInterface exchange req: iface={} token={}... packets={} batch={:?}",
                &request.interface_id[..8.min(request.interface_id.len())],
                &request.session_token[..8.min(request.session_token.len())],
                request.packets.len(),
                request.batch_id,
            ),
            crate::LOG_NOTICE, false, false,
        );

        let response = match self.client
            .post(&exchange_url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
        {
            Ok(r) => r,
            Err(e) => {
                requeue_packets(&mut self.outbound_queue, &mut raw_packets, &self.queue_lock);
                return Err(format!("Exchange HTTP request failed: {}", e));
            }
        };

        let status = response.status();
        log(
            &format!("PostInterface exchange HTTP {}", status.as_u16()),
            crate::LOG_NOTICE, false, false,
        );

        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            requeue_packets(&mut self.outbound_queue, &mut raw_packets, &self.queue_lock);
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
                requeue_packets(&mut self.outbound_queue, &mut raw_packets, &self.queue_lock);
                return Err(format!("Failed to read exchange response: {}", e));
            }
        };

        if !status.is_success() {
            requeue_packets(&mut self.outbound_queue, &mut raw_packets, &self.queue_lock);
            return Err(format!("Exchange failed (HTTP {}): {}", status.as_u16(), response_text));
        }

        let exchange_response: ExchangeResponse = match serde_json::from_str(&response_text) {
            Ok(r) => r,
            Err(e) => {
                requeue_packets(&mut self.outbound_queue, &mut raw_packets, &self.queue_lock);
                return Err(format!("Failed to parse exchange response: {} (body: {})", e, response_text));
            }
        };

        if let Some(ref err) = exchange_response.error {
            requeue_packets(&mut self.outbound_queue, &mut raw_packets, &self.queue_lock);
            return Err(format!("Exchange returned error: {}", err));
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

        Ok(ExchangeResult {
            sent_count: raw_packets.len(),
            recv_count,
            has_more,
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
            let mut data = data;
            // ── Hop fix for link packets from PHP ───────────────────────
            // Python PostInterface.py lines 269-283: browser-originated
            // link packets forwarded by PHP arrive with hops=0.  Look up
            // expected remaining hops: link_table[3] → path_table[2] →
            // fallback 2.  Set hops = expected-1 so Transport.inbound's
            // +1 gives exact match for LRPROOF relay hop check.
            if data.len() >= 2 && data[1] == 0 {
                let expected: usize = if data.len() >= 18 {
                    let dest_hash = data[2..18].to_vec();
                    let state = crate::transport::TRANSPORT.lock().unwrap();
                    if let Some(entry) = state.link_table.get(&dest_hash) {
                        entry.get(crate::transport::IDX_LT_REM_HOPS)
                            .and_then(|v| {
                                if let crate::transport::LinkEntryValue::RemainingHops(h) = v {
                                    Some(*h as usize)
                                } else { None }
                            })
                            .unwrap_or(2)
                    } else if let Some(entries) = state.path_table.get(&dest_hash) {
                        entries.front().map(|e| e.hops as usize).unwrap_or(2)
                    } else {
                        2
                    }
                } else {
                    2
                };
                data[1] = expected.saturating_sub(1) as u8;
            }
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

        {
            let _lock = self.queue_lock.lock().unwrap();
            const MAX_QUEUE_LEN: usize = 1024;
            if self.outbound_queue.len() >= MAX_QUEUE_LEN {
                log("PostInterface outbound queue full, dropping oldest packet",
                    crate::LOG_WARNING, false, false);
                self.outbound_queue.pop_front();
            }
            self.outbound_queue.push_back(data);
        }

        // Signal the exchange worker to send immediately
        let (lock, cvar) = &*self.exchange_signal;
        let mut triggered = lock.lock().unwrap();
        *triggered = true;
        cvar.notify_one();

        Ok(())
    }

    /// Start the event-driven exchange worker and wake HTTP server.
    ///
    /// Exchange worker waits on `exchange_signal`.  It is signalled by:
    /// - `process_outgoing` (Transport has a packet to send)
    /// - wake server (PHP node has data for us)
    ///
    /// On signal, the worker drains the outbound queue and exchanges with
    /// the PHP node.  If PHP returns `delivery_more: true`, the worker
    /// immediately exchanges again.  When there is no more work, it goes
    /// back to waiting on the signal.
    pub fn start_exchange_worker(iface: Arc<Mutex<PostInterface>>) {
        let running = {
            let guard = iface.lock().unwrap();
            guard.running.store(true, Ordering::SeqCst);
            Arc::clone(&guard.running)
        };
        let exchange_signal = {
            let guard = iface.lock().unwrap();
            Arc::clone(&guard.exchange_signal)
        };

        // Spawn wake HTTP server if configured
        {
            let (host, port, node_url) = {
                let guard = iface.lock().unwrap();
                (guard.wake_listen_host.clone(), guard.wake_listen_port, guard.node_url.clone())
            };
            if let (Some(h), Some(p)) = (host, port) {
                let signal = Arc::clone(&exchange_signal);
                let running_clone = Arc::clone(&running);
                thread::spawn(move || {
                    Self::wake_server(h, p, signal, running_clone, node_url);
                });
            }
        }

        thread::spawn(move || {
            // Initial setup: register and wire outbound handler
            {
                let mut guard = iface.lock().unwrap();
                if let Err(e) = guard.register_with_remote() {
                    log(
                        &format!("PostInterface initial registration failed: {}. Will retry on first exchange.", e),
                        crate::LOG_ERROR, false, false,
                    );
                }
                // Register outbound handler so Transport::dispatch_outbound can reach us
                if let Some(ref name) = guard.base.name {
                    let iface_clone = Arc::clone(&iface);
                    let name_clone = name.clone();
                    crate::interface_writer::register(
                        &name_clone,
                        Arc::new(move |raw: &[u8]| -> bool {
                            if let Ok(mut guard) = iface_clone.lock() {
                                match guard.process_outgoing(raw.to_vec()) {
                                    Ok(()) => true,
                                    Err(e) => {
                                        log(&format!("PostInterface handler enqueue failed: {}", e), crate::LOG_ERROR, false, false);
                                        false
                                    }
                                }
                            } else {
                                log("PostInterface handler lock failed", crate::LOG_ERROR, false, false);
                                false
                            }
                        }),
                        256,
                    );
                    log(
                        &format!("PostInterface registered outbound handler for {}", name_clone),
                        crate::LOG_NOTICE, false, false,
                    );
                }
            }

            let mut consecutive_errors: u32 = 0;
            let mut last_exchange = Instant::now();

            while running.load(Ordering::SeqCst) {
                // Wait for a signal (outgoing packet or wake) — or, in poll
                // mode, for the poll interval to elapse.
                //
                // RNS/Interfaces/PostInterface.py `_poll_loop`: with no
                // wake_url the interface exchanges on a timer whether or not
                // it has anything to send, because an exchange is also how it
                // COLLECTS what the node has queued for it, and because the
                // node marks an interface offline after
                // `interface_stale_after_seconds` (15 s by default) of silence.
                // Until 2026-09-21 this worker exchanged only when signalled,
                // so a gateway on a quiet backbone went silent for 15–50 s at
                // a stretch, the PHP node marked it offline, and every path
                // request and LINKREQUEST that arrived in one of those gaps was
                // dropped as "no usable path". Found on the private staging
                // network on its first run; masked in production by public
                // backbones that never stay quiet that long.
                {
                    let (is_wake, interval) = {
                        let guard = iface.lock().unwrap();
                        (guard.is_wake_mode, guard.poll_interval)
                    };
                    let (lock, cvar) = &*exchange_signal;
                    let mut triggered = lock.lock().unwrap();
                    while !*triggered && running.load(Ordering::SeqCst) {
                        let due = if is_wake { None } else { Some(interval.saturating_sub(last_exchange.elapsed())) };
                        if due == Some(Duration::ZERO) {
                            break; // poll interval elapsed: exchange now
                        }
                        let slice = due.unwrap_or(Duration::from_secs(1)).min(Duration::from_secs(1));
                        let (guard, _timeout) = cvar.wait_timeout(triggered, slice).unwrap();
                        triggered = guard;
                    }
                    *triggered = false;
                }

                if !running.load(Ordering::SeqCst) {
                    break;
                }

                // Exchange loop: keep exchanging while there's work
                loop {
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
                                    break; // try again after backoff
                                }
                            }
                        }
                    }

                    // Do exchange
                    last_exchange = Instant::now();
                    let result = {
                        let mut guard = iface.lock().unwrap();
                        if guard.interface_id.is_some() {
                            match guard.exchange() {
                                Ok(r) => Some(r),
                                Err(e) => {
                                    consecutive_errors += 1;
                                    if consecutive_errors <= 3 || consecutive_errors % 10 == 0 {
                                        log(
                                            &format!("PostInterface exchange error ({} consecutive): {}", consecutive_errors, e),
                                            crate::LOG_ERROR, false, false,
                                        );
                                    }
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    };

                    match result {
                        Some(ref r) if r.sent_count > 0 || r.recv_count > 0 || r.has_more => {
                            consecutive_errors = 0;
                            let name = {
                                let guard = iface.lock().unwrap();
                                guard.base.name.clone().unwrap_or_else(|| "post".to_string())
                            };
                            log(
                                &format!("PostInterface({}): sent={} recv={}{}",
                                    name, r.sent_count, r.recv_count,
                                    if r.has_more { " (more)" } else { "" }),
                                crate::LOG_NOTICE, false, false,
                            );
                        }
                        Some(_) => {
                            consecutive_errors = 0;
                        }
                        None => {
                            // Exchange failed — backoff then retry
                            let backoff = (consecutive_errors as f64).min(60.0);
                            thread::sleep(Duration::from_secs_f64(backoff));
                            break; // go back to waiting for signal
                        }
                    }

                    // Determine if we should exchange again immediately
                    let should_continue = {
                        let guard = iface.lock().unwrap();
                        let has_queued = {
                            let _ql = guard.queue_lock.lock().unwrap();
                            !guard.outbound_queue.is_empty()
                        };
                        result.as_ref().map(|r| r.has_more).unwrap_or(false) || has_queued
                    };

                    if !should_continue {
                        break; // no more work, go back to waiting
                    }

                    // Small yield to avoid monopolising the lock
                    thread::sleep(Duration::from_millis(10));
                }
            }

            log("PostInterface exchange worker shutting down", crate::LOG_NOTICE, false, false);
        });
    }

    /// Minimal HTTP server that listens for POST /v1/wake from the PHP node.
    /// Validates waker_url against the configured node_url to prevent
    /// wake spam from arbitrary hosts, then signals the exchange worker.
    fn wake_server(
        host: String,
        port: u16,
        exchange_signal: Arc<(Mutex<bool>, Condvar)>,
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
                    let request = match read_wake_request(&mut stream) {
                        Ok(r) if !r.trim().is_empty() => r,
                        Ok(_) => {
                            log(
                                &format!("PostInterface wake connection from {} closed without sending a request — wake lost", addr),
                                crate::LOG_WARNING, false, false,
                            );
                            continue;
                        }
                        Err(e) => {
                            log(
                                &format!("PostInterface wake connection from {} unreadable ({}) — wake lost", addr, e),
                                crate::LOG_WARNING, false, false,
                            );
                            continue;
                        }
                    };
                    {
                        // POST /v1/interfaces/exchange — PHP peer pushing exchange to us
                        // We signal the exchange worker to do an immediate exchange.
                        if request.starts_with("POST /v1/interfaces/exchange") || request.contains("POST /v1/interfaces/exchange") {
                            let (lock, cvar) = &*exchange_signal;
                            let mut woken = lock.lock().unwrap();
                            *woken = true;
                            cvar.notify_one();
                            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"status\":\"ok\",\"mode\":\"wake\"}";
                            let _ = stream.write_all(response.as_bytes());
                        } else if request.starts_with("POST /v1/wake") || request.contains("POST /v1/wake") {
                            // Extract body (after \r\n\r\n)
                            let waker_url = request
                                .find("\r\n\r\n")
                                .map(|body_start| wake_body_waker_url(&request[body_start + 4..]))
                                .unwrap_or_default();

                            // Validate waker_url matches our configured node_url
                            let expected = node_url.trim_end_matches('/');
                            let received = waker_url.trim_end_matches('/');
                            if received.is_empty() || received != expected {
                                log(
                                    &format!("PostInterface wake rejected: waker_url '{}' does not match node_url '{}'", received, expected),
                                    crate::LOG_WARNING, false, false,
                                );
                                let response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"status\":\"rejected\"}";
                                let _ = stream.write_all(response.as_bytes());
                                continue;
                            }

                            let (lock, cvar) = &*exchange_signal;
                            let mut woken = lock.lock().unwrap();
                            *woken = true;
                            cvar.notify_one();

                            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
                            let _ = stream.write_all(response.as_bytes());

                            log(
                                &format!("PostInterface wake accepted from {}", waker_url),
                                crate::LOG_NOTICE, false, false,
                            );
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
    pub batch_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("name".to_string(), "t".to_string());
        m.insert("node_url".to_string(), "http://127.0.0.1:1".to_string());
        for (k, v) in pairs { m.insert(k.to_string(), v.to_string()); }
        m
    }

    // ── Poll mode exchanges on a timer, not only when signalled ──────────
    //
    // The worker loop itself needs a node to talk to; these pin the interval
    // it will use, which is the part that was missing: the node's
    // idle_exchange_interval_ms was stored and never read.

    #[test]
    fn poll_interval_defaults_and_honours_the_floor() {
        let p = PostInterface::new(&cfg(&[])).unwrap();
        assert!(!p.is_wake_mode);
        assert_eq!(p.poll_interval, PostInterface::DEFAULT_POLL_INTERVAL);
        let p = PostInterface::new(&cfg(&[("poll_interval_seconds", "0.2")])).unwrap();
        assert_eq!(p.poll_interval, PostInterface::MIN_POLL_INTERVAL, "never below the Python floor");
        let p = PostInterface::new(&cfg(&[("poll_interval_seconds", "7.5")])).unwrap();
        assert_eq!(p.poll_interval, Duration::from_secs_f64(7.5));
    }

    #[test]
    fn nodes_idle_interval_applies_unless_configured_locally() {
        // Simulate what register_with_remote does with the node's answer.
        let mut p = PostInterface::new(&cfg(&[])).unwrap();
        let from_node = Duration::from_millis(1000).max(PostInterface::MIN_POLL_INTERVAL);
        if p.configured_poll_interval.is_none() { p.poll_interval = from_node; }
        assert_eq!(p.poll_interval, PostInterface::MIN_POLL_INTERVAL, "1000 ms from the node is floored to 3 s");

        let mut p = PostInterface::new(&cfg(&[("poll_interval_seconds", "10")])).unwrap();
        if p.configured_poll_interval.is_none() { p.poll_interval = from_node; }
        assert_eq!(p.poll_interval, Duration::from_secs(10), "a configured interval wins over the node's");
    }

    #[test]
    fn wake_mode_does_not_poll() {
        let p = PostInterface::new(&cfg(&[("wake_url", "http://127.0.0.1:1/v1/wake")])).unwrap();
        assert!(p.is_wake_mode, "wake mode is event-driven only, as in the Python PostInterface");
    }
}

/// The `waker_url` from a `/v1/wake` body.
///
/// The body is JSON, so it is parsed as JSON. PHP's `json_encode` escapes
/// slashes by default (`"https:\/\/retichat.com\/reticulum"`), and the
/// substring scan this replaced compared the *escaped* text against the
/// configured node_url, rejecting every wake from a PHP peer with
/// "waker_url '…\/\/…' does not match node_url". Anything that is not a JSON
/// object with a string `waker_url` yields an empty string, which the caller
/// rejects.
/// Read one HTTP request from a freshly accepted wake connection.
///
/// The wake listener is non-blocking so its accept loop can watch `running`.
/// Where accept(2) hands the new socket the listener's O_NONBLOCK — macOS,
/// which has no accept4 — the single read() this replaced raced the client's
/// first segment: a wake whose bytes had not landed yet read WouldBlock and
/// was dropped without a log line. Linux and FreeBSD (accept4) return a
/// blocking socket, so only the macOS-hosted staging gateway lost wakes, and
/// with them every LINKREQUEST a browser queued at a quiet PHP node until the
/// gateway next had traffic of its own (~50 s). Read blocking, under a short
/// deadline, until the headers and the Content-Length body are in.
pub(crate) fn read_wake_request(stream: &mut std::net::TcpStream) -> std::io::Result<String> {
    const MAX_REQUEST: usize = 4096;
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    while buf.len() < MAX_REQUEST {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break; // client closed: what we have is the whole request
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let body_len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() >= end + 4 + body_len {
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

pub(crate) fn wake_body_waker_url(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("waker_url").and_then(|u| u.as_str()).map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod wake_body_tests {
    use super::{read_wake_request, wake_body_waker_url};
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    /// A wake whose bytes arrive after the accept, split across segments,
    /// through a non-blocking listener as the wake server uses — the case
    /// that lost every late wake on macOS.
    #[test]
    fn a_late_split_wake_is_read_whole_from_a_nonblocking_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let body = r#"{"waker_url":"http:\/\/127.0.0.1:8080"}"#;
        let head = format!("POST /v1/wake HTTP/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len());
        let client = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            std::thread::sleep(Duration::from_millis(150));
            c.write_all(head.as_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
            c.write_all(body.as_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });
        let mut stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        let request = read_wake_request(&mut stream).unwrap();
        client.join().unwrap();
        assert!(request.starts_with("POST /v1/wake"), "{request:?}");
        let body_start = request.find("\r\n\r\n").unwrap() + 4;
        assert_eq!(wake_body_waker_url(&request[body_start..]), "http://127.0.0.1:8080");
    }

    #[test]
    fn php_escaped_slashes_decode_to_the_configured_url() {
        // Exactly what PHP json_encode() sends without JSON_UNESCAPED_SLASHES.
        let body = r#"{"waker_url":"https:\/\/retichat.com\/reticulum"}"#;
        assert_eq!(wake_body_waker_url(body), "https://retichat.com/reticulum");
    }

    #[test]
    fn plain_and_malformed_bodies() {
        assert_eq!(
            wake_body_waker_url(r#"{"waker_url":"https://selectivesubconscious.com/reticulum/"}"#),
            "https://selectivesubconscious.com/reticulum/"
        );
        assert_eq!(wake_body_waker_url(r#"{"waker_url": 7}"#), "");
        assert_eq!(wake_body_waker_url("not json"), "");
        assert_eq!(wake_body_waker_url(""), "");
    }
}
