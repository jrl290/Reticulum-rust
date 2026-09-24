use crate::destination::{Destination, DestinationType};
use crate::identity::Identity;
use crate::identity::{full_hash, truncated_hash, HASHLENGTH, SIGLENGTH};
use crate::reticulum;
use crate::transport::Transport;
use crate::{log, LOG_ERROR};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MDU: usize = reticulum::MDU;

pub const ENCRYPTED_MDU: usize = ((reticulum::MDU - crate::identity::TOKEN_OVERHEAD - crate::identity::KEYSIZE / 16)
    / crate::identity::AES128_BLOCKSIZE)
    * crate::identity::AES128_BLOCKSIZE
    - 1;

pub const PLAIN_MDU: usize = MDU;

pub const DATA: u8 = 0x00;
pub const ANNOUNCE: u8 = 0x01;
pub const LINKREQUEST: u8 = 0x02;
pub const PROOF: u8 = 0x03;

pub const HEADER_1: u8 = 0x00;
pub const HEADER_2: u8 = 0x01;

pub const NONE: u8 = 0x00;
pub const RESOURCE: u8 = 0x01;
pub const RESOURCE_ADV: u8 = 0x02;
pub const RESOURCE_REQ: u8 = 0x03;
pub const RESOURCE_HMU: u8 = 0x04;
pub const RESOURCE_PRF: u8 = 0x05;
pub const RESOURCE_ICL: u8 = 0x06;
pub const RESOURCE_RCL: u8 = 0x07;
pub const CACHE_REQUEST: u8 = 0x08;
pub const REQUEST: u8 = 0x09;
pub const RESPONSE: u8 = 0x0A;
pub const PATH_RESPONSE: u8 = 0x0B;
pub const COMMAND: u8 = 0x0C;
pub const COMMAND_STATUS: u8 = 0x0D;
pub const CHANNEL: u8 = 0x0E;
pub const KEEPALIVE: u8 = 0xFA;
pub const LINKIDENTIFY: u8 = 0xFB;
pub const LINKCLOSE: u8 = 0xFC;
pub const LINKPROOF: u8 = 0xFD;
pub const LRRTT: u8 = 0xFE;
pub const LRPROOF: u8 = 0xFF;

pub const FLAG_SET: u8 = 0x01;
pub const FLAG_UNSET: u8 = 0x00;

pub const TIMEOUT_PER_HOP: f64 = reticulum::DEFAULT_PER_HOP_TIMEOUT;

#[derive(Clone, Debug)]
pub struct Packet {
    pub hops: u8,
    pub header_type: u8,
    pub packet_type: u8,
    pub transport_type: u8,
    pub context: u8,
    pub context_flag: u8,
    pub destination: Option<Destination>,
    pub transport_id: Option<Vec<u8>>,
    pub data: Vec<u8>,
    pub flags: u8,
    pub raw: Vec<u8>,
    pub packed: bool,
    pub sent: bool,
    pub create_receipt: bool,
    pub receipt: Option<PacketReceipt>,
    pub from_packed: bool,
    pub mtu: usize,
    pub sent_at: Option<f64>,
    pub packet_hash: Option<Vec<u8>>,
    pub ratchet_id: Option<Vec<u8>>,
    pub attached_interface: Option<String>,
    pub receiving_interface: Option<String>,
    pub rssi: Option<f64>,
    pub snr: Option<f64>,
    pub q: Option<f64>,
    pub ciphertext: Option<Vec<u8>>,
    pub plaintext: Option<Vec<u8>>,
    pub destination_hash: Option<Vec<u8>>,
    pub destination_type: Option<DestinationType>,
    pub map_hash: Option<Vec<u8>>,
}

impl Packet {
    pub fn new(
        destination: Option<Destination>,
        data: Vec<u8>,
        packet_type: u8,
        context: u8,
        transport_type: u8,
        header_type: u8,
        transport_id: Option<Vec<u8>>,
        attached_interface: Option<String>,
        create_receipt: bool,
        context_flag: u8,
    ) -> Self {
        if destination.is_some() {
            let dest = destination.as_ref().unwrap();
            let mut packet = Packet {
                hops: 0,
                header_type,
                packet_type,
                transport_type,
                context,
                context_flag,
                destination: destination.clone(),
                transport_id,
                data,
                flags: 0,
                raw: Vec::new(),
                packed: false,
                sent: false,
                create_receipt,
                receipt: None,
                from_packed: false,
                mtu: if dest.dest_type == DestinationType::Link {
                    dest.link.as_ref().and_then(|l| l.mtu).unwrap_or(reticulum::MTU)
                } else {
                    reticulum::MTU
                },
                sent_at: None,
                packet_hash: None,
                ratchet_id: None,
                attached_interface,
                receiving_interface: None,
                rssi: None,
                snr: None,
                q: None,
                ciphertext: None,
                plaintext: None,
                destination_hash: None,
                destination_type: Some(dest.dest_type),
                map_hash: None,
            };
            packet.flags = packet.get_packed_flags();
            packet
        } else {
            Packet {
                hops: 0,
                header_type,
                packet_type,
                transport_type,
                context,
                context_flag,
                destination: None,
                transport_id,
                data: data.clone(),
                flags: 0,
                raw: data,
                packed: true,
                sent: false,
                create_receipt: false,
                receipt: None,
                from_packed: true,
                mtu: reticulum::MTU,
                sent_at: None,
                packet_hash: None,
                ratchet_id: None,
                attached_interface,
                receiving_interface: None,
                rssi: None,
                snr: None,
                q: None,
                ciphertext: None,
                plaintext: None,
                destination_hash: None,
                destination_type: None,
                map_hash: None,
            }
        }
    }

    pub fn get_packed_flags(&self) -> u8 {
        if self.context == LRPROOF {
            (self.header_type << 6)
                | (self.context_flag << 5)
                | (self.transport_type << 4)
                | ((DestinationType::Link as u8) << 2)
                | self.packet_type
        } else {
            let dest_type = self.destination.as_ref().map(|d| d.dest_type).unwrap_or(DestinationType::Plain);
            (self.header_type << 6)
                | (self.context_flag << 5)
                | (self.transport_type << 4)
                | ((dest_type as u8) << 2)
                | self.packet_type
        }
    }

    pub fn pack(&mut self) -> Result<(), String> {
        let mut destination = self.destination.clone().ok_or("Packet has no destination")?;
        self.destination_hash = Some(destination.hash.clone());

        let mut header = Vec::new();
        header.push(self.flags);
        header.push(self.hops);

        if self.context == LRPROOF {
            header.extend_from_slice(&destination.hash);
            self.ciphertext = Some(self.data.clone());
        } else if self.header_type == HEADER_1 {
            header.extend_from_slice(&destination.hash);

            let ciphertext: Result<Vec<u8>, String> = if self.packet_type == ANNOUNCE
                || self.packet_type == LINKREQUEST
                || self.packet_type == PROOF
                || self.context == RESOURCE
                || self.context == KEEPALIVE
                || self.context == LINKIDENTIFY
                || self.context == CACHE_REQUEST
            {
                Ok(self.data.clone())
            } else {
                let encrypted = destination.encrypt(&self.data)?;
                if destination.latest_ratchet_id.is_some() {
                    self.ratchet_id = destination.latest_ratchet_id.clone();
                }
                Ok(encrypted)
            };
            let ciphertext = ciphertext?;
            self.ciphertext = Some(ciphertext);
        } else if self.header_type == HEADER_2 {
            let transport_id = self.transport_id.clone().ok_or("Packet with header type 2 must have a transport ID")?;
            header.extend_from_slice(&transport_id);
            header.extend_from_slice(&destination.hash);
            if self.packet_type == ANNOUNCE {
                self.ciphertext = Some(self.data.clone());
            } else {
                self.ciphertext = Some(self.data.clone());
            }
        }

        header.push(self.context);
        let mut raw = header;
        if let Some(ciphertext) = &self.ciphertext {
            raw.extend_from_slice(ciphertext);
        }

        if raw.len() > self.mtu {
            return Err(format!("Packet size of {} exceeds MTU of {} bytes", raw.len(), self.mtu));
        }

        self.raw = raw;
        self.packed = true;
        self.update_hash();
        Ok(())
    }

    pub fn unpack(&mut self) -> bool {
        if self.raw.len() < 2 {
            return Self::malformed("Truncated header");
        }
        self.flags = self.raw[0];
        self.hops = self.raw[1];

        // RNS/Packet.py:249-250 — a hop count at or beyond the pathfinder
        // maximum is not a packet we can ever process, so it is dropped
        // here rather than carried into Transport.
        if self.hops >= crate::transport::PATHFINDER_M {
            return Self::malformed(&format!("Invalid hop count {}", self.hops));
        }

        self.header_type = (self.flags & 0b0100_0000) >> 6;
        self.context_flag = (self.flags & 0b0010_0000) >> 5;
        self.transport_type = (self.flags & 0b0001_0000) >> 4;
        let dest_type = (self.flags & 0b0000_1100) >> 2;
        self.packet_type = self.flags & 0b0000_0011;
        self.destination_type = match dest_type {
            0x00 => Some(DestinationType::Single),
            0x01 => Some(DestinationType::Group),
            0x02 => Some(DestinationType::Plain),
            0x03 => Some(DestinationType::Link),
            _ => None,
        };

        let dst_len = reticulum::TRUNCATED_HASHLENGTH / 8;
        if self.header_type == HEADER_2 {
            // RNS/Packet.py:267-268 — "Malformed Transport ID field" /
            // "Malformed destination hash field".
            if self.raw.len() < 2 + dst_len * 2 + 1 {
                return Self::malformed("Malformed destination hash field");
            }
            self.transport_id = Some(self.raw[2..2 + dst_len].to_vec());
            self.destination_hash = Some(self.raw[2 + dst_len..2 + dst_len * 2].to_vec());
            self.context = self.raw[2 + dst_len * 2];
            self.data = self.raw[2 + dst_len * 2 + 1..].to_vec();
        } else {
            // RNS/Packet.py:274 — "Malformed destination hash field".
            if self.raw.len() < 2 + dst_len + 1 {
                return Self::malformed("Malformed destination hash field");
            }
            self.transport_id = None;
            self.destination_hash = Some(self.raw[2..2 + dst_len].to_vec());
            self.context = self.raw[2 + dst_len];
            self.data = self.raw[2 + dst_len + 1..].to_vec();
        }

        // RNS/Packet.py:276 — "Zero-length data field".
        if self.data.is_empty() {
            return Self::malformed("Zero-length data field");
        }

        self.packed = false;
        self.update_hash();
        true
    }

    /// RNS/Packet.py:281-283 — one place where every `unpack` rejection is
    /// logged and turned into a drop, so the log line reads the same as the
    /// reference does.
    fn malformed(reason: &str) -> bool {
        log(
            &format!("Received malformed packet, dropping it. The contained exception was: {}", reason),
            crate::LOG_DEBUG,
            false,
            false,
        );
        false
    }

    /// Hand the packet to the transport. `Ok(Some(receipt))` when a receipt was
    /// requested and the packet went out; `Ok(None)` when it went out without
    /// one — OR when no interface could take it. Read `self.sent` to tell the
    /// two apart (RNS/Packet.py send() returns False for the latter; rfed's
    /// fan-out misread the former as a failure until 2026-09-24).
    pub fn send(&mut self) -> Result<Option<PacketReceipt>, String> {
        if self.sent {
            return Err("Packet was already sent".to_string());
        }

        if self.destination.is_none() {
            return Err("Packet has no destination".to_string());
        }

        // RNS/Packet.py:293 — `if self.hops >= RNS.Transport.PATHFINDER_M: return False`.
        // Refuse to put a packet on the wire that no receiver would accept.
        if self.hops >= crate::transport::PATHFINDER_M {
            log(
                &format!("Refusing to send packet with hop count {} at or beyond PATHFINDER_M", self.hops),
                crate::LOG_DEBUG,
                false,
                false,
            );
            return Ok(None);
        }

        if !self.packed {
            self.pack()?;
        }

        if Transport::outbound(self) {
            self.sent = true;
            self.sent_at = Some(now_seconds());
            Ok(self.receipt.clone())
        } else {
            self.sent = false;
            self.receipt = None;
            log("No interfaces could process the outbound packet", LOG_ERROR, false, false);
            Ok(None)
        }
    }

    pub fn resend(&mut self) -> Result<Option<PacketReceipt>, String> {
        if !self.sent {
            return Err("Packet was not sent yet".to_string());
        }

        self.pack()?;
        if Transport::outbound(self) {
            Ok(self.receipt.clone())
        } else {
            self.sent = false;
            self.receipt = None;
            log("No interfaces could process the outbound packet", LOG_ERROR, false, false);
            Ok(None)
        }
    }

    pub fn update_hash(&mut self) {
        self.packet_hash = Some(self.get_hash());
    }

    pub fn get_hash(&self) -> Vec<u8> {
        full_hash(&self.get_hashable_part())
    }

    pub fn get_truncated_hash(&self) -> Vec<u8> {
        truncated_hash(&self.get_hashable_part())
    }

    pub fn get_hashable_part(&self) -> Vec<u8> {
        if self.raw.is_empty() {
            return Vec::new();
        }
        let mut hashable = vec![self.raw[0] & 0b0000_1111];
        let dst_len = reticulum::TRUNCATED_HASHLENGTH / 8;
        if self.header_type == HEADER_2 {
            if self.raw.len() > dst_len + 2 {
                hashable.extend_from_slice(&self.raw[dst_len + 2..]);
            }
        } else if self.raw.len() > 2 {
            hashable.extend_from_slice(&self.raw[2..]);
        }
        hashable
    }

    pub fn should_generate_receipt(&self) -> bool {
        if !self.create_receipt {
            return false;
        }
        if self.packet_type != DATA {
            return false;
        }
        let dest_type = self.destination.as_ref().map(|d| d.dest_type).unwrap_or(DestinationType::Plain);
        if dest_type == DestinationType::Plain {
            return false;
        }
        // LRPROOF is u8::MAX, so <= LRPROOF is always true; only the lower bound matters.
        if self.context >= KEEPALIVE {
            return false;
        }
        if self.context >= RESOURCE && self.context <= RESOURCE_RCL {
            return false;
        }
        true
    }

    /// Get the physical layer Received Signal Strength Indication if available
    pub fn get_rssi(&self) -> Option<f64> {
        self.rssi
        // In a full implementation, would also query reticulum.get_packet_rssi(packet_hash)
    }

    /// Get the physical layer Signal-to-Noise Ratio if available
    pub fn get_snr(&self) -> Option<f64> {
        self.snr
        // In a full implementation, would also query reticulum.get_packet_snr(packet_hash)
    }

    /// Get the physical layer Link Quality if available
    pub fn get_q(&self) -> Option<f64> {
        self.q
        // In a full implementation, would also query reticulum.get_packet_q(packet_hash)
    }

    /// Generate a proof for this packet.
    /// `proving_destination` is the local destination that received this packet
    /// and has the identity private key needed to sign.
    pub fn prove(&self, proving_destination: Option<&Destination>) -> Result<(), String> {
        if !self.from_packed {
            return Err("Can only prove packets constructed from raw data".to_string());
        }

        let packet_hash = self.packet_hash.as_ref()
            .ok_or("Packet has no hash for proving")?;

        // Get identity from the proving destination (preferred) or from self.destination
        let identity = if let Some(dest) = proving_destination {
            dest.identity.as_ref()
        } else if let Some(dest) = self.destination.as_ref() {
            dest.identity.as_ref()
        } else {
            None
        }.ok_or("No identity available for proving packet")?;

        // Sign the packet hash
        let signature = identity.sign(packet_hash);

        // Build proof data
        let proof_data = if crate::reticulum::should_use_implicit_proof() {
            signature
        } else {
            let mut data = packet_hash.clone();
            data.extend_from_slice(&signature);
            data
        };

        // ProofDestination: hash = truncated hash of this packet, dest_type = Single
        let proof_dest_hash = self.get_truncated_hash();
        let proof_destination = Destination {
            hash: proof_dest_hash,
            dest_type: DestinationType::Single,
            ..Default::default()
        };

        let proof_len = proof_data.len();

        // Create and send PROOF packet on same interface the original arrived on
        let mut proof_packet = Packet::new(
            Some(proof_destination),
            proof_data,
            PROOF,
            NONE,
            crate::transport::BROADCAST,
            HEADER_1,
            None,
            self.receiving_interface.clone(),
            false,
            FLAG_UNSET,
        );

        crate::log(&format!(
            "prove_packet hash={} interface={:?} proof_len={}",
            crate::hexrep(packet_hash, false),
            self.receiving_interface,
            proof_len,
        ), crate::LOG_NOTICE, false, false);

        match proof_packet.send() {
            Ok(_) => {
                Ok(())
            }
            Err(e) => {
                Err(format!("Failed to send proof: {}", e))
            }
        }
    }

    /// Generate a special proof destination for directing proofs back to sender
    pub fn generate_proof_destination(&self) -> ProofDestination {
        ProofDestination {
            hash: self.get_hash()[..reticulum::TRUNCATED_HASHLENGTH / 8].to_vec(),
            dest_type: DestinationType::Single,
        }
    }

    /// Validate a proof packet (wrapper that delegates to receipt)
    pub fn validate_proof_packet(&mut self, proof_packet: &Packet) -> bool {
        if let Some(receipt) = &mut self.receipt {
            receipt.validate_proof_packet(proof_packet)
        } else {
            false
        }
    }

    /// Validate a proof (wrapper that delegates to receipt)
    pub fn validate_proof(&mut self, proof: &[u8]) -> bool {
        if let Some(receipt) = &mut self.receipt {
            receipt.validate_proof(proof)
        } else {
            false
        }
    }
}

/// Special destination for directing packet proofs back to sender
#[derive(Clone, Debug)]
pub struct ProofDestination {
    pub hash: Vec<u8>,
    pub dest_type: DestinationType,
}

impl ProofDestination {
    /// Returns plaintext unchanged (proofs are not encrypted)
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }
}

type ReceiptCallback = Arc<dyn Fn(&PacketReceipt) + Send + Sync>;

/// The mutable half of a receipt.
///
/// RNS/Packet.py `send` returns `self.receipt` — the very same object that
/// `Transport.receipts` holds. Python gets that for free; here the receipt
/// was a plain struct, so `Packet::send` handed the caller a by-value copy
/// and `Transport` tracked a different one. A `set_delivery_callback` on the
/// returned copy was set on an object nothing ever proved, and a
/// `get_status()` on it read a status nothing ever advanced. Everything that
/// mutates now lives behind one `Arc<Mutex<_>>`, so `Clone` shares it and
/// the caller's receipt IS the tracked receipt.
struct PacketReceiptInner {
    sent: bool,
    sent_at: f64,
    proved: bool,
    status: u8,
    concluded_at: Option<f64>,
    timeout: f64,
    delivery_callback: Option<ReceiptCallback>,
    timeout_callback: Option<ReceiptCallback>,
    /// A callback has been run for this receipt's conclusion. A callback
    /// registered after the receipt concluded runs once, at registration —
    /// see `set_delivery_callback`.
    delivery_notified: bool,
    timeout_notified: bool,
}

#[derive(Clone)]
pub struct PacketReceipt {
    pub hash: Vec<u8>,
    pub truncated_hash: Vec<u8>,
    pub destination: Destination,
    inner: Arc<std::sync::Mutex<PacketReceiptInner>>,
}

impl std::fmt::Debug for PacketReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f.debug_struct("PacketReceipt")
            .field("hash", &self.hash)
            .field("truncated_hash", &self.truncated_hash)
            .field("sent", &inner.sent)
            .field("sent_at", &inner.sent_at)
            .field("proved", &inner.proved)
            .field("status", &inner.status)
            .field("destination", &self.destination)
            .field("concluded_at", &inner.concluded_at)
            .field("timeout", &inner.timeout)
            .field("delivery_callback", &inner.delivery_callback.is_some())
            .field("timeout_callback", &inner.timeout_callback.is_some())
            .finish()
    }
}

impl PacketReceipt {
    pub const FAILED: u8 = 0x00;
    pub const SENT: u8 = 0x01;
    pub const DELIVERED: u8 = 0x02;
    pub const CULLED: u8 = 0xFF;

    pub const EXPL_LENGTH: usize = HASHLENGTH / 8 + SIGLENGTH / 8;
    pub const IMPL_LENGTH: usize = SIGLENGTH / 8;

    /// The receipt timeout of a packet sent over a link.
    ///
    /// RNS/Packet.py:428 (1.5.2): `max(rtt * traffic_timeout_factor,
    /// RNS.Link.TRAFFIC_TIMEOUT_MIN_MS/1000)`. Both copies of this formula
    /// (here and `Transport::outbound`) had the `max` on the factor instead
    /// of the product — `rtt * max(factor, 0.005)` — so a link with no RTT
    /// yet, or a sub-millisecond one, gave its packets a receipt that timed
    /// out on the next jobs pass, before any proof could arrive.
    pub fn link_timeout(link: Option<&crate::destination::LinkInfo>) -> f64 {
        let rtt = link.and_then(|l| l.rtt).unwrap_or(0.0);
        let factor = link
            .map(|l| l.traffic_timeout_factor)
            .unwrap_or(crate::link::TRAFFIC_TIMEOUT_FACTOR);
        (rtt * factor).max(crate::link::TRAFFIC_TIMEOUT_MIN_MS / 1000.0)
    }

    pub fn new(packet: &Packet) -> Self {
        let _hash = packet.get_hash();
        let _truncated = packet.get_truncated_hash();
        let destination = packet.destination.clone().unwrap_or_default();
        let timeout = if destination.dest_type == DestinationType::Link {
            Self::link_timeout(destination.link.as_ref())
        } else {
            reticulum::DEFAULT_PER_HOP_TIMEOUT
                + TIMEOUT_PER_HOP * Transport::hops_to(packet.destination_hash.as_ref().unwrap_or(&vec![])) as f64
        };
        Self::new_with_timeout(packet, timeout)
    }

    pub fn new_with_timeout(packet: &Packet, timeout: f64) -> Self {
        let hash = packet.get_hash();
        let truncated = packet.get_truncated_hash();
        let destination = packet.destination.clone().unwrap_or_default();
        PacketReceipt::from_parts(hash, truncated, destination, timeout)
    }

    /// Build a receipt for a packet hash that is already known, without a
    /// `Packet` to derive it from. The state starts exactly where
    /// `new_with_timeout` leaves it: sent, unproved, SENT.
    pub fn from_parts(
        hash: Vec<u8>,
        truncated_hash: Vec<u8>,
        destination: Destination,
        timeout: f64,
    ) -> Self {
        PacketReceipt {
            hash,
            truncated_hash,
            destination,
            inner: Arc::new(std::sync::Mutex::new(PacketReceiptInner {
                sent: true,
                sent_at: now_seconds(),
                proved: false,
                status: PacketReceipt::SENT,
                concluded_at: None,
                timeout,
                delivery_callback: None,
                timeout_callback: None,
                delivery_notified: false,
                timeout_notified: false,
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PacketReceiptInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// True when this receipt and `other` share the same tracked state —
    /// i.e. one is a clone of the other rather than a look-alike copy.
    pub fn shares_state_with(&self, other: &PacketReceipt) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    // ── Accessors for the state that moved behind the shared inner ──────
    pub fn sent(&self) -> bool { self.lock().sent }
    pub fn sent_at(&self) -> f64 { self.lock().sent_at }
    pub fn proved(&self) -> bool { self.lock().proved }
    pub fn status(&self) -> u8 { self.lock().status }
    pub fn concluded_at(&self) -> Option<f64> { self.lock().concluded_at }
    pub fn timeout(&self) -> f64 { self.lock().timeout }
    pub fn has_delivery_callback(&self) -> bool { self.lock().delivery_callback.is_some() }
    pub fn has_timeout_callback(&self) -> bool { self.lock().timeout_callback.is_some() }

    pub fn set_sent(&self, sent: bool) { self.lock().sent = sent; }
    pub fn set_sent_at(&self, sent_at: f64) { self.lock().sent_at = sent_at; }
    pub fn set_proved(&self, proved: bool) { self.lock().proved = proved; }
    pub fn set_status(&self, status: u8) { self.lock().status = status; }
    pub fn set_concluded_at(&self, concluded_at: Option<f64>) { self.lock().concluded_at = concluded_at; }

    /// Mark the receipt delivered and run the delivery callback. Returns
    /// whether this call delivered it.
    ///
    /// Only a SENT receipt can become DELIVERED. RNS/Transport.py:2758
    /// (1.5.2) skips every receipt whose status is not SENT, and a concluded
    /// receipt has left `Transport.receipts` by the next jobs pass. The check
    /// sits here, under the lock `check_timeout` concludes under, so a proof
    /// that arrives after the timeout fired (or races it on another thread)
    /// can never also deliver the receipt: one outcome, one callback.
    ///
    /// The inner lock is released before the callback runs: the callback is
    /// handed `&PacketReceipt` and will typically call `get_status()` on it,
    /// which would deadlock against a still-held guard.
    fn mark_delivered(&self) -> bool {
        let callback = {
            let mut inner = self.lock();
            if inner.status != PacketReceipt::SENT {
                return false;
            }
            inner.status = PacketReceipt::DELIVERED;
            inner.proved = true;
            inner.concluded_at = Some(now_seconds());
            inner.delivery_notified = inner.delivery_callback.is_some();
            inner.delivery_callback.clone()
        };
        self.fire_delivery_callback(callback);
        true
    }

    pub fn validate_proof(&mut self, proof: &[u8]) -> bool {
        if proof.len() == Self::EXPL_LENGTH {
            let hash_len = HASHLENGTH / 8;
            let proof_hash = &proof[..hash_len];
            let signature = &proof[hash_len..hash_len + SIGLENGTH / 8];
            if proof_hash == self.hash.as_slice() {
                if let Some(identity) = &self.destination.identity {
                    let valid = Self::validate_with_identity_variants(identity, signature, &self.hash);
                    if valid {
                        return self.mark_delivered();
                    }
                }
            }
            false
        } else if proof.len() == Self::IMPL_LENGTH {
            if let Some(identity) = &self.destination.identity {
                let valid = Self::validate_with_identity_variants(identity, proof, &self.hash);
                if valid {
                    return self.mark_delivered();
                }
            }
            false
        } else {
            false
        }
    }

    fn validate_with_identity_variants(identity: &Identity, signature: &[u8], hash: &[u8]) -> bool {
        if identity.validate(signature, hash) {
            return true;
        }

        if let Ok(public_key) = identity.get_public_key() {
            if public_key.len() == 64 {
                let mut swapped = public_key.clone();
                swapped[..32].copy_from_slice(&public_key[32..64]);
                swapped[32..64].copy_from_slice(&public_key[..32]);

                if let Ok(swapped_identity) = Identity::from_public_key(&swapped) {
                    return swapped_identity.validate(signature, hash);
                }
            }
        }

        false
    }

    /// Validate a proof packet (Python: validate_proof_packet)
    /// Dispatches to validate_link_proof or validate_proof depending on packet type
    pub fn validate_proof_packet(&mut self, proof_packet: &Packet) -> bool {
        // In full implementation: check if proof_packet.link exists
        // For now, just validate as normal proof
        // if proof_packet has link: validate_link_proof(proof_packet.data, link)
        // else: validate_proof(proof_packet.data)
        self.validate_proof(&proof_packet.data)
    }

    /// Validate a proof over a link (Python: validate_link_proof)
    pub fn validate_link_proof(&mut self, proof: &[u8], link: &crate::link::Link) -> bool {
        self.validate_link_proof_with(proof, |signature, hash| {
            link.validate(signature, hash).unwrap_or(false)
        })
    }

    /// RNS/Packet.py validate_link_proof, with `link.validate(signature,
    /// self.hash)` supplied by the caller. Transport validates a link PROOF
    /// from its inbound thread, where the link's peer key is only reachable
    /// as a round trip to the link's actor; everything else — the hash
    /// match, concluding the receipt, the delivery callback — happens on the
    /// caller's thread, as it does in the reference (Transport.inbound runs
    /// the callback). `validate` is only called once the hash matches.
    pub fn validate_link_proof_with<F>(&mut self, proof: &[u8], validate: F) -> bool
    where
        F: FnOnce(&[u8], &[u8]) -> bool,
    {
        // Hardcoded as explicit proofs for now (matches Python TODO comment)
        if proof.len() == Self::EXPL_LENGTH {
            let hash_len = HASHLENGTH / 8;
            let proof_hash = &proof[..hash_len];
            let signature = &proof[hash_len..hash_len + SIGLENGTH / 8];
            if proof_hash == self.hash.as_slice() && validate(signature, &self.hash) {
                // link.last_proof = self.concluded_at
                return self.mark_delivered();
            }
            false
        } else if proof.len() == Self::IMPL_LENGTH {
            // Implicit proof over link  - disabled in Python TODO
            false
        } else {
            false
        }
    }

    pub fn is_timed_out(&self) -> bool {
        let inner = self.lock();
        inner.sent_at + inner.timeout < now_seconds()
    }

    pub fn check_timeout(&mut self) {
        let timeout_callback = {
            let mut inner = self.lock();
            if inner.status != PacketReceipt::SENT {
                return;
            }
            if inner.sent_at + inner.timeout >= now_seconds() {
                return;
            }
            let age = now_seconds() - inner.sent_at;
            if inner.timeout == -1.0 {
                inner.status = PacketReceipt::CULLED;
            } else {
                crate::log(&format!("Receipt TIMEOUT hash={} timeout={:.3}s age={:.3}s",
                    crate::hexrep(&self.hash, false), inner.timeout, age), crate::LOG_WARNING, false, false);
                inner.status = PacketReceipt::FAILED;
            }
            inner.concluded_at = Some(now_seconds());
            inner.timeout_notified = inner.timeout_callback.is_some();
            inner.timeout_callback.clone()
        };

        // Call timeout callback if set, with the inner lock released.
        if let Some(cb) = timeout_callback {
            // Spawn thread to avoid blocking
            let receipt_clone = self.clone();
            std::thread::spawn(move || {
                cb(&receipt_clone);
            });
        }
    }

    pub fn get_rtt(&self) -> Option<f64> {
        let inner = self.lock();
        inner.concluded_at.map(|t| t - inner.sent_at)
    }

    pub fn get_status(&self) -> u8 {
        self.lock().status
    }

    /// Set a function that gets called when successful delivery is proven.
    ///
    /// Takes `&self`: the receipt a caller got back from `Packet::send` is
    /// the tracked receipt, so setting the callback on it is what makes it
    /// fire. Callers holding a `mut` binding are unaffected.
    ///
    /// A receipt that was already delivered, with no callback there to see
    /// it, runs this one once, now. Transport forgets a receipt the moment a
    /// proof concludes it (RNS/Transport.py:2761), and that can happen
    /// between `send()` returning and this call. The reference has the same
    /// window and loses the callback; the `Transport::set_receipt_*_callback`
    /// shim used to catch it by finding the concluded receipt still listed,
    /// which it no longer is. The late run is on its own thread: callers
    /// register while holding their own locks (LXMF holds the message lock),
    /// and the callback takes them.
    pub fn set_delivery_callback(&self, callback: Arc<dyn Fn(&PacketReceipt) + Send + Sync>) {
        let late = {
            let mut inner = self.lock();
            inner.delivery_callback = Some(callback.clone());
            let late = inner.status == PacketReceipt::DELIVERED && !inner.delivery_notified;
            if late {
                inner.delivery_notified = true;
            }
            late
        };
        if late {
            // Not through fire_delivery_callback: the §1 assertion already
            // ran when the proof concluded the receipt.
            let receipt = self.clone();
            std::thread::spawn(move || callback(&receipt));
        }
    }

    /// Single, asserting entry-point for delivery-callback invocation.
    ///
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1.
    /// Every "send proved" path in this file routes through here so the
    /// 5-second send-latency assertion runs at exactly one place.
    /// The callback is passed in by `mark_delivered`, which has already
    /// released the inner lock — the callback re-enters this receipt.
    fn fire_delivery_callback(&self, callback: Option<ReceiptCallback>) {
        crate::send_assertion::assert_send_completed_in_time(
            "packet.receipt", self.sent_at(),
        );
        if let Some(callback) = callback {
            callback(self);
        }
    }

    /// Set a function that gets called if delivery times out.
    ///
    /// Like `set_delivery_callback`: a receipt that already timed out or was
    /// culled, with no callback there to see it, runs this one once, now.
    pub fn set_timeout_callback(&self, callback: Arc<dyn Fn(&PacketReceipt) + Send + Sync>) {
        let late = {
            let mut inner = self.lock();
            inner.timeout_callback = Some(callback.clone());
            let concluded = inner.status == PacketReceipt::FAILED || inner.status == PacketReceipt::CULLED;
            let late = concluded && !inner.timeout_notified;
            if late {
                inner.timeout_notified = true;
            }
            late
        };
        if late {
            let receipt = self.clone();
            std::thread::spawn(move || callback(&receipt));
        }
    }

    /// Set the timeout in seconds
    pub fn set_timeout(&self, timeout: f64) {
        self.lock().timeout = timeout;
    }
}

fn now_seconds() -> f64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
    now.as_secs() as f64 + (now.subsec_nanos() as f64 / 1_000_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::Destination;
    use crate::identity::Identity;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_receipt(identity: Identity) -> PacketReceipt {
        let hash = vec![0x42; 32];
        let receipt = PacketReceipt::from_parts(
            hash.clone(),
            hash[..(reticulum::TRUNCATED_HASHLENGTH / 8)].to_vec(),
            Destination {
                identity: Some(identity),
                ..Destination::default()
            },
            1.0,
        );
        receipt.set_sent_at(0.0);
        receipt
    }

    const DST_LEN: usize = reticulum::TRUNCATED_HASHLENGTH / 8;

    /// A minimal well-formed HEADER_1 frame: flags, hops, destination hash,
    /// context, then `data_len` bytes of data.
    fn raw_header_1(hops: u8, data_len: usize) -> Vec<u8> {
        let mut raw = vec![0u8, hops];
        raw.extend_from_slice(&[0xAB; DST_LEN]);
        raw.push(NONE);
        raw.extend(std::iter::repeat(0x5Au8).take(data_len));
        raw
    }

    fn unpack_raw(raw: Vec<u8>) -> (bool, Packet) {
        let mut packet = Packet::new(None, Vec::new(), 0, 0, 0, HEADER_1, None, None, false, 0);
        packet.raw = raw;
        let ok = packet.unpack();
        (ok, packet)
    }

    // RNS/Packet.py:249-250 — `if self.hops >= RNS.Transport.PATHFINDER_M:
    // raise ValueError`, which unpack turns into a drop.
    #[test]
    fn unpack_drops_a_packet_at_the_pathfinder_hop_limit() {
        let (ok, _) = unpack_raw(raw_header_1(crate::transport::PATHFINDER_M, 4));
        assert!(
            !ok,
            "a hop count of PATHFINDER_M ({}) must be dropped in unpack — it is a packet no \
             receiver can ever forward, and letting it through hands Transport a packet whose \
             hop counter has already wrapped past the limit",
            crate::transport::PATHFINDER_M
        );
    }

    #[test]
    fn unpack_accepts_one_hop_below_the_pathfinder_limit() {
        let (ok, packet) = unpack_raw(raw_header_1(crate::transport::PATHFINDER_M - 1, 4));
        assert!(ok, "127 hops is still a legal packet — the bound is `>=`, not `>`");
        assert_eq!(packet.hops, crate::transport::PATHFINDER_M - 1);
    }

    // RNS/Packet.py:276 — "Zero-length data field".
    #[test]
    fn unpack_drops_a_zero_length_data_field() {
        let (ok, _) = unpack_raw(raw_header_1(0, 0));
        assert!(
            !ok,
            "a frame that ends at the context byte has no data field and must be dropped; \
             without this check every downstream `data[0]` is reading a packet that carries \
             nothing"
        );
    }

    #[test]
    fn unpack_accepts_a_minimal_valid_packet() {
        let (ok, packet) = unpack_raw(raw_header_1(0, 1));
        assert!(ok, "one byte of data is enough — the drop is for a *zero*-length field");
        assert_eq!(packet.data, vec![0x5A]);
        assert_eq!(packet.destination_hash.as_deref(), Some(&[0xABu8; DST_LEN][..]));
        assert_eq!(packet.context, NONE);
    }

    // RNS/Packet.py:293 — `if self.hops >= RNS.Transport.PATHFINDER_M: return False`
    #[test]
    fn send_refuses_a_packet_at_the_pathfinder_hop_limit() {
        let mut packet = Packet::new(
            Some(Destination::default()),
            vec![0x01, 0x02, 0x03],
            DATA,
            NONE,
            0,
            HEADER_1,
            None,
            None,
            false,
            0,
        );
        packet.hops = crate::transport::PATHFINDER_M;

        let result = packet.send().expect("send must not error");
        assert!(result.is_none(), "no receipt is produced for a packet that was never sent");
        assert!(!packet.sent, "and the packet is not marked sent");
        assert!(
            !packet.packed && packet.raw.is_empty(),
            "send() must bail out BEFORE packing when hops >= PATHFINDER_M — the reference \
             returns False on the very first line of send(). Regression: the gate is gone, \
             this packet got packed, and on a node with a live interface it would now be on \
             the wire for every receiver to drop in unpack()."
        );
    }

    #[test]
    fn validate_proof_marks_receipt_delivered_and_invokes_callback() {
        let identity = Identity::new(true);
        let mut receipt = make_receipt(identity.clone());
        let callback_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits_clone = callback_hits.clone();

        receipt.set_delivery_callback(Arc::new(move |_| {
            callback_hits_clone.fetch_add(1, Ordering::SeqCst);
        }));

        let signature = identity.sign(&receipt.hash);
        let mut proof = receipt.hash.clone();
        proof.extend_from_slice(&signature);

        assert!(receipt.validate_proof(&proof));
        assert_eq!(receipt.status(), PacketReceipt::DELIVERED);
        assert!(receipt.proved());
        assert_eq!(callback_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn validate_proof_rejects_truncated_explicit_hash_prefix() {
        let identity = Identity::new(true);
        let mut receipt = make_receipt(identity.clone());
        let signature = identity.sign(&receipt.hash);

        let mut invalid_proof = receipt.truncated_hash.clone();
        invalid_proof.extend_from_slice(&signature);

        assert!(!receipt.validate_proof(&invalid_proof));
        assert_eq!(receipt.status(), PacketReceipt::SENT);
        assert!(!receipt.proved());
    }

    fn explicit_proof(identity: &Identity, receipt: &PacketReceipt) -> Vec<u8> {
        let mut proof = receipt.hash.clone();
        proof.extend_from_slice(&identity.sign(&receipt.hash));
        proof
    }

    fn reporting_callback() -> (ReceiptCallback, std::sync::mpsc::Receiver<u8>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        (Arc::new(move |receipt: &PacketReceipt| { let _ = tx.lock().unwrap().send(receipt.status()); }), rx)
    }

    // Only a SENT receipt can become DELIVERED (RNS/Transport.py:2758). A
    // proof that arrives after the timeout fired used to deliver the FAILED
    // receipt as well, running both callbacks for one packet.
    #[test]
    fn a_proof_after_the_timeout_does_not_deliver_the_receipt() {
        let identity = Identity::new(true);
        let mut receipt = make_receipt(identity.clone()); // sent at 0, timeout 1 s: long expired
        let delivered = Arc::new(AtomicUsize::new(0));
        let delivered_clone = delivered.clone();
        receipt.set_delivery_callback(Arc::new(move |_| { delivered_clone.fetch_add(1, Ordering::SeqCst); }));
        let (timeout_cb, timed_out) = reporting_callback();
        receipt.set_timeout_callback(timeout_cb);

        receipt.check_timeout();
        assert_eq!(timed_out.recv_timeout(Duration::from_secs(5)).expect("timeout callback"), PacketReceipt::FAILED);

        assert!(!receipt.validate_proof(&explicit_proof(&identity, &receipt)), "a late proof validates nothing");
        assert_eq!(receipt.status(), PacketReceipt::FAILED);
        assert!(!receipt.proved());
        assert_eq!(delivered.load(Ordering::SeqCst), 0, "the delivery callback never runs for a timed-out receipt");
    }

    // A second copy of the proof (it can arrive over two interfaces) does
    // not deliver the receipt twice.
    #[test]
    fn a_second_proof_does_not_deliver_the_receipt_again() {
        let identity = Identity::new(true);
        let mut receipt = make_receipt(identity.clone());
        let delivered = Arc::new(AtomicUsize::new(0));
        let delivered_clone = delivered.clone();
        receipt.set_delivery_callback(Arc::new(move |_| { delivered_clone.fetch_add(1, Ordering::SeqCst); }));
        let proof = explicit_proof(&identity, &receipt);

        assert!(receipt.validate_proof(&proof));
        assert!(!receipt.validate_proof(&proof), "the second copy concludes nothing");
        assert_eq!(delivered.load(Ordering::SeqCst), 1);
    }

    // Transport forgets a receipt the moment a proof concludes it, which can
    // be before the sender registers its callback on the receipt `send()`
    // returned. That callback still runs, once.
    #[test]
    fn a_delivery_callback_registered_after_the_proof_runs_once() {
        let identity = Identity::new(true);
        let mut receipt = make_receipt(identity.clone());
        assert!(receipt.validate_proof(&explicit_proof(&identity, &receipt)));

        let (callback, delivered) = reporting_callback();
        receipt.set_delivery_callback(callback.clone());
        assert_eq!(delivered.recv_timeout(Duration::from_secs(5)).expect("late delivery callback"), PacketReceipt::DELIVERED);

        receipt.set_delivery_callback(callback);
        assert!(delivered.recv_timeout(Duration::from_millis(200)).is_err(), "a delivery is reported once");
    }

    #[test]
    fn a_delivery_callback_registered_again_after_it_ran_does_not_run_twice() {
        let identity = Identity::new(true);
        let mut receipt = make_receipt(identity.clone());
        let (callback, delivered) = reporting_callback();
        receipt.set_delivery_callback(callback.clone());
        assert!(receipt.validate_proof(&explicit_proof(&identity, &receipt)));
        assert_eq!(delivered.recv_timeout(Duration::from_secs(5)).expect("delivery callback"), PacketReceipt::DELIVERED);

        // The Transport shim registers the same callback a second time.
        receipt.set_delivery_callback(callback);
        assert!(delivered.recv_timeout(Duration::from_millis(200)).is_err(), "a delivery is reported once");
    }

    #[test]
    fn a_timeout_callback_registered_after_the_timeout_runs_once() {
        let mut receipt = make_receipt(Identity::new(true));
        receipt.check_timeout();
        assert_eq!(receipt.status(), PacketReceipt::FAILED);

        let (callback, timed_out) = reporting_callback();
        receipt.set_timeout_callback(callback.clone());
        assert_eq!(timed_out.recv_timeout(Duration::from_secs(5)).expect("late timeout callback"), PacketReceipt::FAILED);

        receipt.set_timeout_callback(callback);
        assert!(timed_out.recv_timeout(Duration::from_millis(200)).is_err(), "a timeout is reported once");
    }

    // RNS/Packet.py:428: max(rtt * traffic_timeout_factor,
    // Link.TRAFFIC_TIMEOUT_MIN_MS/1000). The Rust formula applied the floor
    // to the factor, so a link with no RTT yet had a zero timeout.
    #[test]
    fn link_receipt_timeout_is_rtt_times_factor_with_the_reference_floor() {
        let timeout_for = |rtt: Option<f64>| {
            let destination = Destination {
                hash: vec![0xE8; DST_LEN],
                dest_type: DestinationType::Link,
                link: Some(crate::destination::LinkInfo {
                    rtt,
                    traffic_timeout_factor: crate::link::TRAFFIC_TIMEOUT_FACTOR,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let packet = Packet::new(Some(destination), vec![1], DATA, NONE, 0, HEADER_1, None, None, true, 0);
            PacketReceipt::new(&packet).timeout()
        };
        let floor = crate::link::TRAFFIC_TIMEOUT_MIN_MS / 1000.0;
        assert_eq!(timeout_for(None), floor, "no RTT yet: the floor, not zero");
        assert_eq!(timeout_for(Some(0.0001)), floor, "0.6 ms is under the 5 ms floor");
        assert!((timeout_for(Some(0.1)) - 0.1 * crate::link::TRAFFIC_TIMEOUT_FACTOR).abs() < 1e-12, "above the floor: rtt x factor");
    }
}
