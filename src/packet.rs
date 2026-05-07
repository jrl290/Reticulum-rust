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
            return false;
        }
        self.flags = self.raw[0];
        self.hops = self.raw[1];
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
            if self.raw.len() < 2 + dst_len * 2 + 1 {
                return false;
            }
            self.transport_id = Some(self.raw[2..2 + dst_len].to_vec());
            self.destination_hash = Some(self.raw[2 + dst_len..2 + dst_len * 2].to_vec());
            self.context = self.raw[2 + dst_len * 2];
            self.data = self.raw[2 + dst_len * 2 + 1..].to_vec();
        } else {
            if self.raw.len() < 2 + dst_len + 1 {
                return false;
            }
            self.transport_id = None;
            self.destination_hash = Some(self.raw[2..2 + dst_len].to_vec());
            self.context = self.raw[2 + dst_len];
            self.data = self.raw[2 + dst_len + 1..].to_vec();
        }

        self.packed = false;
        self.update_hash();
        true
    }

    pub fn send(&mut self) -> Result<Option<PacketReceipt>, String> {
        if self.sent {
            return Err("Packet was already sent".to_string());
        }

        if self.destination.is_none() {
            return Err("Packet has no destination".to_string());
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

#[derive(Clone)]
pub struct PacketReceipt {
    pub hash: Vec<u8>,
    pub truncated_hash: Vec<u8>,
    pub sent: bool,
    pub sent_at: f64,
    pub proved: bool,
    pub status: u8,
    pub destination: Destination,
    pub concluded_at: Option<f64>,
    pub timeout: f64,
    pub delivery_callback: Option<Arc<dyn Fn(&PacketReceipt) + Send + Sync>>,
    pub timeout_callback: Option<Arc<dyn Fn(&PacketReceipt) + Send + Sync>>,
}

impl std::fmt::Debug for PacketReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketReceipt")
            .field("hash", &self.hash)
            .field("truncated_hash", &self.truncated_hash)
            .field("sent", &self.sent)
            .field("sent_at", &self.sent_at)
            .field("proved", &self.proved)
            .field("status", &self.status)
            .field("destination", &self.destination)
            .field("concluded_at", &self.concluded_at)
            .field("timeout", &self.timeout)
            .field("delivery_callback", &self.delivery_callback.is_some())
            .field("timeout_callback", &self.timeout_callback.is_some())
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

    pub fn new(packet: &Packet) -> Self {
        let _hash = packet.get_hash();
        let _truncated = packet.get_truncated_hash();
        let destination = packet.destination.clone().unwrap_or_default();
        let timeout = if destination.dest_type == DestinationType::Link {
            destination
                .link
                .as_ref()
                .and_then(|l| l.rtt)
                .unwrap_or(0.0)
                * destination
                    .link
                    .as_ref()
                    .map(|l| l.traffic_timeout_factor)
                    .unwrap_or(1.0)
                .max(0.005)
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
        PacketReceipt {
            hash,
            truncated_hash: truncated,
            sent: true,
            sent_at: now_seconds(),
            proved: false,
            status: PacketReceipt::SENT,
            destination,
            concluded_at: None,
            timeout,
            delivery_callback: None,
            timeout_callback: None,
        }
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
                        self.status = PacketReceipt::DELIVERED;
                        self.proved = true;
                        self.concluded_at = Some(now_seconds());
                        self.fire_delivery_callback();
                        return true;
                    }
                }
            }
            false
        } else if proof.len() == Self::IMPL_LENGTH {
            if let Some(identity) = &self.destination.identity {
                let valid = Self::validate_with_identity_variants(identity, proof, &self.hash);
                if valid {
                    self.status = PacketReceipt::DELIVERED;
                    self.proved = true;
                    self.concluded_at = Some(now_seconds());
                    self.fire_delivery_callback();
                    return true;
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
        // Hardcoded as explicit proofs for now (matches Python TODO comment)
        if proof.len() == Self::EXPL_LENGTH {
            let hash_len = HASHLENGTH / 8;
            let proof_hash = &proof[..hash_len];
            let signature = &proof[hash_len..hash_len + SIGLENGTH / 8];
            if proof_hash == self.hash.as_slice() {
                // In full implementation: link.validate(signature, &self.hash)
                // For now, use basic validation
                if link.validate(signature, &self.hash).unwrap_or(false) {
                    self.status = PacketReceipt::DELIVERED;
                    self.proved = true;
                    self.concluded_at = Some(now_seconds());
                    // link.last_proof = self.concluded_at
                    self.fire_delivery_callback();
                    return true;
                }
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
        self.sent_at + self.timeout < now_seconds()
    }

    pub fn check_timeout(&mut self) {
        if self.status == PacketReceipt::SENT && self.is_timed_out() {
            let age = now_seconds() - self.sent_at;
            if self.timeout == -1.0 {
                self.status = PacketReceipt::CULLED;
            } else {
                crate::log(&format!("Receipt TIMEOUT hash={} timeout={:.3}s age={:.3}s",
                    crate::hexrep(&self.hash, false), self.timeout, age), crate::LOG_WARNING, false, false);
                self.status = PacketReceipt::FAILED;
            }
            self.concluded_at = Some(now_seconds());
            
            // Call timeout callback if set
            if let Some(callback) = &self.timeout_callback {
                // Spawn thread to avoid blocking
                let cb = callback.clone();
                let receipt_clone = self.clone();
                std::thread::spawn(move || {
                    cb(&receipt_clone);
                });
            }
        }
    }

    pub fn get_rtt(&self) -> Option<f64> {
        self.concluded_at.map(|t| t - self.sent_at)
    }

    pub fn get_status(&self) -> u8 {
        self.status
    }

    /// Set a function that gets called when successful delivery is proven
    pub fn set_delivery_callback(&mut self, callback: Arc<dyn Fn(&PacketReceipt) + Send + Sync>) {
        self.delivery_callback = Some(callback);
    }

    /// Single, asserting entry-point for delivery-callback invocation.
    ///
    /// NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1.
    /// Every "send proved" path in this file routes through here so the
    /// 5-second send-latency assertion runs at exactly one place.
    fn fire_delivery_callback(&self) {
        crate::send_assertion::assert_send_completed_in_time(
            "packet.receipt", self.sent_at,
        );
        if let Some(callback) = &self.delivery_callback {
            callback(self);
        }
    }

    /// Set a function that gets called if delivery times out
    pub fn set_timeout_callback(&mut self, callback: Arc<dyn Fn(&PacketReceipt) + Send + Sync>) {
        self.timeout_callback = Some(callback);
    }

    /// Set the timeout in seconds
    pub fn set_timeout(&mut self, timeout: f64) {
        self.timeout = timeout;
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
        PacketReceipt {
            hash: hash.clone(),
            truncated_hash: hash[..(reticulum::TRUNCATED_HASHLENGTH / 8)].to_vec(),
            sent: true,
            sent_at: 0.0,
            proved: false,
            status: PacketReceipt::SENT,
            destination: Destination {
                identity: Some(identity),
                ..Destination::default()
            },
            concluded_at: None,
            timeout: 1.0,
            delivery_callback: None,
            timeout_callback: None,
        }
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
        assert_eq!(receipt.status, PacketReceipt::DELIVERED);
        assert!(receipt.proved);
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
        assert_eq!(receipt.status, PacketReceipt::SENT);
        assert!(!receipt.proved);
    }
}
