use crate::identity::{Identity, full_hash, truncated_hash, Token};
use crate::packet::{Packet, LINKREQUEST, DATA, PATH_RESPONSE as PATHRESPONSE, NONE, FLAG_SET, FLAG_UNSET};
use rmp_serde::{decode::from_slice, encode::to_vec};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Arc, Mutex};

// Direction constants
pub const DIRECTION_IN: u8 = 0x11;
pub const DIRECTION_OUT: u8 = 0x12;

// Destination type constants
pub const DEST_TYPE_SINGLE: u8 = 0x00;
pub const DEST_TYPE_GROUP: u8 = 0x01;
pub const DEST_TYPE_PLAIN: u8 = 0x02;
pub const DEST_TYPE_LINK: u8 = 0x03;

// Proof strategies
pub const PROVE_NONE: u8 = 0x21;
pub const PROVE_APP: u8 = 0x22;
pub const PROVE_ALL: u8 = 0x23;

// Request policies
pub const ALLOW_NONE: u8 = 0x00;
pub const ALLOW_ALL: u8 = 0x01;
pub const ALLOW_LIST: u8 = 0x02;

// Ratchet settings
pub const RATCHET_COUNT: usize = 512;
pub const RATCHET_INTERVAL: u64 = 30 * 60; // 30 minutes in seconds
pub const PR_TAG_WINDOW: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationType {
	Single = 0x00,
	Group = 0x01,
	Plain = 0x02,
	Link = 0x03,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
	IN = 0x11,
	OUT = 0x12,
}

impl Default for DestinationType {
	fn default() -> Self {
		DestinationType::Plain
	}
}

/// Type aliases for callback functions
pub type PacketCallback = Box<dyn Fn(&[u8], &Packet) + Send>;
pub type LinkEstablishedCallback = Box<dyn Fn(&crate::link::Link) + Send>;
pub type ProofRequestedCallback = Box<dyn Fn(&Packet) -> bool + Send>;
pub type RequestHandlerCallback = Arc<dyn Fn(&str, &[u8], &[u8], Option<&Identity>, f64) -> Vec<u8> + Send + Sync>;

#[derive(Clone)]
pub struct RequestHandler {
	pub path: String,
	pub allow_policy: u8,
	pub allowed_list: Option<Vec<Vec<u8>>>,
	pub auto_compress: bool,
	pub callback: Option<RequestHandlerCallback>,
}

/// Python RNS wire format for a REQUEST packet payload:
/// msgpack array [timestamp_f64, path_hash_16bytes, data_bytes]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestPayload(f64, serde_bytes::ByteBuf, serde_bytes::ByteBuf);

/// Python RNS wire format for a RESPONSE packet payload:
/// msgpack array [request_id_16bytes, response_bytes]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResponsePayload(serde_bytes::ByteBuf, serde_bytes::ByteBuf);

#[derive(Clone, Default)]
pub struct Callbacks {
	pub packet: Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>,
	pub link_established: Option<Arc<dyn Fn(crate::link::LinkHandle) + Send + Sync>>,
	pub proof_requested: Option<Arc<dyn Fn(&Packet) -> bool + Send + Sync>>,
}

#[derive(Clone, Debug, Default)]
pub struct LinkInfo {
	pub rtt: Option<f64>,
	pub traffic_timeout_factor: f64,
	pub status_closed: bool,
	pub mtu: Option<usize>,
	pub attached_interface: Option<String>,
}

pub struct Destination {
	pub hash: Vec<u8>,
	pub hexhash: String,
	pub name_hash: Vec<u8>,
	pub dest_type: DestinationType,
	pub direction: Direction,
	pub identity: Option<Identity>,
	pub latest_ratchet_id: Option<Vec<u8>>,
	pub link: Option<LinkInfo>,
	pub name: String,
	pub app_name: String,
	pub aspects: Vec<String>,
	pub mtu: usize,
	pub proof_strategy: u8,
	pub accept_link_requests: bool,
	pub ratchets: Option<Vec<Vec<u8>>>,
	pub latest_ratchet_time: u64,
	pub ratchet_interval: u64,
	pub retained_ratchets: usize,
	pub path_responses: HashMap<Vec<u8>, (u64, Vec<u8>)>, // (timestamp, announce_data)
	pub default_app_data: Option<Vec<u8>>,
	pub ratchets_path: Option<String>,
	pub enforce_ratchets: bool,
	pub callbacks: Callbacks,
	pub request_handlers: HashMap<Vec<u8>, RequestHandler>,
	pub links: Vec<crate::link::Link>,
	// GROUP destination fields
	pub prv_bytes: Option<Vec<u8>>,  // Symmetric key for GROUP destinations
	pub token: Arc<Mutex<Option<Token>>>,  // Token for GROUP encryption
}

impl Clone for Destination {
	fn clone(&self) -> Self {
		Destination {
			hash: self.hash.clone(),
			hexhash: self.hexhash.clone(),
			name_hash: self.name_hash.clone(),
			dest_type: self.dest_type,
			direction: self.direction,
			identity: self.identity.clone(),
			latest_ratchet_id: self.latest_ratchet_id.clone(),
			link: self.link.clone(),
			name: self.name.clone(),
			app_name: self.app_name.clone(),
			aspects: self.aspects.clone(),
			mtu: self.mtu,
			proof_strategy: self.proof_strategy,
			accept_link_requests: self.accept_link_requests,
			ratchets: self.ratchets.clone(),
			latest_ratchet_time: self.latest_ratchet_time,
			ratchet_interval: self.ratchet_interval,
			retained_ratchets: self.retained_ratchets,
			path_responses: self.path_responses.clone(),
			default_app_data: self.default_app_data.clone(),
			ratchets_path: self.ratchets_path.clone(),
			enforce_ratchets: self.enforce_ratchets,
			callbacks: self.callbacks.clone(),
			request_handlers: self.request_handlers.clone(),
			links: self.links.clone(),
			prv_bytes: self.prv_bytes.clone(),
			token: Arc::clone(&self.token),
		}
	}
}

impl std::fmt::Debug for Destination {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Destination")
			.field("hash", &self.hexhash)
			.field("dest_type", &self.dest_type)
			.field("direction", &self.direction)
			.field("name", &self.name)
			.field("mtu", &self.mtu)
			.field("proof_strategy", &self.proof_strategy)
			.field("identity", &"<non-Debug>")
			.finish()
	}
}

impl Default for Destination {
	fn default() -> Self {
		Destination {
			hash: Vec::new(),
			hexhash: String::new(),
			name_hash: Vec::new(),
			dest_type: DestinationType::Plain,
			direction: Direction::OUT,
			identity: None,
			latest_ratchet_id: None,
			link: None,
			name: String::new(),
			app_name: String::new(),
			aspects: Vec::new(),
			mtu: crate::reticulum::MTU,
			proof_strategy: PROVE_NONE,
			accept_link_requests: true,
			ratchets: None,
			latest_ratchet_time: 0,
			ratchet_interval: RATCHET_INTERVAL,
			retained_ratchets: RATCHET_COUNT,
			path_responses: HashMap::new(),
			default_app_data: None,
			ratchets_path: None,
			enforce_ratchets: false,
			callbacks: Callbacks::default(),
			request_handlers: HashMap::new(),
			links: Vec::new(),
			prv_bytes: None,
			token: Arc::new(Mutex::new(None)),
		}
	}
}

impl Destination {
	/// Expand a destination name from app_name and aspects
	pub fn expand_name(identity_hexhash: Option<&str>, app_name: &str, aspects: &[&str]) -> String {
		if app_name.contains('.') {
			panic!("Dots can't be used in app names");
		}
		
		let mut name = app_name.to_string();
		for aspect in aspects {
			if aspect.contains('.') {
				panic!("Dots can't be used in aspects");
			}
			name.push('.');
			name.push_str(aspect);
		}
		
		if let Some(hash) = identity_hexhash {
			name.push('.');
			name.push_str(hash);
		}
		
		name
	}
	
	/// Calculate the hash for a destination
	pub fn hash(identity_hash: Option<&[u8]>, app_name: &str, aspects: &[&str]) -> Vec<u8> {
		let name_for_hash = Self::expand_name(None, app_name, aspects);
		let name_hash = full_hash(name_for_hash.as_bytes());
		let name_hash_truncated = &name_hash[..crate::identity::NAME_HASH_LENGTH / 8];
		
		let mut addr_hash_material = name_hash_truncated.to_vec();
		if let Some(identity) = identity_hash {
			addr_hash_material.extend_from_slice(identity);
		}
		
		let full_hash_result = full_hash(&addr_hash_material);
		full_hash_result[..crate::reticulum::TRUNCATED_HASHLENGTH / 8].to_vec()
	}
	
	/// Extract app_name and aspects from a full destination name
	pub fn app_and_aspects_from_name(name: &str) -> (String, Vec<String>) {
		let parts: Vec<&str> = name.split('.').collect();
		if parts.is_empty() {
			return (String::new(), Vec::new());
		}
		
		let app_name = parts[0].to_string();
		let aspects = parts[1..].iter().map(|s| s.to_string()).collect();
		(app_name, aspects)
	}
	
	/// Calculate hash from name and identity
	pub fn hash_from_name_and_identity(name: &str, identity: Option<&Identity>) -> Vec<u8> {
		let (app_name, aspects) = Self::app_and_aspects_from_name(name);
		let aspect_strs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();
		let identity_bytes = identity.and_then(|i| i.hash.as_ref().map(|h| h.as_slice()));
		Self::hash(identity_bytes, &app_name, &aspect_strs)
	}

	/// Resolve a destination hash to a fully constructed outbound `Destination`.
	///
	/// Recalls the public key from the known-destination store, handles the
	/// X25519/Ed25519 key-order swap if needed, and returns a `Destination`
	/// whose hash matches the requested `dest_hash`.
	///
	/// Failing closed here is critical: if a recalled public key does not
	/// actually derive the requested destination hash, forcing the hash onto the
	/// constructed `Destination` would emit ciphertext for one key while labeling
	/// it as a different destination hash. The receiver then cannot decrypt the
	/// message, but the propagated blob still looks well-formed on the wire.
	pub fn from_destination_hash(
		dest_hash: &[u8],
		app_name: &str,
		aspects: &[&str],
	) -> Result<Self, String> {
		let public_key = Identity::recall_public_key(dest_hash)
			.ok_or("Destination public key not found in known destinations")?;

		// Try both the original and byte-swapped key order.
		// The known-destination store may record keys in either
		// [enc|sign] or [sign|enc] order depending on source.
		let mut swapped = public_key.clone();
		if swapped.len() == 64 {
			let (left, right) = swapped.split_at_mut(32);
			left.swap_with_slice(right);
		}

		let candidates = [&public_key, &swapped];
		for candidate in &candidates {
			if let Ok(identity) = Identity::from_public_key(candidate) {
				if let Ok(dest) = Self::new_outbound(
					Some(identity),
					DestinationType::Single,
					app_name.to_string(),
					aspects.iter().map(|s| s.to_string()).collect(),
				) {
					if dest.hash == dest_hash {
						return Ok(dest);
					}
				}
			}
		}

		Err(format!(
			"Recalled public key did not match destination hash {} for {}.{}",
			crate::hexrep(dest_hash, false),
			app_name,
			aspects.join(".")
		))
	}
	
	/// Create a new outbound destination
	pub fn new_outbound(
		identity: Option<Identity>,
		dest_type: DestinationType,
		app_name: String,
		aspects: Vec<String>,
	) -> Result<Self, String> {
		// Validate inputs
		if app_name.contains('.') {
			return Err("Dots can't be used in app names".to_string());
		}
		
		if dest_type != DestinationType::Plain && identity.is_none() {
			return Err("Can't create outbound SINGLE/GROUP/LINK destination without an identity".to_string());
		}
		
		if dest_type == DestinationType::Plain && identity.is_some() {
			return Err("Selected destination type PLAIN cannot hold an identity".to_string());
		}
		
		let identity_hash = if dest_type != DestinationType::Plain {
			Some(
				identity
					.as_ref()
					.and_then(|i| i.hash.as_ref())
					.ok_or("Identity hash not available")?
					.clone(),
			)
		} else {
			None
		};
		// Build name
		let identity_hexhash = identity_hash.as_ref().map(|hash| {
			hash
				.iter()
				.map(|b| format!("{:02x}", b))
				.collect::<Vec<_>>()
				.join("")
		});
		let aspect_strs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();
		let name = Self::expand_name(identity_hexhash.as_deref(), &app_name, &aspect_strs);
		
		// Calculate name_hash
		let name_without_identity = Self::expand_name(None, &app_name, &aspect_strs);
		let name_hash_result = full_hash(name_without_identity.as_bytes());
		let name_hash_length = crate::identity::NAME_HASH_LENGTH / 8;
		let name_hash = name_hash_result[..name_hash_length].to_vec();
		
		// Calculate destination hash
		let hash = Self::hash(identity_hash.as_deref(), &app_name, &aspect_strs);
		let hexhash = hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
		
		Ok(Destination {
			hash,
			hexhash,
			name_hash,
			dest_type,
			direction: Direction::OUT,
			identity,
			name,
			app_name,
			aspects,
			mtu: crate::reticulum::MTU,
			proof_strategy: PROVE_NONE,
			accept_link_requests: true,
			latest_ratchet_id: None,
			link: None,
			ratchets: None,
			latest_ratchet_time: 0,
			ratchet_interval: RATCHET_INTERVAL,
			retained_ratchets: RATCHET_COUNT,
			path_responses: HashMap::new(),
			default_app_data: None,
			ratchets_path: None,
			enforce_ratchets: false,
			callbacks: Callbacks::default(),
			request_handlers: HashMap::new(),
			links: Vec::new(),
			prv_bytes: None,
			token: Arc::new(Mutex::new(None)),
		})
	}

	/// Create an inbound destination (for receiving packets on a specific hash)
	pub fn new_inbound(
		identity: Option<Identity>,
		dest_type: DestinationType,
		app_name: String,
		aspects: Vec<String>,
	) -> Result<Self, String> {
		// Validate inputs
		if app_name.contains('.') {
			return Err("Dots can't be used in app names".to_string());
		}
		
		if dest_type != DestinationType::Plain && identity.is_none() {
			return Err("Can't create inbound SINGLE/GROUP/LINK destination without an identity".to_string());
		}
		
		if dest_type == DestinationType::Plain && identity.is_some() {
			return Err("Selected destination type PLAIN cannot hold an identity".to_string());
		}
		
		let identity_hash = if dest_type != DestinationType::Plain {
			Some(
				identity
					.as_ref()
					.and_then(|i| i.hash.as_ref())
					.ok_or("Identity hash not available")?
					.clone(),
			)
		} else {
			None
		};
		// Build name
		let identity_hexhash = identity_hash.as_ref().map(|hash| {
			hash
				.iter()
				.map(|b| format!("{:02x}", b))
				.collect::<Vec<_>>()
				.join("")
		});
		let aspect_strs: Vec<&str> = aspects.iter().map(|s| s.as_str()).collect();
		let name = Self::expand_name(identity_hexhash.as_deref(), &app_name, &aspect_strs);
		
		// Calculate name_hash
		let name_without_identity = Self::expand_name(None, &app_name, &aspect_strs);
		let name_hash_result = full_hash(name_without_identity.as_bytes());
		let name_hash_length = crate::identity::NAME_HASH_LENGTH / 8;
		let name_hash = name_hash_result[..name_hash_length].to_vec();
		
		// Calculate destination hash
		let hash = Self::hash(identity_hash.as_deref(), &app_name, &aspect_strs);
		let hexhash = hash.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
		
		Ok(Destination {
			hash,
			hexhash,
			name_hash,
			dest_type,
			direction: Direction::IN,
			identity,
			name,
			app_name,
			aspects,
			mtu: crate::reticulum::MTU,
			proof_strategy: PROVE_NONE,
			accept_link_requests: true,
			latest_ratchet_id: None,
			link: None,
			ratchets: None,
			latest_ratchet_time: 0,
			ratchet_interval: RATCHET_INTERVAL,
			retained_ratchets: RATCHET_COUNT,
			path_responses: HashMap::new(),
			default_app_data: None,
			ratchets_path: None,
			enforce_ratchets: false,
			callbacks: Callbacks::default(),
			request_handlers: HashMap::new(),
			links: Vec::new(),
			prv_bytes: None,
			token: Arc::new(Mutex::new(None)),
		})
	}
	
	/// Check if destination accepts link requests
	pub fn accepts_links(&self) -> bool {
		self.accept_link_requests
	}
	
	/// Set whether destination accepts link requests
	pub fn set_accept_links(&mut self, accept: bool) {
		self.accept_link_requests = accept;
	}
	
	/// Register callback for when a link is established
	pub fn set_link_established_callback(
		&mut self,
		callback: Option<Arc<dyn Fn(crate::link::LinkHandle) + Send + Sync>>,
	) {
		self.callbacks.link_established = callback;
	}
	
	/// Register callback for when a packet is received
	pub fn set_packet_callback(&mut self, callback: Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>) {
		self.callbacks.packet = callback;
	}
	
	/// Register callback for when proof is requested
	pub fn set_proof_requested_callback(&mut self, callback: Option<Arc<dyn Fn(&Packet) -> bool + Send + Sync>>) {
		self.callbacks.proof_requested = callback;
	}
	
	/// Set the proof strategy for this destination
	pub fn set_proof_strategy(&mut self, strategy: u8) -> Result<(), String> {
		match strategy {
			PROVE_NONE | PROVE_APP | PROVE_ALL => {
				self.proof_strategy = strategy;
				Ok(())
			}
			_ => Err(format!("Invalid proof strategy: {}", strategy)),
		}
	}
	
	/// Register a request handler for a path
	pub fn register_request_handler(
		&mut self,
		path: String,
		callback: Option<RequestHandlerCallback>,
		allow: u8,
		allowed_list: Option<Vec<Vec<u8>>>,
		auto_compress: bool,
	) -> Result<(), String> {
		// Validate allow policy
		match allow {
			ALLOW_NONE | ALLOW_ALL | ALLOW_LIST => {}
			_ => return Err(format!("Invalid allow policy: {}", allow)),
		}
		
		let path_hash = truncated_hash(path.as_bytes());
		self.request_handlers.insert(path_hash, RequestHandler {
			path,
			allow_policy: allow,
			allowed_list,
			auto_compress,
			callback,
		});
		
		Ok(())
	}
	
	/// Deregister a request handler for a path
	pub fn deregister_request_handler(&mut self, path: &str) -> bool {
		let path_hash = truncated_hash(path.as_bytes());
		self.request_handlers.remove(&path_hash).is_some()
	}
	
	/// Announce this destination on the network
	/// Only SINGLE destinations with IN direction can be announced
	pub fn announce(
		&mut self,
		app_data: Option<&[u8]>,
		path_response: bool,
		attached_interface: Option<String>,
		tag: Option<Vec<u8>>,
		send: bool,
	) -> Result<Option<Packet>, String> {
		// Only SINGLE, IN destinations can announce
		if self.dest_type != DestinationType::Single {
			return Err("Only SINGLE destination types can be announced".to_string());
		}
		if self.direction != Direction::IN {
			return Err("Only IN destination types can be announced".to_string());
		}
		
		// Clean up stale path responses (older than PR_TAG_WINDOW seconds)
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		
		self.path_responses.retain(|_, (timestamp, _)| now - *timestamp < PR_TAG_WINDOW);
		
		// Check for cached announce data if this is a path response with a tag
		let announce_data = if path_response && tag.is_some() {
			if let Some(cached) = tag.as_ref().and_then(|t| self.path_responses.get(t)) {
				// Use cached announce data
				crate::log(&format!("Using cached announce data for answering path request with tag {}", 
					crate::hexrep(tag.as_ref().unwrap(), true)), crate::LOG_EXTREME, false, false);
				cached.1.clone()
			} else {
				// Generate new announce data
				self.generate_announce_data(app_data, now, tag.clone())?
			}
		} else {
			// Always generate new announce data for non-path-response announces
			self.generate_announce_data(app_data, now, tag.clone())?
		};
		
		// Determine context and context_flag
		let identity = self.identity.as_ref()
			.ok_or("Cannot announce destination without identity")?;
		let _public_key = identity.get_public_key()?;
		
		let context = if path_response { PATHRESPONSE } else { NONE };
		// The context_flag indicates whether the announce contains a ratchet.
		// We must check the ratchets field directly rather than inferring
		// from announce_data length, because app_data can also increase
		// the length and would be misidentified as a ratchet.
		let has_ratchet = self.ratchets.as_ref().map_or(false, |r| !r.is_empty());
		let context_flag = if has_ratchet { FLAG_SET } else { FLAG_UNSET };
		
		// Create announce packet
		let mut packet = Packet::new(
			Some(self.clone()),
			announce_data,
			crate::packet::ANNOUNCE,
			context,
			crate::transport::BROADCAST,
			crate::packet::HEADER_1,
			None, // transport_id
			attached_interface,
			false, // create_receipt
			context_flag,
		);
		
		// Send or return the packet
		if send {
			packet.send()?;
			Ok(None)
		} else {
			Ok(Some(packet))
		}
	}
	
	/// Generate announce data (helper for announce method)
	fn generate_announce_data(
		&mut self,
		app_data: Option<&[u8]>,
		now: u64,
		tag: Option<Vec<u8>>,
	) -> Result<Vec<u8>, String> {
		// Determine app data to include
		let announce_app_data = if let Some(data) = app_data {
			data.to_vec()
		} else if let Some(default_data) = &self.default_app_data {
			default_data.clone()
		} else {
			Vec::new()
		};
		
		// Build announce data
		// Format: public_key + name_hash + random_hash + ratchet + signature + app_data
		let mut ratchet_bytes = Vec::new();
		
		// Rotate ratchets if enabled
		if self.ratchets.is_some() {
			self.rotate_ratchets()?;
			// Get the latest ratchet public bytes
			if let Some(ratchets) = &self.ratchets {
				if !ratchets.is_empty() {
					ratchet_bytes = crate::identity::Identity::ratchet_public_bytes(&ratchets[0])?;
					let _ = crate::identity::Identity::remember_ratchet(&self.hash, &ratchet_bytes);
				}
			}
		}
		
		let identity = self.identity.as_ref()
			.ok_or("Cannot announce destination without identity")?;
		let public_key = identity.get_public_key()?;
		
		// Generate random hash: 5 random bytes + 5 bytes timestamp
		let random_bytes = crate::identity::get_random_hash();
		let mut random_hash = random_bytes[..5].to_vec();
		let timestamp_bytes = (now as u64).to_be_bytes();
		random_hash.extend_from_slice(&timestamp_bytes[3..8]); // Last 5 bytes
		
		// Build signed_data: hash + public_key + name_hash + random_hash + ratchet + app_data
		let mut signed_data = Vec::new();
		signed_data.extend_from_slice(&self.hash);
		signed_data.extend_from_slice(&public_key);
		signed_data.extend_from_slice(&self.name_hash);
		signed_data.extend_from_slice(&random_hash);
		signed_data.extend_from_slice(&ratchet_bytes);
		if !announce_app_data.is_empty() {
			signed_data.extend_from_slice(&announce_app_data);
		}
		
		// Sign the data
		let signature = identity.sign(&signed_data);

		// Build announce_data: public_key + name_hash + random_hash + ratchet + signature + app_data
		let mut announce_data = Vec::new();
		announce_data.extend_from_slice(&public_key);
		announce_data.extend_from_slice(&self.name_hash);
		announce_data.extend_from_slice(&random_hash);
		announce_data.extend_from_slice(&ratchet_bytes);
		announce_data.extend_from_slice(&signature);
		if !announce_app_data.is_empty() {
			announce_data.extend_from_slice(&announce_app_data);
		}
		
		// Cache the announce data with tag
		if let Some(tag_bytes) = tag {
			self.path_responses.insert(tag_bytes, (now, announce_data.clone()));
		}
		
		Ok(announce_data)
	}
	
	/// Handle incoming packet
	pub fn receive(&mut self, packet: &Packet) -> Result<bool, String> {
		if packet.packet_type == LINKREQUEST {
			// Handle link request with plaintext data
			self.incoming_link_request(&packet.data, packet)?;
			Ok(true)
		} else {
			// Decrypt packet data
			let _plaintext = self.decrypt(&packet.data)?;

			if packet.packet_type == DATA && packet.context == crate::packet::REQUEST {
				self.handle_request_packet(packet, &_plaintext)?;
				return Ok(true);
			}
			
			// Update ratchet ID if present
			if let Some(ratchet_id) = &packet.ratchet_id {
				self.latest_ratchet_id = Some(ratchet_id.clone());
			}
			
			// Handle DATA packets
			if packet.packet_type == DATA {
				if let Some(callback) = self.callbacks.packet.clone() {
					let plaintext = _plaintext.clone();
					let packet_clone = packet.clone();
					thread::spawn(move || {
						callback(&plaintext, &packet_clone);
					});
				}
				return Ok(true);
			}
			
			Ok(false)
		}
	}

	fn handle_request_packet(&self, packet: &Packet, plaintext: &[u8]) -> Result<(), String> {
		// Python RNS wire format: [timestamp_f64, path_hash_16bytes, data_bytes]
		let payload: RequestPayload = match from_slice(plaintext) {
			Ok(parsed) => parsed,
			Err(e) => {
				eprintln!("[DEST] handle_request_packet: failed to decode payload: {} len={}", e, plaintext.len());
				return Ok(());
			}
		};

		let path_hash: Vec<u8> = payload.1.to_vec();
		let request_data: Vec<u8> = payload.2.to_vec();
		// request_id = truncated hash of the raw packet (Python: packet.getTruncatedHash())
		let request_id = packet.get_truncated_hash();

		let handler = match self.request_handlers.get(&path_hash) {
			Some(handler) => handler,
			None => return Ok(()),
		};

		let callback = handler.callback.clone();
		let path_hex = crate::hexrep(&path_hash, false);
		let destination = packet.destination.clone();

		thread::spawn(move || {
			let response = if let Some(callback) = callback {
				let remote_identity: Option<&Identity> = None;
				callback(&path_hex, &request_data, &request_id, remote_identity, payload.0)
			} else {
				Vec::new()
			};

			// Python RNS response wire format: [request_id_bytes, response_bytes]
			let response_payload = ResponsePayload(
				serde_bytes::ByteBuf::from(request_id),
				serde_bytes::ByteBuf::from(response),
			);

			let response_data = match to_vec(&response_payload) {
				Ok(data) => data,
				Err(_) => return,
			};

			let mut response_packet = Packet::new(
				destination,
				response_data,
				DATA,
				crate::packet::RESPONSE,
				crate::transport::BROADCAST,
				crate::packet::HEADER_1,
				None,
				None,
				false,
				0,
			);
			let _ = response_packet.send();
		});
		Ok(())
	}
	
	/// Handle incoming link request
	pub fn incoming_link_request(&mut self, _data: &[u8], _packet: &Packet) -> Result<(), String> {
		if !self.accept_link_requests {
			crate::log(&format!("[DEST] incoming_link_request: REJECTED accept_link_requests=false dest={}", crate::hexrep(&self.hash, false)), crate::LOG_NOTICE, false, false);
			return Ok(());
		}

		// Duplicate LINKREQUESTs for the same link_id can arrive via multiple relays.
		// Ignore duplicates while a live link with this id is already tracked.
		let requested_link_id = crate::link::link_id_from_lr_packet(_packet);
		if self.links.iter().any(|l| l.link_id == requested_link_id && l.status != crate::link::STATE_CLOSED) {
			crate::log(
				&format!(
					"[DEST] incoming_link_request: duplicate suppressed link_id={} dest={}",
					crate::hexrep(&requested_link_id, false),
					crate::hexrep(&self.hash, false)
				),
				crate::LOG_NOTICE,
				false,
				false,
			);
			return Ok(());
		}

		if crate::link::get_runtime_link_handle(&requested_link_id).is_some() {
			crate::log(
				&format!(
					"[DEST] incoming_link_request: runtime duplicate suppressed link_id={} dest={}",
					crate::hexrep(&requested_link_id, false),
					crate::hexrep(&self.hash, false)
				),
				crate::LOG_NOTICE,
				false,
				false,
			);
			return Ok(());
		}
		
		crate::log(&format!("[DEST] incoming_link_request: data_len={} dest={}", _data.len(), crate::hexrep(&self.hash, false)), crate::LOG_NOTICE, false, false);
		
		// Validate the link request and create Link if valid
		match crate::link::Link::validate_request(self, _data, _packet) {
			Ok(link) => {
				crate::log(&format!("[DEST] incoming_link_request: link created link_id={}", crate::hexrep(&link.link_id, false)), crate::LOG_NOTICE, false, false);
				self.links.push(link);
			}
			Err(e) => {
				crate::log(&format!("[DEST] incoming_link_request: validate_request FAILED: {}", e), crate::LOG_NOTICE, false, false);
			}
		}
		
		Ok(())
	}
	
	/// Enable ratchets for forward secrecy
	pub fn enable_ratchets(&mut self, ratchets_path: String) -> Result<(), String> {
		self.latest_ratchet_time = 0;
		self._reload_ratchets(&ratchets_path)?;
		Ok(())
	}
	
	/// Enforce ratchets - only accept packets encrypted with ratchet keys
	pub fn enforce_ratchets(&mut self) -> Result<(), String> {
		if self.ratchets.is_some() {
			self.enforce_ratchets = true;
			Ok(())
		} else {
			Err("Ratchets not enabled".to_string())
		}
	}
	
	/// Set the number of ratchets to retain
	pub fn set_retained_ratchets(&mut self, count: usize) -> Result<(), String> {
		if count > 0 {
			self.retained_ratchets = count;
			Ok(())
		} else {
			Err("Retained ratchets must be > 0".to_string())
		}
	}
	
	/// Set the ratchet rotation interval in seconds
	pub fn set_ratchet_interval(&mut self, interval: u64) -> Result<(), String> {
		if interval > 0 {
			self.ratchet_interval = interval;
			Ok(())
		} else {
			Err("Ratchet interval must be > 0".to_string())
		}
	}
	
	/// Rotate ratchets - generates new ratchet and persists
	pub fn rotate_ratchets(&mut self) -> Result<bool, String> {
		if let Some(ratchets) = &mut self.ratchets {
			let now = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			
			if now > self.latest_ratchet_time + self.ratchet_interval {
				// Generate a proper X25519 private key (32 random bytes)
				let mut ratchet_prv = [0u8; 32];
				use rand::RngCore;
				rand::rngs::OsRng.fill_bytes(&mut ratchet_prv);
				ratchets.insert(0, ratchet_prv.to_vec());
				self.latest_ratchet_time = now;
				self._clean_ratchets();
				let _ = self._persist_ratchets();
				return Ok(true);
			}
			Ok(false)
		} else {
			Err("Cannot rotate ratchet, ratchets are not enabled".to_string())
		}
	}
	
	/// Clean up old ratchets, keeping only retained_ratchets count
	fn _clean_ratchets(&mut self) {
		if let Some(ratchets) = &mut self.ratchets {
			if ratchets.len() > self.retained_ratchets {
				ratchets.truncate(self.retained_ratchets);
			}
		}
	}
	
	/// Persist ratchets to file with signature (Python: _persist_ratchets)
	fn _persist_ratchets(&self) -> Result<(), String> {
		let ratchets_path = self.ratchets_path.as_ref().ok_or("No ratchets path set")?;
		let ratchets = self.ratchets.as_ref().ok_or("No ratchets to persist")?;

		// Serialize the ratchet private keys list as msgpack
		let packed_ratchets = to_vec(ratchets)
			.map_err(|e| format!("Failed to serialize ratchets: {}", e))?;

		// Sign the packed ratchets with our identity
		let signature = if let Some(identity) = &self.identity {
			identity.sign(&packed_ratchets)
		} else {
			return Err("No identity for signing ratchets".to_string());
		};

		// Create persisted data: {"signature": <bytes>, "ratchets": <bytes>}
		let persisted: HashMap<String, serde_bytes::ByteBuf> = [
			("signature".to_string(), serde_bytes::ByteBuf::from(signature)),
			("ratchets".to_string(), serde_bytes::ByteBuf::from(packed_ratchets)),
		].into_iter().collect();
		let file_data = to_vec(&persisted)
			.map_err(|e| format!("Failed to serialize persisted ratchets: {}", e))?;

		// Atomic write: write to .tmp then rename
		let tmp_path = format!("{}.tmp", ratchets_path);
		std::fs::write(&tmp_path, &file_data)
			.map_err(|e| format!("Failed to write ratchet file: {}", e))?;
		if std::path::Path::new(ratchets_path).exists() {
			let _ = std::fs::remove_file(ratchets_path);
		}
		std::fs::rename(&tmp_path, ratchets_path)
			.map_err(|e| format!("Failed to rename ratchet file: {}", e))?;

		Ok(())
	}
	
	/// Reload ratchets from file with signature validation (Python: _reload_ratchets)
	fn _reload_ratchets(&mut self, ratchets_path: &str) -> Result<(), String> {
		use std::path::Path;
		crate::log(&format!("[RATCHET] _reload_ratchets: path={} exists={}", ratchets_path, Path::new(ratchets_path).exists()), crate::LOG_NOTICE, false, false);
		if Path::new(ratchets_path).exists() {
			let load_attempt = |identity: &Identity| -> Result<Vec<Vec<u8>>, String> {
				let file_data = std::fs::read(ratchets_path)
					.map_err(|e| format!("Failed to read ratchet file: {}", e))?;
				let persisted: HashMap<String, serde_bytes::ByteBuf> = from_slice(&file_data)
					.map_err(|e| format!("Failed to deserialize ratchet file: {}", e))?;
				let signature = persisted.get("signature")
					.ok_or("Missing signature in ratchet file")?;
				let packed_ratchets = persisted.get("ratchets")
					.ok_or("Missing ratchets in ratchet file")?;
				if !identity.validate(signature, packed_ratchets) {
					return Err("Invalid ratchet file signature".to_string());
				}
				let ratchets: Vec<serde_bytes::ByteBuf> = from_slice(packed_ratchets)
					.map_err(|e| format!("Failed to deserialize ratchet keys: {}", e))?;
				Ok(ratchets.into_iter().map(|b| b.to_vec()).collect())
			};

			let identity = self.identity.as_ref()
				.ok_or("No identity for ratchet validation")?;

			let result = load_attempt(identity);
			match result {
				Ok(ratchets) => {
					crate::log(&format!("[RATCHET] Loaded {} ratchets from {}", ratchets.len(), ratchets_path), crate::LOG_NOTICE, false, false);
					self.ratchets = Some(ratchets);
					self.ratchets_path = Some(ratchets_path.to_string());
				}
				Err(e) => {
					crate::log(&format!("First ratchet load attempt failed: {}. Retrying in 500ms.", e), crate::LOG_ERROR, false, false);
					std::thread::sleep(std::time::Duration::from_millis(500));
					match load_attempt(identity) {
						Ok(ratchets) => {
							crate::log("[RATCHET] Ratchet reload retry succeeded", crate::LOG_NOTICE, false, false);
							self.ratchets = Some(ratchets);
							self.ratchets_path = Some(ratchets_path.to_string());
						}
						Err(e2) => {
							crate::log(&format!("Ratchet file at {} could not be loaded: {}", ratchets_path, e2), crate::LOG_CRITICAL, false, false);
							self.ratchets = Some(Vec::new());
							self.ratchets_path = Some(ratchets_path.to_string());
						}
					}
				}
			}
		} else {
			// Initialize new ratchet file
			crate::log(&format!("[RATCHET] No existing ratchet file at {}, initialising empty", ratchets_path), crate::LOG_NOTICE, false, false);
			self.ratchets = Some(Vec::new());
			self.ratchets_path = Some(ratchets_path.to_string());
			let _ = self._persist_ratchets();
		}
		Ok(())
	}
	
	/// Create a new symmetric key for GROUP destinations
	pub fn create_keys(&mut self) -> Result<(), String> {
		match self.dest_type {
			DestinationType::Plain => Err("Plain destination cannot hold keys".to_string()),
			DestinationType::Single => Err("Single destination holds keys through Identity".to_string()),
	DestinationType::Group => {
				//  Generate 64-byte key for AES-256-CBC (32 signing + 32 encryption)
				let key_bytes: Vec<u8> = (0..64).map(|i| ((i *  13 + 7) % 256) as u8).collect();
				self.prv_bytes = Some(key_bytes.clone());
				let token = Token::new(&key_bytes)?;
				*self.token.lock().unwrap() = Some(token);
				Ok(())
			}
			DestinationType::Link => Err("Link destination manages keys internally".to_string()),
		}
	}
	
	/// Get the private key for GROUP destinations
	pub fn get_private_key(&self) -> Result<Vec<u8>, String> {
		match self.dest_type {
			DestinationType::Plain => Err("Plain destination cannot hold keys".to_string()),
			DestinationType::Single => Err("Single destination holds keys through Identity".to_string()),
			DestinationType::Group => {
				if let Some(prv_bytes) = &self.prv_bytes {
					Ok(prv_bytes.clone())
				} else {
					Err("No private key. Did you create or load one?".to_string())
				}
			}
			DestinationType::Link => Err("Link destination manages keys internally".to_string()),
		}
	}
	
	/// Load a private key for GROUP destinations
	pub fn load_private_key(&mut self, key: &[u8]) -> Result<(), String> {
		match self.dest_type {
			DestinationType::Plain => Err("Plain destination cannot hold keys".to_string()),
			DestinationType::Single => Err("Single destination holds keys through Identity".to_string()),
			DestinationType::Group => {
				if key.len() != 32 && key.len() != 64 {
					return Err("Symmetric key must be 32 or 64 bytes".to_string());
				}
				self.prv_bytes = Some(key.to_vec());
				let token = Token::new(key)?;
				*self.token.lock().unwrap() = Some(token);
				Ok(())
			}
			DestinationType::Link => Err("Link destination manages keys internally".to_string()),
		}
	}
	
	/// Load a public key (only for SINGLE destinations, handled by Identity)
	pub fn load_public_key(&self, _key: &[u8]) -> Result<(), String> {
		if self.dest_type != DestinationType::Single {
			Err("Only the 'single' destination type can hold a public key".to_string())
		} else {
			Err("A single destination holds keys through an Identity instance".to_string())
		}
	}
	
	/// Set default app_data for announces
	pub fn set_default_app_data(&mut self, app_data: Option<Vec<u8>>) {
		self.default_app_data = app_data;
	}
	
	/// Clear default app_data
	pub fn clear_default_app_data(&mut self) {
		self.default_app_data = None;
	}
	
	// Encrypt data for this destination
	pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
		match self.dest_type {
			DestinationType::Plain => Ok(plaintext.to_vec()),
			DestinationType::Single => {
				if let Some(identity) = &self.identity {
					let selected_ratchet = Identity::get_ratchet(&self.hash);
					if let Some(ref ratchet) = selected_ratchet {
						self.latest_ratchet_id = Some(Identity::ratchet_id_from_pub(ratchet));
					}
					identity.encrypt_with_ratchet(plaintext, selected_ratchet.as_deref())
				} else {
					Err("No identity for encryption".to_string())
				}
			}
			DestinationType::Group => {
				if let Ok(token_guard) = self.token.lock() {
					if let Some(token) = &*token_guard {
						token.encrypt(plaintext)
					} else {
						Err("No private key held by GROUP destination. Did you create or load one?".to_string())
					}
				} else {
					Err("Could not acquire token lock".to_string())
				}
			}
			DestinationType::Link => {
				crate::link::runtime_encrypt_for_destination(&self.hash, plaintext)
			}
		}
	}
	
	// Decrypt data for this destination
	pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
		match self.dest_type {
			DestinationType::Plain => Ok(ciphertext.to_vec()),
			DestinationType::Single => {
				// First attempt: try with current ratchet keys
				let dest_ratchets_clone = self.ratchets.clone();
				let first_result = if let Some(identity) = self.identity.as_mut() {
					let dr = dest_ratchets_clone.as_ref().map(|r| r.as_slice());
					identity.decrypt_with_ratchets(ciphertext, dr)
				} else {
					return Err("No identity for decryption".to_string());
				};

				if first_result.is_ok() || self.ratchets.is_none() {
					return first_result;
				}

				// Ratchet mismatch — try reloading from disk and retry
				crate::log(&format!("[RATCHET] decrypt failed with {} ratchets, reloading from disk...",
					self.ratchets.as_ref().map(|r| r.len()).unwrap_or(0)), crate::LOG_NOTICE, false, false);
				if let Some(ratchets_path) = self.ratchets_path.clone() {
					let _ = self._reload_ratchets(&ratchets_path);
				}
				let dest_ratchets_clone = self.ratchets.clone();
				crate::log(&format!("[RATCHET] after reload: {} ratchets", dest_ratchets_clone.as_ref().map(|r| r.len()).unwrap_or(0)), crate::LOG_NOTICE, false, false);
				if let Some(identity) = self.identity.as_mut() {
					let dr = dest_ratchets_clone.as_ref().map(|r| r.as_slice());
					identity.decrypt_with_ratchets(ciphertext, dr)
				} else {
					Err("No identity for decryption".to_string())
				}
			}
			DestinationType::Group => {
				if let Ok(token_guard) = self.token.lock() {
					if let Some(token) = &*token_guard {
						token.decrypt(ciphertext)
					} else {
						Err("No private key held by GROUP destination. Did you create or load one?".to_string())
					}
				} else {
					Err("Could not acquire token lock".to_string())
				}
			}
			DestinationType::Link => {
				crate::link::runtime_decrypt_for_destination(&self.hash, ciphertext)
			}
		}
	}
	
	/// Sign data with this destination's identity
	pub fn sign(&self, data: &[u8]) -> Vec<u8> {
		match self.dest_type {
			DestinationType::Single => {
				if let Some(identity) = &self.identity {
					identity.sign(data)
				} else {
					Vec::new()
				}
			}
			_ => Vec::new(),
		}
	}
	
	/// Validate a signature for this destination
	pub fn validate(&self, signature: &[u8], data: &[u8]) -> bool {
		match self.dest_type {
			DestinationType::Single => {
				if let Some(identity) = &self.identity {
					identity.validate(signature, data)
				} else {
					false
				}
			}
			_ => false,
		}
	}
}

// Implement Display trait for human-readable output (__str__ equivalent)
impl std::fmt::Display for Destination {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "<{}:{}>", self.name, self.hexhash)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::identity::Identity;

	#[test]
	fn from_destination_hash_rejects_mismatched_public_key() {
		let wrong_identity = Identity::new(true);
		let wrong_public_key = wrong_identity
			.get_public_key()
			.expect("wrong identity public key");
		let dest_hash = [0x11u8; crate::reticulum::TRUNCATED_HASHLENGTH / 8];

		let _ = Identity::remember_destination(&dest_hash, &wrong_public_key, None);

		let result = Destination::from_destination_hash(&dest_hash, "lxmf", &["delivery"]);
		assert!(
			result.is_err(),
			"resolver must fail instead of forcing a mismatched hash onto the destination"
		);

		Identity::forget_destination_in_memory(&dest_hash);
	}

	#[test]
	fn from_destination_hash_accepts_swapped_public_key_order() {
		let identity = Identity::new(true);
		let destination = Destination::new_outbound(
			Some(identity.clone()),
			DestinationType::Single,
			"lxmf".to_string(),
			vec!["delivery".to_string()],
		)
		.expect("destination");

		let mut swapped_public_key = identity.get_public_key().expect("public key");
		let (left, right) = swapped_public_key.split_at_mut(32);
		left.swap_with_slice(right);

		let _ = Identity::remember_destination(&destination.hash, &swapped_public_key, None);

		let resolved = Destination::from_destination_hash(&destination.hash, "lxmf", &["delivery"])
			.expect("resolver should accept swapped key order");

		assert_eq!(resolved.hash, destination.hash);

		Identity::forget_destination_in_memory(&destination.hash);
	}
}
