use crate::identity;
use crate::packet::{Packet, PROOF, RESOURCE_ADV, RESOURCE_REQ, RESOURCE_HMU, RESOURCE_PRF, RESOURCE_ICL, RESOURCE_RCL, RESOURCE};
use crate::reticulum;
use crate::transport::{Transport, BROADCAST};
use bzip2::read::BzDecoder;
use bzip2::write::BzEncoder;
use bzip2::Compression;
use rmp_serde::{decode::from_slice, encode::to_vec_named};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceStatus {
    None = 0x00,
    Queued = 0x01,
    Advertised = 0x02,
    Transferring = 0x03,
    AwaitingProof = 0x04,
    Assembling = 0x05,
    Complete = 0x06,
    Failed = 0x07,
    Corrupt = 0x08,
    Rejected = 0x09,
}

/// Pre-fetched link state passed to `Resource::accept` / `new_internal` so
/// they can avoid round-tripping through the link-actor channel.  When
/// `accept` is called from the actor's own `receive()` handler, sending a
/// `Snapshot` message would deadlock because the actor can't process its own
/// reply while blocked.
#[derive(Clone, Debug)]
pub struct ResourceLinkContext {
    pub mtu: usize,
    pub rtt: Option<f64>,
    pub traffic_timeout_factor: f64,
    pub establishment_cost: usize,
    pub last_resource_window: Option<usize>,
    pub last_resource_eifr: Option<f64>,
}

pub struct Resource {
    pub status: ResourceStatus,
    pub link: crate::link::LinkHandle,
    pub sdu: usize,
    pub size: usize,
    pub total_size: usize,
    pub uncompressed_size: usize,
    pub compressed_size: usize,
    pub data: Option<Vec<u8>>,
    pub encrypted: bool,
    pub compressed: bool,
    pub initiator: bool,
    pub callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub progress_callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub rtt: Option<f64>,
    pub rtt_rxd_bytes: usize,
    pub req_sent: f64,
    pub req_sent_bytes: usize,
    pub req_resp: Option<f64>,
    pub req_resp_rtt_rate: f64,
    pub rtt_rxd_bytes_at_part_req: usize,
    pub req_data_rtt_rate: f64,
    pub eifr: Option<f64>,
    pub previous_eifr: Option<f64>,
    pub fast_rate_rounds: usize,
    pub very_slow_rate_rounds: usize,
    pub hash: Vec<u8>,
    pub original_hash: Vec<u8>,
    pub random_hash: Vec<u8>,
    pub truncated_hash: Vec<u8>,
    pub expected_proof: Vec<u8>,
    pub parts: Vec<Option<Vec<u8>>>,
    pub packets: Vec<Packet>,
    pub hashmap_raw: Vec<u8>,
    pub hashmap: Vec<u8>,
    pub hashmap_height: usize,
    pub waiting_for_hmu: bool,
    pub receiving_part: bool,
    pub consecutive_completed_height: isize,
    pub total_parts: usize,
    pub received_count: usize,
    pub outstanding_parts: usize,
    pub window: usize,
    pub window_max: usize,
    pub window_min: usize,
    pub window_flexibility: usize,
    pub retries_left: usize,
    pub max_retries: usize,
    pub max_adv_retries: usize,
    pub timeout: f64,
    pub timeout_factor: f64,
    pub part_timeout_factor: f64,
    pub sender_grace_time: f64,
    pub hmu_retry_ok: bool,
    pub watchog_lock: bool,
    pub watchdog_job_id: u64,
    pub adv_sent: f64,
    pub last_activity: f64,
    pub last_part_sent: f64,
    pub sent_parts: usize,
    pub request_id: Option<Vec<u8>>,
    pub started_transferring: Option<f64>,
    pub is_response: bool,
    pub auto_compress: bool,
    pub auto_compress_limit: usize,
    pub auto_compress_option: AutoCompressOption,
    pub req_hashlist: Vec<Vec<u8>>,
    pub receiver_min_consecutive_height: usize,
    pub split: bool,
    pub segment_index: usize,
    pub total_segments: usize,
    pub preparing_next_segment: bool,
    pub next_segment: Option<Arc<Mutex<Resource>>>,
    pub metadata: Vec<u8>,
    pub has_metadata: bool,
    pub metadata_size: usize,
    pub storagepath: Option<PathBuf>,
    pub meta_storagepath: Option<PathBuf>,
    pub input_file: Option<File>,
    pub assembly_lock: bool,
    pub receive_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Copy, Debug)]
pub enum AutoCompressOption {
    Disabled,
    Enabled,
    Limit(usize),
}

impl Resource {
    // Constants
    pub const WINDOW: usize = 4;
    pub const WINDOW_MIN: usize = 2;
    pub const WINDOW_MAX_SLOW: usize = 10;
    pub const WINDOW_MAX_VERY_SLOW: usize = 4;
    pub const WINDOW_MAX_FAST: usize = 75;
    pub const WINDOW_MAX: usize = Self::WINDOW_MAX_FAST;
    pub const FAST_RATE_THRESHOLD: usize = Self::WINDOW_MAX_SLOW - Self::WINDOW - 2;
    pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;
    pub const RATE_FAST: f64 = (50.0 * 1000.0) / 8.0;
    pub const RATE_VERY_SLOW: f64 = (2.0 * 1000.0) / 8.0;
    pub const WINDOW_FLEXIBILITY: usize = 4;
    pub const MAPHASH_LEN: usize = 4;
    pub const SDU: usize = crate::packet::MDU;
    pub const RANDOM_HASH_SIZE: usize = 4;
    pub const MAX_EFFICIENT_SIZE: usize = 1 * 1024 * 1024 - 1;
    pub const RESPONSE_MAX_GRACE_TIME: f64 = 10.0;
    pub const METADATA_MAX_SIZE: usize = 16 * 1024 * 1024 - 1;
    pub const AUTO_COMPRESS_MAX_SIZE: usize = 64 * 1024 * 1024;
    pub const PART_TIMEOUT_FACTOR: f64 = 4.0;
    pub const PART_TIMEOUT_FACTOR_AFTER_RTT: f64 = 2.0;
    pub const PROOF_TIMEOUT_FACTOR: f64 = 3.0;
    pub const MAX_RETRIES: usize = 16;
    pub const MAX_ADV_RETRIES: usize = 4;
    pub const SENDER_GRACE_TIME: f64 = 10.0;
    pub const PROCESSING_GRACE: f64 = 1.0;
    pub const RETRY_GRACE_TIME: f64 = 0.25;
    pub const PER_RETRY_DELAY: f64 = 0.5;
    pub const WATCHDOG_MAX_SLEEP: f64 = 1.0;
    pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
    pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

    fn packet_destination(&self) -> Option<crate::destination::Destination> {
        self.link.build_link_destination().ok()
    }

    pub fn reject(advertisement_packet: &Packet) {
        if let Some(plaintext) = &advertisement_packet.plaintext {
            if let Ok(adv) = ResourceAdvertisement::unpack(plaintext) {
                let resource_hash = adv.h.clone();
                let mut reject_packet = Packet::new(
                    advertisement_packet.destination.clone(),
                    resource_hash,
                    crate::packet::DATA,
                    RESOURCE_RCL,
                    BROADCAST,
                    crate::packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );
                let _ = reject_packet.send();
            }
        }
    }

    pub fn accept(
        advertisement_packet: &Packet,
        link: crate::link::LinkHandle,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        progress_callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        request_id: Option<Vec<u8>>,
        link_ctx: Option<ResourceLinkContext>,
    ) -> Option<Arc<Mutex<Resource>>> {
        let plaintext = advertisement_packet.plaintext.as_ref()?;
        let adv = ResourceAdvertisement::unpack(plaintext).ok()?;
        let mut resource = Resource::new_internal(None, link, None, true, AutoCompressOption::Enabled, callback, progress_callback, None, adv.i as usize, Some(adv.o.clone()), request_id, adv.p, 0, link_ctx.as_ref()).ok()?;

        resource.status = ResourceStatus::Transferring;
        resource.flags_from_adv(&adv);
        resource.size = adv.t as usize;
        resource.total_size = adv.d as usize;
        resource.uncompressed_size = adv.d as usize;
        resource.hash = adv.h.clone();
        resource.original_hash = adv.o.clone();
        resource.random_hash = adv.r.clone();
        resource.hashmap_raw = adv.m.clone();
        resource.encrypted = adv.e;
        resource.compressed = adv.c;
        resource.initiator = false;
        // Use the sender's advertised total_parts (adv.n) directly, NOT a
        // local recalculation from size/sdu.  If our link's MTU differs from
        // the sender's (e.g. because the cloned link fell back to the base
        // MTU), a local ceil(size/sdu) would produce too many parts, causing
        // the receiver to request a hashmap update at a non-boundary index.
        // The Python sender treats that as a sequencing error and cancels.
        resource.total_parts = adv.n as usize;
        crate::log(&format!("[RESOURCE] accept size={} parts={} hash={}",
            resource.size, resource.total_parts,
            crate::hexrep(&resource.hash, false)), crate::LOG_DEBUG, false, false);
        resource.received_count = 0;
        resource.outstanding_parts = 0;
        resource.parts = vec![None; resource.total_parts];
        resource.window = Resource::WINDOW;
        resource.window_max = Resource::WINDOW_MAX_SLOW;
        resource.window_min = Resource::WINDOW_MIN;
        resource.window_flexibility = Resource::WINDOW_FLEXIBILITY;
        resource.last_activity = now();
        resource.started_transferring = Some(resource.last_activity);

        ensure_resource_path();
        let resource_dir = reticulum::resource_path();
        resource.storagepath = Some(resource_dir.join(crate::hexrep(&resource.original_hash, false)));
        resource.meta_storagepath = Some(resource_dir.join(format!("{}.meta", crate::hexrep(&resource.original_hash, false))));
        resource.segment_index = adv.i as usize;
        resource.total_segments = adv.l as usize;
        resource.split = adv.l > 1;
        resource.has_metadata = adv.x;
        resource.hashmap = vec![0u8; resource.total_parts * Resource::MAPHASH_LEN];
        resource.hashmap_height = 0;
        resource.waiting_for_hmu = false;
        resource.receiving_part = false;
        resource.consecutive_completed_height = -1;

        resource.window = if let Some(ctx) = link_ctx.as_ref() {
            ctx.last_resource_window.unwrap_or(resource.window)
        } else {
            resource.link.get_last_resource_window().unwrap_or(resource.window)
        };
        resource.previous_eifr = if let Some(ctx) = link_ctx.as_ref() {
            ctx.last_resource_eifr
        } else {
            resource.link.get_last_resource_eifr()
        };

        let resource = Arc::new(Mutex::new(resource));

        // NOTE: Do NOT register in incoming_resources here.
        // The caller (handle_data_packet) registers after accept() returns,
        // and incoming_resources is shared via Arc — registering here would
        // cause double registration and duplicate receive_part calls.

        // Populate hashmap but DON'T call request_next() yet — we may be
        // inside a link lock (dispatch_runtime_packet) and request_next needs
        // to encrypt via the same link → deadlock.  Instead, populate the
        // hashmap synchronously and defer the network request to a thread.
        if let Ok(mut r) = resource.lock() {
            let hashmap_raw = r.hashmap_raw.clone();
            // Inline the hashmap population without calling request_next
            r.status = ResourceStatus::Transferring;
            let _seg_len = ResourceAdvertisement::HASHMAP_MAX_LEN;
            let hashes = hashmap_raw.len() / Resource::MAPHASH_LEN;
            for i in 0..hashes {
                let idx = i; // segment=0 (0 * seg_len == 0)
                let slice = &hashmap_raw[i * Resource::MAPHASH_LEN..(i + 1) * Resource::MAPHASH_LEN];
                let target_index = idx * Resource::MAPHASH_LEN;
                if target_index + Resource::MAPHASH_LEN <= r.hashmap.len() {
                    if r.hashmap[target_index..target_index + Resource::MAPHASH_LEN].iter().all(|b| *b == 0) {
                        r.hashmap_height += 1;
                    }
                    r.hashmap[target_index..target_index + Resource::MAPHASH_LEN].copy_from_slice(slice);
                }
            }
            r.waiting_for_hmu = false;
        }

        // Spawn request_next in a separate thread so it runs after the caller
        // releases the link lock (avoids encrypt→lock deadlock)
        let resource_for_req = resource.clone();
        thread::spawn(move || {
            // Brief yield to allow the link lock to be released
            thread::sleep(std::time::Duration::from_millis(50));
            if let Ok(mut r) = resource_for_req.lock() {
                r.request_next();
            }
        });

        // Start watchdog with the real Arc so it always sees current state
        Resource::start_watchdog(resource.clone());

        Some(resource)
    }

    pub fn new_internal(
        data: Option<ResourceData>,
        link: crate::link::LinkHandle,
        metadata: Option<Vec<u8>>,
        advertise: bool,
        auto_compress: AutoCompressOption,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        progress_callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        timeout: Option<f64>,
        segment_index: usize,
        original_hash: Option<Vec<u8>>,
        request_id: Option<Vec<u8>>,
        is_response: bool,
        sent_metadata_size: usize,
        link_ctx: Option<&ResourceLinkContext>,
    ) -> Result<Resource, String> {
        let mut resource = Resource {
            status: ResourceStatus::None,
            link,
            sdu: Resource::SDU,
            size: 0,
            total_size: 0,
            uncompressed_size: 0,
            compressed_size: 0,
            data: None,
            encrypted: false,
            compressed: false,
            initiator: false,
            callback,
            progress_callback,
            rtt: None,
            rtt_rxd_bytes: 0,
            req_sent: 0.0,
            req_sent_bytes: 0,
            req_resp: None,
            req_resp_rtt_rate: 0.0,
            rtt_rxd_bytes_at_part_req: 0,
            req_data_rtt_rate: 0.0,
            eifr: None,
            previous_eifr: None,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            hash: Vec::new(),
            original_hash: Vec::new(),
            random_hash: Vec::new(),
            truncated_hash: Vec::new(),
            expected_proof: Vec::new(),
            parts: Vec::new(),
            packets: Vec::new(),
            hashmap_raw: Vec::new(),
            hashmap: Vec::new(),
            hashmap_height: 0,
            waiting_for_hmu: false,
            receiving_part: false,
            consecutive_completed_height: -1,
            total_parts: 0,
            received_count: 0,
            outstanding_parts: 0,
            window: Resource::WINDOW,
            window_max: Resource::WINDOW_MAX_SLOW,
            window_min: Resource::WINDOW_MIN,
            window_flexibility: Resource::WINDOW_FLEXIBILITY,
            retries_left: Resource::MAX_RETRIES,
            max_retries: Resource::MAX_RETRIES,
            max_adv_retries: Resource::MAX_ADV_RETRIES,
            timeout: 0.0,
            timeout_factor: Resource::PART_TIMEOUT_FACTOR,
            part_timeout_factor: Resource::PART_TIMEOUT_FACTOR,
            sender_grace_time: Resource::SENDER_GRACE_TIME,
            hmu_retry_ok: false,
            watchog_lock: false,
            watchdog_job_id: 0,
            adv_sent: 0.0,
            last_activity: 0.0,
            last_part_sent: 0.0,
            sent_parts: 0,
            request_id,
            started_transferring: None,
            is_response,
            auto_compress: matches!(auto_compress, AutoCompressOption::Enabled | AutoCompressOption::Limit(_)),
            auto_compress_limit: Resource::AUTO_COMPRESS_MAX_SIZE,
            auto_compress_option: auto_compress,
            req_hashlist: Vec::new(),
            receiver_min_consecutive_height: 0,
            split: false,
            segment_index,
            total_segments: 1,
            preparing_next_segment: false,
            next_segment: None,
            metadata: Vec::new(),
            has_metadata: false,
            metadata_size: sent_metadata_size,
            storagepath: None,
            meta_storagepath: None,
            input_file: None,
            assembly_lock: false,
            receive_lock: Arc::new(Mutex::new(())),
        };

        // Set SDU from link MTU BEFORE prepare_data, so total_parts is
        // calculated with the same SDU that prepare_outgoing will use.
        // Use pre-fetched link_ctx when available to avoid deadlocking the
        // link actor (accept() is called from within the actor's receive()).
        let link_mtu = link_ctx.map(|c| Some(c.mtu))
            .unwrap_or_else(|| resource.link.snapshot().ok().and_then(|s| s.mtu));
        if let Some(mtu) = link_mtu {
            resource.sdu = mtu.saturating_sub(reticulum::HEADER_MAXSIZE + reticulum::IFAC_MIN_SIZE);
        } else {
            resource.sdu = Resource::SDU;
        }

        resource.prepare_metadata(metadata, sent_metadata_size)?;
        resource.prepare_data(data, original_hash)?;

        resource.max_retries = Resource::MAX_RETRIES;
        resource.max_adv_retries = Resource::MAX_ADV_RETRIES;
        resource.retries_left = resource.max_retries;
        resource.timeout_factor = link_ctx.map(|c| c.traffic_timeout_factor)
            .or_else(|| resource.link.snapshot().ok().map(|s| s.traffic_timeout_factor))
            .unwrap_or(Resource::PART_TIMEOUT_FACTOR);
        resource.part_timeout_factor = Resource::PART_TIMEOUT_FACTOR;
        resource.sender_grace_time = Resource::SENDER_GRACE_TIME;
        resource.hmu_retry_ok = false;
        resource.watchog_lock = false;
        resource.watchdog_job_id = 0;
        resource.rtt = None;
        resource.req_sent = 0.0;
        resource.req_resp_rtt_rate = 0.0;
        resource.req_data_rtt_rate = 0.0;
        resource.eifr = None;
        resource.previous_eifr = None;
        resource.fast_rate_rounds = 0;
        resource.very_slow_rate_rounds = 0;
        resource.receiver_min_consecutive_height = 0;

        resource.timeout = timeout.unwrap_or_else(|| {
            if let Some(ctx) = link_ctx {
                let rtt = ctx.rtt.unwrap_or(0.0);
                rtt * ctx.traffic_timeout_factor
            } else {
                let snap = resource.link.snapshot().ok();
                let rtt = snap.as_ref().and_then(|s| s.rtt).unwrap_or(0.0);
                let ttf = snap.as_ref().map(|s| s.traffic_timeout_factor).unwrap_or(1.0);
                rtt * ttf
            }
        });

        if resource.data.is_some() {
            resource.initiator = true;
            resource.prepare_outgoing(advertise)?;
        } else {
            resource.receive_lock = Arc::new(Mutex::new(()));
        }

        Ok(resource)
    }

    fn prepare_metadata(&mut self, metadata: Option<Vec<u8>>, sent_metadata_size: usize) -> Result<(), String> {
        if let Some(meta) = metadata {
            // Use ByteBuf to serialize as msgpack binary, matching Python's umsgpack behavior
            let packed = to_vec_named(&serde_bytes::ByteBuf::from(meta)).map_err(|e| e.to_string())?;
            if packed.len() > Resource::METADATA_MAX_SIZE {
                return Err("Resource metadata size exceeded".to_string());
            }
            let size_bytes = ((packed.len() as u32) & 0xFFFFFF).to_be_bytes();
            self.metadata = vec![size_bytes[1], size_bytes[2], size_bytes[3]];
            self.metadata.extend_from_slice(&packed);
            self.metadata_size = self.metadata.len();
            self.has_metadata = true;
        } else {
            self.metadata = Vec::new();
            if sent_metadata_size > 0 {
                self.has_metadata = true;
            }
        }
        Ok(())
    }

    fn prepare_data(&mut self, data: Option<ResourceData>, original_hash: Option<Vec<u8>>) -> Result<(), String> {
        let mut resource_data: Option<Vec<u8>> = None;

        if let Some(ResourceData::Bytes(bytes)) = &data {
            let _data_size = bytes.len();
        }

        if let Some(ResourceData::File(mut file)) = data {
            let total_size = file.metadata().map_err(|e| e.to_string())?.len() as usize + self.metadata_size;
            self.total_size = total_size;

            if total_size <= Resource::MAX_EFFICIENT_SIZE {
                self.total_segments = 1;
                self.segment_index = 1;
                self.split = false;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf).map_err(|e| e.to_string())?;
                resource_data = Some(buf);
            } else {
                self.total_segments = (self.total_size - 1) / Resource::MAX_EFFICIENT_SIZE + 1;
                self.segment_index = self.segment_index.max(1);
                self.split = true;

                let seek_index = self.segment_index - 1;
                let first_read_size = Resource::MAX_EFFICIENT_SIZE - self.metadata_size;
                let (seek_position, segment_read_size) = if self.segment_index == 1 {
                    (0u64, first_read_size)
                } else {
                    let seek_position = first_read_size + ((seek_index - 1) * Resource::MAX_EFFICIENT_SIZE);
                    (seek_position as u64, Resource::MAX_EFFICIENT_SIZE)
                };

                file.seek(SeekFrom::Start(seek_position)).map_err(|e| e.to_string())?;
                let mut buf = vec![0u8; segment_read_size];
                let read = file.read(&mut buf).map_err(|e| e.to_string())?;
                buf.truncate(read);
                resource_data = Some(buf);
                self.input_file = Some(file);
            }
        } else if let Some(ResourceData::Bytes(bytes)) = data {
            self.total_size = bytes.len() + self.metadata_size;
            self.total_segments = 1;
            self.segment_index = 1;
            self.split = false;
            resource_data = Some(bytes);
        } else if data.is_none() {
            // Receiving resource
        } else {
            return Err("Invalid data instance type passed to resource initialisation".to_string());
        }

        if let Some(mut rd) = resource_data {
            if self.has_metadata {
                let mut combined = self.metadata.clone();
                combined.append(&mut rd);
                rd = combined;
            }
            self.data = Some(rd);
        }

        if let Some(data) = &self.data {
            self.initiator = true;
            self.uncompressed_size = data.len();
            self.total_size = data.len();

            let uncompressed_payload = data.clone();
            let mut payload = uncompressed_payload.clone();
            let should_compress = match self.auto_compress_option {
                AutoCompressOption::Disabled => false,
                AutoCompressOption::Enabled => data.len() <= self.auto_compress_limit,
                AutoCompressOption::Limit(limit) => data.len() <= limit,
            };

            if should_compress {
                let mut encoder = BzEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(&payload).map_err(|e| e.to_string())?;
                let compressed = encoder.finish().map_err(|e| e.to_string())?;
                if compressed.len() < payload.len() {
                    payload = compressed;
                    self.compressed = true;
                } else {
                    self.compressed = false;
                }
            } else {
                self.compressed = false;
            }

            let mut random = identity::get_random_hash();
            random.truncate(Resource::RANDOM_HASH_SIZE);
            self.random_hash = random.clone();

            let mut hash_material = uncompressed_payload.clone();
            hash_material.extend_from_slice(&self.random_hash);

            self.compressed_size = payload.len();
            self.uncompressed_size = data.len();

            let hash = identity::full_hash(&hash_material);
            self.hash = hash.clone();
            self.truncated_hash = identity::truncated_hash(&hash_material);

            let mut proof_material = uncompressed_payload;
            proof_material.extend_from_slice(&hash);
            self.expected_proof = identity::full_hash(&proof_material);

            self.original_hash = original_hash.unwrap_or_else(|| hash.clone());

            let mut data_with_random = self.random_hash.clone();
            data_with_random.extend_from_slice(&payload);
            self.data = Some(self.link.encrypt(&data_with_random).unwrap_or(data_with_random));
            self.encrypted = true;

            self.size = self.data.as_ref().unwrap().len();
            self.total_parts = ((self.size as f64) / (self.sdu as f64)).ceil() as usize;
        }

        Ok(())
    }

    fn prepare_outgoing(&mut self, advertise: bool) -> Result<(), String> {
        let mut parts = Vec::new();
        let mut hashmap = Vec::new();
        let mut packets = Vec::new();
        let data = self.data.clone().ok_or("Missing resource data")?;

        let mut hashmap_ok = false;
        while !hashmap_ok {
            let mut collision_guard_list: Vec<Vec<u8>> = Vec::new();
            hashmap_ok = true;
            hashmap.clear();
            parts.clear();
            packets.clear();

            for i in 0..self.total_parts {
                let start = i * self.sdu;
                let end = std::cmp::min((i + 1) * self.sdu, data.len());
                let part_data = data[start..end].to_vec();
                let map_hash = self.get_map_hash(&part_data);

                if collision_guard_list.iter().any(|h| h == &map_hash) {
                    hashmap_ok = false;
                    break;
                }

                collision_guard_list.push(map_hash.clone());
                if collision_guard_list.len() > ResourceAdvertisement::COLLISION_GUARD_SIZE {
                    collision_guard_list.remove(0);
                }

                let mut part_packet = Packet::new(
                    self.packet_destination(),
                    part_data.clone(),
                    crate::packet::DATA,
                    RESOURCE,
                    BROADCAST,
                    crate::packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );
                let _ = part_packet.pack();
                part_packet.map_hash = Some(map_hash.clone());

                hashmap.extend_from_slice(&map_hash);
                parts.push(Some(part_data));
                packets.push(part_packet);
            }
        }

        self.parts = parts;
        self.hashmap = hashmap;
        self.packets = packets;

        // Set hashmap_height to the total number of hashmap segments so the
        // sender correctly responds to hashmap-update requests from the
        // receiver.  Without this, hashmap_height stays at 0 and every HMU
        // request is silently rejected, stalling transfers that need more
        // than HASHMAP_MAX_LEN (~74) parts.
        self.hashmap_height = (self.total_parts + ResourceAdvertisement::HASHMAP_MAX_LEN - 1)
            / ResourceAdvertisement::HASHMAP_MAX_LEN;

        if advertise {
            self.advertise();
        }

        Ok(())
    }

    pub fn get_map_hash(&self, data: &[u8]) -> Vec<u8> {
        let mut data_with_random = data.to_vec();
        data_with_random.extend_from_slice(&self.random_hash);
        identity::full_hash(&data_with_random)[..Resource::MAPHASH_LEN].to_vec()
    }

    pub fn advertise(&mut self) {
        let resource = Arc::new(Mutex::new(self.clone()));
        // Clone the Arc so both the locking closure and advertise_job receive
        // the SAME allocation (advertise_job registers it with the link and
        // starts the watchdog, avoiding the stale-clone problem).
        let arc_for_job = resource.clone();
        thread::spawn(move || {
            if let Ok(mut r) = resource.lock() {
                r.advertise_job(arc_for_job);
            }
        });

        if self.segment_index < self.total_segments {
            let resource = Arc::new(Mutex::new(self.clone()));
            thread::spawn(move || {
                if let Ok(mut r) = resource.lock() {
                    r.prepare_next_segment();
                }
            });
        }
    }

    /// Advertise using a shared Arc so that the registered outgoing resource,
    /// the watchdog, and the advertise thread all operate on the SAME instance.
    /// This avoids the stale-clone problem where disconnected copies diverge
    /// in state, causing premature cancellation of large transfers.
    pub fn advertise_shared(resource_arc: Arc<Mutex<Self>>) {
        // Optionally prepare next segment in background
        let needs_next = {
            if let Ok(r) = resource_arc.lock() {
                r.segment_index < r.total_segments
            } else {
                false
            }
        };
        if needs_next {
            let arc_for_prep = resource_arc.clone();
            thread::spawn(move || {
                if let Ok(mut r) = arc_for_prep.lock() {
                    r.prepare_next_segment();
                }
            });
        }

        let arc_for_adv = resource_arc.clone();
        thread::spawn(move || {
            // Wait until the link is ready for a new resource
            loop {
                let ready = {
                    if let Ok(r) = arc_for_adv.lock() {
                        r.link.ready_for_new_resource()
                    } else {
                        return;
                    }
                };
                if ready {
                    break;
                }
                if let Ok(mut r) = arc_for_adv.lock() {
                    r.status = ResourceStatus::Queued;
                }
                thread::sleep(Duration::from_millis(250));
            }

            // Build and send advertisement
            let send_ok = {
                let mut r = match arc_for_adv.lock() {
                    Ok(r) => r,
                    Err(_) => return,
                };
                let adv = ResourceAdvertisement::new_from_resource(&r);
                let packed = adv.pack(0).unwrap_or_default();
                let mut packet = Packet::new(
                    r.packet_destination(),
                    packed,
                    crate::packet::DATA,
                    RESOURCE_ADV,
                    BROADCAST,
                    crate::packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );

                if packet.send().is_ok() {
                    r.last_activity = now();
                    r.started_transferring = Some(r.last_activity);
                    r.adv_sent = r.last_activity;
                    r.rtt = None;
                    r.status = ResourceStatus::Advertised;
                    r.retries_left = r.max_adv_retries;
                    true
                } else {
                    r.cancel();
                    false
                }
            };

            if !send_ok {
                return;
            }

            // Register the SAME Arc with the link (not a clone)
            if let Ok(r) = arc_for_adv.lock() {
                r.link.register_outgoing_resource(arc_for_adv.clone());
            }

            // Start watchdog on the SAME Arc
            Resource::start_watchdog(arc_for_adv);
        });
    }

    /// Drive advertisement on the background thread.
    ///
    /// `self_arc` must be the `Arc<Mutex<Self>>` that wraps `self` so that the
    /// same allocation is registered with the link and handed to the watchdog.
    /// This avoids the stale-clone problem where the link and watchdog would
    /// track a disconnected copy that never sees state updates.
    fn advertise_job(&mut self, self_arc: Arc<Mutex<Self>>) {
        while !self.link.ready_for_new_resource() {
            self.status = ResourceStatus::Queued;
            thread::sleep(Duration::from_millis(250));
        }

        let adv = ResourceAdvertisement::new_from_resource(self);
        let packed = adv.pack(0).unwrap_or_default();
        let mut packet = Packet::new(
            self.packet_destination(),
            packed,
            crate::packet::DATA,
            RESOURCE_ADV,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            0,
        );

        if packet.send().is_ok() {
            self.last_activity = now();
            self.started_transferring = Some(self.last_activity);
            self.adv_sent = self.last_activity;
            self.rtt = None;
            self.status = ResourceStatus::Advertised;
            self.retries_left = self.max_adv_retries;
            // Register the same Arc (not a new clone) so the link and watchdog
            // always see up-to-date state.
            self.link.register_outgoing_resource(self_arc.clone());
        } else {
            self.cancel();
            return;
        }

        // Start watchdog on the same Arc.
        Resource::start_watchdog(self_arc);
    }

    pub fn watchdog_job(&mut self) {
        // Legacy: only used for sender-side resources that already have their own Arc.
        // For receiver-side resources, use start_watchdog() instead.
        let resource = Arc::new(Mutex::new(self.clone()));
        Resource::start_watchdog(resource);
    }

    /// Start the watchdog thread using a shared Arc so it always sees current
    /// resource state. This avoids the stale-clone problem where the watchdog
    /// operates on a frozen copy that never sees received parts.
    pub fn start_watchdog(resource_arc: Arc<Mutex<Self>>) {
        thread::spawn(move || {
            // Assign a new watchdog job ID
            let this_job_id = {
                if let Ok(mut r) = resource_arc.lock() {
                    r.watchdog_job_id += 1;
                    r.watchdog_job_id
                } else {
                    return;
                }
            };

            loop {
                // Lock, read state, compute action, mutate if needed, then unlock before sleeping.
                // IMPORTANT: We must NOT call packet.send() while holding the resource lock,
                // because send() acquires the link lock (via encrypt), and the TCP reader
                // thread acquires locks in the opposite order (link → resource), causing deadlock.
                // Instead, we prepare packets inside the lock and send them after dropping it.
                //
                // NEVER REMOVE EVER — DESIGN_PRINCIPLES §4 (strict ordering).
                //
                // Pre-fetch link state OUTSIDE the resource lock.
                //
                // The link actor handles inbound packets that may need to
                // acquire this resource's lock (via `Resource::receive_part`,
                // `Resource::cancel`, etc.). If the watchdog held the resource
                // lock and then made an mpsc round-trip into the link actor —
                // e.g. via `Link::build_link_destination()` (which is
                // `LinkMsg::BuildLinkDestination`) or `Link::snapshot()`
                // (`LinkMsg::Snapshot`) — and the actor was simultaneously
                // blocked trying to lock the resource, the result is a
                // permanent deadlock. This is the same shape as the RFed
                // 23:11:36 stall (see /memories/repo/rfed-stall-deadlock.md).
                //
                // Solution: clone the LinkHandle (cheap), then build the
                // Destination + LinkSnapshot via mpsc to the actor BEFORE
                // taking the resource lock. The resource lock body uses the
                // pre-fetched values. `Link::status()` is a lock-free atomic
                // and is safe to call anywhere.
                let link = {
                    let r = match resource_arc.lock() {
                        Ok(r) => r,
                        Err(_) => break,
                    };
                    if (r.status as u8) >= (ResourceStatus::Assembling as u8) || this_job_id != r.watchdog_job_id {
                        break;
                    }
                    r.link.clone()
                };

                // Lock-free atomic — safe to call without any lock held.
                let link_status = link.status();
                if link_status == crate::link::STATE_CLOSED || link_status == crate::link::STATE_STALE {
                    if let Ok(mut r) = resource_arc.lock() {
                        r.cancel();
                    }
                    break;
                }

                // mpsc round-trips to the link actor; MUST NOT be done under
                // the resource lock (see comment block above).
                let pkt_dest = link.build_link_destination().ok();
                let link_snapshot = link.snapshot().ok();
                // Build a partial ResourceLinkContext from the snapshot so
                // `update_eifr` does not need to issue its own snapshot mpsc
                // while the resource lock is held. Only the fields actually
                // read by `update_eifr` (rtt, establishment_cost) are
                // populated from the snapshot; the rest take harmless defaults.
                let eifr_ctx = link_snapshot.as_ref().map(|s| ResourceLinkContext {
                    mtu: s.mtu.unwrap_or(0),
                    rtt: s.rtt,
                    traffic_timeout_factor: s.traffic_timeout_factor,
                    establishment_cost: s.establishment_cost,
                    last_resource_window: None,
                    last_resource_eifr: None,
                });

                let (sleep_time, pending_packet) = {
                    let mut r = match resource_arc.lock() {
                        Ok(r) => r,
                        Err(_) => break,
                    };

                    // Re-check termination conditions (state may have changed
                    // while we were doing the unlocked mpsc round-trips above).
                    if (r.status as u8) >= (ResourceStatus::Assembling as u8) || this_job_id != r.watchdog_job_id {
                        break;
                    }

                    // Wait if watchdog is locked (e.g. during receive_part)
                    if r.watchog_lock {
                        drop(r);
                        thread::sleep(Duration::from_millis(25));
                        continue;
                    }

                    match r.status {
                        ResourceStatus::Advertised => {
                            let st = (r.adv_sent + r.timeout + Resource::PROCESSING_GRACE) - now();
                            if st < 0.0 {
                                if r.retries_left == 0 {
                                    r.cancel();
                                    (0.001, None)
                                } else {
                                    r.retries_left -= 1;
                                    let adv = ResourceAdvertisement::new_from_resource(&r);
                                    let packed = adv.pack(0).unwrap_or_default();
                                    let packet = Packet::new(
                                        pkt_dest.clone(),
                                        packed,
                                        crate::packet::DATA,
                                        RESOURCE_ADV,
                                        BROADCAST,
                                        crate::packet::HEADER_1,
                                        None,
                                        None,
                                        false,
                                        0,
                                    );
                                    // Don't send here — defer until lock is dropped
                                    r.last_activity = now();
                                    r.adv_sent = r.last_activity;
                                    (0.001, Some(packet))
                                }
                            } else {
                                (st, None)
                            }
                        }
                        ResourceStatus::Transferring => {
                            if !r.initiator {
                                let retries_used = r.max_retries - r.retries_left;
                                let extra_wait = retries_used as f64 * Resource::PER_RETRY_DELAY;
                                // Pass pre-fetched ctx (built from snapshot above)
                                // so update_eifr does NOT issue an mpsc snapshot
                                // call while we hold the resource lock.
                                r.update_eifr(eifr_ctx.as_ref());
                                let expected_tof_remaining = (r.outstanding_parts as f64 * r.sdu as f64 * 8.0) / r.eifr.unwrap_or(1.0);

                                let st = if r.req_resp_rtt_rate != 0.0 {
                                    r.last_activity + r.part_timeout_factor * expected_tof_remaining + Resource::RETRY_GRACE_TIME + extra_wait - now()
                                } else {
                                    r.last_activity + r.part_timeout_factor * ((3.0 * r.sdu as f64) / r.eifr.unwrap_or(1.0)) + Resource::RETRY_GRACE_TIME + extra_wait - now()
                                };

                                if st < 0.0 {
                                    if r.retries_left > 0 {
                                        if r.window > r.window_min {
                                            r.window -= 1;
                                            if r.window_max > r.window_min {
                                                r.window_max -= 1;
                                                if (r.window_max - r.window) > (r.window_flexibility - 1) {
                                                    r.window_max -= 1;
                                                }
                                            }
                                        }
                                        r.retries_left -= 1;
                                        r.waiting_for_hmu = false;
                                        // Build the RESOURCE_REQ via the
                                        // payload-only path so we do NOT
                                        // round-trip through `packet_destination`
                                        // (which calls Link::build_link_destination
                                        // — an mpsc to the actor) while the
                                        // resource lock is held.
                                        let packet = r.prepare_request_next_data().map(|data| Packet::new(
                                            pkt_dest.clone(),
                                            data,
                                            crate::packet::DATA,
                                            RESOURCE_REQ,
                                            BROADCAST,
                                            crate::packet::HEADER_1,
                                            None,
                                            None,
                                            false,
                                            0,
                                        ));
                                        (0.001, packet)
                                    } else {
                                        r.cancel();
                                        (0.001, None)
                                    }
                                } else {
                                    (st, None)
                                }
                            } else {
                                let max_extra_wait = (0..r.max_retries).map(|x| (x + 1) as f64 * Resource::PER_RETRY_DELAY).sum::<f64>();
                                let max_wait = r.rtt.unwrap_or(0.0) * r.timeout_factor * r.max_retries as f64 + r.sender_grace_time + max_extra_wait;
                                let st = r.last_activity + max_wait - now();
                                if st < 0.0 {
                                    r.cancel();
                                    (0.001, None)
                                } else {
                                    (st, None)
                                }
                            }
                        }
                        ResourceStatus::AwaitingProof => {
                            r.timeout_factor = Resource::PROOF_TIMEOUT_FACTOR;
                            let st = r.last_part_sent + (r.rtt.unwrap_or(0.0) * r.timeout_factor + r.sender_grace_time) - now();
                            if st < 0.0 {
                                if r.retries_left == 0 {
                                    r.cancel();
                                    (0.001, None)
                                } else {
                                    r.retries_left -= 1;
                                    let mut expected_data = r.hash.clone();
                                    expected_data.extend_from_slice(&r.expected_proof);
                                    let mut expected_packet = Packet::new(
                                        pkt_dest.clone(),
                                        expected_data,
                                        PROOF,
                                        RESOURCE_PRF,
                                        BROADCAST,
                                        crate::packet::HEADER_1,
                                        None,
                                        None,
                                        false,
                                        0,
                                    );
                                    let _ = expected_packet.pack();
                                    Transport::cache_request(expected_packet.packet_hash.clone().unwrap_or_default(), r.link.clone());
                                    r.last_part_sent = now();
                                    (0.001, None)
                                }
                            } else {
                                (st, None)
                            }
                        }
                        ResourceStatus::Rejected => (0.001, None),
                        _ => break,
                    }
                };

                // Send any pending packet OUTSIDE the resource lock to avoid
                // deadlock with dispatch_runtime_packet (link → resource).
                if let Some(mut packet) = pending_packet {
                    match packet.send() {
                        Ok(_) => {
                            if let Ok(mut r) = resource_arc.lock() {
                                r.record_request_sent(packet.raw.len());
                            }
                        }
                        Err(e) => {
                            crate::log(&format!("Watchdog packet send failed: {}", e), crate::LOG_ERROR, false, false);
                            if let Ok(mut r) = resource_arc.lock() {
                                r.cancel();
                            }
                        }
                    }
                }

                if sleep_time <= 0.0 {
                    // Negative sleep means we already handled it (cancel, etc.)
                    if let Ok(r) = resource_arc.lock() {
                        if r.status == ResourceStatus::Failed {
                            break;
                        }
                    }
                } else {
                    thread::sleep(Duration::from_secs_f64(sleep_time.min(Resource::WATCHDOG_MAX_SLEEP)));
                }
            }
        });
    }

    /// Update the expected inflight rate.
    ///
    /// `link_ctx` must be supplied when called from the actor thread (e.g. from
    /// `receive_part`) to avoid a `snapshot()` round-trip that would deadlock
    /// the actor.  Pass `None` from external threads (e.g. the watchdog) where
    /// a blocking `snapshot()` is safe.
    pub fn update_eifr(&mut self, link_ctx: Option<&ResourceLinkContext>) {
        // When a pre-fetched context is available use it directly; otherwise
        // call snapshot() which is safe only from non-actor threads.
        let snap = if link_ctx.is_none() { self.link.snapshot().ok() } else { None };
        let ctx_rtt  = link_ctx.and_then(|c| c.rtt);
        let snap_rtt = snap.as_ref().and_then(|s| s.rtt);
        let rtt = self.rtt.unwrap_or_else(|| ctx_rtt.or(snap_rtt).unwrap_or(0.0));
        let ctx_cost  = link_ctx.map(|c| c.establishment_cost as f64);
        let snap_cost = snap.as_ref().map(|s| s.establishment_cost as f64);
        let expected_inflight_rate = if self.req_data_rtt_rate != 0.0 {
            self.req_data_rtt_rate * 8.0
        } else if let Some(prev) = self.previous_eifr {
            prev
        } else if rtt > 0.0 {
            (ctx_cost.or(snap_cost).unwrap_or(0.0) * 8.0) / rtt
        } else {
            0.0
        };

        self.eifr = Some(expected_inflight_rate);
        self.link.set_expected_rate(expected_inflight_rate);
    }

    /// Process HMU packet and update hashmap. Returns true if request_next
    /// should be called (caller must defer to avoid link-mutex deadlock).
    pub fn hashmap_update_packet(&mut self, plaintext: &[u8]) -> bool {
        if self.status != ResourceStatus::Failed {
            self.last_activity = now();
            self.retries_left = self.max_retries;
            if plaintext.len() > identity::HASHLENGTH / 8 {
                // Must use serde_bytes::ByteBuf so rmp-serde deserializes
                // msgpack bin format (sent by Python) into Vec<u8>.
                // Plain Vec<u8> expects msgpack array-of-ints which fails.
                if let Ok(update) = from_slice::<(usize, serde_bytes::ByteBuf)>(&plaintext[identity::HASHLENGTH / 8..]) {
                    eprintln!("[RESOURCE-HMU] parsed segment={} hashmap_len={}", update.0, update.1.len());
                    self.hashmap_update(update.0, &update.1);
                    return true;
                } else {
                    eprintln!("[RESOURCE-HMU] from_slice FAILED, plaintext_len={}", plaintext.len());
                }
            }
        }
        false
    }

    pub fn hashmap_update(&mut self, segment: usize, hashmap: &[u8]) {
        if self.status != ResourceStatus::Failed {
            self.status = ResourceStatus::Transferring;
            let seg_len = ResourceAdvertisement::HASHMAP_MAX_LEN;
            let hashes = hashmap.len() / Resource::MAPHASH_LEN;
            for i in 0..hashes {
                let idx = i + segment * seg_len;
                let slice = &hashmap[i * Resource::MAPHASH_LEN..(i + 1) * Resource::MAPHASH_LEN];
                let target_index = idx * Resource::MAPHASH_LEN;
                if target_index + Resource::MAPHASH_LEN <= self.hashmap.len() {
                    if self.hashmap[target_index..target_index + Resource::MAPHASH_LEN].iter().all(|b| *b == 0) {
                        self.hashmap_height += 1;
                    }
                    self.hashmap[target_index..target_index + Resource::MAPHASH_LEN].copy_from_slice(slice);
                }
            }
            self.waiting_for_hmu = false;
            // NOTE: Do NOT call self.request_next() here.
            // The caller must defer request_next to a background thread
            // to avoid deadlocking the link mutex.
        }
    }

    /// Prepare request_next data while holding the resource lock, but return
    /// the packet so it can be sent OUTSIDE the lock.  This avoids deadlock
    /// with dispatch_runtime_packet which holds the link lock and then tries
    /// to lock the resource for receive_part.
    ///
    /// Returns Some(packet) if a REQ should be sent, None otherwise.
    ///
    /// NOTE: This builds the Packet via `self.packet_destination()`, which
    /// performs an mpsc round-trip to the link actor. **Do NOT call this
    /// from a context where the resource lock is held by a thread that is
    /// not the link actor** — that would deadlock if the actor is blocked
    /// trying to acquire the same resource lock. Use
    /// `prepare_request_next_data()` plus an externally-built destination
    /// in that case (see `link::handle_data_packet`).
    pub fn prepare_request_next(&mut self) -> Option<Packet> {
        let request_data = self.prepare_request_next_data()?;
        Some(Packet::new(
            self.packet_destination(),
            request_data,
            crate::packet::DATA,
            RESOURCE_REQ,
            BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            0,
        ))
    }

    /// Build only the RESOURCE_REQ payload bytes — does NOT touch
    /// `self.link`, so it is safe to call while the resource lock is held
    /// by a non-actor thread. The caller is responsible for constructing
    /// the outgoing `Packet` with a pre-built link `Destination`.
    pub fn prepare_request_next_data(&mut self) -> Option<Vec<u8>> {

        // Both prepare_request_next and receive_part require &mut self, so they
        // can never run concurrently — receiving_part must be false here.
        debug_assert!(!self.receiving_part, "prepare_request_next entered while receive_part was active");

        if self.status == ResourceStatus::Failed || self.waiting_for_hmu {
            return None;
        }

        self.outstanding_parts = 0;
        let mut hashmap_exhausted = Resource::HASHMAP_IS_NOT_EXHAUSTED;
        let mut requested_hashes = Vec::new();

        let mut pn = (self.consecutive_completed_height + 1).max(0) as usize;
        let _search_start = pn;
        let search_size = self.window;

        for _ in 0..search_size {
            if pn >= self.parts.len() {
                break;
            }
            if self.parts[pn].is_none() {
                let idx = pn * Resource::MAPHASH_LEN;
                if idx + Resource::MAPHASH_LEN <= self.hashmap.len() {
                    let part_hash = self.hashmap[idx..idx + Resource::MAPHASH_LEN].to_vec();
                    if !part_hash.iter().all(|b| *b == 0) {
                        requested_hashes.extend_from_slice(&part_hash);
                        self.outstanding_parts += 1;
                    } else {
                        hashmap_exhausted = Resource::HASHMAP_IS_EXHAUSTED;
                    }
                } else {
                    hashmap_exhausted = Resource::HASHMAP_IS_EXHAUSTED;
                }
            }
            pn += 1;
            if self.outstanding_parts >= self.window || hashmap_exhausted == Resource::HASHMAP_IS_EXHAUSTED {
                break;
            }
        }

        let mut hmu_part = vec![hashmap_exhausted];
        if hashmap_exhausted == Resource::HASHMAP_IS_EXHAUSTED {
            let last_idx = (self.hashmap_height.saturating_sub(1)) * Resource::MAPHASH_LEN;
            if last_idx + Resource::MAPHASH_LEN <= self.hashmap.len() {
                hmu_part.extend_from_slice(&self.hashmap[last_idx..last_idx + Resource::MAPHASH_LEN]);
                self.waiting_for_hmu = true;
            }
        }

        let mut request_data = hmu_part;
        request_data.extend_from_slice(&self.hash);
        request_data.extend_from_slice(&requested_hashes);

        Some(request_data)
    }

    /// Record a successful REQ send.
    pub fn record_request_sent(&mut self, raw_len: usize) {
        self.last_activity = now();
        self.req_sent = self.last_activity;
        self.req_sent_bytes = raw_len;
        self.req_resp = None;
    }

    /// Legacy inline request_next — only safe when called from a context
    /// where no link lock is held (e.g. the initial accept thread).
    pub fn request_next(&mut self) {
        if let Some(mut packet) = self.prepare_request_next() {
            match packet.send() {
                Ok(_) => {
                    self.record_request_sent(packet.raw.len());
                }
                Err(e) => {
                    crate::log(&format!("Resource REQ send failed: {}", e), crate::LOG_ERROR, false, false);
                    self.cancel();
                }
            }
        }
    }

    pub fn request(&mut self, request_data: &[u8]) {
        if self.status != ResourceStatus::Failed {
            let rtt = now() - self.adv_sent;
            if self.rtt.is_none() {
                self.rtt = Some(rtt);
            }

            if self.status != ResourceStatus::Transferring {
                self.status = ResourceStatus::Transferring;
                // NOTE: Do NOT start a new watchdog here.  When the resource
                // was advertised via advertise_shared(), the watchdog already
                // runs on the same Arc and will naturally see this status
                // transition.  Starting a second watchdog on a clone would
                // create a stale copy that times out independently.
                //
                // For legacy callers that still use advertise() + advertise_job(),
                // the old watchdog_job() clone chain is unchanged — this just
                // prevents ADDITIONAL watchdog clones on each REQ.
            }

            self.retries_left = self.max_retries;

            let wants_more_hashmap = request_data[0] == Resource::HASHMAP_IS_EXHAUSTED;
            let pad = if wants_more_hashmap { 1 + Resource::MAPHASH_LEN } else { 1 };

            let requested_hashes = &request_data[pad + identity::HASHLENGTH / 8..];
            let mut map_hashes = Vec::new();
            for i in 0..(requested_hashes.len() / Resource::MAPHASH_LEN) {
                let map_hash = requested_hashes[i * Resource::MAPHASH_LEN..(i + 1) * Resource::MAPHASH_LEN].to_vec();
                map_hashes.push(map_hash);
            }

            let mut matched_packets = 0usize;
            let mut fresh_sends = 0usize;
            let mut resends = 0usize;

            for packet in self.packets.iter_mut() {
                if let Some(map_hash) = &packet.map_hash {
                    if map_hashes.iter().any(|h| h == map_hash) {
                        matched_packets += 1;
                        if !packet.sent {
                            let _ = packet.send();
                            self.sent_parts += 1;
                            fresh_sends += 1;
                        } else {
                            let _ = packet.resend();
                            resends += 1;
                        }
                        self.last_activity = now();
                        self.last_part_sent = self.last_activity;
                    }
                }
            }

            crate::log(&format!(
                "[RESOURCE] REQ hash={} hmu={} req={} match={} fresh={} resend={} sent={}/{}",
                crate::hexrep(&self.hash[..4.min(self.hash.len())], false),
                wants_more_hashmap,
                map_hashes.len(),
                matched_packets,
                fresh_sends,
                resends,
                self.sent_parts,
                self.packets.len()
            ), crate::LOG_NOTICE, false, false);

            if wants_more_hashmap {
                let last_map_hash = request_data[1..Resource::MAPHASH_LEN + 1].to_vec();
                let last_index = self
                    .packets
                    .iter()
                    .rposition(|packet| packet.map_hash.as_ref() == Some(&last_map_hash));

                let Some(last_index) = last_index else {
                    crate::log(&format!(
                        "[RESOURCE] HMU FAIL: last_map_hash not found in packets"
                    ), crate::LOG_ERROR, false, false);
                    self.cancel();
                    return;
                };

                let part_index = last_index + 1;
                self.receiver_min_consecutive_height = part_index.saturating_sub(1 + Resource::WINDOW_MAX);

                let segment = if part_index % ResourceAdvertisement::HASHMAP_MAX_LEN == 0 {
                    part_index / ResourceAdvertisement::HASHMAP_MAX_LEN
                } else {
                    (last_index / ResourceAdvertisement::HASHMAP_MAX_LEN) + 1
                };

                crate::log(&format!(
                    "[RESOURCE] HMU check: part_idx={} segment={} hashmap_height={} parts={}",
                    part_index, segment, self.hashmap_height, self.parts.len()
                ), crate::LOG_NOTICE, false, false);

                if segment >= self.hashmap_height {
                    crate::log(&format!(
                        "[RESOURCE] HMU FAIL: segment {} >= hashmap_height {}",
                        segment, self.hashmap_height
                    ), crate::LOG_ERROR, false, false);
                    return;
                }

                let hashmap_start = segment * ResourceAdvertisement::HASHMAP_MAX_LEN;
                let hashmap_end = std::cmp::min((segment + 1) * ResourceAdvertisement::HASHMAP_MAX_LEN, self.parts.len());

                let mut hashmap = Vec::new();
                for i in hashmap_start..hashmap_end {
                    let start = i * Resource::MAPHASH_LEN;
                    let end = start + Resource::MAPHASH_LEN;
                    hashmap.extend_from_slice(&self.hashmap[start..end]);
                }

                // Must wrap Vec<u8> in ByteBuf so rmp-serde serializes as msgpack
                // binary (bin) format instead of array-of-integers, matching Python's
                // umsgpack.packb([segment, hashmap]) where hashmap is bytes.
                let update = to_vec_named(&(segment, serde_bytes::ByteBuf::from(hashmap))).unwrap_or_default();
                let mut hmu = self.hash.clone();
                hmu.extend_from_slice(&update);
                let mut hmu_packet = Packet::new(
                    self.packet_destination(),
                    hmu,
                    crate::packet::DATA,
                    RESOURCE_HMU,
                    BROADCAST,
                    crate::packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );

                match hmu_packet.send() {
                    Ok(_) => {
                        self.last_activity = now();
                        crate::log(&format!(
                            "[RESOURCE] sent HMU segment={} hashes={}",
                            segment,
                            hashmap_end.saturating_sub(hashmap_start)
                        ), crate::LOG_NOTICE, false, false);
                    }
                    Err(e) => {
                        crate::log(&format!("[RESOURCE] HMU send FAILED: {}", e), crate::LOG_ERROR, false, false);
                        self.cancel();
                    }
                }
            }

            if self.sent_parts == self.packets.len() {
                self.status = ResourceStatus::AwaitingProof;
                self.retries_left = 3;
                crate::log(&format!(
                    "[RESOURCE] all parts sent, AwaitingProof sent={}",
                    self.sent_parts
                ), crate::LOG_NOTICE, false, false);
            }

            if let Some(cb) = &self.progress_callback {
                cb(Arc::new(Mutex::new(self.clone())));
            }
        }
    }

    /// Returns (needs_request_next, needs_start_watchdog) so caller can defer
    /// these operations to a background thread (they require link encryption
    /// which would deadlock if called while the link lock is held).
    ///
    /// `link_ctx` must be a pre-fetched snapshot of link state.  It is used
    /// instead of calling `self.link.snapshot()` (which would deadlock when
    /// this method is called from the actor thread).
    pub fn receive_part(&mut self, packet: &Packet, link_ctx: &ResourceLinkContext) -> (bool, bool) {
        let mut start_watchdog = false;
        let mut call_update_eifr = false;
        let mut call_request_next = false;

        {
            let _guard = self.receive_lock.lock().unwrap();
            self.receiving_part = true;
            self.last_activity = now();
            self.retries_left = self.max_retries;

            if self.req_resp.is_none() {
                self.req_resp = Some(self.last_activity);
                let rtt = self.req_resp.unwrap() - self.req_sent;
                self.part_timeout_factor = Resource::PART_TIMEOUT_FACTOR_AFTER_RTT;
                if self.rtt.is_none() {
                    // Use the pre-fetched link context instead of snapshot() to
                    // avoid deadlocking the actor (receive_part is called from
                    // handle_data_packet which runs on the actor thread).
                    self.rtt = link_ctx.rtt;
                    start_watchdog = true;
                } else if let Some(current) = self.rtt {
                    if rtt < current {
                        self.rtt = Some(current - current * 0.05);
                    } else if rtt > current {
                        self.rtt = Some(current + current * 0.05);
                    }
                }

                if rtt > 0.0 {
                    let req_resp_cost = packet.raw.len() + self.req_sent_bytes;
                    self.req_resp_rtt_rate = req_resp_cost as f64 / rtt;

                    if self.req_resp_rtt_rate > Resource::RATE_FAST && self.fast_rate_rounds < Resource::FAST_RATE_THRESHOLD {
                        self.fast_rate_rounds += 1;
                        if self.fast_rate_rounds == Resource::FAST_RATE_THRESHOLD {
                            self.window_max = Resource::WINDOW_MAX_FAST;
                        }
                    }
                }
            }

            if self.status != ResourceStatus::Failed {
                self.status = ResourceStatus::Transferring;
                let part_data = packet.data.clone();
                let part_hash = self.get_map_hash(&part_data);

                let mut _matched = false;
                let mut i = (self.consecutive_completed_height + 1).max(0) as usize;
                for map_hash in self.hashmap_chunks(i, self.window) {
                    if map_hash == part_hash {
                        _matched = true;
                        if self.parts[i].is_none() {
                            self.parts[i] = Some(part_data.clone());
                            self.rtt_rxd_bytes += part_data.len();
                            self.received_count += 1;
                            self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                            if i as isize == self.consecutive_completed_height + 1 {
                                self.consecutive_completed_height = i as isize;
                            }

                            let mut cp = (self.consecutive_completed_height + 1) as usize;
                            while cp < self.parts.len() && self.parts[cp].is_some() {
                                self.consecutive_completed_height = cp as isize;
                                cp += 1;
                            }

                            if let Some(cb) = &self.progress_callback {
                                cb(Arc::new(Mutex::new(self.clone())));
                            }
                        }
                    }
                    i += 1;
                }

                self.receiving_part = false;

                if self.received_count == self.total_parts && !self.assembly_lock {
                    self.assembly_lock = true;
                    // Set status to Assembling on the ORIGINAL resource so the
                    // watchdog (which holds a ref to the original Arc) sees the
                    // transition and exits its loop.  The clone inherits this.
                    self.status = ResourceStatus::Assembling;
                    let resource = Arc::new(Mutex::new(self.clone()));
                    thread::spawn(move || {
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            if let Ok(mut r) = resource.lock() {
                                r.assemble();
                            }
                        }));
                        if let Err(e) = result {
                            crate::log(&format!("Resource assembly thread panicked: {:?}", e), crate::LOG_ERROR, false, false);
                        }
                    });
                } else if self.outstanding_parts == 0 {
                    if self.window < self.window_max {
                        self.window += 1;
                        if (self.window - self.window_min) > (self.window_flexibility - 1) {
                            self.window_min += 1;
                        }
                    }

                    if self.req_sent != 0.0 {
                        let rtt = now() - self.req_sent;
                        let req_transferred = self.rtt_rxd_bytes.saturating_sub(self.rtt_rxd_bytes_at_part_req);
                        if rtt != 0.0 {
                            self.req_data_rtt_rate = req_transferred as f64 / rtt;
                            call_update_eifr = true;
                            self.rtt_rxd_bytes_at_part_req = self.rtt_rxd_bytes;

                            if self.req_data_rtt_rate > Resource::RATE_FAST && self.fast_rate_rounds < Resource::FAST_RATE_THRESHOLD {
                                self.fast_rate_rounds += 1;
                                if self.fast_rate_rounds == Resource::FAST_RATE_THRESHOLD {
                                    self.window_max = Resource::WINDOW_MAX_FAST;
                                }
                            }

                            if self.fast_rate_rounds == 0 && self.req_data_rtt_rate < Resource::RATE_VERY_SLOW && self.very_slow_rate_rounds < Resource::VERY_SLOW_RATE_THRESHOLD {
                                self.very_slow_rate_rounds += 1;
                                if self.very_slow_rate_rounds == Resource::VERY_SLOW_RATE_THRESHOLD {
                                    self.window_max = Resource::WINDOW_MAX_VERY_SLOW;
                                }
                            }
                        }
                    }

                    call_request_next = true;
                }
            } else {
                self.receiving_part = false;
            }
        }

        // update_eifr is called with the pre-fetched link context so it does
        // not call snapshot() and thus does not deadlock the actor thread.
        if call_update_eifr {
            self.update_eifr(Some(link_ctx));
        }
        // Return flags so caller can defer these to a background thread
        // (they require link encryption which deadlocks if the link lock is held)
        (call_request_next, start_watchdog)
    }

    pub fn assemble(&mut self) {
        crate::log(&format!("Resource assembly starting, {} parts",
            self.total_parts), crate::LOG_DEBUG, false, false);
        if self.status != ResourceStatus::Failed {
            self.status = ResourceStatus::Assembling;
            let mut stream = Vec::new();
            for part in &self.parts {
                if let Some(p) = part {
                    stream.extend_from_slice(p);
                }
            }

            let mut data = if self.encrypted {
                match self.link.decrypt(&stream) {
                    Ok(d) => d,
                    Err(_e) => stream
                }
            } else {
                stream
            };

            if data.len() >= Resource::RANDOM_HASH_SIZE {
                data = data[Resource::RANDOM_HASH_SIZE..].to_vec();
            }

            if self.compressed {
                let mut decoder = BzDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                if decoder.read_to_end(&mut decompressed).is_ok() {
                    data = decompressed;
                }
            }

            let calculated_hash = identity::full_hash(&[data.clone(), self.random_hash.clone()].concat());
            if calculated_hash == self.hash {
                // self.data is ALWAYS the full decompressed payload (including
                // metadata prefix if any), matching Python's behavior.
                // prove() hashes self.data+self.hash, so it MUST be complete.
                self.data = Some(data.clone());

                let payload = if self.has_metadata && self.segment_index == 1 {
                    let metadata_size = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
                    let packed_metadata = data[3..3 + metadata_size].to_vec();
                    if let Some(path) = &self.meta_storagepath {
                        if let Ok(mut file) = File::create(path) {
                            let _ = file.write_all(&packed_metadata);
                        }
                    }
                    data[3 + metadata_size..].to_vec()
                } else {
                    data
                };

                if let Some(path) = &self.storagepath {
                    let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
                    let _ = file.write_all(&payload);
                }

                self.status = ResourceStatus::Complete;
                self.prove();

                // For multi-segment (split) resources:
                // - Non-final segments: clear self.data so the link-level
                //   resource_concluded callback skips LXMF parsing
                // - Final segment: replace self.data with the complete
                //   combined file from disk
                if self.split {
                    if self.segment_index == self.total_segments {
                        if let Some(path) = &self.storagepath {
                            match File::open(path) {
                                Ok(mut file) => {
                                    let mut combined = Vec::new();
                                    let _ = file.read_to_end(&mut combined);
                                    self.data = Some(combined);
                                }
                                Err(e) => {
                                    crate::log(&format!("Resource failed to read combined storagepath: {}", e), crate::LOG_ERROR, false, false);
                                    self.data = None;
                                }
                            }
                        } else {
                            self.data = None;
                        }
                    } else {
                        self.data = None;
                    }
                }
            } else {
                self.status = ResourceStatus::Corrupt;
            }

            crate::log(&format!("Resource assembly concluded status={:?} data_len={}",
                self.status, self.data.as_ref().map(|d| d.len()).unwrap_or(0)), crate::LOG_DEBUG, false, false);
            let resource_arc = Arc::new(Mutex::new(self.clone()));
            let concluded_cb = self.link.resource_concluded(resource_arc.clone());
            if let Some(cb) = &concluded_cb {
                cb(resource_arc);
            } else {
                crate::log("Resource concluded but no callback registered", crate::LOG_WARNING, false, false);
            }

            if self.segment_index == self.total_segments {
                if let Some(cb) = &self.callback {
                    if let Some(path) = &self.meta_storagepath {
                        if path.exists() {
                            if let Ok(mut file) = File::open(path) {
                                let mut packed = Vec::new();
                                let _ = file.read_to_end(&mut packed);
                                let _ = fs::remove_file(path);
                                let _ = from_slice::<Vec<u8>>(&packed).map(|meta| {
                                    self.metadata = meta;
                                });
                            }
                        }
                    }

                    if let Some(path) = &self.storagepath {
                        if let Ok(file) = File::open(path) {
                            self.input_file = Some(file);
                        }
                    }

                    cb(Arc::new(Mutex::new(self.clone())));
                }

                if let Some(path) = &self.storagepath {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    pub fn prove(&mut self) {
        if self.status != ResourceStatus::Failed {
            let proof = identity::full_hash(&[self.data.clone().unwrap_or_default(), self.hash.clone()].concat());
            let mut proof_data = self.hash.clone();
            proof_data.extend_from_slice(&proof);
            let mut packet = Packet::new(
                self.packet_destination(),
                proof_data,
                PROOF,
                RESOURCE_PRF,
                BROADCAST,
                crate::packet::HEADER_1,
                None,
                None,
                false,
                0,
            );
            if packet.send().is_ok() {
                Transport::cache(&packet, true, Some("resource".to_string()));
            } else {
                self.cancel();
            }
        }
    }

    pub fn validate_proof(&mut self, proof_data: &[u8]) {
        crate::log(&format!("[RESOURCE] validate_proof status={:?} seg={}/{} proof_len={} expected_len={}", self.status, self.segment_index, self.total_segments, proof_data.len(), identity::HASHLENGTH / 8 * 2), crate::LOG_NOTICE, false, false);
        if self.status != ResourceStatus::Failed {
            if proof_data.len() == identity::HASHLENGTH / 8 * 2 {
                if &proof_data[identity::HASHLENGTH / 8..] == self.expected_proof.as_slice() {
                    crate::log("[RESOURCE] proof MATCHED, setting Complete", crate::LOG_NOTICE, false, false);
                    self.status = ResourceStatus::Complete;
                    let resource_arc = Arc::new(Mutex::new(self.clone()));
                    let concluded_cb = self.link.resource_concluded(resource_arc.clone());
                    if let Some(cb) = concluded_cb {
                        cb(resource_arc);
                    }
                    crate::log(&format!("[RESOURCE] resource_concluded done, seg={}/{}", self.segment_index, self.total_segments), crate::LOG_NOTICE, false, false);

                    if self.segment_index == self.total_segments {
                        let has_cb = self.callback.is_some();
                        crate::log(&format!("[RESOURCE] final segment, has_callback={}", has_cb), crate::LOG_NOTICE, false, false);
                        if let Some(cb) = &self.callback {
                            cb(Arc::new(Mutex::new(self.clone())));
                            crate::log("[RESOURCE] resource callback returned", crate::LOG_NOTICE, false, false);
                        }

                        if let Some(file) = &mut self.input_file {
                            let _ = file.sync_all();
                        }
                    } else {
                        if !self.preparing_next_segment {
                            self.prepare_next_segment();
                        }
                        while self.next_segment.is_none() {
                            thread::sleep(Duration::from_millis(50));
                        }
                        if let Some(next) = &self.next_segment {
                            Resource::advertise_shared(next.clone());
                        }
                    }
                } else {
                    crate::log(
                        &format!(
                            "[RESOURCE] proof MISMATCH hash={} expected={} got={}",
                            crate::hexrep(&self.hash, false),
                            crate::hexrep(&self.expected_proof, false),
                            crate::hexrep(&proof_data[identity::HASHLENGTH / 8..], false)
                        ), crate::LOG_WARNING, false, false,
                    );
                }
            } else {
                crate::log(&format!("[RESOURCE] unexpected proof length={} for hash={}", proof_data.len(), crate::hexrep(&self.hash, false)), crate::LOG_WARNING, false, false);
            }
        } else {
            crate::log("[RESOURCE] skipping validate_proof: status is Failed", crate::LOG_WARNING, false, false);
        }
    }

    pub fn cancel(&mut self) {
        if (self.status as u8) < (ResourceStatus::Complete as u8) {
            self.status = ResourceStatus::Failed;
            if self.initiator {
                if self.link.is_active() {
                    let mut packet = Packet::new(
                        self.packet_destination(),
                        self.hash.clone(),
                        crate::packet::DATA,
                        RESOURCE_ICL,
                        BROADCAST,
                        crate::packet::HEADER_1,
                        None,
                        None,
                        false,
                        0,
                    );
                    let _ = packet.send();
                }
                self.link.cancel_outgoing_resource(Arc::new(Mutex::new(self.clone())));
            } else {
                self.link.cancel_incoming_resource(Arc::new(Mutex::new(self.clone())));
            }

            if let Some(cb) = &self.callback {
                let resource_arc = Arc::new(Mutex::new(self.clone()));
                let concluded_cb = self.link.resource_concluded(resource_arc.clone());
                if let Some(ccb) = concluded_cb {
                    ccb(resource_arc.clone());
                }
                cb(Arc::new(Mutex::new(self.clone())));
            }
        }
    }

    pub fn rejected(&mut self) {
        if (self.status as u8) < (ResourceStatus::Complete as u8) {
            if self.initiator {
                self.status = ResourceStatus::Rejected;
                self.link.cancel_outgoing_resource(Arc::new(Mutex::new(self.clone())));
                if let Some(cb) = &self.callback {
                    let resource_arc = Arc::new(Mutex::new(self.clone()));
                    let concluded_cb = self.link.resource_concluded(resource_arc.clone());
                    if let Some(ccb) = concluded_cb {
                        ccb(resource_arc.clone());
                    }
                    cb(Arc::new(Mutex::new(self.clone())));
                }
            }
        }
    }

    pub fn set_callback(&mut self, callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>) {
        self.callback = callback;
    }

    pub fn set_progress_callback(&mut self, callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>) {
        self.progress_callback = callback;
    }

    pub fn get_progress(&mut self) -> f64 {
        if self.status == ResourceStatus::Complete && self.segment_index == self.total_segments {
            return 1.0;
        }

        let (processed_parts, progress_total_parts) = if self.initiator {
            if !self.split {
                (self.sent_parts as f64, self.total_parts as f64)
            } else {
                let processed_segments = self.segment_index - 1;
                let max_parts_per_segment = (Resource::MAX_EFFICIENT_SIZE as f64 / self.sdu as f64).ceil();
                let previously_processed_parts = processed_segments as f64 * max_parts_per_segment;
                let current_segment_factor = if self.total_parts < max_parts_per_segment as usize {
                    max_parts_per_segment / self.total_parts as f64
                } else {
                    1.0
                };
                (
                    previously_processed_parts + self.sent_parts as f64 * current_segment_factor,
                    self.total_segments as f64 * max_parts_per_segment,
                )
            }
        } else {
            if !self.split {
                (self.received_count as f64, self.total_parts as f64)
            } else {
                let processed_segments = self.segment_index - 1;
                let max_parts_per_segment = (Resource::MAX_EFFICIENT_SIZE as f64 / self.sdu as f64).ceil();
                let previously_processed_parts = processed_segments as f64 * max_parts_per_segment;
                let current_segment_factor = if self.total_parts < max_parts_per_segment as usize {
                    max_parts_per_segment / self.total_parts as f64
                } else {
                    1.0
                };
                (
                    previously_processed_parts + self.received_count as f64 * current_segment_factor,
                    self.total_segments as f64 * max_parts_per_segment,
                )
            }
        };

        (processed_parts / progress_total_parts).min(1.0)
    }

    pub fn get_segment_progress(&self) -> f64 {
        if self.status == ResourceStatus::Complete && self.segment_index == self.total_segments {
            1.0
        } else {
            let processed = if self.initiator { self.sent_parts } else { self.received_count };
            (processed as f64 / self.total_parts as f64).min(1.0)
        }
    }

    pub fn get_transfer_size(&self) -> usize {
        self.size
    }

    pub fn get_data_size(&self) -> usize {
        self.total_size
    }

    pub fn get_parts(&self) -> usize {
        self.total_parts
    }

    pub fn get_segments(&self) -> usize {
        self.total_segments
    }

    pub fn get_hash(&self) -> Vec<u8> {
        self.hash.clone()
    }

    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    fn prepare_next_segment(&mut self) {
        self.preparing_next_segment = true;
        let next = Resource::new_internal(
            self.input_file.take().map(ResourceData::File),
            self.link.clone(),
            None,
            false,
            self.auto_compress_option,
            self.callback.clone(),
            self.progress_callback.clone(),
            Some(self.timeout),
            self.segment_index + 1,
            Some(self.original_hash.clone()),
            self.request_id.clone(),
            self.is_response,
            self.metadata_size,
            None,
        );
        if let Ok(next) = next {
            self.next_segment = Some(Arc::new(Mutex::new(next)));
        }
    }

    fn hashmap_chunks(&self, start: usize, count: usize) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        for i in start..(start + count) {
            let idx = i * Resource::MAPHASH_LEN;
            if idx + Resource::MAPHASH_LEN <= self.hashmap.len() {
                chunks.push(self.hashmap[idx..idx + Resource::MAPHASH_LEN].to_vec());
            }
        }
        chunks
    }

    fn flags_from_adv(&mut self, adv: &ResourceAdvertisement) {
        self.has_metadata = adv.x;
    }
}

impl Clone for Resource {
    fn clone(&self) -> Self {
        Resource {
            status: self.status,
            link: self.link.clone(),
            sdu: self.sdu,
            size: self.size,
            total_size: self.total_size,
            uncompressed_size: self.uncompressed_size,
            compressed_size: self.compressed_size,
            data: self.data.clone(),
            encrypted: self.encrypted,
            compressed: self.compressed,
            initiator: self.initiator,
            callback: self.callback.clone(),
            progress_callback: self.progress_callback.clone(),
            rtt: self.rtt,
            rtt_rxd_bytes: self.rtt_rxd_bytes,
            req_sent: self.req_sent,
            req_sent_bytes: self.req_sent_bytes,
            req_resp: self.req_resp,
            req_resp_rtt_rate: self.req_resp_rtt_rate,
            rtt_rxd_bytes_at_part_req: self.rtt_rxd_bytes_at_part_req,
            req_data_rtt_rate: self.req_data_rtt_rate,
            eifr: self.eifr,
            previous_eifr: self.previous_eifr,
            fast_rate_rounds: self.fast_rate_rounds,
            very_slow_rate_rounds: self.very_slow_rate_rounds,
            hash: self.hash.clone(),
            original_hash: self.original_hash.clone(),
            random_hash: self.random_hash.clone(),
            truncated_hash: self.truncated_hash.clone(),
            expected_proof: self.expected_proof.clone(),
            parts: self.parts.clone(),
            packets: self.packets.clone(),
            hashmap_raw: self.hashmap_raw.clone(),
            hashmap: self.hashmap.clone(),
            hashmap_height: self.hashmap_height,
            waiting_for_hmu: self.waiting_for_hmu,
            receiving_part: self.receiving_part,
            consecutive_completed_height: self.consecutive_completed_height,
            total_parts: self.total_parts,
            received_count: self.received_count,
            outstanding_parts: self.outstanding_parts,
            window: self.window,
            window_max: self.window_max,
            window_min: self.window_min,
            window_flexibility: self.window_flexibility,
            retries_left: self.retries_left,
            max_retries: self.max_retries,
            max_adv_retries: self.max_adv_retries,
            timeout: self.timeout,
            timeout_factor: self.timeout_factor,
            part_timeout_factor: self.part_timeout_factor,
            sender_grace_time: self.sender_grace_time,
            hmu_retry_ok: self.hmu_retry_ok,
            watchog_lock: self.watchog_lock,
            watchdog_job_id: self.watchdog_job_id,
            adv_sent: self.adv_sent,
            last_activity: self.last_activity,
            last_part_sent: self.last_part_sent,
            sent_parts: self.sent_parts,
            request_id: self.request_id.clone(),
            started_transferring: self.started_transferring,
            is_response: self.is_response,
            auto_compress: self.auto_compress,
            auto_compress_limit: self.auto_compress_limit,
            auto_compress_option: self.auto_compress_option,
            req_hashlist: self.req_hashlist.clone(),
            receiver_min_consecutive_height: self.receiver_min_consecutive_height,
            split: self.split,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            preparing_next_segment: self.preparing_next_segment,
            next_segment: self.next_segment.clone(),
            metadata: self.metadata.clone(),
            has_metadata: self.has_metadata,
            metadata_size: self.metadata_size,
            storagepath: self.storagepath.clone(),
            meta_storagepath: self.meta_storagepath.clone(),
            input_file: None,
            assembly_lock: self.assembly_lock,
            receive_lock: self.receive_lock.clone(),
        }
    }
}

pub enum ResourceData {
    Bytes(Vec<u8>),
    File(File),
}

pub struct ResourceAdvertisement {
    pub t: u64,
    pub d: u64,
    pub n: u64,
    pub h: Vec<u8>,
    pub r: Vec<u8>,
    pub o: Vec<u8>,
    pub i: u64,
    pub l: u64,
    pub q: Option<Vec<u8>>,
    pub f: u8,
    pub m: Vec<u8>,
    pub e: bool,
    pub c: bool,
    pub s: bool,
    pub u: bool,
    pub p: bool,
    pub x: bool,
}

impl ResourceAdvertisement {
    pub const OVERHEAD: usize = 134;
    pub const HASHMAP_MAX_LEN: usize = (crate::link::MDU - Self::OVERHEAD) / Resource::MAPHASH_LEN;
    pub const COLLISION_GUARD_SIZE: usize = 2 * Resource::WINDOW_MAX + Self::HASHMAP_MAX_LEN;

    pub fn new_from_resource(resource: &Resource) -> Self {
        let mut adv = ResourceAdvertisement {
            t: resource.size as u64,
            d: resource.total_size as u64,
            n: resource.total_parts as u64,
            h: resource.hash.clone(),
            r: resource.random_hash.clone(),
            o: resource.original_hash.clone(),
            i: resource.segment_index as u64,
            l: resource.total_segments as u64,
            q: resource.request_id.clone(),
            f: 0,
            m: resource.hashmap.clone(),
            e: resource.encrypted,
            c: resource.compressed,
            s: resource.split,
            u: false,
            p: false,
            x: resource.has_metadata,
        };

        if adv.q.is_some() {
            if !resource.is_response {
                adv.u = true;
            } else {
                adv.p = true;
            }
        }

        adv.f = 0x00 | ((adv.x as u8) << 5) | ((adv.p as u8) << 4) | ((adv.u as u8) << 3) | ((adv.s as u8) << 2) | ((adv.c as u8) << 1) | (adv.e as u8);
        adv
    }

    pub fn is_request(advertisement_packet: &Packet) -> bool {
        advertisement_packet
            .plaintext
            .as_ref()
            .and_then(|p| ResourceAdvertisement::unpack(p).ok())
            .map(|adv| adv.q.is_some() && adv.u)
            .unwrap_or(false)
    }

    pub fn is_response(advertisement_packet: &Packet) -> bool {
        advertisement_packet
            .plaintext
            .as_ref()
            .and_then(|p| ResourceAdvertisement::unpack(p).ok())
            .map(|adv| adv.q.is_some() && adv.p)
            .unwrap_or(false)
    }

    pub fn read_request_id(advertisement_packet: &Packet) -> Option<Vec<u8>> {
        advertisement_packet
            .plaintext
            .as_ref()
            .and_then(|p| ResourceAdvertisement::unpack(p).ok())
            .and_then(|adv| adv.q)
    }

    pub fn read_transfer_size(advertisement_packet: &Packet) -> Option<u64> {
        advertisement_packet
            .plaintext
            .as_ref()
            .and_then(|p| ResourceAdvertisement::unpack(p).ok())
            .map(|adv| adv.t)
    }

    pub fn read_size(advertisement_packet: &Packet) -> Option<u64> {
        advertisement_packet
            .plaintext
            .as_ref()
            .and_then(|p| ResourceAdvertisement::unpack(p).ok())
            .map(|adv| adv.d)
    }

    pub fn pack(&self, segment: usize) -> Result<Vec<u8>, String> {
        let hashmap_start = segment * ResourceAdvertisement::HASHMAP_MAX_LEN;
        let hashmap_end = std::cmp::min((segment + 1) * ResourceAdvertisement::HASHMAP_MAX_LEN, self.n as usize);
        let mut hashmap = Vec::new();
        for i in hashmap_start..hashmap_end {
            let start = i * Resource::MAPHASH_LEN;
            let end = start + Resource::MAPHASH_LEN;
            hashmap.extend_from_slice(&self.m[start..end]);
        }

        let wire = ResourceAdvertisementData {
            t: self.t,
            d: self.d,
            n: self.n,
            h: self.h.clone(),
            r: self.r.clone(),
            o: self.o.clone(),
            i: self.i,
            l: self.l,
            q: self.q.clone(),
            f: self.f,
            m: hashmap,
            e: false,
            c: false,
            s: false,
            u: false,
            p: false,
            x: false,
        };
        to_vec_named(&wire).map_err(|e| e.to_string())
    }

    pub fn unpack(data: &[u8]) -> Result<ResourceAdvertisement, String> {
        let mut adv = from_slice::<ResourceAdvertisementData>(data).map_err(|e| {
            crate::log(&format!("[RESOURCE-ADV-UNPACK] failed: {} first_bytes={}",
                e,
                if data.len() >= 8 { crate::hexrep(&data[..8], false) } else { crate::hexrep(data, false) }
            ), crate::LOG_NOTICE, false, false);
            e.to_string()
        })?;
        adv.apply_flags();
        Ok(ResourceAdvertisement {
            t: adv.t,
            d: adv.d,
            n: adv.n,
            h: adv.h,
            r: adv.r,
            o: adv.o,
            i: adv.i,
            l: adv.l,
            q: adv.q,
            f: adv.f,
            m: adv.m,
            e: adv.e,
            c: adv.c,
            s: adv.s,
            u: adv.u,
            p: adv.p,
            x: adv.x,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceAdvertisementData {
    pub t: u64,
    pub d: u64,
    pub n: u64,
	#[serde(with = "serde_bytes")]
    pub h: Vec<u8>,
	#[serde(with = "serde_bytes")]
    pub r: Vec<u8>,
	#[serde(with = "serde_bytes")]
    pub o: Vec<u8>,
    pub i: u64,
    pub l: u64,
	#[serde(default, serialize_with = "serialize_optional_bytes", deserialize_with = "deserialize_optional_bytes")]
    pub q: Option<Vec<u8>>,
    pub f: u8,
	#[serde(with = "serde_bytes")]
    pub m: Vec<u8>,
    #[serde(skip)]
    pub e: bool,
    #[serde(skip)]
    pub c: bool,
    #[serde(skip)]
    pub s: bool,
    #[serde(skip)]
    pub u: bool,
    #[serde(skip)]
    pub p: bool,
    #[serde(skip)]
    pub x: bool,
}

fn serialize_optional_bytes<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(bytes) => serializer.serialize_some(&serde_bytes::Bytes::new(bytes)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_bytes::ByteBuf>::deserialize(deserializer)?;
    Ok(value.map(|bytes| bytes.into_vec()))
}

impl ResourceAdvertisementData {
    pub fn apply_flags(&mut self) {
        self.e = (self.f & 0x01) == 0x01;
        self.c = ((self.f >> 1) & 0x01) == 0x01;
        self.s = ((self.f >> 2) & 0x01) == 0x01;
        self.u = ((self.f >> 3) & 0x01) == 0x01;
        self.p = ((self.f >> 4) & 0x01) == 0x01;
        self.x = ((self.f >> 5) & 0x01) == 0x01;
    }
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn ensure_resource_path() {
    let path = reticulum::resource_path();
    if !path.exists() {
        let _ = fs::create_dir_all(&path);
    }
}
