// Reticulum License
//
// Copyright (c) 2016-2025 Mark Qvist
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// - The Software shall not be used in any kind of system which includes amongst
//   its functions the ability to purposefully do harm to human beings.
//
// - The Software shall not be used, directly or indirectly, in the creation of
//   an artificial intelligence, machine learning or language model training
//   dataset, including but not limited to any use that contributes to the
//   training or development of such a model or algorithm.
//
// - The above copyright notice and this permission notice shall be included in
//   all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hkdf::Hkdf;
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use rand::RngCore;
use rmp::encode::write_uint;
use sha2::Sha256;

use crate::identity::{full_hash, HASHLENGTH};
use crate::{host_os, log, LOG_DEBUG, LOG_ERROR, LOG_WARNING};

// ── LXMF proof-of-work stamps ────────────────────────────────────────────────
//
// A direct port of `LXMF/LXStamper.py`, and the single implementation in this
// workspace. `lxmf_rust::lx_stamper` re-exports these rather than keeping its
// own copy: the algorithm is shared with the wider Reticulum network — Python's
// RNS.Discovery validates interface announces with LXMF.LXStamper — so a second
// copy is a second chance to drift out of parity, which is exactly what
// happened once already.
//
// LXMF-layer concerns that need `LXMessage` (PN stamp validation) stay in
// lxmf_rust. Everything protocol-generic lives here.
//
// Verified against Python-generated vectors in the tests below.

pub const STAMP_SIZE: usize = HASHLENGTH / 8;
pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 3000;
pub const WORKBLOCK_EXPAND_ROUNDS_PN: u32 = 1000;
pub const WORKBLOCK_EXPAND_ROUNDS_PEERING: u32 = 25;

static ACTIVE_JOBS: Lazy<Mutex<HashMap<Vec<u8>, Arc<AtomicBool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Expand `material` into the proof-of-work workblock.
///
/// Python:
/// ```text
/// workblock = b""
/// for n in range(expand_rounds):
///     workblock += hkdf(length=256, derive_from=material,
///                       salt=full_hash(material + msgpack.packb(n)))
/// ```
/// so the result is `expand_rounds * 256` bytes, NOT a single digest. The salt
/// uses msgpack's minimal uint encoding, which is what makes rounds past 127
/// line up with Python.
pub fn stamp_workblock(material: &[u8], expand_rounds: u32) -> Vec<u8> {
    let mut workblock = Vec::with_capacity(expand_rounds as usize * 256);

    for n in 0..expand_rounds as u64 {
        let mut packed_n = Vec::new();
        let _ = write_uint(&mut packed_n, n);

        let mut salt_input = Vec::with_capacity(material.len() + packed_n.len());
        salt_input.extend_from_slice(material);
        salt_input.extend_from_slice(&packed_n);
        let salt = full_hash(&salt_input);

        let hkdf = Hkdf::<Sha256>::new(Some(&salt), material);
        let mut derived = vec![0u8; 256];
        if hkdf.expand(&[], &mut derived).is_err() {
            log("HKDF expansion failed while generating stamp workblock".to_string(),
                LOG_ERROR, false, false);
            break;
        }
        workblock.extend_from_slice(&derived);
    }

    workblock
}

/// Number of leading zero bits in `full_hash(workblock || stamp)`.
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    let hash = full_hash(&material);

    let mut value = 0u32;
    for byte in hash.iter() {
        if *byte == 0 {
            value += 8;
        } else {
            value += byte.leading_zeros();
            break;
        }
    }

    value
}

/// Whether `stamp` meets `required_value` against `workblock`.
pub fn stamp_valid(stamp: &[u8], required_value: u32, workblock: &[u8]) -> bool {
    if stamp.len() != STAMP_SIZE {
        return false;
    }
    stamp_value(workblock, stamp) >= required_value
}

pub fn validate_peering_key(peering_id: &[u8], peering_key: &[u8], target_cost: u32) -> bool {
    let workblock = stamp_workblock(peering_id, WORKBLOCK_EXPAND_ROUNDS_PEERING);
    stamp_valid(peering_key, target_cost, &workblock)
}

/// Mine a stamp for `material` meeting `stamp_cost`.
///
/// Returns `(None, 0)` when the search is cancelled via [`cancel_work`] or the
/// worker pool times out — never a stamp that fails its own validator, which an
/// earlier version of this function returned silently after giving up.
pub fn generate_stamp(material: &[u8], stamp_cost: u32, expand_rounds: u32) -> (Option<Vec<u8>>, u32) {
    log(format!("Generating stamp with cost {stamp_cost}"), LOG_DEBUG, false, false);
    let workblock = stamp_workblock(material, expand_rounds);

    let start = Instant::now();
    let (stamp, rounds) = match host_os().as_str() {
        "windows" | "darwin" | "android" => job_simple(stamp_cost, &workblock, material),
        _ => job_parallel(stamp_cost, &workblock, material),
    };

    let duration = start.elapsed().as_secs_f64();
    let speed = if duration > 0.0 { rounds as f64 / duration } else { 0.0 };
    let value = stamp.as_ref().map(|s| stamp_value(&workblock, s)).unwrap_or(0);

    log(format!("Stamp with value {value} generated in {duration:.2}s, {rounds} rounds, {} rounds per second",
                speed as u64), LOG_DEBUG, false, false);

    (stamp, value)
}

/// Ask an in-flight [`generate_stamp`] for `material` to stop.
pub fn cancel_work(material: &[u8]) {
    if let Ok(jobs) = ACTIVE_JOBS.lock() {
        if let Some(stop_flag) = jobs.get(material) {
            stop_flag.store(true, Ordering::SeqCst);
        }
    }
}

fn job_simple(stamp_cost: u32, workblock: &[u8], material: &[u8]) -> (Option<Vec<u8>>, u64) {
    log(format!("Running stamp generation on {}, work limited to single CPU core", host_os()),
        LOG_WARNING, false, false);

    let rounds_start = Instant::now();
    let mut rounds = 0u64;
    let mut stamp = vec![0u8; STAMP_SIZE];

    let stop_flag = Arc::new(AtomicBool::new(false));
    if let Ok(mut jobs) = ACTIVE_JOBS.lock() {
        jobs.insert(material.to_vec(), Arc::clone(&stop_flag));
    }

    loop {
        OsRng.fill_bytes(&mut stamp);
        rounds += 1;

        if stamp_valid(&stamp, stamp_cost, workblock) {
            break;
        }

        if stop_flag.load(Ordering::SeqCst) {
            if let Ok(mut jobs) = ACTIVE_JOBS.lock() { jobs.remove(material); }
            return (None, rounds);
        }

        if rounds % 2500 == 0 {
            let elapsed = rounds_start.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 { rounds as f64 / elapsed } else { 0.0 };
            log(format!("Stamp generation running. {rounds} rounds completed so far, {} rounds per second",
                        speed as u64), LOG_DEBUG, false, false);
        }
    }

    if let Ok(mut jobs) = ACTIVE_JOBS.lock() { jobs.remove(material); }
    (Some(stamp), rounds)
}

fn job_parallel(stamp_cost: u32, workblock: &[u8], material: &[u8]) -> (Option<Vec<u8>>, u64) {
    let cores = thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let jobs_count = if cores <= 12 { cores } else { cores / 2 };
    let stop_flag = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let rounds_total = Arc::new(Mutex::new(0u64));

    if let Ok(mut jobs) = ACTIVE_JOBS.lock() {
        jobs.insert(material.to_vec(), Arc::clone(&stop_flag));
    }

    log(format!("Starting {jobs_count} stamp generation workers"), LOG_DEBUG, false, false);

    for _ in 0..jobs_count {
        let stop = Arc::clone(&stop_flag);
        let sender = tx.clone();
        let wb = workblock.to_vec();
        let rounds_acc = Arc::clone(&rounds_total);
        thread::spawn(move || {
            let mut local_rounds = 0u64;
            let mut stamp = vec![0u8; STAMP_SIZE];
            while !stop.load(Ordering::SeqCst) {
                OsRng.fill_bytes(&mut stamp);
                local_rounds += 1;
                if stamp_valid(&stamp, stamp_cost, &wb) {
                    stop.store(true, Ordering::SeqCst);
                    let _ = sender.send(stamp.clone());
                    break;
                }
            }
            if let Ok(mut total) = rounds_acc.lock() {
                *total += local_rounds;
            }
        });
    }
    drop(tx);

    let stamp = rx.recv_timeout(Duration::from_secs(30)).ok();
    stop_flag.store(true, Ordering::SeqCst);
    if let Ok(mut jobs) = ACTIVE_JOBS.lock() { jobs.remove(material); }

    let total_rounds = rounds_total.lock().map(|g| *g).unwrap_or(0);
    (stamp, total_rounds)
}

// ── Transition aid ───────────────────────────────────────────────────────────

/// The workblock this crate produced before parity with Python was restored:
/// a single 32-byte digest, iterated `expand_rounds` times.
///
/// Retained ONLY so a peer still running the old build can be recognised and
/// named in the logs. Never generate with this.
pub fn legacy_stamp_workblock(material: &[u8], expand_rounds: u32) -> Vec<u8> {
    let mut workblock = full_hash(material);
    for _ in 0..expand_rounds {
        workblock = full_hash(&workblock);
    }
    workblock
}

/// True when `stamp` fails the standard check but satisfies the legacy one —
/// i.e. the sender is running a pre-parity build. A diagnostic, never an
/// acceptance path.
pub fn is_legacy_stamp(material: &[u8], stamp: &[u8], required_value: u32, expand_rounds: u32) -> bool {
    let legacy = legacy_stamp_workblock(material, expand_rounds);
    stamp_valid(stamp, required_value, &legacy)
}

// ── Facade ───────────────────────────────────────────────────────────────────

/// Namespaced access to the functions above, for call sites that read better
/// as `LXStamper::stamp_valid(...)`. Carries no logic of its own.
pub struct LXStamper;

impl LXStamper {
    pub const STAMP_SIZE: usize = STAMP_SIZE;
    pub const WORKBLOCK_EXPAND_ROUNDS: u32 = WORKBLOCK_EXPAND_ROUNDS;
    pub const WORKBLOCK_EXPAND_ROUNDS_PN: u32 = WORKBLOCK_EXPAND_ROUNDS_PN;
    pub const WORKBLOCK_EXPAND_ROUNDS_PEERING: u32 = WORKBLOCK_EXPAND_ROUNDS_PEERING;

    #[inline]
    pub fn stamp_workblock(material: &[u8], expand_rounds: u32) -> Vec<u8> {
        stamp_workblock(material, expand_rounds)
    }
    #[inline]
    pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u32 {
        stamp_value(workblock, stamp)
    }
    #[inline]
    pub fn stamp_valid(stamp: &[u8], required_value: u32, workblock: &[u8]) -> bool {
        stamp_valid(stamp, required_value, workblock)
    }
    #[inline]
    pub fn generate_stamp(material: &[u8], stamp_cost: u32, expand_rounds: u32) -> (Option<Vec<u8>>, u32) {
        generate_stamp(material, stamp_cost, expand_rounds)
    }
    #[inline]
    pub fn is_legacy_stamp(material: &[u8], stamp: &[u8], required_value: u32, expand_rounds: u32) -> bool {
        is_legacy_stamp(material, stamp, required_value, expand_rounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors produced by the reference implementation:
    //   from LXMF import LXStamper
    //   sha256(LXStamper.stamp_workblock(b"rfed-stamp-parity-fixture", expand_rounds=R))
    // If these fail, this crate no longer speaks the same protocol as Python.
    const FIXTURE: &[u8] = b"rfed-stamp-parity-fixture";

    fn sha256_hex(data: &[u8]) -> String {
        full_hash(data).iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn workblock_matches_the_python_reference() {
        let cases: [(u32, usize, &str); 4] = [
            (16,   4096,   "f457e0fe15566fbac513cc02951f5c6fd54adf05b9c368ec63d0855ec1463ebd"),
            (20,   5120,   "cc4db26188fac8b0688ecbdde4c02539e0a14781bc59b9b09294e11f9e48c2ed"),
            (25,   6400,   "9ae5f5d89f3b9c0744cf21816b9fccfefd2d7455527c2d65d3236e89fe76fbd0"),
            // Past 127 rounds the msgpack salt encoding widens; 1000 covers the
            // 1-, 2- and 3-byte forms and is the propagation-node round count.
            (1000, 256000, "6b6f830526fcd3b786513d79b40556d180a5b8b727facd4b1eb0d8425f5ee913"),
        ];

        for (rounds, len, digest) in cases {
            let wb = LXStamper::stamp_workblock(FIXTURE, rounds);
            assert_eq!(wb.len(), len, "workblock length at {rounds} rounds");
            assert_eq!(sha256_hex(&wb), digest, "workblock bytes at {rounds} rounds");
        }
    }

    #[test]
    fn accepts_a_stamp_minted_by_python() {
        // os.urandom stamp mined against stamp_workblock(FIXTURE, 16) at cost 8.
        let stamp = [
            0x5e, 0xb6, 0x46, 0x3a, 0x9f, 0xf6, 0x88, 0x15, 0xe9, 0x97, 0x7d, 0x23,
            0x3a, 0x25, 0x08, 0x0c, 0xc2, 0x25, 0x7a, 0xd8, 0x21, 0xda, 0xd2, 0x98,
            0x17, 0xc5, 0x7b, 0x17, 0x13, 0xd6, 0x07, 0xea,
        ];
        let workblock = LXStamper::stamp_workblock(FIXTURE, 16);
        assert_eq!(LXStamper::stamp_value(&workblock, &stamp), 8);
        assert!(LXStamper::stamp_valid(&stamp, 8, &workblock));
        assert!(!LXStamper::stamp_valid(&stamp, 9, &workblock));
    }

    #[test]
    fn generated_stamps_validate() {
        let (stamp, value) = LXStamper::generate_stamp(FIXTURE, 8, 16);
        let stamp = stamp.expect("generation must succeed at cost 8");
        let workblock = LXStamper::stamp_workblock(FIXTURE, 16);
        assert_eq!(stamp.len(), LXStamper::STAMP_SIZE);
        assert!(value >= 8);
        assert!(LXStamper::stamp_valid(&stamp, 8, &workblock));
    }

    #[test]
    fn a_stamp_for_other_material_is_rejected() {
        let stamp = LXStamper::generate_stamp(b"material-a", 8, 16).0.expect("generated");
        let other = LXStamper::stamp_workblock(b"material-b", 16);
        assert!(!LXStamper::stamp_valid(&stamp, 8, &other));
    }

    #[test]
    fn wrong_length_stamps_are_rejected() {
        let workblock = LXStamper::stamp_workblock(FIXTURE, 16);
        assert!(!LXStamper::stamp_valid(&vec![0u8; LXStamper::STAMP_SIZE - 1], 1, &workblock));
        assert!(!LXStamper::stamp_valid(&vec![0u8; LXStamper::STAMP_SIZE + 1], 1, &workblock));
    }

    #[test]
    fn the_legacy_scheme_is_detectable_and_not_accepted() {
        // A stamp mined the old way must fail the standard check, and be
        // reported as legacy so operators see why.
        let cost = 8;
        let legacy_wb = legacy_stamp_workblock(FIXTURE, 16);
        let mut stamp = vec![0u8; LXStamper::STAMP_SIZE];
        let mut n = 0u64;
        loop {
            stamp[..8].copy_from_slice(&n.to_le_bytes());
            if LXStamper::stamp_value(&legacy_wb, &stamp) >= cost { break; }
            n += 1;
        }

        let standard_wb = LXStamper::stamp_workblock(FIXTURE, 16);
        assert!(!LXStamper::stamp_valid(&stamp, cost, &standard_wb),
            "a legacy stamp must not pass the standard check");
        assert!(LXStamper::is_legacy_stamp(FIXTURE, &stamp, cost, 16),
            "a legacy stamp must be recognisable for the transition warning");

        let good = LXStamper::generate_stamp(FIXTURE, cost, 16).0.expect("generated");
        assert!(!LXStamper::is_legacy_stamp(FIXTURE, &good, cost, 16),
            "a standard stamp must not be misreported as legacy");
    }
}
