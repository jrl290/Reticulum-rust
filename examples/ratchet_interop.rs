//! Interop harness for ratchets: the Rust end.
//!
//! `tests/interop/ratchet_interop.py run` (through `tests/interop/ratchet_run.sh`)
//! drives this binary and a Python reference peer through a Python reference
//! transport node over loopback TCP. See that script for the scenarios.
//!
//!   ratchet_interop node <config_dir> <state_dir>
//!
//! One process owns one IN SINGLE destination `interop.ratchet` with ratchets
//! enabled. Its identity and ratchet file live in `<state_dir>`, so a second
//! run of the same state dir is a restart of the same destination.
//!
//! As an application does, the process registers a clone of its destination
//! with Transport and keeps its own copy (the "app copy", the role
//! LXMRouter's copy plays): Transport answers path requests from a clone of
//! the registered copy, and the app copy announces and rotates on its own.
//!
//! Commands on stdin, one per line; every reply is a line starting `@@`
//! (everything else on stdout is the stack's log):
//!
//!   ANNOUNCE            app copy announces (broadcast)      -> @@ANNOUNCED rotated=<0|1> ratchet=<pub> list=<pubs>
//!   ROTATE_SILENT       app copy builds an announce, unsent -> @@ROTATED   rotated=<0|1> ratchet=<pub> list=<pubs>
//!   LISTS               app copy's list (synced through rotate_ratchets, as its
//!                       next announce would) and the ratchet file's list
//!                                                           -> @@LISTS rotated=<0|1> app=<pubs> file=<pubs>
//!   SEND <hash> <tag>   encrypt one packet to a peer's announced ratchet, prove it
//!                                                           -> @@SENDING <tag> ratchet=<pub|none>, then
//!                                                              @@PROVEN <tag> ms=<n> | @@UNPROVEN <tag> <why>
//!   QUIT
//!
//! Unprompted: `@@DEST <hash> list=<pubs>` once registered, `@@RX <tag>` for
//! each packet the destination decrypts. <pubs> is comma-separated ratchet
//! public keys in hex, newest first ("-" when empty).

use std::collections::HashSet;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use reticulum_rust::destination::{Destination, DestinationType, PROVE_ALL};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{Packet, PacketReceipt};
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::{AnnounceHandler, Transport};

const APP_NAME: &str = "interop";
const ASPECT: &str = "ratchet";
/// The Python peer's own destination (scenario d).
const PEER_ASPECT: &str = "ratchet_py";

/// Hashes of `interop.ratchet_py` destinations heard announcing, and the
/// condvar a SEND waits on for its peer's announce.
static HEARD: Lazy<(Mutex<HashSet<Vec<u8>>>, Condvar)> = Lazy::new(|| (Mutex::new(HashSet::new()), Condvar::new()));

fn hex(b: &[u8]) -> String {
    reticulum_rust::hexrep(b, false)
}

fn pubs(list: &[Vec<u8>]) -> String {
    if list.is_empty() {
        return "-".to_string();
    }
    list.iter()
        .map(|prv| Identity::ratchet_public_bytes(prv).map(|p| hex(&p)).unwrap_or_else(|e| format!("<bad:{e}>")))
        .collect::<Vec<_>>()
        .join(",")
}

fn say(line: String) {
    println!("@@{line}");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("node") if args.len() == 4 => node(PathBuf::from(&args[2]), PathBuf::from(&args[3])),
        _ => {
            eprintln!("usage: node <config_dir> <state_dir>");
            std::process::exit(2);
        }
    }
}

/// The ratchet private keys in a ratchet file, as `_persist_ratchets` wrote
/// them: msgpack {"signature": bin, "ratchets": bin(msgpack [ratchet, ...])}.
fn file_ratchets(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let outer = rmpv::decode::read_value(&mut &data[..]).map_err(|e| format!("outer: {e}"))?;
    let packed = outer
        .as_map()
        .and_then(|m| m.iter().find(|(k, _)| k.as_str() == Some("ratchets")))
        .and_then(|(_, v)| v.as_slice())
        .ok_or("no ratchets entry")?;
    let inner = rmpv::decode::read_value(&mut &packed[..]).map_err(|e| format!("inner: {e}"))?;
    inner
        .as_array()
        .ok_or("ratchets is not an array")?
        .iter()
        .map(|v| {
            // Each ratchet is bin, as the reference writes it; this stack
            // wrote arrays of ints until 2026-09-27. Read either.
            if let Some(b) = v.as_slice() {
                return Ok(b.to_vec());
            }
            v.as_array()
                .ok_or_else(|| "ratchet is neither bin nor an array".to_string())?
                .iter()
                .map(|x| x.as_u64().filter(|n| *n <= 255).map(|n| n as u8).ok_or_else(|| "ratchet array holds a non-byte".to_string()))
                .collect()
        })
        .collect()
}

fn node(config_dir: PathBuf, state_dir: PathBuf) {
    Reticulum::init(Some(config_dir), None, None, None, false, None).expect("Reticulum init");
    // NOTICE: the harness reads "[PR-SELF]", "[DEST-RX]" and "[RATCHET] decrypt
    // failed ... reloading" from the log.
    reticulum_rust::set_loglevel(reticulum_rust::LOG_NOTICE);

    std::fs::create_dir_all(&state_dir).expect("state dir");
    let identity_path = state_dir.join("identity");
    let identity = if identity_path.exists() {
        Identity::from_file(&identity_path).expect("load identity")
    } else {
        let identity = Identity::new(true);
        identity.to_file(&identity_path).expect("save identity");
        identity
    };
    let ratchet_path = state_dir.join("ratchets");

    let mut app = Destination::new_inbound(Some(identity), DestinationType::Single, APP_NAME.to_string(), vec![ASPECT.to_string()])
        .expect("create destination");
    app.enable_ratchets(ratchet_path.to_string_lossy().into_owned()).expect("enable ratchets");
    app.set_proof_strategy(PROVE_ALL).expect("proof strategy");
    app.set_packet_callback(Some(Arc::new(|plaintext: &[u8], _packet: &Packet| {
        say(format!("RX {}", String::from_utf8_lossy(plaintext)));
    })));

    Transport::register_announce_handler(AnnounceHandler {
        aspect_filter: Some(format!("{APP_NAME}.{PEER_ASPECT}")),
        receive_path_responses: true,
        callback: Arc::new(|destination_hash: &[u8], _identity, _app_data, _packet_hash, _is_path_response| {
            let (heard, cv) = &*HEARD;
            heard.lock().unwrap().insert(destination_hash.to_vec());
            cv.notify_all();
        }),
    });

    // Registered BEFORE the app copy's first announce, as applications do: the
    // registered copy holds the list the file had at start.
    Transport::register_destination(app.clone());
    say(format!("DEST {} list={}", hex(&app.hash), pubs(app.ratchets.as_deref().unwrap_or(&[]))));

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["ANNOUNCE"] | ["ROTATE_SILENT"] => {
                let send = words[0] == "ANNOUNCE";
                let before = app.ratchets.clone().unwrap_or_default();
                if let Err(e) = app.announce(None, false, None, None, send) {
                    say(format!("ERROR announce: {e}"));
                    continue;
                }
                let after = app.ratchets.clone().unwrap_or_default();
                let rotated = after.first() != before.first();
                say(format!(
                    "{} rotated={} ratchet={} list={}",
                    if send { "ANNOUNCED" } else { "ROTATED" },
                    rotated as u8,
                    after.first().map(|r| pubs(std::slice::from_ref(r))).unwrap_or_else(|| "-".to_string()),
                    pubs(&after)
                ));
            }
            ["LISTS"] => {
                let rotated = match app.rotate_ratchets() {
                    Ok(r) => r,
                    Err(e) => {
                        say(format!("ERROR rotate: {e}"));
                        continue;
                    }
                };
                let file = match file_ratchets(&ratchet_path) {
                    Ok(f) => pubs(&f),
                    Err(e) => format!("<unreadable:{e}>"),
                };
                say(format!("LISTS rotated={} app={} file={}", rotated as u8, pubs(app.ratchets.as_deref().unwrap_or(&[])), file));
            }
            ["SEND", dest_hex, tag] => send(dest_hex, tag),
            ["QUIT"] => std::process::exit(0),
            _ => say(format!("ERROR unknown command: {line}")),
        }
    }
    std::process::exit(0);
}

fn send(dest_hex: &str, tag: &str) {
    let Some(dest_hash) = reticulum_rust::decode_hex(dest_hex) else {
        return say(format!("UNPROVEN {tag} bad hash"));
    };
    // The peer's announce is the readiness event; the ceiling only turns a
    // missing announce into a failure.
    {
        let (heard, cv) = &*HEARD;
        let guard = heard.lock().unwrap();
        let (guard, timeout) = cv
            .wait_timeout_while(guard, Duration::from_secs(10), |h| !h.contains(&dest_hash))
            .unwrap();
        drop(guard);
        if timeout.timed_out() {
            return say(format!("UNPROVEN {tag} no announce from the peer within 10 s"));
        }
    }
    let Some(peer_identity) = Identity::recall(&dest_hash) else {
        return say(format!("UNPROVEN {tag} peer identity not recalled"));
    };
    let destination = match Destination::new_outbound(
        Some(peer_identity),
        DestinationType::Single,
        APP_NAME.to_string(),
        vec![PEER_ASPECT.to_string()],
    ) {
        Ok(d) => d,
        Err(e) => return say(format!("UNPROVEN {tag} outbound destination: {e}")),
    };
    if destination.hash != dest_hash {
        return say(format!("UNPROVEN {tag} outbound hash {} != {}", hex(&destination.hash), dest_hex));
    }
    let ratchet = Identity::get_ratchet(&dest_hash).map(|r| hex(&r)).unwrap_or_else(|| "none".to_string());
    say(format!("SENDING {tag} ratchet={ratchet}"));

    let mut packet = Packet::new(
        Some(destination),
        tag.as_bytes().to_vec(),
        reticulum_rust::packet::DATA,
        reticulum_rust::packet::NONE,
        reticulum_rust::transport::BROADCAST,
        reticulum_rust::packet::HEADER_1,
        None,
        None,
        true,
        reticulum_rust::packet::FLAG_UNSET,
    );
    let started = Instant::now();
    let receipt = match packet.send() {
        Ok(Some(r)) => r,
        Ok(None) => return say(format!("UNPROVEN {tag} send returned no receipt")),
        Err(e) => return say(format!("UNPROVEN {tag} send failed: {e}")),
    };
    let (tx, rx) = mpsc::channel::<bool>();
    let delivered = Mutex::new(tx.clone());
    receipt.set_delivery_callback(Arc::new(move |_r: &PacketReceipt| {
        let _ = delivered.lock().unwrap().send(true);
    }));
    let timed_out = Mutex::new(tx);
    receipt.set_timeout_callback(Arc::new(move |_r: &PacketReceipt| {
        let _ = timed_out.lock().unwrap().send(false);
    }));
    // Test-failure ceiling only (DESIGN_PRINCIPLES §7): the proof is the event.
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(true) => say(format!("PROVEN {tag} ms={}", started.elapsed().as_millis())),
        Ok(false) => say(format!("UNPROVEN {tag} receipt timed out")),
        Err(_) => say(format!("UNPROVEN {tag} no proof within 10 s")),
    }
}
