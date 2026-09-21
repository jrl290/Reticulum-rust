//! Interop harness for requests and responses that do not fit in one packet.
//!
//! RNS/Link.py sends a packed request or response as a single packet when it
//! fits the link MDU and as a Resource when it does not. This binary is one
//! end of that exchange; `tests/interop/request_resource_interop.py` is the
//! same thing on the Python reference. `tests/interop/run.sh` runs every
//! pairing, so each direction is checked against the reference rather than
//! only against ourselves.
//!
//!   request_resource_interop server <config_dir>
//!   request_resource_interop client <config_dir> <dest_hex> <request_len> <response_len>
//!
//! The request is `[response_len, payload]`; the server checks `payload` and
//! answers with `response_len` bytes. Both payloads come from `pattern()`, so
//! either end can verify every byte without sharing anything but the length.

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use reticulum_rust::destination::{Destination, DestinationType, ALLOW_ALL};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{Link, LinkHandle, RequestReceipt, MODE_AES256_CBC};
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

const APP_NAME: &str = "interop";
const ASPECT: &str = "request";
const PATH: &str = "/echo";

/// Deterministic and close to incompressible, so an over-MDU payload is still
/// a multi-part transfer after the Resource layer has tried to compress it.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7fff_ffff;
            ((x >> 16) & 0xff) as u8
        })
        .collect()
}

const REQUEST_SEED: u32 = 0x1234;
const RESPONSE_SEED: u32 = 0x4321;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") if args.len() == 3 => server(PathBuf::from(&args[2])),
        Some("client") if args.len() == 6 => client(
            PathBuf::from(&args[2]),
            &args[3],
            args[4].parse().expect("request_len"),
            args[5].parse().expect("response_len"),
        ),
        _ => {
            eprintln!("usage: server <config_dir> | client <config_dir> <dest_hex> <request_len> <response_len>");
            std::process::exit(2);
        }
    }
}

fn server(config_dir: PathBuf) {
    Reticulum::init(Some(config_dir.clone()), None, None, None, false, None).expect("Reticulum init");

    let identity = Identity::new(true);
    let mut destination = Destination::new_inbound(
        Some(identity),
        DestinationType::Single,
        APP_NAME.to_string(),
        vec![ASPECT.to_string()],
    )
    .expect("create destination");

    destination
        .register_request_handler(
            PATH.to_string(),
            Some(Arc::new(|_path, data, _request_id, _identity, _link, _requested_at| {
                let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data)).expect("request is msgpack");
                let fields = value.as_array().expect("request is an array");
                let response_len = fields[0].as_u64().expect("response_len") as usize;
                let payload = fields[1].as_slice().expect("payload is bin");
                let intact = payload == pattern(payload.len(), REQUEST_SEED).as_slice();
                println!("REQUEST bytes={} intact={}", payload.len(), intact);
                let body = if intact { pattern(response_len, RESPONSE_SEED) } else { Vec::new() };
                let mut response = Vec::new();
                rmpv::encode::write_value(&mut response, &rmpv::Value::Binary(body)).expect("encode response");
                response
            })),
            ALLOW_ALL,
            None,
            true,
        )
        .expect("register handler");

    Transport::register_destination(destination.clone());
    println!("DEST {}", reticulum_rust::hexrep(&destination.hash, false));

    loop {
        let _ = destination.announce(None, false, None, None, true);
        thread::sleep(Duration::from_secs(3));
    }
}

fn client(config_dir: PathBuf, dest_hex: &str, request_len: usize, response_len: usize) {
    Reticulum::init(Some(config_dir), None, None, None, false, None).expect("Reticulum init");
    let dest_hash = reticulum_rust::decode_hex(dest_hex).expect("dest hex");

    // The server announces every 3 s; the announce is the readiness event.
    let deadline = Instant::now() + Duration::from_secs(40);
    while !Transport::has_path(&dest_hash) {
        if Instant::now() > deadline {
            fail("no announce from the server");
        }
        thread::sleep(Duration::from_millis(200));
    }
    let server_identity = Identity::recall(&dest_hash).unwrap_or_else(|| fail("server identity not recalled"));

    let destination = Destination::new_outbound(
        Some(server_identity),
        DestinationType::Single,
        APP_NAME.to_string(),
        vec![ASPECT.to_string()],
    )
    .expect("create destination");
    let link = LinkHandle::spawn(Link::new_outbound(destination, MODE_AES256_CBC).expect("create link"));

    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, &'static str>>();

    let established_link = link.clone();
    let established_tx = tx.clone();
    link.set_link_established_callback(Some(Arc::new(move |_| {
        let mut data = Vec::new();
        rmpv::encode::write_value(
            &mut data,
            &rmpv::Value::Array(vec![
                rmpv::Value::from(response_len as u64),
                rmpv::Value::Binary(pattern(request_len, REQUEST_SEED)),
            ]),
        )
        .expect("encode request");

        let ok_tx = established_tx.clone();
        let failed_tx = established_tx.clone();
        let sent = established_link.request(
            PATH.to_string(),
            data,
            Some(Arc::new(move |receipt: RequestReceipt| {
                let _ = ok_tx.send(Ok(receipt.response.unwrap_or_default()));
            })),
            Some(Arc::new(move |_receipt: RequestReceipt| {
                let _ = failed_tx.send(Err("request failed"));
            })),
            None,
        );
        if sent.is_err() {
            let _ = established_tx.send(Err("request could not be sent"));
        }
    })));
    let closed_tx = tx.clone();
    link.set_link_closed_callback(Some(Arc::new(move |_| {
        let _ = closed_tx.send(Err("link closed"));
    })));
    link.initiate().expect("initiate link");

    // Test-failure ceiling only (DESIGN_PRINCIPLES §7); success arrives as an event.
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(response)) => {
            let value = rmpv::decode::read_value(&mut std::io::Cursor::new(&response)).expect("response is msgpack");
            let body = value.as_slice().unwrap_or_else(|| fail("response is not bin"));
            if body == pattern(response_len, RESPONSE_SEED).as_slice() {
                println!("PASS request={} response={}", request_len, body.len());
                std::process::exit(0);
            }
            fail(&format!("response mismatch: got {} bytes, wanted {}", body.len(), response_len));
        }
        Ok(Err(reason)) => fail(reason),
        Err(_) => fail("no response within the test ceiling"),
    }
}

fn fail(reason: &str) -> ! {
    println!("FAIL {}", reason);
    std::process::exit(1);
}
