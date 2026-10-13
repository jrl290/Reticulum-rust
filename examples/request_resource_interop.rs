//! Interop harness for requests and responses that do not fit in one packet.
//!
//! RNS/Link.py sends a packed request or response as a single packet when it
//! fits the link MDU and as a Resource when it does not. This binary is one
//! end of that exchange; `tests/interop/request_resource_interop.py` is the
//! same thing on the Python reference. `tests/interop/run.sh` runs every
//! pairing, so each direction is checked against the reference rather than
//! only against ourselves.
//!
//!   request_resource_interop hub    <config_dir>
//!   request_resource_interop server <config_dir>
//!   request_resource_interop client <config_dir> <dest_hex> <request_len> <response_len>
//!   request_resource_interop phone  <config_dir> <dest_hex> <request_len> <response_len>
//!
//! `hub` is a bare transport node — this stack in the role the gateway plays:
//! everything the two ends learn about each other has to be rebroadcast and
//! routed by it.
//!
//! `phone` asks the way the apps do: `ffi::link_request`, one link per
//! request, with the 5 s the apps pass (Android `appLinkSend`, iOS
//! `oneShotRfedRequest`). It asks `/echo` and then `/proven`; on a Rust server
//! `/proven` is rfed's pull, a proven handler that keeps its page until the
//! phone's stack proves the response. A response that needs longer than 5 s to
//! arrive must still be taken whole. Until 2026-10-13 the link was torn down
//! 5 s after the request, mid-Resource, and a phone never took a pull page
//! over about 1 MB. When the response is split it then asks `/echo` again
//! through `ffi::link_request_within`, capped at half the time the first took,
//! as iOS's Notification Service Extension caps its pulls: that call must end
//! at its cap. Last it asks `/unanswered`, which no server here serves: that
//! request must still fail by its own 5 s timeout.
//!
//! After the request is answered the client sends the same request to
//! `/proven`. A Rust server answers it from a proven handler
//! (`Destination::register_proven_request_handler`): the response goes as a
//! Resource whatever its size, and the server prints `PROVEN delivered=…` when
//! its `concluded` fires. The runner requires exactly one, `true`: the
//! client's stack proved the response. The reference has no such hook, so a
//! Python server answers `/proven` as `/echo`.
//!
//! Then the client sends one plain Resource (not a request). The server prints
//! a `RESOURCE` line each time its concluded callback fires, and the runner
//! requires exactly one: a Resource concludes once.
//!
//! The request is `[response_len, payload]`; the server checks `payload` and
//! answers with `response_len` bytes. Both payloads come from `pattern()`, so
//! either end can verify every byte without sharing anything but the length.

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use reticulum_rust::destination::{Destination, DestinationType, ProvenAnswer, ALLOW_ALL};
use reticulum_rust::ffi;
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{Link, LinkHandle, RequestReceipt, ACCEPT_ALL as ACCEPT_ALL_RESOURCES, MODE_AES256_CBC};
use reticulum_rust::resource::{AutoCompressOption, Resource, ResourceData, ResourceStatus};
use std::sync::Mutex;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

const APP_NAME: &str = "interop";
const ASPECT: &str = "request";
const PATH: &str = "/echo";
const PROVEN_PATH: &str = "/proven";
/// A path no server here serves (the phone client's unanswered request).
const UNANSWERED_PATH: &str = "/unanswered";

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
const RESOURCE_SEED: u32 = 0x5678;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("hub") if args.len() == 3 => hub(PathBuf::from(&args[2])),
        Some("server") if args.len() == 3 => server(PathBuf::from(&args[2])),
        Some("client") if args.len() == 6 => client(
            PathBuf::from(&args[2]),
            &args[3],
            args[4].parse().expect("request_len"),
            args[5].parse().expect("response_len"),
        ),
        Some("phone") if args.len() == 6 => phone(
            PathBuf::from(&args[2]),
            &args[3],
            args[4].parse().expect("request_len"),
            args[5].parse().expect("response_len"),
        ),
        _ => {
            eprintln!("usage: hub <config_dir> | server <config_dir> | client|phone <config_dir> <dest_hex> <request_len> <response_len>");
            std::process::exit(2);
        }
    }
}

fn hub(config_dir: PathBuf) {
    Reticulum::init(Some(config_dir), None, None, None, false, None).expect("Reticulum init");
    println!("HUB ready");
    loop {
        thread::sleep(Duration::from_secs(3600));
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
                echo(data).unwrap_or_default()
            })),
            ALLOW_ALL,
            None,
            true,
        )
        .expect("register handler");
    destination
        .register_proven_request_handler(
            PROVEN_PATH.to_string(),
            Arc::new(|_path, data, _request_id, _identity, _link, _requested_at| match echo(data) {
                Some(response) => ProvenAnswer::Proven {
                    data: response,
                    concluded: Arc::new(|proved| println!("PROVEN delivered={}", proved)),
                },
                None => ProvenAnswer::None,
            }),
            ALLOW_ALL,
            None,
            false,
        )
        .expect("register proven handler");

    destination.set_link_established_callback(Some(Arc::new(|link: LinkHandle| {
        link.set_resource_strategy(ACCEPT_ALL_RESOURCES);
        link.set_resource_callbacks(
            None,
            None,
            Some(Arc::new(|resource: Arc<Mutex<Resource>>| {
                let data = resource.lock().ok().and_then(|r| r.data.clone()).unwrap_or_default();
                let intact = data == pattern(data.len(), RESOURCE_SEED);
                println!("RESOURCE bytes={} intact={}", data.len(), intact);
            })),
        );
    })));

    Transport::register_destination(destination.clone());
    println!("DEST {}", reticulum_rust::hexrep(&destination.hash, false));

    loop {
        let _ = destination.announce(None, false, None, None, true);
        thread::sleep(Duration::from_secs(3));
    }
}

/// The answer to a request `[response_len, payload]`: `response_len` bytes of
/// the response pattern, or `None` when the payload arrived damaged.
fn echo(data: &[u8]) -> Option<Vec<u8>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(data)).expect("request is msgpack");
    let fields = value.as_array().expect("request is an array");
    let response_len = fields[0].as_u64().expect("response_len") as usize;
    let payload = fields[1].as_slice().expect("payload is bin");
    let intact = payload == pattern(payload.len(), REQUEST_SEED).as_slice();
    println!("REQUEST bytes={} intact={}", payload.len(), intact);
    if !intact {
        return None;
    }
    let mut response = Vec::new();
    rmpv::encode::write_value(&mut response, &rmpv::Value::Binary(pattern(response_len, RESPONSE_SEED))).expect("encode response");
    Some(response)
}

/// The request `[response_len, payload]` for `request_len` bytes of payload.
fn request_data(request_len: usize, response_len: usize) -> Vec<u8> {
    let mut data = Vec::new();
    rmpv::encode::write_value(
        &mut data,
        &rmpv::Value::Array(vec![
            rmpv::Value::from(response_len as u64),
            rmpv::Value::Binary(pattern(request_len, REQUEST_SEED)),
        ]),
    )
    .expect("encode request");
    data
}

/// The length of `response`'s body, which must be the answer to a request
/// for `response_len` bytes; anything else fails the run.
fn check_response(path: &str, response: &[u8], response_len: usize) -> usize {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(response)).expect("response is msgpack");
    let body = value.as_slice().unwrap_or_else(|| fail(&format!("{path}: response is not bin")));
    if body != pattern(response_len, RESPONSE_SEED).as_slice() {
        fail(&format!("{path}: response mismatch: got {} bytes, wanted {}", body.len(), response_len));
    }
    body.len()
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
        let data = request_data(request_len, response_len);
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
    let received = match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(response)) => check_response(PATH, &response, response_len),
        Ok(Err(reason)) => fail(reason),
        Err(_) => fail("no response within the test ceiling"),
    };

    // The same request to /proven, from this thread now that the link is up.
    let ok_tx = tx.clone();
    let failed_tx = tx.clone();
    if link
        .request(
            PROVEN_PATH.to_string(),
            request_data(request_len, response_len),
            Some(Arc::new(move |receipt: RequestReceipt| {
                let _ = ok_tx.send(Ok(receipt.response.unwrap_or_default()));
            })),
            Some(Arc::new(move |_receipt: RequestReceipt| {
                let _ = failed_tx.send(Err("proven request failed"));
            })),
            None,
        )
        .is_err()
    {
        fail("proven request could not be sent");
    }
    match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(response)) => check_response(PROVEN_PATH, &response, response_len),
        Ok(Err(reason)) => fail(reason),
        Err(_) => fail("no proven response within the test ceiling"),
    };

    send_plain_resource(&link, request_len.max(2000));
    println!("PASS request={} response={}", request_len, received);
    std::process::exit(0);
}

/// The timeout the apps pass to `ffi::link_request` (Android
/// `ConnectionStateManager.appLinkSend`, iOS `oneShotRfedRequest`).
const PHONE_TIMEOUT_SECS: f64 = 5.0;

/// Ask `/echo` and then `/proven` the way the apps do (see the module comment).
fn phone(config_dir: PathBuf, dest_hex: &str, request_len: usize, response_len: usize) {
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

    let identity = ffi::identity_create().unwrap_or_else(|e| fail(&e));
    let mut took = Vec::new();
    for path in [PATH, PROVEN_PATH] {
        let asked = Instant::now();
        let response = ffi::link_request(
            &dest_hash,
            APP_NAME,
            vec![ASPECT.to_string()],
            identity,
            path,
            &request_data(request_len, response_len),
            PHONE_TIMEOUT_SECS,
        )
        .unwrap_or_else(|e| fail(&format!("{path} after {:.1} s: {e}", asked.elapsed().as_secs_f64())));
        check_response(path, &response, response_len);
        took.push((path, asked.elapsed().as_secs_f64()));
    }

    // A split response (over MAX_EFFICIENT_SIZE) is the kind the apps never
    // took. If it arrived within their 5 s, this run says nothing about a
    // response that needs longer, which is what the cell is for.
    let slowest = took.iter().map(|(_, secs)| *secs).fold(0.0, f64::max);
    if response_len > Resource::MAX_EFFICIENT_SIZE && slowest <= PHONE_TIMEOUT_SECS {
        fail(&format!(
            "inconclusive: a {response_len}-byte response arrived within {PHONE_TIMEOUT_SECS} s, so this run shows nothing about one that needs longer"
        ));
    }

    // A caller under a time budget it does not set (iOS's Notification
    // Service Extension, which the system ends after about 30 s) caps the
    // whole call. Capped at half of what /echo took, the same request must
    // end at the cap.
    let mut capped = String::new();
    if response_len > Resource::MAX_EFFICIENT_SIZE {
        let (_, echo_took) = took[0];
        let cap = echo_took / 2.0;
        let asked = Instant::now();
        let outcome = ffi::link_request_within(
            &dest_hash,
            APP_NAME,
            vec![ASPECT.to_string()],
            identity,
            PATH,
            &request_data(request_len, response_len),
            PHONE_TIMEOUT_SECS,
            Some(cap),
        );
        let secs = asked.elapsed().as_secs_f64();
        match outcome {
            Ok(_) => fail(&format!("{PATH} capped at {cap:.1} s arrived whole in {secs:.1} s (uncapped it took {echo_took:.1} s)")),
            Err(e) if secs < cap || secs > cap + 1.0 => fail(&format!("{PATH} capped at {cap:.1} s ended after {secs:.1} s: {e}")),
            Err(_) => capped = format!("; {PATH} capped at {cap:.1} s ended in {secs:.1} s"),
        }
    }

    // A request nobody answers still ends by its own timeout, the apps' 5 s:
    // a response that never begins is the request's to give up on. Both
    // stacks ignore a request for a path they have no handler for.
    let (tx, rx) = mpsc::channel();
    let asked = Instant::now();
    thread::spawn(move || {
        let _ = tx.send(ffi::link_request(
            &dest_hash,
            APP_NAME,
            vec![ASPECT.to_string()],
            identity,
            UNANSWERED_PATH,
            &request_data(16, 16),
            PHONE_TIMEOUT_SECS,
        ));
    });
    // Test-failure ceiling only (DESIGN_PRINCIPLES §7).
    let unanswered = match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Err(_)) if asked.elapsed().as_secs_f64() >= PHONE_TIMEOUT_SECS => asked.elapsed().as_secs_f64(),
        Ok(Err(e)) => fail(&format!(
            "{UNANSWERED_PATH} failed after {:.1} s, before its own {PHONE_TIMEOUT_SECS} s timeout: {e}",
            asked.elapsed().as_secs_f64()
        )),
        Ok(Ok(_)) => fail(&format!("{UNANSWERED_PATH}: answered by a server with no handler for it")),
        Err(_) => fail(&format!("{UNANSWERED_PATH}: still waiting after 30 s; its own {PHONE_TIMEOUT_SECS} s timeout never ended it")),
    };

    let took: Vec<String> = took.iter().map(|(path, secs)| format!("{path} in {secs:.1} s")).collect();
    println!(
        "PASS request={} response={} ({}{capped}; {UNANSWERED_PATH} failed in {unanswered:.1} s)",
        request_len, response_len, took.join(", ")
    );
    std::process::exit(0);
}

/// Send one plain Resource and wait for the receiver's proof.
fn send_plain_resource(link: &LinkHandle, len: usize) {
    let (tx, rx) = mpsc::channel::<bool>();
    let tx = Mutex::new(tx);
    let resource = Resource::new_internal(
        Some(ResourceData::Bytes(pattern(len, RESOURCE_SEED))),
        link.clone(),
        None,
        false,
        AutoCompressOption::Enabled,
        Some(Arc::new(move |resource: Arc<Mutex<Resource>>| {
            let complete = resource.lock().map(|r| r.status == ResourceStatus::Complete).unwrap_or(false);
            let _ = tx.lock().unwrap().send(complete);
        })),
        None,
        None,
        1,
        None,
        None,
        false,
        0,
        None,
    )
    .unwrap_or_else(|e| fail(&format!("could not build resource: {e}")));
    Resource::advertise_shared(Arc::new(Mutex::new(resource)));
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(true) => {
            // Give the receiver's callback a moment to print before we exit
            // and the runner counts its RESOURCE lines.
            thread::sleep(Duration::from_millis(500));
        }
        Ok(false) => fail("plain resource transfer failed"),
        Err(_) => fail("plain resource not proven within the test ceiling"),
    }
}

fn fail(reason: &str) -> ! {
    println!("FAIL {}", reason);
    std::process::exit(1);
}
