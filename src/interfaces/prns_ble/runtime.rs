//! The one engine per process, and the effects it asks for carried out.
//!
//! Threads:
//! - the caller's (a host Bluetooth callback, or an interface writer): feeds
//!   the engine, then runs the host effects after the engine lock is
//!   released, so a host that calls back in synchronously cannot deadlock;
//! - `prns-ble-transport`: every Transport effect, in the order the engine
//!   produced them (sent while the lock is held), so an interface is always
//!   registered before its first inbound packet and deregistered after its
//!   last;
//! - `prns-ble-timer`: the handshake ceiling.

use std::path::Path;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

use ::prns_ble::engine::{Characteristic, Effect, Engine, Level, LinkState};
use ::prns_ble::identity::{self, Loaded};
use ::prns_ble::wire::{Endpoint, IDENTITY_LEN};
use ::prns_ble::{BITRATE, MAX_QUEUED_PACKETS};
use crate::transport::{InterfaceStub, InterfaceStubConfig, Transport};

// A link's queue holds a whole Resource window: a part dropped there costs
// the receiver a wait and a re-request.
const _: () = assert!(MAX_QUEUED_PACKETS > crate::resource::Resource::WINDOW_MAX_FAST);

/// What the platform's Bluetooth code does for the engine. Called on
/// engine-internal threads as well as the caller's; implementations hand the
/// work to their own Bluetooth queue and return.
pub trait Host: Send + Sync {
    /// Start or stop scanning for advertisements of the Prns service. The
    /// host scans from start until told otherwise.
    fn scan(&self, on: bool);
    fn write(&self, link: u64, characteristic: Characteristic, bytes: &[u8]);
    fn disconnect(&self, link: u64);
    fn link_state(&self, link: u64, state: LinkState, peer: Option<&[u8; IDENTITY_LEN]>, interface: Option<&str>);
}

enum TransportJob {
    Effect(Effect),
    Exit,
}

struct Runtime {
    engine: Engine,
    host: Arc<dyn Host>,
    transport: Sender<TransportJob>,
    transport_thread: Option<JoinHandle<()>>,
    timer_thread: Option<JoinHandle<()>>,
}

static RUNTIME: Lazy<Mutex<Option<Runtime>>> = Lazy::new(|| Mutex::new(None));
/// Wakes the timer thread: bumped whenever a deadline may have moved.
static TIMER: Lazy<(Mutex<u64>, Condvar)> = Lazy::new(|| (Mutex::new(0), Condvar::new()));

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn log(message: &str, level: i32) {
    crate::log(&format!("[PRNS-BLE] {message}"), level, false, false);
}

fn log_level(level: Level) -> i32 {
    match level {
        Level::Error => crate::LOG_ERROR,
        Level::Warning => crate::LOG_WARNING,
        Level::Notice => crate::LOG_NOTICE,
        Level::Debug => crate::LOG_DEBUG,
    }
}

/// Loads `<storage_dir>/ble_identity` (the record Prns writes), creating it
/// on first use (`prns_ble::identity`).
pub fn load_or_create_identity(storage_dir: &Path) -> Result<[u8; IDENTITY_LEN], String> {
    let loaded = identity::load_or_create(storage_dir)?;
    if let Loaded::Created { identity, damaged } = &loaded {
        if let Some(why) = damaged {
            log(&format!("{why}; wrote a new identity"), crate::LOG_ERROR);
        }
        log(&format!("new Bluetooth identity {}", crate::hexrep(identity, false)), crate::LOG_NOTICE);
    }
    Ok(loaded.identity())
}

/// Starts the engine. The stack must be running and the app's destinations
/// published first (DESIGN_PRINCIPLES §5): a peer's interface comes up the
/// moment it settles, and that up-edge is when Transport announces the
/// published destinations on it.
pub fn start(storage_dir: &Path, endpoint: Endpoint, host: Arc<dyn Host>) -> Result<[u8; IDENTITY_LEN], String> {
    if crate::reticulum::Reticulum::get_instance().is_none() {
        return Err("Reticulum is not running".into());
    }
    let mut guard = RUNTIME.lock().unwrap();
    if guard.is_some() {
        return Err("Bluetooth is already started".into());
    }
    let identity = load_or_create_identity(storage_dir)?;
    let (transport, jobs) = mpsc::channel::<TransportJob>();
    let transport_thread = std::thread::Builder::new()
        .name("prns-ble-transport".into())
        .spawn(move || {
            for job in jobs {
                match job {
                    TransportJob::Effect(effect) => apply_transport(effect),
                    TransportJob::Exit => break,
                }
            }
        })
        .map_err(|e| format!("cannot start the transport thread: {e}"))?;
    let timer_thread = std::thread::Builder::new()
        .name("prns-ble-timer".into())
        .spawn(timer_loop)
        .map_err(|e| format!("cannot start the timer thread: {e}"))?;
    *guard = Some(Runtime {
        engine: Engine::new(identity, endpoint),
        host,
        transport,
        transport_thread: Some(transport_thread),
        timer_thread: Some(timer_thread),
    });
    log(
        &format!("started, identity {}, endpoint {}/{}", crate::hexrep(&identity, false), endpoint.stack, endpoint.host),
        crate::LOG_NOTICE,
    );
    Ok(identity)
}

/// Closes every link (the host is asked to disconnect each), removes the
/// peers' interfaces from Transport, and stops the engine's threads. Blocks
/// until Transport has let go of the interfaces, so call it off the UI
/// thread (DESIGN_PRINCIPLES §6), and before the stack shuts down.
pub fn stop() {
    let (host, host_effects, transport_thread, timer_thread) = {
        let mut guard = RUNTIME.lock().unwrap();
        let Some(mut runtime) = guard.take() else { return };
        let effects = runtime.engine.close_all();
        let host_effects = route(&runtime.transport, effects);
        let _ = runtime.transport.send(TransportJob::Exit);
        (runtime.host.clone(), host_effects, runtime.transport_thread.take(), runtime.timer_thread.take())
    };
    wake_timer();
    run_host(&host, host_effects);
    if let Some(thread) = transport_thread {
        let _ = thread.join();
    }
    if let Some(thread) = timer_thread {
        let _ = thread.join();
    }
    log("stopped", crate::LOG_NOTICE);
}

pub fn is_running() -> bool {
    RUNTIME.lock().unwrap().is_some()
}

/// See `Engine::sighted`: the link to dial the device on, if any.
pub fn sighted(address: &str, company_id: u16, data: &[u8]) -> Result<Option<u64>, String> {
    let mut dialled = None;
    with_engine(|engine| {
        let (link, effects) = engine.sighted(address, company_id, data, Instant::now(), unix_now());
        dialled = link;
        Ok(effects)
    })??;
    if dialled.is_some() {
        wake_timer();
    }
    Ok(dialled)
}

/// See `Engine::link_ready`.
pub fn link_ready(link: u64, max_write_len: usize) -> Result<(), String> {
    let result = with_engine(|engine| engine.link_ready(link, max_write_len, Instant::now(), unix_now()))?;
    wake_timer();
    result
}

pub fn link_received(link: u64, characteristic: Characteristic, bytes: &[u8]) -> Result<(), String> {
    with_engine(|engine| Ok(engine.link_received(link, characteristic, bytes, unix_now())))?
}

pub fn link_write_done(link: u64, ok: bool) -> Result<(), String> {
    with_engine(|engine| Ok(engine.link_write_done(link, ok, unix_now())))?
}

pub fn link_closed(link: u64) -> Result<(), String> {
    with_engine(|engine| Ok(engine.link_closed(link, Instant::now())))?
}

/// Runs one engine call under the lock: Transport effects are queued in
/// order before the lock is released, host effects are run after.
fn with_engine<F>(call: F) -> Result<Result<(), String>, String>
where
    F: FnOnce(&mut Engine) -> Result<Vec<Effect>, String>,
{
    let (host, host_effects, result) = {
        let mut guard = RUNTIME.lock().unwrap();
        let Some(runtime) = guard.as_mut() else {
            return Err("Bluetooth is not started".into());
        };
        match call(&mut runtime.engine) {
            Ok(effects) => {
                let host_effects = route(&runtime.transport, effects);
                (runtime.host.clone(), host_effects, Ok(()))
            }
            Err(e) => (runtime.host.clone(), Vec::new(), Err(e)),
        }
    };
    run_host(&host, host_effects);
    Ok(result)
}

/// The interface writer's handler for a peer's interface.
fn send_packet(link: u64, packet: &[u8]) -> bool {
    let (host, host_effects, accepted) = {
        let mut guard = RUNTIME.lock().unwrap();
        let Some(runtime) = guard.as_mut() else { return false };
        let (accepted, effects) = runtime.engine.send_packet(link, packet, unix_now());
        let host_effects = route(&runtime.transport, effects);
        (runtime.host.clone(), host_effects, accepted)
    };
    run_host(&host, host_effects);
    accepted
}

/// Queues the Transport effects (in order, under the caller's lock) and
/// returns the rest.
fn route(transport: &Sender<TransportJob>, effects: Vec<Effect>) -> Vec<Effect> {
    let mut rest = Vec::new();
    for effect in effects {
        match effect {
            Effect::Register { .. } | Effect::HandOver { .. } | Effect::Deregister { .. } | Effect::Inbound { .. } => {
                let _ = transport.send(TransportJob::Effect(effect));
            }
            other => rest.push(other),
        }
    }
    rest
}

fn run_host(host: &Arc<dyn Host>, effects: Vec<Effect>) {
    for effect in effects {
        match effect {
            Effect::Scan { on } => host.scan(on),
            Effect::Write { link, characteristic, bytes } => host.write(link, characteristic, &bytes),
            Effect::Disconnect { link } => host.disconnect(link),
            Effect::State { link, state, peer, interface } => host.link_state(link, state, peer.as_ref(), interface.as_deref()),
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            Effect::CheckLate { label, sent_at_unix } => crate::send_assertion::assert_send_completed_in_time(label, sent_at_unix),
            Effect::Log { level, message } => log(&message, log_level(level)),
            Effect::Register { .. } | Effect::HandOver { .. } | Effect::Deregister { .. } | Effect::Inbound { .. } => {}
        }
    }
}

fn outbound_handler(link: u64) -> Arc<dyn Fn(&[u8]) -> bool + Send + Sync> {
    Arc::new(move |packet: &[u8]| send_packet(link, packet))
}

/// Registration mirrors a TCP server's spawned client (tcp_interface.rs),
/// except that the stub starts offline and is then set online: that one
/// call gives both the published-destination sweep and the interface-up
/// listeners (app-links re-attempting its held links), where registering it
/// online would give only the sweep.
fn apply_transport(effect: Effect) {
    match effect {
        Effect::Register { name, link } => {
            Transport::register_outbound_handler(&name, outbound_handler(link));
            let mut config = InterfaceStubConfig::default();
            config.name = name.clone();
            config.mode = InterfaceStub::MODE_FULL;
            config.out = true;
            config.online = Some(false);
            config.bitrate = Some(BITRATE);
            config.announce_cap = Some(crate::reticulum::ANNOUNCE_CAP / 100.0);
            Transport::register_interface_stub_config(config);
            Transport::set_interface_online(&name, true);
        }
        Effect::HandOver { name, link } => {
            Transport::register_outbound_handler(&name, outbound_handler(link));
        }
        Effect::Deregister { name } => {
            Transport::set_interface_online(&name, false);
            Transport::deregister_interface_stub(&name);
            Transport::unregister_outbound_handler(&name);
        }
        Effect::Inbound { name, packet } => {
            Transport::inbound(packet, Some(name));
        }
        _ => {}
    }
}

fn wake_timer() {
    let (generation, condvar) = &*TIMER;
    *generation.lock().unwrap() += 1;
    condvar.notify_all();
}

fn timer_loop() {
    let (generation, condvar) = &*TIMER;
    loop {
        let seen = *generation.lock().unwrap();
        let (host, host_effects, next) = {
            let mut guard = RUNTIME.lock().unwrap();
            let Some(runtime) = guard.as_mut() else { return };
            let effects = runtime.engine.expire(Instant::now());
            let host_effects = route(&runtime.transport, effects);
            (runtime.host.clone(), host_effects, runtime.engine.next_deadline())
        };
        run_host(&host, host_effects);
        let guard = generation.lock().unwrap();
        if *guard != seen {
            continue;
        }
        // With no handshake in progress there is nothing to time; the next
        // link_ready (or stop) bumps the generation and wakes this thread.
        let wait = next.map(|deadline| deadline.saturating_duration_since(Instant::now())).unwrap_or(Duration::from_secs(3600));
        let _ = condvar.wait_timeout(guard, wait);
    }
}
