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

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use rand::RngCore;

use super::engine::{Characteristic, Effect, Engine, LinkState};
use super::wire::{self, Endpoint, IDENTITY_LEN};
use crate::transport::{InterfaceStub, InterfaceStubConfig, Transport};

/// Link bitrate Prns assumes for a Bluetooth peer (`policy.rs`), and RTNode
/// registers for its Bluetooth slots.
pub const BITRATE: u64 = 700_000;

/// What the platform's Bluetooth code does for the engine. Called on
/// engine-internal threads as well as the caller's; implementations hand the
/// work to their own Bluetooth queue and return.
pub trait Host: Send + Sync {
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

/// Loads `<storage_dir>/ble_identity` (the record Prns writes), creating it
/// on first use. The identity persists by design: RTNode keys the phone's
/// interface by it.
pub fn load_or_create_identity(storage_dir: &Path) -> Result<[u8; IDENTITY_LEN], String> {
    let path: PathBuf = storage_dir.join("ble_identity");
    match std::fs::read(&path) {
        Ok(record) => match wire::decode_identity_record(&record) {
            Ok(identity) => return Ok(identity),
            Err(why) => log(&format!("{}: {why}; writing a new identity", path.display()), crate::LOG_ERROR),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    }
    let mut identity = [0u8; IDENTITY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut identity);
    std::fs::create_dir_all(storage_dir).map_err(|e| format!("cannot create {}: {e}", storage_dir.display()))?;
    let temp = storage_dir.join("ble_identity.tmp");
    std::fs::write(&temp, wire::encode_identity_record(&identity)).map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    std::fs::rename(&temp, &path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    log(&format!("new Bluetooth identity {}", crate::hexrep(&identity, false)), crate::LOG_NOTICE);
    Ok(identity)
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
    with_engine(|engine| Ok(engine.link_closed(link)))?
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
            Effect::Write { link, characteristic, bytes } => host.write(link, characteristic, &bytes),
            Effect::Disconnect { link } => host.disconnect(link),
            Effect::State { link, state, peer, interface } => host.link_state(link, state, peer.as_ref(), interface.as_deref()),
            // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
            Effect::CheckLate { label, sent_at_unix } => crate::send_assertion::assert_send_completed_in_time(label, sent_at_unix),
            Effect::Log { level, message } => log(&message, level),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_is_created_once_and_then_read_back() {
        let dir = std::env::temp_dir().join(format!("prns-ble-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = load_or_create_identity(&dir).unwrap();
        assert_eq!(load_or_create_identity(&dir).unwrap(), first);
        let record = std::fs::read(dir.join("ble_identity")).unwrap();
        assert_eq!(wire::decode_identity_record(&record), Ok(first));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_identity_record_is_replaced() {
        let dir = std::env::temp_dir().join(format!("prns-ble-identity-damaged-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ble_identity"), b"not a record").unwrap();
        let identity = load_or_create_identity(&dir).unwrap();
        assert_eq!(wire::decode_identity_record(&std::fs::read(dir.join("ble_identity")).unwrap()), Ok(identity));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
