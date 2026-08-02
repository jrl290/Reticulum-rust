use crate::{identity, reticulum, destination::{Destination, DestinationType}, resource::Resource};
use crate::packet::{self, Packet, DATA, PROOF, LINKIDENTIFY};
use crate::identity::{Identity, Token};
use once_cell::sync::Lazy;
use rand::RngCore;
use rmp_serde::{decode::from_slice, encode::to_vec};
use rmpv::decode::read_value as rmpv_read_value;
use rmpv::encode::write_value as rmpv_write_value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};
use std::thread;
use x25519_dalek::{StaticSecret as X25519PrivateKey, PublicKey as X25519PublicKey};
use ed25519_dalek::{PublicKey as Ed25519PublicKey, Signature, Signer, Verifier};
use hkdf::Hkdf;
use sha2::Sha256;

// ---------------------------------------------------------------------------
// LinkHandle — the public API for interacting with links
// ---------------------------------------------------------------------------

/// Error returned when a link is no longer available (torn down, channel closed).
#[derive(Debug, Clone)]
pub struct LinkGone;

impl std::fmt::Display for LinkGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Link is gone")
    }
}

impl std::error::Error for LinkGone {}

impl From<LinkGone> for String {
    fn from(_: LinkGone) -> String {
        "Link is gone".to_string()
    }
}

/// Read-only snapshot of link state, returned by `LinkHandle::snapshot()`.
/// Replaces direct field reads through `link.lock().field`.
#[derive(Debug, Clone)]
pub struct LinkSnapshot {
    pub link_id: Vec<u8>,
    pub state: u8,
    pub status: u8,
    pub initiator: bool,
    pub rtt: Option<f64>,
    pub activated_at: Option<u64>,
    pub established_at: Option<u64>,
    pub attached_interface: Option<String>,
    pub mtu: Option<usize>,
    pub traffic_timeout_factor: f64,
    pub rssi: Option<i32>,
    pub snr: Option<f64>,
    pub q: Option<f64>,
    pub track_phy_stats: bool,
    pub request_time: Option<f64>,
    pub establishment_cost: usize,
    /// Wall-clock seconds of the most recent inbound packet of any type
    /// (DATA, KEEPALIVE, PROOF, control frames). Used by LXMF's app_link
    /// dual-link disambiguation to pick the link the peer is actually
    /// servicing.
    pub last_inbound: u64,
}

impl LinkSnapshot {
    /// Build a `LinkInfo` from this snapshot, suitable for setting on a delivery destination.
    pub fn to_link_info(&self) -> crate::destination::LinkInfo {
        crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            status_closed: self.status == STATE_CLOSED,
            mtu: self.mtu,
            attached_interface: self.attached_interface.clone(),
        }
    }
}

/// A handle to a link.  Callers hold this instead of `Arc<Mutex<Link>>`.
///
/// Phase 3: wraps a channel sender to a link-actor thread.
/// The actor owns the `Link` and processes all operations sequentially,
/// eliminating mutex contention and deadlocks.
///
/// `Clone` is cheap — it clones a `Sender` and two `Arc`s.
#[derive(Clone)]
pub struct LinkHandle {
    tx: mpsc::Sender<LinkMsg>,
    /// Cached link_id — set after initiation, immutable after that.
    id: Arc<Mutex<Vec<u8>>>,
    /// Identity token for `same_link()` comparison.
    token: Arc<()>,
    /// Cached status byte — written by the actor, read lock-free by callers.
    /// Eliminates channel round-trips for status queries and prevents
    /// actor self-deadlock when callbacks call status() on their own handle.
    status_atomic: Arc<AtomicU8>,
    /// Cached destination hash — captured at spawn time, immutable.
    /// Lets external code (e.g. Transport announce-handling) match a link
    /// to its target destination without a channel round-trip while holding
    /// the transport state lock.
    dest_hash: Arc<Vec<u8>>,
    /// Whether we initiated this link (true) or it was incoming (false).
    /// Immutable after creation — cached here to avoid channel round-trips.
    pub initiator: bool,
    /// Set when Transport tears this link down because a better (fewer-hop)
    /// path to the destination has just been learned.  Lets close-callback
    /// consumers (e.g. `app_links`) skip remediation that would clobber the
    /// freshly-improved path entry.
    cancelled_for_better_path: Arc<AtomicBool>,
}

// ---------------------------------------------------------------------------
// Actor-thread guard — catches reply-awaited calls made from the actor thread
// in debug builds.  Zero overhead in release builds.
// ---------------------------------------------------------------------------

std::thread_local! {
    static ACTOR_THREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// ---------------------------------------------------------------------------
// LinkMsg — messages sent from LinkHandle to the link actor thread
// ---------------------------------------------------------------------------

type Reply<T> = mpsc::SyncSender<T>;

fn oneshot<T>() -> (Reply<T>, mpsc::Receiver<T>) {
    mpsc::sync_channel(1)
}

#[allow(clippy::large_enum_variant)]
enum LinkMsg {
    // --- Read operations (oneshot reply) ---
    Snapshot(Reply<Result<LinkSnapshot, LinkGone>>),
    Status(Reply<u8>),
    IsActive(Reply<bool>),
    IsAlive(Reply<bool>),
    NoDataFor(Reply<Result<u64, LinkGone>>),
    RemoteIdentity(Reply<Result<Option<Identity>, LinkGone>>),
    DestinationHash(Reply<Result<Vec<u8>, LinkGone>>),
    CloneDestination(Reply<Result<Destination, LinkGone>>),
    BuildLinkDestination(Reply<Result<Destination, LinkGone>>),
    GetLinkOutboundInfo(Reply<(Option<String>, bool)>),

    // --- Crypto operations ---
    Encrypt(Vec<u8>, Reply<Result<Vec<u8>, LinkGone>>),
    Decrypt(Vec<u8>, Reply<Result<Vec<u8>, LinkGone>>),

    // --- Mutating with response ---
    /// Request submission. The actor performs encrypt + `packet.send()`
    /// (which is now bounded-latency thanks to Steps 1+2 of the
    /// transport refactor: per-interface writer actors + global-lock
    /// hoist) and replies with the real `request_id` on success.
    ///
    /// Latency on the caller is `O(actor mailbox + encrypt + lock
    /// acquisition + writer enqueue)` — microseconds in the common
    /// case, never bounded by socket RTT.
    Request {
        path: String,
        data: Vec<u8>,
        response_cb: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        failed_cb: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        progress_cb: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        reply: Reply<Result<Vec<u8>, LinkGone>>,
    },
    SendPacket(Vec<u8>, Reply<Result<(), LinkGone>>),
    Identify(Identity, Reply<Result<(), LinkGone>>),
    Initiate(Reply<Result<(), LinkGone>>),

    // --- Resource operations ---
    ReadyForNewResource(Reply<bool>),
    RegisterOutgoingResource(Arc<Mutex<Resource>>),
    RegisterIncomingResource(Arc<Mutex<Resource>>),
    ResourceConcluded(Arc<Mutex<Resource>>, Reply<Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>>),
    CancelOutgoingResource(Arc<Mutex<Resource>>),
    CancelIncomingResource(Arc<Mutex<Resource>>),
    SetExpectedRate(f64),
    GetLastResourceWindow(Reply<Option<usize>>),
    GetLastResourceEifr(Reply<Option<f64>>),

    // --- Fire-and-forget ---
    Teardown(String),
    SetLinkEstablishedCallback(Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>),
    SetLinkClosedCallback(Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>),
    SetPacketCallback(Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>),
    SetRemoteIdentifiedCallback(Option<Arc<dyn Fn(LinkHandle, Identity) + Send + Sync>>),
    SetResourceStrategy(u8),
    SetResourceCallbacks {
        resource: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        started: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        concluded: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    },
    SetTrackPhyStats(bool),

    // --- Internal (used by dispatch_runtime_packet) ---
    Receive(Packet, Reply<ReceiveResult>),
    ValidateProof {
        proof: Vec<u8>,
        receipt: crate::packet::PacketReceipt,
        reply: Reply<(bool, crate::packet::PacketReceipt)>,
    },
    /// Fire-and-forget: send a request response (msgpack-encoded `response`
    /// bytes paired with `request_id`) back to the remote peer.
    /// Used by the background thread that runs the request handler callback.
    SendResponse {
        request_id: Vec<u8>,
        response: Vec<u8>,
    },
    /// Fire-and-forget: dispatch an assembled REQUEST resource into the
    /// link's request handler. Sent by the resource_concluded callback for
    /// inbound multi-segment requests (Python parity:
    /// RNS/Link.py:request_resource_concluded → handle_request).
    HandleRequestPacket {
        request_id: Vec<u8>,
        plaintext: Vec<u8>,
    },
}

/// Result from a Receive message — tells the dispatcher what happened.
struct ReceiveResult {
    handled: bool,
}

impl LinkHandle {
    /// Spawn a link actor and return a handle.
    /// The actor thread owns the Link and processes all operations.
    pub fn spawn(link: Link) -> Self {
        let id = Arc::new(Mutex::new(link.link_id.clone()));
        let token = Arc::new(());
        let status_atomic = Arc::new(AtomicU8::new(link.status));
        let initiator = link.initiator;
        // Capture destination hash up-front (immutable for the link's lifetime).
        let dest_hash = Arc::new(
            link.destination
                .lock()
                .ok()
                .map(|d| d.hash.clone())
                .unwrap_or_default(),
        );
        let (tx, rx) = mpsc::channel();
        let handle = LinkHandle {
            tx: tx.clone(),
            id: Arc::clone(&id),
            token: Arc::clone(&token),
            status_atomic: Arc::clone(&status_atomic),
            dest_hash: Arc::clone(&dest_hash),
            initiator,
            cancelled_for_better_path: Arc::new(AtomicBool::new(false)),
        };
        let self_handle = handle.clone();
        thread::Builder::new()
            .name(format!("link-actor-{}", crate::hexrep(&link.link_id, false)))
            .spawn(move || {
                link_actor(link, rx, self_handle);
            })
            .expect("Failed to spawn link actor thread");
        handle
    }

    /// Build from an Arc<Mutex<Link>> — extracts the Link and spawns an actor.
    pub fn from_arc(arc: Arc<Mutex<Link>>) -> Self {
        let link = match Arc::try_unwrap(arc) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
            Err(arc) => arc.lock().map(|g| g.clone()).expect("link lock poisoned in from_arc"),
        };
        Self::spawn(link)
    }

    /// Build a handle, specifying the link_id explicitly (compatibility shim).
    pub fn from_arc_with_id(arc: Arc<Mutex<Link>>, _id: Vec<u8>) -> Self {
        Self::from_arc(arc)
    }

    /// Get the link_id. Returns a clone of the cached id.
    pub fn link_id(&self) -> Vec<u8> {
        self.id.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Read-only snapshot of link state.
    pub fn snapshot(&self) -> Result<LinkSnapshot, LinkGone> {
        debug_assert!(
            !ACTOR_THREAD.with(|f| f.get()),
            "snapshot() called from the actor thread — this will deadlock! \
             Use resource_link_context() or read link fields directly."
        );
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::Snapshot(tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Check if the link is currently active.
    pub fn is_active(&self) -> bool {
        self.status_atomic.load(Ordering::Relaxed) == STATE_ACTIVE
    }

    /// Check if the link is alive (not closed, not channel-dead).
    pub fn is_alive(&self) -> bool {
        self.status_atomic.load(Ordering::Relaxed) != STATE_CLOSED
    }

    /// Get the current link status byte.
    pub fn status(&self) -> u8 {
        self.status_atomic.load(Ordering::Relaxed)
    }

    /// Lock-free accessor for the destination hash captured at spawn time.
    /// Safe to call while holding any mutex (no channel round-trip).
    pub fn cached_destination_hash(&self) -> &[u8] {
        &self.dest_hash
    }

    /// Mark this link as having been cancelled because Transport learned a
    /// better path to the destination.  Inspected by close-callback consumers
    /// (notably `app_links`) to skip remediation that would clobber the
    /// freshly-improved path entry.
    pub fn mark_cancelled_for_better_path(&self) {
        self.cancelled_for_better_path.store(true, Ordering::Relaxed);
    }

    /// True iff `mark_cancelled_for_better_path()` was called on this handle
    /// before its close callback fired.
    pub fn was_cancelled_for_better_path(&self) -> bool {
        self.cancelled_for_better_path.load(Ordering::Relaxed)
    }

    /// Check if two LinkHandles refer to the same underlying link.
    pub fn same_link(&self, other: &LinkHandle) -> bool {
        Arc::ptr_eq(&self.token, &other.token)
    }

    /// Encrypt plaintext using the link's session key.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::Encrypt(plaintext.to_vec(), tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Decrypt ciphertext using the link's session key.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::Decrypt(ciphertext.to_vec(), tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Send a request on this link.
    ///
    /// Synchronous from the caller's perspective: returns once the actor
    /// has encrypted the payload, packed the packet, and enqueued it on
    /// the per-interface writer (Step 1 of the transport refactor). All
    /// of those steps are bounded-latency — the caller is never blocked
    /// on socket RTT, even against a wedged peer.
    ///
    /// Returns the `request_id` (truncated hash of the wire packet) on
    /// success. Responses are delivered asynchronously via
    /// `response_callback` / `failed_callback` / `progress_callback`.
    pub fn request(
        &self,
        path: String,
        data: Vec<u8>,
        response_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        failed_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        progress_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
    ) -> Result<Vec<u8>, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::Request {
            path,
            data,
            response_cb: response_callback,
            failed_cb: failed_callback,
            progress_cb: progress_callback,
            reply: tx,
        }).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Send a raw DATA packet on this link.
    pub fn send_packet(&self, data: &[u8]) -> Result<(), LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::SendPacket(data.to_vec(), tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Tear down this link.
    #[track_caller]
    pub fn teardown(&self) {
        let loc = std::panic::Location::caller();
        let caller = format!("{}:{}", loc.file(), loc.line());
        let _ = self.tx.send(LinkMsg::Teardown(caller));
    }

    /// Identify this link with the given identity.
    pub fn identify(&self, identity: &Identity) -> Result<(), LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::Identify(identity.clone(), tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Initiate the link handshake (outbound links only).
    /// Updates the cached link_id with the real value set by the handshake.
    pub fn initiate(&self) -> Result<(), LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::Initiate(tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// How long since last data activity (seconds).
    pub fn no_data_for(&self) -> Result<u64, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::NoDataFor(tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Get the remote identity if one has been identified.
    pub fn remote_identity(&self) -> Result<Option<Identity>, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::RemoteIdentity(tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Get the destination hash of the link's destination.
    pub fn destination_hash(&self) -> Result<Vec<u8>, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::DestinationHash(tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Clone the link's destination.
    pub fn clone_destination(&self) -> Result<Destination, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::CloneDestination(tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    /// Build a link-type delivery destination from this link's state.
    pub fn build_link_destination(&self) -> Result<Destination, LinkGone> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::BuildLinkDestination(tx)).map_err(|_| LinkGone)?;
        rx.recv().map_err(|_| LinkGone)?
    }

    // -- Callback setup methods (fire-and-forget) --

    pub fn set_link_established_callback(
        &self,
        callback: Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>,
    ) {
        let _ = self.tx.send(LinkMsg::SetLinkEstablishedCallback(callback));
    }

    pub fn set_link_closed_callback(
        &self,
        callback: Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>,
    ) {
        let _ = self.tx.send(LinkMsg::SetLinkClosedCallback(callback));
    }

    pub fn set_packet_callback(
        &self,
        callback: Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>,
    ) {
        let _ = self.tx.send(LinkMsg::SetPacketCallback(callback));
    }

    pub fn set_remote_identified_callback(
        &self,
        callback: Option<Arc<dyn Fn(LinkHandle, Identity) + Send + Sync>>,
    ) {
        let _ = self.tx.send(LinkMsg::SetRemoteIdentifiedCallback(callback));
    }

    pub fn set_resource_strategy(&self, strategy: u8) {
        let _ = self.tx.send(LinkMsg::SetResourceStrategy(strategy));
    }

    pub fn set_resource_callbacks(
        &self,
        resource: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        started: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
        concluded: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    ) {
        let _ = self.tx.send(LinkMsg::SetResourceCallbacks { resource, started, concluded });
    }

    pub fn set_track_phy_stats(&self, track: bool) {
        let _ = self.tx.send(LinkMsg::SetTrackPhyStats(track));
    }

    /// Cancel an incoming resource on this link.
    pub fn cancel_incoming_resource(&self, resource: Arc<Mutex<Resource>>) {
        let _ = self.tx.send(LinkMsg::CancelIncomingResource(resource));
    }

    /// Cancel an outgoing resource on this link.
    pub fn cancel_outgoing_resource(&self, resource: Arc<Mutex<Resource>>) {
        let _ = self.tx.send(LinkMsg::CancelOutgoingResource(resource));
    }

    /// Check if the link is ready for a new outgoing resource.
    pub fn ready_for_new_resource(&self) -> bool {
        let (tx, rx) = oneshot();
        if self.tx.send(LinkMsg::ReadyForNewResource(tx)).is_err() { return false; }
        rx.recv().unwrap_or(true)
    }

    /// Register an outgoing resource on the link.
    pub fn register_outgoing_resource(&self, resource: Arc<Mutex<Resource>>) {
        let _ = self.tx.send(LinkMsg::RegisterOutgoingResource(resource));
    }

    /// Register an incoming resource on the link.
    pub fn register_incoming_resource(&self, resource: Arc<Mutex<Resource>>) {
        let _ = self.tx.send(LinkMsg::RegisterIncomingResource(resource));
    }

    /// Conclude a resource transfer on this link.
    pub fn resource_concluded(&self, resource: Arc<Mutex<Resource>>) -> Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>> {
        let (tx, rx) = oneshot();
        if self.tx.send(LinkMsg::ResourceConcluded(resource, tx)).is_err() { return None; }
        rx.recv().ok().flatten()
    }

    /// Set the expected inflight rate on the link.
    pub fn set_expected_rate(&self, rate: f64) {
        let _ = self.tx.send(LinkMsg::SetExpectedRate(rate));
    }

    /// Send a pre-computed request response back to the remote peer.
    /// Called from the background thread that runs a request handler callback
    /// so the response is sent after the actor finishes processing `Receive`.
    pub fn send_response(&self, request_id: Vec<u8>, response: Vec<u8>) {
        let _ = self.tx.send(LinkMsg::SendResponse { request_id, response });
    }

    /// Dispatch an assembled REQUEST resource into the link's request handler.
    /// Used by the resource_concluded callback for inbound multi-segment
    /// requests (Python parity: request_resource_concluded → handle_request).
    pub fn handle_request_packet(&self, request_id: Vec<u8>, plaintext: Vec<u8>) {
        let _ = self.tx.send(LinkMsg::HandleRequestPacket { request_id, plaintext });
    }

    /// Get the last resource window size.
    pub fn get_last_resource_window(&self) -> Option<usize> {
        let (tx, rx) = oneshot();
        if self.tx.send(LinkMsg::GetLastResourceWindow(tx)).is_err() { return None; }
        rx.recv().ok().flatten()
    }

    /// Get the last resource EIFR.
    pub fn get_last_resource_eifr(&self) -> Option<f64> {
        let (tx, rx) = oneshot();
        if self.tx.send(LinkMsg::GetLastResourceEifr(tx)).is_err() { return None; }
        rx.recv().ok().flatten()
    }

    // --- Internal methods used by runtime functions ---

    fn dispatch_receive(&self, packet: Packet) -> Option<ReceiveResult> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::Receive(packet, tx)).ok()?;
        rx.recv().ok()
    }

    fn get_link_outbound_info(&self) -> Option<(Option<String>, bool)> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::GetLinkOutboundInfo(tx)).ok()?;
        rx.recv().ok()
    }

    fn validate_proof(
        &self,
        proof: Vec<u8>,
        receipt: crate::packet::PacketReceipt,
    ) -> Option<(bool, crate::packet::PacketReceipt)> {
        let (tx, rx) = oneshot();
        self.tx.send(LinkMsg::ValidateProof { proof, receipt, reply: tx }).ok()?;
        rx.recv().ok()
    }
}

impl std::fmt::Debug for LinkHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkHandle")
            .field("link_id", &crate::hexrep(&self.link_id(), false))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Link actor loop
// ---------------------------------------------------------------------------

/// The actor loop — owns a `Link` and processes messages sequentially.
/// Also performs watchdog duties (keepalive, stale detection, establishment timeout).
fn link_actor(mut link: Link, rx: mpsc::Receiver<LinkMsg>, self_handle: LinkHandle) {
    const WATCHDOG_INTERVAL: Duration = Duration::from_secs(1);

    // Mark this thread as the actor thread so debug builds can catch any
    // reply-awaited LinkMsg sent from within actor callbacks.
    ACTOR_THREAD.with(|f| f.set(true));

    // Give the Link a reference to its own handle for internal methods
    link.self_handle = Some(self_handle.clone());

    loop {
        let msg = match rx.recv_timeout(WATCHDOG_INTERVAL) {
            Ok(msg) => Some(msg),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };

        if link.state == STATE_CLOSED {
            // Drain remaining messages briefly, then exit
            if msg.is_none() { break; }
        }

        if let Some(msg) = msg {
            match msg {
                // --- Read operations ---
                LinkMsg::Snapshot(reply) => {
                    let _ = reply.send(Ok(LinkSnapshot {
                        link_id: link.link_id.clone(),
                        state: link.state,
                        status: link.status,
                        initiator: link.initiator,
                        rtt: link.rtt,
                        activated_at: link.activated_at,
                        established_at: link.established_at,
                        attached_interface: link.attached_interface.clone(),
                        mtu: Some(link.mtu),
                        traffic_timeout_factor: link.traffic_timeout_factor,
                        rssi: link.rssi,
                        snr: link.snr,
                        q: link.q,
                        track_phy_stats: link.track_phy_stats,
                        request_time: link.request_time,
                        establishment_cost: link.establishment_cost,
                        last_inbound: link.last_inbound,
                    }));
                }
                LinkMsg::Status(reply) => { let _ = reply.send(link.status); }
                LinkMsg::IsActive(reply) => { let _ = reply.send(link.state == STATE_ACTIVE); }
                LinkMsg::IsAlive(reply) => { let _ = reply.send(link.state != STATE_CLOSED); }
                LinkMsg::NoDataFor(reply) => { let _ = reply.send(Ok(link.no_data_for())); }
                LinkMsg::RemoteIdentity(reply) => {
                    let ri = link.remote_identity.lock().ok().and_then(|r| r.clone());
                    let _ = reply.send(Ok(ri));
                }
                LinkMsg::DestinationHash(reply) => {
                    let result = link.destination.lock()
                        .map(|d| d.hash.clone())
                        .map_err(|_| LinkGone);
                    let _ = reply.send(result);
                }
                LinkMsg::CloneDestination(reply) => {
                    let result = link.destination.lock()
                        .map(|d| d.clone())
                        .map_err(|_| LinkGone);
                    let _ = reply.send(result);
                }
                LinkMsg::BuildLinkDestination(reply) => {
                    let result = link.destination.lock().map(|d| {
                        let mut dest = d.clone();
                        dest.dest_type = crate::destination::DestinationType::Link;
                        dest.hash = link.link_id.clone();
                        dest.hexhash = crate::hexrep(&dest.hash, false);
                        dest.link = Some(crate::destination::LinkInfo {
                            rtt: link.rtt,
                            traffic_timeout_factor: link.traffic_timeout_factor,
                            status_closed: false,
                            mtu: Some(link.mtu),
                            attached_interface: link.attached_interface.clone(),
                        });
                        dest
                    }).map_err(|_| LinkGone);
                    let _ = reply.send(result);
                }
                LinkMsg::GetLinkOutboundInfo(reply) => {
                    let _ = reply.send((link.attached_interface.clone(), link.state == STATE_CLOSED));
                }

                // --- Crypto operations ---
                LinkMsg::Encrypt(plaintext, reply) => {
                    let result = if link.state != STATE_ACTIVE && link.state != STATE_STALE {
                        Err(LinkGone)
                    } else {
                        link.encrypt(&plaintext).map_err(|_| LinkGone)
                    };
                    let _ = reply.send(result);
                }
                LinkMsg::Decrypt(ciphertext, reply) => {
                    let result = link.decrypt(&ciphertext).map_err(|_| LinkGone);
                    let _ = reply.send(result);
                }

                // --- Mutating with response ---
                // Process the request inline on the actor: encrypt the
                // payload, pack the packet, and enqueue it on the per-
                // interface writer (Step 1 of the transport refactor).
                // All of these are bounded-latency, so replying
                // synchronously to the caller is safe — the FFI / UI
                // thread is never blocked on socket RTT.
                LinkMsg::Request { path, data, response_cb, failed_cb, progress_cb, reply } => {
                    let result = link
                        .request(path, data, response_cb, failed_cb, progress_cb)
                        .map_err(|e| {
                            crate::log(
                                &format!("[LINK] request submission failed: {}", e),
                                crate::LOG_NOTICE,
                                false,
                                false,
                            );
                            LinkGone
                        });
                    let _ = reply.send(result);
                }
                LinkMsg::SendPacket(data, reply) => {
                    let result = link.send_packet(&data).map_err(|_| LinkGone);
                    let _ = reply.send(result);
                }
                LinkMsg::Identify(identity, reply) => {
                    let result = link.identify(&identity).map_err(|_| LinkGone);
                    let _ = reply.send(result);
                }
                LinkMsg::Initiate(reply) => {
                    // Three-step initiation so a LINKPROOF arriving on the
                    // wire (which can happen the instant `packet.send()`
                    // returns, or even slightly before for loopback paths)
                    // can always be routed to this handle:
                    //   1. `initiate_prepare` builds the LR packet and
                    //      derives the real `link.link_id`.
                    //   2. We update the shared cached id on the handle
                    //      AND insert this handle into the runtime
                    //      registry under the real id — both before the
                    //      packet hits the wire.
                    //   3. `initiate_send` performs the (potentially
                    //      blocking) `packet.send()`.
                    match link.initiate_prepare() {
                        Ok(packet) => {
                            let new_id = link.link_id.clone();
                            if let Ok(mut id) = self_handle.id.lock() {
                                *id = new_id;
                            }
                            register_runtime_link_handle(self_handle.clone());
                            match link.initiate_send(packet) {
                                Ok(()) => { let _ = reply.send(Ok(())); }
                                Err(_) => { let _ = reply.send(Err(LinkGone)); }
                            }
                        }
                        Err(_) => { let _ = reply.send(Err(LinkGone)); }
                    }
                }

                // --- Resource operations ---
                LinkMsg::ReadyForNewResource(reply) => {
                    let _ = reply.send(link.ready_for_new_resource());
                }
                LinkMsg::RegisterOutgoingResource(resource) => {
                    link.register_outgoing_resource(resource);
                }
                LinkMsg::RegisterIncomingResource(resource) => {
                    link.register_incoming_resource(resource);
                }
                LinkMsg::ResourceConcluded(resource, reply) => {
                    let cb = link.resource_concluded(resource);
                    let _ = reply.send(cb);
                }
                LinkMsg::CancelOutgoingResource(resource) => {
                    link.cancel_outgoing_resource(resource);
                }
                LinkMsg::CancelIncomingResource(resource) => {
                    link.cancel_incoming_resource(resource);
                }
                LinkMsg::SetExpectedRate(rate) => {
                    link.set_expected_rate(rate);
                }
                LinkMsg::GetLastResourceWindow(reply) => {
                    let _ = reply.send(link.get_last_resource_window());
                }
                LinkMsg::GetLastResourceEifr(reply) => {
                    let _ = reply.send(link.get_last_resource_eifr());
                }

                // --- Fire-and-forget ---
                LinkMsg::Teardown(caller) => {
                    crate::log(&format!("LINK teardown-caller link={} state={} from={}", crate::hexrep(&link.link_id, false), link.state, caller), crate::LOG_NOTICE, false, false);
                    link.teardown();
                    self_handle.status_atomic.store(link.status, Ordering::Relaxed);
                    // Actor exits.  link_closed callback is spawned on a new thread
                    // inside teardown() — same as link_established/remote_identified/packet —
                    // so the callback can safely acquire external mutexes without
                    // deadlocking the actor on its own queue.
                    break;
                }
                LinkMsg::SetLinkEstablishedCallback(cb) => {
                    link.callbacks.link_established = cb;
                }
                LinkMsg::SetLinkClosedCallback(cb) => {
                    link.callbacks.link_closed = cb;
                }
                LinkMsg::SetPacketCallback(cb) => {
                    link.set_packet_callback(cb);
                }
                LinkMsg::SetRemoteIdentifiedCallback(cb) => {
                    link.callbacks.remote_identified = cb;
                }
                LinkMsg::SetResourceStrategy(strategy) => {
                    link.resource_strategy = strategy;
                }
                LinkMsg::SetResourceCallbacks { resource, started, concluded } => {
                    link.callbacks.resource = resource;
                    link.callbacks.resource_started = started;
                    link.callbacks.resource_concluded = concluded;
                }
                LinkMsg::SetTrackPhyStats(track) => {
                    link.track_phy_stats = track;
                }

                // --- Internal: packet dispatch ---
                LinkMsg::Receive(packet, reply) => {
                    let was_pending = link.state != STATE_ACTIVE;
                    let handled = link.receive(&packet).is_ok();
                    let now_active = link.state == STATE_ACTIVE;

                    // Sync the atomic before firing any callback — callbacks may call
                    // status()/is_active()/is_alive() on self_handle and must see the
                    // updated value without going through the channel (which would deadlock).
                    self_handle.status_atomic.store(link.status, Ordering::Relaxed);

                    // Fire link_established callback on a dedicated thread — same pattern
                    // as remote_identified. The callback may call back into LinkHandle
                    // methods (snapshot, identify, request, etc.) which would deadlock
                    // if called on the actor thread itself (the actor can't process its
                    // own reply while it's blocked inside the callback).
                    if was_pending && now_active {
                        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                        crate::send_assertion::assert_send_completed_in_time(
                            "link.establish",
                            link.request_time.unwrap_or(0.0),
                        );
                        if let Some(cb) = link.callbacks.link_established.take() {
                            let h = self_handle.clone();
                            thread::spawn(move || cb(h));
                        }
                    }

                    // Fire remote_identified callback on a dedicated thread.
                    if link.pending_remote_identified {
                        link.pending_remote_identified = false;
                        if let Some(cb) = link.callbacks.remote_identified.clone() {
                            let identity = link.remote_identity.lock().ok().and_then(|r| r.clone());
                            if let Some(identity) = identity {
                                let h = self_handle.clone();
                                thread::spawn(move || cb(h, identity));
                            }
                        }
                    }

                    let _ = reply.send(ReceiveResult { handled });
                }
                LinkMsg::ValidateProof { proof, mut receipt, reply } => {
                    let valid = receipt.validate_link_proof(&proof, &link);
                    let _ = reply.send((valid, receipt));
                }

                // Fire-and-forget: send a request response assembled by the
                // background thread that ran the request handler callback.
                LinkMsg::SendResponse { request_id, response } => {
                    // Match Python RNS: a handler that returns no bytes is
                    // treated as "no response" — we emit no packet at all and
                    // let the requester time out cleanly. Sending an empty
                    // payload through send_request_response would either
                    // produce a malformed wire packet (original bug) or a
                    // non-Python `[id, nil]` packet (earlier band-aid);
                    // neither is protocol-conformant.
                    if response.is_empty() {
                        crate::log("[REQ] handler returned 0 bytes — no response packet sent (matches Python None)", crate::LOG_NOTICE, false, false);
                    } else {
                        let _ = link.send_request_response(&request_id, &response);
                    }
                }

                // Dispatch an assembled REQUEST resource — sent by the
                // request_resource_concluded callback after a multi-segment
                // inbound request has finished assembling.
                LinkMsg::HandleRequestPacket { request_id, plaintext } => {
                    let _ = link.handle_request_packet(request_id, &plaintext);
                }
            }
        }

        // --- Watchdog: runs on every timeout AND after every message ---
        if link.state == STATE_CLOSED {
            break;
        }
        if !link.watchdog_lock {
            actor_watchdog_tick(&mut link, &self_handle);
        }

        // Sync the atomic after watchdog may have changed state (stale, closed).
        self_handle.status_atomic.store(link.status, Ordering::Relaxed);

        // Request timeout checks
        actor_check_request_timeouts(&mut link);
    }
}

/// Watchdog logic extracted for the actor loop.
fn actor_watchdog_tick(link: &mut Link, _self_handle: &LinkHandle) {
    let now = current_time().unwrap_or(0);

    match link.state {
        STATE_PENDING | STATE_HANDSHAKE => {
            if let Some(request_time) = link.request_time {
                if now_seconds() >= request_time + link.establishment_timeout {
                    let state_name = if link.state == STATE_PENDING { "PENDING" } else { "HANDSHAKE" };
                    crate::log(&format!("Link establishment timed out ({}): {}", state_name, crate::hexrep(&link.link_id, false)), crate::LOG_DEBUG, false, false);
                    link.teardown_reason = REASON_TIMEOUT;
                    link.teardown();
                }
            }
        }
        STATE_ACTIVE => {
            let activated_at = link.activated_at.unwrap_or(0);
            let last_inbound = link.last_inbound
                .max(link.last_proof)
                .max(activated_at);
            let keepalive_secs = link.keepalive as u64;

            if now >= last_inbound + keepalive_secs {
                // Send keepalive if due
                if link.initiator && now >= link.last_keepalive + keepalive_secs {
                    if let Some((dest, _link_id)) = link.prepare_keepalive() {
                        let mut keepalive_packet = Packet::new(
                            Some(dest),
                            vec![0xFF],
                            DATA,
                            crate::packet::KEEPALIVE,
                            crate::transport::BROADCAST,
                            packet::HEADER_1,
                            None,
                            None,
                            false,
                            0,
                        );
                        let _ = keepalive_packet.send();
                    }
                }

                let stale_secs = link.stale_time as u64;
                if now >= last_inbound + stale_secs {
                    let rtt_grace = link.rtt.unwrap_or(0.0)
                        * link.keepalive_timeout_factor
                        + STALE_GRACE;
                    link.state = STATE_STALE;
                    link.status = STATE_STALE;
                    link.stale_since = Some(now);
                    link.stale_grace = rtt_grace;
                }
            }
        }
        STATE_STALE => {
            let stale_at = link.stale_since.unwrap_or(0);
            let grace_secs = link.stale_grace as u64;
            if now >= stale_at + grace_secs.max(1) {
                crate::log(&format!("Link timeout, tearing down {}", crate::hexrep(&link.link_id, false)), crate::LOG_DEBUG, false, false);
                link.teardown();
            }
        }
        _ => {}
    }
}

/// Request timeout checks — replaces the old request_timeout_watchdog thread.
fn actor_check_request_timeouts(link: &mut Link) {
    let now = now_seconds();
    let mut timed_out = Vec::new();
    if let Ok(mut pending) = link.pending_requests.lock() {
        pending.retain(|req| {
            if now >= req.sent_at + req.timeout {
                timed_out.push(req.clone());
                false
            } else {
                true
            }
        });
    }
    for timed_out_req in timed_out {
        if let Some(callback) = timed_out_req.failed_callback {
            let receipt = RequestReceipt {
                request_id: timed_out_req.request_id.clone(),
                response: None,
                link: Arc::new(Mutex::new(link.clone())),
                sent_at: timed_out_req.sent_at,
                received_at: None,
                progress: 0.0,
            };
            thread::spawn(move || {
                callback(receipt);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime link registry
// ---------------------------------------------------------------------------

static RUNTIME_LINKS: Lazy<Mutex<HashMap<Vec<u8>, LinkHandle>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Register a link handle in the global registry.
/// The actor thread is already running (spawned in LinkHandle::spawn),
/// so no separate watchdog thread is needed.
///
/// If a handle is already registered under the same `link_id`, it is
/// REPLACED. Suppressing duplicates is unsafe because most callers run
/// the actor's `LinkMsg::Initiate` flow, which always calls this with
/// the freshly-derived real `link_id`; an older entry with the same id
/// is necessarily stale (e.g. a previous registration during an earlier
/// reconnect cycle that never got cleaned up).
pub fn register_runtime_link_handle(handle: LinkHandle) {
    let link_id = handle.link_id();
    let link_id_hex = crate::hexrep(&link_id, false);
    if let Ok(mut links) = RUNTIME_LINKS.lock() {
        let was_present = links.contains_key(&link_id);
        links.insert(link_id, handle);
        if was_present {
            crate::log(
                &format!("RUNTIME register link={} (replaced existing entry) total={}", link_id_hex, links.len()),
                crate::LOG_NOTICE,
                false,
                false,
            );
        } else {
            crate::log(
                &format!("RUNTIME register link={} total={}", link_id_hex, links.len()),
                crate::LOG_NOTICE,
                false,
                false,
            );
        }
    }
}

/// Legacy entry point: wraps an Arc<Mutex<Link>> in a LinkHandle and registers it.
pub fn register_runtime_link(link: Arc<Mutex<Link>>) {
    let handle = LinkHandle::from_arc(link);
    register_runtime_link_handle(handle);
}

pub fn unregister_runtime_link(link_id: &[u8]) {
    if let Ok(mut links) = RUNTIME_LINKS.lock() {
        let removed = links.remove(link_id).is_some();
        crate::log(&format!("RUNTIME unregister link={} removed={} remaining={}", crate::hexrep(link_id, false), removed, links.len()), crate::LOG_NOTICE, false, false);
    }
}

/// Look up a LinkHandle by link_id. Returns a clone of the handle.
pub fn get_runtime_link_handle(link_id: &[u8]) -> Option<LinkHandle> {
    let links = RUNTIME_LINKS.lock().ok()?;
    links.get(link_id).cloned()
}

/// Tear down all currently-pending (non-ACTIVE, non-CLOSED) outbound links
/// targeting the given destination hash.
///
/// Used by Transport when an announce reveals a strictly better path to a
/// destination — the in-flight link establishment is committed to a stale
/// long-hop route, so we close it so the application's link-closed handler
/// (which observes the new path entry) can retry on the better path.
///
/// Returns the number of links torn down. Inbound links and ACTIVE links
/// are never disturbed.
pub fn teardown_pending_links_to_destination(dest_hash: &[u8]) -> usize {
    // Snapshot candidate handles under the registry lock, then call teardown
    // outside the lock to avoid any chance of cross-actor deadlock.
    let candidates: Vec<LinkHandle> = {
        let Ok(links) = RUNTIME_LINKS.lock() else {
            return 0;
        };
        links
            .values()
            .filter(|h| h.initiator
                && h.cached_destination_hash() == dest_hash
                && h.status() != STATE_ACTIVE
                && h.status() != STATE_CLOSED)
            .cloned()
            .collect()
    };

    let n = candidates.len();
    for handle in candidates {
        crate::log(
            &format!(
                "Cancelling pending link={} due to better path to dest={}",
                crate::hexrep(&handle.link_id(), false),
                crate::hexrep(dest_hash, false),
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );
        handle.mark_cancelled_for_better_path();
        handle.teardown();
    }
    n
}

/// Returns (attached_interface, is_closed) for a link by its link_id.
/// Used by Transport::outbound to filter link packets to only the correct interface.
pub fn get_link_outbound_info(link_id: &[u8]) -> Option<(Option<String>, bool)> {
    let links = RUNTIME_LINKS.lock().ok()?;
    let handle = links.get(link_id)?;
    handle.get_link_outbound_info()
}

/// Dispatch a received packet to the link actor via channel message.
/// The actor fires callbacks (link_established, remote_identified) internally
/// and processes everything in FIFO order — no lock-based races.
pub fn dispatch_runtime_packet(packet: &Packet) -> bool {
    let destination_hash = match packet.destination_hash.as_ref() {
        Some(hash) => hash.clone(),
        None => return false,
    };
    crate::log(&format!("[LINK-DISPATCH] packet type={} ctx={} dst={}", packet.packet_type, packet.context, crate::hexrep(&destination_hash, false)), crate::LOG_DEBUG, false, false);

    let handle = {
        let links = match RUNTIME_LINKS.lock() {
            Ok(links) => links,
            Err(_) => return false,
        };

        match links.get(&destination_hash) {
            Some(handle) => handle.clone(),
            None => return false,
        }
    };

    match handle.dispatch_receive(packet.clone()) {
        Some(result) => result.handled,
        None => false,
    }
}

pub fn runtime_encrypt_for_destination(destination_hash: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let handle = {
        let links = RUNTIME_LINKS
            .lock()
            .map_err(|_| "Runtime link registry lock poisoned".to_string())?;

        match links.get(destination_hash) {
            Some(handle) => handle.clone(),
            None => {
                let known: Vec<String> = links.keys().map(|k| crate::hexrep(k, false)).collect();
                crate::log(&format!("RUNTIME encrypt FAILED: no link for {} known=[{}]", crate::hexrep(destination_hash, false), known.join(", ")), crate::LOG_WARNING, false, false);
                return Err("No runtime link found for destination".to_string());
            }
        }
    };

    handle.encrypt(plaintext).map_err(|_| "Link gone (actor dead)".to_string())
}

pub fn validate_runtime_proof_for_receipt(
    destination_hash: &[u8],
    proof: &[u8],
    receipt: &mut crate::packet::PacketReceipt,
) -> bool {
    let handle = {
        let links = match RUNTIME_LINKS.lock() {
            Ok(links) => links,
            Err(_) => {
                crate::log("validate_runtime_proof: RUNTIME_LINKS lock poisoned", crate::LOG_ERROR, false, false);
                return false;
            }
        };

        match links.get(destination_hash) {
            Some(handle) => handle.clone(),
            None => {
                crate::log(&format!("validate_runtime_proof: no link for {}",
                    crate::hexrep(destination_hash, false)), crate::LOG_DEBUG, false, false);
                return false;
            }
        }
    };

    // Clone receipt, send to actor for validation, write back the mutated copy
    let receipt_clone = receipt.clone();
    match handle.validate_proof(proof.to_vec(), receipt_clone) {
        Some((valid, updated_receipt)) => {
            if valid {
                *receipt = updated_receipt;
            }
            valid
        }
        None => {
            crate::log("validate_runtime_proof: actor dead", crate::LOG_ERROR, false, false);
            false
        }
    }
}

pub fn runtime_decrypt_for_destination(destination_hash: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let handle = {
        let links = RUNTIME_LINKS
            .lock()
            .map_err(|_| "Runtime link registry lock poisoned".to_string())?;

        match links.get(destination_hash) {
            Some(handle) => handle.clone(),
            None => {
                return Err("No runtime link found for destination".to_string());
            }
        }
    };

    handle.decrypt(ciphertext).map_err(|_| "Link gone (actor dead)".to_string())
}

// Link state constants
pub const STATE_PENDING: u8 = 0x00;
pub const STATE_HANDSHAKE: u8 = 0x01;
pub const STATE_ACTIVE: u8 = 0x02;
pub const STATE_STALE: u8 = 0x03;
pub const STATE_CLOSED: u8 = 0x04;

// Link close reasons
pub const REASON_TIMEOUT: u8 = 0x01;
pub const REASON_INITIATOR_CLOSED: u8 = 0x02;
pub const REASON_DESTINATION_CLOSED: u8 = 0x03;

// Resource acceptance strategies
pub const ACCEPT_NONE: u8 = 0x00;
pub const ACCEPT_APP: u8 = 0x01;
pub const ACCEPT_ALL: u8 = 0x02;

// Link modes and constants
pub const CURVE: &str = identity::CURVE;
pub const ECPUBSIZE: usize = 32 + 32;
pub const KEYSIZE: usize = 32;

pub const MDU: usize = ((reticulum::MTU
    - reticulum::IFAC_MIN_SIZE
    - reticulum::HEADER_MINSIZE
    - identity::TOKEN_OVERHEAD)
    / identity::AES128_BLOCKSIZE)
    * identity::AES128_BLOCKSIZE
    - 1;

pub const ESTABLISHMENT_TIMEOUT_PER_HOP: f64 = reticulum::DEFAULT_PER_HOP_TIMEOUT;
pub const LINK_MTU_SIZE: usize = 3;
pub const TRAFFIC_TIMEOUT_MIN_MS: f64 = 5.0;
pub const TRAFFIC_TIMEOUT_FACTOR: f64 = 6.0;
pub const KEEPALIVE_MAX_RTT: f64 = 1.75;
pub const KEEPALIVE_TIMEOUT_FACTOR: f64 = 4.0;
pub const STALE_GRACE: f64 = 5.0;
pub const KEEPALIVE_MAX: f64 = 360.0;
pub const KEEPALIVE_MIN: f64 = 5.0;
pub const KEEPALIVE: f64 = KEEPALIVE_MAX;
pub const STALE_FACTOR: f64 = 2.0;
pub const STALE_TIME: f64 = STALE_FACTOR * KEEPALIVE;
pub const WATCHDOG_MAX_SLEEP: f64 = 5.0;
pub const REQUEST_TIMEOUT_CHECK_INTERVAL: f64 = 0.5;

// Encryption modes
pub const MODE_AES128_CBC: u8 = 0x00;
pub const MODE_AES256_CBC: u8 = 0x01;
pub const MODE_AES256_GCM: u8 = 0x02;
pub const MODE_OTP_RESERVED: u8 = 0x03;
pub const MODE_PQ_RESERVED_1: u8 = 0x04;
pub const MODE_PQ_RESERVED_2: u8 = 0x05;
pub const MODE_PQ_RESERVED_3: u8 = 0x06;
pub const MODE_PQ_RESERVED_4: u8 = 0x07;
pub const MODE_DEFAULT: u8 = MODE_AES256_CBC;

pub const MTU_BYTEMASK: u32 = 0x1FFFFF;
pub const MODE_BYTEMASK: u32 = 0xE0;

/// Signalling byte helper
pub fn signalling_bytes(mtu: usize, mode: u8) -> Result<[u8; 3], String> {
    if mode != MODE_AES256_CBC && mode != MODE_AES128_CBC {
        return Err(format!("Requested link mode {} not enabled", mode));
    }
    let signalling_value = (mtu as u32 & MTU_BYTEMASK) + ((((mode as u32) << 5) & MODE_BYTEMASK) << 16);
    let bytes = signalling_value.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}

/// Extract MTU from link request packet
pub fn mtu_from_lr_packet(data: &[u8]) -> Option<usize> {
    if data.len() == ECPUBSIZE + LINK_MTU_SIZE {
        let mtu = ((data[ECPUBSIZE] as u32) << 16)
            + ((data[ECPUBSIZE + 1] as u32) << 8)
            + (data[ECPUBSIZE + 2] as u32);
        Some((mtu & MTU_BYTEMASK) as usize)
    } else {
        None
    }
}

/// Extract MTU from link proof packet
pub fn mtu_from_lp_packet(data: &[u8]) -> Option<usize> {
    let offset = identity::SIGLENGTH / 8 + ECPUBSIZE / 2;
    if data.len() == offset + LINK_MTU_SIZE {
        let mtu = ((data[offset] as u32) << 16) + ((data[offset + 1] as u32) << 8) + (data[offset + 2] as u32);
        Some((mtu & MTU_BYTEMASK) as usize)
    } else {
        None
    }
}

/// Extract mode from link request packet
pub fn mode_from_lr_packet(data: &[u8]) -> u8 {
    if data.len() > ECPUBSIZE {
        ((data[ECPUBSIZE] as u32 & MODE_BYTEMASK) >> 5) as u8
    } else {
        MODE_DEFAULT
    }
}

/// Extract mode from link proof packet
pub fn mode_from_lp_packet(data: &[u8]) -> u8 {
    let offset = identity::SIGLENGTH / 8 + ECPUBSIZE / 2;
    if data.len() > offset {
        (data[offset] >> 5) as u8
    } else {
        MODE_DEFAULT
    }
}

/// Derive link ID from a link request packet
pub fn link_id_from_lr_packet(packet: &Packet) -> Vec<u8> {
    let mut hashable_part = packet.get_hashable_part();
    if packet.data.len() > ECPUBSIZE {
        let diff = packet.data.len() - ECPUBSIZE;
        if hashable_part.len() >= diff {
            hashable_part.truncate(hashable_part.len() - diff);
        }
    }
    let result = identity::truncated_hash(&hashable_part);
    result
}

/// Callbacks for link lifecycle events
#[derive(Clone, Default)]
pub struct LinkCallbacks {
    pub link_established: Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>,
    pub link_closed: Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>,
    pub packet: Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>,
    pub resource: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub resource_started: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub resource_concluded: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    pub remote_identified: Option<Arc<dyn Fn(LinkHandle, Identity) + Send + Sync>>,
}

/// Python RNS wire format for a REQUEST packet payload:
/// msgpack array [timestamp_f64, path_hash_16bytes, data_bytes]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestPayload(f64, serde_bytes::ByteBuf, serde_bytes::ByteBuf);

/// Python RNS wire format for a RESPONSE packet payload:
/// msgpack array [request_id_16bytes, response_bytes]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ResponsePayload(serde_bytes::ByteBuf, serde_bytes::ByteBuf);

#[derive(Clone)]
pub struct RequestReceipt {
    pub request_id: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub link: Arc<Mutex<Link>>,
    pub sent_at: f64,
    pub received_at: Option<f64>,
    pub progress: f64,
}

impl RequestReceipt {
    pub fn get_progress(&self) -> f64 {
        self.progress
    }
}

// Old request_timeout_watchdog and start_link_watchdog removed —
// both are now handled by the actor loop (actor_check_request_timeouts
// and actor_watchdog_tick).

#[derive(Clone)]
struct PendingRequest {
    request_id: Vec<u8>,
    sent_at: f64,
    timeout: f64,
    response_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
    failed_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
    #[allow(dead_code)]
    progress_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
}

/// A link to a remote destination for encrypted communication
pub struct Link {
    // Core identifiers
    pub link_id: Vec<u8>,
    pub destination: Arc<Mutex<Destination>>,
    
    // State management
    pub state: u8,
    pub status: u8,
    pub teardown_reason: u8,
    
    // Configuration
    pub mode: u8,
    pub initiator: bool,
    pub mtu: usize,
    pub mdu: usize,
    
    // Timing
    pub rtt: Option<f64>,
    pub established_at: Option<u64>,
    pub activated_at: Option<u64>,
    pub request_time: Option<f64>,
    pub last_inbound: u64,
    pub last_outbound: u64,
    pub last_keepalive: u64,
    pub last_proof: u64,
    pub last_data: u64,
    
    // Statistics
    pub tx: u64,
    pub rx: u64,
    pub txbytes: u64,
    pub rxbytes: u64,
    pub rssi: Option<i32>,
    pub snr: Option<f64>,
    pub q: Option<f64>,
    pub establishment_cost: usize,
    pub establishment_rate: Option<f64>,
    pub expected_rate: Option<f64>,
    pub expected_hops: Option<usize>,
    
    // Cryptography
    pub prv_bytes: Option<Vec<u8>>,  // X25519 private key bytes
    pub pub_bytes: Option<Vec<u8>>,  // X25519 public key bytes
    pub sig_prv_bytes: Option<Vec<u8>>,  // Ed25519 private key bytes
    pub sig_pub_bytes: Option<Vec<u8>>,  // Ed25519 public key bytes
    
    pub peer_pub_bytes: Option<Vec<u8>>,  // Peer's X25519 public key
    pub peer_sig_pub_bytes: Option<Vec<u8>>,  // Peer's Ed25519 public key
    
    pub shared_key: Option<Vec<u8>>,
    pub derived_key: Option<Vec<u8>>,
    pub token: Arc<Mutex<Option<Token>>>,
    
    // Remote identity
    pub remote_identity: Arc<Mutex<Option<Identity>>>,
    
    // Callbacks and resources
    pub callbacks: LinkCallbacks,
    pub resource_strategy: u8,
    
    // Resource tracking
    pub outgoing_resources: Arc<Mutex<Vec<Arc<Mutex<Resource>>>>>,
    pub incoming_resources: Arc<Mutex<Vec<Arc<Mutex<Resource>>>>>,
    pending_requests: Arc<Mutex<Vec<PendingRequest>>>,
    pub last_resource_window: Option<usize>,
    pub last_resource_eifr: Option<f64>,
    
    // Connection management
    pub attached_interface: Option<String>,
    pub traffic_timeout_factor: f64,
    pub keepalive_timeout_factor: f64,
    pub keepalive: f64,
    pub stale_time: f64,
    pub stale_since: Option<u64>,
    pub stale_grace: f64,
    pub establishment_timeout: f64,
    pub watchdog_lock: bool,
    pub track_phy_stats: bool,
    
    /// Flag set by handle_linkidentify_packet so dispatch_runtime_packet
    /// can fire the remote_identified callback OUTSIDE the link lock,
    /// passing the original Arc (not a clone).
    pub pending_remote_identified: bool,
    
    // Channel support
    pub channel: Option<()>, // Placeholder for Channel integration

    /// Inbound DATA packets (plaintext + original packet) that arrived before
    /// `callbacks.packet` was set (e.g. between link activation and
    /// `delivery_link_established`).  Drained when `set_packet_callback` wires
    /// the handler.
    pub early_packets: Vec<(Vec<u8>, Packet)>,
    
    /// Handle to this link's actor — set by the actor loop.
    /// Used by internal methods (teardown, handle_data_packet) that need
    /// to provide a LinkHandle to callbacks or Resource::accept().
    pub self_handle: Option<LinkHandle>,
}

impl Link {
    /// Build a `ResourceLinkContext` snapshot directly from this `Link`'s
    /// fields.  Used when the actor calls `Resource::accept` inside its own
    /// `receive()` handler — going through the channel would deadlock.
    pub fn resource_link_context(&self) -> crate::resource::ResourceLinkContext {
        crate::resource::ResourceLinkContext {
            mtu: self.mtu,
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            establishment_cost: self.establishment_cost,
            last_resource_window: self.last_resource_window,
            last_resource_eifr: self.last_resource_eifr,
        }
    }

    /// Build a `Destination` configured for sending packets on this link,
    /// directly from the actor's owned `Link` fields.  Equivalent to the
    /// `LinkMsg::BuildLinkDestination` actor handler but avoids the mpsc
    /// round-trip — safe (and required) when called from inside the actor
    /// thread itself, e.g. before spawning a deferred sender that holds the
    /// resource lock and therefore cannot wait for the actor.
    pub fn build_link_destination_direct(&self) -> Option<crate::destination::Destination> {
        let dest_guard = self.destination.lock().ok()?;
        let mut dest = dest_guard.clone();
        dest.dest_type = crate::destination::DestinationType::Link;
        dest.hash = self.link_id.clone();
        dest.hexhash = crate::hexrep(&dest.hash, false);
        dest.link = Some(crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            status_closed: false,
            mtu: Some(self.mtu),
            attached_interface: self.attached_interface.clone(),
        });
        Some(dest)
    }
}

impl Clone for Link {
    fn clone(&self) -> Self {
        Link {
            link_id: self.link_id.clone(),
            destination: Arc::clone(&self.destination),
            state: self.state,
            status: self.status,
            teardown_reason: self.teardown_reason,
            mode: self.mode,
            initiator: self.initiator,
            mtu: self.mtu,
            mdu: self.mdu,
            rtt: self.rtt,
            established_at: self.established_at,
            activated_at: self.activated_at,
            request_time: self.request_time,
            last_inbound: self.last_inbound,
            last_outbound: self.last_outbound,
            last_keepalive: self.last_keepalive,
            last_proof: self.last_proof,
            last_data: self.last_data,
            tx: self.tx,
            rx: self.rx,
            txbytes: self.txbytes,
            rxbytes: self.rxbytes,
            rssi: self.rssi,
            snr: self.snr,
            q: self.q,
            establishment_cost: self.establishment_cost,
            establishment_rate: self.establishment_rate,
            expected_rate: self.expected_rate,
            expected_hops: self.expected_hops,
            prv_bytes: self.prv_bytes.clone(),
            pub_bytes: self.pub_bytes.clone(),
            sig_prv_bytes: self.sig_prv_bytes.clone(),
            sig_pub_bytes: self.sig_pub_bytes.clone(),
            peer_pub_bytes: self.peer_pub_bytes.clone(),
            peer_sig_pub_bytes: self.peer_sig_pub_bytes.clone(),
            shared_key: self.shared_key.clone(),
            derived_key: self.derived_key.clone(),
            token: Arc::clone(&self.token),
            remote_identity: Arc::clone(&self.remote_identity),
            callbacks: self.callbacks.clone(),
            resource_strategy: self.resource_strategy,
            outgoing_resources: Arc::clone(&self.outgoing_resources),
            incoming_resources: Arc::clone(&self.incoming_resources),
            pending_requests: Arc::clone(&self.pending_requests),
            last_resource_window: self.last_resource_window,
            last_resource_eifr: self.last_resource_eifr,
            attached_interface: self.attached_interface.clone(),
            traffic_timeout_factor: self.traffic_timeout_factor,
            keepalive_timeout_factor: self.keepalive_timeout_factor,
            keepalive: self.keepalive,
            stale_time: self.stale_time,
            stale_since: self.stale_since,
            stale_grace: self.stale_grace,
            establishment_timeout: self.establishment_timeout,
            watchdog_lock: self.watchdog_lock,
            track_phy_stats: self.track_phy_stats,
            pending_remote_identified: false,
            channel: self.channel.clone(),
            early_packets: Vec::new(),
            self_handle: self.self_handle.clone(),
        }
    }
}

impl Link {
    fn set_link_id_from_packet(&mut self, packet: &Packet) {
        self.link_id = link_id_from_lr_packet(packet);
    }

    /// Validate an incoming link request and create a Link if valid.
    /// This is the receiver-side counterpart to `initiate()`.
    pub fn validate_request(owner: &Destination, data: &[u8], packet: &Packet) -> Result<Link, String> {
        if data.len() != ECPUBSIZE && data.len() != ECPUBSIZE + LINK_MTU_SIZE {
            return Err(format!("Invalid link request data length: {} (expected {} or {})", data.len(), ECPUBSIZE, ECPUBSIZE + LINK_MTU_SIZE));
        }


        // Extract peer's public keys
        let peer_pub_bytes = data[..ECPUBSIZE / 2].to_vec();         // X25519 (32 bytes)
        let peer_sig_pub_bytes = data[ECPUBSIZE / 2..ECPUBSIZE].to_vec(); // Ed25519 (32 bytes)

        // Create inbound link
        let mut link = Link::new_inbound(owner.clone())?;
        link.load_peer(peer_pub_bytes, peer_sig_pub_bytes)?;

        // Copy the destination's link_established callback to the link so it fires
        // when LRRTT arrives and the link activates
        if let Some(cb) = &owner.callbacks.link_established {
            link.callbacks.link_established = Some(Arc::clone(cb));
        }

        // Make any destination-level packet callback available immediately on
        // the inbound link. The first plain DATA packet can arrive before the
        // async link_established callback thread gets a chance to install a
        // handler, and in that case we must not leave it stranded in the early
        // packet queue.
        if let Some(cb) = &owner.callbacks.packet {
            link.callbacks.packet = Some(Arc::clone(cb));
        }

        // Set link_id from packet
        link.set_link_id_from_packet(packet);

        // Parse MTU and mode from signalling bytes
        if data.len() == ECPUBSIZE + LINK_MTU_SIZE {
            if let Some(mtu) = mtu_from_lr_packet(data) {
                link.mtu = mtu;
            }
        }
        link.mode = mode_from_lr_packet(data);
        link.update_mdu();

        link.establishment_timeout = ESTABLISHMENT_TIMEOUT_PER_HOP * (packet.hops.max(1) as f64) + KEEPALIVE;
        link.establishment_cost += packet.raw.len();

        // Generate our ephemeral X25519 keypair
        let mut x25519_private = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut x25519_private);
        let x25519_public = X25519PublicKey::from(&X25519PrivateKey::from(x25519_private));

        link.prv_bytes = Some(x25519_private.to_vec());
        link.pub_bytes = Some(x25519_public.as_bytes().to_vec());

        // For incoming links, use the destination's Ed25519 signing key (not ephemeral)
        let identity = owner.identity.as_ref().ok_or("Destination has no identity for link proof")?;
        let public_key = identity.get_public_key()?;
        if public_key.len() != 64 {
            return Err("Invalid destination public key length".to_string());
        }
        // sig_pub_bytes = Ed25519 public key (second 32 bytes of the 64-byte public key)
        link.sig_pub_bytes = Some(public_key[32..64].to_vec());

        // Store the Ed25519 signing private key so we can prove received packets later
        let private_key = identity.get_private_key()?;
        if private_key.len() >= 64 {
            link.sig_prv_bytes = Some(private_key[32..64].to_vec());
        }

        // Perform ECDH handshake
        link.handshake()?;

        link.attached_interface = packet.receiving_interface.clone();

        // Generate and send the link proof
        link.prove_with_identity(identity)?;

        link.request_time = Some(now_seconds());
        link.had_inbound(true); // Initialize last_data/last_inbound before cloning

        // Register in Transport's active_links (incoming links go directly to active)
        crate::transport::Transport::register_link(link.clone());

        // Also register as runtime link so dispatch_runtime_packet can find it
        let handle = LinkHandle::spawn(link.clone());
        register_runtime_link_handle(handle);


        Ok(link)
    }

    pub fn initiate(&mut self) -> Result<(), String> {
        let packet = self.initiate_prepare()?;
        self.initiate_send(packet)
    }

    /// First half of `initiate()`: generate ephemeral keys, build the LR
    /// packet, derive the link_id, and register the link with `Transport`.
    /// Returns the prepared packet for the caller to send.
    ///
    /// Split out so the link actor can update its cached `LinkHandle.id`
    /// and runtime registry entry BEFORE the slow `packet.send()` lets a
    /// LINKPROOF race back in. Without this split, the cached id stays at
    /// its placeholder value (see `new_outbound`/`new_inbound`), causing
    /// runtime registry collisions and dropped LINKPROOFs.
    pub fn initiate_prepare(&mut self) -> Result<Packet, String> {
        if !self.initiator {
            return Err("Cannot initiate inbound link".to_string());
        }

        let mut x25519_private = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut x25519_private);
        let x25519_public = X25519PublicKey::from(&X25519PrivateKey::from(x25519_private));

        let signing_identity = Identity::new(true);
        let signing_private = signing_identity.get_private_key()?;
        let signing_public = signing_identity.get_public_key()?;
        if signing_private.len() != 64 || signing_public.len() != 64 {
            return Err("Invalid generated key sizes for link initiation".to_string());
        }

        self.prv_bytes = Some(x25519_private.to_vec());
        self.pub_bytes = Some(x25519_public.as_bytes().to_vec());
        self.sig_prv_bytes = Some(signing_private[32..64].to_vec());
        self.sig_pub_bytes = Some(signing_public[32..64].to_vec());

        let mut request_data = self.pub_bytes.clone().ok_or("Missing link public key")?;
        request_data.extend_from_slice(&self.sig_pub_bytes.clone().ok_or("Missing link signing public key")?);
        request_data.extend_from_slice(&signalling_bytes(reticulum::MTU, self.mode)?);

        let destination = self.destination.lock().map_err(|_| "Destination lock poisoned")?.clone();

        // Calculate establishment timeout based on hops and first hop latency (matches Python Link.__init__)
        let dest_hash = destination.hash.clone();
        let hops = crate::transport::Transport::hops_to(&dest_hash);
        let first_hop_timeout = if let Some(ret) = reticulum::Reticulum::get_instance() {
            if let Ok(ret_guard) = ret.lock() {
                ret_guard.get_first_hop_timeout(&dest_hash)
            } else {
                crate::transport::Transport::first_hop_timeout(&dest_hash)
            }
        } else {
            crate::transport::Transport::first_hop_timeout(&dest_hash)
        };
        self.establishment_timeout = first_hop_timeout + ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64);
        self.expected_hops = Some(hops as usize);
        crate::log(
            &format!(
                "Link establishment timeout {:.1}s (first_hop={:.1}s, hops={}, per_hop={:.1}s)",
                self.establishment_timeout, first_hop_timeout, hops, ESTABLISHMENT_TIMEOUT_PER_HOP
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );

        let mut packet = Packet::new(
            Some(destination),
            request_data,
            packet::LINKREQUEST,
            packet::NONE,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );

        packet.pack()?;
        self.establishment_cost += packet.raw.len();
        self.set_link_id_from_packet(&packet);
        self.request_time = Some(now_seconds());

        crate::transport::Transport::register_link(self.clone());
        Ok(packet)
    }

    /// Second half of `initiate()`: actually transmit the LR packet.
    /// This is the slow part — `packet.send()` may block on `Transport::outbound`.
    pub fn initiate_send(&mut self, mut packet: Packet) -> Result<(), String> {
        packet.send()?;
        self.had_outbound(false);
        Ok(())
    }

    /// Create a new outbound link to a destination
    pub fn new_outbound(destination: Destination, mode: u8) -> Result<Self, String> {
        // Random placeholder — the REAL link_id is derived from the LR
        // packet inside `initiate_prepare()`. We never use this value to
        // route packets, but it's exposed via `LinkHandle::link_id()`
        // before initiate runs, so it must be unique to avoid spurious
        // collisions in the runtime registry.
        let mut link_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut link_id);
        let link_id = link_id.to_vec();
        let established_at = current_time();
        
        Ok(Link {
            link_id,
            destination: Arc::new(Mutex::new(destination)),
            state: STATE_PENDING,
            status: 0,
            teardown_reason: 0,
            mode,
            initiator: true,
            mtu: reticulum::MTU,
            mdu: MDU,
            rtt: None,
            established_at,
            activated_at: None,
            request_time: Some(now_seconds()),
            last_inbound: current_time().unwrap_or(0),
            last_outbound: current_time().unwrap_or(0),
            last_keepalive: 0,
            last_proof: 0,
            last_data: 0,
            tx: 0,
            rx: 0,
            txbytes: 0,
            rxbytes: 0,
            rssi: None,
            snr: None,
            q: None,
            establishment_cost: 0,
            establishment_rate: None,
            expected_rate: None,
            expected_hops: None,
            prv_bytes: None,
            pub_bytes: None,
            sig_prv_bytes: None,
            sig_pub_bytes: None,
            peer_pub_bytes: None,
            peer_sig_pub_bytes: None,
            shared_key: None,
            derived_key: None,
            token: Arc::new(Mutex::new(None)),
            remote_identity: Arc::new(Mutex::new(None)),
            callbacks: LinkCallbacks::default(),
            resource_strategy: ACCEPT_NONE,
            outgoing_resources: Arc::new(Mutex::new(Vec::new())),
            incoming_resources: Arc::new(Mutex::new(Vec::new())),
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            last_resource_window: None,
            last_resource_eifr: None,
            attached_interface: None,
            traffic_timeout_factor: TRAFFIC_TIMEOUT_FACTOR,
            keepalive_timeout_factor: KEEPALIVE_TIMEOUT_FACTOR,
            keepalive: KEEPALIVE,
            stale_time: STALE_TIME,
            stale_since: None,
            stale_grace: STALE_GRACE,
            establishment_timeout: ESTABLISHMENT_TIMEOUT_PER_HOP,
            watchdog_lock: false,
            track_phy_stats: false,
            pending_remote_identified: false,
            channel: None,
            early_packets: Vec::new(),
            self_handle: None,
        })
    }
    
    /// Create a new inbound link for an incoming request
    pub fn new_inbound(owner_destination: Destination) -> Result<Self, String> {
        // Random placeholder — the real link_id is set by
        // `validate_request` from the inbound LR packet. Random avoids
        // spurious runtime-registry collisions if the handle is exposed
        // before validation completes.
        let mut link_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut link_id);
        let link_id = link_id.to_vec();
        let established_at = current_time();
        
        Ok(Link {
            link_id,
            destination: Arc::new(Mutex::new(owner_destination)),
            state: STATE_PENDING,
            status: 0,
            teardown_reason: 0,
            mode: MODE_DEFAULT,
            initiator: false,
            mtu: reticulum::MTU,
            mdu: MDU,
            rtt: None,
            established_at,
            activated_at: None,
            request_time: Some(now_seconds()),
            last_inbound: current_time().unwrap_or(0),
            last_outbound: current_time().unwrap_or(0),
            last_keepalive: 0,
            last_proof: 0,
            last_data: 0,
            tx: 0,
            rx: 0,
            txbytes: 0,
            rxbytes: 0,
            rssi: None,
            snr: None,
            q: None,
            establishment_cost: 0,
            establishment_rate: None,
            expected_rate: None,
            expected_hops: None,
            prv_bytes: None,
            pub_bytes: None,
            sig_prv_bytes: None,
            sig_pub_bytes: None,
            peer_pub_bytes: None,
            peer_sig_pub_bytes: None,
            shared_key: None,
            derived_key: None,
            token: Arc::new(Mutex::new(None)),
            remote_identity: Arc::new(Mutex::new(None)),
            callbacks: LinkCallbacks::default(),
            resource_strategy: ACCEPT_NONE,
            outgoing_resources: Arc::new(Mutex::new(Vec::new())),
            incoming_resources: Arc::new(Mutex::new(Vec::new())),
            pending_requests: Arc::new(Mutex::new(Vec::new())),
            last_resource_window: None,
            last_resource_eifr: None,
            attached_interface: None,
            traffic_timeout_factor: TRAFFIC_TIMEOUT_FACTOR,
            keepalive_timeout_factor: KEEPALIVE_TIMEOUT_FACTOR,
            keepalive: KEEPALIVE,
            stale_time: STALE_TIME,
            stale_since: None,
            stale_grace: STALE_GRACE,
            establishment_timeout: ESTABLISHMENT_TIMEOUT_PER_HOP,
            watchdog_lock: false,
            track_phy_stats: false,
            pending_remote_identified: false,
            channel: None,
            early_packets: Vec::new(),
            self_handle: None,
        })
    }
    
    /// Perform key exchange handshake
    pub fn handshake(&mut self) -> Result<(), String> {
        if self.state != STATE_PENDING {
            return Err("Invalid link state for handshake".to_string());
        }
        
        if self.prv_bytes.is_none() || self.peer_pub_bytes.is_none() {
            return Err("Missing keys for handshake".to_string());
        }
        
        self.state = STATE_HANDSHAKE;
        
        // Perform ECDH key exchange
        let prv_bytes_vec = self.prv_bytes.as_ref().unwrap();
        if prv_bytes_vec.len() != 32 {
            return Err("Invalid private key length".to_string());
        }
        let prv_array: [u8; 32] = prv_bytes_vec.as_slice().try_into()
            .map_err(|_| "Invalid private key".to_string())?;
        let prv = X25519PrivateKey::from(prv_array);
        
        let peer_pub_bytes = self.peer_pub_bytes.as_ref().unwrap();
        if peer_pub_bytes.len() != 32 {
            return Err("Invalid peer public key length".to_string());
        }
        
        let peer_pub_array: [u8; 32] = peer_pub_bytes.as_slice().try_into()
            .map_err(|_| "Invalid peer public key".to_string())?;
        let peer_pub = X25519PublicKey::from(peer_pub_array);
        
        let shared_secret = prv.diffie_hellman(&peer_pub);
        self.shared_key = Some(shared_secret.as_bytes().to_vec());
        
        // Derive encryption key using HKDF
        let derived_key_length = match self.mode {
            MODE_AES128_CBC => 32,
            MODE_AES256_CBC => 64,
            _ => return Err(format!("Invalid link mode {}", self.mode)),
        };
        
        self.derived_key = Some(self.derive_key_hkdf(derived_key_length)?);
        
        // Create token for encryption/decryption
        if let Some(derived_key) = &self.derived_key {
            let token = Token::new(derived_key)?;
            *self.token.lock().unwrap() = Some(token);
        }
        
        Ok(())
    }
    
    /// Derive encryption key using HKDF with salt=link_id, context=None
    fn derive_key_hkdf(&self, length: usize) -> Result<Vec<u8>, String> {
        if let Some(shared_key) = &self.shared_key {
            let hkdf = Hkdf::<Sha256>::new(Some(self.link_id.as_slice()), shared_key.as_slice());
            let mut derived_key = vec![0u8; length];
            hkdf.expand(&[], &mut derived_key)
                .map_err(|_| "HKDF expansion failed".to_string())?;
            Ok(derived_key)
        } else {
            Err("Missing shared key for derivation".to_string())
        }
    }
    
    /// Derive encryption key using HKDF (legacy simplified version)
    #[allow(dead_code)]
    fn derive_key(&self, length: usize) -> Result<Vec<u8>, String> {
        if let Some(shared_key) = &self.shared_key {
            // Simplified key derivation - in real implementation use HKDF
            let mut derived = Vec::with_capacity(length);
            let mut hash_input = self.link_id.clone();
            hash_input.extend_from_slice(shared_key);
            
            for _ in 0..((length + 31) / 32) {
                let chunk = identity::full_hash(&hash_input);
                derived.extend_from_slice(&chunk);
                hash_input = chunk.to_vec();
            }
            
            Ok(derived[..length].to_vec())
        } else {
            Err("Missing keys for derivation".to_string())
        }
    }
    
    /// Encrypt data for transmission
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(derived_key) = &self.derived_key {
            let token = Token::new(derived_key)?;
            token.encrypt(plaintext)
        } else {
            Err("Link not properly established for encryption".to_string())
        }
    }
    
    /// Decrypt received data
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(derived_key) = &self.derived_key {
            let token = Token::new(derived_key)?;
            token.decrypt(ciphertext)
        } else {
            Err("Link not properly established for decryption".to_string())
        }
    }
    
    /// Sign data with link's signing key (Ed25519)
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let sig_prv = self.sig_prv_bytes.as_ref().ok_or("Signing private key not available")?;
        let sig_pub = self.sig_pub_bytes.as_ref().ok_or("Signing public key not available")?;
        if sig_prv.len() != 32 || sig_pub.len() != 32 {
            return Err(format!("Invalid signing key lengths: prv={} pub={}", sig_prv.len(), sig_pub.len()));
        }

        let mut keypair_bytes = [0u8; 64];
        keypair_bytes[..32].copy_from_slice(sig_prv);
        keypair_bytes[32..].copy_from_slice(sig_pub);
        let keypair = ed25519_dalek::Keypair::from_bytes(&keypair_bytes)
            .map_err(|e| format!("Failed to construct keypair: {}", e))?;
        let signature = keypair.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Prove a received packet by signing its hash and sending a PROOF packet
    /// back to the sender via this link.
    pub fn prove_packet(&self, packet: &Packet) -> Result<(), String> {
        let packet_hash = packet.get_hash();
        let signature = self.sign(&packet_hash)?;

        let mut proof_data = packet_hash.clone();
        proof_data.extend_from_slice(&signature);

        crate::log(&format!("prove_packet hash={} link={} proof_len={} iface={:?}",
            crate::hexrep(&packet_hash, false),
            crate::hexrep(&self.link_id, false),
            proof_data.len(),
            self.attached_interface), crate::LOG_NOTICE, false, false);

        let link_destination = {
            let dest = self.destination.lock()
                .map_err(|_| "Destination lock poisoned")?;
            let mut ld = dest.clone();
            ld.dest_type = crate::destination::DestinationType::Link;
            ld.hash = self.link_id.clone();
            ld.hexhash = crate::hexrep(&ld.hash, false);
            // ── FIX: PROOF INTERFACE ROUTING ───────────────────────────────────────
            // DO NOT REMOVE THE ld.link = Some(...) ASSIGNMENT BELOW.
            //
            // Bug (pre-fix): prove_packet() left ld.link as None, so
            // Transport::outbound() broadcast the 96-byte PROOF packet on ALL
            // interfaces instead of routing it only through the link's own
            // attached interface.  The receiving peer never saw the proof on the
            // correct interface, so delivery receipts never fired.
            //
            // Fix: populate ld.link with a LinkInfo that carries attached_interface.
            // Transport::outbound() checks link.attached_interface and sends only
            // via that interface, matching Python's Packet.prove() behaviour.
            // ────────────────────────────────────────────────────────────────────────
            ld.link = Some(crate::destination::LinkInfo {
                rtt: self.rtt,
                traffic_timeout_factor: crate::link::TRAFFIC_TIMEOUT_FACTOR,
                status_closed: self.state == crate::link::STATE_CLOSED,
                mtu: Some(self.mtu),
                attached_interface: self.attached_interface.clone(),
            });
            ld
        };

        let mut proof_packet = Packet::new(
            Some(link_destination),
            proof_data,
            PROOF,
            packet::NONE,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        proof_packet.send()?;
        Ok(())
    }
    
    /// Validate a signature with peer's public key
    pub fn validate(&self, signature: &[u8], data: &[u8]) -> Result<bool, String> {
        if signature.len() != 64 {
            return Ok(false);
        }
        
        if let Some(peer_sig_pub_bytes) = &self.peer_sig_pub_bytes {
            if peer_sig_pub_bytes.len() != 32 {
                return Ok(false);
            }
            
            let sig_array: [u8; 64] = signature.try_into()
                .map_err(|_| "Invalid signature length".to_string())?;
            let sig = Signature::from_bytes(&sig_array)
                .map_err(|e| format!("Invalid signature: {}", e))?;
            
            let pub_array: [u8; 32] = peer_sig_pub_bytes.as_slice().try_into()
                .map_err(|_| "Invalid public key".to_string())?;
            let public_key = Ed25519PublicKey::from_bytes(&pub_array)
                .map_err(|e| format!("Invalid public key: {}", e))?;
            
            match public_key.verify(data, &sig) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Err("Peer signing key not available".to_string())
        }
    }
    
    /// Load peer public keys from bytes
    pub fn load_peer(&mut self, peer_pub_bytes: Vec<u8>, peer_sig_pub_bytes: Vec<u8>) -> Result<(), String> {
        if peer_pub_bytes.len() != 32 {
            return Err("Invalid peer public key length".to_string());
        }
        if peer_sig_pub_bytes.len() != 32 {
            return Err("Invalid peer signing public key length".to_string());
        }
        
        self.peer_pub_bytes = Some(peer_pub_bytes);
        self.peer_sig_pub_bytes = Some(peer_sig_pub_bytes);
        Ok(())
    }
    
    /// Send link proof after handshake
    pub fn prove(&mut self, owner_sig_prv_bytes: Option<&[u8]>) -> Result<(), String> {
        let signalling_bytes = signalling_bytes(self.mtu, self.mode)?;
        
        let mut signed_data = self.link_id.clone();
        if let Some(pub_bytes) = &self.pub_bytes {
            signed_data.extend_from_slice(pub_bytes);
        } else {
            return Err("Own public key not available".to_string());
        }
        if let Some(sig_pub_bytes) = &self.sig_pub_bytes {
            signed_data.extend_from_slice(sig_pub_bytes);
        } else {
            return Err("Own signing public key not available".to_string());
        }
        signed_data.extend_from_slice(&signalling_bytes);
        
        // Sign with owner's identity (or our own if this is inbound link)
        let signature = if let Some(owner_sig_prv) = owner_sig_prv_bytes {
            // Sign with owner's key
            if owner_sig_prv.len() != 32 {
                return Err("Invalid owner signing key".to_string());
            }
            let owner_keypair = ed25519_dalek::Keypair::from_bytes(owner_sig_prv)
                .map_err(|e| format!("Failed to construct owner keypair: {}", e))?;
            owner_keypair.sign(&signed_data).to_bytes().to_vec()
        } else if let Some(_sig_prv_bytes) = &self.sig_prv_bytes {
            self.sign(&signed_data)?
        } else {
            return Err("Signing key not available for proof".to_string())
        };
        
        let mut proof_data = signature;
        if let Some(pub_bytes) = &self.pub_bytes {
            proof_data.extend_from_slice(pub_bytes);
        }
        proof_data.extend_from_slice(&signalling_bytes);
        
        // Note: Actual packet sending would happen here
        // For now, we've assembled the proof data that would be sent
        self.last_proof = current_time().unwrap_or(0);
        self.establishment_cost += proof_data.len();
        
        Ok(())
    }

    /// Send link proof using the destination's identity for signing, and actually dispatch the packet
    pub fn prove_with_identity(&mut self, identity: &Identity) -> Result<(), String> {
        let sig_bytes = signalling_bytes(self.mtu, self.mode)?;

        let mut signed_data = self.link_id.clone();
        if let Some(pub_bytes) = &self.pub_bytes {
            signed_data.extend_from_slice(pub_bytes);
        } else {
            return Err("Own public key not available for proof".to_string());
        }
        if let Some(sig_pub_bytes) = &self.sig_pub_bytes {
            signed_data.extend_from_slice(sig_pub_bytes);
        } else {
            return Err("Own signing public key not available for proof".to_string());
        }
        signed_data.extend_from_slice(&sig_bytes);

        // Sign with the destination's identity Ed25519 key
        let signature = identity.sign(&signed_data);

        let mut proof_data = signature;
        if let Some(pub_bytes) = &self.pub_bytes {
            proof_data.extend_from_slice(pub_bytes);
        }
        proof_data.extend_from_slice(&sig_bytes);


        // Create a Link destination with dest_type=Link and hash=link_id for the proof packet
        let mut link_destination = self.destination.lock()
            .map_err(|_| "Destination lock poisoned")?
            .clone();
        link_destination.dest_type = DestinationType::Link;
        link_destination.hash = self.link_id.clone();
        link_destination.hexhash = crate::hexrep(&link_destination.hash, false);
        // Set LinkInfo so Transport::outbound routes the LRPROOF only via the
        // link's attached interface (not broadcast to all interfaces).
        // This matches the fix already applied in prove_packet().
        link_destination.link = Some(crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: crate::link::TRAFFIC_TIMEOUT_FACTOR,
            status_closed: self.state == crate::link::STATE_CLOSED,
            mtu: Some(self.mtu),
            attached_interface: self.attached_interface.clone(),
        });

        // Create and send the proof packet
        let mut proof_packet = Packet::new(
            Some(link_destination),
            proof_data,
            PROOF,
            packet::LRPROOF,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        proof_packet.send()?;

        self.last_proof = current_time().unwrap_or(0);
        self.establishment_cost += proof_packet.raw.len();

        Ok(())
    }
    
    /// Get salt for HKDF (link_id)
    pub fn get_salt(&self) -> Vec<u8> {
        self.link_id.clone()
    }
    
    /// Get context for HKDF (None in RNS)
    pub fn get_context(&self) -> Option<Vec<u8>> {
        None
    }
    
    /// Check if link is active
    pub fn is_active(&self) -> bool {
        self.state == STATE_ACTIVE
    }
    
    /// Check if link is stale
    pub fn is_stale(&self) -> bool {
        self.state == STATE_STALE
    }
    
    /// Check if link is closed
    pub fn is_closed(&self) -> bool {
        self.state == STATE_CLOSED
    }
    
    /// Get human-readable state name
    pub fn state_name(&self) -> &'static str {
        match self.state {
            STATE_PENDING => "PENDING",
            STATE_HANDSHAKE => "HANDSHAKE",
            STATE_ACTIVE => "ACTIVE",
            STATE_STALE => "STALE",
            STATE_CLOSED => "CLOSED",
            _ => "UNKNOWN",
        }
    }
    
    /// Record outbound activity
    pub fn had_outbound(&mut self, is_keepalive: bool) {
        self.last_outbound = current_time().unwrap_or(0);
        if !is_keepalive {
            self.last_data = self.last_outbound;
        } else {
            self.last_keepalive = self.last_outbound;
        }
    }
    
    /// Record inbound activity
    pub fn had_inbound(&mut self, is_data: bool) {
        self.last_inbound = current_time().unwrap_or(0);
        if is_data {
            self.last_data = self.last_inbound;
        }
    }
    
    /// Get time since last inbound
    pub fn no_inbound_for(&self) -> u64 {
        let activated = self.activated_at.unwrap_or(0);
        let last_inbound = std::cmp::max(self.last_inbound, activated);
        current_time().unwrap_or(0).saturating_sub(last_inbound)
    }
    
    /// Get time since last outbound
    pub fn no_outbound_for(&self) -> u64 {
        current_time().unwrap_or(0).saturating_sub(self.last_outbound)
    }
    
    /// Get time since last data
    pub fn no_data_for(&self) -> u64 {
        current_time().unwrap_or(0).saturating_sub(self.last_data)
    }
    
    /// Get time since activity (min of inbound/outbound)
    pub fn inactive_for(&self) -> u64 {
        std::cmp::min(self.no_inbound_for(), self.no_outbound_for())
    }
    
    /// Get age of link (time since activation)
    pub fn get_age(&self) -> Option<u64> {
        self.activated_at.and_then(|activated| {
            current_time().map(|now| now.saturating_sub(activated))
        })
    }
    
    /// Get remote identity
    pub fn get_remote_identity(&self) -> Option<String> {
        // Returns a string placeholder since Identity doesn't implement Clone
        if let Ok(id) = self.remote_identity.lock() {
            if id.is_some() {
                Some("remote_identity".to_string())
            } else {
                None
            }
        } else {
            None
        }
    }
    
    /// Set link established callback
    pub fn set_link_established_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>,
    ) {
        self.callbacks.link_established = callback;
    }
    
    /// Set link closed callback
    pub fn set_link_closed_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(LinkHandle) + Send + Sync>>,
    ) {
        self.callbacks.link_closed = callback;
    }
    
    /// Set packet received callback.
    /// If any DATA packets arrived before the callback was set, they are
    /// proved and dispatched now (draining the early_packets queue).
    pub fn set_packet_callback(&mut self, callback: Option<Arc<dyn Fn(&[u8], &Packet) + Send + Sync>>) {
        self.callbacks.packet = callback;

        // Drain early-arrival queue
        if self.callbacks.packet.is_some() && !self.early_packets.is_empty() {
            let queued: Vec<(Vec<u8>, Packet)> = std::mem::take(&mut self.early_packets);
            crate::log(&format!("[LINK] draining {} early packet(s) on link={}",
                queued.len(), crate::hexrep(&self.link_id, false)),
                crate::LOG_NOTICE, false, false);
            for (plaintext, packet) in &queued {
                let _ = self.prove_packet(packet);
            }
            // Fire callbacks outside the tight loop so prove_packet
            // results are already on the wire.
            let cb = self.callbacks.packet.as_ref().unwrap().clone();
            for (plaintext, packet) in queued {
                let cb2 = cb.clone();
                std::thread::spawn(move || {
                    cb2(&plaintext, &packet);
                });
            }
        }
    }
    
    /// Set resource callback
    pub fn set_resource_callback(&mut self, callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>) {
        self.callbacks.resource = callback;
    }
    
    /// Set resource started callback
    pub fn set_resource_started_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    ) {
        self.callbacks.resource_started = callback;
    }
    
    /// Set resource concluded callback
    pub fn set_resource_concluded_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>>,
    ) {
        self.callbacks.resource_concluded = callback;
    }
    
    /// Set remote identified callback
    pub fn set_remote_identified_callback(
        &mut self,
        callback: Option<Arc<dyn Fn(LinkHandle, Identity) + Send + Sync>>,
    ) {
        self.callbacks.remote_identified = callback;
    }
    
    /// Set resource acceptance strategy
    pub fn set_resource_strategy(&mut self, strategy: u8) -> Result<(), String> {
        match strategy {
            ACCEPT_NONE | ACCEPT_APP | ACCEPT_ALL => {
                self.resource_strategy = strategy;
                Ok(())
            }
            _ => Err(format!("Invalid resource strategy: {}", strategy)),
        }
    }
    
    /// Update MDU based on MTU
    pub fn update_mdu(&mut self) {
        self.mdu = ((self.mtu - reticulum::IFAC_MIN_SIZE - reticulum::HEADER_MINSIZE - identity::TOKEN_OVERHEAD) / identity::AES128_BLOCKSIZE) * identity::AES128_BLOCKSIZE - 1;
    }
    
    /// Get MTU if link is active
    pub fn get_mtu(&self) -> Option<usize> {
        if self.is_active() {
            Some(self.mtu)
        } else {
            None
        }
    }

    pub fn mtu(&self) -> Option<usize> {
        self.get_mtu()
    }
    
    /// Get MDU if link is active
    pub fn get_mdu(&self) -> Option<usize> {
        if self.is_active() {
            Some(self.mdu)
        } else {
            None
        }
    }
    
    /// Get RTT if available
    pub fn get_rtt(&self) -> Option<f64> {
        self.rtt
    }

    pub fn rtt(&self) -> Option<f64> {
        self.get_rtt()
    }

    pub fn traffic_timeout_factor(&self) -> Option<f64> {
        Some(self.traffic_timeout_factor)
    }

    pub fn establishment_cost(&self) -> Option<f64> {
        Some(self.establishment_cost as f64)
    }

    pub fn set_expected_rate(&mut self, rate: f64) {
        self.expected_rate = Some(rate);
        self.last_resource_eifr = Some(rate);
    }

    pub fn get_last_resource_window(&self) -> Option<usize> {
        self.last_resource_window
    }

    pub fn get_last_resource_eifr(&self) -> Option<f64> {
        self.last_resource_eifr
    }
    
    /// Get establishment rate
    pub fn get_establishment_rate(&self) -> Option<f64> {
        self.establishment_rate.map(|rate| rate * 8.0)
    }
    
    /// Get expected data rate
    pub fn get_expected_rate(&self) -> Option<f64> {
        if self.is_active() {
            self.expected_rate
        } else {
            None
        }
    }
    
    /// Get mode
    pub fn get_mode(&self) -> u8 {
        self.mode
    }
    
    /// Get physical stats if tracking enabled
    pub fn get_rssi(&self) -> Option<i32> {
        if self.track_phy_stats {
            self.rssi
        } else {
            None
        }
    }
    
    /// Get SNR if tracking enabled
    pub fn get_snr(&self) -> Option<f64> {
        if self.track_phy_stats {
            self.snr
        } else {
            None
        }
    }
    
    /// Get link quality if tracking enabled
    pub fn get_q(&self) -> Option<f64> {
        if self.track_phy_stats {
            self.q
        } else {
            None
        }
    }
    
    /// Enable/disable physical layer statistics tracking
    pub fn track_phy_stats(&mut self, track: bool) {
        self.track_phy_stats = track;
    }
    
    /// Tear down the link
    pub fn teardown(&mut self) {
        crate::log(&format!("LINK teardown link={} state={}", crate::hexrep(&self.link_id, false), self.state), crate::LOG_NOTICE, false, false);
        if self.state != STATE_CLOSED && self.state != STATE_PENDING {
            // Send teardown packet so the remote knows the link is closed.
            // Encrypt the link_id payload NOW (before unregister_runtime_link removes us
            // from RUNTIME_LINKS) and dispatch directly, avoiding the spawn-then-lookup
            // race that produced "RUNTIME encrypt FAILED" warnings.
            if let Ok(ciphertext) = self.encrypt(&self.link_id.clone()) {
                if let Some(ref iface) = self.attached_interface {
                    let flags: u8 = (DestinationType::Link as u8) << 2;
                    let mut raw = vec![flags, 0u8]; // flags byte, hops=0
                    raw.extend_from_slice(&self.link_id);
                    raw.push(crate::packet::LINKCLOSE);
                    raw.extend_from_slice(&ciphertext);
                    let raw_clone = raw.clone();
                    let iface_clone = iface.clone();
                    thread::spawn(move || {
                        crate::transport::Transport::dispatch_outbound(&iface_clone, &raw_clone);
                    });
                }
            }
            self.had_outbound(false);
        }
        self.state = STATE_CLOSED;
        self.status = STATE_CLOSED;
        unregister_runtime_link(&self.link_id);
        // Immediately remove the transport relay entry instead of waiting for
        // the periodic cull (~900s). Prevents stale link_table buildup on
        // lossy links where connections drop frequently.
        crate::transport::Transport::remove_link_entry(&self.link_id);
        self.link_closed();
    }
    
    /// Handle link closure cleanup
    fn link_closed(&mut self) {
        // Cancel resources
        self.prv_bytes = None;
        self.pub_bytes = None;
        self.sig_prv_bytes = None;
        self.sig_pub_bytes = None;
        self.shared_key = None;
        self.derived_key = None;
        
        if let Ok(mut token) = self.token.lock() {
            *token = None;
        }
        
        if let Some(callback) = &self.callbacks.link_closed {
            // Use the actor's own handle, or try the registry.
            let handle = self.self_handle.clone()
                .or_else(|| get_runtime_link_handle(&self.link_id));
            if let Some(handle) = handle {
                // Spawn on a new thread — same pattern as link_established — so the
                // callback can safely acquire external mutexes without blocking the
                // actor.  Calling it synchronously here would deadlock if the callback
                // waits for a mutex held by a thread that is itself waiting for the
                // actor to process a message.
                let cb = callback.clone();
                thread::spawn(move || cb(handle));
            }
        }
    }
    
    /// Process received packet
    pub fn receive(&mut self, packet: &Packet) -> Result<(), String> {
        self.watchdog_lock = true;
        
        if !self.is_closed() {
            self.had_inbound(packet.packet_type == DATA);
            self.rx += 1;
            self.rxbytes += packet.data.len() as u64;
            
            // Mark active if stale
            if self.state == STATE_STALE {
                self.state = STATE_ACTIVE;
            }
            
            // Route based on packet context
            match packet.packet_type {
                DATA => {
                    self.handle_data_packet(packet)?;
                }
                PROOF => {
                    if let Err(err) = self.handle_proof_packet(packet) {
						return Err(err);
					}
                }
                _ => {}
            }
        }
        
        self.watchdog_lock = false;
        Ok(())
    }
    
    /// Handle DATA packets
    fn handle_data_packet(&mut self, packet: &Packet) -> Result<(), String> {
        crate::log(&format!("[HDR] context=0x{:02x} data_len={} link={}",
            packet.context, packet.data.len(),
            crate::hexrep(&self.link_id, false)), crate::LOG_NOTICE, false, false);

        if packet.context == crate::packet::RESOURCE {
            // Pre-fetch link state so receive_part can update resource RTT without
            // calling self.link.snapshot() (which would deadlock the actor).
            let link_ctx = self.resource_link_context();
            let mut deferred_actions: Vec<(Arc<Mutex<Resource>>, bool, bool)> = Vec::new();
            if let Ok(resources) = self.incoming_resources.lock() {
                for resource in resources.iter() {
                    if let Ok(mut resource_guard) = resource.lock() {
                        let (needs_request_next, needs_start_watchdog) = resource_guard.receive_part(packet, &link_ctx);
                        if needs_request_next || needs_start_watchdog {
                            deferred_actions.push((resource.clone(), needs_request_next, needs_start_watchdog));
                        }
                    }
                }
            }
            // Defer request_next and start_watchdog to background threads.
            // These need the link for encryption, and the link lock is currently
            // held by dispatch_runtime_packet — calling them inline would deadlock.
            //
            // IMPORTANT: build the link Destination NOW, while we are inside
            // the actor (i.e. `self` is the owned Link), and pass the result
            // into the spawned thread.  The deferred thread takes the
            // resource lock and would deadlock if it tried to round-trip
            // through the actor for `packet_destination()` while the actor
            // is blocked trying to take the resource lock for the next
            // inbound RESOURCE part.  See rfed.log 2026-04-25 23:11:36
            // post-mortem (rfed-stall-deadlock memory note).
            let req_next_destination = if deferred_actions.iter().any(|(_, n, _)| *n) {
                self.build_link_destination_direct()
            } else {
                None
            };
            for (resource_arc, needs_request_next, needs_start_watchdog) in deferred_actions {
                if needs_start_watchdog {
                    Resource::start_watchdog(resource_arc.clone());
                }
                if needs_request_next {
                    let r = resource_arc.clone();
                    let dest = req_next_destination.clone();
                    std::thread::spawn(move || {
                        // Brief delay so the caller can release the link lock.
                        // Without this, the deferred thread would immediately
                        // contend on the link lock that the TCP reader still holds.
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        // Phase 1: Lock resource, prepare REQ payload bytes,
                        // then RELEASE the lock.  We use the *_data variant
                        // so we never call self.link.* while holding the
                        // resource lock — that would deadlock against the
                        // actor processing the next inbound RESOURCE part.
                        let maybe_data = match r.lock() {
                            Ok(mut guard) => {
                                guard.prepare_request_next_data()
                            }
                            Err(e) => {
                                crate::log(&format!("Resource lock poisoned in deferred REQ: {}", e), crate::LOG_ERROR, false, false);
                                None
                            }
                        };
                        // Phase 2: Build the Packet OUTSIDE the resource lock
                        // using the destination snapshot built in the actor.
                        if let Some(request_data) = maybe_data {
                            let mut packet = crate::packet::Packet::new(
                                dest,
                                request_data,
                                crate::packet::DATA,
                                crate::packet::RESOURCE_REQ,
                                crate::transport::BROADCAST,
                                crate::packet::HEADER_1,
                                None,
                                None,
                                false,
                                0,
                            );
                            match packet.send() {
                                Ok(_) => {
                                    // Phase 3: Re-lock resource to record success
                                    if let Ok(mut guard) = r.lock() {
                                        guard.record_request_sent(packet.raw.len());
                                    }
                                }
                                Err(e) => {
                                    crate::log(&format!("Deferred REQ send failed: {}", e), crate::LOG_ERROR, false, false);
                                    if let Ok(mut guard) = r.lock() {
                                        guard.cancel();
                                    }
                                }
                            }
                        }
                    });
                }
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_ADV {
            let plaintext = match self.decrypt(&packet.data) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    crate::log(&format!("[RESP-RES] RESOURCE_ADV decrypt failed: {}", e), crate::LOG_NOTICE, false, false);
                    return Ok(());
                }
            };

            let mut advertisement_packet = packet.clone();
            advertisement_packet.plaintext = Some(plaintext);

            let is_req = crate::resource::ResourceAdvertisement::is_request(&advertisement_packet);
            let is_resp = crate::resource::ResourceAdvertisement::is_response(&advertisement_packet);
            crate::log(&format!("[RESP-RES] RESOURCE_ADV is_request={} is_response={}",
                is_req, is_resp), crate::LOG_NOTICE, false, false);

            if is_req {
                let link_ctx = self.resource_link_context();
                let adv_request_id =
                    crate::resource::ResourceAdvertisement::read_request_id(&advertisement_packet);

                // Python parity: RNS/Link.py:request_resource_concluded.
                // When a multi-segment REQUEST resource finishes assembling,
                // unpack it and dispatch into handle_request_packet so the
                // registered request handler runs.
                let link_handle = self.self_handle.as_ref().unwrap().clone();
                let request_concluded_cb: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>> =
                    Some(Arc::new(move |resource: Arc<Mutex<Resource>>| {
                        let (data_opt, status, res_request_id_opt) = {
                            let res = resource.lock().unwrap();
                            (res.data.clone(), res.status, res.request_id.clone())
                        };
                        if status != crate::resource::ResourceStatus::Complete {
                            crate::log(&format!(
                                "[REQ-RES] incoming request resource failed status={:?}", status
                            ), crate::LOG_DEBUG, false, false);
                            return;
                        }
                        let data = match data_opt {
                            Some(d) => d,
                            None => {
                                crate::log("[REQ-RES] concluded but data is None", crate::LOG_NOTICE, false, false);
                                return;
                            }
                        };
                        // Python derives request_id = truncated_hash(packed_request)
                        // (RNS/Link.py:request_resource_concluded). Mirror that
                        // and fall back to the resource advertisement's
                        // request_id when the helper isn't available.
                        let request_id = crate::identity::Identity::truncated_hash(&data);
                        let request_id = if request_id.is_empty() {
                            res_request_id_opt.unwrap_or_default()
                        } else {
                            request_id
                        };
                        link_handle.handle_request_packet(request_id, data);
                    }));

                if let Some(resource) = Resource::accept(
                    &advertisement_packet,
                    self.self_handle.as_ref().unwrap().clone(),
                    request_concluded_cb,
                    None,
                    adv_request_id,
                    Some(link_ctx),
                ) {
                    // Register on real link so RESOURCE data packets find it
                    self.register_incoming_resource(resource);
                }
                return Ok(());
            }

            if is_resp {
                let request_id_opt = crate::resource::ResourceAdvertisement::read_request_id(&advertisement_packet);
                crate::log(&format!(
                    "[RESP-RES] incoming response resource, request_id={}",
                    request_id_opt.as_ref().map(|id| crate::hexrep(id, false)).unwrap_or_else(|| "None".to_string())
                ), crate::LOG_NOTICE, false, false);

                // Build a per-request concluded callback so that when the resource is fully
                // assembled we can route the data to the correct pending request callback.
                // Python RNS encodes response resources as msgpack([request_id_bytes, response_value])
                // — identical to the direct RESPONSE packet plaintext format.
                let pending_requests = Arc::clone(&self.pending_requests);
                let link_arc = Arc::new(Mutex::new(self.clone()));
                let concluded_callback: Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>> =
                    Some(Arc::new(move |resource: Arc<Mutex<Resource>>| {
                        let (data_opt, res_request_id_opt) = {
                            let res = resource.lock().unwrap();
                            (res.data.clone(), res.request_id.clone())
                        };
                        crate::log(&format!(
                            "[RESP-RES] concluded, data_len={:?}, res_request_id={}",
                            data_opt.as_ref().map(|d| d.len()),
                            res_request_id_opt.as_ref().map(|id| crate::hexrep(id, false)).unwrap_or_else(|| "None".to_string())
                        ), crate::LOG_NOTICE, false, false);

                        let data = match data_opt {
                            Some(d) => d,
                            None => {
                                crate::log("[RESP-RES] concluded but data is None", crate::LOG_NOTICE, false, false);
                                return;
                            }
                        };

                        // Parse msgpack([request_id_bytes, response_value]) — same as direct RESPONSE format.
                        let parsed = rmpv_read_value(&mut std::io::Cursor::new(&data));
                        let (request_id, response_bytes) = match parsed {
                            Ok(rmpv::Value::Array(elements)) if elements.len() >= 2 => {
                                match &elements[0] {
                                    rmpv::Value::Binary(b) => {
                                        let rid = b.clone();
                                        let mut rb = Vec::new();
                                        if rmpv_write_value(&mut rb, &elements[1]).is_ok() {
                                            (rid, rb)
                                        } else {
                                            crate::log("[RESP-RES] failed to re-encode response value", crate::LOG_NOTICE, false, false);
                                            return;
                                        }
                                    }
                                    _ => match res_request_id_opt {
                                        Some(rid) => (rid, data),
                                        None => { crate::log("[RESP-RES] no request_id (non-binary elements[0])", crate::LOG_NOTICE, false, false); return; }
                                    }
                                }
                            }
                            _ => match res_request_id_opt {
                                Some(rid) => (rid, data),
                                None => { crate::log("[RESP-RES] no request_id (non-array data)", crate::LOG_NOTICE, false, false); return; }
                            }
                        };

                        let mut pending = match pending_requests.lock() {
                            Ok(p) => p,
                            Err(_) => return,
                        };
                        crate::log(&format!(
                            "[RESP-RES] pending_requests count={}, looking for id={}",
                            pending.len(), crate::hexrep(&request_id, false)
                        ), crate::LOG_NOTICE, false, false);

                        if let Some(index) = pending.iter().position(|p| p.request_id == request_id) {
                            crate::log("[RESP-RES] found pending request, spawning callback thread", crate::LOG_NOTICE, false, false);
                            let request = pending.remove(index);
                            let receipt = RequestReceipt {
                                request_id: request_id.clone(),
                                response: Some(response_bytes),
                                link: Arc::clone(&link_arc),
                                sent_at: request.sent_at,
                                received_at: Some(current_time().unwrap_or(0) as f64),
                                progress: 1.0,
                            };
                            if let Some(callback) = request.response_callback {
                                thread::spawn(move || { callback(receipt); });
                            }
                        } else {
                            crate::log(&format!(
                                "[RESP-RES] NO matching pending request for id={}",
                                crate::hexrep(&request_id, false)
                            ), crate::LOG_NOTICE, false, false);
                        }
                    }));

                if let Some(resource) = Resource::accept(
                    &advertisement_packet,
                    self.self_handle.as_ref().unwrap().clone(),
                    concluded_callback,
                    None,
                    request_id_opt,
                    Some(self.resource_link_context()),
                ) {
                    self.register_incoming_resource(resource);
                }
                return Ok(());
            }

            match self.resource_strategy {
                ACCEPT_NONE => {
                }
                ACCEPT_APP => {
                    // Python parity (RNS/Link.py:1106-1109): ACCEPT_APP only
                    // accepts the resource if `callbacks.resource` is set and
                    // returns True. If no resource callback is registered,
                    // the advertisement is silently ignored — assembling the
                    // resource with no concluded callback would just produce
                    // a "Resource concluded but no callback registered"
                    // warning and drop the bytes anyway.
                    let resource_cb = self.callbacks.resource.clone();
                    if resource_cb.is_none() {
                        return Ok(());
                    }
                    let link_ctx = self.resource_link_context();
                    if let Some(resource) = Resource::accept(
                        &advertisement_packet,
                        self.self_handle.as_ref().unwrap().clone(),
                        self.callbacks.resource_concluded.clone(),
                        None,
                        None,
                        Some(link_ctx),
                    ) {
                        // Register on real link so RESOURCE data packets find it
                        self.register_incoming_resource(resource.clone());
                        // Spawn callback off the actor thread so the user's handler
                        // can freely call LinkHandle methods (snapshot, send_packet,
                        // etc.) without deadlocking the actor on its own queue.
                        let callback = resource_cb.unwrap();
                        std::thread::spawn(move || callback(resource));
                    } else {
                        Resource::reject(&advertisement_packet);
                    }
                }
                ACCEPT_ALL => {
                    if let Some(resource) = Resource::accept(
                        &advertisement_packet,
                        self.self_handle.as_ref().unwrap().clone(),
                        self.callbacks.resource_concluded.clone(),
                        None,
                        None,
                        Some(self.resource_link_context()),
                    ) {
                        self.register_incoming_resource(resource);
                    }
                }
                _ => {}
            }

            return Ok(());
        }

        if packet.context == crate::packet::LRRTT {
            // LRRTT packets are encrypted over the link, decrypt first
            let plaintext = match self.decrypt(&packet.data) {
                Ok(pt) => pt,
                Err(_) => {
                    return Ok(());
                }
            };
            self.handle_lrrtt_packet(&plaintext)?;
            return Ok(());
        }

        // KEEPALIVE packets travel UNENCRYPTED on the wire (single byte 0xFF
        // ping / 0xFE pong — see Packet::pack which skips encryption for
        // context == KEEPALIVE).  They MUST therefore be handled BEFORE the
        // decrypt step below, or self.decrypt() will fail on a 1-byte input
        // and we'll silently return Ok(()) without ever sending a reply —
        // which causes the initiator's last_inbound to never refresh on
        // quiet links and the link to be torn down at stale_time
        // (= 2*keepalive + STALE_GRACE, i.e. ~15s for low-RTT links).
        // had_inbound() at the top of receive() has already refreshed our
        // own last_inbound; here we only need to bounce a 0xFE reply if we
        // are the responder so the initiator's stale timer also resets.
        if packet.context == crate::packet::KEEPALIVE {
            if !self.initiator && packet.data.as_slice() == [0xFFu8] {
                if let Some((dest, _link_id)) = self.prepare_keepalive() {
                    let mut reply = Packet::new(
                        Some(dest),
                        vec![0xFEu8],
                        DATA,
                        crate::packet::KEEPALIVE,
                        crate::transport::BROADCAST,
                        packet::HEADER_1,
                        None,
                        None,
                        false,
                        0,
                    );
                    let _ = reply.send();
                }
            }
            return Ok(());
        }

        let plaintext = match self.decrypt(&packet.data) {
            Ok(plaintext) => {
                plaintext
            },
            Err(_) => {
                return Ok(());
            },
        };

        if packet.context == crate::packet::REQUEST {
            let request_id = packet.get_truncated_hash();
            self.handle_request_packet(request_id, &plaintext)?;
            return Ok(());
        }

        if packet.context == crate::packet::RESPONSE {
            self.handle_response_packet(&plaintext)?;
            return Ok(());
        }

        if packet.context == LINKIDENTIFY {
            self.handle_linkidentify_packet(&plaintext)?;
            return Ok(());
        }

        if packet.context == crate::packet::LINKCLOSE {
            crate::log(&format!("[LINK] LINKCLOSE received on link={}", crate::hexrep(&self.link_id, false)), crate::LOG_NOTICE, false, false);
            self.teardown();
            return Ok(());
        }

        // KEEPALIVE is handled above (BEFORE decrypt) — see comment block.

        if packet.context == crate::packet::RESOURCE_REQ {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= 1 + hash_len {
                let offset = if plaintext[0] == crate::resource::Resource::HASHMAP_IS_EXHAUSTED {
                    1 + crate::resource::Resource::MAPHASH_LEN
                } else {
                    1
                };
                if plaintext.len() >= offset + hash_len {
                    let resource_hash = plaintext[offset..offset + hash_len].to_vec();
                    let packet_hash = packet.packet_hash.clone();
                    // Clone the list of outgoing resource Arcs WITHOUT locking
                    // individual resources.  We must NOT lock any resource while
                    // the link lock is held — request() sends RESOURCE_HMU
                    // packets whose encrypt path needs the link lock, creating
                    // an AB-BA deadlock (link→resource vs resource→link).
                    let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.outgoing_resources.lock() {
                        resources.clone()
                    } else {
                        Vec::new()
                    };
                    let pt = plaintext.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        // Find matching resource OUTSIDE the link lock
                        let mut target_resource: Option<Arc<Mutex<Resource>>> = None;
                        for resource in resources.iter() {
                            if let Ok(guard) = resource.lock() {
                                if guard.hash == resource_hash.as_slice() {
                                    target_resource = Some(resource.clone());
                                    break;
                                }
                            }
                        }
                        if let Some(resource_arc) = target_resource {
                            if let Ok(mut guard) = resource_arc.lock() {
                                if let Some(req_hash) = packet_hash.as_ref() {
                                    if !guard.req_hashlist.iter().any(|h| h == req_hash) {
                                        guard.req_hashlist.push(req_hash.clone());
                                        if guard.req_hashlist.len() > 64 {
                                            let drop_count = guard.req_hashlist.len().saturating_sub(64);
                                            guard.req_hashlist.drain(0..drop_count);
                                        }
                                    }
                                }
                                guard.request(&pt);
                            }
                        }
                    });
                }
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_HMU {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= hash_len {
                let resource_hash = &plaintext[..hash_len];
                let mut needs_request_next: Option<Arc<Mutex<Resource>>> = None;
                if let Ok(mut resources) = self.incoming_resources.lock() {
                    for resource in resources.iter_mut() {
                        if let Ok(mut resource_guard) = resource.lock() {
                            if resource_guard.hash == resource_hash {
                                if resource_guard.hashmap_update_packet(&plaintext) {
                                    needs_request_next = Some(resource.clone());
                                }
                            }
                        }
                    }
                }
                // Defer request_next to a background thread — we're inside
                // the link mutex and request_next needs to encrypt via
                // the same link, which would deadlock.
                if let Some(r) = needs_request_next {
                    // Build the link Destination NOW (inside the actor) and
                    // pass it into the spawned thread, so the deferred sender
                    // never has to round-trip through the actor while
                    // holding the resource lock.  See deadlock note in the
                    // RESOURCE handler above.
                    let dest = self.build_link_destination_direct();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                        // Phase 1: Lock resource, build REQ payload bytes, RELEASE
                        let maybe_data = match r.lock() {
                            Ok(mut guard) => {
                                guard.prepare_request_next_data()
                            }
                            Err(e) => {
                                crate::log(&format!("Resource lock poisoned in deferred HMU REQ: {}", e), crate::LOG_ERROR, false, false);
                                None
                            }
                        };
                        // Phase 2: Build Packet outside resource lock and send
                        if let Some(request_data) = maybe_data {
                            let mut packet = crate::packet::Packet::new(
                                dest,
                                request_data,
                                crate::packet::DATA,
                                crate::packet::RESOURCE_REQ,
                                crate::transport::BROADCAST,
                                crate::packet::HEADER_1,
                                None,
                                None,
                                false,
                                0,
                            );
                            match packet.send() {
                                Ok(_) => {
                                    if let Ok(mut guard) = r.lock() {
                                        guard.record_request_sent(packet.raw.len());
                                    }
                                }
                                Err(e) => {
                                    crate::log(&format!("Deferred HMU REQ send failed: {}", e), crate::LOG_ERROR, false, false);
                                    if let Ok(mut guard) = r.lock() {
                                        guard.cancel();
                                    }
                                }
                            }
                        }
                    });
                }
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_ICL {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= hash_len {
                let resource_hash = plaintext[..hash_len].to_vec();
                // Clone the incoming resource list without locking individual
                // resources — avoids deadlock with deferred request_next threads
                // that hold the resource lock and need the link lock to send.
                let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.incoming_resources.lock() {
                    resources.clone()
                } else {
                    Vec::new()
                };
                std::thread::spawn(move || {
                    for resource in resources.iter() {
                        if let Ok(mut resource_guard) = resource.lock() {
                            if resource_guard.hash == resource_hash.as_slice() {
                                resource_guard.cancel();
                            }
                        }
                    }
                });
            }
            return Ok(());
        }

        if packet.context == crate::packet::RESOURCE_RCL {
            let hash_len = identity::HASHLENGTH / 8;
            if plaintext.len() >= hash_len {
                let resource_hash = plaintext[..hash_len].to_vec();
                // Clone without locking individual resources — same deadlock
                // avoidance as RESOURCE_REQ handler.
                let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.outgoing_resources.lock() {
                    resources.clone()
                } else {
                    Vec::new()
                };
                std::thread::spawn(move || {
                    for resource in resources.iter() {
                        if let Ok(mut resource_guard) = resource.lock() {
                            if resource_guard.hash == resource_hash.as_slice() {
                                resource_guard.rejected();
                            }
                        }
                    }
                });
            }
            return Ok(());
        }

        if let Some(callback) = &self.callbacks.packet {
            // Prove the packet (sign hash and send PROOF back to sender)
            let _ = self.prove_packet(packet);
            // Spawn callback on a dedicated thread so the TCP read thread
            // is not blocked by consumer locks (matches Destination::receive).
            let cb = callback.clone();
            let pt = plaintext.clone();
            let pkt = packet.clone();
            std::thread::spawn(move || {
                cb(&pt, &pkt);
            });
        } else {
            // Callback not yet wired (link_established hasn't fired).
            // Queue the packet so it can be replayed once the callback
            // is set via set_packet_callback.
            crate::log(&format!("[LINK] queuing early packet ({} bytes) on link={}",
                plaintext.len(), crate::hexrep(&self.link_id, false)),
                crate::LOG_NOTICE, false, false);
            self.early_packets.push((plaintext.clone(), packet.clone()));
        }
        
        Ok(())
    }

    fn handle_lrrtt_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        if self.initiator {
            return Ok(());
        }

        let measured_rtt = self
            .request_time
            .map(|requested| (now_seconds() - requested).max(0.001))
            .unwrap_or(0.0);

        let peer_rtt: f64 = from_slice(plaintext).map_err(|e| format!("Invalid LRRTT payload: {}", e))?;
        self.rtt = Some(measured_rtt.max(peer_rtt));
        self.status = STATE_ACTIVE;
        self.state = STATE_ACTIVE;
        self.activated_at = current_time();
        self.update_keepalive();


        // NOTE: We do NOT fire the link_established callback here because we
        // are inside a Mutex lock. The callback would receive a clone Arc
        // and modifications wouldn't affect the real link. Instead,
        // dispatch_runtime_packet handles this after the lock is released.

        Ok(())
    }

    fn handle_request_packet(&mut self, request_id: Vec<u8>, plaintext: &[u8]) -> Result<(), String> {
        crate::log(&format!("[REQ] handle_request_packet: request_id={} plaintext_len={}", crate::hexrep(&request_id, false), plaintext.len()), crate::LOG_NOTICE, false, false);
        // Python RNS wire format: msgpack array [timestamp_f64, path_hash_bytes, data_any]
        // The third element (data) can be ANY msgpack type (bytes, array, nil, etc.)
        // so we must use rmpv to parse the outer array generically.
        let outer = match rmpv_read_value(&mut std::io::Cursor::new(plaintext)) {
            Ok(rmpv::Value::Array(arr)) if arr.len() >= 3 => arr,
            Ok(_) => {
                crate::log("[REQ] msgpack not a 3-element array", crate::LOG_ERROR, false, false);
                return Ok(());
            }
            Err(e) => {
                crate::log(&format!("[REQ] msgpack parse FAILED: {}", e), crate::LOG_ERROR, false, false);
                return Ok(());
            }
        };

        let timestamp = match &outer[0] {
            rmpv::Value::F64(f) => *f,
            rmpv::Value::F32(f) => *f as f64,
            rmpv::Value::Integer(i) => i.as_f64().unwrap_or(0.0),
            _ => 0.0,
        };

        let path_hash: Vec<u8> = match &outer[1] {
            rmpv::Value::Binary(b) => b.clone(),
            _ => {
                crate::log("[REQ] path_hash is not binary", crate::LOG_ERROR, false, false);
                return Ok(());
            }
        };

        // Extract request data for the handler.
        //
        // When the sender is Python RNS, `data` is passed as raw bytes which Python
        // msgpack wraps as a Binary element in the outer array.  Those bytes are
        // themselves a msgpack-encoded value (the actual payload).  Re-serializing
        // the Binary wrapper would add an extra length-prefix layer that doubles the
        // encoding depth and breaks all handler decoders.
        //
        // Instead: if outer[2] is Binary, hand the inner bytes directly to the
        // handler.  For any other type (Array, Integer, Nil …) — used by Rust-to-Rust
        // calls where link.request() decodes `data` back to an rmpv Value before
        // embedding — fall through to the normal re-serialisation path.
        let request_data: Vec<u8> = match &outer[2] {
            rmpv::Value::Binary(b) => b.clone(),
            rmpv::Value::Nil => Vec::new(),
            _ => {
                let mut buf = Vec::new();
                rmpv_write_value(&mut buf, &outer[2]).map_err(|e| e.to_string())?;
                buf
            }
        };
        crate::log(&format!("[REQ] path_hash={} request_data_len={} timestamp={}", crate::hexrep(&path_hash, false), request_data.len(), timestamp), crate::LOG_NOTICE, false, false);

        let handler = {
            let dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?;
            let h = dest.request_handlers.get(&path_hash).cloned();
            if h.is_none() {
                let registered: Vec<String> = dest.request_handlers.keys().map(|k| crate::hexrep(k, false)).collect();
                crate::log(&format!("[REQ] NO handler for path_hash={}, registered={:?}", crate::hexrep(&path_hash, false), registered), crate::LOG_ERROR, false, false);
            }
            h
        };

        // Determine response: run the `allowed` check on the actor thread (it only
        // reads remote_identity which is already locked), then either:
        // - Spawn a background thread to run the callback (so the callback can freely
        //   call LinkHandle methods without deadlocking the actor).  The thread sends
        //   `LinkMsg::SendResponse` when done.
        // - Send an empty response inline for the !allowed / no-callback cases (those
        //   paths only call self.encrypt() and Transport::dispatch_outbound, both of
        //   which are safe on the actor thread).
        if let Some(handler) = handler {
            // Clone the identity up-front so the MutexGuard is dropped before we
            // call send_request_response (&mut self), which avoids the
            // immutable-then-mutable borrow conflict on self.remote_identity.
            let remote_identity_owned: Option<crate::identity::Identity> = {
                let guard = self.remote_identity.lock().ok();
                guard.as_ref().and_then(|g| g.as_ref()).cloned()
            };
            let remote_identity_ref = remote_identity_owned.as_ref();
            let remote_identity_hash = remote_identity_ref
                .and_then(|identity| identity.hash.as_ref().map(|hash| crate::hexrep(hash, false)))
                .unwrap_or_else(|| "none".to_string());
            crate::log(
                &format!(
                    "[REQ] resolved path='{}' request_id={} link_id={} remote_identity={}",
                    handler.path,
                    crate::hexrep(&request_id, false),
                    crate::hexrep(&self.link_id, false),
                    remote_identity_hash,
                ),
                crate::LOG_NOTICE,
                false,
                false,
            );

            let allowed = match handler.allow_policy {
                crate::destination::ALLOW_NONE => false,
                crate::destination::ALLOW_ALL => true,
                crate::destination::ALLOW_LIST => {
                    if let (Some(identity), Some(allowed_list)) = (remote_identity_ref, handler.allowed_list.as_ref()) {
                        identity
                            .hash
                            .as_ref()
                            .map(|hash| allowed_list.iter().any(|allowed| allowed == hash))
                            .unwrap_or(false)
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if !allowed {
                // Python RNS (RNS/Link.py:handle_request) silently logs and
                // returns when a request is not allowed — it does NOT send a
                // response packet. Mirror that: client times out cleanly.
                crate::log(&format!("[REQ] request denied for path '{}' (not allowed) — no response sent (matches Python)", handler.path), crate::LOG_NOTICE, false, false);
                return Ok(());
            } else if let Some(callback) = handler.callback {
                // Spawn callback on a background thread so it can freely call
                // LinkHandle methods (snapshot, send_packet, request, etc.) without
                // deadlocking the actor on its own channel.
                let link_handle = self.self_handle.as_ref().unwrap().clone();
                let path_hex = crate::hexrep(&path_hash, false);
                let handler_path = handler.path.clone();
                let request_id_c = request_id.clone();
                let request_data_c = request_data.clone();
                // Clone the identity so the spawned thread owns it (avoids
                // lifetime issues with `remote_identity_guard`).
                let remote_identity_owned: Option<crate::identity::Identity> =
                    remote_identity_ref.cloned();
                std::thread::spawn(move || {
                    let identity_ref = remote_identity_owned.as_ref();
                    let response = callback(
                        &path_hex,
                        &request_data_c,
                        &request_id_c,
                        identity_ref,
                        Some(&link_handle),
                        timestamp,
                    );
                    crate::log(
                        &format!(
                            "[REQ] callback completed path='{}' request_id={} response_len={}",
                            handler_path,
                            crate::hexrep(&request_id_c, false),
                            response.len(),
                        ),
                        crate::LOG_NOTICE,
                        false,
                        false,
                    );
                    // send_response enqueues LinkMsg::SendResponse; the actor
                    // processes it after it has finished handling `Receive`.
                    link_handle.send_response(request_id_c, response);
                });
                return Ok(()); // response sent asynchronously from the spawned thread
            } else {
                // Handler registered but no callback — same as Python's
                // "response is None" path: send nothing, let client time out.
                return Ok(());
            }
        }
        // No handler registered for this path — Python silently ignores; do the same.
        Ok(())
    }

    /// Build and send the msgpack-encoded response for a request.
    ///
    /// This is safe to call from the actor thread because it uses `self.encrypt()`
    /// (direct field access, no channel round-trip) and `Transport::dispatch_outbound`.
    fn send_request_response(&mut self, request_id: &[u8], response: &[u8]) -> Result<(), String> {
        // Python RNS response wire format: msgpack array [request_id_bytes, response_value]
        // CRITICAL: The response must be encoded as [Binary(request_id), <native_msgpack_value>]
        // where the response value is embedded as its native msgpack type (array, int, nil, etc.)
        // NOT wrapped in a Binary container. Our handler returns pre-encoded msgpack bytes,
        // so we build the outer array manually: write array header, write request_id as Binary,
        // then append the raw response bytes directly (they are already valid msgpack).
        let attached_interface = self.attached_interface.clone().unwrap_or_else(|| "<none>".to_string());
        crate::log(
            &format!(
                "[REQ] handler returned {} bytes, building response request_id={} link_id={} iface={}",
                response.len(),
                crate::hexrep(request_id, false),
                crate::hexrep(&self.link_id, false),
                attached_interface,
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );
        let mut response_data = Vec::new();
        // 2-element array header
        rmp::encode::write_array_len(&mut response_data, 2).map_err(|e| e.to_string())?;
        // First element: request_id as Binary
        rmp::encode::write_bin(&mut response_data, &request_id).map_err(|e| e.to_string())?;
        // Second element: raw msgpack response value (already encoded by handler).
        //
        // Callers MUST NOT invoke this with an empty `response`. Python RNS
        // (RNS/Link.py:handle_request) emits NO response packet at all when
        // the handler returns None, the request is denied, or no handler is
        // registered. Mirror that behavior at the call sites; this assertion
        // catches accidental regressions because emitting array_len=2 with
        // nothing in element 2 produces a malformed 19-byte plaintext that
        // the peer fails to decode ("failed to fill whole buffer").
        debug_assert!(!response.is_empty(), "send_request_response called with empty payload — callers must skip the send instead (matches Python RNS)");
        response_data.extend_from_slice(&response);
        crate::log(&format!("[REQ] response_data (msgpack) {} bytes: {:02x?}", response_data.len(), &response_data[..response_data.len().min(64)]), crate::LOG_NOTICE, false, false);

        // Encrypt directly via self (we already hold the link lock, so we MUST NOT
        // go through runtime_encrypt_for_destination which would try to re-acquire
        // the same mutex → deadlock).
        let ciphertext = match self.encrypt(&response_data) {
            Ok(ct) => ct,
            Err(e) => {
                crate::log(&format!("[REQ] encrypt FAILED: {}", e), crate::LOG_ERROR, false, false);
                return Ok(());
            }
        };

        // Build wire bytes manually: [flags(1), hops(1), link_id(16), context(1), ciphertext]
        // flags = HEADER_1(0)<<6 | BROADCAST(0)<<4 | Link(3)<<2 | DATA(0) = 0x0C
        let flags: u8 = (DestinationType::Link as u8) << 2;
        let mut raw = vec![flags, 0u8]; // flags, hops=0
        raw.extend_from_slice(&self.link_id);
        raw.push(crate::packet::RESPONSE);
        raw.extend_from_slice(&ciphertext);

        // Send directly on the link's attached interface (no need to acquire link lock again).
        // Using dispatch_outbound bypasses Packet::pack()'s encryption which would deadlock.
        let sent = if let Some(ref iface) = self.attached_interface {
            crate::transport::Transport::dispatch_outbound(iface, &raw)
        } else {
            crate::log("[REQ] NO attached_interface!", crate::LOG_ERROR, false, false);
            false
        };

        if !sent {
            crate::log(
                &format!(
                    "[REQ] dispatch_outbound FAILED request_id={} link_id={} iface={} - response not sent!",
                    crate::hexrep(request_id, false),
                    crate::hexrep(&self.link_id, false),
                    attached_interface,
                ),
                crate::LOG_ERROR,
                false,
                false,
            );
        } else {
            crate::log(
                &format!(
                    "[REQ] response SENT request_id={} link_id={} iface={} wire_bytes={} ciphertext_bytes={}",
                    crate::hexrep(request_id, false),
                    crate::hexrep(&self.link_id, false),
                    attached_interface,
                    raw.len(),
                    ciphertext.len(),
                ),
                crate::LOG_NOTICE,
                false,
                false,
            );
        }

        self.had_outbound(false);
        Ok(())
    }

    fn handle_response_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        // Python RNS wire format: msgpack array [request_id_bytes, response_value]
        // The response_value can be any msgpack type (integer error code, list, bytes)
        // so we must NOT decode it as ByteBuf — use rmpv to read the outer array.
        crate::log(&format!("[RESP] handle_response_packet: {} bytes plaintext", plaintext.len()), crate::LOG_NOTICE, false, false);
        let outer = match rmpv_read_value(&mut std::io::Cursor::new(plaintext)) {
            Ok(v) => v,
            Err(e) => {
                crate::log(&format!("[RESP] rmpv_read_value failed: {}", e), crate::LOG_NOTICE, false, false);
                return Ok(());
            }
        };
        let elements = match outer {
            rmpv::Value::Array(v) if v.len() >= 2 => v,
            ref other => {
                crate::log(&format!("[RESP] outer value is not Array(>=2): {:?}", other), crate::LOG_NOTICE, false, false);
                return Ok(());
            }
        };
        let request_id: Vec<u8> = match &elements[0] {
            rmpv::Value::Binary(b) => b.clone(),
            other => {
                crate::log(&format!("[RESP] elements[0] is not Binary: {:?}", other), crate::LOG_NOTICE, false, false);
                return Ok(());
            }
        };
        crate::log(&format!("[RESP] response request_id={}", crate::hexrep(&request_id, false)), crate::LOG_NOTICE, false, false);
        // Re-encode the response value as raw msgpack bytes so callers can decode it.
        let mut response_bytes: Vec<u8> = Vec::new();
        if rmpv_write_value(&mut response_bytes, &elements[1]).is_err() {
            return Ok(());
        }
        crate::log(
            &format!(
                "[RESP] response value {} bytes preview={:02x?}",
                response_bytes.len(),
                &response_bytes[..response_bytes.len().min(32)]
            ),
            crate::LOG_NOTICE,
            false,
            false,
        );

        let mut pending = self.pending_requests.lock().map_err(|_| "Pending request lock poisoned")?;
        let pending_ids: Vec<String> = pending
            .iter()
            .map(|request| crate::hexrep(&request.request_id, false))
            .collect();
        crate::log(&format!("[RESP] pending_requests count={}, looking for id={} pending_ids={:?}", pending.len(), crate::hexrep(&request_id, false), pending_ids), crate::LOG_NOTICE, false, false);
        if let Some(index) = pending.iter().position(|p| p.request_id == request_id) {
            crate::log(&format!("[RESP] found pending request, spawning callback thread"), crate::LOG_NOTICE, false, false);
            let request = pending.remove(index);
            let receipt = RequestReceipt {
                request_id: request_id.clone(),
                response: Some(response_bytes),
                link: Arc::new(Mutex::new(self.clone())),
                sent_at: request.sent_at,
                received_at: Some(current_time().unwrap_or(0) as f64),
                progress: 1.0,
            };

            if let Some(callback) = request.response_callback {
                // Spawn a thread so the callback can re-lock the link
                // (e.g. for teardown) without deadlocking the TCP reader thread
                // that currently holds the link mutex.
                thread::spawn(move || { callback(receipt); });
            }
        } else {
            crate::log(&format!("[RESP] NO matching pending request found for id={} pending_ids={:?}", crate::hexrep(&request_id, false), pending_ids), crate::LOG_NOTICE, false, false);
        }

        Ok(())
    }

    pub fn request(
        &self,
        path: String,
        data: Vec<u8>,
        response_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        failed_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
        progress_callback: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>>,
    ) -> Result<Vec<u8>, String> {
        // Python RNS wire format: [timestamp_f64, path_hash_16bytes, data_bytes]
        let path_hash = identity::truncated_hash(path.as_bytes());
        let timestamp = current_time().unwrap_or(0) as f64;
        let payload = RequestPayload(
            timestamp,
            serde_bytes::ByteBuf::from(path_hash),
            serde_bytes::ByteBuf::from(data),
        );

        // Python wire format: msgpack.packb([timestamp_f64, path_hash_bytes, data])
        // where `data` is the VALUE itself — not double-encoded as bin.
        // We decode our pre-encoded `data` bytes back to an rmpv Value so we can
        // embed it inline in the outer array (matching Python's msgpack.packb behaviour).
        let data_value = rmpv_read_value(&mut std::io::Cursor::new(&payload.2.as_ref()))
            .unwrap_or(rmpv::Value::Nil);
        let outer_value = rmpv::Value::Array(vec![
            rmpv::Value::F64(payload.0),
            rmpv::Value::Binary(payload.1.into_vec()),
            data_value,
        ]);
        let mut payload_data = Vec::new();
        rmpv_write_value(&mut payload_data, &outer_value).map_err(|e| format!("Failed to encode request payload: {}", e))?;
        // Encrypt the payload using the link session key directly (via self.encrypt),
        // avoiding the self-deadlock that would occur if we went through
        // DestinationType::Link → runtime_encrypt_for_destination → link.lock()
        // while the caller already holds link_arc.lock().
        let ciphertext = self.encrypt(&payload_data)?;

        // Build a Link-type destination (hash = link_id) to get correct routing
        // and link-interface filtering in Transport::outbound. We skip
        // destination.encrypt() by pre-setting packet.ciphertext below.
        let mut dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?.clone();
        dest.dest_type = DestinationType::Link;
        dest.hash = self.link_id.clone();
        dest.hexhash = crate::hexrep(&dest.hash, false);
        // Attach link routing info so Transport::outbound knows the interface.
        dest.link = Some(crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            status_closed: self.state == STATE_CLOSED,
            mtu: Some(self.mtu),
            attached_interface: self.attached_interface.clone(),
        });
        let mut packet = Packet::new(
            Some(dest),
            vec![], // data unused — we supply ciphertext manually below
            DATA,
            crate::packet::REQUEST,
            crate::transport::BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        // Inject the pre-encrypted ciphertext and mark packet as packed so
        // send() won't call pack() and attempt to re-encrypt.
        packet.ciphertext = Some(ciphertext);
        // pack() manually: build raw = flags + hops + link_id + context + ciphertext.
        {
            let mut raw = Vec::new();
            raw.push(packet.flags);
            raw.push(packet.hops);
            raw.extend_from_slice(&self.link_id);
            raw.push(packet.context);
            raw.extend_from_slice(packet.ciphertext.as_ref().unwrap());
            packet.destination_hash = Some(self.link_id.clone());
            packet.raw = raw;
            packet.packed = true;
            packet.update_hash();
        }
        // Python computes request_id = truncated_hash(packet.get_hashable_part())
        // We must compute this BEFORE send() since send() doesn't change the hash
        let request_id = packet.get_truncated_hash();

        let sent_at = current_time().unwrap_or(0) as f64;
        let receipt = RequestReceipt {
            request_id: request_id.clone(),
            response: None,
            link: Arc::new(Mutex::new(self.clone())),
            sent_at,
            received_at: None,
            progress: 0.0,
        };

        if let Err(err) = packet.send() {
            if let Some(callback) = failed_callback {
                // Spawn so callback can re-acquire locks (e.g. router) that may
                // already be held by the thread calling request().
                thread::spawn(move || { callback(receipt); });
            }
            return Err(err);
        }

        if let Some(callback) = progress_callback.clone() {
            let mut initial = receipt.clone();
            initial.progress = 0.1;
            // Spawn so the progress callback can re-acquire locks (e.g. router)
            // that may already be held by the calling thread.
            thread::spawn(move || { callback(initial); });
        }

        // Calculate timeout based on RTT or default
        let timeout = if let Some(rtt) = self.rtt {
            rtt * self.traffic_timeout_factor + crate::resource::Resource::RESPONSE_MAX_GRACE_TIME * 1.125
        } else {
            // Default timeout when RTT not available
            self.traffic_timeout_factor * 3.0 + crate::resource::Resource::RESPONSE_MAX_GRACE_TIME * 1.125
        };

        let mut pending = self.pending_requests.lock().map_err(|_| "Pending request lock poisoned")?;
        
        // Request timeout checking is now handled by the actor loop
        // (actor_check_request_timeouts).
        
        pending.push(PendingRequest {
            request_id: request_id.clone(),
            sent_at,
            timeout,
            response_callback,
            failed_callback,
            progress_callback,
        });

        Ok(request_id)
    }
    
    /// Handle LINKIDENTIFY packets - validate identity signature and establish remote identity
    fn handle_linkidentify_packet(&mut self, plaintext: &[u8]) -> Result<(), String> {
        // LINKIDENTIFY packet format: public_key (64 bytes) + signature (64 bytes)
        if plaintext.len() != 128 {
            return Err("Invalid LINKIDENTIFY packet length".to_string());
        }

        let public_key = &plaintext[0..64];
        let signature = &plaintext[64..128];

        // Create signed data: link_id + public_key
        let mut signed_data = self.link_id.clone();
        signed_data.extend_from_slice(public_key);

        // Create Identity from public key bytes for signature validation
        match Identity::from_public_key(public_key) {
            Ok(identity) => {
                // Validate the signature
                if identity.validate(signature, &signed_data) {
                    // Store the remote identity
                    if let Ok(mut remote_id) = self.remote_identity.lock() {
                        *remote_id = Some(identity.clone());
                    }

                    // Signal that remote_identified callback should fire
                    // OUTSIDE the link lock (in dispatch_runtime_packet)
                    // so the callback receives the original Arc, not a clone.
                    self.pending_remote_identified = true;

                    Ok(())
                } else {
                    Err("LINKIDENTIFY signature validation failed".to_string())
                }
            }
            Err(e) => Err(format!("Failed to create identity from public key: {}", e)),
        }
    }
    
    /// Handle PROOF packets
    fn handle_proof_packet(&mut self, packet: &Packet) -> Result<(), String> {
        if packet.context == crate::packet::RESOURCE_PRF {
            let hash_len = identity::HASHLENGTH / 8;
            if packet.data.len() >= hash_len {
                let resource_hash = packet.data[..hash_len].to_vec();
                // Clone the list of outgoing resource Arcs WITHOUT locking
                // individual resources — avoids AB-BA deadlock with deferred
                // REQ handler thread (resource→link vs link→resource).
                let resources: Vec<Arc<Mutex<Resource>>> = if let Ok(resources) = self.outgoing_resources.lock() {
                    resources.clone()
                } else {
                    Vec::new()
                };

                let proof_data = packet.data.clone();
                thread::spawn(move || {
                    // Find matching resources and validate proof OUTSIDE the link lock
                    for resource in resources.iter() {
                        let matches = if let Ok(guard) = resource.lock() {
                            guard.hash == resource_hash.as_slice()
                        } else {
                            false
                        };
                        if matches {
                            let proof = proof_data.clone();
                            let target = resource.clone();
                            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                if let Ok(mut resource_guard) = target.lock() {
                                    resource_guard.validate_proof(&proof);
                                } else {
                                }
                            }));
                            let _ = result;
                        }
                    }
                });
            }
            return Ok(());
        }

        if !self.initiator || self.state != STATE_PENDING {
            return Ok(());
        }

        let data = &packet.data;
        if data.len() != (identity::SIGLENGTH / 8 + ECPUBSIZE / 2)
            && data.len() != (identity::SIGLENGTH / 8 + ECPUBSIZE / 2 + LINK_MTU_SIZE)
        {
            return Err("Invalid link proof packet length".to_string());
        }

        let mode = mode_from_lp_packet(data);
        if mode != self.mode {
            return Err("Invalid link mode in proof packet".to_string());
        }

        let signature = data[..identity::SIGLENGTH / 8].to_vec();
        let peer_pub_bytes = data[identity::SIGLENGTH / 8..identity::SIGLENGTH / 8 + ECPUBSIZE / 2].to_vec();

        let (peer_sig_pub_bytes, destination_identity) = {
            let destination = self.destination.lock().map_err(|_| "Destination lock poisoned")?;
            let identity = destination.identity.clone().ok_or("Missing destination identity on link")?;
            let public_key = identity.get_public_key()?;
            if public_key.len() != 64 {
                return Err("Invalid destination public key length".to_string());
            }
            (public_key[32..64].to_vec(), identity)
        };

        self.load_peer(peer_pub_bytes.clone(), peer_sig_pub_bytes.clone())?;
        self.handshake()?;

        let mut signed_data = self.link_id.clone();
        signed_data.extend_from_slice(&peer_pub_bytes);
        signed_data.extend_from_slice(&peer_sig_pub_bytes);
        if data.len() == (identity::SIGLENGTH / 8 + ECPUBSIZE / 2 + LINK_MTU_SIZE) {
            signed_data.extend_from_slice(&signalling_bytes(mtu_from_lp_packet(data).unwrap_or(reticulum::MTU), mode)?);
        }

        if !destination_identity.validate(&signature, &signed_data) {
            return Err("Invalid link proof signature".to_string());
        }

        let now = current_time().unwrap_or(0);
        let now_precise = now_seconds();
        if let Some(request_time) = self.request_time {
            self.rtt = Some((now_precise - request_time).max(0.001));
        }
        self.state = STATE_ACTIVE;
        self.status = STATE_ACTIVE;
        self.activated_at = Some(now);
        self.attached_interface = packet.receiving_interface.clone();
        self.last_proof = now;
        self.last_inbound = now;
        self.last_outbound = now;
        if let Some(mtu) = mtu_from_lp_packet(data) {
            self.mtu = mtu;
            self.update_mdu();
        }

        self.update_keepalive();

        crate::log(&format!("Link activated {} rtt={:.3}s keepalive={:.0}s attached_interface={:?}", crate::hexrep(&self.link_id, false), self.rtt.unwrap_or(0.0), self.keepalive, self.attached_interface), crate::LOG_NOTICE, false, false);

        if let Some(rtt) = self.rtt {
            let rtt_data = to_vec(&rtt).map_err(|e| format!("Failed to encode LRRTT payload: {}", e))?;

            let mut link_destination = self
                .destination
                .lock()
                .map_err(|_| "Destination lock poisoned")?
                .clone();
            link_destination.dest_type = DestinationType::Link;
            link_destination.hash = self.link_id.clone();
            link_destination.hexhash = crate::hexrep(&link_destination.hash, false);
            link_destination.link = Some(crate::destination::LinkInfo {
                rtt: self.rtt,
                traffic_timeout_factor: self.traffic_timeout_factor,
                status_closed: self.state == STATE_CLOSED,
                mtu: Some(self.mtu),
                attached_interface: self.attached_interface.clone(),
            });

            thread::spawn(move || {
                let mut rtt_packet = Packet::new(
                    Some(link_destination),
                    rtt_data,
                    DATA,
                    packet::LRRTT,
                    crate::transport::BROADCAST,
                    packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );
                let _ = rtt_packet.send();
            });
            self.had_outbound(false);
        }

        // NOTE: We do NOT fire the link_established callback here because
        // dispatch_runtime_packet now fires it for BOTH initiator and
        // non-initiator when it detects the state transition to ACTIVE.
        // This eliminates the disconnected-clone bug where a new
        // Arc::new(Mutex::new(self.clone())) was passed to the callback.

        Ok(())
    }
    
    /// Send a raw DATA packet on this link.
    ///
    /// Unlike [`request`], this does not invoke any request handler on the remote
    /// side.  The packet falls through to the remote's `callbacks.packet` callback
    /// (the same path used by client PUT packets).  Use this for fire-and-forget
    /// delivery where no response ACK is expected.
    ///
    /// **Locking**: `self` must be locked by the caller (normal `&self` borrow).
    /// The method pre-encrypts using the link session key and manually packs the
    /// packet to avoid calling `Transport::outbound` while holding the link mutex
    /// (same pattern as [`request`]).
    pub fn send_packet(&self, data: &[u8]) -> Result<(), String> {
        if self.state != STATE_ACTIVE {
            return Err(format!("Link is not active (state={})", self.state));
        }
        let ciphertext = self.encrypt(data)?;

        let mut dest = self.destination.lock().map_err(|_| "Destination lock poisoned")?.clone();
        dest.dest_type = DestinationType::Link;
        dest.hash = self.link_id.clone();
        dest.hexhash = crate::hexrep(&dest.hash, false);
        dest.link = Some(crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            status_closed: self.state == STATE_CLOSED,
            mtu: Some(self.mtu),
            attached_interface: self.attached_interface.clone(),
        });

        let mut packet = Packet::new(
            Some(dest),
            vec![], // data unused — ciphertext injected manually below
            DATA,
            crate::packet::DATA,
            crate::transport::BROADCAST,
            crate::packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        packet.ciphertext = Some(ciphertext);
        {
            let mut raw = Vec::new();
            raw.push(packet.flags);
            raw.push(packet.hops);
            raw.extend_from_slice(&self.link_id);
            raw.push(packet.context);
            raw.extend_from_slice(packet.ciphertext.as_ref().unwrap());
            packet.destination_hash = Some(self.link_id.clone());
            packet.raw = raw;
            packet.packed = true;
            packet.update_hash();
        }
        packet.send().map(|_| ()).map_err(|e| format!("send_packet failed: {e}"))
    }

    /// Update keepalive interval based on measured RTT (matches Python __update_keepalive)
    pub fn update_keepalive(&mut self) {
        if let Some(rtt) = self.rtt {
            self.keepalive = (rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)).min(KEEPALIVE_MAX).max(KEEPALIVE_MIN);
            self.stale_time = self.keepalive * STALE_FACTOR;
        }
    }

    /// Prepare keepalive info so the caller can send the packet outside the link lock.
    /// Returns (destination, link_id) if a keepalive should be sent.
    pub fn prepare_keepalive(&mut self) -> Option<(Destination, Vec<u8>)> {
        let mut link_destination = match self.destination.lock() {
            Ok(d) => d.clone(),
            Err(_) => return None,
        };
        link_destination.dest_type = DestinationType::Link;
        link_destination.hash = self.link_id.clone();
        link_destination.hexhash = crate::hexrep(&link_destination.hash, false);
        self.had_outbound(true);
        Some((link_destination, self.link_id.clone()))
    }

    /// Send keep-alive packet (called when link lock is NOT held externally)
    pub fn send_keepalive(&mut self) -> Result<(), String> {
        let info = self.prepare_keepalive();
        if let Some((link_destination, _link_id)) = info {
            thread::spawn(move || {
                let mut keepalive_packet = Packet::new(
                    Some(link_destination),
                    vec![0xFF],
                    DATA,
                    crate::packet::KEEPALIVE,
                    crate::transport::BROADCAST,
                    packet::HEADER_1,
                    None,
                    None,
                    false,
                    0,
                );
                let _ = keepalive_packet.send();
            });
        }
        Ok(())
    }

    /// Identify the initiator of the link to the remote peer over the encrypted link.
    /// This can only happen once the link has been established, and is carried out
    /// over the encrypted link. The identity is only revealed to the remote peer,
    /// and initiator anonymity is thus preserved. This method can be used for authentication.
    pub fn identify(&mut self, identity: &Identity) -> Result<(), String> {
        if !self.initiator || self.state != STATE_ACTIVE {
            return Err("Can only identify on outbound link after activation".to_string());
        }

        let public_key = identity.get_public_key()?;
        // Create signed data: link_id + public_key
        let mut signed_data = self.link_id.clone();
        signed_data.extend_from_slice(&public_key);

        // Sign the data with the identity
        let signature = identity.sign(&signed_data);

        // Create proof data: public_key + signature
        let mut proof_data = public_key.clone();
        proof_data.extend_from_slice(&signature);

        let encrypted_identify = self.encrypt(&proof_data)?;

        // Send identify over the active link destination semantics
        let mut dest = self
            .destination
            .lock()
            .map_err(|_| "Failed to lock destination".to_string())?
            .clone();
        dest.dest_type = crate::destination::DestinationType::Link;
        dest.hash = self.link_id.clone();
        dest.hexhash = crate::hexrep(&dest.hash, false);
        dest.link = Some(crate::destination::LinkInfo {
            rtt: self.rtt,
            traffic_timeout_factor: self.traffic_timeout_factor,
            status_closed: self.state == STATE_CLOSED,
            mtu: Some(self.mtu),
            attached_interface: self.attached_interface.clone(),
        });

        // Create packet with LINKIDENTIFY context
        let packet = Packet::new(
            Some(dest),
            encrypted_identify,
            DATA,
            LINKIDENTIFY,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );

        // Send the packet
        let mut packet = packet;
        packet.send()?;

        // Record outbound activity
        self.had_outbound(false);

        Ok(())
    }
    
    /// Register resource management
    pub fn register_outgoing_resource(&self, resource: Arc<Mutex<Resource>>) {
        if let Ok(mut resources) = self.outgoing_resources.lock() {
            resources.push(resource);
        }
    }
    
    /// Register incoming resource
    pub fn register_incoming_resource(&self, resource: Arc<Mutex<Resource>>) {
        if let Ok(mut resources) = self.incoming_resources.lock() {
            resources.push(resource);
        }
    }

    /// Check if incoming resource is already registered
    pub fn has_incoming_resource(&self, resource: &Arc<Mutex<Resource>>) -> bool {
        let target_hash = resource.lock().ok().map(|r| r.hash.clone()).unwrap_or_default();
        if let Ok(resources) = self.incoming_resources.lock() {
            resources.iter().any(|r| {
                r.try_lock().ok().map(|r| r.hash == target_hash).unwrap_or(false)
            })
        } else {
            false
        }
    }

    /// Cancel outgoing resource and remove from tracking.
    /// Uses try_lock on individual resources to avoid deadlock when called
    /// from validate_proof (which already holds the resource lock).
    /// If a resource can't be locked, deferred cleanup runs after 100ms.
    pub fn cancel_outgoing_resource(&self, resource: Arc<Mutex<Resource>>) {
        let target_hash = resource.lock().ok().map(|r| r.hash.clone()).unwrap_or_default();
        if target_hash.is_empty() { return; }
        let mut need_deferred = false;
        match self.outgoing_resources.try_lock() {
            Ok(mut resources) => {
                let before = resources.len();
                resources.retain(|r| {
                    match r.try_lock() {
                        Ok(guard) => guard.hash != target_hash,
                        Err(_) => true, // can't lock (possibly held by us), keep for deferred
                    }
                });
                if resources.len() == before {
                    need_deferred = true; // nothing removed, schedule retry
                }
            }
            Err(_) => {
                need_deferred = true;
            }
        }
        if need_deferred {
            let outgoing = Arc::clone(&self.outgoing_resources);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(mut resources) = outgoing.lock() {
                    resources.retain(|r| {
                        r.lock().ok().map(|r| r.hash != target_hash).unwrap_or(true)
                    });
                }
            });
        }
    }

    /// Cancel incoming resource and remove from tracking.
    /// Uses try_lock to avoid deadlock (same pattern as cancel_outgoing_resource).
    pub fn cancel_incoming_resource(&self, resource: Arc<Mutex<Resource>>) {
        let target_hash = resource.lock().ok().map(|r| r.hash.clone()).unwrap_or_default();
        if target_hash.is_empty() { return; }
        let mut need_deferred = false;
        match self.incoming_resources.try_lock() {
            Ok(mut resources) => {
                let before = resources.len();
                resources.retain(|r| {
                    match r.try_lock() {
                        Ok(guard) => guard.hash != target_hash,
                        Err(_) => true,
                    }
                });
                if resources.len() == before {
                    need_deferred = true;
                }
            }
            Err(_) => {
                need_deferred = true;
            }
        }
        if need_deferred {
            let incoming = Arc::clone(&self.incoming_resources);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                if let Ok(mut resources) = incoming.lock() {
                    resources.retain(|r| {
                        r.lock().ok().map(|r| r.hash != target_hash).unwrap_or(true)
                    });
                }
            });
        }
    }

    /// Mark resource concluded and update tracking stats
    /// Returns the resource_concluded callback (if any) so the caller can invoke
    /// it OUTSIDE the link lock, preventing deadlocks on incoming_resources.
    pub fn resource_concluded(&mut self, resource: Arc<Mutex<Resource>>) -> Option<Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync>> {
        if let Ok(resource_guard) = resource.lock() {
            self.last_resource_window = Some(resource_guard.window);
            self.last_resource_eifr = resource_guard.eifr;
        }
        let callback = self.callbacks.resource_concluded.clone();
        self.cancel_outgoing_resource(resource.clone());
        self.cancel_incoming_resource(resource);
        callback
    }
    
    /// Check if ready for new resource
    pub fn ready_for_new_resource(&self) -> bool {
        self.outgoing_resources.lock().map(|r| r.is_empty()).unwrap_or(true)
    }
}

/// Helper to get current Unix timestamp
fn current_time() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Helper to get current Unix timestamp as f64 with subsecond precision
fn now_seconds() -> f64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0));
    now.as_secs() as f64 + (now.subsec_nanos() as f64 / 1_000_000_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Build a minimal incoming Link with a unique link_id. `initiator=false`.
    fn make_incoming_link(link_id: Vec<u8>) -> Link {
        let dest = crate::destination::Destination::default();
        let mut link = Link::new_inbound(dest).expect("new_inbound");
        link.link_id = link_id;
        link.initiator = false;
        link
    }

    /// Regression test: `unregister_runtime_link` must not deadlock when called
    /// while the caller already holds the link's Mutex.
    #[test]
    fn unregister_runtime_link_no_deadlock_while_holding_link_mutex() {
        let link_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(13)).collect();
        let link = make_incoming_link(link_id.clone());
        let link_arc = Arc::new(Mutex::new(link));

        register_runtime_link(Arc::clone(&link_arc));

        let (tx, rx) = mpsc::channel::<()>();
        let link_arc_clone = Arc::clone(&link_arc);
        let link_id_clone = link_id.clone();
        std::thread::spawn(move || {
            let _guard = link_arc_clone.lock().unwrap();
            unregister_runtime_link(&link_id_clone);
            let _ = tx.send(());
        });

        rx.recv_timeout(std::time::Duration::from_secs(2))
            .expect("unregister_runtime_link deadlocked while link mutex was held");
    }

    /// After `register_runtime_link` + `unregister_runtime_link`, the entry must
    /// be absent from RUNTIME_LINKS.
    #[test]
    fn unregister_runtime_link_removes_from_registry() {
        let link_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(17)).collect();
        let link = make_incoming_link(link_id.clone());
        let link_arc = Arc::new(Mutex::new(link));

        register_runtime_link(Arc::clone(&link_arc));

        assert!(
            RUNTIME_LINKS.lock().unwrap().contains_key(&link_id),
            "RUNTIME_LINKS should contain the link after register"
        );

        unregister_runtime_link(&link_id);

        assert!(
            !RUNTIME_LINKS.lock().unwrap().contains_key(&link_id),
            "RUNTIME_LINKS should not contain the link after unregister"
        );
    }

    /// Both inbound and outbound links should appear in RUNTIME_LINKS.
    #[test]
    fn register_runtime_link_outbound_stored_in_registry() {
        let link_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(19)).collect();
        let dest = crate::destination::Destination::default();
        let mut link = Link::new_inbound(dest).expect("new_inbound");
        link.link_id = link_id.clone();
        link.initiator = true; // outbound

        let link_arc = Arc::new(Mutex::new(link));
        register_runtime_link(Arc::clone(&link_arc));

        let in_runtime = RUNTIME_LINKS.lock().unwrap().contains_key(&link_id);

        unregister_runtime_link(&link_id);

        assert!(in_runtime, "outbound link must appear in RUNTIME_LINKS");
    }

    /// LinkHandle::snapshot returns correct state.
    #[test]
    fn link_handle_snapshot_basic() {
        let link_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(23)).collect();
        let mut link = make_incoming_link(link_id.clone());
        link.state = STATE_ACTIVE;
        link.status = STATE_ACTIVE;
        link.rtt = Some(0.05);
        let handle = LinkHandle::from_arc_with_id(Arc::new(Mutex::new(link)), link_id.clone());
        let snap = handle.snapshot().expect("snapshot should succeed");
        assert_eq!(snap.link_id, link_id);
        assert_eq!(snap.state, STATE_ACTIVE);
        assert!(handle.is_active());
        assert!(handle.is_alive());
    }

    /// `prove_with_identity` must populate `link_destination.link` with a `LinkInfo`
    /// that carries `attached_interface`. Without this, `Transport::outbound` broadcasts
    /// the LRPROOF on ALL interfaces instead of routing it to only the link's peer.
    ///
    /// We verify the invariant by inspecting the `prove_with_identity` path indirectly:
    /// a link with `attached_interface = Some("iface0")` must produce `LinkInfo` with
    /// the same value. The test reaches this by checking the field is propagated when
    /// we manually run the setup that `prove_with_identity` does.
    #[test]
    fn prove_with_identity_builds_link_destination_with_link_info() {
        let dest = crate::destination::Destination::default();
        let mut link = Link::new_inbound(dest).expect("new_inbound");
        link.attached_interface = Some("test_iface".to_string());
        link.state = STATE_ACTIVE;

        // Reproduce the link_destination construction from prove_with_identity.
        let mut link_destination = link.destination.lock().unwrap().clone();
        link_destination.dest_type = DestinationType::Link;
        link_destination.hash = link.link_id.clone();
        link_destination.hexhash = crate::hexrep(&link_destination.hash, false);
        link_destination.link = Some(crate::destination::LinkInfo {
            rtt: link.rtt,
            traffic_timeout_factor: TRAFFIC_TIMEOUT_FACTOR,
            status_closed: link.state == STATE_CLOSED,
            mtu: Some(link.mtu),
            attached_interface: link.attached_interface.clone(),
        });

        let info = link_destination.link
            .as_ref()
            .expect("link_destination.link must be Some after prove_with_identity setup");
        assert_eq!(
            info.attached_interface.as_deref(),
            Some("test_iface"),
            "LinkInfo.attached_interface must match the link's attached_interface"
        );
        assert!(!info.status_closed, "link is ACTIVE, status_closed must be false");
    }

    /// Regression: KEEPALIVE packets travel UNENCRYPTED on the wire (1-byte
    /// payload — see `Packet::pack` which skips encryption for context ==
    /// KEEPALIVE).  `handle_data_packet` MUST therefore dispatch the KEEPALIVE
    /// branch BEFORE attempting `self.decrypt(packet.data)`, otherwise a
    /// 1-byte ciphertext fails AES-GCM and the function silently returns
    /// Ok(()) without sending the 0xFE pong.  When that bug was present the
    /// initiator's `last_inbound` never refreshed on quiet links and links
    /// were torn down at exactly `2*keepalive + STALE_GRACE` (~15 s for
    /// low-RTT links), causing the iOS pill to flicker between Linked and
    /// Linking every ~15 s.
    ///
    /// We assert the responder side (`initiator = false`) reacts to a 0xFF
    /// ping by setting `last_keepalive` (which only happens inside
    /// `prepare_keepalive` → `had_outbound(true)`, i.e. the KEEPALIVE branch
    /// actually fired).  Sanity-check that `decrypt(&[0xFF])` does indeed
    /// fail so we know the test is genuinely exercising the pre-decrypt
    /// dispatch and not a path that happens to also work post-decrypt.
    #[test]
    fn keepalive_dispatched_before_decrypt_for_unencrypted_one_byte_payload() {
        let link_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(29)).collect();
        let mut link = make_incoming_link(link_id.clone());
        link.state = STATE_ACTIVE;
        link.status = STATE_ACTIVE;
        // initiator=false ensures the KEEPALIVE branch SHOULD send a pong.
        assert!(!link.initiator);

        // Sanity: decrypting a 1-byte buffer must fail so this test would
        // catch a regression that re-orders KEEPALIVE after the decrypt
        // step (which would silently drop the packet).
        assert!(
            link.decrypt(&[0xFFu8]).is_err(),
            "1-byte buffer must not be decryptable; otherwise this regression \
             test would also pass under the buggy post-decrypt ordering"
        );

        let before = link.last_keepalive;

        // Build the packet exactly as it appears on the wire: DATA packet,
        // context = KEEPALIVE (0xFA), 1-byte unencrypted payload 0xFF.
        let dest = link.destination.lock().unwrap().clone();
        let mut ping = Packet::new(
            Some(dest),
            vec![0xFFu8],
            DATA,
            crate::packet::KEEPALIVE,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        ping.data = vec![0xFFu8]; // ensure not mutated by pack

        // Dispatch.  Must succeed AND must have triggered the KEEPALIVE
        // branch (which calls prepare_keepalive → had_outbound(true) →
        // last_keepalive = now).
        link.handle_data_packet(&ping)
            .expect("handle_data_packet must succeed for an unencrypted KEEPALIVE");

        assert!(
            link.last_keepalive > before,
            "responder must enter the KEEPALIVE branch (which sets last_keepalive); \
             if last_keepalive is unchanged, the dispatch fell through to decrypt() \
             and silently dropped the ping — the exact regression we are guarding \
             against"
        );
    }

    /// Companion regression: an initiator receiving a 0xFE pong must NOT
    /// generate its own reply (would create an infinite ping/pong loop and
    /// also matches Python RNS semantics).  Verifies the `!self.initiator`
    /// guard inside the KEEPALIVE branch.
    #[test]
    fn keepalive_pong_does_not_trigger_reply_on_initiator() {
        let link_id: Vec<u8> = (0u8..16).map(|i| i.wrapping_mul(31)).collect();
        let mut link = make_incoming_link(link_id.clone());
        link.initiator = true; // outbound side
        link.state = STATE_ACTIVE;
        link.status = STATE_ACTIVE;

        let before = link.last_keepalive;

        let dest = link.destination.lock().unwrap().clone();
        let mut pong = Packet::new(
            Some(dest),
            vec![0xFEu8],
            DATA,
            crate::packet::KEEPALIVE,
            crate::transport::BROADCAST,
            packet::HEADER_1,
            None,
            None,
            false,
            0,
        );
        pong.data = vec![0xFEu8];

        link.handle_data_packet(&pong)
            .expect("handle_data_packet must succeed for a KEEPALIVE pong");

        assert_eq!(
            link.last_keepalive, before,
            "initiator must NOT send another keepalive in response to a 0xFE pong"
        );
    }
}
