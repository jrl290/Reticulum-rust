//! The dialer's side of the Prns native protocol as a pure state machine.
//!
//! No radio, no threads, no globals: every host event returns the effects it
//! causes, and `runtime.rs` carries them out. That keeps the protocol
//! testable without Bluetooth.
//!
//! Zero configuration (James, 2026-09-28: "any RTNode in range"): the host
//! scans and reports every advertisement it sees; `sighted` decides whether
//! to dial it. A link exists from that decision on, so a dial that never
//! completes is bounded like a handshake that never completes.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::wire::{self, Control, Endpoint, Greeting, IDENTITY_LEN};

/// Hello to Welcome. The Prns protocol constant (prns tokio runtime, both
/// sides); a hard ceiling for a peer that never answers, not a fix for a
/// slow one (DESIGN_PRINCIPLES §4). The 5-second rule still applies inside it.
pub const HANDSHAKE_CEILING: Duration = Duration::from_secs(10);

/// Sighting to `link_ready` (connect, discover, subscribe): Prns's Apple
/// backend dial timeout (prns-ffi macos `backend.rs`). A ceiling like the
/// handshake's; the 5-second rule applies inside it too.
pub const DIAL_CEILING: Duration = Duration::from_secs(15);

/// Prns `policy.rs` DIAL_RETRY_TTL_MS: a node that was dialled is not
/// dialled again for this long unless its link settles. Prns clears it when
/// a handshake fails; here it stands, so a node that fails every handshake
/// is dialled at most this often rather than on every advertisement.
pub const DIAL_RETRY: Duration = Duration::from_secs(16);

/// Prns `policy.rs` DIAL_FAILED_RETRY_TTL_MS: after a dial that never
/// reached the handshake.
pub const DIAL_FAILED_RETRY: Duration = Duration::from_secs(5);

/// RTNodes linked or being dialled at once. One: several nodes in range
/// would each rebroadcast the phone's traffic onto LoRa.
pub const MAX_NODES: usize = 1;

/// Packets waiting on one link, the depth of an interface writer queue
/// (`interface_writer::DEFAULT_WRITER_QUEUE_DEPTH`). Past it a packet is
/// dropped with a warning, as a full writer queue does.
pub const MAX_QUEUED_PACKETS: usize = 64;

/// The largest value this side writes. Hosts pass the value length a write
/// of one ATT PDU can carry (ATT MTU - 3), so a write never becomes an ATT
/// long write, which Prns peers do not handle.
pub const MAX_FRAGMENT: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Characteristic {
    Control = 0,
    Data = 1,
}

impl Characteristic {
    pub fn from_u8(value: u8) -> Option<Characteristic> {
        match value {
            0 => Some(Characteristic::Control),
            1 => Some(Characteristic::Data),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LinkState {
    Handshaking = 0,
    Settled = 1,
    Closed = 2,
    Dialing = 3,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Host: start (`true`) or stop scanning for advertisements. The engine
    /// wants sightings only while it could dial one.
    Scan { on: bool },
    /// Host: write `bytes` to the characteristic, with response, and report
    /// the result through `link_write_done`.
    Write { link: u64, characteristic: Characteristic, bytes: Vec<u8> },
    /// Host: cancel the connection, or the connection attempt. It need not
    /// report `link_closed` after.
    Disconnect { link: u64 },
    /// Host: the link changed state (for status in the app).
    State { link: u64, state: LinkState, peer: Option<[u8; IDENTITY_LEN]>, interface: Option<String> },
    /// Transport: a peer settled; register its interface and bring it online.
    Register { name: String, link: u64 },
    /// Transport: the peer reconnected before its old link was reported gone;
    /// the interface stays up and its packets now go to `link`.
    HandOver { name: String, link: u64 },
    /// Transport: the peer is gone; take its interface offline and remove it.
    Deregister { name: String },
    /// Transport: a whole packet arrived on the named interface.
    Inbound { name: String, packet: Vec<u8> },
    /// A send that completed: check it against the 5-second rule.
    CheckLate { label: &'static str, sent_at_unix: f64 },
    Log { level: i32, message: String },
}

#[derive(Debug)]
enum Phase {
    Dialing { dialed_at_unix: f64, deadline: Instant },
    Handshaking { hello_sent_at_unix: f64, deadline: Instant },
    Settled { peer: [u8; IDENTITY_LEN], interface: String },
}

#[derive(Debug)]
struct InFlight {
    sent_at_unix: f64,
    handshake: bool,
}

#[derive(Debug)]
struct Link {
    address: String,
    fragment_size: usize,
    phase: Phase,
    tx: VecDeque<VecDeque<Vec<u8>>>,
    in_flight: Option<InFlight>,
    reassembler: wire::Reassembler,
    bad_fragments: u64,
}

/// A Transport interface name for a peer: stable across reconnects, since
/// Transport keys everything (paths, links, writers) by interface name.
pub fn interface_name(peer: &[u8; IDENTITY_LEN]) -> String {
    format!("PrnsBLE[{}]", crate::hexrep(peer, false))
}

pub struct Engine {
    identity: [u8; IDENTITY_LEN],
    endpoint: Endpoint,
    links: HashMap<u64, Link>,
    next_link: u64,
    /// Per address: no dial before this instant.
    retry_after: HashMap<String, Instant>,
    /// What the host was last told about scanning (it starts scanning).
    scanning: bool,
}

impl Engine {
    pub fn new(identity: [u8; IDENTITY_LEN], endpoint: Endpoint) -> Self {
        Engine { identity, endpoint, links: HashMap::new(), next_link: 1, retry_after: HashMap::new(), scanning: true }
    }

    pub fn identity(&self) -> [u8; IDENTITY_LEN] {
        self.identity
    }

    /// The host saw an advertisement carrying the Prns service. `address`
    /// is the host's stable name for the device (CoreBluetooth peripheral
    /// identifier, Android device address); `company_id` and `data` its
    /// manufacturer data. Returns the link to dial it on, or `None`.
    pub fn sighted(
        &mut self,
        address: &str,
        company_id: u16,
        data: &[u8],
        now: Instant,
        now_unix: f64,
    ) -> (Option<u64>, Vec<Effect>) {
        if !wire::is_peripheral_only(company_id, data) {
            return (None, Vec::new());
        }
        if self.links.len() >= MAX_NODES
            || self.links.values().any(|l| l.address == address)
            || self.retry_after.get(address).is_some_and(|after| *after > now)
        {
            return (None, Vec::new());
        }
        self.retry_after.retain(|_, after| *after > now);
        self.retry_after.insert(address.to_string(), now + DIAL_RETRY);
        let link = self.next_link;
        self.next_link += 1;
        self.links.insert(
            link,
            Link {
                address: address.to_string(),
                fragment_size: 0,
                phase: Phase::Dialing { dialed_at_unix: now_unix, deadline: now + DIAL_CEILING },
                tx: VecDeque::new(),
                in_flight: None,
                reassembler: wire::Reassembler::default(),
                bad_fragments: 0,
            },
        );
        let mut effects = vec![
            Effect::State { link, state: LinkState::Dialing, peer: None, interface: None },
            Effect::Log { level: crate::LOG_NOTICE, message: format!("link {link}: dialling RTNode {address}") },
        ];
        effects.extend(self.scan_effect());
        (Some(link), effects)
    }

    /// The host connected, discovered the service and subscribed to both
    /// characteristics (subscriptions confirmed), in that order: a listener
    /// notifies Welcome on the control characteristic, so Hello must follow
    /// the subscription. `max_write_len` is what one write can carry.
    pub fn link_ready(
        &mut self,
        link: u64,
        max_write_len: usize,
        now: Instant,
        now_unix: f64,
    ) -> Result<Vec<Effect>, String> {
        let Some(state) = self.links.get_mut(&link) else {
            return Err(format!("link {link} is not being dialled"));
        };
        let Phase::Dialing { dialed_at_unix, .. } = state.phase else {
            return Err(format!("link {link} is already past dialling"));
        };
        let fragment_size = max_write_len.min(MAX_FRAGMENT);
        if fragment_size <= wire::FRAGMENT_HEADER_LEN {
            let mut effects = self.fail_dial(link, now, &format!("a write of {max_write_len} bytes cannot carry a fragment"));
            effects.push(Effect::Disconnect { link });
            return Ok(effects);
        }
        let hello = Control::Hello(Greeting {
            identity: self.identity,
            endpoint: self.endpoint,
            psm: 0,
            link_mtu: wire::HW_MTU as u16,
            rssi: None,
        })
        .encode();
        state.fragment_size = fragment_size;
        state.phase = Phase::Handshaking { hello_sent_at_unix: now_unix, deadline: now + HANDSHAKE_CEILING };
        state.in_flight = Some(InFlight { sent_at_unix: now_unix, handshake: true });
        Ok(vec![
            Effect::CheckLate { label: "prns_ble.dial", sent_at_unix: dialed_at_unix },
            Effect::State { link, state: LinkState::Handshaking, peer: None, interface: None },
            Effect::Write { link, characteristic: Characteristic::Control, bytes: hello },
            Effect::Log { level: crate::LOG_NOTICE, message: format!("link {link}: Hello sent, fragments up to {fragment_size} bytes") },
        ])
    }

    pub fn link_received(&mut self, link: u64, characteristic: Characteristic, bytes: &[u8], now_unix: f64) -> Vec<Effect> {
        let Some(state) = self.links.get_mut(&link) else {
            return vec![Effect::Log { level: crate::LOG_DEBUG, message: format!("link {link}: {} bytes after close, ignored", bytes.len()) }];
        };
        match characteristic {
            Characteristic::Control => match Control::decode(bytes) {
                Some(Control::Welcome(greeting)) => match state.phase {
                    Phase::Handshaking { hello_sent_at_unix, .. } => self.settle(link, greeting, hello_sent_at_unix, now_unix),
                    Phase::Dialing { .. } => self.close(link, "a Welcome before the Hello", true),
                    Phase::Settled { .. } => vec![Effect::Log { level: crate::LOG_WARNING, message: format!("link {link}: second Welcome ignored") }],
                },
                Some(Control::Close(reason)) => self.close(link, &format!("the peer closed it ({reason:?})"), true),
                Some(Control::Hello(_)) => self.close(link, "the peer sent a Hello; this side only dials", true),
                None => self.close(link, &format!("undecodable control message {}", crate::hexrep(bytes, false)), true),
            },
            Characteristic::Data => {
                let Phase::Settled { interface, .. } = &state.phase else {
                    return vec![Effect::Log { level: crate::LOG_WARNING, message: format!("link {link}: data before Welcome ignored") }];
                };
                let interface = interface.clone();
                let result = match wire::decode_fragment(bytes) {
                    Some(fragment) => state.reassembler.absorb(&fragment),
                    None => Err("undecodable fragment"),
                };
                match result {
                    Ok(Some(packet)) => vec![Effect::Inbound { name: interface, packet }],
                    Ok(None) => Vec::new(),
                    Err(why) => {
                        state.bad_fragments += 1;
                        vec![Effect::Log { level: crate::LOG_WARNING, message: format!("link {link}: {why} ({} so far)", state.bad_fragments) }]
                    }
                }
            }
        }
    }

    fn settle(&mut self, link: u64, greeting: Greeting, hello_sent_at_unix: f64, _now_unix: f64) -> Vec<Effect> {
        if greeting.identity == self.identity {
            return self.close(link, "the peer has this side's own identity", true);
        }
        let name = interface_name(&greeting.identity);
        let mut effects = vec![Effect::CheckLate { label: "prns_ble.handshake", sent_at_unix: hello_sent_at_unix }];

        // The same peer on another link: it reconnected before that link was
        // reported gone. Keep the new link (as RTNode does) and hand it the
        // interface, so its paths and links carry on.
        let previous = self.links.iter().find_map(|(id, other)| match &other.phase {
            Phase::Settled { peer, .. } if *id != link && *peer == greeting.identity => Some(*id),
            _ => None,
        });
        match previous {
            Some(old) => {
                self.links.remove(&old);
                effects.push(Effect::HandOver { name: name.clone(), link });
                effects.push(Effect::Disconnect { link: old });
                effects.push(Effect::State { link: old, state: LinkState::Closed, peer: Some(greeting.identity), interface: Some(name.clone()) });
            }
            None => effects.push(Effect::Register { name: name.clone(), link }),
        }
        if let Some(state) = self.links.get_mut(&link) {
            // A dial that settles clears its retry pause (Prns does the same).
            self.retry_after.remove(&state.address);
            state.phase = Phase::Settled { peer: greeting.identity, interface: name.clone() };
        }
        effects.push(Effect::State { link, state: LinkState::Settled, peer: Some(greeting.identity), interface: Some(name.clone()) });
        effects.push(Effect::Log {
            level: crate::LOG_NOTICE,
            message: format!(
                "link {link}: settled with peer {} (endpoint {}/{}), interface {name}{}",
                crate::hexrep(&greeting.identity, false),
                greeting.endpoint.stack,
                greeting.endpoint.host,
                if previous.is_some() { ", taken over from its previous link" } else { "" }
            ),
        });
        effects.extend(self.scan_effect());
        effects
    }

    /// A GATT write this side issued completed. A failed write is the
    /// deterministic end of the link.
    pub fn link_write_done(&mut self, link: u64, ok: bool, now_unix: f64) -> Vec<Effect> {
        let Some(state) = self.links.get_mut(&link) else {
            return Vec::new();
        };
        let Some(done) = state.in_flight.take() else {
            return vec![Effect::Log { level: crate::LOG_WARNING, message: format!("link {link}: write completion with no write outstanding") }];
        };
        if !ok {
            let what = if done.handshake { "the Hello write failed" } else { "a write failed" };
            return self.close(link, what, true);
        }
        let mut effects = Vec::new();
        if !done.handshake {
            effects.push(Effect::CheckLate { label: "prns_ble.write", sent_at_unix: done.sent_at_unix });
        }
        if let Some(write) = next_write(link, state, now_unix) {
            effects.push(write);
        }
        effects
    }

    /// Transport has a packet for the peer on `link`. Returns whether it was
    /// accepted.
    pub fn send_packet(&mut self, link: u64, packet: &[u8], now_unix: f64) -> (bool, Vec<Effect>) {
        let Some(state) = self.links.get_mut(&link) else {
            return (false, vec![Effect::Log { level: crate::LOG_DEBUG, message: format!("link {link}: packet for a closed link dropped") }]);
        };
        if !matches!(state.phase, Phase::Settled { .. }) {
            return (false, vec![Effect::Log { level: crate::LOG_WARNING, message: format!("link {link}: packet before Welcome dropped") }]);
        }
        if packet.len() > wire::HW_MTU {
            return (false, vec![Effect::Log { level: crate::LOG_ERROR, message: format!("link {link}: {} byte packet exceeds the {} byte MTU", packet.len(), wire::HW_MTU) }]);
        }
        if state.tx.len() >= MAX_QUEUED_PACKETS {
            return (false, vec![Effect::Log { level: crate::LOG_WARNING, message: format!("link {link}: {MAX_QUEUED_PACKETS} packets queued, {} byte packet dropped", packet.len()) }]);
        }
        state.tx.push_back(wire::fragments(packet, state.fragment_size).into());
        (true, next_write(link, state, now_unix).into_iter().collect())
    }

    /// The host reports the connection, or the connection attempt, gone:
    /// the OS disconnect or connect-failure callback, or a failure setting
    /// the link up (discovery, subscription).
    pub fn link_closed(&mut self, link: u64, now: Instant) -> Vec<Effect> {
        match self.links.get(&link).map(|l| &l.phase) {
            Some(Phase::Dialing { .. }) => self.fail_dial(link, now, "the dial failed"),
            Some(_) => self.close(link, "disconnected", false),
            None => Vec::new(),
        }
    }

    /// Dials and handshakes whose ceiling has passed.
    pub fn expire(&mut self, now: Instant) -> Vec<Effect> {
        let expired: Vec<(u64, bool)> = self
            .links
            .iter()
            .filter_map(|(id, l)| match l.phase {
                Phase::Dialing { deadline, .. } if deadline <= now => Some((*id, true)),
                Phase::Handshaking { deadline, .. } if deadline <= now => Some((*id, false)),
                _ => None,
            })
            .collect();
        let mut effects = Vec::new();
        for (link, dialing) in expired {
            if dialing {
                effects.extend(self.fail_dial(link, now, &format!("not connected within {} s", DIAL_CEILING.as_secs())));
                effects.push(Effect::Disconnect { link });
            } else {
                effects.extend(self.close(link, &format!("no Welcome within {} s", HANDSHAKE_CEILING.as_secs()), true));
            }
        }
        effects
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.links
            .values()
            .filter_map(|l| match l.phase {
                Phase::Dialing { deadline, .. } | Phase::Handshaking { deadline, .. } => Some(deadline),
                Phase::Settled { .. } => None,
            })
            .min()
    }

    /// Close every link (the stack is stopping). The host stops scanning
    /// itself, so no scan effect comes back.
    pub fn close_all(&mut self) -> Vec<Effect> {
        let ids: Vec<u64> = self.links.keys().copied().collect();
        let mut effects = Vec::new();
        for link in ids {
            effects.extend(self.close(link, "Bluetooth stopped", true));
        }
        effects.retain(|e| !matches!(e, Effect::Scan { .. }));
        effects
    }

    fn fail_dial(&mut self, link: u64, now: Instant, why: &str) -> Vec<Effect> {
        if let Some(state) = self.links.get(&link) {
            self.retry_after.insert(state.address.clone(), now + DIAL_FAILED_RETRY);
        }
        self.close(link, why, false)
    }

    fn close(&mut self, link: u64, why: &str, disconnect: bool) -> Vec<Effect> {
        let Some(state) = self.links.remove(&link) else {
            return Vec::new();
        };
        let mut effects = Vec::new();
        let (peer, interface) = match state.phase {
            Phase::Settled { peer, interface } => {
                effects.push(Effect::Deregister { name: interface.clone() });
                (Some(peer), Some(interface))
            }
            Phase::Dialing { .. } | Phase::Handshaking { .. } => (None, None),
        };
        if disconnect {
            effects.push(Effect::Disconnect { link });
        }
        effects.push(Effect::State { link, state: LinkState::Closed, peer, interface });
        effects.push(Effect::Log { level: crate::LOG_NOTICE, message: format!("link {link}: closed, {why}") });
        effects.extend(self.scan_effect());
        effects
    }

    /// Scanning is wanted exactly while another node could be dialled.
    fn scan_effect(&mut self) -> Option<Effect> {
        let wanted = self.links.len() < MAX_NODES;
        if wanted == self.scanning {
            return None;
        }
        self.scanning = wanted;
        Some(Effect::Scan { on: wanted })
    }
}

fn next_write(link: u64, state: &mut Link, now_unix: f64) -> Option<Effect> {
    if state.in_flight.is_some() {
        return None;
    }
    while let Some(packet) = state.tx.front_mut() {
        if let Some(fragment) = packet.pop_front() {
            if packet.is_empty() {
                state.tx.pop_front();
            }
            state.in_flight = Some(InFlight { sent_at_unix: now_unix, handshake: false });
            return Some(Effect::Write { link, characteristic: Characteristic::Data, bytes: fragment });
        }
        state.tx.pop_front();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: [u8; 16] = [0x11; 16];
    const NODE: [u8; 16] = [0xA5; 16];
    const RTNODE_ADV: [u8; 2] = [0x03, 0x01];
    const PHONE_ADV: [u8; 2] = [0x03, 0x00];

    fn welcome(identity: [u8; 16]) -> Vec<u8> {
        Control::Welcome(Greeting { identity, endpoint: Endpoint::ESP32, psm: 0, link_mtu: 500, rssi: None }).encode()
    }

    fn writes(effects: &[Effect]) -> Vec<(u64, Characteristic, Vec<u8>)> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Write { link, characteristic, bytes } => Some((*link, *characteristic, bytes.clone())),
                _ => None,
            })
            .collect()
    }

    fn transport(effects: &[Effect]) -> Vec<Effect> {
        effects
            .iter()
            .filter(|e| matches!(e, Effect::Register { .. } | Effect::HandOver { .. } | Effect::Deregister { .. } | Effect::Inbound { .. }))
            .cloned()
            .collect()
    }

    fn scans(effects: &[Effect]) -> Vec<bool> {
        effects.iter().filter_map(|e| match e { Effect::Scan { on } => Some(*on), _ => None }).collect()
    }

    fn dial(engine: &mut Engine, address: &str, t: Instant) -> u64 {
        engine.sighted(address, 0xFFFF, &RTNODE_ADV, t, 1000.0).0.expect("dialled")
    }

    /// Sighting to settled, returning the link and the settle effects.
    fn settled(engine: &mut Engine, address: &str, t: Instant) -> (u64, Vec<Effect>) {
        let link = dial(engine, address, t);
        engine.link_ready(link, 185, t, 1000.5).unwrap();
        engine.link_write_done(link, true, 1000.6);
        let effects = engine.link_received(link, Characteristic::Control, &welcome(NODE), 1000.7);
        (link, effects)
    }

    #[test]
    fn only_an_rtnode_advertisement_is_dialled() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        assert_eq!(engine.sighted("phone", 0xFFFF, &PHONE_ADV, t, 1000.0).0, None);
        assert_eq!(engine.sighted("apple", 0x004C, &RTNODE_ADV, t, 1000.0).0, None);
        assert_eq!(engine.sighted("none", 0xFFFF, &[], t, 1000.0).0, None);
        let (link, effects) = engine.sighted("node", 0xFFFF, &RTNODE_ADV, t, 1000.0);
        assert!(link.is_some());
        assert!(effects.iter().any(|e| matches!(e, Effect::State { state: LinkState::Dialing, .. })));
    }

    #[test]
    fn one_node_at_a_time_and_scanning_only_while_there_is_room() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let (a, effects) = engine.sighted("a", 0xFFFF, &RTNODE_ADV, t, 1000.0);
        assert_eq!(scans(&effects), vec![false], "at capacity the host stops scanning");
        assert_eq!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, t, 1000.0).0, None, "already dialling it");
        assert_eq!(engine.sighted("b", 0xFFFF, &RTNODE_ADV, t, 1000.0).0, None, "at capacity");
        let effects = engine.link_closed(a.unwrap(), t);
        assert_eq!(scans(&effects), vec![true], "room again: scan again");
        assert!(engine.sighted("b", 0xFFFF, &RTNODE_ADV, t, 1000.0).0.is_some());
    }

    #[test]
    fn a_failed_dial_pauses_that_node_for_five_seconds() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        engine.link_closed(link, t + Duration::from_secs(1));
        let pause_end = t + Duration::from_secs(1) + DIAL_FAILED_RETRY;
        assert_eq!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, pause_end - Duration::from_millis(1), 1002.0).0, None);
        assert!(engine.sighted("b", 0xFFFF, &RTNODE_ADV, pause_end - Duration::from_millis(1), 1002.0).0.is_some(), "another node is free to dial");
        let mut engine = Engine::new(US, Endpoint::IOS);
        let link = dial(&mut engine, "a", t);
        engine.link_closed(link, t + Duration::from_secs(1));
        assert!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, pause_end, 1006.0).0.is_some());
    }

    #[test]
    fn a_failed_handshake_keeps_the_sixteen_second_pause_from_the_dial() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        engine.link_ready(link, 185, t, 1000.1).unwrap();
        let effects = engine.link_received(link, Characteristic::Control, &[0x03, 0x03], 1000.2);
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert_eq!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, t + DIAL_RETRY - Duration::from_millis(1), 1015.0).0, None);
        assert!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, t + DIAL_RETRY, 1016.0).0.is_some());
    }

    #[test]
    fn a_settled_link_that_drops_is_dialled_again_at_the_next_sighting() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let (link, _) = settled(&mut engine, "a", t);
        engine.link_closed(link, t + Duration::from_secs(1));
        assert!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, t + Duration::from_secs(1), 1001.0).0.is_some(), "settling cleared the pause");
    }

    #[test]
    fn a_dial_that_never_completes_is_cancelled_at_the_ceiling() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        assert_eq!(engine.next_deadline(), Some(t + DIAL_CEILING));
        assert!(engine.expire(t + DIAL_CEILING - Duration::from_millis(1)).is_empty());
        let effects = engine.expire(t + DIAL_CEILING);
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert_eq!(scans(&effects), vec![true]);
        assert_eq!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, t + DIAL_CEILING, 1015.0).0, None, "a failed dial pauses the node");
        assert!(engine.sighted("a", 0xFFFF, &RTNODE_ADV, t + DIAL_CEILING + DIAL_FAILED_RETRY, 1020.0).0.is_some());
    }

    #[test]
    fn hello_goes_out_on_the_control_characteristic_when_the_link_is_ready() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        let effects = engine.link_ready(link, 185, t, 1000.4).unwrap();
        assert!(effects.contains(&Effect::CheckLate { label: "prns_ble.dial", sent_at_unix: 1000.0 }));
        let w = writes(&effects);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].1, Characteristic::Control);
        assert_eq!(Control::decode(&w[0].2), Some(Control::Hello(Greeting { identity: US, endpoint: Endpoint::IOS, psm: 0, link_mtu: 500, rssi: None })));
        assert!(engine.link_ready(link, 185, t, 1000.4).is_err(), "only once per link");
        assert!(engine.link_ready(99, 185, t, 1000.4).is_err(), "only a link being dialled");
    }

    #[test]
    fn a_write_too_small_for_a_fragment_fails_the_dial() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        let effects = engine.link_ready(link, 5, t, 1000.4).unwrap();
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert!(writes(&effects).is_empty());
    }

    #[test]
    fn a_welcome_registers_one_interface_named_by_the_peer() {
        let mut engine = Engine::new(US, Endpoint::ANDROID);
        let (link, effects) = settled(&mut engine, "a", Instant::now());
        assert_eq!(transport(&effects), vec![Effect::Register { name: interface_name(&NODE), link }]);
        assert!(effects.contains(&Effect::CheckLate { label: "prns_ble.handshake", sent_at_unix: 1000.5 }));
        assert!(effects.iter().any(|e| matches!(e, Effect::State { state: LinkState::Settled, peer: Some(p), .. } if *p == NODE)));
    }

    #[test]
    fn packets_are_written_one_fragment_at_a_time_in_order() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let (link, _) = settled(&mut engine, "a", Instant::now());
        let a: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let b = vec![0xBB; 10];
        let (ok, first) = engine.send_packet(link, &a, 2000.0);
        assert!(ok);
        let (ok, none) = engine.send_packet(link, &b, 2000.0);
        assert!(ok);
        assert!(writes(&none).is_empty(), "one write outstanding at a time");
        let mut sent = writes(&first);
        loop {
            let w = writes(&engine.link_write_done(link, true, 2000.1));
            if w.is_empty() {
                break;
            }
            sent.extend(w);
        }
        let expected: Vec<Vec<u8>> = wire::fragments(&a, 185).into_iter().chain(wire::fragments(&b, 185)).collect();
        assert_eq!(sent.into_iter().map(|(_, c, bytes)| { assert_eq!(c, Characteristic::Data); bytes }).collect::<Vec<_>>(), expected);
    }

    #[test]
    fn notified_fragments_become_one_inbound_packet() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let (link, _) = settled(&mut engine, "a", Instant::now());
        let packet: Vec<u8> = (0..400).map(|i| (i * 7) as u8).collect();
        let mut inbound = Vec::new();
        for fragment in wire::fragments(&packet, 244) {
            inbound.extend(transport(&engine.link_received(link, Characteristic::Data, &fragment, 2000.0)));
        }
        assert_eq!(inbound, vec![Effect::Inbound { name: interface_name(&NODE), packet }]);
    }

    #[test]
    fn data_before_welcome_is_not_delivered() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        engine.link_ready(link, 185, t, 1000.0).unwrap();
        let effects = engine.link_received(link, Characteristic::Data, &wire::fragments(&[1, 2, 3], 185)[0], 1000.1);
        assert!(transport(&effects).is_empty());
        assert!(!engine.send_packet(link, &[1, 2, 3], 1000.1).0);
    }

    #[test]
    fn a_disconnect_deregisters_the_interface_and_a_later_one_is_a_no_op() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let (link, _) = settled(&mut engine, "a", t);
        let effects = engine.link_closed(link, t);
        assert_eq!(transport(&effects), vec![Effect::Deregister { name: interface_name(&NODE) }]);
        assert!(!effects.iter().any(|e| matches!(e, Effect::Disconnect { .. })), "the OS already disconnected");
        assert!(engine.link_closed(link, t).is_empty());
        assert!(!engine.send_packet(link, &[1], 3000.0).0);
    }

    #[test]
    fn a_failed_write_ends_the_link() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let (link, _) = settled(&mut engine, "a", Instant::now());
        engine.send_packet(link, &[1, 2, 3], 2000.0);
        let effects = engine.link_write_done(link, false, 2000.1);
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert_eq!(transport(&effects), vec![Effect::Deregister { name: interface_name(&NODE) }]);
    }

    #[test]
    fn a_failed_hello_write_ends_the_handshake_without_touching_transport() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        engine.link_ready(link, 185, t, 1000.0).unwrap();
        let effects = engine.link_write_done(link, false, 1000.1);
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert!(transport(&effects).is_empty());
    }

    #[test]
    fn close_undecodable_and_unexpected_control_messages_end_the_link() {
        for message in [vec![0x03, 0x03], vec![0x02, 0x00], Control::Hello(Greeting { identity: NODE, endpoint: Endpoint::ESP32, psm: 0, link_mtu: 500, rssi: None }).encode()] {
            let mut engine = Engine::new(US, Endpoint::IOS);
            let t = Instant::now();
            let link = dial(&mut engine, "a", t);
            engine.link_ready(link, 185, t, 1000.0).unwrap();
            let effects = engine.link_received(link, Characteristic::Control, &message, 1000.1);
            assert!(effects.contains(&Effect::Disconnect { link }), "{message:02x?}");
            assert!(transport(&effects).is_empty());
        }
    }

    #[test]
    fn a_peer_with_our_identity_is_refused() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        engine.link_ready(link, 185, t, 1000.0).unwrap();
        let effects = engine.link_received(link, Characteristic::Control, &welcome(US), 1000.1);
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert!(transport(&effects).is_empty());
    }

    #[test]
    fn the_handshake_ceiling_closes_a_silent_link() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        let link = dial(&mut engine, "a", t);
        let ready_at = t + Duration::from_secs(2);
        engine.link_ready(link, 185, ready_at, 1002.0).unwrap();
        assert_eq!(engine.next_deadline(), Some(ready_at + HANDSHAKE_CEILING));
        assert!(engine.expire(ready_at + HANDSHAKE_CEILING - Duration::from_millis(1)).is_empty());
        let effects = engine.expire(ready_at + HANDSHAKE_CEILING);
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert_eq!(engine.next_deadline(), None);
    }

    #[test]
    fn a_settled_link_has_no_deadline() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        settled(&mut engine, "a", Instant::now());
        assert_eq!(engine.next_deadline(), None);
    }

    #[test]
    fn the_queue_is_bounded() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let (link, _) = settled(&mut engine, "a", Instant::now());
        // A packet counts until its last fragment has been written.
        for _ in 0..MAX_QUEUED_PACKETS {
            assert!(engine.send_packet(link, &[0u8; 400], 2000.0).0);
        }
        assert!(!engine.send_packet(link, &[0u8; 400], 2000.0).0);
        engine.link_write_done(link, true, 2000.1);
        engine.link_write_done(link, true, 2000.2);
        assert!(engine.send_packet(link, &[0u8; 400], 2000.3).0, "room again once the first packet is out");
    }

    #[test]
    fn a_packet_over_the_mtu_is_refused() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let (link, _) = settled(&mut engine, "a", Instant::now());
        assert!(!engine.send_packet(link, &[0u8; wire::HW_MTU + 1], 2000.0).0);
        assert!(engine.send_packet(link, &[0u8; wire::HW_MTU], 2000.0).0);
    }

    #[test]
    fn stopping_closes_every_link_without_asking_to_scan() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let (link, _) = settled(&mut engine, "a", Instant::now());
        let effects = engine.close_all();
        assert!(effects.contains(&Effect::Disconnect { link }));
        assert_eq!(transport(&effects), vec![Effect::Deregister { name: interface_name(&NODE) }]);
        assert!(scans(&effects).is_empty());
        assert_eq!(engine.next_deadline(), None);
    }
}
