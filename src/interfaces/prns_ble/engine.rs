//! The dialer's side of the Prns native protocol as a pure state machine.
//!
//! No radio, no threads, no globals: every host event returns the effects it
//! causes, and `runtime.rs` carries them out. That keeps the protocol
//! testable without Bluetooth.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use super::wire::{self, Control, Endpoint, Greeting, IDENTITY_LEN};

/// Hello to Welcome. The Prns protocol constant (prns tokio runtime, both
/// sides); a hard ceiling for a peer that never answers, not a fix for a
/// slow one (DESIGN_PRINCIPLES §4). The 5-second rule still applies inside it.
pub const HANDSHAKE_CEILING: Duration = Duration::from_secs(10);

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
}

#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Host: write `bytes` to the characteristic, with response, and report
    /// the result through `link_write_done`.
    Write { link: u64, characteristic: Characteristic, bytes: Vec<u8> },
    /// Host: cancel the connection. It need not report `link_closed` after.
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
}

impl Engine {
    pub fn new(identity: [u8; IDENTITY_LEN], endpoint: Endpoint) -> Self {
        Engine { identity, endpoint, links: HashMap::new() }
    }

    pub fn identity(&self) -> [u8; IDENTITY_LEN] {
        self.identity
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
        if self.links.contains_key(&link) {
            return Err(format!("link {link} is already open"));
        }
        let fragment_size = max_write_len.min(MAX_FRAGMENT);
        if fragment_size <= wire::FRAGMENT_HEADER_LEN {
            return Err(format!("link {link}: a write of {max_write_len} bytes cannot carry a fragment"));
        }
        let hello = Control::Hello(Greeting {
            identity: self.identity,
            endpoint: self.endpoint,
            psm: 0,
            link_mtu: wire::HW_MTU as u16,
            rssi: None,
        })
        .encode();
        self.links.insert(
            link,
            Link {
                fragment_size,
                phase: Phase::Handshaking { hello_sent_at_unix: now_unix, deadline: now + HANDSHAKE_CEILING },
                tx: VecDeque::new(),
                in_flight: Some(InFlight { sent_at_unix: now_unix, handshake: true }),
                reassembler: wire::Reassembler::default(),
                bad_fragments: 0,
            },
        );
        Ok(vec![
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

    /// The host reports the connection gone (the OS disconnect callback).
    pub fn link_closed(&mut self, link: u64) -> Vec<Effect> {
        if self.links.contains_key(&link) {
            self.close(link, "disconnected", false)
        } else {
            Vec::new()
        }
    }

    /// Handshakes whose ceiling has passed.
    pub fn expire(&mut self, now: Instant) -> Vec<Effect> {
        let expired: Vec<u64> = self
            .links
            .iter()
            .filter(|(_, l)| matches!(l.phase, Phase::Handshaking { deadline, .. } if deadline <= now))
            .map(|(id, _)| *id)
            .collect();
        let mut effects = Vec::new();
        for link in expired {
            effects.extend(self.close(link, &format!("no Welcome within {} s", HANDSHAKE_CEILING.as_secs()), true));
        }
        effects
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.links
            .values()
            .filter_map(|l| match l.phase {
                Phase::Handshaking { deadline, .. } => Some(deadline),
                Phase::Settled { .. } => None,
            })
            .min()
    }

    /// Close every link (the stack is stopping).
    pub fn close_all(&mut self) -> Vec<Effect> {
        let ids: Vec<u64> = self.links.keys().copied().collect();
        let mut effects = Vec::new();
        for link in ids {
            effects.extend(self.close(link, "Bluetooth stopped", true));
        }
        effects
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
            Phase::Handshaking { .. } => (None, None),
        };
        if disconnect {
            effects.push(Effect::Disconnect { link });
        }
        effects.push(Effect::State { link, state: LinkState::Closed, peer, interface });
        effects.push(Effect::Log { level: crate::LOG_NOTICE, message: format!("link {link}: closed, {why}") });
        effects
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

    fn settled(engine: &mut Engine, link: u64, t: Instant) -> Vec<Effect> {
        engine.link_ready(link, 185, t, 1000.0).unwrap();
        engine.link_write_done(link, true, 1000.1);
        engine.link_received(link, Characteristic::Control, &welcome(NODE), 1000.2)
    }

    #[test]
    fn hello_goes_out_on_the_control_characteristic_when_the_link_is_ready() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let effects = engine.link_ready(7, 185, Instant::now(), 1000.0).unwrap();
        let w = writes(&effects);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].1, Characteristic::Control);
        assert_eq!(Control::decode(&w[0].2), Some(Control::Hello(Greeting { identity: US, endpoint: Endpoint::IOS, psm: 0, link_mtu: 500, rssi: None })));
        assert!(engine.link_ready(7, 185, Instant::now(), 1000.0).is_err(), "one link per id");
        assert!(engine.link_ready(8, 5, Instant::now(), 1000.0).is_err(), "a write must carry a fragment");
    }

    #[test]
    fn a_welcome_registers_one_interface_named_by_the_peer() {
        let mut engine = Engine::new(US, Endpoint::ANDROID);
        let effects = settled(&mut engine, 7, Instant::now());
        assert_eq!(transport(&effects), vec![Effect::Register { name: interface_name(&NODE), link: 7 }]);
        assert!(effects.contains(&Effect::CheckLate { label: "prns_ble.handshake", sent_at_unix: 1000.0 }));
        assert!(effects.iter().any(|e| matches!(e, Effect::State { link: 7, state: LinkState::Settled, peer: Some(p), .. } if *p == NODE)));
    }

    #[test]
    fn packets_are_written_one_fragment_at_a_time_in_order() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        settled(&mut engine, 7, Instant::now());
        let a: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let b = vec![0xBB; 10];
        let (ok, first) = engine.send_packet(7, &a, 2000.0);
        assert!(ok);
        let (ok, none) = engine.send_packet(7, &b, 2000.0);
        assert!(ok);
        assert!(writes(&none).is_empty(), "one write outstanding at a time");
        let mut sent = writes(&first);
        loop {
            let next = engine.link_write_done(7, true, 2000.1);
            let w = writes(&next);
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
        settled(&mut engine, 7, Instant::now());
        let packet: Vec<u8> = (0..400).map(|i| (i * 7) as u8).collect();
        let mut inbound = Vec::new();
        for fragment in wire::fragments(&packet, 244) {
            inbound.extend(transport(&engine.link_received(7, Characteristic::Data, &fragment, 2000.0)));
        }
        assert_eq!(inbound, vec![Effect::Inbound { name: interface_name(&NODE), packet }]);
    }

    #[test]
    fn data_before_welcome_is_not_delivered() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        engine.link_ready(7, 185, Instant::now(), 1000.0).unwrap();
        let effects = engine.link_received(7, Characteristic::Data, &wire::fragments(&[1, 2, 3], 185)[0], 1000.1);
        assert!(transport(&effects).is_empty());
        let (ok, _) = engine.send_packet(7, &[1, 2, 3], 1000.1);
        assert!(!ok);
    }

    #[test]
    fn a_disconnect_deregisters_the_interface_and_a_later_one_is_a_no_op() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        settled(&mut engine, 7, Instant::now());
        let effects = engine.link_closed(7);
        assert_eq!(transport(&effects), vec![Effect::Deregister { name: interface_name(&NODE) }]);
        assert!(!effects.iter().any(|e| matches!(e, Effect::Disconnect { .. })), "the OS already disconnected");
        assert!(engine.link_closed(7).is_empty());
        assert!(!engine.send_packet(7, &[1], 3000.0).0);
    }

    #[test]
    fn a_failed_write_ends_the_link() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        settled(&mut engine, 7, Instant::now());
        let (_, _) = engine.send_packet(7, &[1, 2, 3], 2000.0);
        let effects = engine.link_write_done(7, false, 2000.1);
        assert!(effects.contains(&Effect::Disconnect { link: 7 }));
        assert_eq!(transport(&effects), vec![Effect::Deregister { name: interface_name(&NODE) }]);
    }

    #[test]
    fn a_failed_hello_write_ends_the_handshake_without_touching_transport() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        engine.link_ready(7, 185, Instant::now(), 1000.0).unwrap();
        let effects = engine.link_write_done(7, false, 1000.1);
        assert!(effects.contains(&Effect::Disconnect { link: 7 }));
        assert!(transport(&effects).is_empty());
    }

    #[test]
    fn close_undecodable_and_unexpected_control_messages_end_the_link() {
        for message in [vec![0x03, 0x03], vec![0x02, 0x00], wire::Control::Hello(Greeting { identity: NODE, endpoint: Endpoint::ESP32, psm: 0, link_mtu: 500, rssi: None }).encode()] {
            let mut engine = Engine::new(US, Endpoint::IOS);
            engine.link_ready(7, 185, Instant::now(), 1000.0).unwrap();
            let effects = engine.link_received(7, Characteristic::Control, &message, 1000.1);
            assert!(effects.contains(&Effect::Disconnect { link: 7 }), "{message:02x?}");
            assert!(transport(&effects).is_empty());
        }
    }

    #[test]
    fn a_peer_with_our_identity_is_refused() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        engine.link_ready(7, 185, Instant::now(), 1000.0).unwrap();
        let effects = engine.link_received(7, Characteristic::Control, &welcome(US), 1000.1);
        assert!(effects.contains(&Effect::Disconnect { link: 7 }));
        assert!(transport(&effects).is_empty());
    }

    #[test]
    fn the_handshake_ceiling_closes_a_silent_link_and_only_that_one() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        engine.link_ready(7, 185, t, 1000.0).unwrap();
        engine.link_ready(8, 185, t + Duration::from_secs(5), 1005.0).unwrap();
        assert_eq!(engine.next_deadline(), Some(t + HANDSHAKE_CEILING));
        assert!(engine.expire(t + HANDSHAKE_CEILING - Duration::from_millis(1)).is_empty());
        let effects = engine.expire(t + HANDSHAKE_CEILING);
        assert!(effects.contains(&Effect::Disconnect { link: 7 }));
        assert!(!effects.contains(&Effect::Disconnect { link: 8 }));
        assert_eq!(engine.next_deadline(), Some(t + Duration::from_secs(5) + HANDSHAKE_CEILING));
        engine.link_received(8, Characteristic::Control, &welcome(NODE), 1006.0);
        assert_eq!(engine.next_deadline(), None, "a settled link has no deadline");
    }

    #[test]
    fn a_reconnect_before_the_old_link_is_reported_gone_hands_the_interface_over() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        settled(&mut engine, 7, t);
        engine.link_ready(9, 185, t, 1001.0).unwrap();
        let effects = engine.link_received(9, Characteristic::Control, &welcome(NODE), 1001.1);
        assert_eq!(transport(&effects), vec![Effect::HandOver { name: interface_name(&NODE), link: 9 }]);
        assert!(effects.contains(&Effect::Disconnect { link: 7 }));
        assert!(engine.link_closed(7).is_empty(), "the old link's late disconnect must not deregister the interface");
        assert!(engine.send_packet(9, &[1, 2, 3], 1002.0).0);
    }

    #[test]
    fn the_queue_is_bounded() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        settled(&mut engine, 7, Instant::now());
        // A packet counts until its last fragment has been written.
        for _ in 0..MAX_QUEUED_PACKETS {
            assert!(engine.send_packet(7, &[0u8; 400], 2000.0).0);
        }
        assert!(!engine.send_packet(7, &[0u8; 400], 2000.0).0);
        engine.link_write_done(7, true, 2000.1);
        engine.link_write_done(7, true, 2000.2);
        assert!(engine.send_packet(7, &[0u8; 400], 2000.3).0, "room again once the first packet is out");
    }

    #[test]
    fn a_packet_over_the_mtu_is_refused() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        settled(&mut engine, 7, Instant::now());
        assert!(!engine.send_packet(7, &[0u8; wire::HW_MTU + 1], 2000.0).0);
        assert!(engine.send_packet(7, &[0u8; wire::HW_MTU], 2000.0).0);
    }

    #[test]
    fn stopping_closes_every_link() {
        let mut engine = Engine::new(US, Endpoint::IOS);
        let t = Instant::now();
        settled(&mut engine, 7, t);
        engine.link_ready(8, 185, t, 1000.0).unwrap();
        let effects = engine.close_all();
        assert!(effects.contains(&Effect::Disconnect { link: 7 }));
        assert!(effects.contains(&Effect::Disconnect { link: 8 }));
        assert_eq!(transport(&effects), vec![Effect::Deregister { name: interface_name(&NODE) }]);
        assert_eq!(engine.next_deadline(), None);
    }
}
