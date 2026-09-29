//! The Prns native Bluetooth LE wire format, dialer (GATT central) side.
//!
//! Ported from Prns 0.3.7 (`prns-core/src/interfaces/bluetooth_auto/`:
//! `advertisement.rs`, `framing.rs`, `handshake.rs`, `identity.rs`),
//! Copyright (c) 2026 The Prns Authors, MIT OR Apache-2.0. Prns has no
//! written spec; that code is the spec, and RTNode's `BleInterface.h`
//! implements the same bytes on the listener side.

/// Primary service. Every characteristic is this UUID with the last byte
/// changed.
pub const SERVICE_UUID: &str = "37145b00-442d-4a94-917f-8f42c5da28e3";
/// Handshake PDUs: the dialer writes Hello, the listener notifies Welcome.
pub const CONTROL_UUID: &str = "37145b00-442d-4a94-917f-8f42c5da28e7";
/// Packet fragments: the dialer writes, the listener notifies.
pub const DATA_UUID: &str = "37145b00-442d-4a94-917f-8f42c5da28e8";

/// Largest Reticulum packet carried (Prns `BLE_HW_MTU`, RNS MTU).
pub const HW_MTU: usize = 500;
/// `[kind][seq u16 BE][total u16 BE]`
pub const FRAGMENT_HEADER_LEN: usize = 5;
/// Hello and Welcome: tag, 16-byte identity, 2-byte endpoint, PSM,
/// link MTU (u16 BE), RSSI.
pub const GREETING_LEN: usize = 23;
pub const IDENTITY_LEN: usize = 16;

const CONTROL_HELLO: u8 = 0x01;
const CONTROL_WELCOME: u8 = 0x02;
const CONTROL_CLOSE: u8 = 0x03;
const RSSI_UNKNOWN: u8 = 0x80;

const FRAGMENT_START: u8 = 0x01;
const FRAGMENT_CONTINUE: u8 = 0x02;
const FRAGMENT_END: u8 = 0x03;

const ROLE_COMPANY_ID: u16 = 0xFFFF;
const ROLE_VERSION: u8 = 0x03;
const ROLE_PERIPHERAL_ONLY: u8 = 0x01;

/// Whether an advertisement's manufacturer data says "peripheral only".
/// `company_id` is the manufacturer-data company identifier and `data` what
/// follows it: Android's `ScanRecord.getManufacturerSpecificData(0xFFFF)`,
/// or CoreBluetooth's `kCBAdvDataManufacturerData` minus its first two bytes.
///
/// RTNode advertises `FF FF 03 01`. Prns daemons and phone apps are
/// dual-role (`03 00`), and Apple hosts cannot advertise manufacturer data at
/// all, so this is how a Retichat phone tells an RTNode from everything else.
pub fn is_peripheral_only(company_id: u16, data: &[u8]) -> bool {
    company_id == ROLE_COMPANY_ID
        && data.first().is_some_and(|version| *version >= ROLE_VERSION)
        && data.get(1).is_some_and(|flags| flags & ROLE_PERIPHERAL_ONLY != 0)
}

/// The sender's Bluetooth stack and host, bytes [17..19] of a greeting.
/// A greeting naming an endpoint Prns does not know is undecodable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub stack: u8,
    pub host: u8,
}

impl Endpoint {
    pub const MACOS: Endpoint = Endpoint { stack: 1, host: 0 };
    pub const IOS: Endpoint = Endpoint { stack: 1, host: 1 };
    pub const IPADOS: Endpoint = Endpoint { stack: 1, host: 2 };
    pub const LINUX: Endpoint = Endpoint { stack: 2, host: 0 };
    pub const ANDROID: Endpoint = Endpoint { stack: 3, host: 0 };
    pub const WINDOWS: Endpoint = Endpoint { stack: 4, host: 0 };
    pub const ESP32: Endpoint = Endpoint { stack: 5, host: 0 };
    pub const NRF52: Endpoint = Endpoint { stack: 6, host: 0 };

    pub fn new(stack: u8, host: u8) -> Option<Endpoint> {
        let known = match stack {
            1 => host <= 2,
            2..=6 => host == 0,
            _ => false,
        };
        known.then_some(Endpoint { stack, host })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Greeting {
    pub identity: [u8; IDENTITY_LEN],
    pub endpoint: Endpoint,
    /// L2CAP PSM low byte; 0 = none. This side never offers one, so a peer
    /// never tries to move the link off GATT.
    pub psm: u8,
    pub link_mtu: u16,
    pub rssi: Option<i8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    SelfConnection,
    DuplicateLink,
    Incompatible,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Hello(Greeting),
    Welcome(Greeting),
    Close(CloseReason),
}

impl Control {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Control::Hello(greeting) => encode_greeting(CONTROL_HELLO, greeting),
            Control::Welcome(greeting) => encode_greeting(CONTROL_WELCOME, greeting),
            Control::Close(reason) => vec![
                CONTROL_CLOSE,
                match reason {
                    CloseReason::SelfConnection => 0x01,
                    CloseReason::DuplicateLink => 0x02,
                    CloseReason::Incompatible => 0x03,
                },
            ],
        }
    }

    /// Prns rules: a greeting of 22 bytes (no RSSI) decodes, trailing bytes
    /// are ignored, and an unknown endpoint or a PSM byte in 0x01..=0x7F
    /// (outside the LE dynamic range) makes the whole PDU undecodable.
    pub fn decode(bytes: &[u8]) -> Option<Control> {
        let (tag, body) = bytes.split_first()?;
        match *tag {
            CONTROL_HELLO => decode_greeting(body).map(Control::Hello),
            CONTROL_WELCOME => decode_greeting(body).map(Control::Welcome),
            CONTROL_CLOSE => Some(Control::Close(match *body.first()? {
                0x01 => CloseReason::SelfConnection,
                0x02 => CloseReason::DuplicateLink,
                0x03 => CloseReason::Incompatible,
                _ => return None,
            })),
            _ => None,
        }
    }
}

fn encode_greeting(tag: u8, greeting: &Greeting) -> Vec<u8> {
    let mut out = Vec::with_capacity(GREETING_LEN);
    out.push(tag);
    out.extend_from_slice(&greeting.identity);
    out.push(greeting.endpoint.stack);
    out.push(greeting.endpoint.host);
    out.push(greeting.psm);
    out.extend_from_slice(&greeting.link_mtu.to_be_bytes());
    out.push(match greeting.rssi {
        Some(dbm) if dbm != i8::MIN => dbm as u8,
        _ => RSSI_UNKNOWN,
    });
    out
}

fn decode_greeting(body: &[u8]) -> Option<Greeting> {
    let identity: [u8; IDENTITY_LEN] = body.get(..IDENTITY_LEN)?.try_into().ok()?;
    let endpoint = Endpoint::new(*body.get(16)?, *body.get(17)?)?;
    let psm = *body.get(18)?;
    if psm != 0 && psm < 0x80 {
        return None;
    }
    let link_mtu = u16::from_be_bytes(body.get(19..21)?.try_into().ok()?);
    let rssi = body.get(21).map(|b| *b as i8).filter(|dbm| *dbm != i8::MIN);
    Some(Greeting { identity, endpoint, psm, link_mtu, rssi })
}

/// Splits one packet into fragments of at most `fragment_size` bytes, header
/// included. The first fragment is a Start even when it is also the last.
pub fn fragments(packet: &[u8], fragment_size: usize) -> Vec<Vec<u8>> {
    let cap = fragment_size.saturating_sub(FRAGMENT_HEADER_LEN).max(1);
    let total = packet.len().div_ceil(cap).max(1);
    let mut out = Vec::with_capacity(total);
    for index in 0..total {
        let chunk = &packet[(index * cap).min(packet.len())..((index + 1) * cap).min(packet.len())];
        let kind = if index == 0 {
            FRAGMENT_START
        } else if index + 1 == total {
            FRAGMENT_END
        } else {
            FRAGMENT_CONTINUE
        };
        let mut fragment = Vec::with_capacity(FRAGMENT_HEADER_LEN + chunk.len());
        fragment.push(kind);
        fragment.extend_from_slice(&(index as u16).to_be_bytes());
        fragment.extend_from_slice(&(total as u16).to_be_bytes());
        fragment.extend_from_slice(chunk);
        out.push(fragment);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub seq: u16,
    pub total: u16,
    pub data: &'a [u8],
}

pub fn decode_fragment(bytes: &[u8]) -> Option<Fragment<'_>> {
    match *bytes.first()? {
        FRAGMENT_START | FRAGMENT_CONTINUE | FRAGMENT_END => {}
        _ => return None,
    }
    let seq = u16::from_be_bytes(bytes.get(1..3)?.try_into().ok()?);
    let total = u16::from_be_bytes(bytes.get(3..5)?.try_into().ok()?);
    Some(Fragment { seq, total, data: bytes.get(FRAGMENT_HEADER_LEN..)? })
}

/// Prns reassembly: seq 0 always starts a new packet; any gap, change of
/// total, or packet over `HW_MTU` abandons the one in progress.
#[derive(Debug, Default)]
pub struct Reassembler {
    buf: Vec<u8>,
    next_seq: u16,
    total: u16,
    active: bool,
}

impl Reassembler {
    pub fn absorb(&mut self, fragment: &Fragment<'_>) -> Result<Option<Vec<u8>>, &'static str> {
        if fragment.seq == 0 {
            self.buf.clear();
            self.total = fragment.total;
            self.next_seq = 0;
            self.active = true;
        }
        if !self.active {
            return Err("fragment without a start");
        }
        if fragment.seq != self.next_seq || fragment.total != self.total {
            self.active = false;
            return Err("fragment out of sequence");
        }
        if self.buf.len() + fragment.data.len() > HW_MTU {
            self.active = false;
            return Err("packet larger than the hardware MTU");
        }
        self.buf.extend_from_slice(fragment.data);
        self.next_seq += 1;
        if self.next_seq == self.total {
            self.active = false;
            return Ok(Some(std::mem::take(&mut self.buf)));
        }
        Ok(None)
    }
}

/// The persisted identity record Prns writes to `<storage>/ble_identity`:
/// `"PRNSBLE1"`, the identity, then its bitwise complement.
pub const IDENTITY_RECORD_LEN: usize = 40;
const IDENTITY_RECORD_MAGIC: &[u8; 8] = b"PRNSBLE1";

pub fn encode_identity_record(identity: &[u8; IDENTITY_LEN]) -> [u8; IDENTITY_RECORD_LEN] {
    let mut record = [0u8; IDENTITY_RECORD_LEN];
    record[..8].copy_from_slice(IDENTITY_RECORD_MAGIC);
    record[8..24].copy_from_slice(identity);
    for (out, byte) in record[24..].iter_mut().zip(identity) {
        *out = !byte;
    }
    record
}

pub fn decode_identity_record(record: &[u8]) -> Result<[u8; IDENTITY_LEN], &'static str> {
    if record.len() != IDENTITY_RECORD_LEN {
        return Err("wrong length");
    }
    if &record[..8] != IDENTITY_RECORD_MAGIC {
        return Err("bad magic");
    }
    let mut identity = [0u8; IDENTITY_LEN];
    identity.copy_from_slice(&record[8..24]);
    if record[24..].iter().zip(identity).any(|(stored, byte)| *stored != !byte) {
        return Err("integrity check failed");
    }
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> [u8; IDENTITY_LEN] {
        core::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    /// The Welcome RTNode sends (BleInterface.h on_control): its identity,
    /// endpoint ESP32, no PSM, link MTU 500, RSSI unknown.
    fn rtnode_welcome(id: &[u8; IDENTITY_LEN]) -> Vec<u8> {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&[0x05, 0x00, 0x00, 0x01, 0xF4, 0x80]);
        bytes
    }

    #[test]
    fn a_hello_is_the_23_bytes_rtnode_requires() {
        let hello = Control::Hello(Greeting {
            identity: identity(0x10),
            endpoint: Endpoint::IOS,
            psm: 0,
            link_mtu: 500,
            rssi: None,
        })
        .encode();
        let mut expected = vec![0x01];
        expected.extend_from_slice(&identity(0x10));
        expected.extend_from_slice(&[0x01, 0x01, 0x00, 0x01, 0xF4, 0x80]);
        assert_eq!(hello, expected);
        assert_eq!(hello.len(), GREETING_LEN);
    }

    #[test]
    fn rtnodes_welcome_decodes() {
        let id = identity(0xA0);
        assert_eq!(
            Control::decode(&rtnode_welcome(&id)),
            Some(Control::Welcome(Greeting {
                identity: id,
                endpoint: Endpoint::ESP32,
                psm: 0,
                link_mtu: 500,
                rssi: None,
            }))
        );
    }

    #[test]
    fn a_greeting_without_rssi_decodes_and_trailing_bytes_are_ignored() {
        let id = identity(3);
        let welcome = rtnode_welcome(&id);
        assert!(matches!(Control::decode(&welcome[..22]), Some(Control::Welcome(_))));
        let mut longer = welcome.clone();
        longer.extend_from_slice(&[9, 9, 9]);
        assert_eq!(Control::decode(&longer), Control::decode(&welcome));
    }

    #[test]
    fn an_unknown_endpoint_or_a_psm_below_the_dynamic_range_is_undecodable() {
        let mut welcome = rtnode_welcome(&identity(1));
        welcome[17] = 7;
        assert_eq!(Control::decode(&welcome), None);
        let mut welcome = rtnode_welcome(&identity(1));
        welcome[18] = 1;
        assert_eq!(Control::decode(&welcome), None);
        let mut welcome = rtnode_welcome(&identity(1));
        welcome[19] = 0x7F;
        assert_eq!(Control::decode(&welcome), None);
        welcome[19] = 0x83;
        assert!(matches!(Control::decode(&welcome), Some(Control::Welcome(g)) if g.psm == 0x83));
    }

    #[test]
    fn close_round_trips() {
        for reason in [CloseReason::SelfConnection, CloseReason::DuplicateLink, CloseReason::Incompatible] {
            assert_eq!(Control::decode(&Control::Close(reason).encode()), Some(Control::Close(reason)));
        }
        assert_eq!(Control::decode(&[0x03, 0x04]), None);
        assert_eq!(Control::decode(&[0x03]), None);
    }

    #[test]
    fn only_a_peripheral_only_role_field_is_an_rtnode() {
        assert!(is_peripheral_only(0xFFFF, &[0x03, 0x01]));
        assert!(is_peripheral_only(0xFFFF, &[0x04, 0x03]));
        assert!(!is_peripheral_only(0xFFFF, &[0x03, 0x00]), "dual-role (Prns, phones)");
        assert!(!is_peripheral_only(0xFFFF, &[0x02, 0x01]), "role version too old");
        assert!(!is_peripheral_only(0x004C, &[0x03, 0x01]), "another company's data");
        assert!(!is_peripheral_only(0xFFFF, &[0x03]));
    }

    #[test]
    fn a_small_packet_is_one_start_fragment() {
        let out = fragments(&[1, 2, 3], 64);
        assert_eq!(out, vec![vec![0x01, 0x00, 0x00, 0x00, 0x01, 1, 2, 3]]);
    }

    #[test]
    fn fragments_are_start_continue_end_with_big_endian_counters() {
        let packet: Vec<u8> = (0..12).collect();
        let out = fragments(&packet, FRAGMENT_HEADER_LEN + 5);
        assert_eq!(
            out,
            vec![
                vec![0x01, 0, 0, 0, 3, 0, 1, 2, 3, 4],
                vec![0x02, 0, 1, 0, 3, 5, 6, 7, 8, 9],
                vec![0x03, 0, 2, 0, 3, 10, 11],
            ]
        );
    }

    #[test]
    fn a_full_size_packet_round_trips() {
        let packet: Vec<u8> = (0..HW_MTU).map(|i| i as u8).collect();
        for size in [20, 64, 180, 244, 505, 512] {
            let mut reassembler = Reassembler::default();
            let mut done = None;
            for fragment in fragments(&packet, size) {
                assert!(fragment.len() <= size);
                if let Some(p) = reassembler.absorb(&decode_fragment(&fragment).unwrap()).unwrap() {
                    done = Some(p);
                }
            }
            assert_eq!(done.as_deref(), Some(&packet[..]), "fragment size {size}");
        }
    }

    #[test]
    fn a_gap_abandons_the_packet_and_a_new_start_recovers() {
        let packet: Vec<u8> = (0..30).collect();
        let parts = fragments(&packet, 15);
        let mut reassembler = Reassembler::default();
        assert_eq!(reassembler.absorb(&decode_fragment(&parts[0]).unwrap()), Ok(None));
        assert!(reassembler.absorb(&decode_fragment(&parts[2]).unwrap()).is_err());
        assert!(reassembler.absorb(&decode_fragment(&parts[1]).unwrap()).is_err(), "abandoned");
        let mut done = None;
        for part in &parts {
            if let Some(p) = reassembler.absorb(&decode_fragment(part).unwrap()).unwrap() {
                done = Some(p);
            }
        }
        assert_eq!(done, Some(packet));
    }

    #[test]
    fn a_packet_over_the_hardware_mtu_is_refused() {
        let packet = vec![7u8; HW_MTU + 1];
        let mut reassembler = Reassembler::default();
        let mut refused = false;
        for fragment in fragments(&packet, 180) {
            if reassembler.absorb(&decode_fragment(&fragment).unwrap()).is_err() {
                refused = true;
            }
        }
        assert!(refused);
    }

    #[test]
    fn the_identity_record_matches_prns() {
        let id = identity(0x55);
        let record = encode_identity_record(&id);
        assert_eq!(&record[..8], b"PRNSBLE1");
        assert_eq!(decode_identity_record(&record), Ok(id));
        let mut damaged = record;
        damaged[30] ^= 1;
        assert!(decode_identity_record(&damaged).is_err());
        assert!(decode_identity_record(&record[..39]).is_err());
    }
}
