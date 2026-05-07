> **⚠ WIP — API is unstable.** This crate is being actively refactored. App-specific
> conveniences (AppLinks, send-strategy layer) will be extracted to a higher-level crate.
> The public API will break. Not yet recommended for external use.

# Rusticulum

A Rust implementation of the [Reticulum Network Stack](https://reticulum.network/) — a cryptography-based networking protocol for building resilient, decentralized communication networks that can operate over any transport medium.

## About

Rusticulum is a from-scratch Rust port of the [Python Reticulum reference implementation](https://github.com/markqvist/Reticulum) (v1.1.3). The project aims to bring the Reticulum protocol to environments where Rust's performance, safety, and cross-compilation strengths are beneficial — embedded systems, mobile applications via FFI, and high-throughput transport nodes.

### AI-Assisted Development

This codebase was generated with significant assistance from **GitHub Copilot (Claude)**, acting as an AI pair-programming partner. The AI translated protocol logic from the Python Reticulum reference implementation into idiomatic Rust, designed the module architecture, implemented cryptographic operations, and helped debug interoperability issues during live hardware testing. All code was reviewed, tested, and validated by the human developer against the reference implementation and real Reticulum network hardware.

## Features

### Core Protocol
- **Identity** — Curve25519 keypairs (X25519 key exchange + Ed25519 signing) with 512-bit key material
- **Destination** — Single, Group, Plain, and Link destination types with configurable proof strategies
- **Packet** — Full packet type support: DATA, ANNOUNCE, LINKREQUEST, PROOF, RESOURCE transfers, KEEPALIVE, CHANNEL
- **Link** — Encrypted point-to-point links with key exchange, keepalive, and watchdog monitoring
- **Transport** — Multi-hop routing with automatic path discovery, broadcast/unicast modes, and 7-day path expiry
- **Resource** — Large data transfers with chunking, compression (bzip2), and integrity verification
- **Ratcheting** — Forward-secrecy ratchets with 30-day key rotation

### Interfaces (11 types)
| Interface | Transport | Protocol |
|-----------|-----------|----------|
| **TCPInterface** | TCP client/server | HDLC framing |
| **UDPInterface** | UDP broadcast/unicast | Raw UDP |
| **LocalInterface** | Unix domain sockets | HDLC framing |
| **AutoInterface** | Multicast auto-peering | Auto-discovery |
| **SerialInterface** | Serial ports | HDLC framing |
| **RNodeInterface** | LoRa/BLE via RNode | KISS framing |
| **KISSInterface** | KISS TNC devices | KISS protocol |
| **PipeInterface** | Unix pipes | HDLC framing |
| **BackboneInterface** | Multi-hop backbone links | Custom |
| **I2PInterface** | I2P anonymity network | SAM protocol |

### Cross-Language Support
- **FFI module** — Handle-based C-compatible registry for integration with C, JNI (Android), and other languages
- Thread-safe global object store with opaque `u64` handles

## Building

```bash
# Default build (includes serial/BLE/RNode support)
cargo build --release

# Without serial features (no serialport/BLE dependencies)
cargo build --release --no-default-features
```

### Dependencies

Requires Rust 2021 edition. Key dependencies:
- **Cryptography**: x25519-dalek, ed25519-dalek, aes, hkdf, hmac, sha2
- **Serialization**: rmp-serde (MessagePack, wire-compatible with Python implementation)
- **Async runtime**: Tokio (multi-threaded)
- **Serial** (optional): serialport, btleplug (Bluetooth LE)

## Testing

### Python Oracle Tests

Cross-language validation tests in `tests/python_oracle.rs` verify that Rust output matches the Python Reticulum reference implementation byte-for-byte. These tests use PyO3 to call the Python RNS library and compare results:

```bash
cargo test  # Requires Python with RNS installed
```

Validated functions include: `hexrep`, `prettyhexrep`, `prettysize`, `prettytime`, `prettyshorttime`, `prettyfrequency`, `prettydistance`.

### Integration Testing with Real Hardware

Rusticulum has been tested extensively in live network configurations with real Reticulum hardware:

- **RNode boundary nodes** (Heltec V4, GAT562) — LoRa mesh communication with KISS framing over serial and BLE
- **TCP transport** — LAN and WAN link establishment, path discovery, and resource transfer between Rust and Python nodes
- **LXMF messaging** — End-to-end encrypted message delivery using the companion [LXMF-rust](https://github.com/jrl290/LXMF-rust) implementation
- **Resource transfer** — Large file transfers (multi-packet) with compression over linked connections
- **Python interoperability** — Rust nodes communicating bidirectionally with Python Reticulum nodes (rnsd) and Sideband mobile clients

### Test Harnesses

Dedicated test harnesses (in the development workspace) cover:

- **RTNode-HeltecV4-Resource** — Large file transfer testing with compression and encryption over RNode links
- **RTNode-HeltecV4-TCPSimple** — TCP-based link and resource testing across LAN/WAN topologies
- **CLI test scripts** — Automated sender/receiver pairs for v3 boundary nodes, LXMF messaging, RNS daemon client configurations, and property-based testing

## Project Structure

```
src/
├── lib.rs              # Core library: logging, constants, utilities
├── identity.rs         # Cryptographic identity (Curve25519)
├── destination.rs      # Network destinations and proof strategies
├── packet.rs           # Packet types and wire format
├── link.rs             # Encrypted point-to-point links
├── transport.rs        # Routing engine and path discovery
├── resource.rs         # Large data transfer protocol
├── reticulum.rs        # Core manager and configuration
├── discovery.rs        # Announcement handling
├── channel.rs          # Channel protocol support
├── buffer.rs           # Buffer management
├── config.rs           # INI-style configuration parser
├── resolver.rs         # Identity name resolution
├── lxstamper.rs        # Timestamp utilities
├── ffi.rs              # C/JNI FFI bindings
├── version.rs          # Version constant (1.1.3)
└── interfaces/
    ├── mod.rs
    ├── interface.rs        # Interface trait and common types
    ├── tcp_interface.rs
    ├── udp_interface.rs
    ├── local_interface.rs
    ├── auto_interface.rs
    ├── serial_interface.rs
    ├── rnode_interface.rs
    ├── kiss_interface.rs
    ├── pipe_interface.rs
    ├── backbone_interface.rs
    └── i2p/                # I2P anonymity network support
```

## Status

**Active development.** The core protocol is implemented and has been validated against the Python reference in real network scenarios. Current areas of work include:

- Resolver (identity-by-name lookup) — stub implementation
- Continued interoperability testing with Python Reticulum ecosystem
- Performance optimization for embedded targets

## Related Projects

- [Reticulum](https://github.com/markqvist/Reticulum) — The original Python reference implementation this project is based on
- [LXMF-rust](https://github.com/jrl290/LXMF-rust) — Rust implementation of the LXMF messaging protocol, built on Rusticulum
- [microReticulum](https://github.com/attermann/microReticulum) — C++ Reticulum implementation for microcontrollers

## License

This project is provided under the same spirit as the Reticulum ecosystem. See [LICENSE](LICENSE) for details.

## Acknowledgments

- **Mark Qvist** — Creator of the [Reticulum Network Stack](https://reticulum.network/) and the Python reference implementation
- **GitHub Copilot (Claude, Anthropic)** — AI pair-programming assistant that helped generate and debug the Rust implementation
- **attermann** — Author of [microReticulum](https://github.com/attermann/microReticulum), the C++ implementation that informed embedded testing strategies
