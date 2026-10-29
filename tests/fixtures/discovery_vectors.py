#!/usr/bin/env python3
# Writes discovery_vectors.json: interface discovery announces built and
# decoded by RNS's own Discovery.py, for the tests in src/discovery.rs.
#
#   <venv>/bin/python discovery_vectors.py > discovery_vectors.json
#
# The venv needs rns 1.5.2 and lxmf. Stamps are found by random search, so a
# new run gives different bytes for the same checks.

import json
import os
import sys
import tempfile

import RNS
import RNS.Discovery as D
from RNS.vendor import umsgpack as msgpack
from LXMF import LXStamper

STAMP_COST = D.InterfaceAnnouncer.DEFAULT_STAMP_VALUE
EXPAND_ROUNDS = D.InterfaceAnnouncer.WORKBLOCK_EXPAND_ROUNDS


def plain(value):
    if isinstance(value, (bytes, bytearray)): return {"hex": bytes(value).hex()}
    if isinstance(value, dict): return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)): return [plain(v) for v in value]
    return value


def checked(test, value):
    # None where the reference raises; the handler then drops the announce.
    try: return bool(test(value))
    except Exception: return None


def stamped(info, cost=STAMP_COST, below=None):
    # Stamp the packed info as InterfaceAnnouncer does. With `below`, search
    # for a stamp that is valid for `cost` but worth less than `below`.
    packed = msgpack.packb(info)
    infohash = RNS.Identity.full_hash(packed)
    while True:
        stamp, value = LXStamper.generate_stamp(infohash, stamp_cost=cost, expand_rounds=EXPAND_ROUNDS)
        if below is None or value < below: return packed, stamp, value


def base_info(transport_id, interface_type, name, fields):
    info = {D.INTERFACE_TYPE: interface_type,
            D.TRANSPORT:      True,
            D.TRANSPORT_ID:   transport_id,
            D.TRANSPORT_IMPL: D.IMPLEMENTATION_NAME,
            D.TRANSPORT_VERS: D.RNS_VERSION,
            D.NAME:           name,
            D.LATITUDE:       None,
            D.LONGITUDE:      None,
            D.HEIGHT:         None}
    info.update(fields)
    return info


def main():
    configdir = tempfile.mkdtemp(prefix="discovery-vectors-")
    with open(os.path.join(configdir, "config"), "w") as f:
        f.write("[reticulum]\n  enable_transport = No\n  share_instance = No\n\n"
                "[logging]\n  loglevel = 1\n\n[interfaces]\n")
    RNS.Reticulum(configdir=configdir, loglevel=RNS.LOG_CRITICAL)

    network_identity = RNS.Identity()
    transport_id = RNS.Identity.truncated_hash(b"discovery vectors transport identity")
    destination_hash = RNS.Destination.hash(network_identity, D.APP_NAME, "discovery", "interface")

    cases = [
        ("backbone_hostname", base_info(transport_id, "BackboneInterface", "Example Backbone 1",
            {D.REACHABLE_ON: "rns.example.org", D.PORT: 4242,
               D.LATITUDE: 52.5, D.LONGITUDE: 13.4, D.HEIGHT: 34.0}), {}),
        ("tcpserver_ipv4_ifac", base_info(transport_id, "TCPServerInterface", "  zer0bitz  ",
            {D.TRANSPORT: False, D.REACHABLE_ON: "203.0.113.7", D.PORT: 4965,
               D.IFAC_NETNAME: "testnet", D.IFAC_NETKEY: "secret phrase"}), {}),
        ("backbone_ipv6_operator", base_info(transport_id, "BackboneInterface", "RMAP World",
            {D.REACHABLE_ON: "2001:db8::1", D.PORT: 4242,
               D.OP_ADDR: RNS.Identity.truncated_hash(b"operator")}), {}),
        ("backbone_hostname_trailing_dot", base_info(transport_id, "BackboneInterface", "Dot Host",
            {D.REACHABLE_ON: "rns.example.org.", D.PORT: 4242}), {}),
        ("backbone_no_name", base_info(transport_id, "BackboneInterface", None,
            {D.REACHABLE_ON: "198.51.100.20", D.PORT: 4242}), {}),
        ("backbone_lowercase_name", base_info(transport_id, "BackboneInterface", "lowercase only",
            {D.REACHABLE_ON: "198.51.100.21", D.PORT: 4242}), {}),
        ("rnode", base_info(transport_id, "RNodeInterface", "RNode Gateway",
            {D.FREQUENCY: 868000000, D.BANDWIDTH: 125000, D.SPREADINGFACTOR: 8, D.CODINGRATE: 5,
               D.LATITUDE: -33.9, D.LONGITUDE: 151.2, D.HEIGHT: 10.0}), {}),
        ("i2p", base_info(transport_id, "I2PInterface", "I2P Node",
            {D.REACHABLE_ON: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.b32.i2p"}), {}),
        ("kiss", base_info(transport_id, "KISSInterface", "KISS TNC",
            {D.FREQUENCY: 433000000, D.BANDWIDTH: 125000, D.MODULATION: "LoRa"}), {}),
        ("weave", base_info(transport_id, "WeaveInterface", "Weave Mesh",
            {D.FREQUENCY: 2400000000, D.BANDWIDTH: 1000000, D.CHANNEL: 3, D.MODULATION: "GFSK"}), {}),
        ("tcpclient_type", base_info(transport_id, "TCPClientInterface", "TCP Client",
            {D.REACHABLE_ON: "198.51.100.22", D.PORT: 4242}), {}),
        ("low_stamp", base_info(transport_id, "BackboneInterface", "Low Stamp",
            {D.REACHABLE_ON: "198.51.100.23", D.PORT: 4242}), {"cost": 8, "below": STAMP_COST}),
        ("short_transport_id", base_info(transport_id[:8], "BackboneInterface", "Short ID",
            {D.REACHABLE_ON: "198.51.100.24", D.PORT: 4242}), {}),
        ("bad_reachable_on", base_info(transport_id, "BackboneInterface", "Bad Host",
            {D.REACHABLE_ON: "not a host!", D.PORT: 4242}), {}),
        ("integer_latitude", base_info(transport_id, "BackboneInterface", "Int Lat",
            {D.REACHABLE_ON: "198.51.100.25", D.PORT: 4242, D.LATITUDE: 52}), {}),
        ("unknown_type", base_info(transport_id, "SerialInterface", "Serial",
            {D.REACHABLE_ON: "198.51.100.26", D.PORT: 4242}), {}),
        ("encrypted_without_network_identity", base_info(transport_id, "BackboneInterface", "Encrypted",
            {D.REACHABLE_ON: "198.51.100.27", D.PORT: 4242}), {"flags": D.InterfaceAnnounceHandler.FLAG_ENCRYPTED}),
    ]

    announces = []
    for label, info, options in cases:
        packed, stamp, value = stamped(info, options.get("cost", STAMP_COST), options.get("below"))
        app_data = bytes([options.get("flags", 0x00)]) + packed + stamp

        received = []
        handler = D.InterfaceAnnounceHandler(callback=received.append)
        handler.received_announce(destination_hash, network_identity, app_data)
        if received:
            expected = dict(received[0])
            del expected["received"]
        else:
            expected = None

        announces.append({"label": label, "app_data": app_data.hex(), "stamp_value": value,
                          "expected": plain(expected)})

    # The files InterfaceDiscovery keeps: first heard, then heard again.
    discovery = D.InterfaceDiscovery(discover_interfaces=False)
    received = []
    handler = D.InterfaceAnnounceHandler(callback=received.append)
    handler.received_announce(destination_hash, network_identity, bytes.fromhex(announces[0]["app_data"]))
    info = received[0]
    filepath = os.path.join(discovery.storagepath, info["discovery_hash"].hex())
    discovery.interface_discovered(dict(info))
    with open(filepath, "rb") as f: first = f.read()
    heard_again = dict(info); heard_again["received"] = info["received"] + 60.0
    discovery.interface_discovered(heard_again)
    with open(filepath, "rb") as f: second = f.read()

    names = ["", "zer0bitz", "  zer0bitz  ", "Example Backbone 1", "RMAP World", "My Backbone Node!",
             "lowercase only", "Node (EU)", "Node (EU) ", "(Paren) Node", "Café Zürich 2", "A     B   C  D",
             "A\tB", "--- X ---", "123", "ÄÖÜ", "Discovered BackboneInterface", "x)", "X)"]

    hosts = ["rns.example.org", "rns.example.org.", "rns.example.org..", "localhost", "a-b.c",
             "-a.b", "a-.b", "a_b.c", "1.2.3.4", "1.2.3.4.", "example.123", "123", "a" * 63 + ".com",
             "a" * 64 + ".com", "", ".", "2001:db8::1", "::1", "fe80::1%en0", "256.1.1.1", "1.2.3",
             "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.b32.i2p", "example.onion"]

    vectors = {
        "generator": "Reticulum-rust tests/fixtures/discovery_vectors.py (RNS %s)" % D.RNS_VERSION,
        "note": "Regenerate with the generator, never by hand. Hex is lower-case.",
        "required_value": STAMP_COST,
        # Config entries name a BackboneInterface where the reference supports
        # one (not on Windows or macOS), a TCPClientInterface elsewhere.
        "backbone_support": not RNS.vendor.platformutils.is_windows() and not RNS.vendor.platformutils.is_darwin(),
        "network_identity_public_key": network_identity.get_public_key().hex(),
        "network_id": network_identity.hash.hex(),
        "destination_hash": destination_hash.hex(),
        "announces": announces,
        "stored": {"first_heard": first.hex(), "heard_again": second.hex(),
                   "endpoint_hash": discovery.endpoint_hash(info).hex(),
                   "first_heard_info": plain(msgpack.unpackb(first)),
                   "heard_again_info": plain(msgpack.unpackb(second))},
        "sanitize_name": [[n, D.InterfaceAnnounceHandler.sanitize_name(n)] for n in names],
        "hosts": [[h, checked(D.is_ip_address, h), checked(D.is_hostname, h)] for h in hosts],
    }
    json.dump(vectors, sys.stdout, indent=1)
    sys.stdout.write("\n")
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
