#!/usr/bin/env python3
"""Python-reference end of the over-MDU request/response interop harness.

Mirror of examples/request_resource_interop.rs — see that file for the
protocol. Run through tests/interop/run.sh.

  request_resource_interop.py hub    <config_dir>
  request_resource_interop.py server <config_dir>
  request_resource_interop.py client <config_dir> <dest_hex> <request_len> <response_len>

`hub` is a bare reference transport node. Both ends connect to it as TCP
clients, so every exchange crosses a real transport hop — as it does in
production — and neither end has to be the listener.
"""
import os
import sys
import threading
import time

import RNS

APP_NAME, ASPECT, PATH = "interop", "request", "/echo"
REQUEST_SEED, RESPONSE_SEED = 0x1234, 0x4321


def pattern(length, seed):
    x, out = seed, bytearray()
    for _ in range(length):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def emit(line):
    print(line, flush=True)


def hub(config_dir):
    # A bounded medium, like PostInterface or LoRa and unlike raw loopback TCP.
    # With MTU autoconfiguration off, the reference strips link MTU signalling
    # as it forwards the link request (Transport.py, "not AUTOCONFIGURE_MTU and
    # not FIXED_MTU"), so every link through here runs at the base 500-byte
    # MTU — and any frame above that is one the sender had no right to emit.
    # Loopback TCP would carry it anyway, which is exactly how an over-MDU
    # response sent as a single packet went unnoticed; here it is reported and
    # dropped, as a real medium would drop it.
    from RNS.Interfaces import TCPInterface
    TCPInterface.TCPClientInterface.AUTOCONFIGURE_MTU = False
    TCPInterface.TCPServerInterface.AUTOCONFIGURE_MTU = False

    RNS.Reticulum(config_dir)
    forward = RNS.Transport.inbound

    def bounded_inbound(raw, interface=None):
        if len(raw) > RNS.Reticulum.MTU:
            emit(f"OVERSIZE {len(raw)} bytes on a {RNS.Reticulum.MTU}-byte medium - dropped")
            return
        return forward(raw, interface)

    RNS.Transport.inbound = bounded_inbound
    emit("HUB ready")
    while True:
        time.sleep(3600)


def server(config_dir):
    RNS.Reticulum(config_dir)
    destination = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, ASPECT)

    def echo(path, data, request_id, link_id, remote_identity, requested_at):
        response_len, payload = data[0], data[1]
        intact = payload == pattern(len(payload), REQUEST_SEED)
        emit(f"REQUEST bytes={len(payload)} intact={intact}")
        return pattern(response_len, RESPONSE_SEED) if intact else b""

    destination.register_request_handler(PATH, response_generator=echo, allow=RNS.Destination.ALLOW_ALL)
    emit(f"DEST {destination.hash.hex()}")
    while True:
        destination.announce()
        time.sleep(3)


def client(config_dir, dest_hex, request_len, response_len):
    RNS.Reticulum(config_dir)
    dest_hash = bytes.fromhex(dest_hex)

    deadline = time.time() + 40
    while not RNS.Transport.has_path(dest_hash):
        if time.time() > deadline:
            fail("no announce from the server")
        time.sleep(0.2)

    destination = RNS.Destination(
        RNS.Identity.recall(dest_hash), RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, ASPECT
    )
    outcome, done = {}, threading.Event()

    def finish(result, reason=None):
        outcome.setdefault("result", (result, reason))
        done.set()

    def established(link):
        link.request(
            PATH,
            data=[response_len, pattern(request_len, REQUEST_SEED)],
            response_callback=lambda receipt: finish(receipt.response),
            failed_callback=lambda receipt: finish(None, "request failed"),
        )

    link = RNS.Link(destination)
    link.set_link_established_callback(established)
    link.set_link_closed_callback(lambda l: finish(None, "link closed"))

    if not done.wait(120):
        fail("no response within the test ceiling")
    response, reason = outcome["result"]
    if response is None:
        fail(reason)
    if response == pattern(response_len, RESPONSE_SEED):
        emit(f"PASS request={request_len} response={len(response)}")
        os._exit(0)
    fail(f"response mismatch: got {len(response)} bytes, wanted {response_len}")


def fail(reason):
    emit(f"FAIL {reason}")
    os._exit(1)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "hub":
        hub(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "server":
        server(sys.argv[2])
    elif len(sys.argv) == 6 and sys.argv[1] == "client":
        client(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
    else:
        sys.exit(__doc__)
