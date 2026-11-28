#!/usr/bin/env python3
"""A hub that comes back, a burst to a slow peer, and a peer that stops
reading: the rnsd under test among stock Python RNS nodes, over loopback.

    ../.venv/bin/python tests/interop/egress_and_hub_return.py [path/to/rnsd]

Everything runs on 127.0.0.1 and ::1, each node with its own config
folder in a temporary directory; nothing reads or writes ~/.reticulum.
The rnsd under test (default target/debug/rnsd) is set up like the house
gateway: transport on, discover_interfaces = yes,
autoconnect_discovered_interfaces = 2, a bootstrap_only TCP client to a
seed, and a TCP server ("LAN") for local clients. It also dials two
configured TCP clients: "Hub", a stock rnsd, and "Slow Peer", a stock node
behind a proxy that passes on 1 MB a second and can pause. Three stock backbones, each a
client of the seed, publish discoverable TCP servers on ::1, announced as
BackboneInterface as in discovery_autoconnect.py. Every stock node but the
seed and the hub hosts a destination, "egresstest.sink", that counts the
packets it receives.

Steps, each judged on its own:
  1. two backbones are auto-connected and the bootstrap client torn down;
  2. the configured hub goes away for 20 s and comes back: rnsd dials it
     again by itself;
  3. a client on LAN sends the slow peer's sink 1,153 packets at once, the
     burst the house gateway forwarded to "murph" on 2026-11-28, while the
     peer takes nothing for 2 s: every one arrives and rnsd drops none;
  4. a connected backbone stops reading (SIGSTOP; its kernel still holds the
     connection) while a client on LAN streams packets to its sink: rnsd
     tears the connection down once it has taken nothing for 12 s
     (DP_EC_DEAD_TIME), and the backbone's slot is filled by the third one;
  5. every backbone stops: the bootstrap client comes back.

Exit 0 only if every step passes. INTEROP_KEEP=dir keeps the run's configs
and logs there.
"""

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from discovery_autoconnect import Run, free_port, ANNOUNCE_DEADLINE, MONITOR_INTERVAL  # noqa: E402

PY = sys.executable
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BACKBONES = 3
DEAD_TIME = 12              # RNS/Interfaces/BackboneInterface.py DP_EC_DEAD_TIME, seconds
BURST = int(os.environ.get("INTEROP_BURST", 1153))   # Resource parts murph was offered in one second
PAYLOAD = 300               # bytes of each packet's plaintext; about 420 on the wire
SLOW_RATE = int(os.environ.get("INTEROP_SLOW_RATE", 1024 * 1024))   # bytes a second the slow peer's proxy passes on
STREAM_RATE = 200           # packets a second streamed to the stalled backbone
PAUSE = float(os.environ.get("INTEROP_PAUSE", 2.0))   # seconds the slow peer takes nothing as the burst arrives


# --- Node modes, run as child processes -------------------------------------

def node_mode(configdir, backbone):
    # A stock node hosting egresstest.sink; with backbone=1 its TCP servers
    # announce as BackboneInterface.
    import RNS
    from RNS.Interfaces.TCPInterface import TCPServerInterface

    class BackboneInterface(TCPServerInterface):
        pass

    RNS.Reticulum(configdir=configdir)
    if backbone == "1":
        for server in [i for i in RNS.Transport.interfaces if type(i) is TCPServerInterface]:
            server.__class__ = BackboneInterface
    sink = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "egresstest", "sink")
    received = [0]

    def on_packet(data, packet):
        received[0] += 1

    sink.set_packet_callback(on_packet)
    with open(os.path.join(configdir, "sink"), "w") as f:
        f.write(sink.hash.hex())
    announced = 0
    while True:
        if time.time() - announced >= 10:
            sink.announce()
            announced = time.time()
        tmp = os.path.join(configdir, "received.tmp")
        with open(tmp, "w") as f:
            f.write(str(received[0]))
        os.replace(tmp, os.path.join(configdir, "received"))
        time.sleep(0.25)


def flood_mode(configdir, dest_hex, count, rate, go_file):
    # A stock client that sends `count` packets (0: without end) to a sink,
    # `rate` a second (0: as fast as it can), once `go_file` exists.
    import RNS
    RNS.Reticulum(configdir=configdir)
    count, rate = int(count), float(rate)
    dest_hash = bytes.fromhex(dest_hex)
    if not RNS.Transport.has_path(dest_hash):
        RNS.Transport.request_path(dest_hash)
    deadline = time.time() + 30
    while not RNS.Transport.has_path(dest_hash) and time.time() < deadline:
        time.sleep(0.1)
    if not RNS.Transport.has_path(dest_hash):
        with open(os.path.join(configdir, "ready"), "w") as f:
            f.write("no path")
        os._exit(3)
    dest = RNS.Destination(RNS.Identity.recall(dest_hash), RNS.Destination.OUT, RNS.Destination.SINGLE, "egresstest", "sink")
    with open(os.path.join(configdir, "ready"), "w") as f:
        f.write(f"hops {RNS.Transport.hops_to(dest_hash)}")
    while not os.path.exists(go_file):
        time.sleep(0.05)
    sent, started = 0, time.time()
    while count == 0 or sent < count:
        RNS.Packet(dest, os.urandom(PAYLOAD)).send()
        sent += 1
        if rate:
            ahead = sent / rate - (time.time() - started)
            if ahead > 0:
                time.sleep(ahead)
        if sent % 50 == 0 or sent == count:
            with open(os.path.join(configdir, "sent"), "w") as f:
                f.write(f"{sent} {time.time() - started:.2f}")
    while True:
        time.sleep(1)


def proxy_mode(listen_port, target_port, rate, pause_file):
    # Passes a connection on to target_port, taking at most `rate` bytes a
    # second from the side that connected, through a small receive buffer,
    # and nothing at all while `pause_file` exists: a live peer that is
    # briefly busy, so a burst backs up into the sender's socket.
    listen_port, target_port, rate = int(listen_port), int(target_port), float(rate)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024)
    server.bind(("127.0.0.1", listen_port))
    server.listen(4)
    while True:
        near, _ = server.accept()
        far = socket.create_connection(("127.0.0.1", target_port))

        def pass_on(src, dst, limit):
            started, moved = time.time(), 0
            try:
                while True:
                    while limit and os.path.exists(pause_file):
                        time.sleep(0.02)
                    data = src.recv(2048 if limit else 65536)
                    if not data:
                        break
                    dst.sendall(data)
                    if limit:
                        moved += len(data)
                        ahead = moved / limit - (time.time() - started)
                        if ahead > 0:
                            time.sleep(ahead)
            except OSError:
                pass
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

        threading.Thread(target=pass_on, args=(near, far, rate), daemon=True).start()
        threading.Thread(target=pass_on, args=(far, near, 0), daemon=True).start()


# --- The run ----------------------------------------------------------------

def read(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def main():
    if len(sys.argv) > 3 and sys.argv[1] == "--node":
        return node_mode(sys.argv[2], sys.argv[3])
    if len(sys.argv) > 6 and sys.argv[1] == "--flood":
        return flood_mode(*sys.argv[2:7])
    if len(sys.argv) > 5 and sys.argv[1] == "--proxy":
        return proxy_mode(*sys.argv[2:6])

    rnsd = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(ROOT, "target", "debug", "rnsd")
    if not os.access(rnsd, os.X_OK):
        print(f"No rnsd at {rnsd}; build it with: cargo build --bin rnsd")
        return 2
    py_rnsd = os.path.join(os.path.dirname(PY), "rnsd")
    run = Run(rnsd)
    results = []
    try:
        scenario(run, py_rnsd, results)
    finally:
        for name, proc in list(run.procs.items()):
            try:
                proc.send_signal(signal.SIGCONT)
            except OSError:
                pass
        run.stop_all()
        print("\nSteps:")
        for step, ok, detail in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {step}: {detail}")
        keep = os.environ.get("INTEROP_KEEP")
        if keep:
            shutil.copytree(run.dir, os.path.join(keep, os.path.basename(run.dir)))
        shutil.rmtree(run.dir, ignore_errors=True)
    passed = len(results) == 5 and all(ok for _, ok, _ in results)
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


def scenario(run, py_rnsd, results):
    def step(name, ok, detail):
        results.append((name, bool(ok), detail))
        run.say(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
        return bool(ok)

    seed_port, hub_port, lan_port = free_port("127.0.0.1"), free_port("127.0.0.1"), free_port("127.0.0.1")
    slow_port, proxy_port = free_port("127.0.0.1"), free_port("127.0.0.1")
    ports = {n: free_port("::1") for n in range(1, BACKBONES + 1)}
    node = "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n\n[logging]\n  loglevel = 4\n\n"
    leaf = "[reticulum]\n  enable_transport = No\n  share_instance = No\n\n[logging]\n  loglevel = 4\n\n"

    def server(name, host, port, extra=""):
        return f"  [[{name}]]\n    type = TCPServerInterface\n    enabled = yes\n    listen_ip = {host}\n    listen_port = {port}\n{extra}"

    def client(name, port, extra=""):
        return f"  [[{name}]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {port}\n{extra}"

    seed = run.config("seed", node + "[interfaces]\n" + server("Seed Server", "127.0.0.1", seed_port))
    run.start("seed", [py_rnsd, "--config", seed])
    hub = run.config("hub", node + "[interfaces]\n" + server("Hub Server", "127.0.0.1", hub_port))
    run.start("hub", [py_rnsd, "--config", hub])
    slow = run.config("slow", node + "[interfaces]\n" + server("Slow Server", "127.0.0.1", slow_port))
    run.start("slow", [PY, os.path.abspath(__file__), "--node", slow, "0"])
    pause_file = os.path.join(slow, "pause")
    run.start("proxy", [PY, os.path.abspath(__file__), "--proxy", str(proxy_port), str(slow_port), str(SLOW_RATE), pause_file])
    time.sleep(2)

    rust = run.config("rust", f"""[reticulum]
  enable_transport = Yes
  share_instance = No
  discover_interfaces = Yes
  autoconnect_discovered_interfaces = 2

[logging]
  loglevel = 6

[interfaces]
""" + client("Seed", seed_port, "    bootstrap_only = yes\n") + client("Hub", hub_port) + client("Slow Peer", proxy_port)
        + server("LAN", "127.0.0.1", lan_port))
    run.start("rust", [run.rnsd, "--config", rust, "-v", "-v", "-v"])

    backbone_dirs = {}
    for n, port in ports.items():
        backbone_dirs[n] = run.config(f"backbone{n}", node + "[interfaces]\n" + client("Seed", seed_port)
                                      + server("Loop Server", "::1", port,
                                               f"    discoverable = yes\n    discovery_name = Loop Backbone {n}\n"
                                               "    reachable_on = ::1\n    announce_interval = 5\n"))
        run.start(f"backbone{n}", [PY, os.path.abspath(__file__), "--node", backbone_dirs[n], "1"])
    run.say(f"seed 127.0.0.1:{seed_port}, hub :{hub_port}, slow peer :{slow_port} behind proxy :{proxy_port}, "
            f"LAN :{lan_port}; backbones on ::1:{list(ports.values())}")

    backbone_of = {port: n for n, port in ports.items()}
    connected = lambda: {backbone_of[p] for p in run.connected_ports("rust") if p in backbone_of}
    on = lambda port: (lambda: port in run.connected_ports("rust"))

    def flooder(name, sink_dir, count, rate):
        cdir = run.config(name, leaf + "[interfaces]\n" + client("To rnsd", lan_port))
        go = os.path.join(cdir, "go")
        run.start(name, [PY, os.path.abspath(__file__), "--flood", cdir, read(os.path.join(sink_dir, "sink")),
                         str(count), str(rate), go])
        ready = run.wait_for(f"{name}'s path to its sink", 60, lambda: read(os.path.join(cdir, "ready")))
        return cdir, go, ready

    # 0. The configured clients are up.
    if not run.wait_for("connections to the seed, the hub and the slow peer", 60,
                        lambda: all(f() for f in (on(seed_port), on(hub_port), on(proxy_port)))):
        return
    run.say("rnsd dialled the seed (bootstrap), the hub and the slow peer")

    # 1. Two backbones heard and connected, the bootstrap client torn down.
    two = run.wait_for("two auto-connected backbones", ANNOUNCE_DEADLINE, lambda: len(connected()) == 2 and connected())
    if not step("1 auto-connect", two and run.wait_for("bootstrap teardown", 3 * MONITOR_INTERVAL, lambda: not on(seed_port)()),
                f"backbones {sorted(two) if two else None} connected, bootstrap client torn down"):
        return

    # 2. The configured hub goes away and comes back.
    run.stop("hub")
    gone = time.time()
    noticed = run.wait_for("rnsd to notice the hub had gone", 15, lambda: not on(hub_port)())
    time.sleep(20)
    run.start("hub", [py_rnsd, "--config", hub])
    back = time.time()
    again = run.wait_for("rnsd to dial the hub again", 330, on(hub_port))
    step("2 hub comes back", noticed and again,
         f"hub away {back - gone:.0f} s; rnsd connected again {time.time() - back:.1f} s after it came back"
         if again else "rnsd never dialled the hub again")

    # 3. A burst to a live peer that drains slowly.
    received_before = int(read(os.path.join(slow, "received"), "0"))
    cdir, go, ready = flooder("burst", slow, BURST, 0)
    if ready and ready.startswith("hops"):
        dropped_before = run.count(r"\[DISPATCH\] outbound failed for interface Slow Peer ")
        # The slow peer is busy for PAUSE seconds as the burst arrives, as
        # murph's socket was: it took the burst only over a second or two.
        open(pause_file, "w").close()
        time.sleep(0.5)
        open(go, "w").close()
        began = time.time()
        sent = run.wait_for("the burst to be sent", 60, lambda: (read(os.path.join(cdir, "sent")) or "").startswith(f"{BURST} "))
        time.sleep(max(0.0, PAUSE - (time.time() - began)))
        os.remove(pause_file)
        # Wait for every packet, or for the count to stand still for 10 s.
        last, stable_since, waiting_since = -1, time.time(), time.time()
        while time.time() - waiting_since < 120:
            got = int(read(os.path.join(slow, "received"), "0")) - received_before
            if got != last:
                last, stable_since = got, time.time()
            if got >= BURST or time.time() - stable_since >= 10:
                break
            time.sleep(0.5)
        drops = run.count(r"\[DISPATCH\] outbound failed for interface Slow Peer ") - dropped_before
        step("3 burst to a slow peer", sent and last == BURST and drops == 0,
             f"{last} of {BURST} packets arrived ({read(os.path.join(cdir, 'sent'))} s to send, the peer busy for {PAUSE:.0f} s); "
             f"rnsd dropped {drops} frames it had for Slow Peer")
    else:
        step("3 burst to a slow peer", False, f"the client had no path to the slow peer's sink ({ready})")
    run.stop("burst")

    # 4. A connected backbone stops reading while packets stream to it.
    now = connected()
    victim = min(now)
    survivor = (now - {victim}).pop()
    third = (set(ports) - now).pop()
    cdir, go, ready = flooder("stream", backbone_dirs[victim], 0, STREAM_RATE)
    if not (ready and ready.startswith("hops")):
        step("4 a peer stops reading", False, f"the client had no path to backbone {victim}'s sink ({ready})")
        return
    run.say(f"backbone {victim} stops reading; packets stream to its sink at {STREAM_RATE}/s ({ready})")
    vport = ports[victim]
    notice = rf"No egress control drain progress for 12s on .*{vport}\]"
    os.kill(run.procs[f"backbone{victim}"].pid, signal.SIGSTOP)
    stopped = time.time()
    open(go, "w").close()
    torn = run.wait_for("rnsd to tear the stalled connection down", 90, lambda: run.count(notice) > 0)
    torn_after = time.time() - stopped
    # The reference picks a free slot's candidate at random, and the stopped
    # backbone stays one, so it may be dialled again before the third.
    refilled = torn and run.wait_for("the third backbone in the slot", 600,
                                     lambda: connected() == {survivor, third})
    gates = run.count(r"gating outbound")
    step("4 a peer stops reading", torn and refilled,
         (f"torn down {torn_after:.1f} s after backbone {victim} stopped reading; "
          f"slot filled by backbone {third} {time.time() - stopped:.0f} s after; "
          f"{run.count(notice)} dead-time teardowns, {gates or 0} gate closings logged")
         if torn and refilled else
         (f"torn down {torn_after:.1f} s after it stopped reading, but the slot was not filled by backbone {third}"
          if torn else f"backbone {victim} stayed connected for 90 s after it stopped reading; rnsd dropped "
          f"{run.count(rf'outbound failed for interface Loop Backbone {victim} ')} frames it had for it"))
    run.stop("stream")
    os.kill(run.procs[f"backbone{victim}"].pid, signal.SIGCONT)

    # 5. Every backbone stops: the bootstrap client comes back.
    for n in range(1, BACKBONES + 1):
        run.stop(f"backbone{n}")
    restored = run.wait_for("bootstrap restore", 12 + 3 * MONITOR_INTERVAL + 10, on(seed_port))
    step("5 bootstrap restore", restored and run.count(r"re-enabling bootstrap interfaces") > 0,
         "the bootstrap client came back once no backbone was connected" if restored else "it did not come back")


if __name__ == "__main__":
    sys.exit(main())
