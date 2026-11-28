#!/usr/bin/env python3
"""Interface discovery auto-connect against the Python reference, over loopback.

    ../.venv/bin/python tests/interop/discovery_autoconnect.py [path/to/rnsd]

The rnsd under test (default target/debug/rnsd) runs with
discover_interfaces = yes, autoconnect_discovered_interfaces = 2 and one
bootstrap_only TCP client. Around it run Python reference nodes from the
venv's RNS:

  - a seed: a transport node with a TCP server, the bootstrap client's target;
  - four backbones: transport nodes, each a client of the seed and a
    discoverable TCP server on ::1. The reference's BackboneInterface runs on
    Linux only, so each server is a TCPServerInterface announced under the
    BackboneInterface type, the only type the reference auto-connects. On the
    wire it serves the same framing.

The rnsd must, as RNS/Discovery.py does:
  1. hear the backbones' discovery announces through the seed and connect to two;
  2. then tear down its bootstrap client;
then, where it departs from the reference (PARITY-AUDIT-1.5.2.md B46):
  3. after a restart, connect the same two again, though the reference's order
     (most recently heard first) would now pick the other two;
  4. after a restart with one of them dead, connect the live one again, detach
     the dead one as before and connect a live backbone in its place;
and again as the reference does:
  5. when a connected backbone dies, detach it 12 s after it was first seen
     down, and connect another;
  6. when every backbone is dead, bring the bootstrap client back;
and store entries the reference lists as its own, with the working file next
to them.

Exit 0 only if every step passes. INTEROP_KEEP=dir keeps the run's configs
and logs there.
"""

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

PY = sys.executable
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BACKBONES = 4
ANNOUNCE_DEADLINE = 240     # the reference's announcer first runs 60 s after start
DETACH_THRESHOLD = 12       # RNS/Discovery.py DETACH_THRESHOLD, seconds
MONITOR_INTERVAL = 5        # RNS/Discovery.py MONITOR_INTERVAL, seconds


def backbone_mode(configdir):
    # A reference node whose TCP servers announce as BackboneInterface.
    import RNS
    from RNS.Interfaces.TCPInterface import TCPServerInterface

    class BackboneInterface(TCPServerInterface):
        pass

    RNS.Reticulum(configdir=configdir)
    servers = [i for i in RNS.Transport.interfaces if type(i) is TCPServerInterface]
    for server in servers:
        server.__class__ = BackboneInterface
    RNS.log(f"Announcing {len(servers)} TCP server(s) as BackboneInterface", RNS.LOG_NOTICE)
    while True:
        time.sleep(1)


def listing_mode(configdir):
    # The reference's own listing of a storage directory.
    import RNS
    RNS.Reticulum(configdir=configdir, loglevel=RNS.LOG_CRITICAL)
    listed = RNS.Discovery.InterfaceDiscovery(discover_interfaces=False).list_discovered_interfaces()
    plain = [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in info.items()} for info in listed]
    sys.stdout.write(json.dumps(plain) + "\n")
    sys.stdout.flush()
    os._exit(0)


def read_working(path):
    # The endpoints rnsd remembers as working, as it writes them.
    try:
        with open(path) as f:
            return sorted(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return []


def rank_entries(store, newest_first):
    # Order the stored entries as the reference's listing would rank them
    # (status, then stamp value, then last heard): one stamp value for all,
    # and last heard a minute apart, newest first. `newest_first` is ports.
    # The reference's own msgpack, as Discovery.py reads and writes entries.
    from RNS.vendor import umsgpack
    now = time.time()
    ranked = 0
    for name in os.listdir(store):
        path = os.path.join(store, name)
        with open(path, "rb") as f:
            info = umsgpack.unpackb(f.read())
        if info.get("port") in newest_first:
            info["value"] = 14
            info["last_heard"] = now - 60 * newest_first.index(info["port"])
            with open(path, "wb") as f:
                f.write(umsgpack.packb(info))
            ranked += 1
    if ranked != len(newest_first):
        raise RuntimeError(f"ranked {ranked} stored entries, expected {len(newest_first)}")


def free_port(host):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return probe.getsockname()[1]


class Run:
    def __init__(self, rnsd):
        self.rnsd = rnsd
        self.dir = tempfile.mkdtemp(prefix="discovery-interop-")
        self.procs = {}
        self.logs = {}
        self.started = time.time()
        self.failed = False

    def stamp(self):
        return f"{time.time() - self.started:6.1f}s"

    def say(self, text):
        print(f"[{self.stamp()}] {text}", flush=True)

    def config(self, name, text):
        path = os.path.join(self.dir, name)
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "config"), "w") as f:
            f.write(text)
        return path

    def start(self, name, argv, logname=None):
        # A restarted process logs to a new file, so each start's lines count apart.
        self.logs[name] = logname or name
        log = open(os.path.join(self.dir, self.logs[name] + ".log"), "w")
        env = dict(os.environ, PYTHONUNBUFFERED="1")
        self.procs[name] = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)

    def stop(self, name):
        proc = self.procs.pop(name, None)
        if proc is None:
            return
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def stop_all(self):
        for name in list(self.procs):
            self.stop(name)

    def log(self, name):
        with open(os.path.join(self.dir, self.logs.get(name, name) + ".log"), errors="replace") as f:
            return f.read()

    def alive(self, name):
        return name in self.procs and self.procs[name].poll() is None

    def connected_ports(self, name):
        # Remote ports of the process's established TCP connections.
        out = subprocess.run(["lsof", "-nP", "-a", "-p", str(self.procs[name].pid), "-iTCP", "-sTCP:ESTABLISHED"],
                             capture_output=True, text=True).stdout
        return {int(m.group(1)) for m in re.finditer(r"->\S*:(\d+) \(ESTABLISHED\)", out)}

    def wait_for(self, what, deadline, check):
        end = time.time() + deadline
        while time.time() < end:
            if not self.alive("rust"):
                return self.fail(f"rnsd exited while waiting for {what}")
            result = check()
            if result:
                return result
            time.sleep(0.5)
        return self.fail(f"no {what} within {deadline} s")

    def fail(self, text):
        self.say("FAIL: " + text)
        self.failed = True
        return None

    def count(self, pattern):
        return len(re.findall(pattern, self.log("rust")))


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--backbone":
        return backbone_mode(sys.argv[2])
    if len(sys.argv) > 2 and sys.argv[1] == "--listing":
        return listing_mode(sys.argv[2])

    rnsd = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(ROOT, "target", "debug", "rnsd")
    if not os.access(rnsd, os.X_OK):
        print(f"No rnsd at {rnsd}; build it with: cargo build --bin rnsd")
        return 2
    py_rnsd = os.path.join(os.path.dirname(PY), "rnsd")
    loglevel = os.environ.get("INTEROP_LOGLEVEL", "4")
    run = Run(rnsd)
    try:
        return scenario(run, py_rnsd, loglevel)
    finally:
        run.stop_all()
        keep = os.environ.get("INTEROP_KEEP")
        if keep:
            shutil.copytree(run.dir, os.path.join(keep, os.path.basename(run.dir)))
        if run.failed:
            for name in ["rust", "rust-2", "rust-3", "seed"] + [f"backbone{n}" for n in range(1, BACKBONES + 1)]:
                # The reference's rnsd logs to its config directory's logfile.
                for path in [os.path.join(run.dir, name + ".log"), os.path.join(run.dir, name, "logfile")]:
                    if os.path.exists(path) and os.path.getsize(path):
                        print(f"\n----- tail of {os.path.relpath(path, run.dir)} -----")
                        print("".join(open(path, errors="replace").readlines()[-40:]), end="")
        shutil.rmtree(run.dir, ignore_errors=True)


def scenario(run, py_rnsd, loglevel):
    seed_port = free_port("127.0.0.1")
    ports = {n: free_port("::1") for n in range(1, BACKBONES + 1)}
    node = "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n\n[logging]\n  loglevel = %s\n\n" % loglevel

    seed = run.config("seed", node + f"""[interfaces]
  [[Seed Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {seed_port}
""")
    run.start("seed", [py_rnsd, "--config", seed])

    rust = run.config("rust", f"""[reticulum]
  enable_transport = Yes
  share_instance = No
  discover_interfaces = Yes
  autoconnect_discovered_interfaces = 2

[logging]
  loglevel = 6

[interfaces]
  [[Seed]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {seed_port}
    bootstrap_only = yes
""")
    rust_argv = [run.rnsd, "--config", rust, "-v", "-v", "-v"]
    run.start("rust", rust_argv)

    for n, port in ports.items():
        backbone = run.config(f"backbone{n}", node + f"""[interfaces]
  [[Seed]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {seed_port}

  [[Loop Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = ::1
    listen_port = {port}
    discoverable = yes
    discovery_name = Loop Backbone {n}
    reachable_on = ::1
    announce_interval = 5
""")
        run.start(f"backbone{n}", [PY, os.path.abspath(__file__), "--backbone", backbone])
    run.say(f"seed on 127.0.0.1:{seed_port}; backbones on ::1:{list(ports.values())}")

    backbone_of = {port: n for n, port in ports.items()}
    connected = lambda: {backbone_of[p] for p in run.connected_ports("rust") if p in backbone_of}
    on_seed = lambda: seed_port in run.connected_ports("rust")

    # 0. The bootstrap client is up.
    if not run.wait_for("connection to the seed", 30, on_seed):
        return 1
    run.say("rnsd connected to the seed (bootstrap)")

    # 1. Two backbones heard and connected.
    stored = os.path.join(rust, "storage", "discovery", "interfaces")
    two = run.wait_for("two auto-connected backbones", ANNOUNCE_DEADLINE, lambda: len(connected()) == 2 and connected())
    if not two:
        return 1
    run.say(f"auto-connected backbones {sorted(two)}; stored entries: {len(os.listdir(stored))}")
    if run.count(r"Auto-connecting discovered BackboneInterface") < 2:
        return run.fail("rnsd did not log its two auto-connects") or 1

    # 2. The bootstrap client comes down.
    if not run.wait_for("bootstrap teardown", 3 * MONITOR_INTERVAL, lambda: not on_seed()):
        return 1
    run.say("bootstrap client torn down")

    # 3. A restart with both alive: the same two again, though the reference's
    #    order, as the stored entries now rank them, would dial the other two.
    working_file = os.path.join(rust, "storage", "discovery", "working_interfaces")
    endpoints = lambda backbones: sorted(f"::1:{ports[n]}" for n in backbones)
    entries = lambda: [name for name in os.listdir(stored) if not name.endswith(".tmp")]
    if not run.wait_for("all four backbones stored", ANNOUNCE_DEADLINE, lambda: len(entries()) == BACKBONES):
        return 1
    if not run.wait_for("the two in the working file", 3 * MONITOR_INTERVAL,
                        lambda: read_working(working_file) == endpoints(two)):
        return 1
    others = sorted(set(ports) - two)
    run.stop("rust")
    rank_entries(stored, [ports[n] for n in others + sorted(two)])
    run.start("rust", rust_argv, logname="rust-2")
    run.say(f"rnsd restarted; the reference's order would dial backbones {others} first")
    if not run.wait_for("the same two backbones", 3 * MONITOR_INTERVAL, lambda: connected() == two):
        return 1
    held = time.time() + 2 * MONITOR_INTERVAL
    while time.time() < held:
        if connected() - two:
            return run.fail(f"rnsd dialled backbones {sorted(connected() - two)} after the restart") or 1
        time.sleep(0.5)
    if run.count(r"Auto-connecting first 2 discovered interfaces working before this start") != 1:
        return run.fail("rnsd did not log that it dialled the two first") or 1
    run.say(f"after the restart: the same backbones {sorted(two)}, held for two passes")

    # 4. A restart with one of them dead: the live one again, the dead one
    #    detached 12 s after it was first seen down, a live one in its place.
    dead, kept = sorted(two)
    run.stop("rust")
    run.stop(f"backbone{dead}")
    rank_entries(stored, [ports[n] for n in others + [dead, kept]])
    run.start("rust", rust_argv, logname="rust-3")
    run.say(f"rnsd restarted with backbone {dead} stopped")
    if not run.wait_for(f"backbone {kept} again", 3 * MONITOR_INTERVAL, lambda: kept in connected()):
        return 1
    if run.count(r"Auto-connecting first 2 discovered interfaces working before this start") != 1:
        return run.fail("rnsd did not log that it dialled the two first") or 1
    # The free slot is filled at random from all four, dead or not, so it can
    # take a few dials, each holding the slot about 20 s.
    if not run.wait_for("a live backbone in the dead one's place", 300,
                        lambda: len(connected()) == 2 and kept in connected() and connected()):
        return 1
    two = connected()
    if not run.wait_for("the new pair in the working file", 3 * MONITOR_INTERVAL,
                        lambda: read_working(working_file) == endpoints(two)):
        return 1
    run.say(f"now connected to backbones {sorted(two)}; the working file lists them")

    # 5. A connected backbone dies: detached after 12 s down, another connected.
    victim = min(two)
    detaches = run.count(r"has been down for .*detaching")
    run.stop(f"backbone{victim}")
    killed = time.time()
    run.say(f"backbone {victim} stopped")
    if not run.wait_for("detach", DETACH_THRESHOLD + 4 * MONITOR_INTERVAL,
                        lambda: run.count(r"has been down for .*detaching") > detaches):
        return 1
    after = time.time() - killed
    run.say(f"detached {after:.1f} s after the backbone stopped")
    if not DETACH_THRESHOLD <= after <= DETACH_THRESHOLD + 2 * MONITOR_INTERVAL + 2:
        return run.fail(f"detach after {after:.1f} s, outside "
                        f"{DETACH_THRESHOLD}..{DETACH_THRESHOLD + 2 * MONITOR_INTERVAL + 2} s") or 1
    survivor = (two - {victim}).pop()
    third = (set(ports) - two - {dead}).pop()
    replaced = {survivor, third}
    # The reference picks a candidate at random, and the stopped backbones stay
    # candidates (they were heard within the day), so a pass may dial one again;
    # each such dial holds the free slot for about 20 s. With four backbones a
    # pass picks the live one a quarter of the time.
    if not run.wait_for("a replacement backbone", 300, lambda: connected() == replaced):
        return 1
    run.say(f"now connected to backbones {sorted(replaced)}")
    if on_seed():
        return run.fail("the bootstrap client came back while a backbone was online") or 1

    # 6. Every backbone dies: the bootstrap client comes back.
    for n in sorted(replaced):
        run.stop(f"backbone{n}")
    run.say("all backbones stopped")
    if not run.wait_for("bootstrap restore", 3 * MONITOR_INTERVAL + 10, on_seed):
        return 1
    run.say("bootstrap client restored")
    if run.count(r"re-enabling bootstrap interfaces") < 1:
        return run.fail("rnsd did not log the bootstrap restore") or 1

    # 7. The reference lists what rnsd stored, the working file beside it.
    reader = run.config("reader", "[reticulum]\n  share_instance = No\n\n[logging]\n  loglevel = 0\n\n[interfaces]\n")
    if not os.path.isfile(working_file):
        return run.fail("rnsd left no working file") or 1
    shutil.copytree(os.path.dirname(stored), os.path.join(reader, "storage", "discovery"))
    out = subprocess.run([PY, os.path.abspath(__file__), "--listing", reader], capture_output=True, text=True, timeout=60)
    try:
        listed = json.loads(out.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return run.fail(f"the reference could not list the stored entries: {out.stdout[-500:]} {out.stderr[-500:]}") or 1
    seen = sorted((i["name"], i["type"], i.get("reachable_on"), i.get("port"), i["status"]) for i in listed)
    want = sorted((f"Loop Backbone {n}", "BackboneInterface", "::1", port, "available") for n, port in ports.items())
    if seen != want:
        return run.fail(f"the reference listed {seen}, expected {want}") or 1
    run.say(f"the reference lists rnsd's {len(listed)} stored entries")

    run.say("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
