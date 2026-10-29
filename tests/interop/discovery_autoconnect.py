#!/usr/bin/env python3
"""Interface discovery auto-connect against the Python reference, over loopback.

    ../.venv/bin/python tests/interop/discovery_autoconnect.py [path/to/rnsd]

The rnsd under test (default target/debug/rnsd) runs with
discover_interfaces = yes, autoconnect_discovered_interfaces = 2 and one
bootstrap_only TCP client. Around it run Python reference nodes from the
venv's RNS:

  - a seed: a transport node with a TCP server, the bootstrap client's target;
  - three backbones: transport nodes, each a client of the seed and a
    discoverable TCP server on ::1. The reference's BackboneInterface runs on
    Linux only, so each server is a TCPServerInterface announced under the
    BackboneInterface type, the only type the reference auto-connects. On the
    wire it serves the same framing.

The rnsd must, as RNS/Discovery.py does:
  1. hear the backbones' discovery announces through the seed and connect to two;
  2. then tear down its bootstrap client;
  3. when a connected backbone dies, detach it 12 s after it was first seen
     down, and connect another;
  4. when every backbone is dead, bring the bootstrap client back;
and store entries the reference lists as its own.

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
BACKBONES = 3
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

    def start(self, name, argv):
        log = open(os.path.join(self.dir, name + ".log"), "w")
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
        with open(os.path.join(self.dir, name + ".log"), errors="replace") as f:
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
            for name in ["rust", "seed"] + [f"backbone{n}" for n in range(1, BACKBONES + 1)]:
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
    run.start("rust", [run.rnsd, "--config", rust, "-v", "-v", "-v"])

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

    # 3. A connected backbone dies: detached after 12 s down, another connected.
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
    third = (set(ports) - two).pop()
    replaced = {survivor, third}
    # The reference picks a candidate at random, and the stopped backbone stays
    # one (it was heard within the day), so a pass may dial it again; each such
    # dial holds the free slot for about 20 s. With three backbones a pass picks
    # the live one a third of the time.
    if not run.wait_for("a replacement backbone", 300, lambda: connected() == replaced):
        return 1
    run.say(f"now connected to backbones {sorted(replaced)}")
    if on_seed():
        return run.fail("the bootstrap client came back while a backbone was online") or 1

    # 4. Every backbone dies: the bootstrap client comes back.
    for n in sorted(replaced):
        run.stop(f"backbone{n}")
    run.say("all backbones stopped")
    if not run.wait_for("bootstrap restore", 3 * MONITOR_INTERVAL + 10, on_seed):
        return 1
    run.say("bootstrap client restored")
    if run.count(r"re-enabling bootstrap interfaces") < 1:
        return run.fail("rnsd did not log the bootstrap restore") or 1

    # 5. The reference lists what rnsd stored.
    reader = run.config("reader", "[reticulum]\n  share_instance = No\n\n[logging]\n  loglevel = 0\n\n[interfaces]\n")
    shutil.copytree(stored, os.path.join(reader, "storage", "discovery", "interfaces"))
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
