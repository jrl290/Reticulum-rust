#!/usr/bin/env python3
"""Ratchet interop: this stack's ratchets against the Python reference.

The Rust end is examples/ratchet_interop.rs. Run through
tests/interop/ratchet_run.sh, which builds it and calls `run` here.

  ratchet_interop.py run  <rust_binary> <work_dir>    the orchestrator
  ratchet_interop.py hub  <config_dir>                a bare reference transport node
  ratchet_interop.py peer <config_dir>                the Python reference peer
  ratchet_interop.py load <identity> <ratchet_file>   the reference loads a ratchet file

Every process is a TCP client of a Python reference transport node (the hub),
so every exchange crosses a real transport hop. Scenarios, each decided on an
event (a proof, a log line, an announce); ceilings only turn a missing event
into a FAIL (DESIGN_PRINCIPLES §1), and a proof later than 5 s is a FAIL too.

  a  A Rust IN destination with ratchets announces. The Python peer learns the
     ratchet from the announce, sends a packet encrypted to it, and the Rust
     side decrypts it and proves it, with the ratchet the app copy's
     announce made, from the state every clone shares: Transport's registered
     copy, which decrypts, was cloned before that announce, and a decrypt
     that needed a reload from disk is a FAIL.
  b  The Rust process restarts on the same identity and ratchet file.
     enable_ratchets resets latest_ratchet_time, so its first announce rotates.
     After that announce the peer encrypts to the NEW ratchet and Rust
     decrypts; a packet encrypted to the previous ratchet still decrypts.
     Neither may need a reload from disk.
  d  The reverse: a Python IN destination with ratchets announces, the Rust
     peer encrypts to the announced ratchet, Python decrypts it with that
     ratchet (not the identity key) and proves it.
  c  (a fresh hub that has never heard the Rust destination, in gateway mode
     so it searches for unknown paths). The Rust process restarts again; its
     app copy rotates without sending (the registered copy Transport holds is
     now older than the app copy). A fresh Python peer requests a path, and
     Transport answers from a clone of its registered copy ("[PR-SELF]" in
     the Rust log). The ratchet in that path response must be one the
     destination's shared state holds, Python encrypts to it and Rust
     decrypts; every ratchet of the app copy's list must still decrypt on the
     registered copy without a reload from disk, and the app copy's list and
     the ratchet file must agree afterwards (no ratchet lost). The Python
     reference then loads the Rust-written ratchet file with its own
     _reload_ratchets and must get the same ratchets (each ratchet bin, as it
     writes them; until 2026-09-27 this stack wrote arrays of integers).

Exit 0 only if every scenario passes.
"""
import hashlib
import os
import queue
import re
import subprocess
import sys
import threading
import time

APP_NAME, ASPECT, PEER_ASPECT = "interop", "ratchet", "ratchet_py"
PROOF_LATE_S = 5.0     # DESIGN_PRINCIPLES §1: a later proof is a failure
EVENT_CEILING_S = 15   # a missing event becomes a FAIL after this
START_CEILING_S = 60   # interpreter start + RNS init (Python import alone is ~3 s here)


def emit(line):
    print(line, flush=True)


# ── hub and peer (the Python reference ends) ────────────────────────────────

def hub(config_dir):
    import RNS
    RNS.Reticulum(config_dir)
    emit("HUB ready")
    servers = [i for i in RNS.Transport.interfaces if type(i).__name__ == "TCPServerInterface"]
    last = None
    while True:
        # Evidence and the attach event for the orchestrator: how many peers
        # are connected right now.
        n = sum(len(s.spawned_interfaces or []) for s in servers)
        if n != last:
            emit(f"@@PEERS {n}")
            last = n
        time.sleep(0.1)


def peer(config_dir):
    import RNS
    RNS.Reticulum(config_dir)
    online = all(getattr(i, "online", False) for i in RNS.Transport.interfaces)
    emit(f"@@READY online={int(online)}")

    watched = set()

    class Handler:
        aspect_filter = f"{APP_NAME}.{ASPECT}"
        receive_path_responses = True

        def received_announce(self, destination_hash, announced_identity, app_data, announce_packet_hash, is_path_response):
            if destination_hash in watched:
                ratchet = RNS.Identity.get_ratchet(destination_hash)
                emit(f"@@HEARD path_response={int(bool(is_path_response))} ratchet={ratchet.hex() if ratchet else 'none'}")

    RNS.Transport.register_announce_handler(Handler())
    in_dest = None

    def send(dest_hash, tag, ratchet_hex):
        identity = RNS.Identity.recall(dest_hash)
        if identity is None:
            return emit(f"@@UNPROVEN {tag} identity not recalled")
        dest = RNS.Destination(identity, RNS.Destination.OUT, RNS.Destination.SINGLE, APP_NAME, ASPECT)
        if ratchet_hex:
            # The reference has no API to pick an older ratchet; encrypt this
            # one packet to the given one.
            forced = bytes.fromhex(ratchet_hex)
            dest.encrypt = lambda plaintext: identity.encrypt(plaintext, ratchet=forced)
            used = ratchet_hex
        else:
            r = RNS.Identity.get_ratchet(dest_hash)
            used = r.hex() if r else "none"
        emit(f"@@SENT {tag} ratchet={used}")
        started = time.time()
        receipt = RNS.Packet(dest, tag.encode()).send()
        if not receipt:
            return emit(f"@@UNPROVEN {tag} no receipt")
        receipt.set_timeout(EVENT_CEILING_S)
        receipt.set_delivery_callback(lambda r: emit(f"@@PROVEN {tag} ms={int((time.time() - started) * 1000)}"))
        receipt.set_timeout_callback(lambda r: emit(f"@@UNPROVEN {tag} receipt timed out"))

    for line in sys.stdin:
        words = line.split()
        if not words:
            continue
        cmd = words[0]
        if cmd == "WATCH":
            watched.add(bytes.fromhex(words[1]))
            emit("@@WATCHING")
        elif cmd == "REQUEST_PATH":
            RNS.Transport.request_path(bytes.fromhex(words[1]))
            emit("@@PATH_REQUESTED")
        elif cmd == "SEND":
            send(bytes.fromhex(words[1]), words[2], words[3] if len(words) > 3 else None)
        elif cmd == "INDEST":
            in_dest = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, PEER_ASPECT)
            in_dest.enable_ratchets(os.path.join(config_dir, "peer_ratchets"))
            in_dest.set_proof_strategy(RNS.Destination.PROVE_ALL)

            def rx(data, packet, d=in_dest):
                rid = packet.ratchet_id
                emit(f"@@INRX {data.decode(errors='replace')} ratchet_id={rid.hex() if rid else 'none'}")

            in_dest.set_packet_callback(rx)
            in_dest.announce()
            pub = RNS.Identity._ratchet_public_bytes(in_dest.ratchets[0])
            emit(f"@@INDEST {in_dest.hash.hex()} ratchet={pub.hex()}")
        elif cmd == "QUIT":
            os._exit(0)
        else:
            emit(f"@@ERROR unknown command {line.strip()}")


def load(identity_path, ratchet_path):
    """Load a ratchet file as the reference does and print its ratchets'
    public keys, newest first."""
    import RNS
    identity = RNS.Identity.from_file(identity_path)
    d = object.__new__(RNS.Destination)
    d.type = RNS.Destination.SINGLE
    d.identity = identity
    d.ratchet_file_lock = threading.Lock()
    d.ratchets = None
    d._reload_ratchets(ratchet_path)
    for r in d.ratchets:
        if not isinstance(r, bytes) or len(r) != 32:
            sys.exit(f"not a ratchet key: {r!r}")
    print(",".join(RNS.Identity._ratchet_public_bytes(r).hex() for r in d.ratchets) or "-")


# ── orchestrator ────────────────────────────────────────────────────────────

class Fail(Exception):
    pass


REGISTRY = os.path.join(os.environ.get("TMPDIR", "/tmp"), "reticulum-interop-ports")


def claim_port():
    """A free 127.0.0.1 port in 20000-31999, claimed in run.sh's registry."""
    import fcntl
    import random
    import socket

    def alive(pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    def free(port):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        finally:
            s.close()
        c = socket.socket()
        c.settimeout(0.5)
        try:
            return c.connect_ex(("127.0.0.1", port)) != 0
        finally:
            c.close()

    with open(REGISTRY, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        entries = [l.split() for l in f.read().splitlines()]
        entries = [(int(p), r) for p, r in (e for e in entries if len(e) == 2) if alive(int(r))]
        taken = {p for p, _ in entries}
        for port in random.sample(range(20000, 32000), 12000):
            if port not in taken and free(port):
                break
        else:
            raise Fail("no free port in 20000-31999")
        entries.append((port, str(os.getpid())))
        f.seek(0)
        f.truncate()
        f.write("".join(f"{p} {r}\n" for p, r in entries))
    return port


def release_ports():
    import fcntl
    try:
        with open(REGISTRY, "a+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.seek(0)
            keep = [l for l in f.read().splitlines() if len(l.split()) == 2 and l.split()[1] != str(os.getpid())]
            f.seek(0)
            f.truncate()
            f.write("".join(k + "\n" for k in keep))
    except OSError:
        pass


def config(path, port, transport, mode=None):
    os.makedirs(path, exist_ok=True)
    if transport:
        iface = f"type = TCPServerInterface\n    listen_ip = 127.0.0.1\n    listen_port = {port}"
    else:
        iface = f"type = TCPClientInterface\n    target_host = 127.0.0.1\n    target_port = {port}"
    if mode:
        # `mode`, not `interface_mode`: rns 1.5.2's _synthesize_interface
        # reads c["mode"] for "gateway" whichever key was given, and raises
        # KeyError for `interface_mode = gateway`.
        iface += f"\n    mode = {mode}"
    with open(os.path.join(path, "config"), "w") as f:
        f.write(f"""[reticulum]
  enable_transport = {'true' if transport else 'false'}
  share_instance = false

[logging]
  loglevel = {os.environ.get('INTEROP_LOGLEVEL', '3')}

[interfaces]
  [[Interop]]
    {iface}
    enabled = true
""")


class Proc:
    """A child process whose stdout lines are kept, in order, for expect()."""

    def __init__(self, name, cmd, log_dir):
        self.name = name
        self.lines = []            # every stdout line so far
        self.cursor = 0            # expect() searches from here
        self.cond = threading.Condition()
        self.out_path = os.path.join(log_dir, f"{name}.out")
        self.err = open(os.path.join(log_dir, f"{name}.err"), "w")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err, text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        with open(self.out_path, "w") as out:
            for line in self.p.stdout:
                out.write(line)
                out.flush()
                with self.cond:
                    self.lines.append(line.rstrip("\n"))
                    self.cond.notify_all()
        with self.cond:
            self.cond.notify_all()

    def send(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()

    def mark(self):
        with self.cond:
            return len(self.lines)

    def expect(self, pattern, what, ceiling=EVENT_CEILING_S, fail_pattern=None):
        """The first line from the cursor on matching `pattern`; advances the
        cursor past it. A line matching `fail_pattern` first, the process
        exiting, or the ceiling passing is a Fail."""
        rx = re.compile(pattern)
        frx = re.compile(fail_pattern) if fail_pattern else None
        deadline = time.time() + ceiling
        with self.cond:
            while True:
                while self.cursor < len(self.lines):
                    line = self.lines[self.cursor]
                    self.cursor += 1
                    if frx and frx.search(line):
                        raise Fail(f"{what}: {self.name} printed {line!r}")
                    m = rx.search(line)
                    if m:
                        return m
                if self.p.poll() is not None:
                    raise Fail(f"{what}: {self.name} exited ({self.p.returncode}) first")
                left = deadline - time.time()
                if left <= 0:
                    raise Fail(f"{what}: not seen from {self.name} within {ceiling} s")
                self.cond.wait(min(left, 0.5))

    def between(self, start, end, pattern):
        rx = re.compile(pattern)
        with self.cond:
            return [l for l in self.lines[start:end] if rx.search(l)]

    def stop(self):
        if self.p.poll() is None:
            try:
                self.send("QUIT")
            except (BrokenPipeError, OSError):
                pass
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.terminate()
                try:
                    self.p.wait(5)
                except subprocess.TimeoutExpired:
                    emit(f"      ({self.name} still up 5 s after SIGTERM; sent SIGKILL)")
                    self.p.kill()
                    self.p.wait()
        self.err.close()

    def tail(self, n=25):
        with self.cond:
            return self.lines[-n:]


def ratchet_id(pub_hex):
    return hashlib.sha256(bytes.fromhex(pub_hex)).digest()[:10].hex()


def run(rust_bin, work):
    py = sys.executable
    me = os.path.abspath(__file__)
    procs = []
    results = {}   # scenario -> (ok, detail)
    notes = []

    def start(name, cmd):
        p = Proc(name, cmd, work)
        procs.append(p)
        return p

    def stop(p):
        p.stop()
        procs.remove(p)

    def start_hub(name, port, mode=None):
        d = os.path.join(work, name)
        config(d, port, True, mode)
        h = start(name, [py, me, "hub", d])
        h.expect(r"^HUB ready", f"{name} ready", START_CEILING_S)
        h.expect(r"^@@PEERS 0$", f"{name} listening", START_CEILING_S)
        return h

    def start_peer(name, port, hub, peers_after):
        d = os.path.join(work, name)
        config(d, port, False)
        p = start(name, [py, me, "peer", d])
        m = p.expect(r"^@@READY online=(\d)", f"{name} ready", START_CEILING_S)
        hub.expect(rf"^@@PEERS {peers_after}$", f"{name} attached to the hub", START_CEILING_S)
        return p

    rust_config = os.path.join(work, "rust")
    rust_state = os.path.join(work, "rust-state")

    def start_rust(name, port, hub, peers_after):
        config(rust_config, port, False)
        r = start(name, [rust_bin, "node", rust_config, rust_state])
        m = r.expect(r"^@@DEST ([0-9a-f]{32}) list=(\S+)", f"{name} destination", START_CEILING_S)
        hub.expect(rf"^@@PEERS {peers_after}$", f"{name} attached to the hub", START_CEILING_S)
        return r, m.group(1), m.group(2)

    def proven(p, tag, what):
        m = p.expect(rf"^@@(PROVEN|UNPROVEN) {re.escape(tag)}\b(.*)", what, EVENT_CEILING_S + 5)
        if m.group(1) != "PROVEN":
            raise Fail(f"{what}: {m.group(0)}")
        ms = int(re.search(r"ms=(\d+)", m.group(2)).group(1))
        if ms > PROOF_LATE_S * 1000:
            raise Fail(f"{what}: proof after {ms} ms (DESIGN_PRINCIPLES §1: over 5 s is a failure)")
        return ms

    rust_rx_fail = r"\[DEST-RX\] ERROR"

    def py_to_rust(peer, rust, dest, tag, ratchet_hex=None):
        """Python sends one packet; Rust must decrypt it (RX) and prove it.
        Returns (ms, whether Rust had to reload its ratchets from disk)."""
        start_mark = rust.mark()
        peer.send(f"SEND {dest} {tag}" + (f" {ratchet_hex}" if ratchet_hex else ""))
        sent = peer.expect(rf"^@@SENT {re.escape(tag)} ratchet=(\S+)", f"{tag} sent").group(1)
        rust.expect(rf"^@@RX {re.escape(tag)}$", f"{tag}: Rust decrypts it", EVENT_CEILING_S, rust_rx_fail)
        ms = proven(peer, tag, f"{tag}: proof reaches Python")
        reloaded = bool(rust.between(start_mark, rust.mark(), r"\[RATCHET\] decrypt failed with"))
        return sent, ms, reloaded

    try:
        port1 = claim_port()
        hub1 = start_hub("hub1", port1)
        peer1 = start_peer("peer1", port1, hub1, 1)

        # ── a ──
        try:
            rust1, dest, initial = start_rust("rust1", port1, hub1, 2)
            if initial != "-":
                raise Fail(f"a fresh ratchet file loaded ratchets: {initial}")
            peer1.send(f"WATCH {dest}")
            peer1.expect(r"^@@WATCHING", "peer watching")
            rust1.send("ANNOUNCE")
            m = rust1.expect(r"^@@ANNOUNCED rotated=(\d) ratchet=(\S+) list=(\S+)", "Rust announces")
            if m.group(1) != "1":
                raise Fail(f"the first announce did not rotate: {m.group(0)}")
            r_a = m.group(2)
            announced_at = time.time()   # not earlier than the announce's emission second
            heard = peer1.expect(r"^@@HEARD path_response=0 ratchet=(\S+)", "Python hears the announce").group(1)
            if heard != r_a:
                raise Fail(f"Python learned ratchet {heard}, Rust announced {r_a}")
            sent, ms, reloaded = py_to_rust(peer1, rust1, dest, "a1")
            if sent != r_a:
                raise Fail(f"Python encrypted to {sent}, not the announced {r_a}")
            if reloaded:
                raise Fail("a1 decrypted only after a ratchet reload from disk: Transport's registered copy, "
                           "cloned before the app copy's first announce, did not take that announce's ratchet from the shared state")
            results["a"] = (True, f"announced ratchet {r_a[:16]}.. learned by Python; packet to it decrypted by Rust with no reload, proof in {ms} ms")
        except Fail as e:
            results["a"] = (False, str(e))
            raise
        stop(rust1)
        hub1.expect(r"^@@PEERS 1$", "rust1 detached from the hub")

        # ── b ──
        try:
            rust2, dest2, loaded = start_rust("rust2", port1, hub1, 2)
            if dest2 != dest:
                raise Fail(f"restart changed the destination hash: {dest2} != {dest}")
            if loaded != r_a:
                raise Fail(f"restart loaded list {loaded}, the ratchet file should hold [{r_a}]")
            # The reference orders two announces of one destination by the
            # emission time in their random blobs, in whole seconds
            # (Transport.inbound: `announce_emitted > path_timebase`): an
            # announce emitted in the same second as the one the peer holds is
            # not a newer announce, the path is not updated and no announce
            # handler runs. A process restarting within that second is
            # invisible to the reference, whichever stack emits it, so the
            # restarted announce goes out in a later second.
            while int(time.time()) <= int(announced_at):
                time.sleep(int(announced_at) + 1 - time.time() + 0.01)
            rust2.send("ANNOUNCE")
            m = rust2.expect(r"^@@ANNOUNCED rotated=(\d) ratchet=(\S+) list=(\S+)", "restarted Rust announces")
            if m.group(1) != "1":
                raise Fail(f"the first announce after a restart did not rotate (latest_ratchet_time not reset): {m.group(0)}")
            r_b = m.group(2)
            if m.group(3) != f"{r_b},{r_a}":
                raise Fail(f"list after the restart's rotation is {m.group(3)}, wanted {r_b},{r_a}")
            heard = peer1.expect(r"^@@HEARD path_response=0 ratchet=(\S+)", "Python hears the new announce").group(1)
            if heard != r_b:
                raise Fail(f"after the new announce Python holds ratchet {heard}, Rust announced {r_b}")
            sent, ms_new, rl_new = py_to_rust(peer1, rust2, dest, "b-new")
            if sent != r_b:
                raise Fail(f"Python encrypted to {sent}, not the new {r_b}")
            sent, ms_old, rl_old = py_to_rust(peer1, rust2, dest, "b-old", r_a)
            reloads = [t for t, rl in (("b-new", rl_new), ("b-old", rl_old)) if rl]
            if reloads:
                raise Fail(f"{', '.join(reloads)} decrypted only after a ratchet reload from disk: Transport's registered copy, "
                           "cloned before the app copy's first announce, did not take that announce's ratchet from the shared state")
            results["b"] = (True, f"restart rotated {r_a[:16]}.. -> {r_b[:16]}..; packet to the new ratchet proven in {ms_new} ms, "
                                  f"packet to the previous ratchet proven in {ms_old} ms, neither needing a reload")
        except Fail as e:
            results["b"] = (False, str(e))
            raise

        # ── d ──
        try:
            peer1.send("INDEST")
            m = peer1.expect(r"^@@INDEST ([0-9a-f]{32}) ratchet=(\S+)", "Python IN destination announces")
            py_dest, py_ratchet = m.group(1), m.group(2)
            rust2.send(f"SEND {py_dest} d1")
            used = rust2.expect(r"^@@SENDING d1 ratchet=(\S+)", "Rust sends to the Python destination").group(1)
            if used != py_ratchet:
                raise Fail(f"Rust encrypted to ratchet {used}, Python announced {py_ratchet}")
            rid = peer1.expect(r"^@@INRX d1 ratchet_id=(\S+)", "Python decrypts").group(1)
            if rid != ratchet_id(py_ratchet):
                raise Fail(f"Python decrypted with ratchet id {rid}, wanted {ratchet_id(py_ratchet)} (the announced ratchet)")
            ms = proven(rust2, "d1", "proof reaches Rust")
            results["d"] = (True, f"Rust encrypted to Python's announced ratchet {py_ratchet[:16]}..; Python decrypted with ratchet id {rid}; proof in {ms} ms")
        except Fail as e:
            results["d"] = (False, str(e))
            raise
        for p in (rust2, peer1, hub1):
            stop(p)

        # ── c ──
        try:
            port2 = claim_port()
            hub2 = start_hub("hub2", port2, "gateway")
            peer2 = start_peer("peer2", port2, hub2, 1)
            rust3, dest3, loaded = start_rust("rust3", port2, hub2, 2)
            if loaded != f"{r_b},{r_a}":
                raise Fail(f"second restart loaded {loaded}, wanted {r_b},{r_a}")
            rust3.send("ROTATE_SILENT")
            m = rust3.expect(r"^@@ROTATED rotated=(\d) ratchet=(\S+) list=(\S+)", "app copy rotates (unsent)")
            if m.group(1) != "1":
                raise Fail(f"the app copy did not rotate: {m.group(0)}")
            r_c, app_list = m.group(2), m.group(3).split(",")
            if app_list != [r_c, r_b, r_a]:
                raise Fail(f"app copy list {app_list}, wanted [{r_c}, {r_b}, {r_a}]")
            peer2.send(f"WATCH {dest}")
            peer2.expect(r"^@@WATCHING", "peer watching")
            mark = rust3.mark()
            peer2.send(f"REQUEST_PATH {dest}")
            heard = peer2.expect(r"^@@HEARD path_response=(\d) ratchet=(\S+)", "Python hears the path response")
            if heard.group(1) != "1":
                raise Fail(f"Python heard a non-path-response announce: {heard.group(0)}")
            r_pr = heard.group(2)
            pr_self = [l for l in rust3.between(mark, rust3.mark(), r"\[PR-SELF\] responding with announce") if dest in l.replace(":", "")]
            if not pr_self:
                raise Fail("the path response did not come from the Rust Transport's clone (no [PR-SELF] line)")
            if r_pr not in app_list:
                raise Fail(f"the path response carried ratchet {r_pr}, which the destination's shared state does not hold ({app_list})")
            sent, ms_pr, rl_pr = py_to_rust(peer2, rust3, dest, "c-pr")
            if sent != r_pr:
                raise Fail(f"Python encrypted to {sent}, not the path response's {r_pr}")
            reloaded = []
            for i, r in enumerate(app_list):
                _, _, rl = py_to_rust(peer2, rust3, dest, f"c-{i}", r)
                if rl:
                    reloaded.append(f"c-{i} ({r[:16]}..)")
            if rl_pr:
                reloaded.insert(0, "c-pr")
            if reloaded:
                raise Fail(f"after the path response the registered copy lacked {', '.join(reloaded)}: decrypted only after a reload from disk")
            rust3.send("LISTS")
            m = rust3.expect(r"^@@LISTS rotated=(\d) app=(\S+) file=(\S+)", "ratchet lists")
            if m.group(1) != "0":
                raise Fail(f"syncing the app copy rotated again: {m.group(0)}")
            if m.group(2) != m.group(3):
                raise Fail(f"app copy list {m.group(2)} != ratchet file {m.group(3)}")
            if m.group(2).split(",") != app_list:
                raise Fail(f"app copy list changed to {m.group(2)} from {','.join(app_list)} (a ratchet was lost or replaced)")
            loaded = subprocess.run([py, me, "load", os.path.join(rust_state, "identity"), os.path.join(rust_state, "ratchets")],
                                    capture_output=True, text=True)
            if loaded.returncode != 0:
                raise Fail(f"the Python reference could not load the Rust ratchet file: {(loaded.stderr or loaded.stdout).strip()[-400:]}")
            if loaded.stdout.strip() != m.group(3):
                raise Fail(f"the Python reference loaded {loaded.stdout.strip()} from the Rust ratchet file, which holds {m.group(3)}")
            results["c"] = (True, f"path response from Transport's clone carried {r_pr[:16]}.. (the app copy's newest, {'==' if r_pr == r_c else '!='} r_c); "
                                  f"proven in {ms_pr} ms; all {len(app_list)} ratchets decrypted on the registered copy with no reload; app list == file list; "
                                  f"the Python reference loads the Rust ratchet file")
        except Fail as e:
            results["c"] = (False, str(e))
            raise
    except Fail as e:
        emit(f"ABORT {e}")
        for p in list(procs):
            emit(f"      --- {p.name} (last lines) ---")
            for l in p.tail():
                emit(f"      | {l}")
    finally:
        for p in list(procs):
            p.stop()
        release_ports()

    ok = True
    for s in ("a", "b", "c", "d"):
        if s in results:
            passed, detail = results[s]
            emit(f"{'PASS' if passed else 'FAIL'}  {s}: {detail}")
            ok = ok and passed
        else:
            emit(f"FAIL  {s}: not run (an earlier scenario failed)")
            ok = False
    for n in notes:
        emit(f"NOTE  {n}")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "hub":
        hub(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "peer":
        peer(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "load":
        load(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "run":
        sys.exit(run(os.path.abspath(sys.argv[2]), os.path.abspath(sys.argv[3])))
    else:
        sys.exit(__doc__)
