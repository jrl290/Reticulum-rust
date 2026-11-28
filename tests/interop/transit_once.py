#!/usr/bin/env python3
"""A packet in transit goes out once, in the reference's form, and not along
an echo route while its path's interface is down: the rnsd under test among
stock Python RNS nodes, over loopback.

    ../.venv/bin/python tests/interop/transit_once.py [path/to/rnsd]

Everything runs on 127.0.0.1, each node with its own config folder in a
temporary directory; nothing reads or writes ~/.reticulum. The rnsd under
test (default target/debug/rnsd) is a transport node at loglevel 6, so its
log has a `[DISPATCH-OUT]` line for every frame it queues. It has a TCP
server ("LAN") for the senders, and dials three stock nodes:

  "Near Sink"    a sink one hop away, so the next hop is the destination;
  "Relay"        a stock transport node with a second sink, "far", behind
                 it, two hops away;
  "Echo Direct"  a third sink one hop away. Its announces also come back to
                 rnsd through Relay, which rebroadcasts what rnsd
                 rebroadcast to it: an echo route, three hops, the same
                 announce.

Steps, each judged on its own:
  1. 200 packets to the near sink: rnsd queues each once for Near Sink,
     stripped to HEADER_1 (RNS/Transport.py, remaining_hops == 1), and all
     arrive;
  2. 200 packets to the far sink: each is queued once for Relay, the hop
     count and Relay's transport_id written in (remaining_hops > 1), and all
     arrive;
  3. the echo sink stops, so Echo Direct is offline, and 100 packets are sent
     to it: rnsd queues none of them anywhere, not along the echo route
     through Relay either, and says why;
  4. the echo sink comes back, with its identity, and rnsd dials it again:
     50 packets reach it, each queued once.

Exit 0 only if every step passes. INTEROP_KEEP=dir keeps the run's configs
and logs there.
"""

import os
import re
import shutil
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from discovery_autoconnect import Run, free_port  # noqa: E402
from egress_and_hub_return import flood_mode, read  # noqa: E402

PY = sys.executable
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA_FRAME = 300   # bytes: frames longer than this are the test's packets (about 400), not announces
STEPS = 4


def sink_mode(configdir):
    # A stock node hosting egresstest.sink under an identity kept in its
    # config folder, so it comes back with the same destination. It counts
    # what it receives and announces every 10 s.
    import RNS
    RNS.Reticulum(configdir=configdir)
    id_path = os.path.join(configdir, "sink_identity")
    identity = RNS.Identity.from_file(id_path) if os.path.exists(id_path) else None
    if identity is None:
        identity = RNS.Identity()
        identity.to_file(id_path)
    # The name egress_and_hub_return.flood_mode sends to.
    sink = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "egresstest", "sink")
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


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--sink":
        return sink_mode(sys.argv[2])
    if len(sys.argv) > 6 and sys.argv[1] == "--flood":
        return flood_mode(*sys.argv[2:7])

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
        run.stop_all()
        print("\nSteps:")
        for step, ok, detail in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {step}: {detail}")
        keep = os.environ.get("INTEROP_KEEP")
        if keep:
            shutil.copytree(run.dir, os.path.join(keep, os.path.basename(run.dir)))
        shutil.rmtree(run.dir, ignore_errors=True)
    passed = len(results) == STEPS and all(ok for _, ok, _ in results)
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


def scenario(run, py_rnsd, results):
    def step(name, ok, detail):
        results.append((name, bool(ok), detail))
        run.say(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
        return bool(ok)

    lan_port, near_port, relay_port, echo_port = (free_port("127.0.0.1") for _ in range(4))
    node = "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n\n[logging]\n  loglevel = 4\n\n"
    leaf = "[reticulum]\n  enable_transport = No\n  share_instance = No\n\n[logging]\n  loglevel = 4\n\n"

    def server(name, port):
        return f"  [[{name}]]\n    type = TCPServerInterface\n    enabled = yes\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n"

    def client(name, port):
        return f"  [[{name}]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {port}\n"

    me = os.path.abspath(__file__)
    near = run.config("near", leaf + "[interfaces]\n" + server("Near Server", near_port))
    run.start("near", [PY, me, "--sink", near])
    echo = run.config("echo", leaf + "[interfaces]\n" + server("Echo Server", echo_port))
    run.start("echo", [PY, me, "--sink", echo])
    relay = run.config("relay", node + "[interfaces]\n" + server("Relay Server", relay_port))
    run.start("relay", [py_rnsd, "--config", relay])
    time.sleep(2)

    # The transport node starts before the sinks behind it announce.
    rust = run.config("rust", "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n\n"
                      "[logging]\n  loglevel = 6\n\n[interfaces]\n" + server("LAN", lan_port)
                      + client("Near Sink", near_port) + client("Relay", relay_port) + client("Echo Direct", echo_port))
    run.start("rust", [run.rnsd, "--config", rust, "-v", "-v", "-v"])
    far = run.config("far", leaf + "[interfaces]\n" + client("To Relay", relay_port))
    run.start("far", [PY, me, "--sink", far])
    run.say(f"LAN :{lan_port}; near sink :{near_port}; relay :{relay_port} with the far sink behind it; "
            f"echo sink :{echo_port}")

    if not run.wait_for("rnsd's connections to the near sink, the relay and the echo sink", 60,
                        lambda: {near_port, relay_port, echo_port} <= run.connected_ports("rust")):
        return

    def frames(iface):
        # Sizes of the data frames rnsd has queued for `iface` so far.
        return [int(n) for n in re.findall(rf"\[DISPATCH-OUT\] iface={re.escape(iface)} raw_len=(\d+)", run.log("rust"))
                if int(n) > DATA_FRAME]

    def flooder(name, sink_dir, count, rate):
        cdir = run.config(name, leaf + "[interfaces]\n" + client("To rnsd", lan_port))
        go = os.path.join(cdir, "go")
        run.start(name, [PY, os.path.abspath(__file__), "--flood", cdir, read(os.path.join(sink_dir, "sink")),
                         str(count), str(rate), go])
        ready = run.wait_for(f"{name}'s path to its sink", 90, lambda: read(os.path.join(cdir, "ready")))
        return cdir, go, ready

    def send(name, sink_dir, iface, count, rate, before_go=None):
        # Sends `count` packets to the sink in `sink_dir`, and returns what
        # arrived and the frames rnsd queued, by interface, meanwhile.
        cdir, go, ready = flooder(name, sink_dir, count, rate)
        if not (ready and ready.startswith("hops")):
            return None, f"the sender had no path to its sink ({ready})"
        if before_go:
            before_go()
        received_before = int(read(os.path.join(sink_dir, "received"), "0"))
        queued_before = {i: len(frames(i)) for i in ("Near Sink", "Relay", "Echo Direct")}
        marks = {"drop": run.count(r"\[TRANSIT-DROP\]"), "failed": run.count(r"\[DISPATCH\] outbound failed"),
                 "transit": run.count(r"\[TRANSIT\] "), "fwd": run.count(r"\[FWD-DATA\]")}
        open(go, "w").close()
        run.wait_for(f"{name} to send {count} packets", 60,
                     lambda: (read(os.path.join(cdir, "sent")) or "").startswith(f"{count} "))
        # Then until every packet has arrived, or the count stands still for 5 s.
        last, still_since, began = -1, time.time(), time.time()
        while time.time() - began < 60:
            got = int(read(os.path.join(sink_dir, "received"), "0")) - received_before
            if got != last:
                last, still_since = got, time.time()
            if got >= count or time.time() - still_since >= 5:
                break
            time.sleep(0.5)
        run.stop(name)
        queued = {i: frames(i)[queued_before[i]:] for i in queued_before}
        counts = {k: run.count(p) - marks[k] for k, p in (("drop", r"\[TRANSIT-DROP\]"),
                                                            ("failed", r"\[DISPATCH\] outbound failed"),
                                                            ("transit", r"\[TRANSIT\] "), ("fwd", r"\[FWD-DATA\]"))}
        return {"ready": ready, "arrived": last, "queued": queued, **counts}, None

    def sizes(frames_):
        found = {}
        for n in frames_:
            found[n] = found.get(n, 0) + 1
        return " + ".join(f"{c} x {n} bytes" for n, c in sorted(found.items())) or "none"

    def logged(got):
        return (f"[TRANSIT] {got['transit']}, [FWD-DATA] {got['fwd']}, [TRANSIT-DROP] {got['drop']}, "
                f"outbound failures {got['failed']}")

    # 1. One hop: the next hop is the destination.
    got, why = send("one-hop", near, "Near Sink", 200, 100)
    if got:
        q = got["queued"]["Near Sink"]
        h1 = min(q) if q else 0
        step("1 one hop", got["arrived"] == 200 and len(q) == 200 and set(q) == {h1},
             f"{got['arrived']} of 200 arrived ({got['ready']}); rnsd queued {len(q)} data frames for Near Sink "
             f"({sizes(q)}), {len(got['queued']['Relay'])} for Relay, {len(got['queued']['Echo Direct'])} for "
             f"Echo Direct; logged {logged(got)}")
    else:
        step("1 one hop", False, why)

    # 2. Two hops: the next hop is the relay.
    got, why = send("two-hop", far, "Relay", 200, 100)
    if got:
        q = got["queued"]["Relay"]
        step("2 two hops", got["arrived"] == 200 and len(q) == 200 and len(set(q)) == 1,
             f"{got['arrived']} of 200 arrived ({got['ready']}); rnsd queued {len(q)} data frames for Relay "
             f"({sizes(q)}), {len(got['queued']['Near Sink'])} for Near Sink; logged {logged(got)}")
    else:
        step("2 two hops", False, why)

    # 3. The echo sink stops: Echo Direct goes offline while packets come for it.
    def stop_echo():
        offline_before = run.count(r"Interface Echo Direct transitioned offline")
        run.stop("echo")
        run.wait_for("rnsd to see Echo Direct go offline", 30,
                     lambda: run.count(r"Interface Echo Direct transitioned offline") > offline_before)
        time.sleep(1)

    got, why = send("echo-down", echo, "Echo Direct", 100, 50, before_go=stop_echo)
    if got:
        relay_q, direct_q = got["queued"]["Relay"], got["queued"]["Echo Direct"]
        step("3 path down, echo up", not relay_q and not direct_q and got["arrived"] == 0,
             f"100 sent while Echo Direct was offline; rnsd queued {len(relay_q)} data frames for Relay "
             f"(the echo route: {sizes(relay_q)}) and {len(direct_q)} for Echo Direct; logged {logged(got)}")
    else:
        step("3 path down, echo up", False, why)

    # 4. The echo sink comes back with its identity; rnsd dials it again.
    run.start("echo", [PY, me, "--sink", echo])
    if not run.wait_for("rnsd to dial the echo sink again", 180, lambda: echo_port in run.connected_ports("rust")):
        step("4 path back", False, "rnsd did not dial the echo sink again")
        return
    got, why = send("echo-back", echo, "Echo Direct", 50, 50)
    if got:
        q = got["queued"]["Echo Direct"]
        step("4 path back", got["arrived"] == 50 and len(q) == 50 and len(set(q)) == 1 and not got["queued"]["Relay"],
             f"{got['arrived']} of 50 arrived; rnsd queued {len(q)} data frames for Echo Direct ({sizes(q)}), "
             f"{len(got['queued']['Relay'])} for Relay; logged {logged(got)}")
    else:
        step("4 path back", False, why)


if __name__ == "__main__":
    sys.exit(main())
