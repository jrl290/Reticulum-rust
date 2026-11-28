#!/usr/bin/env python3
"""
The gateway's list, over loopback: discovery's working set goes from rnsd's
PostInterface to a Reticulum-post PHP node, which serves it at GET
/v1/servers as the servers every Retichat connects to first (Reticulum-post
GatewayServers; James, 2026-11-28: "The gateway's list").

Four stock backbones announce themselves through a seed, as in
discovery_autoconnect.py, whose helpers this uses. The rnsd under test runs
discovery with two auto-connects and a PostInterface in wake mode, as the
house gateway does, so an exchange goes only when something starts one. Its
transport identity is made first, so that the PHP node's
[servers] gateway_identity_hash can name it. Steps:

  1. the two backbones rnsd connects to are what the PHP node lists, as the
     working file holds them, within seconds of the file;
  2. one of them stopped: once it is detached the PHP node lists the other
     alone, within seconds, and then the pair with its replacement;
  3. a restart: rnsd sends the list again after its registration.

  python3 tests/interop/gateway_servers.py [rnsd] [Reticulum-post php/src]

Exit 0 only if every step passes. INTEROP_KEEP=dir keeps the run's configs
and logs there. INTEROP_PHP_MYSQL_DB=name runs the PHP node on that database of
the private MySQL on 127.0.0.1:3307 (user reticulum, as php/config.php's
staging block), as retichat.com runs on MySQL; SQLite otherwise.
"""

import json
import os
import re
import shutil
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import discovery_autoconnect as da  # noqa: E402

PHP = shutil.which("php")
LISTED_WITHIN = 10   # seconds from a change of the working file to the PHP node's list
DETACHED_WITHIN = da.DETACH_THRESHOLD + 4 * da.MONITOR_INTERVAL


def listed(base):
    # What the PHP node gives the apps, as host:port, sorted like the working file.
    try:
        with urllib.request.urlopen(base + "/v1/servers", timeout=3) as answer:
            return sorted(f"{s['host']}:{s['port']}" for s in json.load(answer)["servers"])
    except Exception:
        return None


def main():
    rnsd = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(da.ROOT, "target", "debug", "rnsd")
    php_src = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(da.ROOT, "..", "Reticulum-post", "php", "src")
    if not os.access(rnsd, os.X_OK):
        print(f"No rnsd at {rnsd}; build it with: cargo build --bin rnsd")
        return 2
    if PHP is None or not os.path.exists(os.path.join(php_src, "lib", "gateway_servers.php")):
        print(f"Needs php and a Reticulum-post php/src with GatewayServers (looked in {php_src})")
        return 2
    py_rnsd = os.path.join(os.path.dirname(da.PY), "rnsd")
    run = da.Run(rnsd)
    try:
        return scenario(run, py_rnsd, php_src)
    finally:
        run.stop_all()
        keep = os.environ.get("INTEROP_KEEP")
        if keep:
            shutil.copytree(run.dir, os.path.join(keep, os.path.basename(run.dir)))
        if run.failed:
            for path in ["rust.log", "rust-2.log", "php.log", "php/router.log"]:
                path = os.path.join(run.dir, path)
                if os.path.exists(path) and os.path.getsize(path):
                    print(f"\n----- tail of {os.path.relpath(path, run.dir)} -----")
                    print("".join(open(path, errors="replace").readlines()[-40:]), end="")
        shutil.rmtree(run.dir, ignore_errors=True)


def scenario(run, py_rnsd, php_src):
    import RNS

    seed_port = da.free_port("127.0.0.1")
    ports = {n: da.free_port("::1") for n in range(1, da.BACKBONES + 1)}
    php_port = da.free_port("127.0.0.1")
    wake_port = da.free_port("127.0.0.1")
    node = "[reticulum]\n  enable_transport = Yes\n  share_instance = No\n\n[logging]\n  loglevel = 4\n\n"

    # rnsd's transport identity, made before anything starts: the PHP node names it.
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

  [[RNS PostInterface]]
    type = PostInterface
    enabled = yes
    node_url = http://127.0.0.1:{php_port}
    wake_url = http://127.0.0.1:{wake_port}/v1/wake
    wake_listen_host = 127.0.0.1
    wake_listen_port = {wake_port}
    mode = gateway
""")
    os.makedirs(os.path.join(rust, "storage"), exist_ok=True)
    identity = RNS.Identity()
    identity.to_file(os.path.join(rust, "storage", "transport_identity"))

    # The PHP node: a copy of php/src with its own config.
    php_dir = os.path.join(run.dir, "php")
    src = os.path.join(php_dir, "src")
    shutil.copytree(php_src, src, ignore=shutil.ignore_patterns("config.*", "build.json"))
    mysql_db = os.environ.get("INTEROP_PHP_MYSQL_DB")
    storage = (f'[storage]\nbackend = "mysql"\nmysql_host = "127.0.0.1"\nmysql_port = 3307\nmysql_dbname = "{mysql_db}"\n'
               f'mysql_user = "reticulum"\nmysql_pass = "local-test-only"\nlog_path = "{php_dir}/router.log"\n') if mysql_db else \
              f'[storage]\nbackend = "sqlite"\nsqlite_path = "{php_dir}/node.sqlite"\nlog_path = "{php_dir}/router.log"\n'
    with open(os.path.join(src, "config.toml"), "w") as f:
        f.write(f'host_url = "http://127.0.0.1:{php_port}"\n' + storage +
                f'[maintenance]\ninterface_stale_after_seconds = 30\n'
                f'[servers]\ngateway_identity_hash = "{identity.hash.hex()}"\n')
    run.start("php", [PHP, "-S", f"127.0.0.1:{php_port}", "-t", src, os.path.join(src, "index.php")])
    base = f"http://127.0.0.1:{php_port}"
    end = time.time() + 15
    while listed(base) is None and time.time() < end:
        time.sleep(0.2)
    if listed(base) != []:
        return run.fail(f"the PHP node did not answer an empty list: {listed(base)}") or 1
    run.say(f"PHP node on {base}, listing nothing; it takes the list from {identity.hash.hex()}")

    seed = run.config("seed", node + f"""[interfaces]
  [[Seed Server]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {seed_port}
""")
    run.start("seed", [py_rnsd, "--config", seed])
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
        run.start(f"backbone{n}", [da.PY, da.__file__, "--backbone", backbone])
    run.say(f"seed on 127.0.0.1:{seed_port}; backbones on ::1:{list(ports.values())}")

    backbone_of = {port: n for n, port in ports.items()}
    connected = lambda: {backbone_of[p] for p in run.connected_ports("rust") if p in backbone_of}
    working_file = os.path.join(rust, "storage", "discovery", "working_interfaces")
    working = lambda: da.read_working(working_file)

    def listed_as_working(step, size):
        held = run.wait_for(f"a working file of {size}", da.ANNOUNCE_DEADLINE, lambda: len(working()) == size and working())
        if not held:
            return None
        since = time.time()
        if not run.wait_for(f"list of {held} at the PHP node", LISTED_WITHIN, lambda: listed(base) == working()):
            run.say(f"the PHP node lists {listed(base)}")
            return None
        run.say(f"{step}: the working file holds {held}; the PHP node lists the same {time.time() - since:.1f} s later")
        return held

    # 1. The two auto-connected backbones are what the PHP node lists.
    if not run.wait_for("two auto-connected backbones", da.ANNOUNCE_DEADLINE, lambda: len(connected()) == 2 and connected()):
        return 1
    first = listed_as_working("1", 2)
    if not first:
        return 1
    if run.count(r"keeps the gateway's 2 servers") < 1:
        return run.fail("rnsd did not log that the PHP node keeps its 2 servers") or 1

    # 2. One stopped: after the detach the other alone, then the pair with its replacement.
    gone = backbone_of[int(first[0].rsplit(":", 1)[1])]
    run.stop(f"backbone{gone}")
    stopped = time.time()
    run.say(f"stopped backbone {gone}")
    if not run.wait_for("the detach", DETACHED_WITHIN, lambda: len(working()) == 1):
        return 1
    run.say(f"detached {time.time() - stopped:.1f} s after the stop")
    if not listed_as_working("2a", 1):
        return 1
    second = listed_as_working("2b", 2)
    if not second:
        return 1
    if f"::1:{ports[gone]}" in second:
        return run.fail(f"the stopped backbone is listed again: {second}") or 1

    # 3. A restart sends the list again after the registration.
    run.stop("rust")
    run.start("rust", rust_argv, logname="rust-2")
    if not run.wait_for("the list sent again", 30, lambda: "keeps the gateway's 2 servers" in run.log("rust")):
        return 1
    if listed(base) != working():
        return run.fail(f"after the restart the PHP node lists {listed(base)}, the file holds {working()}") or 1
    run.say(f"3: restarted; the list went again after the registration; the PHP node lists {listed(base)}")

    exchanges = len(re.findall(r"PostInterface exchange req", run.log("rust")))
    run.say(f"PASS ({exchanges} exchanges in the restart's log)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
