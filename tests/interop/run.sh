#!/usr/bin/env bash
# Over-MDU request/response interop: every client/server pairing of the Rust
# stack and the Python reference. Both ends connect over loopback TCP to a
# Python reference transport node, so each exchange crosses a transport hop.
#
#   tests/interop/run.sh                             all three size classes
#   tests/interop/run.sh <request_len> <response_len>   one of your choosing
#
# The size classes are each a different code path: one packet each way
# (which is also the regression test for LRRTT reaching the wire before the
# established callback can send a request), one Resource window, and many.
#
# Needs the workspace venv (../.venv with `rns` at the reference version,
# 1.5.2 since 2026-09-22). Exit 0 only if all pass.
#
#   PYTHON=...            interpreter for the Python end (default ../.venv/bin/python)
#   INTEROP_LOGLEVEL=n    RNS loglevel written into every config (default 3)
#   INTEROP_KEEP=dir      on a FAIL, copy every cell's config dir and logs there
#
# Harness hygiene, because every "no announce from the server" flake so far
# was the harness and not the stack:
#   - each cell listens on a port that was probed free and is recorded in a
#     machine-wide registry, so neither this run nor a concurrent one reuses it;
#   - a cell's client starts only once the listener is the process we started
#     (not a leftover from another run) and is accepting connections;
#   - hub, server and client are started as plain commands, so the pid the
#     harness kills IS the process (a backgrounded shell function is a
#     subshell, and killing it orphaned the real process — hundreds of them
#     accumulated, announcing and holding ports, before this was fixed);
#   - every process of a cell is killed and reaped before the next cell starts;
#   - a FAIL prints the tail of every log of that cell.
set -u
cd "$(dirname "$0")/../.."
PY="${PYTHON:-../.venv/bin/python}"
RUST=target/debug/examples/request_resource_interop
SCRIPT=tests/interop/request_resource_interop.py
REGISTRY="${TMPDIR:-/tmp}/reticulum-interop-ports"   # "<port> <run pid>" per line, shared by all runs
# The run that owns the port claims: the top-level invocation, inherited by
# the per-size child invocations.
[ -n "${_INTEROP_RUN_ID:-}" ] || export _INTEROP_RUN_ID=$$

now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
since() { perl -MTime::HiRes=time -e 'printf "%.1fs", time - $ARGV[0]' "$1"; }

# True while <pid> exists and has not exited (a zombie awaiting `wait` has).
running() { local s; s="$(ps -o stat= -p "$1" 2>/dev/null)"; [ -n "$s" ] && [ "${s#Z}" = "$s" ]; }

# Stop <pids...> and reap them. SIGTERM, then SIGKILL for anything still up
# after 5 s; returns only when every one of them is gone.
stop() {
  [ $# -gt 0 ] || return 0
  local p i any
  kill -TERM "$@" 2>/dev/null
  for i in $(seq 1 50); do
    any=0; for p in "$@"; do running "$p" && any=1; done
    [ $any -eq 0 ] && break
    sleep 0.1
  done
  for p in "$@"; do
    if running "$p"; then echo "      (pid $p still up 5 s after SIGTERM; sent SIGKILL)"; kill -KILL "$p" 2>/dev/null; fi
  done
  wait "$@" 2>/dev/null
  return 0
}

release_ports() { # drop every registry entry of this run
  [ "$_INTEROP_RUN_ID" = "$$" ] || return 0
  "$PY" - "$REGISTRY" "$$" <<'PYEOF' 2>/dev/null
import fcntl, sys
path, run = sys.argv[1], sys.argv[2]
with open(path, "a+") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    f.seek(0)
    keep = [l for l in f.read().splitlines() if len(l.split()) == 2 and l.split()[1] != run]
    f.seek(0); f.truncate(); f.write("".join(k + "\n" for k in keep))
PYEOF
}

if [ $# -eq 0 ]; then
  orphans="$(ps -ax -o ppid=,command= | awk '$1 == 1 && /request_resource_interop/ && !/awk/' | wc -l | tr -d ' ')"
  if [ "$orphans" -gt 0 ]; then
    echo "NOTE  $orphans request_resource_interop process(es) left over from earlier runs are still running and loading"
    echo "      this machine. Their ports are avoided. To stop them (only orphans, never a live run's):"
    echo "      ps -ax -o pid=,ppid=,command= | awk '\$2 == 1 && /request_resource_interop/ {print \$1}' | xargs kill"
  fi
  status=0; child=""
  trap '[ -n "$child" ] && { kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null; }; release_ports; exit 143' INT TERM HUP
  for sizes in "100 200" "3000 5000" "60000 250000"; do
    "$0" $sizes & child=$!
    wait "$child" || status=1
    child=""
  done
  release_ports
  exit $status
fi
REQ="$1"; RESP="$2"
WORK="$(mktemp -d)"; LIVE=()
cleanup() { stop ${LIVE[@]+"${LIVE[@]}"}; rm -rf "$WORK"; release_ports; }
trap cleanup EXIT
trap 'exit 143' INT TERM HUP

cargo build --quiet --example request_resource_interop || exit 1

# Print a port on 127.0.0.1 that nothing is bound to or listening on and
# that no live run has claimed, and claim it for this run. Drawn from
# 20000-31999, below the ephemeral ranges (49152+ on macOS, 32768+ on Linux),
# so an outgoing connection cannot be given it between the probe and the
# listener's bind.
claim_port() {
  "$PY" - "$REGISTRY" "$_INTEROP_RUN_ID" <<'PYEOF'
import fcntl, os, random, socket, sys
path, run = sys.argv[1], sys.argv[2]

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

with open(path, "a+") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    f.seek(0)
    entries = [l.split() for l in f.read().splitlines()]
    entries = [(int(p), r) for p, r in (e for e in entries if len(e) == 2) if alive(int(r))]
    taken = {p for p, _ in entries}
    for port in random.sample(range(20000, 32000), 12000):
        if port not in taken and free(port):
            break
    else:
        sys.exit("no free port in 20000-31999")
    entries.append((port, run))
    f.seek(0); f.truncate(); f.write("".join(f"{p} {r}\n" for p, r in entries))
print(port)
PYEOF
}

# Wait until <pid> is the process listening on 127.0.0.1:<port>. Returns 1
# with WHY set if it exits first, if something else holds the port, or after
# 30 s. With lsof the check is ownership of the LISTEN socket and makes no
# connection; without it, a bare connect probe.
wait_listening() { # <pid> <port>
  local pid="$1" port="$2" owners start=$SECONDS
  while [ $(( SECONDS - start )) -lt 30 ]; do
    running "$pid" || { WHY="exited before listening on $port"; return 1; }
    if command -v lsof >/dev/null; then
      owners="$(lsof -nP -a -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | tr '\n' ' ')"
      case " $owners" in *" $pid "*) return 0;; esac
      if [ -n "$owners" ]; then WHY="port $port is held by pid(s) ${owners% } (not ours: $pid)"; return 1; fi
    else
      "$PY" -c 'import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(s.connect_ex(("127.0.0.1", int(sys.argv[1]))))' "$port" && return 0
    fi
    sleep 0.1
  done
  WHY="not listening on $port after 30 s"; return 1
}

# Wait up to <seconds> for <pid> to print a line matching <regex> to <file>.
wait_line() { # <pid> <file> <regex> <seconds>
  local start=$SECONDS
  while [ $(( SECONDS - start )) -lt "$4" ]; do
    grep -qE "$3" "$2" && return 0
    running "$1" || { grep -qE "$3" "$2" && return 0; WHY="exited without printing it"; return 1; }
    sleep 0.1
  done
  WHY="not printed within $4 s"; return 1
}

config() { # <dir> <listen|connect> <port> <transport: true|false>
  mkdir -p "$1"
  local transport="$4"
  if [ "$2" = listen ]; then
    iface="type = TCPServerInterface
    listen_ip = 127.0.0.1
    listen_port = $3"
  else
    iface="type = TCPClientInterface
    target_host = 127.0.0.1
    target_port = $3"
  fi
  cat > "$1/config" <<CFG
[reticulum]
  enable_transport = $transport
  share_instance = false

[logging]
  loglevel = ${INTEROP_LOGLEVEL:-3}

[interfaces]
  [[Interop]]
    $iface
    enabled = true
CFG
}

# The command line of one end. Set into CMD and then run as a plain command,
# never through a function: `f args &` forks a subshell whose pid is what $!
# reports, and killing it leaves the real process running.
end_cmd() { # <rust|python>
  if [ "$1" = rust ]; then CMD=("$RUST"); else CMD=("$PY" "$SCRIPT"); fi
}

show_logs() { # <dir> <name>
  local f
  for f in out err; do
    [ -s "$1/$f" ] || { echo "      --- $2 std$f: (empty)"; continue; }
    echo "      --- $2 std$f (last 15 lines) ---"
    tail -15 "$1/$f" | sed 's/^/      | /'
  done
}

CLIENT_CEILING=260   # the client's own ceilings: 40 s path + 120 s response + 60 s resource
FAILED=0
pair() { # <server kind> <client kind> [hub|rusthub|direct]
  local s="$1" c="$2" topo="${3:-hub}"
  local label="$c client -> $s server" port hpid="" spid="" cpid="" t result="" setup="" timing="" conns=""
  case "$topo" in
    rusthub) label="$label (via Rust hub)";;
    direct)  label="$label (direct, server listens)";;
  esac
  if ! port="$(claim_port)"; then echo "FAIL  $label: harness could not find a free port"; FAILED=1; return; fi
  local hdir="$WORK/hub-$port" sdir="$WORK/$s-server-$port" cdir="$WORK/$c-client-$port"
  mkdir -p "$hdir"; : > "$hdir/out"; : > "$hdir/err"
  LIVE=()

  if [ "$topo" = hub ] || [ "$topo" = rusthub ]; then
    config "$hdir" listen "$port" true; config "$sdir" connect "$port" false
    if [ "$topo" = rusthub ]; then
      # This stack as the transport node in the middle — the gateway's role.
      # It cannot police the medium the way the Python hub does, so this
      # topology checks routing and rebroadcast, not frame sizes.
      end_cmd rust
    else
      end_cmd python
    fi
    t="$(now)"
    "${CMD[@]}" hub "$hdir" > "$hdir/out" 2> "$hdir/err" &
    hpid=$!; LIVE+=("$hpid")
    if ! wait_line "$hpid" "$hdir/out" '^HUB ready' 30; then setup="hub never reported ready ($WHY)"
    elif ! wait_listening "$hpid" "$port"; then setup="hub not listening: $WHY"
    else timing="hub $(since "$t")"; fi
  else
    # No hub: the server is itself the listener and the client connects
    # straight to it. A listener has to send its OWN announces to the peers
    # connected to it, or the client never learns the destination exists.
    config "$sdir" listen "$port" false
  fi
  config "$cdir" connect "$port" false
  mkdir -p "$sdir" "$cdir"; : > "$sdir/out"; : > "$sdir/err"; : > "$cdir/out"; : > "$cdir/err"

  local dest=""
  if [ -z "$setup" ]; then
    end_cmd "$s"; t="$(now)"
    "${CMD[@]}" server "$sdir" > "$sdir/out" 2> "$sdir/err" &
    spid=$!; LIVE+=("$spid")
    if ! wait_line "$spid" "$sdir/out" '^DEST ' 60; then setup="server never printed its destination hash ($WHY)"
    elif [ "$topo" = direct ] && ! wait_listening "$spid" "$port"; then setup="server not listening: $WHY"
    else
      dest="$(sed -n 's/^DEST //p' "$sdir/out" | head -1)"
      timing="${timing:+$timing, }server $(since "$t")"
    fi
  fi

  if [ -z "$setup" ]; then
    end_cmd "$c"; t="$(now)"
    "${CMD[@]}" client "$cdir" "$dest" "$REQ" "$RESP" > "$cdir/out" 2> "$cdir/err" &
    cpid=$!; LIVE+=("$cpid")
    # While it runs, keep a snapshot (every ~2 s) of who is connected to the
    # cell's port: evidence for a FAIL (were both ends attached at all?).
    local start=$SECONDS snap=$SECONDS snapshot
    while running "$cpid"; do
      if [ $(( SECONDS - start )) -ge $CLIENT_CEILING ]; then
        echo "FAIL client still running after ${CLIENT_CEILING} s (harness ceiling)" >> "$cdir/out"; break
      fi
      if [ $(( SECONDS - snap )) -ge 2 ] && command -v lsof >/dev/null; then
        snapshot="$(lsof -nP -iTCP:"$port" 2>/dev/null)"
        running "$cpid" && conns="at $(( SECONDS - start )) s into the client run:
$snapshot"
        snap=$SECONDS
      fi
      sleep 0.2
    done
    timing="${timing:+$timing, }client $(since "$t")"
  fi
  stop ${LIVE[@]+"${LIVE[@]}"}; LIVE=()

  if [ -n "$setup" ]; then
    result="FAIL harness: $setup"
  else
    result="$(grep -E '^(PASS|FAIL)' "$cdir/out" | head -1)"
    local oversize; oversize="$(grep -c '^OVERSIZE' "$hdir/out")"
    [ "$oversize" -gt 0 ] && result="FAIL $oversize frame(s) over the medium MTU: $(grep -m1 '^OVERSIZE' "$hdir/out") [end result: ${result:-none}]"
    # A Resource concludes once. The server prints one RESOURCE line per
    # concluded-callback invocation; two means every inbound Resource is being
    # handed to the application twice.
    local concluded; concluded="$(grep -c '^RESOURCE' "$sdir/out")"
    case "$result" in PASS*) [ "$concluded" -eq 1 ] || result="FAIL the server's resource-concluded callback fired $concluded times for one Resource [end result: $result]";; esac
    grep -q '^RESOURCE .*intact=\(False\|false\)' "$sdir/out" && result="FAIL plain resource arrived corrupted"
  fi
  case "$result" in
    PASS*) echo "PASS  $label: $result ($(grep -c '^REQUEST' "$sdir/out") request(s) seen by server, 0 oversize frames) [port $port; $timing]";;
    *)     echo "FAIL  $label: ${result:-no result}"; FAILED=1
           echo "      port $port; ${timing:-no timings}; pids hub=${hpid:--} server=${spid:--} client=${cpid:--}"
           [ "$topo" != direct ] && show_logs "$hdir" hub
           show_logs "$sdir" "$s server"
           show_logs "$cdir" "$c client"
           if [ -n "$conns" ]; then echo "      --- TCP sockets on port $port, last snapshot while the client ran ---"; echo "$conns" | sed 's/^/      | /'; fi
           [ -n "${INTEROP_KEEP:-}" ] && { mkdir -p "${INTEROP_KEEP}"; cp -r "$WORK"/. "${INTEROP_KEEP}"/; echo "      logs kept in ${INTEROP_KEEP}"; };;
  esac
}

pair python python   # control: proves the harness itself
pair python rust     # Rust sends an over-MDU request; receives an over-MDU response
pair rust python     # Rust receives an over-MDU request; sends an over-MDU response
pair rust rust
if [ "$REQ" -le 431 ]; then   # topology, not payload size, is what these two add
  pair rust python direct    # a Rust listener must announce to its own TCP peers
  pair rust rust direct
  pair python python rusthub # a Rust transport node must rebroadcast and route for its TCP peers
  pair rust rust rusthub
fi
exit $FAILED
