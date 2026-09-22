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
set -u
cd "$(dirname "$0")/../.."
PY="${PYTHON:-../.venv/bin/python}"
if [ $# -eq 0 ]; then
  status=0
  for sizes in "100 200" "3000 5000" "60000 250000"; do "$0" $sizes || status=1; done
  exit $status
fi
REQ="$1"; RESP="$2"
WORK="$(mktemp -d)"; PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

cargo build --quiet --example request_resource_interop || exit 1
RUST=target/debug/examples/request_resource_interop
SCRIPT=tests/interop/request_resource_interop.py

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

run_end() { # <rust|python> args...
  local kind="$1"; shift
  if [ "$kind" = rust ]; then "$RUST" "$@"; else "$PY" "$SCRIPT" "$@"; fi
}

FAILED=0; PORT=$((42000 + RANDOM % 2000))
pair() { # <server kind> <client kind> [hub|rusthub|direct]
  local s="$1" c="$2" topo="${3:-hub}"; PORT=$((PORT + 1))
  local hdir="$WORK/hub-$PORT" sdir="$WORK/$s-server-$PORT" cdir="$WORK/$c-client-$PORT"
  local hpid="" label="$c client -> $s server"
  mkdir -p "$hdir"; : > "$hdir/out"
  if [ "$topo" = hub ] || [ "$topo" = rusthub ]; then
    config "$hdir" listen "$PORT" true; config "$sdir" connect "$PORT" false
    if [ "$topo" = rusthub ]; then
      # This stack as the transport node in the middle — the gateway's role.
      # It cannot police the medium the way the Python hub does, so this
      # topology checks routing and rebroadcast, not frame sizes.
      label="$label (via Rust hub)"
      run_end rust hub "$hdir" > "$hdir/out" 2> "$hdir/err" &
    else
      "$PY" "$SCRIPT" hub "$hdir" > "$hdir/out" 2> "$hdir/err" &
    fi
    hpid=$!; PIDS+=("$hpid")
    for _ in $(seq 1 100); do grep -q '^HUB ready' "$hdir/out" && break; sleep 0.1; done
  else
    # No hub: the server is itself the listener and the client connects
    # straight to it. A listener has to send its OWN announces to the peers
    # connected to it, or the client never learns the destination exists.
    label="$label (direct, server listens)"
    config "$sdir" listen "$PORT" false
  fi
  config "$cdir" connect "$PORT" false
  run_end "$s" server "$sdir" > "$sdir/out" 2> "$sdir/err" &
  local spid=$!; PIDS+=("$spid")
  local dest=""
  for _ in $(seq 1 100); do
    dest="$(sed -n 's/^DEST //p' "$sdir/out" | head -1)"; [ -n "$dest" ] && break; sleep 0.2
  done
  if [ -z "$dest" ]; then echo "FAIL  $label: server never started"; tail -5 "$sdir/err"; FAILED=1; kill "$spid" $hpid 2>/dev/null; return; fi
  run_end "$c" client "$cdir" "$dest" "$REQ" "$RESP" > "$cdir/out" 2> "$cdir/err"
  local result; result="$(grep -E '^(PASS|FAIL)' "$cdir/out" | head -1)"
  kill "$spid" $hpid 2>/dev/null; wait "$spid" $hpid 2>/dev/null
  local oversize; oversize="$(grep -c '^OVERSIZE' "$hdir/out")"
  [ "$oversize" -gt 0 ] && result="FAIL $oversize frame(s) over the medium MTU: $(grep -m1 '^OVERSIZE' "$hdir/out") [end result: ${result:-none}]"
  # A Resource concludes once. The server prints one RESOURCE line per
  # concluded-callback invocation; two means every inbound Resource is being
  # handed to the application twice.
  local concluded; concluded="$(grep -c '^RESOURCE' "$sdir/out")"
  case "$result" in PASS*) [ "$concluded" -eq 1 ] || result="FAIL the server's resource-concluded callback fired $concluded times for one Resource [end result: $result]";; esac
  grep -q '^RESOURCE .*intact=\(False\|false\)' "$sdir/out" && result="FAIL plain resource arrived corrupted"
  case "$result" in
    PASS*) echo "PASS  $label: $result ($(grep -c '^REQUEST' "$sdir/out") request(s) seen by server, 0 oversize frames)";;
    *)     echo "FAIL  $label: ${result:-no result}"; FAILED=1
           [ -n "${INTEROP_KEEP:-}" ] && { cp -r "$WORK" "${INTEROP_KEEP}"; echo "      logs kept in ${INTEROP_KEEP}"; };;
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
