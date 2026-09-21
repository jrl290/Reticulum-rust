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
# Needs the workspace venv (../.venv with `rns`). Exit 0 only if all pass.
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

config() { # <dir> <listen|connect> <port>
  mkdir -p "$1"
  local transport=false
  if [ "$2" = listen ]; then
    transport=true
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
pair() { # <server kind> <client kind>
  local s="$1" c="$2"; PORT=$((PORT + 1))
  local hdir="$WORK/hub-$PORT" sdir="$WORK/$s-server-$PORT" cdir="$WORK/$c-client-$PORT"
  config "$hdir" listen "$PORT"; config "$sdir" connect "$PORT"; config "$cdir" connect "$PORT"
  "$PY" "$SCRIPT" hub "$hdir" > "$hdir/out" 2> "$hdir/err" &
  local hpid=$!; PIDS+=("$hpid")
  for _ in $(seq 1 100); do grep -q '^HUB ready' "$hdir/out" && break; sleep 0.1; done
  run_end "$s" server "$sdir" > "$sdir/out" 2> "$sdir/err" &
  local spid=$!; PIDS+=("$spid")
  local dest=""
  for _ in $(seq 1 100); do
    dest="$(sed -n 's/^DEST //p' "$sdir/out" | head -1)"; [ -n "$dest" ] && break; sleep 0.2
  done
  if [ -z "$dest" ]; then echo "FAIL  $c client -> $s server: server never started"; tail -5 "$sdir/err"; FAILED=1; kill "$spid" "$hpid" 2>/dev/null; return; fi
  run_end "$c" client "$cdir" "$dest" "$REQ" "$RESP" > "$cdir/out" 2> "$cdir/err"
  local result; result="$(grep -E '^(PASS|FAIL)' "$cdir/out" | head -1)"
  kill "$spid" "$hpid" 2>/dev/null; wait "$spid" "$hpid" 2>/dev/null
  local oversize; oversize="$(grep -c '^OVERSIZE' "$hdir/out")"
  [ "$oversize" -gt 0 ] && result="FAIL $oversize frame(s) over the medium MTU: $(grep -m1 '^OVERSIZE' "$hdir/out") [end result: ${result:-none}]"
  case "$result" in
    PASS*) echo "PASS  $c client -> $s server: $result ($(grep -c '^REQUEST' "$sdir/out") request(s) seen by server, 0 oversize frames)";;
    *)     echo "FAIL  $c client -> $s server: ${result:-no result}"; FAILED=1
           [ -n "${INTEROP_KEEP:-}" ] && { cp -r "$WORK" "${INTEROP_KEEP}"; echo "      logs kept in ${INTEROP_KEEP}"; };;
  esac
}

pair python python   # control: proves the harness itself
pair python rust     # Rust sends an over-MDU request; receives an over-MDU response
pair rust python     # Rust receives an over-MDU request; sends an over-MDU response
pair rust rust
exit $FAILED
