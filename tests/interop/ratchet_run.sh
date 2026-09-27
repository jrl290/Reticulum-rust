#!/usr/bin/env bash
# Ratchet interop against the Python reference (rns in ../.venv, 1.5.2):
# a Rust ratcheted destination announced, restarted and answered for by
# Transport's path-response clone, and a Python ratcheted destination sent to
# by Rust, all through a Python reference transport node over loopback TCP.
# The scenarios are in the header of tests/interop/ratchet_interop.py.
#
#   tests/interop/ratchet_run.sh
#
#   PYTHON=...            interpreter for the Python ends (default ../.venv/bin/python)
#   INTEROP_LOGLEVEL=n    RNS loglevel written into every Python config (default 3)
#   INTEROP_KEEP=dir      keep every process's config, state and logs there
#
# Exit 0 only if every scenario passes. Ports come from the same registry
# run.sh uses, so the two can run side by side.
set -u
cd "$(dirname "$0")/../.."
PY="${PYTHON:-../.venv/bin/python}"
cargo build --quiet --example ratchet_interop || exit 1
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
"$PY" tests/interop/ratchet_interop.py run target/debug/examples/ratchet_interop "$WORK"
status=$?
if [ -n "${INTEROP_KEEP:-}" ]; then
  mkdir -p "$INTEROP_KEEP" && cp -r "$WORK"/. "$INTEROP_KEEP"/ && echo "logs kept in $INTEROP_KEEP"
fi
exit $status
