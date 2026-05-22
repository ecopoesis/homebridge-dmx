#!/usr/bin/env bash
# Extract the 0x48 TCP-auth HMAC key from a running debug Hardware Manager.
#
# The 0x48 handshake is authenticated with HMAC-SHA256(key, msg[0:82]); the
# key is an internal HWM constant. This attaches lldb, breakpoints the HMAC
# routine, and dumps the key the instant HWM builds a 0x48 (one hit, then
# detaches — not a per-frame breakpoint, so HWM stays healthy).
#
# Steps:
#   1. Quit the normal Hardware Manager (it holds the Stick's single session).
#   2. Launch the debug copy:   tools/pathA-launch-hwm.sh
#      Leave it DISCONNECTED from the Stick for now.
#   3. Run this script.
#   4. When it prints "waiting for the 0x48 handshake", connect the debug HWM
#      to the Stick (Connection -> Add/Connect). The key is dumped + logged.

set -uo pipefail
cd "$(dirname "$0")/.."

SCAN_PY="tools/lldb_hmac_key.py"
LOG="/tmp/stick-hmac-key.log"

PID="$(pgrep -f '/tmp/HM-ESA2-dbg.app/Contents/MacOS/HardwareManager' | head -1)"
if [ -z "$PID" ]; then
  echo "ERROR: the debug Hardware Manager is not running."
  echo "  1. Quit the normal Hardware Manager."
  echo "  2. Run:  tools/pathA-launch-hwm.sh"
  echo "  3. Leave it DISCONNECTED from the Stick, then re-run this script."
  exit 1
fi

echo ">>> debug HWM pid = $PID"
echo ">>> attaching lldb and arming the HMAC breakpoint ..."
echo ">>> when it says 'waiting for the 0x48 handshake', CONNECT HWM to the Stick."
echo

timeout 600 lldb --batch \
  -o "command script import $SCAN_PY" \
  -o "detach" \
  -o "quit" \
  -p "$PID" 2>&1 | sed 's/^/  /'

echo
if grep -q 'auth HMAC caught' "$LOG" 2>/dev/null; then
  echo ">>> SUCCESS — the auth key:"
  grep -E 'key length|key \(hex\)|key \(text\)' "$LOG" | sed 's/^/  /'
  echo ">>> full log: $LOG"
else
  echo "!!! the 0x48 HMAC was not caught — did HWM connect to the Stick?"
  echo "    log: $LOG"
fi
