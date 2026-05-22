#!/usr/bin/env bash
# Path D — attach lldb, arm a watchpoint on the AES key, catch the KDF.
#
# Prereqs: the debug HWM is running and currently CONNECTED to the Stick
# (so the cipher object exists with a live key to watch).
#
# Flow:
#   1. this attaches lldb and arms a write-watchpoint on cipher_obj+0x48
#   2. when it prints "watchpoint armed", YOU disconnect HWM from the Stick
#      and reconnect it (Network panel -> Disconnect, then Connect)
#   3. the handshake rederives the key -> watchpoint fires -> lldb dumps the
#      KDF backtrace + registers + stack, then detaches
#
# Also run a handshake capture in another terminal so the X25519 pubkeys
# are recorded for the same session:
#   tools/capture-handshake.sh

set -uo pipefail
cd "$(dirname "$0")/.."

SCAN_PY="tools/lldb_pathD_kdf_watch.py"
LOG="/tmp/stick-pathD-kdf.log"

PID="$(pgrep -f '/tmp/HM-ESA2-dbg.app/Contents/MacOS/HardwareManager' | head -1)"
if [ -z "$PID" ]; then
  echo "ERROR: debug HWM not running — run tools/pathA-launch-hwm.sh first."
  exit 1
fi

echo ">>> debug HWM pid = $PID"
echo ">>> attaching lldb and arming the KDF watchpoint"
echo ">>> when it says 'watchpoint armed', reconnect HWM to the Stick"
echo

# The import script arms the watchpoint and drives its own continue-loop
# (lldb watchpoints have no script callback), so there is NO -o "continue"
# here. Generous timeout: it waits for a human-driven reconnect.
timeout 600 lldb --batch \
  -o "command script import $SCAN_PY" \
  -o "detach" \
  -o "quit" \
  -p "$PID" 2>&1 | sed 's/^/  /'

echo
if [ -f "$LOG" ]; then
  echo ">>> full log: $LOG"
  echo ">>> captured blobs: /tmp/stick-pathD-blob-*.bin"
  echo ">>> then: node tools/crack-kdf.mjs <new-key-hex> /tmp/stick-pathD-blob-*.bin"
else
  echo "!!! no log produced — the trace script may have errored above"
fi
