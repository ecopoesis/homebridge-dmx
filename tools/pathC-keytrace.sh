#!/usr/bin/env bash
# Path C-lite — attach lldb and run the runtime key-trace.
#
# Prereqs (same as pathA-scan.sh):
#   - the debug HWM (tools/pathA-launch-hwm.sh) is running
#   - it is connected to the Stick and streaming live DMX
#
# Sets one-shot breakpoints on the encrypt path, lets ONE frame hit, dumps
# registers + stack + the cipher/device memory, runs the AES key-schedule
# detector, then detaches. HWM is stopped ~1-2s total.

set -uo pipefail
cd "$(dirname "$0")/.."

SCAN_PY="tools/lldb_pathC_keytrace.py"
LOG="/tmp/stick-pathC-keytrace.log"

PID="$(pgrep -f '/tmp/HM-ESA2-dbg.app/Contents/MacOS/HardwareManager' | head -1)"
if [ -z "$PID" ]; then
  echo "ERROR: debug HWM not running. Run tools/pathA-launch-hwm.sh first,"
  echo "       connect it to the Stick, and stream live DMX."
  exit 1
fi

echo ">>> debug HWM pid = $PID"
echo ">>> attaching lldb for the runtime key-trace"
echo ">>> 'continue' runs until the encrypt path fires (~40ms at 25Hz)"
echo

# 'continue' blocks until a breakpoint callback returns True (stop). The
# script's fallback (capture-at-entry after 6 frames) guarantees that always
# happens, so 'continue' cannot hang. timeout is just a safety net.
timeout 180 lldb --batch \
  -o "command script import $SCAN_PY" \
  -o "continue" \
  -o "detach" \
  -o "quit" \
  -p "$PID" 2>&1 | sed 's/^/  /'

echo
if [ -f "$LOG" ]; then
  echo ">>> full log: $LOG"
  echo ">>> captured memory blobs: /tmp/stick-pathC-blob-*.bin"
  echo
  echo "If a key was recovered:  node tools/try-key.mjs <frame.bin> <key-hex>"
  echo "Otherwise brute-force:   node tools/crack-key.mjs <frame.bin> /tmp/stick-pathC-blob-*.bin"
else
  echo "!!! no log produced — the trace script may have errored above"
fi
