#!/usr/bin/env bash
# Path A, step 2 — attach lldb to the debug HWM and run the passive scan.
#
# Prereqs:
#   1. tools/pathA-launch-hwm.sh has launched the debug copy
#   2. that HWM is connected to the Stick and streaming live DMX
#
# This attaches lldb, runs tools/lldb-pathA-scan.py (no breakpoints — one
# brief stop while it scans), then detaches. HWM keeps running.
#
# Set STICK_HEAP_DUMP=1 to also dump rw memory for an offline heap-wide
# AES key-schedule search (slower; only needed if the fast scan finds nothing).

set -uo pipefail
cd "$(dirname "$0")/.."

SCAN_PY="tools/lldb_pathA_scan.py"
LOG="/tmp/stick-pathA-scan.log"

# Find the debug copy's pid (NOT the installed HWM).
PID="$(pgrep -f '/tmp/HM-ESA2-dbg.app/Contents/MacOS/HardwareManager' | head -1)"

if [ -z "$PID" ]; then
  echo "ERROR: debug HWM not running."
  echo "  Run tools/pathA-launch-hwm.sh first, connect it to the Stick,"
  echo "  and open the DMX screen so live DMX is streaming."
  # show what IS running, to help diagnose
  echo
  echo "Currently running Hardware Managers:"
  pgrep -fl 'HardwareManager.app/Contents/MacOS/HardwareManager' | sed 's/^/  /' \
    || echo "  (none)"
  exit 1
fi

echo ">>> debug HWM pid = $PID"
echo ">>> attaching lldb for a passive scan (one brief stop, then detach)"
[ "${STICK_HEAP_DUMP:-0}" = "1" ] && echo ">>> STICK_HEAP_DUMP=1 — will also dump rw memory"
echo

STICK_HEAP_DUMP="${STICK_HEAP_DUMP:-0}" \
lldb --batch \
  -o "command script import $SCAN_PY" \
  -o "detach" \
  -o "quit" \
  -p "$PID" 2>&1 | sed 's/^/  /'

echo
if [ -f "$LOG" ]; then
  echo ">>> full log saved at $LOG"
else
  echo "!!! no log produced — the scan script may have errored above"
fi
