#!/usr/bin/env bash
# Path A, step 1 — launch a debuggable copy of the ESA2 Hardware Manager.
#
# Why a copy: the installed ESA2 HWM is signed with hardened runtime and NO
# `get-task-allow`, so lldb cannot attach (`attach failed: lost connection`).
# We copy it, adhoc-re-sign the whole bundle with tools/hwm-entitlements.plist
# (which now includes `get-task-allow` + `disable-library-validation`), and
# launch that. lldb can then attach to the copy for a passive memory scan.
#
# Source MUST be the ESA2 build — the Ghidra addresses (vptr 0x10095F838 etc.)
# come from the 2024-03-21 ESA2 binary, not the EsaPro2 one.
#
# Usage:
#   tools/pathA-launch-hwm.sh            # launch the debug copy
#   FORCE_KILL=1 tools/pathA-launch-hwm.sh   # also kill any running HWM first
#
# The Stick is single-session: only one Hardware Manager can hold the TCP/2431
# slot. Quit the normally-installed HWM before launching this copy.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="/Applications/ESA2/HardwareManager/HardwareManager.app"
COPY="/tmp/HM-ESA2-dbg.app"
ENTS="$SCRIPT_DIR/hwm-entitlements.plist"

[ -d "$SRC" ]  || { echo "ERROR: $SRC not found"; exit 1; }
[ -f "$ENTS" ] || { echo "ERROR: $ENTS not found"; exit 1; }

# --- single-session guard -------------------------------------------------
RUNNING="$(pgrep -fl 'HardwareManager.app/Contents/MacOS/HardwareManager' || true)"
if [ -n "$RUNNING" ]; then
  # ignore our own debug copy when deciding
  OTHER="$(echo "$RUNNING" | grep -v "$COPY" || true)"
  if [ -n "$OTHER" ]; then
    echo ">>> A Hardware Manager is already running:"
    echo "$OTHER" | sed 's/^/      /'
    if [ "${FORCE_KILL:-0}" = "1" ]; then
      echo ">>> FORCE_KILL=1 — terminating it so the Stick session frees up."
      echo "$OTHER" | awk '{print $1}' | xargs -r kill
      sleep 2
    else
      echo ">>> The Stick allows only ONE HWM session. Quit it, then re-run."
      echo ">>> (or re-run with FORCE_KILL=1)"
      exit 2
    fi
  fi
fi

# --- (re)build the debug copy --------------------------------------------
if [ "${REBUILD:-0}" = "1" ] && [ -d "$COPY" ]; then
  echo ">>> REBUILD=1 — removing stale $COPY"
  rm -rf "$COPY"
fi

if [ ! -d "$COPY" ]; then
  echo ">>> Copying $SRC"
  echo "    -> $COPY"
  cp -R "$SRC" "$COPY"

  echo ">>> Adhoc re-signing the bundle with debug entitlements"
  # Adhoc (--sign -), no hardened runtime, no library validation. --deep
  # re-signs the nested Qt frameworks adhoc too so signatures stay
  # consistent. The entitlements (incl. get-task-allow) apply to the main
  # executable — that is what lldb attaches to.
  codesign --force --deep --sign - --entitlements "$ENTS" "$COPY" 2>&1 \
    | sed 's/^/    /'

  echo ">>> Verifying get-task-allow landed on the main executable"
  if codesign -d --entitlements - "$COPY" 2>/dev/null | grep -q 'get-task-allow'; then
    echo "    OK: get-task-allow present"
  else
    echo "    WARNING: get-task-allow not found — lldb attach may still fail"
  fi
else
  echo ">>> Using existing debug copy at $COPY  (REBUILD=1 to recreate)"
fi

echo
echo ">>> Launching the debug Hardware Manager"
echo "    Next steps:"
echo "      1. In this HWM, connect to the Stick at 192.168.96.2"
echo "      2. Open the DMX / fader screen so live DMX is streaming"
echo "      3. In another terminal:  tools/pathA-scan.sh"
echo
open -n "$COPY"
