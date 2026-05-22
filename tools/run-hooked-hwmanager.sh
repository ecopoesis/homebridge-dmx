#!/bin/bash
# Runs a copy of HardwareManager with our AES key-capture hook injected.
# The copy has its code signature stripped so DYLD_INSERT_LIBRARIES works.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK="$SCRIPT_DIR/aes-hook.dylib"
SRC="/Applications/EsaPro2/HardwareManager/HardwareManager.app"
COPY="/tmp/HardwareManager-hooked.app"
LOG="/tmp/stick-aes-keys.log"

if [ ! -f "$HOOK" ]; then
  echo "ERROR: aes-hook.dylib not found. Run:"
  echo "  clang -arch x86_64 -shared -undefined dynamic_lookup -o tools/aes-hook.dylib tools/aes-hook.c"
  exit 1
fi

echo "=== Stick-DE3 AES Key Capture ==="
echo ""

# Copy the app if needed
if [ ! -d "$COPY" ]; then
  echo "Copying HardwareManager to $COPY ..."
  cp -R "$SRC" "$COPY"

  echo "Stripping code signatures..."
  # Strip signature from main binary and all frameworks
  codesign --remove-signature "$COPY/Contents/MacOS/HardwareManager"
  for fw in "$COPY/Contents/Frameworks/"*.dylib; do
    codesign --remove-signature "$fw" 2>/dev/null || true
  done
  for fw in "$COPY/Contents/Frameworks/"*.framework/Versions/*/Qt*; do
    codesign --remove-signature "$fw" 2>/dev/null || true
  done
  echo "Signatures stripped."
else
  echo "Using existing copy at $COPY"
fi

echo ""
echo "Starting HardwareManager with AES hook..."
echo "Key captures will be logged to: $LOG"
echo ""
echo ">>> Connect to the Stick-DE3 via the UI, then check $LOG <<<"
echo ""

# Clear old log
> "$LOG"

DYLD_INSERT_LIBRARIES="$HOOK" "$COPY/Contents/MacOS/HardwareManager"
