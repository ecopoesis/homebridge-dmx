#!/usr/bin/env bash
# Atomic same-session key capture.
#
# The Stick's AES key is per-session: every TCP/2431 reconnect derives a new
# key. A long lldb stop (the 41s passive scan) kills the session, so the key
# you read no longer matches frames captured afterwards.
#
# This script avoids that:
#   1. start tcpdump in the background (captures encrypted frames)
#   2. run the Path C breakpoint key-trace — its stop is only ~1-2s, short
#      enough that the TCP session survives
#   3. extract the FIRST captured frame (captured before the attach => same
#      session as the key Path C caught)
#   4. crack-key / try-key against the captured memory
#
# Run it from a terminal (tcpdump needs sudo — it will prompt once):
#   tools/pathC-run.sh
#
# Prereqs: the debug HWM is running, connected to the Stick, streaming DMX.

set -uo pipefail
cd "$(dirname "$0")/.."

IFACE="${IFACE:-en0}"
STICK_IP="${STICK_IP:-192.168.96.2}"
STICK_PORT="${STICK_PORT:-2431}"
PCAP=/tmp/stick-pathC.pcap
FRAME=/tmp/stick-pathC-frame.bin
CAP_SECS="${CAP_SECS:-55}"

echo ">>> caching sudo credentials for tcpdump"
sudo -v

echo ">>> starting ${CAP_SECS}s background capture of UDP -> ${STICK_IP}:${STICK_PORT} on ${IFACE}"
rm -f "$PCAP" "$FRAME"
sudo tcpdump -i "$IFACE" -w "$PCAP" -G "$CAP_SECS" -W 1 \
  "udp and host ${STICK_IP} and port ${STICK_PORT}" 2>/dev/null &
TCPDUMP_PID=$!
sleep 3      # let some frames land before we attach

echo ">>> running Path C key-trace (short stop — session should survive)"
tools/pathC-keytrace.sh

echo ">>> waiting for the background capture to finish"
wait "$TCPDUMP_PID" 2>/dev/null || true

if [[ ! -s "$PCAP" ]]; then
  echo "!!! no packets captured — is HWM connected + streaming? wrong IFACE?"
  exit 2
fi
echo ">>> pcap: $(wc -c < "$PCAP") bytes"

echo ">>> extracting the first 576-byte frame (pre-attach => same session)"
STICK_IP="$STICK_IP" STICK_PORT="$STICK_PORT" \
  node tools/extract-frame.mjs "$PCAP" "$FRAME" || {
    echo "!!! no 576-byte frame found in the capture"; exit 3; }

echo
echo ">>> === try any key Path C recovered from a live schedule ==="
shopt -s nullglob
KEYHIT=0
for kf in /tmp/stick-pathC-key-*.bin; do
  KEYHIT=1
  echo "--- $kf ---"
  node tools/try-key.mjs "$FRAME" "$(xxd -p -c256 "$kf")" || true
done
[ "$KEYHIT" = 0 ] && echo "(Path C recovered no standard schedule — going to brute-force)"

echo
echo ">>> === brute-force the captured memory blobs against the frame ==="
node tools/crack-key.mjs "$FRAME" /tmp/stick-pathC-blob-*.bin
