#!/usr/bin/env bash
# Capture a COMPLETE HWM<->Stick session: TCP/2431 (control + handshake) +
# UDP/2431 (encrypted DMX stream). We need the handshake from the very first
# byte, so HWM should be DISCONNECTED from the Stick before running this.
#
# Workflow:
#   1. In HWM: disconnect from the Stick (Network panel -> Disconnect).
#   2. Run this script. It captures for 20 sec.
#   3. While it's capturing: in HWM click Connect.
#   4. Wait for HWM to reach "Connected" state, then move a fader so DMX
#      starts streaming. Script should record both the TCP handshake AND
#      a few UDP DMX frames.
#
# Output: /tmp/stick-handshake.pcap (timestamped copy at ./tools/captures/<ts>.pcap)

set -euo pipefail
cd "$(dirname "$0")/.."

IFACE="${IFACE:-en0}"
STICK_IP="${STICK_IP:-192.168.96.2}"
DUR="${DUR:-60}"
PCAP=/tmp/stick-handshake.pcap

mkdir -p tools/captures
TS=$(date +%Y%m%d-%H%M%S)
SAVE="tools/captures/handshake-${TS}.pcap"

echo ">>> About to capture ${DUR}s of ALL traffic to/from ${STICK_IP} on ${IFACE}"
echo ">>> "
echo ">>> BEFORE this starts: disconnect HWM from the Stick."
echo ">>> AS SOON as the capture starts: click HWM Connect, then once"
echo ">>> connected, move a fader to start DMX streaming."
echo ">>> "
read -p "Ready? (y/Enter to start, anything else to abort): " ans
[[ -z "$ans" || "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted"; exit 1; }

echo ">>> Capturing..."
sudo tcpdump -i "$IFACE" -w "$PCAP" -G "$DUR" -W 1 \
  "host ${STICK_IP}" \
  2>/dev/null || true

echo
echo ">>> pcap size: $(wc -c < "$PCAP") bytes"
cp "$PCAP" "$SAVE"
echo ">>> archived to $SAVE"

echo
echo ">>> Packet summary (TCP control + UDP DMX)"
node tools/dump-pcap-summary.mjs "$PCAP" > /tmp/stick-handshake-summary.txt
echo "   written to /tmp/stick-handshake-summary.txt   ($(wc -l < /tmp/stick-handshake-summary.txt) packets)"
echo
echo ">>> First few TCP frames (the handshake):"
grep ' TCP ' /tmp/stick-handshake-summary.txt | head -10
echo
echo ">>> First UDP DMX frame's first 32B (clear header):"
grep ' UDP .* 576B' /tmp/stick-handshake-summary.txt | head -1
echo
echo ">>> Full summary at /tmp/stick-handshake-summary.txt"
echo ">>> pcap at $SAVE — share this output and we'll decode the handshake"
