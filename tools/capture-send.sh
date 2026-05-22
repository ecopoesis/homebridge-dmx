#!/usr/bin/env bash
# Capture a send_dmx run: all TCP + UDP traffic to/from the Stick while
# send_dmx connects, handshakes and streams. The resulting pcap shows whether
# the Stick accepts our handshake, whether our UDP DMX frames go out, and
# whether the Stick errors or drops the connection.
#
#   ./tools/capture-send.sh <ip> <universe,channel=value> [...]
#   e.g.  ./tools/capture-send.sh 192.168.96.2 0,6=255 0,9=255 0,10=170
#
# Needs sudo for tcpdump (it will prompt). Output: /tmp/send_dmx-run.pcap

set -euo pipefail
cd "$(dirname "$0")/.."

IFACE="${IFACE:-en0}"
IP="${1:?usage: capture-send.sh <ip> <universe,channel=value>...}"
shift
PCAP=/tmp/send_dmx-run.pcap
rm -f "$PCAP"

echo ">>> starting tcpdump (sudo) on ${IFACE}, host ${IP}"
sudo tcpdump -i "$IFACE" -w "$PCAP" "host ${IP}" >/dev/null 2>&1 &
sleep 3   # let tcpdump come up

echo ">>> running: send_dmx ${IP} $*"
node tools/send_dmx.mjs "$IP" "$@" || true
sleep 2   # let the last frames + any Stick response land

echo ">>> stopping tcpdump"
sudo pkill -INT -f 'tcpdump.*send_dmx-run' 2>/dev/null || true
sleep 1

echo
echo ">>> pcap: ${PCAP}  ($(wc -c < "$PCAP" 2>/dev/null || echo 0) bytes)"
if [[ -s "$PCAP" ]]; then
  node tools/dump-pcap-summary.mjs "$PCAP" 2>/dev/null | head -50 || true
  echo ">>> total packets: $(node tools/dump-pcap-summary.mjs "$PCAP" 2>/dev/null | wc -l)"
fi
echo ">>> done — tell the assistant; ${PCAP} will be analysed."
