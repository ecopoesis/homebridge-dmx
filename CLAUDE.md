# homebridge-wac-dmx

Homebridge plugin to control WAC Lighting CUBE Architectural DC-WD05 fixtures via a Nicolaudie Stick-DE3 DMX controller.

## Architecture

- 18x WAC DC-WD05 fixtures on a DMX chain
- Nicolaudie Stick-DE3 wall-mount DMX controller at 192.168.96.2
- Stick-DE3 exposes a TCP interface (port 2431) that sends raw DMX values
- This plugin bridges HomeKit ↔ DMX via Homebridge

## Fixture Configuration

- RDM Personality: 4 (Enhanced Tuning, 5 channels per fixture)
- DMX addresses: 1, 6, 11, 16, 21, 26, 31, 36, 41, 46, 51, 56, 61, 66, 71, 76, 81, 86

### Channel Map (per fixture, 5 channels)

| Slot | Name             | DMX Range | Notes                        |
|------|------------------|-----------|------------------------------|
| 0    | Intensity        | 0-255     | Master dimmer (coarse)       |
| 1    | Intensity (fine) | 0-255     | 16-bit fine dimmer           |
| 2    | Color Temp       | 0-255     | Maps to 1650K-8000K          |
| 3    | Saturation       | 0-255     | 0 = white/CCT mode           |
| 4    | Hue              | 0-255     | 0-360° mapped to 0-255       |

## HomeKit ↔ DMX Mapping

HomeKit Lightbulb service characteristics:

| HomeKit Characteristic | Range      | DMX Channel | Conversion                                              |
|------------------------|------------|-------------|---------------------------------------------------------|
| On                     | bool       | Ch 0        | on=last brightness, off=0                               |
| Brightness             | 0-100%     | Ch 0 (+ Ch 1 for fine) | `Math.round(value * 2.55)`                |
| Hue                    | 0-360°     | Ch 4        | `Math.round(value * 255 / 360)`                         |
| Saturation             | 0-100%     | Ch 3        | `Math.round(value * 2.55)`                              |
| ColorTemperature       | 50-400 mireds | Ch 2     | mireds→K: `1000000/mireds`, then scale 1650-8000K→0-255 |

When saturation is 0, the fixture is in white/CCT mode using the color temp channel.
When saturation > 0, it's in color mode using hue + saturation.

## Stick-DE3 Network

- Static IP: 192.168.96.2 (on dedicated /30 VLAN, ID 96)
- The Stick changes its MAC address on every settings update (this is "a feature")

### Protocol (observed via packet capture)

- **TCP/2431** — control + per-session crypto handshake. Client sends
  `LSAG_ALL\x00\x00\x15\x00\x00\x00`; Stick replies
  `Stick_3A\x00\xc9\x00DEFAULT\x00…` (carries device name/identity). Short
  probe connections close in ~30 ms (normal); one long-lived control session.
- **UDP → 192.168.96.2:2431** (src port 2430) — the live DMX stream:
  **576-byte AES-128-CBC-encrypted frames** (see [[stick-protocol-reverse-engineering]]).
- **UDP/2430 broadcast** — device discovery only.

### Required device setup (CRITICAL — fixes the multi-minute lag)

Symptom (now resolved): every DMX change — from any source (HWM faders, ESA
Pro 2, raw stream) — applied a **consistent ~2–3 min late, then snapped**.

Root cause: the Stick's **DMX output wire-timing** was set to absurd values
(MBB 15000 / Break 1000 / MAB 1500 / **MBS 400**). MBS is applied between all
512 slots every frame, so the output engine emitted frames so slowly that live
input backed up in the device's FIFO for minutes. NOT a network/AES/show/fade
problem — all of those were investigated and ruled out.

Fix: **USB-connect Hardware Manager** → the DMX/fader screen → set
**Standard/Recommended**:

| Param | Good value |
|-------|-----------|
| MBB (Mark Before Break) | 100 |
| Break | 180 |
| MAB (Mark After Break) | 20 |
| MBS (Mark Between Slots) | 4 |

(≈ 40 Hz / ~348 fps figure shown). Lights then change instantly, over USB
**and** the network.

Gotchas:
- This DMX-timing screen exists **only in USB-connected Hardware Manager** —
  it is NOT in the network config, and a **factory Reset does NOT fix it**
  (Reset wipes network + showfile but not these toward sane values).
- After a Reset you must re-enter the static network *and* re-enable **WAN
  access** for network HWM control.
- fw **3.08** is the newest (no firmware fix; the in-app changelog's recurring
  fix is the MAC issue, not latency).

### Other notes

- Hardware Manager / ESA Pro 2 send a tame, steady **25 Hz** stream — *not* a
  flood. A pacing relay/bridge was built, deployed, and **disproven**; do not
  revisit it.
- First Connect after launching Hardware Manager often fails **XHL 17**; the
  retry succeeds → stale single TCP/2431 session slot freed by the failed
  attempt. The plugin should auto-retry and close its session cleanly.
- `tools/quick-trigger.mjs` — spec-verified UDP/2430 Quick Trigger (scene-level
  only; not actioned on fw3.08 unless "Security for Cloud Access" is off).
  `tools/stick-status.mjs` — reads the TCP/2431 status packet (Live-Mode flag).
- Per-fixture HomeKit control still requires sending the **AES-128-CBC 576-byte
  DMX stream**; see [[stick-next-steps.md]]. (The latency fix above is
  independent and a prerequisite for that to be usable.)

## Reference

- Existing plugin by same author for style reference: https://github.com/ecopoesis/homebridge-unifi-ap-rgb/tree/main
- WAC fixture spec: RGBWW, 1650K-8000K CCT range
- Manufacturer ID (RDM): 0x0776
