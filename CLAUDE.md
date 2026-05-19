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
- Control ports: UDP 2430, TCP 2431
- The Stick's TCP interface sends/receives raw DMX channel values
- The Stick changes its MAC address on every settings update (this is "a feature")

## DMX Pacing Relay (`tools/dmx-relay/`)

The Stick gets overwhelmed by Nicolaudie Hardware Manager / ESA Pro 2's UDP
live stream: a gigabit PC sends far faster than DMX's ~44 Hz wire ceiling, so
the Stick's network task starves its DMX engine (lights freeze/stay on) and the
single TCP/2431 session never frees (can't reconnect without a power-cycle).

`tools/dmx-relay/` is a zero-dependency Node relay (Dockerized, runs as a
Portainer stack on server03 with host networking) that sits in the path:

- **UDP/2430** — last-frame-wins coalescing, forwarded at a fixed `RATE_HZ`
  (default 40). The flood is dropped, not buffered.
- **TCP/2431** — transparent proxy, one session at a time; a reconnecting
  client hard-RSTs the previous session so the Stick frees its slot.

Point Hardware Manager / ESA Pro 2 at server03's IP instead of 192.168.96.2.
See `tools/dmx-relay/README.md` for deploy + tuning.

## Reference

- Existing plugin by same author for style reference: https://github.com/ecopoesis/homebridge-unifi-ap-rgb/tree/main
- WAC fixture spec: RGBWW, 1650K-8000K CCT range
- Manufacturer ID (RDM): 0x0776
