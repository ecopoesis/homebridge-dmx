# homebridge-stick-de3

Homebridge plugin to control **WAC Lighting CUBE Architectural DC-WD05**
fixtures via a **Nicolaudie Stick-DE3** DMX controller.

## Overview

- 18× WAC DC-WD05 fixtures on a DMX chain
- Nicolaudie Stick-DE3 wall-mount DMX controller at `192.168.96.2`
- The Stick exposes a network interface (UDP 2430 / TCP 2431) carrying raw
  DMX channel values
- This plugin bridges HomeKit ↔ DMX via Homebridge

Each fixture uses RDM Personality 4 (Enhanced Tuning, 5 channels): intensity
(coarse + 16-bit fine), color temperature (1650K–8000K), saturation, and hue.
When saturation is 0 the fixture is in white/CCT mode; above 0 it's in
hue+saturation color mode. See [`CLAUDE.md`](CLAUDE.md) for the full channel
map and HomeKit characteristic conversions.

## Install

```bash
npm install
npm run build
```

Then add the platform to your Homebridge config (see `stick-de3.json`).

## Tools

### `tools/dmx-relay/` — Stick-DE3 pacing relay

Nicolaudie Hardware Manager / ESA Pro 2 floods the Stick with UDP far faster
than DMX's ~44 Hz wire ceiling. The Stick's network task starves its DMX
engine (lights freeze / stay on) and its single TCP control session never
frees, so you can't reconnect after restarting the software without a
power-cycle.

`tools/dmx-relay/` is a zero-dependency Node relay (Dockerized, deployed as a
Portainer stack on `server03` with host networking) that sits between the
Nicolaudie software and the Stick:

- **UDP/2430** — last-frame-wins coalescing, forwarded at a fixed rate
  (default 40 Hz). The flood is dropped, not buffered.
- **TCP/2431** — transparent proxy, one session at a time; a reconnecting
  client hard-RSTs the previous session so the Stick immediately frees its
  slot (this is the reconnect fix).

Point Hardware Manager / ESA Pro 2 at server03's IP instead of
`192.168.96.2`. Full rationale, deploy steps, and tuning knobs in
[`tools/dmx-relay/README.md`](tools/dmx-relay/README.md).

## License

Apache-2.0
