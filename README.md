# homebridge-stick-de3

Homebridge plugin to control **WAC Lighting CUBE Architectural DC-WD05**
fixtures via a **Nicolaudie Stick-DE3** DMX controller.

## Overview

- 18× WAC DC-WD05 fixtures on a DMX chain
- Nicolaudie Stick-DE3 wall-mount DMX controller at `192.168.96.2`
- TCP/2431 = control + per-session crypto handshake (`LSAG_ALL`/`Stick_3A`);
  UDP→`192.168.96.2:2431` = the AES-128-CBC-encrypted 576-byte DMX frames;
  UDP/2430 broadcast = device discovery
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

## Required device setup

The Stick must have sane **DMX output timing** or every change applies ~2–3 min
late then snaps. Set it via **USB-connected Hardware Manager** → DMX screen →
**Standard/Recommended** (MBB 100 / Break 180 / MAB 20 / MBS 4). This screen is
USB-only and a factory Reset does **not** fix it. See `CLAUDE.md` →
"Required device setup" for the full story and gotchas.

A network "pacing relay" was tried and **disproven** (captures show a tame
25 Hz stream, not a flood); that detour is closed. Per-fixture control still
needs the AES-128-CBC 576-byte DMX stream — the original project work.

## License

Apache-2.0
