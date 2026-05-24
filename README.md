# homebridge-dmx

Homebridge platform plugin that exposes DMX fixtures as HomeKit Lightbulb
accessories. The DMX controller is abstracted so additional controllers can be
plugged in without rewriting your patch; the supported controller today is the
**Nicolaudie Stick-DE3** (TCP/2431 + AES-256-CBC-encrypted 576-byte UDP DMX
stream, reverse-engineered from the ESA2 Hardware Manager).

[![npm](https://img.shields.io/npm/v/@ecopoesis/homebridge-dmx.svg)](https://www.npmjs.com/package/@ecopoesis/homebridge-dmx)

## Nicolaudie Stick-DE3

Please, under no circumstances, should you buy a Nicolaudie Stick-DE3 because this plugin exists.

The Stick-DE3 hardware, and its accompanying software, are some of the worst I have had the misfortune to use.

Some of the litany of problems with the Stick-DE3 ecosystem:
* The Stick does not support power-over-ethernet. It takes power over an Ethernet (8P8C) shaped port, but it's non-standard.
* The Stick touchscreen is very touchy. And not in a good way. Phantom clicks, slow responsiveness: all the problems from pre-iPhone touchscreens are here. I believe I've clicked buttons by looking at it too hard.
* Every setting change also changes the MAC address. Hope you didn't want to give it a static address via DHCP.
* HSV-style color spaces are not supported at all. Except: look at the color-wheel. It's in HSV. So they do support converting from HSV to RGB or various RGB+W derivatives, but can't pass the native values their controller's UI generates straight through to DMX channels.
* The software suite is ancient and terrible. ESA Pro, ESA Pro 2, and Hardware Manager all only support x86 on MacOS. In 2026. Apple Silicon came out 6 years ago!
* The software has a UI that would have looked dated in Windows 95.
* Why is there so much encryption? This is my hardware. Nicolaudie sensibly ships a way to turn off IoT access, making this a pure NoT ("Network of Things") device. Let me talk to it.
* Why do you make a DMX interface without simple channel control? It'd be great if I could use this as intended, but since it doesn't support HSV-style color, give me an easy escape hatch. You have a (poorly) documented API. Just add the ability for me to send a DMX packet. I shouldn't need to break AES to do that.

That said, this plugin does just that. Reusing the encryption scheme used by Hardware Manager (with keys extracted from the binary) lets us send the same type of per-channel control used there. We then cleanly disconnect; the Stick latches the last frame, with a brief wall-controller blink as a side effect.

`send_dmx.mjs` is the pieces of the protocol needed to authenticate and start streaming, including the keys extracted from Hardware Manager. Other files in `tools` are the code developed to get to that point.

If you, like me, bought a Stick-DE3 based on the assumption that it was competently executed and are now stuck with it, hopefully this repo and the research it contains can help you actually make it useful.

## Status

| Piece | State |
| --- | --- |
| Stick-DE3 control (auth, ECDH, encrypted DMX stream) | ✅ working |
| Color models: dimmer, cct, rgb, rgbw, rgbww, rgbaw, hsvcct | ✅ |
| YAML and Homebridge-UI config | ✅ |
| Multiple controllers in one patch | ✅ (only `StickDE3` type supported today) |
| Universe B on the Stick | 🚧 plumbed but the wire encoding is unknown |
| Stick-DE3 password / "Cloud Access" auth | 🚧 not implemented |
| State read-back | 🚧 Homebridge holds the canonical state; local drift accepted |

## How it works

Each HomeKit change is rendered into DMX bytes by the fixture's color model
(HSV → channel values for the appropriate model), written into a per-universe
buffer, and dispatched via a debounced controller. After 750 ms of quiet (or
during a slider drag, continuously), the controller spawns
**`tools/send_dmx.mjs`** as a child process which runs the full Stick-DE3
handshake + 750 ms of 25 Hz encrypted UDP frames + a dirty close (RST → Stick
latches the last values).

The subprocess-per-transaction architecture is an empirical workaround:
running the same protocol in-process in a long-lived plugin only worked for
the first transaction; sessions 2+ silently failed to drive output. Running
each transaction in a fresh node process bypasses whatever in-process state
poisons subsequent sessions. Each transaction costs ~1.5–2 s total.

## Install

```bash
npm install -g @ecopoesis/homebridge-dmx
```

Or, in the Homebridge UI: **Plugins** → search for "DMX" → install.

## Config

Two flavours: inline JSON via the Homebridge UI, or external YAML pointed to by
`yamlPath`. YAML is recommended for anything beyond a couple of fixtures.

Minimal inline config:

```json
"platforms": [
  {
    "platform": "DMX",
    "name": "DMX",
    "controllers": [
      { "id": "main", "type": "StickDE3", "ip": "192.168.96.2" }
    ],
    "profiles": [
      {
        "name": "WAC",
        "colormodel": "hsvcct",
        "channel_order": [
          "Intensity", "Intensity (Fine)",
          "ColorTemp 1650-8000",
          "Saturation", "Hue"
        ]
      }
    ],
    "patch": [
      { "id": "a_down", "name": "A Down", "type": "WAC", "controller": "main", "start": 6 }
    ]
  }
]
```

External YAML form (recommended):

```json
"platforms": [
  { "platform": "DMX", "yamlPath": "/homebridge/dmx.yaml" }
]
```

See [`examples/dmx.yaml`](examples/dmx.yaml) for a starting point.

## Color models

| Model | Channels | HomeKit characteristics |
| --- | --- | --- |
| `dimmer` | 1 (Intensity, +optional Fine) | On, Brightness |
| `cct` | 2 (Intensity, ColorTemp `KMin-KMax`) | On, Brightness, ColorTemperature |
| `rgb` | 3 (Red, Green, Blue — any order) | On, Brightness, Hue, Saturation |
| `rgbw` | 4 (+ White; W = min(R,G,B)) | On, Brightness, Hue, Saturation |
| `rgbww` | 5 (+ WarmWhite, CoolWhite — split by CCT) | On, Brightness, Hue, Saturation, ColorTemperature |
| `rgbaw` | 5 (+ Amber, White) | On, Brightness, Hue, Saturation |
| `hsvcct` | 5 (Intensity, Intensity (Fine), ColorTemp, Saturation, Hue) | All five characteristics; HomeKit-native (the WAC DC-WD05 layout) |

Channel-name syntax:

- `(Fine)` appended → 16-bit companion to the preceding channel
  (e.g. `Intensity (Fine)` is the low byte of a 16-bit intensity).
- CCT channels carry a Kelvin range: `ColorTemp 1650-8000`,
  `WarmWhite 2700`, `CoolWhite 6500`.
- Names are case-insensitive and recognise common aliases (`R`/`Red`,
  `WW`/`Warm White`/`WarmWhite`, etc.).

## CLI

A `stick` CLI is included for hand-testing without Homebridge:

```bash
# Set channel 6 of universe A to 255 on a Stick at 192.168.96.2
npx -p @ecopoesis/homebridge-dmx stick 192.168.96.2 uA,6=255

# Named fixture from your YAML
stick --config ~/.config/dmx.yaml 192.168.96.2 a_down=#ff8800
```

Value forms: `#rrggbb`, `#rgb`, `hsl(120, 100%, 50%)`, `hwb(180 10% 20%)`,
`rgb(255,128,0)`, `kelvin(2700)`, `0..255` (dimmer profiles), `on`, `off`,
`50%`.

## Required Stick-DE3 device setup

Brand-new (or factory-reset) Stick-DE3 devices ship with pathological DMX
output timing. Symptom: every DMX change applies ~2–3 minutes late then snaps.
Fix via **USB-connected Hardware Manager** → DMX/fader screen → set
**Standard/Recommended** (MBB 100 / Break 180 / MAB 20 / MBS 4). This screen
is USB-only; a factory Reset does NOT fix it. See `CLAUDE.md` →
"Required device setup" for the full landmine.

## Single-session lock

While the plugin is mid-transaction (~1.5 s per change), the Stick is unusable
from Hardware Manager (single TCP/2431 session, mutually exclusive). For an
idle Homebridge the Stick is free for HWM commissioning at all other times.
The latch model (clean disconnect leaves the last value lit) is what lets us
be polite about this.

## License

Apache-2.0
