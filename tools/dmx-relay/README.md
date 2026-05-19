# Stick-DE3 pacing relay

A zero-dependency Node relay that sits between Nicolaudie **Hardware Manager /
ESA Pro 2** and the **Stick-DE3** to stop the controller being overwhelmed.

## The problem

DMX512 on the wire tops out around **44 Hz** (250 kbaud, 44 µs/slot, ~22.7 ms
for a full 512-channel frame). The Stick generates that waveform at its own
fixed rate no matter how fast you feed it. A gigabit PC running Nicolaudie's
live output streams UDP **far** faster than that — the Stick's network task
starves its DMX engine, so:

- lights freeze / stay on for a while, and
- the single TCP control session never frees, so you **can't reconnect** after
  restarting Hardware Manager until you power-cycle the Stick.

## What the relay does

| Channel   | Behaviour |
|-----------|-----------|
| UDP/2430  | Last-frame-wins coalescing, forwarded to the Stick at a fixed `RATE_HZ` (default 40). Excess frames are dropped, not buffered. |
| TCP/2431  | Transparent proxy, **one session at a time**. A new client connection hard-RSTs the previous client *and* upstream sockets so the Stick immediately frees its session slot — this is the reconnect fix. |

It is a transparent forwarder: it does **not** do Nicolaudie device discovery.
You point the software at the relay's IP manually (confirmed supported in this
setup).

## Deploy (Portainer on server03)

server03 can route to the Stick at `192.168.96.2`, so the container runs with
**host networking** and binds `2430/udp` + `2431/tcp` on server03 directly.

1. Portainer → **Stacks** → **Add stack**.
2. Point it at this directory (`tools/dmx-relay/`) via the Git repository
   option, or paste `docker-compose.yml` into the web editor.
3. Adjust env if needed (defaults are fine):
   - `STICK_IP` — `192.168.96.2`
   - `RATE_HZ` — `40` (don't exceed ~44)
   - `STALE_MS` — stop streaming this long after Nicolaudie goes quiet
   - `COALESCE_KEY_BYTES` — `0` for our single universe; raise only if
     Nicolaudie streams multiple universes as separate datagrams
4. Deploy, then in **Hardware Manager / ESA Pro 2** set the Stick's address to
   **server03's IP** instead of `192.168.96.2`.

Confirm in the container logs:

```
UDP pacer  0.0.0.0:2430  ->  192.168.96.2:2430  @ 40 Hz
TCP proxy  0.0.0.0:2431  ->  192.168.96.2:2431  (single session, RST on supersede)
stats  udp in=2400 out=400 dropped=2000  tcp=connected
```

`in` ≫ `out` with a high `dropped` count is the relay working as intended:
it's absorbing the flood and pacing the Stick at the wire rate.

## Run locally (without Docker)

```bash
STICK_IP=192.168.96.2 node tools/dmx-relay/relay.mjs
```

Requires Node ≥ 18.

## Tuning notes

- If fixtures look choppy, raise `RATE_HZ` toward 44 — never above.
- If the Stick still wedges, lower `RATE_HZ` (e.g. 25–30); some standalone
  controllers are happy well below the wire ceiling.
- `dropped` near zero means Nicolaudie isn't actually flooding — the relay is
  then just a clean TCP session manager, which still fixes reconnect.
