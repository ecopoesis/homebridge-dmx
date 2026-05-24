# Stick-DE3 Protocol

What we know about the Nicolaudie Stick-DE3 wire protocol, focused on the path
needed to drive per-channel DMX from a third-party client. Everything below
was reverse-engineered from packet captures of Hardware Manager / ESA Pro 2
plus static RE of the 2024-03-21 macOS Hardware Manager binary.

The authoritative implementation is [`tools/send_dmx.mjs`](tools/send_dmx.mjs).
This document is the explanation; the code is the spec.

For the encryption details (KDF, key material, AES mode), see
[ENCRYPTION.md](ENCRYPTION.md).

## Ports & transports

| Port | Transport | Direction | Purpose |
|------|-----------|-----------|---------|
| 2431 | TCP       | client → Stick | Control + per-session key exchange. Single session, mutually exclusive with HWM. |
| 2431 | UDP       | client → Stick | Live DMX stream (encrypted 576-byte frames). |
| 2430 | UDP       | bidirectional, broadcast | Discovery + the documented "Quick Trigger" scene control. |
| 24299 | UDP      | client broadcast | Hardware Manager presence announce (`LIGHTINGSOFT_XHL`). |

The DMX UDP stream uses **source port 2430** and destination port 2431.
This pairing matters — the Stick filters on it.

## Message framing (TCP/2431)

Every TCP message starts with an 8-byte ASCII magic, then a 2-byte
little-endian opcode, then opcode-specific payload:

```
+--------+--------+----------------+
| magic  | opcode | payload …      |
| 8B     | 2B LE  | variable       |
+--------+--------+----------------+
```

Two magics are used:

- `Stick_3A` — the Stick's identity; used for most messages.
- `LSAG_ALL` — broadcast/handshake magic; used for the initial auth opcodes
  (0x47, 0x48) and for discovery.

Most payloads begin with an 8-byte session token. The token is a single
monotonically-increasing little-endian uint32 (padded to 8 bytes) that
**continues across both TCP messages and the UDP DMX frames** within the same
session. Restarting the counter, or using a separate counter for UDP, causes
the Stick to drop every frame. Initial value in our implementation is `0x80`
to mirror HWM.

## TCP handshake (go-live)

Sequence observed from HWM and replicated by `send_dmx.mjs`. Numbers in
parens are the opcode in hex.

1. **`LSAG_ALL` 0x47 — hello.** Client sends `magic ‖ opcode ‖ token(8)`.
   Stick replies with a 54-byte message; bytes `[0x16:0x36]` are a 32-byte
   per-session "Stick handshake key" used in step 2.
2. **`LSAG_ALL` 0x48 — authenticated handshake.** Layout:
   ```
   magic(8) ‖ 0x48 ‖ token(8) ‖ softwareName(32) ‖ stickHandshakeKey(32) ‖ hmac(32)
   ```
   The HMAC is `HMAC-SHA256(AUTH_KEY, first 82 bytes)`. `AUTH_KEY` is a
   15-byte string baked into Hardware Manager (see [ENCRYPTION.md](ENCRYPTION.md)
   for the recovered value). Reply contains a status uint32 at `[0x12]`:
   `0` = ok, `100` = `PermissionDenied`. A rejected HMAC means the session
   never gets promoted to live.
3. **Pre-DMX chatter** — six small messages, **each sent in its own TCP
   segment** (HWM never coalesces these; coalescing them empirically prevents
   the Stick from emitting its 0xc9 status):
   ```
   Stick_3A 0x46  4 zero bytes
   Stick_3A 0x09  "14000000"
   Stick_3A 0x09  "14000000"
   Stick_3A 0x00  "14000000"
   Stick_3A 0x011c  token(8) ‖ "01001600"
   Stick_3A 0x05  "0200"
   ```
   After this the Stick sends a `0x00c9` status indicating the session is
   registered. Our implementation paces these with `CHATTER_MS` (default 10ms;
   tested down to 5ms with no failures).
4. **`Stick_3A` 0x10 — crypto-state query.** Reply has a state uint32 at
   `[0x12]`: state 3 on a fresh device, state 4 if a DMX key from a previous
   session is still latched.
5. **`Stick_3A` 0x0F — DMX key exchange.** Client sends its 64-byte P-256
   ephemeral public key (X ‖ Y, both little-endian limbs — see
   [ENCRYPTION.md](ENCRYPTION.md)). Stick replies with its own 64-byte
   P-256 public key at `[0x16:0x56]`. The Stick's public key has been
   observed identical across every session captured to date; a static
   fallback is hardcoded in `send_dmx.mjs` for resiliency.
6. **Device sync chatter** — observed from HWM, byte-for-byte:
   ```
   Stick_3A 0x10  token
   Stick_3A 0x75  token
   Stick_3A 0x74  token
   Stick_3A 0x71  token ‖ "0200000000"
   Stick_3A 0x71  token ‖ "0100000000"
   Stick_3A 0x71  token ‖ "0100000000"
   Stick_3A 0x71  token ‖ "02b37f0000"
   ```
   These appear to be informational reads. The 4th `0x71` was the one HWM
   pattern previously missed by our impl.
7. **`Stick_3A` 0x70 — sector reads (skippable).** HWM reads sector 0
   followed by sectors 63..185 (124 reads) to populate its commissioning UI.
   Empirically the Stick will latch values even with `SECTORS=0`; this is
   HWM UI chatter, not a Stick precondition. `send_dmx.mjs` defaults to
   skipping it (saves ~1.5s/transaction).
8. **`Stick_3A` 0x2e — go-live primer.** 32 zero bytes payload. HWM then
   waits ~3.7s (UI-paced); the Stick only needs a much shorter settle. We
   use 50ms via `SETTLE_2E_MS`.
9. **`Stick_3A` 0x10, 0x11, 0x10** — enters live mode. The 0x11 reply
   confirms live mode is active; a follow-up 0x10 should now report crypto
   state 4.

## DMX UDP frames (576 bytes)

Once the session is live, DMX values are sent as encrypted 576-byte UDP
datagrams from src-port 2430 → dst-port 2431.

```
+----------------------------------+-----------------------------------------+
| 32-byte clear header             | 544-byte AES-256-CBC ciphertext         |
+----------------------------------+-----------------------------------------+
```

### Clear header (32 bytes)

| Offset | Size | Field | Value / meaning |
|--------|------|-------|-----------------|
| 0x00   | 8    | magic | `Stick_3A` |
| 0x08   | 2    | opcode | `0x0019` LE |
| 0x0a   | 8    | `fieldA` | session token (same counter as TCP tokens — continues the sequence) |
| 0x12   | 2    | port / universe | DMX port selector, LE |
| 0x14   | 2    | channel count | `512` LE |
| 0x16   | 1    | constant | `100` (HWM's value) |
| 0x17   | 1    | sequence byte | per-frame counter mod 256 |
| 0x18   | 8    | nonce | random per frame |

### AES IV

The 16-byte AES-CBC IV is `fieldA (8) ‖ nonce (8)` — i.e. the two header
fields at offsets 0x0a and 0x18. The receiver pulls these straight out of
the clear header to decrypt.

### Plaintext layout (544 bytes)

```
+---------------------+---------------------+-------------------------+
| P0 (16B constant)   | header2 (16B zeros) | 512 DMX channel bytes   |
+---------------------+---------------------+-------------------------+
0                    16                   32                       544
```

`P0` is a fixed 16-byte constant baked into HWM (see
[ENCRYPTION.md](ENCRYPTION.md)). It serves as a known-plaintext anchor —
when the Stick decrypts a frame, the first 16 bytes of plaintext must
equal `P0` or the frame is dropped.

`header2` has been observed all-zero in every captured frame. It may be
meaningful in some other path; we send zeros and the Stick accepts it.

**Channel data starts at plaintext offset 32**, not 16. This was an
off-by-16 bug in an earlier impl (we lit HWM's channel 6 when sending to
ours-channel 22, because 22 - 16 = 6).

## Transactional streaming & the latch

The Stick holds the last received DMX values **on disconnect** (any kind that
doesn't send HWM's "polite goodbye" opcode — which we have never observed
identified). This lets a client be transactional rather than maintaining a
persistent stream:

1. Connect, run the handshake, derive the session key.
2. Stream encrypted DMX frames at 25Hz for ~750ms (~19 frames). The Stick
   commits values after roughly 12 frames at 25Hz; below ~500ms wall-time
   the commit doesn't happen.
3. `socket.destroy()` (RST). The Stick latches the last frame's values.

Trade-off: each transaction takes ~1.5–2s end-to-end (handshake + stream +
disconnect), and the wall controller blinks briefly on disconnect — HWM
exhibits the same blink, so it's at the protocol layer, not avoidable from
the client side.

## UDP/2430 broadcast — discovery

HWM emits a startup burst on UDP/2430 (255.255.255.255):

```
LSAG_ALL <8B zeros> 14 00 00 00
Stick_U1 <8B zeros> 14 00 00 00
Stick_3A <8B zeros> 14 00 00 00
Siudi_7B <8B zeros> 14 00 00 00
```

…repeated three times with a 25ms gap. `send_dmx.mjs` does the same before
connecting; it doesn't appear to be required (the Stick is reachable by IP
without it) but matches HWM exactly.

## UDP/2430 — "Quick Trigger" (documented but limited)

Nicolaudie's STICK Remote Protocol spec defines a 24-byte UDP packet on port
2430 with **no authentication** and **no encryption**. See
[`tools/quick-trigger.mjs`](tools/quick-trigger.mjs):

```
[0..7]   "Stick_3A"
[8..9]   opcode 109 (0x6D 0x00)
[10..11] Scene number (page*50 + sceneInPage), LE
[12]     ZoneSyncId
[13]     Command (0=scene-off, 1=scene-on, 5=dimmer, 7=color, 8/9=blackout, …)
[14..15] Dimmer, LE
[16..17] Speed, LE
[18..19] unused
[20..23] R, G, B, 0
```

Useful for testing connectivity but **scene-level only**: it cannot set
individual DMX channels, and on fw3.08 it is gated by "Security for Cloud
Access" (must be disabled in Hardware Manager for the device to action it).
For per-fixture HomeKit control, the encrypted UDP/2431 path is the only
route.

## UDP/24299 — `LIGHTINGSOFT_XHL` presence broadcast

HWM broadcasts an "I am Hardware Manager" beacon on UDP/24299 (src+dst
24299) at startup: one 114-byte announce containing the literal string
`Hardware Manager`, followed by two 46-byte status packets. The 32-byte
header is:

```
"LIGHTINGSOFT_XHL"  16B
00 00 00 00 00 00 00 00   8B zeros
14 00 00 00               op/len = 20
01 00 00 00               version = 1
```

We have no Stick-side traffic acknowledging these but HWM emits them
consistently, and `send_dmx.mjs` replicates them. Mode of action unconfirmed.

## TCP/2431 — passive status

Per the STICK Remote Protocol spec, once a client connects to TCP/2431 the
Stick emits a status packet every 5s. [`tools/stick-status.mjs`](tools/stick-status.mjs)
reads it:

| Offset | Field |
|--------|-------|
| 0..7   | `Stick_3A` |
| 8      | opcode |
| 9      | version |
| 10..11 | scene number |
| 12..23 | scene name (NUL-terminated) |
| 24     | zone number |
| 25..36 | zone name |
| 37..38 | dimmer |
| 39..41 | R, G, B |
| 42..43 | speed |
| 47     | **RemoteClientsCount** |
| 48     | **LiveModeIsActivated** (1 = live/remote, 0 = standalone) |

On fw2.x/3.x the LSAG/auth challenge must complete before status is emitted;
without that the client sees only the auth-challenge reply.

## Open questions

- **The "polite goodbye" opcode** — HWM has a right-click menu option that
  cleanly disconnects and *does not* latch. The opcode that triggers that
  exit path has not been identified. Every other disconnect we've tried
  (FIN, RST, process kill, cmd-Q) latches.
- **The 0x011c reply body** is AES-encrypted device-info; the full payload
  schema is undocumented. `tools/decrypt-011c.mjs`, `extract-011c.mjs`,
  `find-011c-key.mjs`, `verify-011c-key.mjs`, `diff-011c.mjs` were used to
  recover its key; the contents are not needed for the DMX path.
- **The 0x10 crypto-state values** — 3 = pre-handshake, 4 = key installed.
  Other values not observed.
- **`Siudi_7B`** discovery magic — the Stick-DE3 doesn't respond to this
  one; presumably it targets a different product line.
