# Stick-DE3 Encryption

All of the encryption used by the Stick-DE3 / Hardware Manager protocol,
recovered by reverse engineering and verified end-to-end against captured
sessions.

Two independent crypto primitives are involved:

1. **HMAC-SHA256** — TCP auth handshake (opcode 0x48). Fixed key.
2. **AES-256-CBC** with a P-256 ECDH-derived per-session key — the DMX UDP
   stream and the 0x011c control reply.

For the wire format that uses these, see [PROTOCOL.md](PROTOCOL.md). For the
working implementation, see [`tools/send_dmx.mjs`](tools/send_dmx.mjs) and
[`tools/derive-dmx-key.mjs`](tools/derive-dmx-key.mjs).

## 1. TCP auth — HMAC-SHA256

The opcode 0x48 message authenticates the client to the Stick. The signed
region is the 82-byte head of the message (everything up to and not
including the trailing HMAC):

```
HMAC-SHA256(AUTH_KEY, magic(8) ‖ 0x48 ‖ token(8) ‖ softwareName(32) ‖ stickHandshakeKey(32))
```

The HMAC is appended (32 bytes) to make the full 0x48 message 114 bytes.

### `AUTH_KEY`

A 15-byte ASCII string baked into Hardware Manager. The literal string is:

```
#h.6xcKsGD{y}-z
```

As bytes (hex):

```
23 68 2e 36 78 63 4b 73 47 44 7b 79 7d 2d 7a
```

Embedded as a constant in [`tools/send_dmx.mjs`](tools/send_dmx.mjs#L45) as
`AUTH_KEY`. Originally extracted at runtime with `tools/hmac-key.sh` /
`tools/lldb_hmac_key.py`, then verified against a captured HWM handshake.

A bad HMAC results in 0x48 reply status 100 (`PermissionDenied`), and the
session is never promoted to a live control session — no further opcodes will
work.

## 2. DMX stream cipher — AES-256-CBC, P-256-derived key

The 544-byte body of every DMX UDP frame is AES-256 in CBC mode. The IV is
constructed from two fields in the clear 32-byte header
(`fieldA ‖ nonce`, see [PROTOCOL.md](PROTOCOL.md#aes-iv)). The key is
derived freshly each session from an ECDH-style handshake on opcode 0x0F.

### Mode confirmation

The cipher was statically reverse-engineered from the 2024-03-21 Hardware
Manager binary: custom-inlined AES (S-box at `DAT_1007c0010`), not the
Gladman library reference. The mode bit in the cipher state structure
selects CBC or CFB; the live Stick-DE3 path uses **CBC**, confirmed by
re-encrypting a captured plaintext with the recovered key + IV and
byte-matching the captured ciphertext.

### The KDF (`deriveDmxKey`)

Implemented in [`tools/derive-dmx-key.mjs`](tools/derive-dmx-key.mjs).
Recovered from `FUN_100107650` in the binary. In full:

```
1. d   = random scalar mod n            (client ephemeral private key)
2. our = d · G                          (client ephemeral public key)
3. send `our`, receive Stick pubkey `Q`  (opcode 0x0F handshake)
4. S   = decompress(STATIC_POINT_COMPRESSED)
5. AES-256 key = LE( X(d · S)  XOR  X(d · Q) )
```

This is a **two-DH construction**: one ECDH against the hardcoded static
point `S` (authenticates the application — anyone who doesn't know `S`
can't talk to the Stick), and one against the Stick's per-session ephemeral
`Q` (provides forward secrecy across sessions).

The Stick computes the identical key on its side as
`X(s · our) XOR X(e · our)`, where `s` and `e` are the Stick's static and
ephemeral private scalars. The two agree by ECDH symmetry.

### Curve parameters

NIST P-256 / secp256r1 / prime256v1. Confirmed three ways from the binary —
prime, order, and base point all byte-match P-256, and the curve `b`
constant `5ac635d8…27d2604b` is used during point decompression.

```javascript
p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
a  = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc  // -3 mod p
b  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
```

### The static point `S`

A 33-byte SEC1-compressed P-256 point stored verbatim in the Hardware
Manager binary at file offset `0x7b0490` (vmaddr `0x1007b0490`). The
prefix byte `0x03` indicates odd-Y:

```
03 28 08 12 90 39 6d 06 3e 51 14 52 6e d9 78 b9
26 55 8f 6b a1 c9 6a d2 fa cf 76 ff fb 3f fe a0 fe
```

Embedded as `STATIC_POINT_COMPRESSED` in
[`tools/derive-dmx-key.mjs`](tools/derive-dmx-key.mjs#L68).

(An earlier RE pass tried XOR-masking these bytes with `0x51, 0x52, …`,
which produces a different point used elsewhere in the app. That isn't the
KDF static point — the raw bytes above are the ones that reproduce a real
session's installed AES key. Confirmed by `tools/verify-kdf.mjs` against an
lldb-dumped ephemeral `d` plus the Stick pubkey from a captured handshake.)

### Endianness

The Stick stores every 256-bit coordinate as **little-endian limbs** (byte 0
is the least-significant byte). Node's `crypto` works in big-endian SEC1
form, so a byte-reverse happens at every wire boundary:

- The 64-byte public key sent on opcode 0x0F is `LE(X) ‖ LE(Y)`. See
  `pointToWire()` / `wireToPoint()` in `derive-dmx-key.mjs`.
- The installed AES key is the **little-endian form** of `X(d·S) ⊕ X(d·Q)`.
  See `deriveDmxKey()` lines 128-135.

Forgetting the byte-reverse on the key was a multi-day debugging detour.

### Plaintext header `P0`

The first 16 bytes of every frame's plaintext are a fixed constant baked
into Hardware Manager:

```
5b 4e 99 da 96 85 ad 97 6c 43 2b 0a 7f f9 ff cc
```

Embedded as `P0` in [`tools/send_dmx.mjs`](tools/send_dmx.mjs#L41). The
Stick decrypts the body and verifies the first 16 bytes equal `P0` before
accepting the frame. This is effectively a known-plaintext anchor /
integrity check — a frame encrypted with the wrong key fails this check
even though CBC otherwise has no built-in authentication.

The 16 bytes immediately after `P0` are zero in every observed frame; we
send zeros there. The 512 DMX channel bytes follow at plaintext offset 32.

## 3. The 0x011c reply

The TCP/2431 reply to opcode 0x011c is encrypted device-info using the same
AES-256 session key. The body is not needed for the DMX control path and
its plaintext schema is not fully documented here. Tooling that decrypted
it for analysis:

- [`tools/extract-011c.mjs`](tools/extract-011c.mjs)
- [`tools/find-011c-key.mjs`](tools/find-011c-key.mjs)
- [`tools/decrypt-011c.mjs`](tools/decrypt-011c.mjs)
- [`tools/verify-011c-key.mjs`](tools/verify-011c-key.mjs)
- [`tools/diff-011c.mjs`](tools/diff-011c.mjs)

`send_dmx.mjs` sends the 0x011c request (it's part of the wire-faithful
handshake sequence) and discards the reply.

## What's NOT encrypted

- **Discovery broadcasts** on UDP/2430 (the four `LSAG_ALL`/`Stick_U1`/
  `Stick_3A`/`Siudi_7B` startup packets) are clear.
- **UDP/2430 "Quick Trigger"** is clear and unauthenticated by design — see
  [PROTOCOL.md §Quick Trigger](PROTOCOL.md#udp2430--quick-trigger-documented-but-limited).
  Scene-level only; cannot set individual DMX channels.
- **`LIGHTINGSOFT_XHL`** beacons on UDP/24299 are clear.
- **The 32-byte UDP/2431 DMX frame header** is clear (this is what carries
  the IV components).
- **TCP opcodes 0x47, 0x48, and the handshake chatter (0x46, 0x09, 0x00,
  0x05, 0x10, 0x0F, 0x70, 0x71, 0x74, 0x75, 0x2e, 0x11)** are clear. Only
  the 0x011c reply body and the DMX UDP body are AES-encrypted.

## Verification harness

The KDF self-test runs without hardware:

```sh
node tools/derive-dmx-key.mjs
```

It exercises ECDH symmetry, the wire round-trip, and the real static point.
End-to-end verification against captured sessions uses
`tools/verify-kdf.mjs`, `tools/verify-011c-key.mjs`, and the lldb dumps in
`tools/lldb_*.py`.

## Provenance summary

| Constant | Where it lives in HWM | Recovery method |
|----------|----------------------|-----------------|
| `AUTH_KEY` (15B) | string literal | `tools/hmac-key.sh`, lldb HMAC trace |
| `STATIC_POINT_COMPRESSED` (33B) | file offset `0x7b0490` | static RE (Ghidra), verified against captured KDF output |
| `P0` (16B plaintext header) | constant inlined in frame builder | static RE, verified against decrypted captured frame |
| Curve = P-256 | code constants | byte-match against NIST P-256 |
| Mode = AES-256-CBC | custom-inlined AES, S-box at `DAT_1007c0010` | static RE + ciphertext byte-match |
| KDF = `X(d·S) ⊕ X(d·Q)` | `FUN_100107650` | static RE, verified `tools/verify-kdf.mjs` |
