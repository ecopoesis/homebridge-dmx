# Stick-DE3 DMX cipher RE — Ghidra static analysis

Headless pyghidra scripts that reverse-engineer the DMX cipher in the
**2024-03-21 ESA2 HardwareManager** binary at:

```
/Applications/ESA2/HardwareManager/HardwareManager.app/Contents/MacOS/HardwareManager
```

Static RE *replaces* the prior interactive-lldb attempts (see
`memory/stick-aes-symbolized-breakthrough.md` for what didn't work, and
`memory/stick-cipher-is-stream-not-aes.md` for what's now known).

## TL;DR — the cipher IS AES-128 (with mode dispatch)

The Stick3 DMX cipher is **AES-128** (custom-inlined, not Gladman), running
in CBC or CFB mode depending on a flag in the cipher state. Earlier in this
RE session I briefly concluded "stream cipher, not AES" — that was wrong;
I had been looking at a sibling class (`XHL_DasEccStreamCryptography`, used
for USB devices) whose encrypt path uses a small-state stream cipher. The
*Stick3 ANet* path doesn't go through that. The real AES path is via
`FUN_100107950` → `FUN_1003f6790` (CBC) / `FUN_1003f5140` (CFB) → block
cipher at `FUN_1003f5980` / `FUN_1003f4690` with S-box at `DAT_1007c0010`.

576-byte DMX frame format:

```
+0x00 (8B)   session_magic    table @ DAT_100d11a90 + idx*0x0E
+0x08 (2B)   0x0019           constant
+0x0A (8B)   8-byte from vtable slot 0x78
+0x12 (2B)   port16
+0x14 (2B)   channel count (≤512)
+0x16 (1B)   100              constant
+0x17 (1B)   seq_counter++
+0x18 (8B)   8 random bytes   nonce / first-block IV seed
+0x20 (544B) ENCRYPTED        AES-128 (CBC or CFB) — 34 blocks of 16 bytes
```

## Key addresses

| Addr        | Function                                            |
|-------------|------------------------------------------------------|
| 0x10006C8A0 | `DmxWidget::onTimerSendAndReceive` (Qt timer slot)   |
| 0x100074090 | `DmxUniversePage::onTimerSendReceive`                |
| 0x100073BD0 | `DmxUniversePage::sendDmx` (QtConcurrent worker fn)  |
| 0x1001a9d50 | `Stick3CryptDmxUniverse` "send DMX" (vt[22] primary) |
| 0x1001eeac0 | Frame-build wrapper                                  |
| 0x1001ee990 | Build encrypted frame                                |
| **0x100107950** | **Real encrypt entry** (mode-dispatch CBC vs CFB) |
| 0x1003f5140 | AES-CFB outer (uses IV at +0xB0)                     |
| **0x1003f4690** | **AES-128 block cipher (CFB path, 1153 B)**      |
| 0x1003f6790 | AES-CBC outer (chains with previous ciphertext)      |
| **0x1003f5980** | **AES-128 block cipher (CBC path, 1872 B)**      |
| **DAT_1007c0010** | **AES S-box** (256 bytes)                      |
| 0x1001b0340 | `XHL_UdpSocket::send`                                |
| 0x100677060 | `sendto` wrapper                                     |

The earlier "stream cipher" addresses (`FUN_100108200`, `FUN_1005e0530`) are
for `XHL_DasEccStreamCryptography` — a sibling class for USB devices, NOT
on the Stick3 DMX path.

Typeinfo addresses (for further vtable hunting via `dyld_info -fixups`):

| Class                          | TypeInfo @     |
|--------------------------------|----------------|
| XHL_Stick3CryptDmxUniverse     | 0x100970DC0    |
| XHL_DasEccStreamCryptography   | 0x100852080    |
| XHL_DasEccAesCryptography      | 0x100851ED8    |
| XHL_AesOStream                 | 0x100851C48    |

## Reproduce

```bash
# Install (one-time)
brew install ghidra

# Run any script (-noanalysis once initial import has been done)
/opt/homebrew/Cellar/ghidra/12.1/bin/pyghidraRun -H \
    tools/ghidra HwmESA2 \
    -import /Applications/ESA2/HardwareManager/HardwareManager.app/Contents/MacOS/HardwareManager \
    -scriptPath tools/ghidra \
    -postScript dump-anchors.py
```

After the first run, omit `-import` and add `-process HardwareManager
-noanalysis` to re-run scripts against the saved project (fast).

## Scripts

- `dump-anchors.py` — dump every named DMX/AES anchor function (Gladman, sendto, RTTI strings)
- `find-cipher.py` — chase XHL_UdpSocket::sendto callers and any RTTI vtable
- `find-vtables.py` — scan for typeinfo bytes in `__const` (mostly empty: Mach-O chained fixups)
- `string-walk.py` — find typeinfo-name strings then follow their data xrefs
- `find-stick3-crypto.py` — search Ghidra symbols by class-name keyword (mostly empty)
- `dump-stick3-vtable.py` — dump every Stick3 primary + secondary vtable slot fn
- `dump-cipher.py` — dump the encrypt chain rooted at `FUN_1001a9d50`
- `dump-aes-candidates.py` — dump candidate encrypt fn vt[3] across classes

## Side-channel: `dyld_info -fixups`

Mach-O chained fixups aren't materialized by Ghidra for unsymbolized
typeinfos. Use `xcrun dyld_info -fixups <binary>` to dump every rebase /
bind. Vtables for hidden classes are reached by grepping for rebases
targeting a known typeinfo struct address. Example:

```bash
xcrun dyld_info -fixups <binary> | grep 'rebase  0x100970DC0$'
# Each result is a vtable's typeinfo_ptr field; vt[0] is +8.
```

## KDF — SOLVED & VERIFIED (2026-05-21)

The per-session AES-256 key derivation is fully recovered by static RE and
**verified end-to-end** against a real captured session.
Scripts `dump-kdf-chain.py`, `dump-curve.py`, `dump-secret.py` decompile the
chain `FUN_100178030 → FUN_100107650`. Result:

- **Curve = NIST P-256.** `p`, `n`, `G`, and the `b` constant all byte-match.
- **KDF:** `key = LE( X(d·S) XOR X(d·Q) )` — `d` ephemeral, `S` a hardcoded
  static point (raw 33-byte SEC1 point at `0x1007b0490`), `Q` the Stick
  pubkey from the opcode-0x0F handshake.
- **Reference impl:** `tools/derive-dmx-key.mjs` (passing self-test).
- **Proof:** `tools/verify-kdf.mjs` recomputes a real session's installed
  AES key byte-for-byte (using an lldb-dumped `d` + the handshake pcap).

Ghidra shows the curve-constant DATs as zero — its `__const`/`__data` blocks
weren't materialized. Read them straight from the Mach-O file:
`file_offset = vmaddr − 0x100000000`. Full write-up:
`memory/stick-cipher-is-stream-not-aes.md`.

## What's left

1. **Session-magic table** — `DAT_100d11a90` is a table of 14-byte entries.
   Decode it (frame `+0x00` magic + handshake validation).
2. **Random nonce source** — `FUN_100108670` (likely `std::mt19937`).
   Either reproduce or pick our own.
