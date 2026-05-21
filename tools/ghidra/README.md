# Stick-DE3 DMX cipher RE — Ghidra static analysis

Headless pyghidra scripts that reverse-engineer the DMX cipher in the
**2024-03-21 ESA2 HardwareManager** binary at:

```
/Applications/ESA2/HardwareManager/HardwareManager.app/Contents/MacOS/HardwareManager
```

Static RE *replaces* the prior interactive-lldb attempts (see
`memory/stick-aes-symbolized-breakthrough.md` for what didn't work, and
`memory/stick-cipher-is-stream-not-aes.md` for what's now known).

## TL;DR — the cipher is NOT AES

Prior live-RE / `try-decrypt.ts` heuristics had this misidentified as
AES-128-CBC. Static RE proves it is a **custom small-state stream cipher**
(8 × u32 state, ISAAC-style shift-XOR-and-table-lookup mixers). The
576-byte DMX frame format:

```
+0x00 (8B)   session_magic    table @ DAT_100d11a90 + idx*0x0E
+0x08 (2B)   0x0019           constant
+0x0A (8B)   8-byte from vtable slot 0x78
+0x12 (2B)   port16
+0x14 (2B)   channel count (≤512)
+0x16 (1B)   100              constant
+0x17 (1B)   seq_counter++
+0x18 (8B)   8 random bytes   nonce
+0x20 (544B) ENCRYPTED        XOR with keystream from FUN_1005e0530
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
| 0x100108200 | **The encrypt function** (XOR with keystream)        |
| 0x1005e0530 | **Keystream generator** (8-state LFSR)               |
| 0x1001b0340 | `XHL_UdpSocket::send`                                |
| 0x100677060 | `sendto` wrapper                                     |

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

## What's left

1. **Cipher state initialization** — where does the 8-word state at
   `cryptObj+0x24..0x44` come from? Static constants, RNG, or derived
   from the TCP/2431 handshake. Trace the constructor that writes
   the Stick3 vptr value `0x100962BE8`.
2. **Session-magic table** — `DAT_100d11a90` is a table of 14-byte entries.
   Decode it.
3. **Random nonce source** — `FUN_100108670` (likely `std::mt19937`).
   Either reproduce or pick our own.
