"""
Path C-lite — runtime key-trace via one-shot lldb breakpoints.

When the passive scan can't find the key (it isn't a byte-contiguous window
of the cipher object), the key/round-schedule is either expanded transiently
on the stack per frame, or stored somewhere a register points to during
encryption. This catches it: breakpoint the encrypt path, and the instant it
fires, dump every register + the memory it points at + the stack, then run
the AES key-schedule detector over all of it.

NOT a persistent breakpoint. It fires, captures once, deletes all
breakpoints, and the batch detaches — HWM is stopped only ~1-2s total
(same as the passive scan).

Breakpoints (ESA2 2024-03-21 file addrs, from the Ghidra RE):
  0x100107950  encrypt entry (mode dispatch)   -> capture device, keep going
  0x1003f5980  AES block, CBC path             -> capture stack+regs, stop
  0x1003f4690  AES block, CFB path             -> capture stack+regs, stop
If no block bp fires within 6 frames, capture at the entry and stop anyway,
so the batch always terminates cleanly (no HWM kill on hang).

Usage (driven by tools/pathC-keytrace.sh):
  lldb -p <PID> --batch \
       -o "command script import tools/lldb_pathC_keytrace.py" \
       -o "continue" -o "detach" -o "quit"
"""

import os
import time

try:
    import lldb
except ImportError:
    lldb = None

# --- breakpoint file addresses (image vmaddrs) ----------------------------
FA_ENTRY     = 0x100107950
FA_CBC_BLOCK = 0x1003F5980
FA_CFB_BLOCK = 0x1003F4690
CIPHER_VPTR_FILEADDR = 0x10095F838

LOG_PATH = "/tmp/stick-pathC-keytrace.log"

# --- AES key-schedule detectors (AES-128 and AES-256) --------------------
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def aes128_schedule_check(b):
    if len(b) < 176:
        return None
    w = [b[4 * i:4 * i + 4] for i in range(44)]
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = bytes((SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]))
            t = bytes((t[0] ^ RCON[i // 4 - 1], t[1], t[2], t[3]))
        if bytes((w[i - 4][k] ^ t[k] for k in range(4))) != w[i]:
            return None
    return b[0:16]


def aes256_schedule_check(b):
    if len(b) < 240:
        return None
    w = [b[4 * i:4 * i + 4] for i in range(60)]
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = bytes((SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]))
            t = bytes((t[0] ^ RCON[i // 8 - 1], t[1], t[2], t[3]))
        elif i % 8 == 4:
            t = bytes((SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]))
        if bytes((w[i - 8][k] ^ t[k] for k in range(4))) != w[i]:
            return None
    return b[0:32]


def find_schedules(blob):
    """Return list of (offset, bits, key) for every AES schedule in blob."""
    hits = []
    for o in range(0, len(blob) - 176):
        k = aes128_schedule_check(blob[o:o + 176])
        if k is not None:
            hits.append((o, 128, k))
        if o < len(blob) - 240:
            k2 = aes256_schedule_check(blob[o:o + 240])
            if k2 is not None:
                hits.append((o, 256, k2))
    return hits


# --- state ---------------------------------------------------------------
_logf = None
_entry_hits = 0
_done = False
_blobs = []          # list of (label, addr, bytes)


def log(msg=""):
    global _logf
    print(msg)
    if _logf:
        _logf.write(msg + "\n")
        _logf.flush()


def hexsp(b):
    return " ".join("%02x" % x for x in b)


def read_mem(process, addr, size):
    err = lldb.SBError()
    d = process.ReadMemory(addr, size, err)
    return d if (err.Success() and d) else None


def cipher_vptr_runtime(target):
    for m in target.module_iter():
        if m.GetFileSpec().GetFilename() == "HardwareManager":
            a = m.ResolveFileAddress(CIPHER_VPTR_FILEADDR).GetLoadAddress(target)
            return a if a != lldb.LLDB_INVALID_ADDRESS else 0
    return 0


def capture(frame, where):
    """Dump registers + pointed-to memory + stack + (if found) the cipher
    object / device struct. Accumulate into _blobs."""
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    vptr = cipher_vptr_runtime(target)

    log("")
    log("=" * 68)
    log("CAPTURE @ %s" % where)
    log("=" * 68)

    gpr = ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rbx",
           "rbp", "rsp", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]
    regs = {}
    for r in gpr:
        v = frame.FindRegister(r)
        regs[r] = v.GetValueAsUnsigned() if v.IsValid() else 0
        log("  %-4s = 0x%x" % (r, regs[r]))

    # dump memory each plausible pointer register points at
    for r in ["rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rbx",
              "r12", "r13", "r14", "r15"]:
        a = regs[r]
        if 0x10000 < a < 0x7fffffffffff:
            d = read_mem(process, a, 768)
            if d:
                _blobs.append(("%s_ptr_0x%x" % (r, a), a, d))
                # if this points at the cipher object, also grab the whole
                # device struct (cipher subobject is at device + 0x1618)
                if vptr and len(d) >= 8 and int.from_bytes(d[0:8], "little") == vptr:
                    dev = a - 0x1618
                    big = read_mem(process, dev, 0x3800)
                    if big:
                        _blobs.append(("device_0x%x" % dev, dev, big))
                        log("  %s -> cipher object; dumped device struct @ 0x%x" % (r, dev))

    # the stack — a transiently-expanded schedule lives here during encrypt
    rsp = regs["rsp"]
    st = read_mem(process, rsp - 0x400, 0x4400)
    if st:
        _blobs.append(("stack_0x%x" % (rsp - 0x400), rsp - 0x400, st))
        log("  dumped stack 0x%x .. 0x%x" % (rsp - 0x400, rsp - 0x400 + len(st)))


def finalize():
    global _done
    if _done:
        return
    _done = True

    log("")
    log("=" * 68)
    log("ANALYSIS — %d memory blob(s) captured" % len(_blobs))
    log("=" * 68)

    # save every blob; run the schedule detector across all of them
    found = []
    for label, addr, data in _blobs:
        path = "/tmp/stick-pathC-blob-%s.bin" % label
        with open(path, "wb") as f:
            f.write(data)
        scheds = find_schedules(data)
        log("  %-26s %6d B @ 0x%x  -> %s"
            % (label, len(data), addr,
               "%d schedule(s)!" % len(scheds) if scheds else "saved"))
        for off, bits, key in scheds:
            log("      *** AES-%d KEY @ %s+0x%x = %s"
                % (bits, label, off, hexsp(key)))
            found.append((bits, key))

    log("")
    if found:
        log("*** KEY(S) RECOVERED FROM A LIVE ROUND-KEY SCHEDULE ***")
        seen = set()
        n = 0
        for bits, key in found:
            h = key.hex()
            if h in seen:
                continue
            seen.add(h)
            with open("/tmp/stick-pathC-key-%d.bin" % n, "wb") as f:
                f.write(key)
            log("  key %d (AES-%d): %s" % (n, bits, hexsp(key)))
            n += 1
        log("")
        log("verify: node tools/try-key.mjs <frame.bin> <key-hex>")
    else:
        log("No standard AES schedule in the captured memory.")
        log("The raw key may still be in these blobs in a non-standard layout.")
        log("Brute-force them against a captured frame:")
        log("  node tools/crack-key.mjs <frame.bin> /tmp/stick-pathC-blob-*.bin")
    log("")
    log("done — detaching. log: %s" % LOG_PATH)


# --- breakpoint callbacks ------------------------------------------------
def on_entry(frame, bp_loc, internal_dict):
    global _entry_hits
    _entry_hits += 1
    if _entry_hits == 1:
        capture(frame, "encrypt-entry FUN_100107950 (frame 1)")
    if _entry_hits >= 6:
        log("")
        log("no AES-block breakpoint fired in %d frames — finalizing at entry"
            % _entry_hits)
        finalize()
        return True          # stop
    return False             # keep running so a block bp can fire


def on_block(frame, bp_loc, internal_dict):
    capture(frame, "aes-block (CBC/CFB path)")
    finalize()
    return True              # stop


def __lldb_init_module(debugger, internal_dict):
    global _logf
    _logf = open(LOG_PATH, "w")

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        log("ERROR: no target")
        return
    process = target.GetProcess()
    if not process or not process.IsValid():
        log("ERROR: no live process")
        return

    log("=== Path C key-trace  %s ===" % time.strftime("%Y-%m-%d %H:%M:%S"))

    mod = None
    for m in target.module_iter():
        if m.GetFileSpec().GetFilename() == "HardwareManager":
            mod = m
            break
    if not mod:
        log("ERROR: HardwareManager module not found")
        return

    def runtime(fa):
        return mod.ResolveFileAddress(fa).GetLoadAddress(target)

    plan = [
        ("encrypt-entry", FA_ENTRY,     on_entry),
        ("cbc-block",     FA_CBC_BLOCK, on_block),
        ("cfb-block",     FA_CFB_BLOCK, on_block),
    ]
    for name, fa, cb in plan:
        addr = runtime(fa)
        if addr == lldb.LLDB_INVALID_ADDRESS:
            log("  WARNING: could not resolve %s (0x%x)" % (name, fa))
            continue
        bp = target.BreakpointCreateByAddress(addr)
        if bp.IsValid():
            bp.SetScriptCallbackFunction("lldb_pathC_keytrace.%s" % cb.__name__)
            bp.SetAutoContinue(False)
            log("  bp %-14s file 0x%x -> runtime 0x%x  id=%d"
                % (name, fa, addr, bp.GetID()))
        else:
            log("  ERROR: breakpoint at 0x%x failed" % addr)

    log("")
    log("breakpoints armed — `continue` now; will capture on first hit.")
