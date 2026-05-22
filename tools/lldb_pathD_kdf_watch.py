"""
Path D — catch the key-derivation function with a hardware watchpoint.

The 32-byte AES key lives at cipher_obj+0x48 and is rewritten when the
TCP/2431 handshake completes. cipher_obj is a stable heap address (reused
across reconnects within one HWM run). So: arm a write-watchpoint on
cipher_obj+0x48, let the user reconnect HWM, and the instant the handshake
writes the freshly-derived key, lldb stops — with the KDF call chain on the
backtrace and the ECDH shared secret live in registers/stack.

lldb's SBWatchpoint has no script callback, so run-control is driven here:
arm the watchpoint(s), then loop process.Continue() until a watched key
slot CHANGES to a new non-zero value (the KDF rederive — not the disconnect
zeroing, not a spurious same-value write).

Usage (driven by tools/pathD-kdf-watch.sh):
  lldb -p <PID> --batch \
       -o "command script import tools/lldb_pathD_kdf_watch.py" \
       -o "detach" -o "quit"
After it prints "watchpoint(s) armed", reconnect HWM to the Stick.
"""

import os
import sys
import struct
import time

try:
    import lldb
except ImportError:
    lldb = None

CIPHER_VPTR_FILEADDR = 0x10095F838
KEY_OFF = 0x48
LOG_PATH = "/tmp/stick-pathD-kdf.log"
MAX_CONTINUES = 400

_logf = None
_blobs = []


def log(m=""):
    print(m)
    sys.stdout.flush()
    if _logf:
        _logf.write(m + "\n")
        _logf.flush()


def hexs(b):
    return "".join("%02x" % x for x in b)


def read_mem(process, addr, size):
    err = lldb.SBError()
    d = process.ReadMemory(addr, size, err)
    return d if (err.Success() and d) else None


def rw_regions(process):
    regions = process.GetMemoryRegions()
    for i in range(regions.GetSize()):
        info = lldb.SBMemoryRegionInfo()
        if regions.GetMemoryRegionAtIndex(i, info) \
           and info.IsReadable() and info.IsWritable():
            yield info.GetRegionBase(), info.GetRegionEnd()


def find_cipher_objects(process, target):
    mod = None
    for m in target.module_iter():
        if m.GetFileSpec().GetFilename() == "HardwareManager":
            mod = m
            break
    if not mod:
        return []
    vptr = mod.ResolveFileAddress(CIPHER_VPTR_FILEADDR).GetLoadAddress(target)
    if vptr == lldb.LLDB_INVALID_ADDRESS:
        return []
    pattern = struct.pack("<Q", vptr)
    hits = []
    CH = 8 * 1024 * 1024
    for base, end in rw_regions(process):
        if end - base > 4 * 1024 * 1024 * 1024:
            continue
        addr, carry = base, b""
        while addr < end:
            n = min(CH, end - addr)
            data = read_mem(process, addr, n)
            if data is None:
                addr += n
                carry = b""
                continue
            bb = carry + data
            bbase = addr - len(carry)
            s = 0
            while True:
                idx = bb.find(pattern, s)
                if idx < 0:
                    break
                hits.append(bbase + idx)
                s = idx + 1
            carry = bb[-7:]
            addr += n
    return [h for h in hits if h > 0x7000_0000_0000]   # heap objects only


def backtrace(thread):
    log("")
    log("backtrace (KDF call chain):")
    for i in range(min(thread.GetNumFrames(), 28)):
        f = thread.GetFrameAtIndex(i)
        log("  #%-2d 0x%x  %s" % (i, f.GetPC(), f.GetFunctionName() or "?"))


def capture(process, frame, label):
    log("")
    log("=" * 68)
    log("CAPTURE @ %s" % label)
    log("=" * 68)
    regs = {}
    for r in ("rdi rsi rdx rcx r8 r9 rax rbx rbp rsp r10 r11 r12 r13 r14 "
              "r15 rip").split():
        v = frame.FindRegister(r)
        regs[r] = v.GetValueAsUnsigned() if v.IsValid() else 0
        log("  %-4s = 0x%x" % (r, regs[r]))
    for r in ("rdi rsi rdx rcx r8 r9 rax rbx r12 r13 r14 r15").split():
        a = regs[r]
        if 0x10000 < a < 0x7fffffffffff:
            d = read_mem(process, a, 1024)
            if d:
                _blobs.append(("%s_0x%x" % (r, a), a, d))
    rsp = regs["rsp"]
    st = read_mem(process, rsp - 0x400, 0x6000)
    if st:
        _blobs.append(("stack_0x%x" % (rsp - 0x400), rsp - 0x400, st))


def finalize():
    log("")
    log("=" * 68)
    log("saving %d blob(s) for offline KDF analysis" % len(_blobs))
    for label, addr, data in _blobs:
        p = "/tmp/stick-pathD-blob-%s.bin" % label
        with open(p, "wb") as f:
            f.write(data)
        log("  %-22s %6d B @ 0x%x" % (label, len(data), addr))
    log("")
    log("NEXT: node tools/crack-kdf.mjs <new-key-hex> /tmp/stick-pathD-blob-*.bin")
    log("done — detaching. log: %s" % LOG_PATH)


def __lldb_init_module(debugger, internal_dict):
    global _logf
    _logf = open(LOG_PATH, "w")
    # async: process.Continue() returns immediately and we poll, so the
    # script can never wedge in an unkillable synchronous kernel wait.
    debugger.SetAsync(True)

    target = debugger.GetSelectedTarget()
    process = target.GetProcess() if target else None
    if not process or not process.IsValid():
        log("ERROR: no live process")
        return

    log("=== Path D KDF watchpoint  %s ===" % time.strftime("%Y-%m-%d %H:%M:%S"))
    objs = find_cipher_objects(process, target)
    if not objs:
        log("ERROR: no live cipher object found")
        return
    log("cipher object(s): %s" % ", ".join("0x%x" % o for o in objs))

    # The 32-byte key spans cipher_obj+0x48 (half C) .. +0x58 (half D). A real
    # handshake rederive changes BOTH halves; UI writes touch only one. Watch
    # both 8-byte halves so we get a hit once the full key is written. Active
    # objects (non-zero key) come first so they get watchpoints within the
    # hardware budget (4 on x86_64).
    objs.sort(key=lambda o: 0 if any(read_mem(process, o + KEY_OFF, 32) or b"")
              else 1)
    # one initial 32-byte key per object
    initials = {}
    for o in objs:
        initials[o] = read_mem(process, o + KEY_OFF, 32) or b"\x00" * 32
        log("  obj 0x%x  key = %s" % (o, hexs(initials[o])))

    budget = 4
    armed_objs = []
    for o in objs:
        ok = False
        for half in (0x48, 0x58):
            if budget <= 0:
                break
            err = lldb.SBError()
            wp = target.WatchAddress(o + half, 8, False, True, err)
            if err.Success() and wp and wp.IsValid():
                budget -= 1
                ok = True
                log("    watchpoint id %d on 0x%x (+0x%x)"
                    % (wp.GetID(), o + half, half))
            else:
                log("    WARNING: watchpoint on 0x%x failed: %s"
                    % (o + half, err))
        if ok:
            armed_objs.append(o)

    if not armed_objs:
        log("ERROR: no watchpoints armed")
        return

    # Force the reconnect ourselves: HWM is already stopped (from the lldb
    # attach). Hold it stopped long enough that the Stick drops the idle
    # TCP/2431 session (~41s sufficed in an earlier scan; 85s is safe). When
    # we then resume, HWM finds the dead socket and reconnects — a fresh
    # handshake + KDF — with no UI interaction needed.
    FREEZE = 85
    log("")
    log(">>> watchpoint(s) armed.")
    log(">>> Freezing HWM for %ds so the Stick drops the idle TCP session" % FREEZE)
    log(">>> (HWM has been stopped since the lldb attach; just holding it).")
    t0 = time.time()
    while time.time() - t0 < FREEZE:
        time.sleep(1.0)
    log(">>> resuming HWM — it will detect the dead socket and reconnect.")
    log(">>> watching for the reconnect handshake to rederive the key ...")
    log("")

    # Async poll loop, hard-bounded by a wall-clock deadline. process.Continue()
    # returns immediately; we poll GetState() with short sleeps, so the script
    # always self-terminates and lets lldb run `detach`/`quit` — it can never
    # hang in an unkillable synchronous wait.
    last_seen = dict(initials)        # last key value observed per object
    deadline = time.time() + 300.0
    process.Continue()

    while time.time() < deadline:
        st = process.GetState()
        if st == lldb.eStateExited:
            log("process exited — aborting")
            return
        if st != lldb.eStateStopped:
            time.sleep(0.2)
            continue

        # stopped — a watchpoint (or signal) hit
        thread = process.GetSelectedThread()
        for t in process:
            if t.GetStopReason() == lldb.eStopReasonWatchpoint:
                thread = t
                break

        full = None
        for o in armed_objs:
            v = read_mem(process, o + KEY_OFF, 32)
            if not v or v == last_seen[o]:
                continue                      # unchanged / stale re-read
            last_seen[o] = v
            init = initials[o]
            c_new = v[0:16] != init[0:16]
            d_new = v[16:32] != init[16:32]
            nonzero = any(b != 0 for b in v)
            if c_new and d_new and nonzero:
                full = (o, v)
            else:
                log("  (partial write: %s changed via %s — skipping)"
                    % ("C" if c_new else "D" if d_new else "?",
                       thread.GetFrameAtIndex(0).GetFunctionName() or "?"))
        if full:
            log("")
            log(">>> FULL KEY REDERIVED — key@0x%x" % (full[0] + KEY_OFF))
            log("    %s" % hexs(full[1]))
            backtrace(thread)
            capture(process, thread.GetFrameAtIndex(0), "full key rederive (KDF)")
            finalize()
            return

        process.Continue()               # resume, wait for the next write
        time.sleep(0.25)

    log("")
    log("timed out after 5 min — no full key rederive seen. HWM left running;")
    log("re-run and be sure to fully Disconnect THEN Connect in HWM.")
