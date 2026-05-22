"""
Path A — passive lldb memory scan for the Stick3 DMX AES key.

NO breakpoints. lldb attach stops the process; this script does a fast
in-memory scan and detaches. Common case = a few seconds stopped.

What it does:
  1. Resolves the cipher vtable runtime address (file addr 0x10095F838 + slide).
  2. Scans every readable+writable region for that 8-byte LE pointer value.
     Each hit is the start of a cipher subobject (XHL_Stick3ANet device + 0x1618).
  3. For each hit: dumps 0x800 bytes, reads the documented candidate fields,
     and runs an AES-128 key-schedule auto-detector over the whole object.
  4. Writes a log + raw object dumps + any recovered keys to /tmp.

If STICK_HEAP_DUMP=1 is set in the environment, it also dumps every rw region
to /tmp/stick-heap/ with a manifest, so tools/scan-aes-schedule.mjs can do a
heap-wide schedule search offline (fallback if step 3 finds nothing).

Usage (driven by tools/pathA-scan.sh):
  lldb -p <PID> --batch \
       -o "command script import tools/lldb_pathA_scan.py" \
       -o "detach" -o "quit"
"""

import os
import struct
import time

# lldb is only present when run inside the debugger; guard the import so the
# pure-Python detector functions below stay unit-testable standalone.
try:
    import lldb
except ImportError:
    lldb = None

# --- known addresses (ESA2 2024-03-21 build, image vmaddrs) ---------------
CIPHER_VPTR_FILEADDR = 0x10095F838   # value stored at cipher_obj+0x00
CIPHER_OBJ_DUMP_LEN  = 0x800         # how much of each cipher object to grab

# documented offsets within the cipher object (cipher_obj = device+0x1618)
OFF_MODE   = 0x20   # 1 byte: 0=CBC, 1=CFB
OFF_KEY    = 0x48   # candidate raw AES-128 key (16 bytes)
OFF_CBC_IV = 0x60   # candidate CBC chaining IV (16 bytes)
OFF_CFB_IV = 0xB0   # candidate CFB IV (16 bytes)

LOG_PATH   = "/tmp/stick-pathA-scan.log"
HEAP_DIR   = "/tmp/stick-heap"

# --- AES-128 key schedule detector ---------------------------------------
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


def aes128_schedule_check(blob):
    """If blob[0:176] is a valid AES-128 forward key schedule, return the
    16-byte master key; else None."""
    if len(blob) < 176:
        return None
    w = [blob[4 * i:4 * i + 4] for i in range(44)]
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            # RotWord -> SubWord -> xor Rcon
            t = bytes((SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]))
            t = bytes((t[0] ^ RCON[i // 4 - 1], t[1], t[2], t[3]))
        exp = bytes((w[i - 4][k] ^ t[k] for k in range(4)))
        if exp != w[i]:
            return None
    return blob[0:16]


def find_schedules(blob, base_label):
    """Slide a 176-byte window over blob; return list of (offset, key)."""
    hits = []
    limit = len(blob) - 176
    o = 0
    while o <= limit:
        key = aes128_schedule_check(blob[o:o + 176])
        if key is not None:
            hits.append((o, key))
        o += 1
    return hits


# --- helpers --------------------------------------------------------------
_logf = None


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
    data = process.ReadMemory(addr, size, err)
    if err.Success() and data:
        return data
    return None


def find_main_module(target):
    for m in target.module_iter():
        fs = m.GetFileSpec()
        name = fs.GetFilename()
        if name == "HardwareManager":
            return m
    # fall back to module 0 (the main executable)
    return target.GetModuleAtIndex(0) if target.GetNumModules() else None


def rw_regions(process):
    """Yield (base, end) for readable+writable memory regions."""
    regions = process.GetMemoryRegions()
    for i in range(regions.GetSize()):
        info = lldb.SBMemoryRegionInfo()
        if not regions.GetMemoryRegionAtIndex(i, info):
            continue
        if info.IsReadable() and info.IsWritable():
            yield info.GetRegionBase(), info.GetRegionEnd()


def scan_for_pattern(process, pattern):
    """Return list of runtime addresses where the 8-byte pattern occurs in
    rw memory."""
    hits = []
    CHUNK = 8 * 1024 * 1024
    plen = len(pattern)
    for base, end in rw_regions(process):
        size = end - base
        if size <= 0 or size > 4 * 1024 * 1024 * 1024:
            continue
        addr = base
        carry = b""
        while addr < end:
            n = min(CHUNK, end - addr)
            data = read_mem(process, addr, n)
            if data is None:
                addr += n
                carry = b""
                continue
            # buf[0] sits at memory address (addr - len(carry))
            buf_base = addr - len(carry)
            buf = carry + data
            start = 0
            while True:
                idx = buf.find(pattern, start)
                if idx < 0:
                    break
                hits.append(buf_base + idx)
                start = idx + 1
            carry = buf[-(plen - 1):] if plen > 1 else b""
            addr += n
    return hits


def dump_heap(process):
    """Dump every rw region to HEAP_DIR with a manifest (fallback path)."""
    try:
        os.makedirs(HEAP_DIR, exist_ok=True)
    except Exception as e:
        log("  heap dump: mkdir failed: %s" % e)
        return
    manifest = open(os.path.join(HEAP_DIR, "manifest.txt"), "w")
    total = 0
    idx = 0
    CHUNK = 16 * 1024 * 1024
    for base, end in rw_regions(process):
        size = end - base
        if size <= 0 or size > 2 * 1024 * 1024 * 1024:
            continue
        path = os.path.join(HEAP_DIR, "region-%03d-0x%x.bin" % (idx, base))
        f = open(path, "wb")
        got = 0
        addr = base
        while addr < end:
            n = min(CHUNK, end - addr)
            data = read_mem(process, addr, n)
            if data is None:
                break
            f.write(data)
            got += len(data)
            addr += len(data)
        f.close()
        manifest.write("0x%x %d %s\n" % (base, got, os.path.basename(path)))
        total += got
        idx += 1
    manifest.close()
    log("  heap dump: %d regions, %.1f MiB -> %s" %
        (idx, total / 1048576.0, HEAP_DIR))


def inspect_cipher_obj(process, addr, n):
    """Dump + analyse one cipher object found at runtime address `addr`."""
    log("")
    log("=" * 70)
    log("CIPHER OBJECT @ 0x%x" % addr)
    log("=" * 70)

    blob = read_mem(process, addr, CIPHER_OBJ_DUMP_LEN)
    if blob is None:
        log("  !! could not read object memory")
        return []

    # raw dump of the first 0x200 bytes (16 bytes/line)
    log("  raw bytes 0x000..0x200:")
    for off in range(0, 0x200, 16):
        log("    +0x%03x  %s" % (off, hexsp(blob[off:off + 16])))

    # documented candidate fields
    mode = blob[OFF_MODE]
    log("")
    log("  documented candidate fields:")
    log("    +0x%02x mode flag = 0x%02x  (%s)" %
        (OFF_MODE, mode, "CFB" if mode == 1 else "CBC" if mode == 0 else "??"))
    log("    +0x%02x key(16)   = %s" % (OFF_KEY, hexsp(blob[OFF_KEY:OFF_KEY + 16])))
    log("    +0x%02x CBC IV(16)= %s" % (OFF_CBC_IV, hexsp(blob[OFF_CBC_IV:OFF_CBC_IV + 16])))
    log("    +0x%02x CFB IV(16)= %s" % (OFF_CFB_IV, hexsp(blob[OFF_CFB_IV:OFF_CFB_IV + 16])))

    # AES-128 key schedule auto-detect over the whole object
    scheds = find_schedules(blob, "obj@0x%x" % addr)
    log("")
    if scheds:
        log("  *** AES-128 KEY SCHEDULE DETECTED (%d) ***" % len(scheds))
        for off, key in scheds:
            log("    +0x%03x  master key = %s" % (off, hexsp(key)))
    else:
        log("  no valid AES-128 key schedule in this object")
        log("  (impl may store only the 16-byte raw key — see +0x%02x above," % OFF_KEY)
        log("   or expand the schedule on the fly per frame)")
    return scheds


def __lldb_init_module(debugger, internal_dict):
    global _logf
    _logf = open(LOG_PATH, "w")

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        log("ERROR: no target — attach with `lldb -p <PID>` first")
        return
    process = target.GetProcess()
    if not process or not process.IsValid():
        log("ERROR: no live process")
        return

    log("=== Path A passive scan  %s ===" % time.strftime("%Y-%m-%d %H:%M:%S"))
    log("pid=%d  state=%s" % (process.GetProcessID(), process.GetState()))

    mod = find_main_module(target)
    if not mod:
        log("ERROR: HardwareManager module not found")
        return

    # resolve cipher vptr file address -> runtime address (handles ASLR slide)
    sb = mod.ResolveFileAddress(CIPHER_VPTR_FILEADDR)
    vptr_runtime = sb.GetLoadAddress(target)
    if vptr_runtime == lldb.LLDB_INVALID_ADDRESS:
        log("ERROR: could not resolve cipher vptr 0x%x to a runtime address"
            % CIPHER_VPTR_FILEADDR)
        log("       module=%s" % mod.GetFileSpec())
        return
    slide = vptr_runtime - CIPHER_VPTR_FILEADDR
    log("module        : %s" % mod.GetFileSpec())
    log("ASLR slide    : 0x%x" % slide)
    log("cipher vptr   : fileaddr 0x%x -> runtime 0x%x"
        % (CIPHER_VPTR_FILEADDR, vptr_runtime))

    pattern = struct.pack("<Q", vptr_runtime)
    log("scan pattern  : %s" % hexsp(pattern))
    log("")
    log("scanning rw memory for the cipher vtable pointer ...")

    t0 = time.time()
    hits = scan_for_pattern(process, pattern)
    log("scan done in %.1fs — %d hit(s)" % (time.time() - t0, len(hits)))

    all_keys = []
    for i, addr in enumerate(hits):
        scheds = inspect_cipher_obj(process, addr, CIPHER_OBJ_DUMP_LEN)
        # save the raw object dump
        blob = read_mem(process, addr, CIPHER_OBJ_DUMP_LEN)
        if blob:
            objpath = "/tmp/stick-pathA-obj-%d-0x%x.bin" % (i, addr)
            with open(objpath, "wb") as f:
                f.write(blob)
            log("  raw object saved -> %s" % objpath)
        for off, key in scheds:
            all_keys.append((addr, off, key))

    # save any recovered keys
    log("")
    log("=" * 70)
    if all_keys:
        log("RECOVERED %d AES-128 KEY(S):" % len(all_keys))
        seen = set()
        n = 0
        for addr, off, key in all_keys:
            hexk = key.hex()
            if hexk in seen:
                continue
            seen.add(hexk)
            kp = "/tmp/stick-pathA-key-%d.bin" % n
            with open(kp, "wb") as f:
                f.write(key)
            log("  key %d: %s  (obj 0x%x +0x%x)  -> %s"
                % (n, hexsp(key), addr, off, kp))
            n += 1
        log("")
        log("NEXT: capture a 576B frame and verify, e.g.:")
        log("  node tools/try-key.mjs <frame.bin> $(xxd -p /tmp/stick-pathA-key-0.bin)")
    else:
        log("No AES-128 key schedule auto-detected.")
        log("Inspect the +0x48 raw-key candidates in the per-object dumps above,")
        log("or set STICK_HEAP_DUMP=1 and re-run for a heap-wide offline scan.")

    if os.environ.get("STICK_HEAP_DUMP") == "1":
        log("")
        log("STICK_HEAP_DUMP=1 — dumping rw regions for offline scan ...")
        dump_heap(process)
        log("  then run: node tools/scan-aes-schedule.mjs %s" % HEAP_DIR)

    log("")
    log("scan complete — detaching. log: %s" % LOG_PATH)
    _logf.close()
