"""
Extract the 0x48 TCP-auth HMAC key from a running Hardware Manager.

The 0x48 handshake message ends with HMAC-SHA256(key, msg[0:82]). The key is
an internal HWM constant we can't derive offline. But the HMAC routine
FUN_1004080b0 receives it directly:

    FUN_1004080b0(rdi=key, rsi=keylen, rdx=msg, rcx=msglen, r8=out, r9=32)

When HWM builds the 0x48 it calls this with rcx (msglen) == 0x52. We set one
breakpoint on FUN_1004080b0, and on the call where rcx==0x52 we dump rdi/rsi
— that's the key. One hit, then detach. Not a per-frame breakpoint, so it
won't starve HWM the way the old encrypt-path breakpoints did.

Usage (driven by tools/hmac-key.sh):
  lldb -p <PID> --batch \
       -o "command script import tools/lldb_hmac_key.py" -o "detach" -o "quit"
Then in HWM: disconnect from the Stick and reconnect.
"""

import sys

try:
    import lldb
except ImportError:
    lldb = None

HMAC_FN_FILEADDR = 0x1004080b0   # FUN_1004080b0 — HMAC-SHA256
LOG_PATH = "/tmp/stick-hmac-key.log"
_logf = None


def log(m=""):
    print(m)
    sys.stdout.flush()
    if _logf:
        _logf.write(m + "\n")
        _logf.flush()


def hexs(b):
    return "".join("%02x" % x for x in bytearray(b))


def hmac_bp_callback(frame, bp_loc, internal_dict):
    """Fires on every FUN_1004080b0 call; reports the one for the 0x48 (msglen 0x52)."""
    process = frame.GetThread().GetProcess()
    reg = lambda n: frame.FindRegister(n).GetValueAsUnsigned()
    key, keylen, msglen = reg("rdi"), reg("rsi"), reg("rcx")
    if msglen != 0x52:
        return False   # not the 0x48 auth HMAC — keep going
    err = lldb.SBError()
    n = keylen if 0 < keylen <= 512 else 64
    kd = process.ReadMemory(key, n, err)
    md = process.ReadMemory(reg("rdx"), 0x52, err)
    log("")
    log(">>> 0x48 auth HMAC caught")
    log("    key length : %d" % keylen)
    log("    key (hex)  : %s" % (hexs(kd) if kd else "(unreadable)"))
    if kd:
        try:
            log("    key (text) : %r" % bytearray(kd).decode("utf-8"))
        except Exception:
            log("    key (text) : (not utf-8)")
    log("    msg[0:82]  : %s" % (hexs(md) if md else "(unreadable)"))
    log("")
    log(">>> got it — detaching.")
    return True    # stop so the batch script can detach


def __lldb_init_module(debugger, internal_dict):
    global _logf
    _logf = open(LOG_PATH, "w")
    log("=== HMAC-key extraction %s ===" % __import__("time").ctime())
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    saddr = target.ResolveFileAddress(HMAC_FN_FILEADDR)
    laddr = saddr.GetLoadAddress(target)
    log("HMAC fn  file 0x%x  ->  load 0x%x" % (HMAC_FN_FILEADDR, laddr))

    bp = target.BreakpointCreateByAddress(laddr)
    bp.SetScriptCallbackFunction("lldb_hmac_key.hmac_bp_callback")
    if bp.GetNumLocations() == 0:
        log("!!! breakpoint resolved 0 locations — wrong address/module")
        return
    log("breakpoint armed on the HMAC function (%d location)" % bp.GetNumLocations())
    log("")
    log(">>> NOW: in HWM, disconnect from the Stick and reconnect.")
    log(">>> waiting for the 0x48 handshake ...")

    process.Continue()   # blocks until the 0x48 HMAC call stops us
    log(">>> done — log at %s" % LOG_PATH)
