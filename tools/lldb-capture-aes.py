"""
lldb script to capture AES keys from HardwareManager.
Attach to HardwareManager, then source this script.

Usage:
  lldb -p <PID>
  (lldb) command script import /path/to/lldb-capture-aes.py
  (lldb) continue

Then connect to the Stick in the HardwareManager UI.
Keys will be printed and saved to /tmp/stick-aes-keys.log
"""

import lldb
import os

LOG_PATH = "/tmp/stick-aes-keys.log"
key_count = 0

def log(msg):
    with open(LOG_PATH, "a") as f:
        f.write(msg + "\n")
    print(msg)

def on_setkey_enc(frame, bp_loc, dict):
    global key_count
    key_count += 1
    thread = frame.GetThread()
    process = thread.GetProcess()

    # x86_64 calling convention: rdi=ctx, rsi=key, edx=keybits
    keybits = frame.FindRegister("edx").GetValueAsUnsigned()
    key_ptr = frame.FindRegister("rsi").GetValueAsUnsigned()
    key_len = keybits // 8

    err = lldb.SBError()
    key_bytes = process.ReadMemory(key_ptr, key_len, err)

    if err.Success() and key_bytes:
        hex_key = " ".join(f"{b:02x}" for b in key_bytes)
        log(f"[{key_count}] AES_SETKEY_ENC bits={keybits} key={hex_key}")

        # Save raw key to file
        with open("/tmp/stick-aes-key.bin", "wb") as f:
            f.write(key_bytes)
        log(f"    Raw key saved to /tmp/stick-aes-key.bin")
    else:
        log(f"[{key_count}] AES_SETKEY_ENC bits={keybits} (failed to read key: {err})")

    # Don't stop, continue running
    return False

def on_setkey_dec(frame, bp_loc, dict):
    global key_count
    key_count += 1
    thread = frame.GetThread()
    process = thread.GetProcess()

    keybits = frame.FindRegister("edx").GetValueAsUnsigned()
    key_ptr = frame.FindRegister("rsi").GetValueAsUnsigned()
    key_len = keybits // 8

    err = lldb.SBError()
    key_bytes = process.ReadMemory(key_ptr, key_len, err)

    if err.Success() and key_bytes:
        hex_key = " ".join(f"{b:02x}" for b in key_bytes)
        log(f"[{key_count}] AES_SETKEY_DEC bits={keybits} key={hex_key}")
    else:
        log(f"[{key_count}] AES_SETKEY_DEC bits={keybits} (failed to read key: {err})")

    return False

def on_crypt_cbc(frame, bp_loc, dict):
    thread = frame.GetThread()
    process = thread.GetProcess()

    # rdi=ctx, esi=mode, rdx=length, rcx=iv, r8=input, r9=output
    mode = frame.FindRegister("esi").GetValueAsUnsigned()
    length = frame.FindRegister("rdx").GetValueAsUnsigned()

    mode_str = "ENC" if mode == 1 else "DEC"
    log(f"    AES_CBC {mode_str} len={length}")

    return False

def __lldb_init_module(debugger, internal_dict):
    target = debugger.GetSelectedTarget()
    if not target:
        print("ERROR: No target. Attach to HardwareManager first.")
        return

    # Clear old log
    with open(LOG_PATH, "w") as f:
        f.write("=== lldb AES key capture started ===\n")

    # Find the mbedcrypto module
    found_module = None
    for module in target.module_iter():
        name = module.GetFileSpec().GetFilename()
        if name and "mbedcrypto" in name:
            found_module = module
            break

    if not found_module:
        print("WARNING: libmbedcrypto not found in loaded modules")
        print("Available modules:")
        for module in target.module_iter():
            print(f"  {module.GetFileSpec()}")
        return

    print(f"Found: {found_module.GetFileSpec()}")

    # Set breakpoints on the symbols
    bp_enc = target.BreakpointCreateByName("mbedtls_aes_setkey_enc", found_module.GetFileSpec().GetFilename())
    if bp_enc.IsValid():
        bp_enc.SetScriptCallbackFunction("lldb_capture_aes.on_setkey_enc")
        bp_enc.SetAutoContinue(True)
        print(f"Breakpoint on mbedtls_aes_setkey_enc: {bp_enc}")
    else:
        print("ERROR: Could not set breakpoint on mbedtls_aes_setkey_enc")

    bp_dec = target.BreakpointCreateByName("mbedtls_aes_setkey_dec", found_module.GetFileSpec().GetFilename())
    if bp_dec.IsValid():
        bp_dec.SetScriptCallbackFunction("lldb_capture_aes.on_setkey_dec")
        bp_dec.SetAutoContinue(True)
        print(f"Breakpoint on mbedtls_aes_setkey_dec: {bp_dec}")

    bp_cbc = target.BreakpointCreateByName("mbedtls_aes_crypt_cbc", found_module.GetFileSpec().GetFilename())
    if bp_cbc.IsValid():
        bp_cbc.SetScriptCallbackFunction("lldb_capture_aes.on_crypt_cbc")
        bp_cbc.SetAutoContinue(True)
        print(f"Breakpoint on mbedtls_aes_crypt_cbc: {bp_cbc}")

    log("Breakpoints set. Connect to the Stick in the UI, then check this log.")
    print(f"\nReady! Keys will be logged to {LOG_PATH}")
    print("Now type 'continue' and connect to the Stick in the UI.")
