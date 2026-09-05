#!/usr/bin/env python3
# Drive the Traceless-Frida end-to-end test: spawn tlf_target under frida, inject
# agent/traceless.js + test/test.js (concatenated into one script so they share
# scope), collect the script's structured `send()` events AND the target's stdout,
# then clean up and print a PASS/FAIL summary.
#
#   python test/run.py            # spawn a fresh tlf_target
#   python test/run.py --ghost    # arm ghost (VMA-less clone) mode
#
# Requires: frida-python matching the device frida-server major, a USB device with
# shpte loaded + bridge armed, and /data/local/tmp/{tlf_target,libtracelessfrida.so}.
import frida, sys, time, os, json

HERE = os.path.dirname(os.path.abspath(__file__))
GHOST = "--ghost" in sys.argv
TARGET = "/data/local/tmp/tlf_target"
RUN_SECS = 6

def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

# concatenate: traceless.js defines `Traceless`; test.js uses it (same script scope).
src = read(os.path.join(HERE, "..", "agent", "traceless.js"))
if GHOST:
    src = "var GHOST_MODE = true;\n" + src  # test.js reads this global to arm ghost mode
src += "\n" + read(os.path.join(HERE, "test.js"))

events = []
target_out = []

def on_message(msg, data):
    if msg.get("type") == "send":
        p = msg["payload"]
        events.append(p)
        print("  [send]", json.dumps(p, ensure_ascii=False))
    else:
        print("  [msg ]", msg)

def on_output(pid, fd, data):
    if fd in (1, 2) and data:
        s = data.decode("utf-8", "replace")
        target_out.append(s)
        for line in s.rstrip("\n").split("\n"):
            print("  [tgt ]", line)

def main():
    print("[*] connecting to USB device ...")
    dev = frida.get_usb_device(timeout=8)
    print("[*] frida-python", frida.__version__, "device:", dev.name)
    dev.on("output", on_output)
    print("[*] spawning", TARGET, "(ghost)" if GHOST else "")
    pid = dev.spawn([TARGET], stdio="pipe")  # route target stdout to the output signal
    session = dev.attach(pid)
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    print("[*] resuming; collecting for", RUN_SECS, "s ...")
    dev.resume(pid)
    time.sleep(RUN_SECS)

    print("[*] cleanup (revert + shutdown) ...")
    try:
        exports = getattr(script, "exports_sync", None) or script.exports
        exports.cleanup()
    except Exception as e:
        print("  [warn] cleanup rpc failed:", e)
    time.sleep(1.0)
    try: dev.kill(pid)
    except Exception: pass

    # ---- verdict ----
    hooked = next((e for e in events if e.get("t") == "hooked"), None)
    calls = [e for e in events if e.get("t") == "call"]
    rwx = next((e for e in events if e.get("t") == "rwx"), None)
    maps = next((e for e in events if e.get("t") == "maps"), None)
    errs = [e for e in events if e.get("t") == "error"]

    # stdout evidence: after the hook, secret(i) printed value == 3*i+7+1000
    joined = "".join(target_out)
    hooked_lines = [ln for ln in joined.split("\n") if "secret(" in ln]

    print("\n==================== VERDICT ====================")
    ok = True
    def check(name, cond, detail=""):
        nonlocal ok
        ok = ok and cond
        print(f"  [{'PASS' if cond else 'FAIL'}] {name} {detail}")

    check("bridge armed", any(e.get("t") == "armed" for e in events))
    check("hook installed", hooked is not None,
          f"backup={hooked.get('backup') if hooked else None}")
    check("interceptions live (>=1)", len(calls) >= 1, f"calls={len(calls)}")
    if calls:
        c = calls[0]
        check("return rewritten (+1000)", c.get("ret") == c.get("orig") + 1000,
              f"orig={c.get('orig')} ret={c.get('ret')}")
    if hooked:
        check("target .text UNCHANGED (traceless)", hooked.get("textUnchanged") is True,
              f"{hooked.get('textBefore')} -> {hooked.get('textAfter')}")
    if maps:
        check("target page not writable", "w" not in (maps.get("prot") or ""),
              f"prot={maps.get('prot')}")
    if rwx:
        check("no rwx covers secret()", rwx.get("coveringSecret") == 0,
              f"rwx_total={rwx.get('total')} covering={rwx.get('coveringSecret')}")
    check("no script errors", not errs, str(errs) if errs else "")
    check("stdout shows hooked values", any(
        f"={3*i+7+1000}" in joined for i in range(0, 20)), f"{len(hooked_lines)} secret() lines")

    print("================================================")
    print("RESULT:", "PASS ✅" if ok else "FAIL ❌")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
