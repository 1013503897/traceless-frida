#!/usr/bin/env python3
# Spawn GCash under Frida with the traceless-frida cloak agent and measure survival.
#
# The known failure: a bare frida-spawn of GCash dies at ~t+6s (SIGSEGV@HeapTaskDaemon)
# because the Appdome injection-verdict withhold reads /proc/self/maps, sees the
# unhidden frida-agent memfds, judges "tamper", and poisons libloader's libc imports.
# This harness arms autocloak (hide those memfds via the same shpte KPM the Vector
# bypass uses) BEFORE resuming the app, then polls survival + what an external
# maps-reader (the detector's view) still sees.
#
#   python run_gcash.py
import frida, sys, time, os, subprocess

SERIAL = "1C091FDF6008DN"
PKG = "com.globe.gcash.android"
HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "cloak_agent.js")
CHECKPOINTS = [2, 4, 6, 8, 10, 15, 20, 30, 45, 60]

detached = {"reason": None}


def adb_root(cmd):
    r = subprocess.run(["adb", "-s", SERIAL, "shell", "su", "-c", cmd],
                       capture_output=True, text=True, timeout=20)
    return r.stdout


def on_message(msg, data):
    if msg.get("type") == "send":
        print("  [agent]", msg["payload"])
    else:
        print("  [msg  ]", msg)


def on_detached(reason, *a):
    detached["reason"] = reason
    print("  [DETACHED] reason=%s" % reason)


def snapshot(pid, tag):
    st = adb_root("cat /proc/%d/status" % pid)
    if "Name:" not in st:
        print("[%s] pid %d GONE" % (tag, pid))
        return False
    tracer = next((l.strip() for l in st.split("\n") if "TracerPid" in l), "?")
    maps = adb_root("cat /proc/%d/maps" % pid)
    mlines = maps.split("\n")
    frida_lines = [l for l in mlines if any(k in l for k in
                   ("memfd", "frida", "gum", "jvmti", "openjdk", "tracelessfrida"))]
    rwx = [l for l in mlines if "rwx" in l]
    print("[%s] ALIVE  %s  frida/memfd_lines=%d  rwx=%d" %
          (tag, tracer, len(frida_lines), len(rwx)))
    for l in frida_lines[:16]:
        print("        |", l.strip())
    for l in rwx[:6]:
        print("        R|", l.strip())
    return True


def main():
    dev = frida.get_device(SERIAL, timeout=8)
    print("[*] device:", dev.name, " frida-python:", frida.__version__)
    src = open(AGENT, encoding="utf-8").read()

    subprocess.run(["adb", "-s", SERIAL, "shell", "am", "force-stop", PKG], timeout=15)
    time.sleep(1)

    pid = dev.spawn([PKG])
    print("[*] spawned pid", pid)
    session = dev.attach(pid)
    session.on("detached", on_detached)
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    print("[*] agent loaded; resuming ...")
    dev.resume(pid)

    t0 = time.time()
    last_alive = 0
    for cp in CHECKPOINTS:
        while time.time() - t0 < cp:
            time.sleep(0.2)
            if detached["reason"]:
                break
        if detached["reason"]:
            print("[t+%02ds] session detached: %s" % (cp, detached["reason"]))
            snapshot(pid, "t+%02ds" % cp)  # is the process itself gone?
            break
        if snapshot(pid, "t+%02ds" % cp):
            last_alive = cp
        else:
            break

    # foreground activity (did it reach a UI?)
    fg = subprocess.run(["adb", "-s", SERIAL, "shell", "dumpsys", "activity", "activities"],
                        capture_output=True, text=True, timeout=15).stdout
    res = next((l.strip() for l in fg.split("\n") if "ResumedActivity" in l), "?")
    print("\n[*] last_alive=t+%ds  detached=%s" % (last_alive, detached["reason"]))
    print("[*] ResumedActivity:", res[:160])
    try:
        dev.kill(pid)
    except Exception:
        pass


if __name__ == "__main__":
    main()
