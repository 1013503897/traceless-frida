#!/usr/bin/env python3
# Minimal survival watch: spawn GCash + cloak agent, print beats only. No external
# /proc reads, no dev.kill -- removes the harness as a variable. Lets GCash run so we
# can see how long frida survives before GCash severs it.
import frida, sys, time, os

SERIAL = "1C091FDF6008DN"
PKG = "com.globe.gcash.android"
HERE = os.path.dirname(os.path.abspath(__file__))
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 30
AGENT = os.path.join(HERE, sys.argv[2] if len(sys.argv) > 2 else "cloak_agent.js")

state = {"detached": None}

def on_message(msg, data):
    print("  [agent]", msg.get("payload", msg))

def on_detached(reason, *a):
    state["detached"] = (time.time(), reason)
    print("  [DETACHED]", reason)

def main():
    dev = frida.get_device(SERIAL, timeout=8)
    src = open(AGENT, encoding="utf-8").read()
    import subprocess
    subprocess.run(["adb", "-s", SERIAL, "shell", "am", "force-stop", PKG], timeout=15)
    time.sleep(1)
    pid = dev.spawn([PKG])
    print("[*] spawned pid", pid)
    session = dev.attach(pid)
    session.on("detached", on_detached)
    script = session.create_script(src)
    script.on("message", on_message)
    script.load()
    t0 = time.time()
    dev.resume(pid)
    print("[*] resumed; watching %ds (NO external reads, NO kill)" % WATCH)
    while time.time() - t0 < WATCH:
        time.sleep(0.5)
        if state["detached"]:
            print("[*] survived ~%.1fs before detach (%s)" %
                  (state["detached"][0] - t0, state["detached"][1]))
            return
    print("[*] STILL ALIVE at t+%ds (no detach)" % WATCH)

if __name__ == "__main__":
    main()
