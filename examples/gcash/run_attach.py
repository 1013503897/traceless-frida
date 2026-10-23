#!/usr/bin/env python3
# ATTACH (not spawn) discriminator: let GCash start on its own under Vector, reach a
# running state, THEN frida-attach + watch. If the session dies ~1.5s after attach ->
# GCash detects the agent injection (detection). If it stays -> the t+1.5s death was a
# frida-SPAWN mechanic, not detection.
import frida, sys, time, os, subprocess

SERIAL = "1C091FDF6008DN"
PKG = "com.globe.gcash.android"
HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, sys.argv[2] if len(sys.argv) > 2 else "heartbeat_only.js")
WATCH = int(sys.argv[1]) if len(sys.argv) > 1 else 15

state = {"detached": None}

def on_message(msg, data): print("  [agent]", msg.get("payload", msg))
def on_detached(reason, *a):
    state["detached"] = (time.time(), reason)
    print("  [DETACHED]", reason)

def main():
    dev = frida.get_device(SERIAL, timeout=8)
    subprocess.run(["adb", "-s", SERIAL, "shell", "am", "force-stop", PKG], timeout=15)
    time.sleep(1)
    subprocess.run(["adb", "-s", SERIAL, "shell", "am", "start", "-n",
                    PKG + "/gcash.module.splashscreen.mvp.view.SplashScreenActivity"], timeout=15)
    wait = float(sys.argv[3]) if len(sys.argv) > 3 else 4.0
    print("[*] launched; waiting %.1fs, then attaching ..." % wait)
    time.sleep(wait)
    gpid = subprocess.run(["adb", "-s", SERIAL, "shell", "pidof", PKG],
                          capture_output=True, text=True, timeout=10).stdout.strip().split()
    if not gpid:
        print("[!] gcash not running after launch"); return
    pid = int(gpid[0])
    print("[*] attaching to pid", pid)
    session = dev.attach(pid)
    session.on("detached", on_detached)
    script = session.create_script(open(AGENT, encoding="utf-8").read())
    script.on("message", on_message)
    t0 = time.time()
    script.load()
    print("[*] attached+loaded; watching %ds" % WATCH)
    while time.time() - t0 < WATCH:
        time.sleep(0.5)
        if state["detached"]:
            print("[*] survived ~%.1fs after attach (%s)" %
                  (state["detached"][0] - t0, state["detached"][1]))
            return
    print("[*] STILL ATTACHED+ALIVE at t+%ds" % WATCH)

if __name__ == "__main__":
    main()
