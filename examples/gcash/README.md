# traceless-frida on GCash (Ant APSE + Appdome)

Making **frida usable on `com.globe.gcash.android`** (6.03.0) — Ant APSE 9.0.2 fingerprint/
soft-risk + Appdome fusion shell (`libnyadgfpeuju` → `libloader`) hard withhold, three
co-resident RASP. Companion to memory `traceless-frida-gcash-status` and
`gcash-603-apse-detection-map`.

## TL;DR — ATTACH works

A bare frida spawn/attach dies ~1s after the agent is present. **Root cause (proven):
Appdome's signal anti-debug** — `libnyadgfpeuju` `raise(SIGTRAP)` + a periodic (~5s)
`kill(0,sig)` from `libloader.so+0x2540c0`. Without frida's **gum exceptor** installed,
those signals are consumed by the ptrace tracer (frida-server) instead of the app's own
handler, so GCash concludes "debugger present" and severs frida.

**Fix is one line:** install *any* Interceptor hook right after attach — that makes gum
install its exceptor, which catches those signals and chains them to the app's handler,
defeating the anti-debug. A **no-op `Interceptor.attach(getpid, {})` is enough.**

Result (measured on Pixel 6, APatch, art-runtime-srv = frida-server 17.18.0):
- frida **attach survives 25s+** (past the splash wall), GCash foreground on its real UI.
- Pair with the tlf cloak to also hide frida's maps footprint (4 frida ranges → 0, even
  from the process's own `/proc/self/maps`).

## Recipe (attach — the working path)

Prereqs (once): shpte KPM loaded + bridge armed (Vector's GCash bypass already does this);
`art-runtime-srv` (frida-server 17.18.0) running as root; host frida == 17.18.0;
`chcon u:object_r:apk_data_file:s0 /data/local/tmp/libtracelessfrida.so` (untrusted_app
cannot `PROT_EXEC`-map a `/data/local/tmp` .so otherwise).

```
python run_attach.py 25 demo_full.js
```

`demo_full.js` = tlf cloak (hide frida maps) + `Interceptor.attach(openat)` (activates the
exceptor AND does live instrumentation) + heartbeat. The single load-bearing trick is the
**exceptor** — see `minimal_hook.js` (a lone no-op `getpid` hook) which alone survives.

## Files

| file | role |
|---|---|
| `run_attach.py` / `run_min.py` | attach / spawn harness (`arg1`=watch secs, `arg2`=agent) |
| `minimal_hook.js` | **mechanism proof**: one no-op `getpid` hook → frida survives (exceptor) |
| `kill_probe.js` | how the anti-debug fires: hooks `raise`/`kill`/… + backtraces |
| `demo_full.js` | full attach demo: cloak + exceptor + live `openat` instrumentation |
| `cloak_agent.js` / `diag_agent.js` | cloak-only / frida-footprint diagnostics |
| `spawn_full.js` | spawn attempt: cloak + exceptor + `dl_iterate_phdr` filter (see below) |

## Mechanism (why it works)

`kill_probe.js` caught the anti-debug red-handed:
```
raise(5=SIGTRAP)   <- libnyadgfpeuju.so+0x38208 <- +0x39828 <- libart
kill(0, sig)       <- libloader.so+0x2540c0 <- +0xaea58 <- +0x24f96c <- +0x24f97c
                      <- +0x52b10c <- +0xb4370 <- +0x38f39c   (periodic, ~5s)
```
Under a ptrace tracer these signals divert to the tracer. gum's exceptor (installed by any
Interceptor use) re-delivers them to the app's handler → the anti-debug sees "no debugger".

## Spawn — NOT yet solved (further R&D)

`attach` works because GCash's **one-shot early maps/module verdict** (~t+0.5–1.5s) already
ran clean before you attach (at t+4s). **Spawn** puts frida in the process *during* that
verdict window and still dies ~1.7s with a **SIGSEGV** (the withhold), even with:
cloak (hides `/proc/maps`, verified 4→0), the exceptor (signal anti-debug handled), and a
`dl_iterate_phdr` filter (hides frida modules from the linker's link_map — `libnyadgfpeuju`
imports `dl_iterate_phdr`).

So the spawn verdict detects frida through a channel none of those cover. Open suspects for
a future session: (1) spawn holds ptrace → `/proc/self/status` **TracerPid** (KPM has a
`hidetracer` verb, but the currently-loaded KPM lacks `autocloak`/likely `hidetracer` too —
needs the newer `shpte.new.kpm`, which needs shctl → confirm with user); (2) the linker's
**solist walked directly** from memory (not via `dl_iterate_phdr`); (3) gum memory
signatures. Attach is sufficient for post-startup instrumentation; spawn is only needed to
catch the very first pre-`main` code.
