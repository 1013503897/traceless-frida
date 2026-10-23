'use strict';
/*
 * GCash cloak agent (survival test, no app hooks).
 *
 * Loaded at spawn BEFORE the app's own code runs. Arms the shpte KPM bridge,
 * enables fs-hide (root/mount), then autocloak (kernel-side hide of Frida's own
 * memfd/gum/jvmti lines from /proc/<pid>/maps for self AND external readers).
 * Falls back to the userspace selfCloak sweep if the loaded KPM lacks autocloak.
 *
 * Purpose: prove that hiding the frida-agent footprint via the SAME maps-hide the
 * GCash bypass already uses defeats the Appdome injection-verdict withhold that
 * killed a bare frida-spawn at ~t+6s. Pure cloak + heartbeat -- isolates "can frida
 * coexist" from "do app hooks crash".
 */
const SO = '/data/local/tmp/libtracelessfrida.so';
const started = Date.now();
function log(o) { o.dt = ((Date.now() - started) / 1000).toFixed(2); send(o); }
function nf(mod, name, ret, args) {
  const p = (mod.findExportByName && mod.findExportByName(name)) ||
            (mod.getExportByName && mod.getExportByName(name));
  if (!p || p.isNull()) throw new Error('missing export ' + name);
  return new NativeFunction(p, ret, args);
}

try {
  const mod = Module.load(SO);
  const tlf_init      = nf(mod, 'tlf_init', 'int', ['int']);
  const tlf_fshide    = nf(mod, 'tlf_fshide', 'void', []);
  const tlf_autocloak = nf(mod, 'tlf_autocloak', 'int', []);
  const tlf_selfcloak = nf(mod, 'tlf_selfcloak', 'int', []);

  const rc = tlf_init(0).valueOf();          // arm bridge (force-enable this proc)
  log({ t: 'init', rc: rc });
  if (rc === 0) {
    tlf_fshide();                            // root / overlayfs / mount hide
    const ac = tlf_autocloak().valueOf();    // kernel-side frida-footprint hide
    log({ t: 'autocloak', rc: ac });
    if (ac !== 0) {                          // fallback: userspace sweep
      const n = tlf_selfcloak().valueOf();
      log({ t: 'selfcloak', hidden: n });
      setInterval(() => { try { tlf_selfcloak(); } catch (e) {} }, 200);
    }
  } else {
    log({ t: 'bridge-down', rc: rc });       // shpte not loaded / bridge off
  }
} catch (e) {
  log({ t: 'error', msg: String(e) });
}

// heartbeat so the harness sees liveness from inside the process too
let beat = 0;
setInterval(() => { beat++; log({ t: 'beat', n: beat }); }, 1000);
