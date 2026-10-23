'use strict';
// SPAWN recipe v2: spawn_full + KPM `hidetracer` (global TracerPid->0 spoof) sent over
// the sysinfo(179) bridge directly from JS, armed BEFORE resume. Tests whether the
// spawn-time verdict was catching frida via /proc/self/status TracerPid (spawn holds a
// ptrace tracer). Also reports the bridge reply so we learn if the loaded KPM even has
// the verb.
const SO = '/data/local/tmp/libtracelessfrida.so';
const started = Date.now();
const dt = () => ((Date.now() - started) / 1000).toFixed(2);
const exp = (m, n) => (m.findExportByName && m.findExportByName(n)) || m.getExportByName(n);
const RE = /frida|gum|jvmti|memfd|tracelessfrida|openjdkjvm|linjector/i;

// --- 0) KPM bridge: hidetracer (TracerPid spoof) ---
try {
  const syscall = new NativeFunction(Module.findGlobalExportByName('syscall'),
    'int64', ['int64', 'int64', 'pointer', 'int64', 'pointer', 'int64']);
  const MAGIC = int64('0x5348505442524447'); // "SHPTBRDG" (fits positive int64)
  const bridge = (cmd) => {
    const c = Memory.allocUtf8String(cmd);
    const out = Memory.alloc(256); out.writeU8(0);
    syscall(int64(179), MAGIC, c, int64(cmd.length + 1), out, int64(256));
    return out.readUtf8String();
  };
  send({ t: 'probe', dt: dt(), reply: bridge('probe') });
  send({ t: 'hidetracer', dt: dt(), reply: bridge('hidetracer') });
} catch (e) { send({ t: 'bridge-err', dt: dt(), msg: String(e) }); }

// --- 1) dl_iterate_phdr filter (hide frida from link_map) ---
try {
  const dlip = Module.findGlobalExportByName('dl_iterate_phdr');
  const origDlip = new NativeFunction(dlip, 'int', ['pointer', 'pointer']);
  Interceptor.replace(dlip, new NativeCallback(function (cb, data) {
    const origCb = new NativeFunction(cb, 'int', ['pointer', 'size_t', 'pointer']);
    const filt = new NativeCallback(function (info, size, d) {
      try {
        const namePtr = info.add(Process.pointerSize).readPointer();
        const name = namePtr.isNull() ? '' : namePtr.readUtf8String();
        if (name && RE.test(name)) return 0;
      } catch (e) {}
      return origCb(info, size, d);
    }, 'int', ['pointer', 'size_t', 'pointer']);
    return origDlip(filt, data);
  }, 'int', ['pointer', 'pointer']));
} catch (e) {}

// --- 2) tlf cloak (maps) ---
let cloakRc = 'skip';
try {
  const mod = Module.load(SO);
  const tlf_init = new NativeFunction(exp(mod, 'tlf_init'), 'int', ['int']);
  const tlf_fshide = new NativeFunction(exp(mod, 'tlf_fshide'), 'void', []);
  const tlf_autocloak = new NativeFunction(exp(mod, 'tlf_autocloak'), 'int', []);
  const tlf_selfcloak = new NativeFunction(exp(mod, 'tlf_selfcloak'), 'int', []);
  const rc = tlf_init(0).valueOf();
  tlf_fshide();
  let ac = tlf_autocloak().valueOf();
  if (ac !== 0) { tlf_selfcloak(); setInterval(() => { try { tlf_selfcloak(); } catch (e) {} }, 200); }
  cloakRc = { init: rc, autocloak: ac };
} catch (e) { cloakRc = 'err:' + e; }
send({ t: 'cloak', dt: dt(), rc: cloakRc });

// --- 3) exceptor ---
Interceptor.attach(Module.findGlobalExportByName('getpid'), { onEnter() {} });
send({ t: 'armed', dt: dt() });

let beat = 0;
setInterval(() => { beat++; if (beat % 4 === 0) send({ t: 'beat', n: beat, dt: dt() }); }, 500);
