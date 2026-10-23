'use strict';
// SPAWN full recipe: cloak (hide frida from /proc/maps) + exceptor (beat signal
// anti-debug) + dl_iterate_phdr filter (hide frida modules from the linker's link_map,
// which the Appdome shell libnyadgfpeuju enumerates -- /proc/maps cloak does NOT cover
// dl_iterate_phdr). All armed before resume so the one-shot early maps/module verdict
// reads clean.
const SO = '/data/local/tmp/libtracelessfrida.so';
const started = Date.now();
const dt = () => ((Date.now() - started) / 1000).toFixed(2);
const exp = (m, n) => (m.findExportByName && m.findExportByName(n)) || m.getExportByName(n);
const RE = /frida|gum|jvmti|memfd|tracelessfrida|openjdkjvm|linjector/i;

// --- 1) hide frida modules from dl_iterate_phdr (link_map enumeration) ---
try {
  const dlip = Module.findGlobalExportByName('dl_iterate_phdr');
  const origDlip = new NativeFunction(dlip, 'int', ['pointer', 'pointer']);
  Interceptor.replace(dlip, new NativeCallback(function (cb, data) {
    const origCb = new NativeFunction(cb, 'int', ['pointer', 'size_t', 'pointer']);
    const filt = new NativeCallback(function (info, size, d) {
      try {
        const namePtr = info.add(Process.pointerSize).readPointer(); // dl_phdr_info.dlpi_name @ off 8
        const name = namePtr.isNull() ? '' : namePtr.readUtf8String();
        if (name && RE.test(name)) return 0; // skip frida entries, keep iterating
      } catch (e) {}
      return origCb(info, size, d);
    }, 'int', ['pointer', 'size_t', 'pointer']);
    return origDlip(filt, data);
  }, 'int', ['pointer', 'pointer']));
  send({ t: 'dlip-filter-armed', dt: dt() });
} catch (e) { send({ t: 'dlip-err', dt: dt(), msg: String(e) }); }

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

// --- 3) exceptor: any Interceptor hook installs gum's exceptor (beats raise/kill anti-debug) ---
Interceptor.attach(Module.findGlobalExportByName('getpid'), { onEnter() {} });
send({ t: 'armed', dt: dt() });

let beat = 0;
setInterval(() => { beat++; if (beat % 4 === 0) send({ t: 'beat', n: beat, dt: dt() }); }, 500);
