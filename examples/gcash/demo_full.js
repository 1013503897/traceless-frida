'use strict';
// Full-stack demo on GCash (attach): frida ALIVE (exceptor beats gum anti-debug) +
// HIDDEN (tlf cloak hides frida maps) + HOOKING (openat interception logs live file
// access). One combined proof that frida is usable on GCash.
const SO = '/data/local/tmp/libtracelessfrida.so';
const started = Date.now();
const dt = () => ((Date.now() - started) / 1000).toFixed(2);
const exp = (m, n) => (m.findExportByName && m.findExportByName(n)) || m.getExportByName(n);

function fridaRanges() {
  return Process.enumerateRanges('r-x').filter(r => {
    const f = (r.file && r.file.path) || '';
    return /frida|gum|memfd|tracelessfrida|jvmti|openjdk/i.test(f);
  }).length;
}

send({ t: 'frida-ranges-before-cloak', dt: dt(), n: fridaRanges() });

// --- tlf cloak: hide frida's own footprint via the shpte KPM ---
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
  if (ac !== 0) { tlf_selfcloak(); setInterval(() => { try { tlf_selfcloak(); } catch (e) {} }, 300); }
  cloakRc = { init: rc, autocloak: ac };
} catch (e) { cloakRc = 'err:' + e; }
send({ t: 'cloak', dt: dt(), rc: cloakRc });

// --- exceptor + live instrumentation: hook openat, log distinct paths (capped) ---
const seen = new Set(); let logged = 0;
Interceptor.attach(Module.findGlobalExportByName('openat'), {
  onEnter(a) {
    try {
      const p = a[1].readUtf8String();
      if (p && logged < 18 && !seen.has(p) && /gcash|apse|guard|secstore|\.so$|edge|apdid/i.test(p)) {
        seen.add(p); logged++; send({ t: 'open', dt: dt(), path: p });
      }
    } catch (e) {}
  }
});
send({ t: 'armed-openat-hook', dt: dt() });

setTimeout(() => send({ t: 'frida-ranges-after-cloak', dt: dt(), n: fridaRanges() }), 800);
let beat = 0;
setInterval(() => { beat++; if (beat % 4 === 0) send({ t: 'beat', n: beat, dt: dt() }); }, 500);
