'use strict';
// SPAWN recipe v3: in-place RENAME of frida modules in the linker's name strings (what
// dl_iterate_phdr AND a direct soinfo-name walk both read), so a name-based module check
// at the one-shot spawn verdict finds nothing. Then cloak (maps) + exceptor. Armed before
// resume.
const SO = '/data/local/tmp/libtracelessfrida.so';
const dt = () => '0';
const exp = (m, n) => (m.findExportByName && m.findExportByName(n)) || m.getExportByName(n);
const KEYS = ['frida', 'gum', 'jvmti', 'openjdkjvm', 'tracelessfrida', 'linjector', 'memfd'];
const RE = /frida|gum|jvmti|openjdkjvm|tracelessfrida|linjector|memfd/i;

// --- 0) rename frida modules in the soinfo name strings (in place) ---
try {
  const dlip = Module.findGlobalExportByName('dl_iterate_phdr');
  const origDlip = new NativeFunction(dlip, 'int', ['pointer', 'pointer']);
  const renamed = [];
  const cb = new NativeCallback(function (info, size, d) {
    try {
      const namePtr = info.add(Process.pointerSize).readPointer(); // dl_phdr_info.dlpi_name
      if (!namePtr.isNull()) {
        const name = namePtr.readUtf8String();
        if (name && RE.test(name)) {
          const bytes = Memory.allocUtf8String(name); // measure
          let low = name.toLowerCase();
          Memory.protect(namePtr, name.length + 1, 'rw-');
          // overwrite each offending keyword's bytes in place with 'a'
          for (const k of KEYS) {
            let idx = low.indexOf(k);
            while (idx >= 0) {
              for (let j = 0; j < k.length; j++) namePtr.add(idx + j).writeU8(0x61); // 'a'
              low = low.substring(0, idx) + 'a'.repeat(k.length) + low.substring(idx + k.length);
              idx = low.indexOf(k);
            }
          }
          renamed.push(name + ' -> ' + namePtr.readUtf8String());
        }
      }
    } catch (e) {}
    return 0; // continue iterating all
  }, 'int', ['pointer', 'size_t', 'pointer']);
  origDlip(cb, ptr(0));
  send({ t: 'renamed', list: renamed });
} catch (e) { send({ t: 'rename-err', msg: String(e) }); }

// --- 1) tlf cloak (maps) ---
let cloakRc = 'skip';
try {
  const mod = Module.load(SO);
  const tlf_init = new NativeFunction(exp(mod, 'tlf_init'), 'int', ['int']);
  const tlf_fshide = new NativeFunction(exp(mod, 'tlf_fshide'), 'void', []);
  const tlf_selfcloak = new NativeFunction(exp(mod, 'tlf_selfcloak'), 'int', []);
  const rc = tlf_init(0).valueOf();
  tlf_fshide();
  tlf_selfcloak(); setInterval(() => { try { tlf_selfcloak(); } catch (e) {} }, 200);
  cloakRc = rc;
} catch (e) { cloakRc = 'err:' + e; }
send({ t: 'cloak', rc: cloakRc });

// --- 2) exceptor ---
Interceptor.attach(Module.findGlobalExportByName('getpid'), { onEnter() {} });
send({ t: 'armed' });

let beat = 0;
setInterval(() => { beat++; if (beat % 4 === 0) send({ t: 'beat', n: beat, dt: (beat * 0.5).toFixed(1) }); }, 500);
