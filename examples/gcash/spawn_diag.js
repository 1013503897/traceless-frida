'use strict';
// Spawn diagnostic: after cloak, what frida footprint is STILL enumerable via channels
// the /proc/maps cloak does NOT cover -- the linker's module list (_r_debug.r_map walk,
// and frida's own Process.enumerateModules which uses the soinfo list).
const SO = '/data/local/tmp/libtracelessfrida.so';
const dt = () => '0';
const exp = (m, n) => (m.findExportByName && m.findExportByName(n)) || m.getExportByName(n);
const RE = /frida|gum|jvmti|memfd|tracelessfrida|openjdkjvm|linjector/i;

// cloak first (so we test the POST-cloak enumerable surface)
try {
  const mod = Module.load(SO);
  new NativeFunction(exp(mod, 'tlf_init'), 'int', ['int'])(0);
  new NativeFunction(exp(mod, 'tlf_selfcloak'), 'int', [])();
} catch (e) { send({ t: 'cloak-err', msg: String(e) }); }

// 1) frida's own module list (soinfo-based) -- filtered
const mods = Process.enumerateModules().map(m => m.name).filter(n => RE.test(n));
send({ t: 'enumModules', frida: mods });

// 2) walk _r_debug.r_map (the debugger rendezvous link_map chain)
try {
  const rd = Module.findGlobalExportByName('_r_debug');
  if (!rd) { send({ t: 'r_debug', found: false }); }
  else {
    // struct r_debug { int r_version; /*pad*/ struct link_map* r_map; ... }
    let lm = rd.add(Process.pointerSize).readPointer(); // r_map at offset 8 (ptr-aligned)
    const names = []; let count = 0;
    while (!lm.isNull() && count < 600) {
      count++;
      const namePtr = lm.add(8).readPointer();           // link_map.l_name @ off 8
      const name = namePtr.isNull() ? '' : namePtr.readUtf8String();
      if (name && RE.test(name)) names.push(name);
      lm = lm.add(24).readPointer();                     // link_map.l_next @ off 24
    }
    send({ t: 'r_debug', found: true, total: count, frida: names });
  }
} catch (e) { send({ t: 'r_debug-err', msg: String(e) }); }
