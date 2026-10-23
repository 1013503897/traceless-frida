'use strict';
// Diagnostic: enumerate frida's OWN in-process tells that a NATIVE scan could catch
// (thread names, module names, fds/socket, telltale strings). Runs at spawn (before
// resume) and again at +600ms once gum's threads have spun up.
const started = Date.now();
function dt() { return ((Date.now() - started) / 1000).toFixed(2); }

function dumpThreads(tag) {
  const th = Process.enumerateThreads().map(t => t.name || ('#' + t.id));
  send({ t: 'threads', tag: tag, dt: dt(), names: th });
}
function dumpModules() {
  const sus = Process.enumerateModules()
    .map(m => m.name)
    .filter(n => /frida|gum|agent|openjdkjvm|inject/i.test(n));
  send({ t: 'modules', dt: dt(), sus: sus });
}
function dumpFds() {
  // read /proc/self/fd targets via readlink for frida sockets / pipes
  const readlink = new NativeFunction(Module.getGlobalExportByName('readlink'),
    'long', ['pointer', 'pointer', 'long']);
  const out = [];
  const buf = Memory.alloc(256);
  for (let i = 0; i < 64; i++) {
    const p = Memory.allocUtf8String('/proc/self/fd/' + i);
    const n = readlink(p, buf, 255).valueOf();
    if (n > 0) {
      const s = buf.readUtf8String(n);
      if (s && /frida|gum|pipe|socket|linjector|:[0-9]{4,5}/i.test(s)) out.push(i + '->' + s);
    }
  }
  send({ t: 'fds', dt: dt(), sus: out });
}

try {
  dumpThreads('load');
  dumpModules();
  dumpFds();
} catch (e) { send({ t: 'err', dt: dt(), msg: String(e) }); }

setTimeout(() => { try { dumpThreads('t+0.6'); } catch (e) {} }, 600);
let beat = 0;
setInterval(() => { beat++; send({ t: 'beat', n: beat, dt: dt() }); }, 500);
