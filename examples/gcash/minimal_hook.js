'use strict';
// Mechanism test: hook ONE unrelated function (getpid) to force gum's exceptor to
// install, nothing else. If frida then survives GCash's anti-debug, the survival is
// due to the gum-exceptor handling the anti-debug signals -- NOT anything specific
// to raise/kill. Confirms the stable fix = keep the exceptor active.
const started = Date.now();
function dt() { return ((Date.now() - started) / 1000).toFixed(2); }

const p = Module.findGlobalExportByName('getpid');
Interceptor.attach(p, { onEnter() {} });   // no-op hook: just activates the exceptor
send({ t: 'armed-getpid-hook', dt: dt() });

let beat = 0;
setInterval(() => { beat++; send({ t: 'beat', n: beat, dt: dt() }); }, 500);
