'use strict';
// Control agent: pure heartbeat, NO tlf load, NO cloak. Measures bare frida-agent
// survival in the current (Vector+sergei) GCash environment.
const started = Date.now();
let beat = 0;
setInterval(() => { beat++; send({ t: 'beat', n: beat, dt: ((Date.now() - started) / 1000).toFixed(2) }); }, 1000);
send({ t: 'ready', dt: '0.00' });
