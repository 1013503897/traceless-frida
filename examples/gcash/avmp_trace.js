'use strict';
// AVMP devirt input dump: hook libsgmainso's core recursive interpreter sub_B4DD0
// (@+0xb4dd0). arg0 = the serialized AVMP program/data stream (first byte = opcode
// char K/V/r/F/...). Build an opcode-char histogram over all (recursive) calls and
// capture a handful of full arg0 blobs = the actual VM program the devirt targets.
// Hooking also installs gum's exceptor so frida survives GCash's signal anti-debug.
const OFF = 0xb4dd0;
const hist = {};       // opcode char -> count
const blobs = [];      // sample arg0 streams
let calls = 0;

function armOn(mod) {
  const base = mod.base;
  Interceptor.attach(base.add(OFF), {
    onEnter(a) {
      calls++;
      try {
        const p = a[0];
        const c = p.readU8();
        const ch = (c >= 32 && c <= 126) ? String.fromCharCode(c) : ('\\x' + c.toString(16));
        hist[ch] = (hist[ch] || 0) + 1;
        // capture a few top-ish blobs (heuristic: arg0 whose first char is a letter, sampled)
        if (blobs.length < 24 && calls % 7 === 0) {
          const bytes = p.readByteArray(48);
          blobs.push({ n: calls, head: ch, hex: Array.from(new Uint8Array(bytes)).map(x => x.toString(16).padStart(2, '0')).join('') });
        }
      } catch (e) {}
    }
  });
  send({ t: 'armed', mod: mod.name, base: base.toString(), at: base.add(OFF).toString() });
}

const cand = Process.enumerateModules().filter(m => /sgmain/i.test(m.name));
send({ t: 'sgmain-modules', list: cand.map(m => m.name) });
if (cand.length) armOn(cand[0]);
else send({ t: 'no-sgmain' });

setInterval(() => {
  send({ t: 'hist', calls: calls, top: Object.entries(hist).sort((a, b) => b[1] - a[1]).slice(0, 20) });
  if (blobs.length) { send({ t: 'blobs', blobs: blobs.splice(0, 24) }); }
}, 2500);
