'use strict';
// Dynamic string-decrypt dump: hook libloader's per-callsite string decryptor
// sub_97BA4(dst, enc_src, 0) and read `dst` after the call. Reveals every runtime-
// decrypted string (detection paths/keywords) without fighting the OLLVM. Hooking it
// also installs gum's exceptor, so frida survives GCash's signal anti-debug.
const seen = new Set();
let n = 0;

function arm(modName, off) {
  const m = Process.findModuleByName(modName);
  if (!m) { send({ t: 'no-mod', mod: modName }); return false; }
  const base = m.base;
  const fn = base.add(off);
  Interceptor.attach(fn, {
    onEnter(a) {
      this.dst = a[0];
      // caller offsets relative to libloader base -> maps decrypted string to detection fn
      try {
        this.callers = Thread.backtrace(this.context, Backtracer.FUZZY).slice(0, 4)
          .map(p => { const d = p.sub(base); return (d.compare(0) >= 0 && d.compare(0x1000000) < 0) ? '+0x' + d.toString(16) : null; })
          .filter(Boolean);
      } catch (e) { this.callers = []; }
    },
    onLeave() {
      try {
        const buf = this.dst.readByteArray(160);
        if (!buf) return;
        const u = new Uint8Array(buf);
        let s = '';
        for (let i = 0; i < u.length; i++) {
          const c = u[i];
          if (c === 0) break;
          if (c === 9 || c === 10 || (c >= 32 && c <= 126)) s += String.fromCharCode(c);
          else break;
        }
        if (s.length >= 3 && !seen.has(s)) {
          seen.add(s); n++;
          if (n <= 700) send({ t: 'str', s: s, from: this.callers });
        }
      } catch (e) {}
    }
  });
  send({ t: 'armed', mod: modName, at: fn.toString() });
  return true;
}

// libloader string decryptor @ +0x97ba4 (dst, enc, 0)
arm('libloader.so', 0x97ba4);

setInterval(() => send({ t: 'count', n: n }), 2000);
