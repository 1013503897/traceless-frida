/*
 * test.js -- end-to-end proof that the Frida frontend installs a WORKING and
 * TRACELESS inline hook via the shpte KPM. Load AFTER agent/traceless.js:
 *     frida -U -f /data/local/tmp/tlf_target -l agent/traceless.js -l test/test.js
 *
 * It hooks secret(n) to return orig(n)+1000, then reports:
 *   - call: the first few interceptions (orig vs returned) -> hook is LIVE
 *   - hooked.textUnchanged: secret()'s first .text word before vs after -> the code
 *     was NOT patched (a real inline hook flips this word to a branch)
 *   - maps.prot: the target's own page protection for secret() -> stays r-x (no rwx,
 *     not writable) because the redirect lives in the kernel fault router, not here
 *   - rwx_count: rwx ranges visible in the TARGET -> none cover secret()
 */
'use strict';

const TARGET_SYM = 'secret';
const OFFSET = 1000;

function main() {
    const secret = Module.findGlobalExportByName(TARGET_SYM);
    if (!secret) { send({ t: 'error', msg: 'symbol ' + TARGET_SYM + ' not found' }); return; }
    const before = secret.readU32();

    const ghost = (typeof GHOST_MODE !== 'undefined') && !!GHOST_MODE;
    Traceless.init({ ghost: ghost }); // throws if the shpte bridge is not armed
    send({ t: 'armed', ghost: ghost });

    let calls = 0;
    const rec = Traceless.replace(secret, {
        retType: 'int', argTypes: ['int'],
        onCall(args, orig) {
            const o = orig(args[0]).valueOf();
            calls++;
            const r = o + OFFSET;
            if (calls <= 5) send({ t: 'call', n: args[0].valueOf(), orig: o, ret: r });
            return r;
        }
    });

    const after = secret.readU32();
    send({
        t: 'hooked', target: secret.toString(), backup: rec.backup.toString(),
        textBefore: '0x' + before.toString(16), textAfter: '0x' + after.toString(16),
        textUnchanged: before === after
    });

    const page = secret.and(ptr('0xfff').not());
    const rr = Process.findRangeByAddress(secret);
    send({ t: 'maps', page: page.toString(), prot: rr ? rr.protection : '?', file: rr && rr.file ? rr.file.path : null });

    const rwx = Process.enumerateRanges('rwx');
    const overSecret = rwx.filter(r => secret.compare(r.base) >= 0 && secret.compare(r.base.add(r.size)) < 0);
    send({ t: 'rwx', total: rwx.length, coveringSecret: overSecret.length });
}

rpc.exports = {
    cleanup() {
        try { Traceless.dispose(); send({ t: 'disposed' }); }
        catch (e) { send({ t: 'error', msg: '' + e }); }
    }
};

try { main(); } catch (e) { send({ t: 'error', msg: '' + e, stack: e.stack }); }
