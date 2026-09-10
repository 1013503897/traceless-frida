/*
 * traceless.js -- a Frida frontend for the shpte KPM "page-table shadow" backend.
 *
 * Public API mirrors Frida's Interceptor (replace / attach / revert), but instead of
 * writing an inline patch (which leaves an rwx trampoline and a modified .text that
 * anti-tamper CRCs and /proc/maps scans catch), each hook is installed by the shpte
 * KPM: the target's code page is UXN-trapped and every instruction on it is routed
 * through a whole-region DBI clone; the target function's entry is overridden to your
 * replacement. The hooked library's .text is NEVER written and its maps stay clean.
 *
 * It works by loading a tiny native backend (libtracelessfrida.so) into the target
 * with Module.load(), then driving it through five NativeFunctions. That native side
 * is the exact same lib/kpmhook glue Vector uses; Frida here is purely the frontend
 * (target selection, symbol resolution, NativeCallback replacements).
 *
 * TRACELESSNESS SCOPE. What is hidden: the target library -- byte-identical, non-
 * writable, no inline branch, no rwx over its .text. What is NOT hidden by default:
 * Frida's own presence (frida-agent maps) and your replacement function, which lives
 * in Frida's gum code allocator. `init({ghost:true})` additionally hosts the recompiled
 * clone in VMA-less kernel memory (invisible to maps/mincore). Hiding frida-agent
 * itself is out of scope -- combine with a Frida-hiding stack if you need that.
 *
 * Frida 17 API (Module.load / mod.getExportByName / NativeFunction / NativeCallback).
 *
 * Usage (REPL / -l):
 *   Traceless.init();                         // arm the backend (throws if bridge off)
 *   const secret = Module.findGlobalExportByName('secret');
 *   Traceless.replace(secret, {
 *     retType: 'int', argTypes: ['int'],
 *     onCall(args, orig) { return orig(args[0]) + 1000; }
 *   });
 *   // ... later:
 *   Traceless.revert(secret);
 */

'use strict';

const DEFAULT_SO = '/data/local/tmp/libtracelessfrida.so';

// A wide generic AAPCS64 signature: 8 integer/pointer args in x0-x7, pointer return.
// Correct for any function with <= 8 integer/pointer args and an integer/pointer
// return (extra register reads are harmless). Pass an explicit {retType,argTypes}
// for float/double args or returns, or for variadic functions.
const SIG_GENERIC = {
    retType: 'pointer',
    argTypes: ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
};

const Traceless = (function () {
    let soPath = DEFAULT_SO;
    let mod = null;
    let fn = null;         // { init, hook, unhook, shutdown, fshide, selfcloak }
    let armed = false;
    let cloakTimer = null; // setInterval id for the periodic self-cloak sweep
    const hooks = new Map(); // key = target hex -> { target, cb, orig, backup, spec }

    function loadBackend() {
        if (fn) return;
        mod = Module.load(soPath);
        const exp = (name) => {
            // Frida 17: Module instance carries getExportByName; fall back to global.
            const p = (mod.findExportByName && mod.findExportByName(name)) ||
                      (mod.getExportByName && mod.getExportByName(name));
            if (!p || p.isNull()) throw new Error('traceless: missing export ' + name + ' in ' + soPath);
            return p;
        };
        fn = {
            init: new NativeFunction(exp('tlf_init'), 'int', ['int']),
            hook: new NativeFunction(exp('tlf_hook'), 'pointer', ['pointer', 'pointer']),
            unhook: new NativeFunction(exp('tlf_unhook'), 'int', ['pointer']),
            shutdown: new NativeFunction(exp('tlf_shutdown'), 'void', []),
            fshide: new NativeFunction(exp('tlf_fshide'), 'void', []),
            selfcloak: new NativeFunction(exp('tlf_selfcloak'), 'int', [])
        };
    }

    function keyOf(ptr) { return ptr.toString(); }

    // --- public API ---

    // init({ so, ghost, fshide, selfCloak }) -> true; throws if the shpte bridge is not armed.
    //   selfCloak: true            -> cloak once now + a periodic sweep every 300ms (default)
    //   selfCloak: { intervalMs }  -> same, custom sweep period; intervalMs<=0 = one-shot only
    function init(opts) {
        opts = opts || {};
        if (opts.so) soPath = opts.so;
        loadBackend();
        const rc = fn.init(opts.ghost ? 1 : 0).valueOf();
        armed = (rc === 0);
        if (!armed) {
            throw new Error('traceless.init: bridge not armed (tlf_init rc=' + rc +
                '). Is shpte loaded and the bridge on? (shctl <KEY> control shpte probe/bridge)');
        }
        if (opts.fshide) fn.fshide();
        if (opts.selfCloak) {
            const iv = (typeof opts.selfCloak === 'object' && 'intervalMs' in opts.selfCloak)
                ? opts.selfCloak.intervalMs : 300;
            selfCloak();                              // cover the startup maps-scan window
            if (iv > 0 && !cloakTimer) cloakTimer = setInterval(selfCloak, iv);
        }
        return true;
    }

    // Hide Frida's own footprint (agent / Gum JIT / jvmti memfds) from /proc/self/maps via
    // the KPM. The traceless hook keeps the TARGET clean; this covers Frida's own presence,
    // which is out of scope for the hook itself. Returns the number of regions hidden.
    // Safe/idempotent to call repeatedly (re-call catches lazily-created JIT memfds).
    function selfCloak() {
        requireArmed();
        return fn.selfcloak().valueOf();
    }

    function requireArmed() {
        if (!armed) throw new Error('traceless: call Traceless.init() first');
    }

    /*
     * replace(target, spec)
     *   spec forms:
     *     1) { retType, argTypes, onCall(args, orig) }  -- typed; onCall receives the
     *        arg values (per argTypes) as an array and `orig`, a NativeFunction that
     *        runs the ORIGINAL (the KPM backup clone). Return value -> callback return.
     *     2) a NativeCallback or raw NativePointer -- used directly as the replacement
     *        function; you manage the signature yourself. Returns the backup pointer.
     * Returns: { backup: NativePointer, orig: NativeFunction|null, revert() }.
     */
    function replace(target, spec) {
        requireArmed();
        target = ptr(target);
        if (hooks.has(keyOf(target))) revert(target);

        let cb, orig = null, retType, argTypes;

        if (spec && typeof spec.onCall === 'function') {
            retType = spec.retType || SIG_GENERIC.retType;
            argTypes = spec.argTypes || SIG_GENERIC.argTypes;
            // `orig` is bound after the hook lands; the closure below runs later so it
            // sees the assigned NativeFunction.
            cb = new NativeCallback(function () {
                const args = Array.prototype.slice.call(arguments);
                return spec.onCall.call(this, args, orig);
            }, retType, argTypes);
        } else if (spec instanceof NativePointer || (spec && spec.constructor && spec.constructor.name === 'NativeCallback')) {
            cb = spec; // raw replacement; caller owns the signature/lifetime
        } else {
            throw new Error('traceless.replace: spec must be {retType,argTypes,onCall} or a NativePointer/NativeCallback');
        }

        const backup = fn.hook(target, cb);
        if (backup.isNull()) {
            throw new Error('traceless.replace: hook failed for ' + target +
                ' (no clean region / bridge reject -- see logcat tag "kpmhook")');
        }
        if (retType) orig = new NativeFunction(backup, retType, argTypes);

        const rec = { target, cb, orig, backup, spec };
        rec.revert = () => revert(target);
        hooks.set(keyOf(target), rec); // strong ref keeps the NativeCallback alive
        return rec;
    }

    /*
     * attach(target, { onEnter, onLeave }, signature?)  -- Frida-Interceptor-style.
     *   onEnter(args): args is the mutable arg array (mutate before original runs).
     *   onLeave(retval): return a value to OVERRIDE the return, or nothing to keep it.
     *   signature: { retType, argTypes }; defaults to SIG_GENERIC (8 ptr args, ptr ret).
     * Built on top of replace(). Returns the same record as replace().
     */
    function attach(target, callbacks, signature) {
        callbacks = callbacks || {};
        const sig = signature || SIG_GENERIC;
        return replace(target, {
            retType: sig.retType,
            argTypes: sig.argTypes,
            onCall(args, orig) {
                const ctx = {};
                if (callbacks.onEnter) callbacks.onEnter.call(ctx, args);
                let ret = orig.apply(null, args);
                if (callbacks.onLeave) {
                    const over = callbacks.onLeave.call(ctx, ret);
                    if (over !== undefined) ret = over;
                }
                return ret;
            }
        });
    }

    // revert(target) -> bool. Removes the override (disarms the page if it was the last).
    function revert(target) {
        requireArmed();
        target = ptr(target);
        const k = keyOf(target);
        const rec = hooks.get(k);
        const ok = fn.unhook(target).valueOf() === 1;
        hooks.delete(k); // drop the NativeCallback ref regardless
        return ok && !!rec;
    }

    // revert everything and release the backend's region mappings.
    //
    // ⚠️ HAZARD: reverting the LAST live region makes the shpte KPM reconfigure/tear
    // down its GLOBAL maps-hide (show_map) hook; that teardown can RACE a concurrent
    // /proc/<pid>/maps read in ANOTHER process and jump through a stale ->show pointer
    // -> potential kernel panic. This is a backend (shpte) race, not a frontend logic
    // error, but the frontend triggers it. Mitigations: (1) prefer ghost mode -- its
    // clone needs no maps-hide entry; (2) avoid draining to zero regions while the
    // device is under load; (3) `settleMs` gives in-flight faults a moment to quiesce.
    function dispose(opts) {
        if (!fn) return;
        opts = opts || {};
        if (cloakTimer) { clearInterval(cloakTimer); cloakTimer = null; }
        for (const k of Array.from(hooks.keys())) {
            try { fn.unhook(ptr(k)); } catch (e) {}
        }
        hooks.clear();
        const settle = (opts.settleMs != null) ? opts.settleMs : 30;
        if (settle > 0) { const t = Date.now(); while (Date.now() - t < settle) {} }
        try { fn.shutdown(); } catch (e) {}
        armed = false;
    }

    function list() {
        return Array.from(hooks.values()).map(r => ({ target: r.target.toString(), backup: r.backup.toString() }));
    }

    return { init, replace, attach, revert, dispose, list, selfCloak, SIG_GENERIC, get armed() { return armed; } };
})();

// Expose for REPL / cross-script (-l traceless.js -l yourscript.js) use.
if (typeof globalThis !== 'undefined') globalThis.Traceless = Traceless;
if (typeof module !== 'undefined' && module.exports) module.exports = Traceless;
