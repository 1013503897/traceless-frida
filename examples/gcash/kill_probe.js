'use strict';
/*
 * Kill-mechanism probe. Attach to a running GCash and watch what neutralizes the
 * frida agent ~1s later:
 *  - Process.setExceptionHandler: catch any signal delivered to an agent/gum thread.
 *  - Interceptor on exit/_exit/abort/kill/tgkill/pthread_kill/raise + backtrace: who
 *    calls a terminator and from where.
 *  - heartbeat: last beat before severance marks the moment.
 * Plain Interceptor (inline) is fine here -- we are diagnosing, the app dies anyway.
 */
const started = Date.now();
function dt() { return ((Date.now() - started) / 1000).toFixed(2); }

// NOTE: no setExceptionHandler -- it intercepts ART's normal implicit-check SIGSEGVs
// (a storm) and is itself invasive. We only watch explicit terminators here.

function hookTerm(name, argIdx) {
  const p = Module.findGlobalExportByName(name);
  if (!p) return;
  try {
    Interceptor.attach(p, {
      onEnter(args) {
        const info = { t: 'term', fn: name, dt: dt(), tid: Process.getCurrentThreadId(),
                       thname: Process.getCurrentThreadName && (function(){try{return Process.enumerateThreads().find(x=>x.id===Process.getCurrentThreadId())?.name}catch(e){return '?'}})() };
        if (argIdx != null) info.arg = args[argIdx].toInt32();
        info.bt = Thread.backtrace(this.context, Backtracer.FUZZY)
          .slice(0, 8).map(a => { const m = Process.findModuleByAddress(a);
            return m ? (m.name + '+0x' + a.sub(m.base).toString(16)) : String(a); });
        send(info);
      }
    });
  } catch (e) {}
}

hookTerm('exit', 0);
hookTerm('_exit', 0);
hookTerm('abort', null);
hookTerm('kill', 0);        // arg0=pid, arg1=sig
hookTerm('tgkill', null);
hookTerm('pthread_kill', null);
hookTerm('raise', 0);
send({ t: 'armed', dt: dt() });

let beat = 0;
setInterval(() => { beat++; send({ t: 'beat', n: beat, dt: dt() }); }, 250);
