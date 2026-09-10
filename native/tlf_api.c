// SPDX-License-Identifier: GPL-2.0-or-later
//
// tlf_api: the stable C ABI that the Frida frontend (agent/traceless.js) binds to
// via NativeFunction. It is a thin, dependency-free shim over lib/kpmhook -- the
// SAME userspace glue Vector uses -- so a Frida-driven inline hook is installed by
// the shpte KPM's page-table shadow (UXN-trap + whole-region DBI clone) instead of
// a visible inline patch. The hooked library's .text is never written; /proc/<pid>/
// maps over the target stays byte-identical and non-writable.
//
// Why a separate shim (and not just export kpm_* directly): (1) the whole .so is
// built -fvisibility=hidden, so these five wrappers are the ONLY exported symbols
// -- a clean, minimal ABI surface for the JS side to resolve; (2) tlf_init folds
// force-enable + ghost + probe into one call (a Frida operator is always explicit
// about which process they inject, so the Vector-only cmdline process-gate is
// bypassed by design here); (3) it decouples the JS ABI from any future kpmhook.h
// signature drift.
//
// Runs inside the TARGET process (Frida injects this .so there): kpm_inline_hooker
// reads /proc/self/maps, mmaps the clone in-process, and drives the KPM over the
// no-superkey sysinfo(179) bridge. Prerequisite (once per boot, out of band):
//     shctl <KEY> load shpte.kpm ; shctl <KEY> control shpte probe ; ... bridge
// (on the dev device shpte is already loaded and the bridge armed at boot).

#include "kpmhook.h"

#define TLF_EXPORT __attribute__((visibility("default"), used))

/*
 * Arm the backend for THIS (injected) process. `ghost`!=0 hosts every region clone
 * in VMA-less kernel memory (pghookg) so even the recompiled clone is invisible to
 * /proc/maps + mincore; `ghost`==0 uses the proven anon-RX clone path. Returns 0 if
 * the bridge is live and armed, <0 otherwise (shpte not loaded / bridge off) -- the
 * JS side treats <0 as "traceless backend unavailable" and refuses to arm.
 */
TLF_EXPORT int tlf_init(int ghost)
{
    kpm_hook_force_enable();          /* Frida operator is explicit about the target */
    if (ghost) kpm_hook_set_ghost(1); /* opt-in VMA-less clone hosting */
    return kpm_hook_init();           /* probe the bridge; caches getpid() */
}

/*
 * Install a traceless inline hook: redirect `target`'s entry to `replacement`.
 * Returns the backup (a faithful, position-independent clone of the original) to
 * call the original, or NULL on failure (no clean region / bridge reject). Several
 * targets on one code page share a single trapped page + clone (overrides append).
 */
TLF_EXPORT void *tlf_hook(void *target, void *replacement)
{
    return kpm_inline_hooker(target, replacement);
}

/* Remove one override; disarms (un-traps) the page when its last override goes.
 * Returns 1 on success, 0 if `target` was not a live traceless hook. */
TLF_EXPORT int tlf_unhook(void *target)
{
    return kpm_inline_unhooker(target);
}

/* Release every region clone mapping. Call after all unhooks are done. */
TLF_EXPORT void tlf_shutdown(void)
{
    kpm_hook_shutdown();
}

/* Optional: register this tgid for the KPM fs-hide (statfs/mountinfo spoof) --
 * defeats "hidden overlayfs"/magisk mount detection. No-op on a pre-0.6.6 KPM. */
TLF_EXPORT void tlf_fshide(void)
{
    kpm_hook_fshide_enable();
}

/*
 * Optional: self-cloak Frida's OWN footprint. The traceless hook keeps the TARGET clean,
 * but the injected frida-agent / Gum JIT / openjdkjvmti memfds still show in /proc/self/maps
 * -- what a maps-scan inject-detector (counts executable/deleted memfd regions) kills on.
 * This hides those regions via the KPM general hide-set. Returns #regions hidden. Call after
 * tlf_init(); the JS side re-calls it on a timer to catch lazily-created JIT memfds.
 */
TLF_EXPORT int tlf_selfcloak(void)
{
    return kpm_hook_selfcloak();
}
