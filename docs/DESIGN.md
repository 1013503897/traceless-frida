# Design

## Goal

Give Frida users an `Interceptor`-shaped API whose hooks are **invisible to the target**:
no inline patch over the function prologue, no `rwx` trampoline mapped over the library,
and a `.text` that stays byte-identical under CRC / `/proc/maps` / `mincore` inspection.

## Why not patch `frida-gum`

The kanxue write-up *Frida 无痕 Hook* integrates a page-table shadow (`wxshadow`,
`PR_WXSHADOW_PATCH` / `PR_WXSHADOW_RELEASE`) directly into `frida-gum`'s `Interceptor`, so
stock `Interceptor.replace/attach` become traceless. That is the most transparent result
but requires **forking and rebuilding frida-gum** for android-arm64 and shipping a custom
`frida-server`/gadget.

This project takes the equivalent-but-decoupled route: keep stock Frida, and install the
hook through an **already-device-proven traceless backend** — the shpte KPM — via a tiny
native shim that Frida `Module.load`s into the target. Frida remains the frontend
(process model, symbol resolution, `NativeCallback` replacements); the "code write" is a
page-table shadow in the kernel, not a patch over the target.

## Mechanism (what shpte does)

Same core idea as `wxshadow`:

- The KPM sets the target code page's PTE **`UXN`** (bit 54, unprivileged execute-never)
  so any *execution* on that page traps into `do_page_fault`.
- `do_page_fault` is routed to run the corresponding instruction from a **whole-region
  DBI clone** — a position-independent recompilation of `[base,end)` produced in-process
  by `dbi_recompile_range()` (handles ADR/ADRP, internal vs external B/BL, and the
  `ldr` **literal-pool** loads that cause the classic read/execute *livelock* — those are
  materialized into the clone so the original page is never re-read for execution).
- The target function's entry is **overridden** to the replacement; a **backup** (the
  faithful in-clone copy) lets the replacement call the original.
- The original `.text` is **never written**. Reads still see the pristine bytes.

`ghost` mode additionally hosts the clone in **VMA-less kernel memory** (`pghookg`), so the
recompiled clone is also unreachable by `/proc/maps` + `mincore`.

The 2 MB huge-page problem the kanxue post calls out (libart's PMD-block sections) is
sidestepped here by cloning a *region* into separate 4 KiB-backed memory rather than
splitting the live block descriptor — `MAX_GHOST_PG = 512` is exactly one 2 MB region.

## The bridge

No superkey at runtime. Commands ride a magic-gated `sysinfo(179)` carrier:

```
syscall(179, 0x5348505442524447 /* "SHPTBRDG" */, cmd_ptr, cmd_len, out_ptr, out_len)
```

`kpmhook.c` issues `pghook` / `pghookg` / `pgunhook` (and `probe`). A real `sysinfo()`
(arg0 ≠ magic) passes straight through. See
`stealth-poc/docs/bridge-protocol.md` for the wire contract.

## The frontend ↔ backend ABI

`native/tlf_api.c` exports exactly five symbols (everything else is
`-fvisibility=hidden`), thin wrappers over `lib/kpmhook`:

| export | over | meaning |
|---|---|---|
| `tlf_init(ghost)` | `kpm_hook_force_enable` + `kpm_hook_set_ghost` + `kpm_hook_init` | arm; 0 = bridge live |
| `tlf_hook(target, repl)` | `kpm_inline_hooker` | install; returns backup or NULL |
| `tlf_unhook(target)` | `kpm_inline_unhooker` | remove one override |
| `tlf_shutdown()` | `kpm_hook_shutdown` | release region mappings |
| `tlf_fshide()` | `kpm_hook_fshide_enable` | optional statfs/mountinfo hide |

`tlf_init` force-enables the process gate because a Frida operator is *always* explicit
about which process they inject (Vector, by contrast, gates on a cmdline property).

`agent/traceless.js` binds those five via `NativeFunction` and layers the
`Interceptor`-style API on top: `replace` builds a typed `NativeCallback`, hooks it, and
wraps the returned backup as a `NativeFunction` so the replacement can call the original;
`attach` is `replace` with an onEnter/onLeave wrapper.

## Correctness notes / limits

- **Signatures.** `replace`/`attach` synthesize a C-callable replacement, so a
  `{retType,argTypes}` is needed. The default `SIG_GENERIC` (8 pointer args, pointer
  return) is correct for ≤8 integer/pointer args and integer/pointer returns; pass an
  explicit signature for float/double or variadic functions.
- **Page-span.** A region is a clean-bounded multi-page clone, so functions crossing a
  page boundary are handled; extremely large functions beyond `MAX_RGN_PAGES` fall back
  to NULL (the caller then does nothing / can use stock Frida for that one).
- **Teardown race.** Reverting the last live region can perturb shpte's global maps-hide
  hook (a concurrent `/proc/maps` read in another process may race it → potential panic).
  Prefer ghost mode; don't drain to zero regions under load.
- **Frida's own footprint** (agent maps, gum-allocated replacement) is not hidden.
