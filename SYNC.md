# Vendored sources

`native/kpmhook.c`, `native/kpmhook.h`, `native/dbi.c`, `native/dbi.h`,
`native/aarch64_decode.h` are copied **verbatim** from the canonical source repo:

- **stealth-poc** — `lib/kpmhook.{c,h}`, `lib/dbi.{c,h}`, `lib/aarch64_decode.h`
- provenance: commit `f37b25b` (2026-09-05)

These are the same files [Vector](https://github.com/1013503897/Vector) vendors under
`native/src/kpm/`. Keep them in lock-step with stealth-poc; do not fork them here. The
only original native code in this repo is `native/tlf_api.c` (the five-symbol Frida ABI).

To re-sync:

```bash
cp ../stealth-poc/lib/{kpmhook.c,kpmhook.h,dbi.c,dbi.h,aarch64_decode.h} native/
```

If the `kpm_*` signatures or the `pghook`/`pgunhook` bridge wire format change, update
`native/tlf_api.c` and `agent/traceless.js` accordingly (the JS side only depends on the
five `tlf_*` exports, so most backend drift is absorbed by `tlf_api.c`).
