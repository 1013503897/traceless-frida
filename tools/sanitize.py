#!/usr/bin/env python3
"""
traceless-frida binary sanitizer (vendored, self-contained -- no external deps beyond
a stock Python 3; strip is optional via $STRIP).

    sanitize.py patch  <elf> [--strip]   length-preserving rename of giveaway tokens
    sanitize.py report <elf>             count residual giveaway tokens

The traceless-frida shim (libtracelessfrida.so) does NOT embed a frida-agent, so it
carries none of frida's own strings ("frida"/"gum"/...). Its only fingerprints are:
  1. internal symbol names (kpm_inline_hooker, dbi_recompile, ...)   -> $STRIP --strip-all
  2. the SO file / soname ("libtracelessfrida.so")                   -> build.ps1 -Name <rand>
  3. a few identity tokens in log strings ("traceless", "kpmhook" tag)-> this renamer

CRITICAL -- these tokens are the KPM bridge protocol / getprop keys and are matched by
STRING at runtime; they MUST NOT be renamed (kept out of RENAME_TOKENS on purpose):
    pghook  pghookg  hidergn  fshide  probe  bridge          (sysinfo(179) command verbs)
    persist.kpmhook.mode  persist.kpmhook.target             (getprop keys read by the shim)
    /proc/self/maps                                          (a real path)

Renames are length-preserving, whole-file, and skip mid-identifier hits (an alnum byte
immediately before the match) so a token embedded in a longer identifier is left alone.
Random replacements come from os.urandom -> a hex/lowercase alphabet, so every build
morphs. Deterministic renames can be pinned via env (e.g. TOK_traceless=<9 chars>).
"""
from __future__ import annotations
import os, re, sys, subprocess

# token -> replacement length; replacement is a per-build random of the SAME length
# (or $TOK_<token> if set). Order does not matter (applied longest-first internally).
# Keep ONLY identity giveaways here; never a protocol/getprop/path token (see header).
RENAME_TOKENS = [
    b"tracelessfrida",   # inside the (default) soname string, if the random -Name is not used
    b"traceless",        # log/tag identity
]

_ALNUM = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_RAND_ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789"


def _rand(n: int) -> bytes:
    return bytes(_RAND_ALPHABET[b % len(_RAND_ALPHABET)] for b in os.urandom(n))


def _repl_for(tok: bytes) -> bytes:
    env = os.environ.get("TOK_" + tok.decode())
    if env is not None:
        if len(env) != len(tok):
            sys.exit(f"[sanitize] TOK_{tok.decode()} must be {len(tok)} chars (got {len(env)})")
        return env.encode()
    r = _rand(len(tok))
    # keep a leading letter so it stays a valid C identifier fragment
    if r[:1].isdigit():
        r = b"z" + r[1:]
    return r


def _bounded_replace(buf: bytearray, old: bytes, new: bytes) -> int:
    if len(old) != len(new):
        raise ValueError("length drift")
    n, i = 0, 0
    while True:
        j = buf.find(old, i)
        if j < 0:
            break
        if j > 0 and buf[j - 1] in _ALNUM:      # mid-identifier -> skip
            i = j + 1
            continue
        buf[j:j + len(old)] = new
        n += 1
        i = j + len(new)
    return n


def patch(path: str, do_strip: bool):
    with open(path, "rb") as f:
        original = f.read()
    buf = bytearray(original)
    # longest tokens first so "tracelessfrida" is consumed before "traceless"
    for tok in sorted(RENAME_TOKENS, key=len, reverse=True):
        repl = _repl_for(tok)
        c = _bounded_replace(buf, tok, repl)
        if c:
            print(f"[sanitize] renamed {tok.decode():<16} -> {repl.decode()}  x{c}")
    if len(buf) != len(original):
        sys.exit("[sanitize] file size changed -- aborting")
    with open(path, "wb") as f:
        f.write(buf)
    if do_strip:
        _strip(path)
    print("[sanitize] done")


def _strip(path: str):
    strip_bin = os.environ.get("STRIP")
    if not strip_bin:
        print("[sanitize] STRIP unset -- skipping --strip-all")
        return
    print(f"[sanitize] {strip_bin} --strip-all {path}")
    subprocess.run([strip_bin, "--strip-all", path], check=True)


def report(path: str):
    with open(path, "rb") as f:
        data = f.read()
    print(f"[report] {os.path.basename(path)} ({len(data)} bytes)")
    # identity giveaways that SHOULD be gone after patch:
    for tok in RENAME_TOKENS + [b"libtracelessfrida"]:
        print(f"  {tok.decode():<18} {data.count(tok)}")
    # functional strings that MUST survive (protocol/getprop) -- informational:
    for tok in (b"pghook", b"hidergn", b"fshide", b"persist.kpmhook", b"/proc/self/maps"):
        print(f"  [keep] {tok.decode():<12} {data.count(tok)}")


def main() -> int:
    if len(sys.argv) < 3 or sys.argv[1] not in ("patch", "report"):
        print("usage: sanitize.py patch|report <elf> [--strip]", file=sys.stderr)
        return 2
    mode, target = sys.argv[1], sys.argv[2]
    if not os.path.exists(target):
        print(f"[sanitize] target missing: {target}", file=sys.stderr)
        return 1
    if mode == "patch":
        patch(target, "--strip" in sys.argv[3:])
    else:
        report(target)
    return 0


if __name__ == "__main__":
    sys.exit(main())
