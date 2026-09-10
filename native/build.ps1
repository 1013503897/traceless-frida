# Build libtracelessfrida.so (arm64) with the NDK clang toolchain.
#
# This is an ORDINARY userspace Android shared library (unlike the shpte KPM, which
# is a freestanding -O0 relocatable ELF -- see stealth-core/kpm/build.ps1). Normal
# -O2 is fine here; it links libc + liblog and is dlopen'd into the target by Frida.
#
# Anti-fingerprint (self-contained; no dependency on any external obfuscator):
#   -Name <base>   : output <base>.so + matching soname. Pass a per-build random base
#                    (e.g. -Name ("l"+(New-Guid).ToString("N").Substring(0,11))) so the
#                    loaded-module name is not "libtracelessfrida.so". Pass to the JS side
#                    as Traceless.init({ so: '/data/local/tmp/<base>.so' }).
#   (default)      : llvm-strip --strip-all -> drops internal gum-free symbol names
#                    (kpm_inline_hooker / dbi_recompile / ...); the tlf_* exports in
#                    .dynsym survive. -NoStrip to keep symbols (debugging).
#   -Sanitize      : also run tools/sanitize.py (length-preserving identity-token rename;
#                    protocol/getprop strings are excluded by design -- see that file).
#
# Usage: powershell native/build.ps1 [-Api 29] [-Name libtracelessfrida] [-NoStrip] [-Sanitize]
param(
    [int]$Api = 29,
    [string]$Name = "libtracelessfrida",
    [string]$Out = "",
    [switch]$NoStrip,
    [switch]$Sanitize
)
$ErrorActionPreference = "Stop"

# NDK: honour ANDROID_NDK_HOME, fall back to the local dev default (same as stealth-core).
$ndk = if ($env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME } else { "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125" }
$bin = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$clang = Join-Path $bin "clang.exe"
if (-not (Test-Path $clang)) { throw "clang not found: $clang (set ANDROID_NDK_HOME)" }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$soname = "$Name.so"
if (-not $Out) { $Out = Join-Path $here $soname }

$srcs = @("tlf_api.c", "kpmhook.c", "dbi.c") | ForEach-Object { Join-Path $here $_ }

$cflags = @(
    "--target=aarch64-linux-android$Api",
    "-fPIC",
    "-O2",
    "-fvisibility=hidden",           # only the tlf_* wrappers are exported
    "-Wall", "-Wno-unused-function", "-Wno-unused-parameter",
    "-shared",
    "-Wl,-soname,$soname",
    "-Wl,--no-undefined"
)

Write-Host "[*] clang : $clang"
Write-Host "[*] target: aarch64-linux-android$Api"
Write-Host "[*] soname: $soname"
Write-Host "[*] out   : $Out"
& $clang @cflags @srcs -o $Out -llog
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $Out"

$strip = Join-Path $bin "llvm-strip.exe"
if (-not $NoStrip) {
    if (Test-Path $strip) {
        & $strip --strip-all $Out
        Write-Host "[+] stripped internal symbols (llvm-strip --strip-all)"
    } else {
        Write-Warning "llvm-strip not found ($strip) -- internal symbols NOT stripped"
    }
}

if ($Sanitize) {
    $py = Get-Command python -ErrorAction SilentlyContinue
    $san = Join-Path $here "..\tools\sanitize.py"
    if ($py -and (Test-Path $san)) {
        $env:STRIP = if (Test-Path $strip) { $strip } else { "" }
        & $py.Source $san patch $Out --strip
        Write-Host "[+] sanitized identity tokens (tools/sanitize.py)"
    } else {
        Write-Warning "python or tools/sanitize.py missing -- skipped -Sanitize"
    }
}

$readelf = Join-Path $bin "llvm-readelf.exe"
if (Test-Path $readelf) {
    Write-Host "[*] exported dynamic symbols (should be exactly the tlf_* set):"
    & $readelf --dyn-syms $Out | Select-String -Pattern "tlf_"
}
