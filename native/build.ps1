# Build libtracelessfrida.so (arm64) with the NDK clang toolchain.
#
# This is an ORDINARY userspace Android shared library (unlike the shpte KPM, which
# is a freestanding -O0 relocatable ELF -- see stealth-core/kpm/build.ps1). Normal
# -O2 is fine here; it links libc + liblog and is dlopen'd into the target by Frida.
#
# Usage: powershell native/build.ps1 [-Api 29] [-Out ..\libtracelessfrida.so]
param(
    [int]$Api = 29,
    [string]$Out = ""
)
$ErrorActionPreference = "Stop"

# NDK: honour ANDROID_NDK_HOME, fall back to the local dev default (same as stealth-core).
$ndk = if ($env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME } else { "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125" }
$bin = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$clang = Join-Path $bin "clang.exe"
if (-not (Test-Path $clang)) { throw "clang not found: $clang (set ANDROID_NDK_HOME)" }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Out) { $Out = Join-Path $here "libtracelessfrida.so" }

$srcs = @("tlf_api.c", "kpmhook.c", "dbi.c") | ForEach-Object { Join-Path $here $_ }

$cflags = @(
    "--target=aarch64-linux-android$Api",
    "-fPIC",
    "-O2",
    "-fvisibility=hidden",           # only the tlf_* wrappers are exported
    "-Wall", "-Wno-unused-function", "-Wno-unused-parameter",
    "-shared",
    "-Wl,-soname,libtracelessfrida.so",
    "-Wl,--no-undefined"
)

Write-Host "[*] clang : $clang"
Write-Host "[*] target: aarch64-linux-android$Api"
Write-Host "[*] out   : $Out"
& $clang @cflags @srcs -o $Out -llog
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

Write-Host "[+] built: $Out"
$readelf = Join-Path $bin "llvm-readelf.exe"
if (Test-Path $readelf) {
    Write-Host "[*] exported dynamic symbols (should be exactly the tlf_* set):"
    & $readelf --dyn-syms $Out | Select-String -Pattern "tlf_"
}
