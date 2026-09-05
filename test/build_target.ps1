# Build the tlf_target test binary (arm64). -rdynamic exports secret()/neighbour()
# into .dynsym so the Frida test script can resolve them by name.
param([int]$Api = 29, [string]$Out = "")
$ErrorActionPreference = "Stop"

$ndk = if ($env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME } else { "C:\Users\Administrator\AppData\Local\Android\Sdk\ndk\26.1.10909125" }
$clang = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe"
if (-not (Test-Path $clang)) { throw "clang not found: $clang (set ANDROID_NDK_HOME)" }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Out) { $Out = Join-Path $here "tlf_target" }
$src = Join-Path $here "target.c"

& $clang "--target=aarch64-linux-android$Api" "-O0" "-fno-inline" "-rdynamic" "-pie" $src -o $Out
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
Write-Host "[+] built: $Out"
