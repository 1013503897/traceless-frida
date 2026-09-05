# One-shot end-to-end test on a USB device: build, push, run the frida harness.
#
#   powershell test/run_test.ps1                 # legacy (anon-RX clone) mode
#   powershell test/run_test.ps1 -Ghost          # ghost (VMA-less clone) mode
#   powershell test/run_test.ps1 -Serial <adb-serial>
#
# Prereq: shpte loaded + bridge armed on the device; a frida-server running on it that
# matches the host frida major; adb + python(frida) on PATH.
param(
    [switch]$Ghost,
    [string]$Serial = "",
    [string]$Adb = "adb"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$sel = if ($Serial) { @("-s", $Serial) } else { @() }

Write-Host "[*] building native backend + test target ..."
& powershell (Join-Path $root "native\build.ps1")
& powershell (Join-Path $root "test\build_target.ps1")

Write-Host "[*] pushing to /data/local/tmp ..."
& $Adb @sel push (Join-Path $root "native\libtracelessfrida.so") /data/local/tmp/libtracelessfrida.so
& $Adb @sel push (Join-Path $root "test\tlf_target") /data/local/tmp/tlf_target
& $Adb @sel shell 'chmod 755 /data/local/tmp/tlf_target /data/local/tmp/libtracelessfrida.so'

Write-Host "[*] running frida harness ..."
$py = Join-Path $root "test\run.py"
if ($Ghost) { python $py --ghost } else { python $py }
