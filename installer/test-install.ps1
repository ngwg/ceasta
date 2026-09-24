# installs the setup exe silently for the current user, checks the result, then uninstalls
# and checks everything is gone. used by ci, safe to run by hand (uses a temp folder).
#   powershell -ExecutionPolicy Bypass -File installer\test-install.ps1 [-Setup dist\ceasta-0.6.0-setup.exe]
param([string]$Setup = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not $Setup) {
    $Setup = (Get-ChildItem dist\ceasta-*-setup.exe | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $Setup -or -not (Test-Path $Setup)) { throw "no installer found, run installer\package.ps1 first" }
$dir = Join-Path $env:TEMP "ceasta-install-test"
if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
$failures = 0
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "ok   $what" } else { Write-Host "FAIL $what"; $script:failures++ }
}

Write-Host "== installing $Setup into $dir"
$p = Start-Process -FilePath $Setup -Wait -PassThru -ArgumentList @(
    "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CURRENTUSER", "/DIR=`"$dir`"", "/TASKS=`"contextmenu,addtopath`"",
    "/LOG=`"$env:TEMP\ceasta-install.log`"")
Check ($p.ExitCode -eq 0) "installer exit code $($p.ExitCode)"
foreach ($f in @("ceasta.exe", "ceasta-cli.exe", "plugins\hello.lua", "plugins\README.md", "README.md", "THIRD_PARTY_NOTICES.md", "unins000.exe")) {
    Check (Test-Path (Join-Path $dir $f)) "installed $f"
}
$cmd = (Get-ItemProperty -Path "HKCU:\Software\Classes\SystemFileAssociations\.exe\shell\ceasta\command" -ErrorAction SilentlyContinue).'(default)'
Check ($cmd -and $cmd.Contains("ceasta.exe")) "right-click entry for .exe files: $cmd"
$userPath = (Get-ItemProperty -Path "HKCU:\Environment").Path
Check ($userPath -and $userPath.ToLower().Contains($dir.ToLower())) "install folder added to the user PATH"
$startMenu = Join-Path ([Environment]::GetFolderPath("Programs")) "ceasta.lnk"
Check (Test-Path $startMenu) "start menu shortcut"

# the installed cli runs on its own (static runtime, no extra dlls needed)
$out = & (Join-Path $dir "ceasta-cli.exe") info tests\fixtures\sample64.exe
Check ($LASTEXITCODE -eq 0 -and ($out -join "`n").Contains("pe x64")) "installed ceasta-cli analyzes a file"

Write-Host "== uninstalling"
$p = Start-Process -FilePath (Join-Path $dir "unins000.exe") -Wait -PassThru -ArgumentList @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART")
# the uninstaller finishes from a copy in temp, wait until the files are gone
for ($i = 0; $i -lt 120 -and (Test-Path (Join-Path $dir "ceasta.exe")); $i++) { Start-Sleep -Milliseconds 500 }
Check (-not (Test-Path (Join-Path $dir "ceasta.exe"))) "program files removed"
Check (-not (Test-Path "HKCU:\Software\Classes\SystemFileAssociations\.exe\shell\ceasta")) "right-click entry removed"
$userPath = (Get-ItemProperty -Path "HKCU:\Environment").Path
Check (-not ($userPath -and $userPath.ToLower().Contains($dir.ToLower()))) "install folder removed from PATH"
Check (-not (Test-Path $startMenu)) "start menu shortcut removed"

if ($failures -gt 0) { Write-Host "installer test FAILED ($failures)"; exit 1 }
Write-Host "installer test passed"
