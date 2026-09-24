# builds ceasta, runs the tests, and makes the release files in dist\:
#   ceasta-<version>-windows-x64.zip   portable, unzip and run
#   ceasta-<version>-setup.exe         installer (needs Inno Setup 6: winget install JRSoftware.InnoSetup)
#
# usage, from the repo root with cmake + visual studio installed:
#   powershell -ExecutionPolicy Bypass -File installer\package.ps1 [-Version 0.6.0] [-SkipBuild] [-SkipTests]
param(
    [string]$Version = "",
    [switch]$SkipBuild,
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Invoke-Checked([string]$exe, [string[]]$argv) {
    & $exe @argv
    if ($LASTEXITCODE -ne 0) { throw "$exe $($argv -join ' ') failed with exit code $LASTEXITCODE" }
}

if (-not $Version) {
    $m = Select-String -Path "src\version.h" -Pattern '#define CEASTA_VERSION "([^"]+)"'
    $Version = $m.Matches[0].Groups[1].Value
}
Write-Host "== packaging ceasta $Version"

if (-not $SkipBuild) {
    Invoke-Checked cmake @("-S", ".", "-B", "build")
    Invoke-Checked cmake @("--build", "build", "--config", "Release", "--parallel")
    if (-not $SkipTests) {
        Invoke-Checked ctest @("--test-dir", "build", "-C", "Release", "--output-on-failure")
    }
}

$dist = Join-Path $root "dist"
$stage = Join-Path $dist "ceasta"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $dist | Out-Null
Invoke-Checked cmake @("--install", "build", "--config", "Release", "--prefix", $stage)
foreach ($f in @("ceasta.exe", "ceasta-cli.exe", "plugins\hello.lua", "THIRD_PARTY_NOTICES.md")) {
    if (-not (Test-Path (Join-Path $stage $f))) { throw "missing $f in $stage" }
}

# portable zip: a single "ceasta" folder inside
$zip = Join-Path $dist "ceasta-$Version-windows-x64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $stage -DestinationPath $zip
Write-Host "== portable zip: $zip"

# installer
$iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    $iscc = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $iscc) {
    throw "Inno Setup 6 wasn't found. Install it (winget install JRSoftware.InnoSetup) or use the zip."
}
Invoke-Checked $iscc @("/Q", "/DAppVersion=$Version", "/DSourceDir=$stage", "/DOutputDir=$dist", "installer\ceasta.iss")
$setup = Join-Path $dist "ceasta-$Version-setup.exe"
if (-not (Test-Path $setup)) { throw "the installer wasn't created" }
Write-Host "== installer: $setup"

Get-FileHash -Algorithm SHA256 $zip, $setup | ForEach-Object { "{0}  {1}" -f $_.Hash.ToLower(), (Split-Path -Leaf $_.Path) }
