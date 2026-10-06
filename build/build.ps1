# Сборка AnyRoute: три бинаря в dist\ и (если есть makensis) установщик.
#   powershell -ExecutionPolicy Bypass -File build\build.ps1 -Version 0.1.0
param(
  [string]$Version = "0.0.0-dev",
  [switch]$NoInstaller
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force -Path dist | Out-Null

$env:CGO_ENABLED = "0"
$ld = "-s -w -X main.version=$Version"

Write-Host "==> AnyRoute.exe (интерфейс)"
go build -trimpath -tags "desktop,production" -ldflags "$ld -H=windowsgui" -o dist\AnyRoute.exe .\cmd\anyroute
if ($LASTEXITCODE -ne 0) { throw "сборка интерфейса" }

Write-Host "==> anyroute-service.exe (служба)"
go build -trimpath -tags "with_gvisor" -ldflags "$ld" -o dist\anyroute-service.exe .\cmd\anyroute-service
if ($LASTEXITCODE -ne 0) { throw "сборка службы" }

Write-Host "==> anyroute-cli.exe (диагностика)"
go build -trimpath -tags "with_gvisor" -ldflags "$ld" -o dist\anyroute-cli.exe .\cmd\anyroute-cli
if ($LASTEXITCODE -ne 0) { throw "сборка cli" }

if ($NoInstaller) { return }
$makensis = (Get-Command makensis -ErrorAction SilentlyContinue).Source
if (-not $makensis) {
  foreach ($p in @("${env:ProgramFiles(x86)}\NSIS\makensis.exe", "$env:ProgramFiles\NSIS\makensis.exe")) {
    if (Test-Path $p) { $makensis = $p; break }
  }
}
if (-not $makensis) { Write-Warning "makensis не найден — установщик не собран"; return }
$nsisVersion = ($Version -replace '-.*$', '')
Write-Host "==> установщик $Version"
& $makensis /V2 "/DVERSION=$nsisVersion" "/DSRC=$root" build\windows\installer.nsi
if ($LASTEXITCODE -ne 0) { throw "сборка установщика" }
Get-ChildItem dist | Format-Table Name, Length
