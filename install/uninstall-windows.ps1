# SelfProxy — Windows uninstaller
#
# Usage:
#   .\uninstall-windows.ps1            # remove shortcuts + registry, keep config/logs
#   .\uninstall-windows.ps1 -Purge     # also delete the whole app folder
#   .\uninstall-windows.ps1 -DryRun

[CmdletBinding()]
param(
    [switch]$Purge,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$AppName = 'SelfProxy'

$scriptDir = $PSScriptRoot
$AppRoot = Split-Path -Parent $scriptDir                     # <app>/install/.. = <app>
$marker = Join-Path $AppRoot '.selfproxy_install.json'
if (Test-Path $marker) {
    try { $AppRoot = (Get-Content $marker -Raw | ConvertFrom-Json).appRoot } catch { }
}

function Say  { param([string]$m) Write-Host $m }
function Step { param([string]$m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Ok   { param([string]$m) Write-Host "   OK  $m" -ForegroundColor Green }
function Warn { param([string]$m) Write-Host "   !   $m" -ForegroundColor Yellow }
function Run  { param([string]$What, [scriptblock]$Action)
    if ($DryRun) { Say "   [dry-run] $What" } else { & $Action; }
}

Step "Удаление $AppName"
Say "   app root: $AppRoot"
if ($DryRun) { Warn "DRY RUN — ничего не удаляется" }

Step "Ярлыки"
foreach ($lnk in @(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk"),
    (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$AppName.lnk"),
    (Join-Path $AppRoot 'Start SelfProxy.lnk')
)) {
    if (Test-Path $lnk) { Run "rm $lnk" { Remove-Item -LiteralPath $lnk -Force }; Ok "удалён: $lnk" }
}

Step "Запись в реестре"
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppName"
if (Test-Path $regPath) { Run "rm $regPath" { Remove-Item -Path $regPath -Recurse -Force }; Ok "удалена" }

if ($Purge) {
    Step "Файлы приложения"
    $keep = @('proxy_config.json')       # настройки подключений не трогаем без спроса
    Run "rm -r $AppRoot (кроме $($keep -join ', '))" {
        Get-ChildItem -LiteralPath $AppRoot -Force | Where-Object { $keep -notcontains $_.Name } |
            Remove-Item -Recurse -Force
    }
    Ok "папка очищена: $AppRoot"
} else {
    Step "Файлы приложения"
    Warn "папка оставлена на месте (запусти с -Purge, чтобы удалить): $AppRoot"
}

Step "Готово"
