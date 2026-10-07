# SelfProxy — Windows installer
#
# Usage (from a normal PowerShell window, no admin needed):
#   .\install-windows.ps1                  # install to %LOCALAPPDATA%\Programs\SelfProxy
#   .\install-windows.ps1 -InPlace         # run from this folder, no copying
#   .\install-windows.ps1 -DryRun          # show what would happen, change nothing
#   .\install-windows.ps1 -MigrateProfiles # move browser_profiles from a legacy install
#   .\install-windows.ps1 -LegacyDir "D:\old\win-http-proxy"
#
# Uninstall: .\uninstall-windows.ps1

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\SelfProxy'),
    [string]$LegacyDir  = (Join-Path $env:USERPROFILE 'win-http-proxy'),
    [switch]$InPlace,
    [switch]$MigrateProfiles,
    [switch]$NoShortcuts,
    [switch]$NoRegister,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$AppName    = 'SelfProxy'
$SourceRoot = Split-Path -Parent $PSScriptRoot          # <app>/install/.. = <app>
if (-not (Test-Path (Join-Path $SourceRoot 'proxy_tool.py'))) {
    throw "Не найден proxy_tool.py рядом с $SourceRoot — installer должен лежать в <app>\install\"
}

function Say  { param([string]$m) Write-Host $m }
function Step { param([string]$m) Write-Host "`n== $m" -ForegroundColor Cyan }
function Ok   { param([string]$m) Write-Host "   OK  $m" -ForegroundColor Green }
function Warn { param([string]$m) Write-Host "   !   $m" -ForegroundColor Yellow }

function Invoke-Or-Show {
    param([string]$What, [scriptblock]$Action)
    if ($DryRun) { Say "   [dry-run] $What" } else { & $Action }
}

# --- 1. Python ---------------------------------------------------------------
function Find-Python {
    # Returns @{ Gui = pythonw-ish exe; Console = console exe }
    $pairs = @()
    $pyw = Get-Command pyw.exe -ErrorAction SilentlyContinue
    $py  = Get-Command py.exe  -ErrorAction SilentlyContinue
    if ($pyw -and $py) { $pairs += @{ Gui = $pyw.Source; Console = $py.Source; Args = @('-3') } }

    foreach ($name in @('pythonw.exe', 'python.exe')) {
        $c = Get-Command $name -ErrorAction SilentlyContinue
        if ($c) {
            $console = $c.Source -replace 'pythonw\.exe$', 'python.exe'
            $pairs += @{ Gui = $c.Source; Console = $console; Args = @() }
        }
    }
    # Standard per-user / machine installs (py launcher missing case)
    foreach ($root in @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python'),
        'C:\Program Files\Python*',
        'C:\Python*'
    )) {
        Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $pw = Join-Path $_.FullName 'pythonw.exe'
            $pc = Join-Path $_.FullName 'python.exe'
            if ((Test-Path $pw) -and (Test-Path $pc)) {
                $pairs += @{ Gui = $pw; Console = $pc; Args = @() }
            }
        }
    }

    foreach ($p in $pairs) {
        if (-not (Test-Path $p.Console)) { continue }
        try {
            & $p.Console @($p.Args + @('-c', 'import tkinter, sys; sys.exit(0)')) 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { return $p }
        } catch { }
    }
    return $null
}

Step "SelfProxy installer"
Say "   source : $SourceRoot"
Say "   target : $(if ($InPlace) { $SourceRoot } else { $InstallDir })"
if ($DryRun) { Warn "DRY RUN — ничего не меняется" }

$python = Find-Python
if (-not $python) {
    throw @"
Python 3 с tkinter не найден.
Поставь Python 3.12+ с https://www.python.org/downloads/ (галочка "tcl/tk and IDLE")
и запусти installer заново.
"@
}
Ok "Python: $($python.Gui) $($python.Args -join ' ')"

# --- 2. Copy files -----------------------------------------------------------
$AppRoot = if ($InPlace) { $SourceRoot } else { $InstallDir }
$payload = @('start.pyw', 'proxy_tool.py', 'README.md')
$payloadDirs = @('assets')

Step "Установка в $AppRoot"
if (-not $InPlace) {
    Invoke-Or-Show "mkdir $AppRoot" { New-Item -ItemType Directory -Path $AppRoot -Force | Out-Null }
    foreach ($f in $payload) {
        $src = Join-Path $SourceRoot $f
        if (Test-Path $src) {
            Invoke-Or-Show "copy $f" { Copy-Item -LiteralPath $src -Destination (Join-Path $AppRoot $f) -Force }
        }
    }
    foreach ($d in $payloadDirs) {
        $src = Join-Path $SourceRoot $d
        if (Test-Path $src) {
            Invoke-Or-Show "copy $d\" {
                $dst = Join-Path $AppRoot $d
                New-Item -ItemType Directory -Path $dst -Force | Out-Null
                Copy-Item -Path (Join-Path $src '*') -Destination $dst -Recurse -Force
            }
        }
    }
    # uninstaller + installer travel with the app so Uninstall works after copying
    Invoke-Or-Show "copy install\" {
        $dst = Join-Path $AppRoot 'install'
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        Copy-Item -Path (Join-Path $SourceRoot 'install\*') -Destination $dst -Recurse -Force
    }
} else {
    Warn "in-place: файлы не копируются, приложение запускается из этой папки"
}

# --- 3. Config + profiles migration -----------------------------------------
$cfgDst = Join-Path $AppRoot 'proxy_config.json'
$legacyCfg = Join-Path $LegacyDir 'proxy_config.json'
if ((Test-Path $legacyCfg) -and -not (Test-Path $cfgDst)) {
    Invoke-Or-Show "migrate proxy_config.json from $LegacyDir" {
        Copy-Item -LiteralPath $legacyCfg -Destination $cfgDst -Force
    }
    Ok "перенесены сохранённые подключения (proxy_config.json)"
} elseif (Test-Path $cfgDst) {
    Ok "конфиг на месте: $cfgDst"
}

$profDst = Join-Path $AppRoot 'browser_profiles'
$profSrc = Join-Path $LegacyDir 'browser_profiles'
if ($MigrateProfiles) {
    if ((Test-Path $profSrc) -and -not (Test-Path $profDst)) {
        Invoke-Or-Show "move browser_profiles from $LegacyDir" {
            Move-Item -LiteralPath $profSrc -Destination $profDst -Force
        }
        Ok "профили браузеров перенесены"
    } elseif (Test-Path $profDst) {
        Ok "профили браузеров уже на месте"
    } else {
        Warn "нечего переносить: $profSrc не найден"
    }
}

# --- 4. Entry point + icon ---------------------------------------------------
$entry = Join-Path $AppRoot 'start.pyw'
if (-not (Test-Path $entry) -and -not $DryRun) { throw "Не найден вход: $entry" }

$ico = Join-Path $AppRoot 'assets\selfproxy.ico'
if (-not (Test-Path $ico)) { $ico = Join-Path $AppRoot 'assets\proxy.ico' }
if (-not (Test-Path $ico)) { $ico = $python.Gui }

$argList = @($python.Args + @("`"$entry`"")) -join ' '

# --- 5. Shortcuts ------------------------------------------------------------
function New-Shortcut {
    param([string]$Path, [string]$Target, [string]$Arguments, [string]$WorkDir, [string]$Icon, [string]$Description)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($Path)
    $lnk.TargetPath       = $Target
    $lnk.Arguments        = $Arguments
    $lnk.WorkingDirectory = $WorkDir
    $lnk.IconLocation     = "$Icon,0"
    $lnk.Description      = $Description
    $lnk.WindowStyle      = 1
    $lnk.Save()
    Ok "ярлык: $Path"
}

if (-not $NoShortcuts) {
    Step "Ярлыки"
    $targets = @(
        @{ Path = (Join-Path $AppRoot 'Start SelfProxy.lnk') },
        @{ Path = (Join-Path ([Environment]::GetFolderPath('Desktop')) "$AppName.lnk") },
        @{ Path = (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\$AppName.lnk") }
    )
    foreach ($t in $targets) {
        Invoke-Or-Show "shortcut $($t.Path)" {
            New-Shortcut -Path $t.Path -Target $python.Gui -Arguments $argList `
                -WorkDir $AppRoot -Icon $ico -Description $AppName
        }
    }
}

# --- 6. Uninstall registration ----------------------------------------------
if ($NoRegister) {
    Step "Регистрация в «Установка и удаление программ»"
    Warn "пропущено (-NoRegister)"
} else {
Step "Регистрация в «Установка и удаление программ»"
$uninst = Join-Path $AppRoot 'install\uninstall-windows.ps1'
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppName"
Invoke-Or-Show "registry $regPath" {
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name 'DisplayName'     -Value $AppName
    Set-ItemProperty -Path $regPath -Name 'Publisher'       -Value 'SelfProxy'
    Set-ItemProperty -Path $regPath -Name 'DisplayVersion'  -Value '1.0'
    Set-ItemProperty -Path $regPath -Name 'InstallLocation' -Value $AppRoot
    Set-ItemProperty -Path $regPath -Name 'DisplayIcon'     -Value $ico
    Set-ItemProperty -Path $regPath -Name 'NoModify'        -Value 1 -Type DWord
    Set-ItemProperty -Path $regPath -Name 'NoRepair'        -Value 1 -Type DWord
    if (Test-Path $uninst) {
        Set-ItemProperty -Path $regPath -Name 'UninstallString' -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$uninst`""
    }
}
if (-not (Test-Path $uninst)) { Warn "uninstall-windows.ps1 не найден в $AppRoot\install" }
}

$marker = Join-Path $AppRoot '.selfproxy_install.json'
Invoke-Or-Show "marker $marker" {
    @{
        appName     = $AppName
        appRoot     = $AppRoot
        sourceRoot  = $SourceRoot
        python      = $python.Gui
        pythonArgs  = $python.Args
        mode        = $(if ($InPlace) { 'inplace' } else { 'copy' })
        installedAt = (Get-Date).ToString('o')
        version     = '1.0'
    } | ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding UTF8
}

Step "Готово"
Say "   запуск : Start SelfProxy.lnk, ярлык на рабочем столе или из меню Пуск"
Say "   удалить: .\uninstall-windows.ps1"
if ($DryRun) { Warn "это был dry-run — ничего не установлено" }
