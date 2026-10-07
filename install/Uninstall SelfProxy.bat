@echo off
REM SelfProxy — Windows uninstaller (double-click friendly)
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall-windows.ps1" %*
echo.
pause
exit /b %ERRORLEVEL%
