@echo off
REM SelfProxy — Windows installer (double-click friendly)
setlocal
cd /d "%~dp0"
echo Installing SelfProxy...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-windows.ps1" %*
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" (
  echo Install FAILED ^(exit %RC%^). See messages above.
) else (
  echo Install finished.
)
pause
exit /b %RC%
