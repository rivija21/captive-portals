@echo off
rem Double-click to check the connection and log in to UoM Wi-Fi right away.
set "SCRIPT=%LOCALAPPDATA%\UoMAutoLogin\uom_autologin.ps1"
if not exist "%SCRIPT%" (
  echo Auto-login is not set up yet. Double-click "Set Up.bat" first.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Now
echo.
echo Full history: %LOCALAPPDATA%\UoMAutoLogin\Logs\autologin.log
pause
