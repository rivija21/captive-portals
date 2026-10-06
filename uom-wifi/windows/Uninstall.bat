@echo off
rem Double-click to turn off automatic UoM Wi-Fi login and delete the saved password.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Uninstall
echo.
pause
