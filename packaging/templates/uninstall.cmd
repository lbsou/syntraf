@echo off
rem uninstall.ps1 sans dependre de la strategie d execution PowerShell (un zip telecharge bloque les scripts)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1" %*
exit /b %errorlevel%
