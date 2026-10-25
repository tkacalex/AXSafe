@echo off
rem AXSafe: automatische Tests auf diesem Rechner (Windows 10 LTSC). Keine
rem Administratorrechte, keine Schadsoftware, keine EICAR-Datei auf der Platte.
rem Ergebnis: Desktop\AXSafe\nachweise\ltsc-tests-*.txt
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-ltsc-tests.ps1"
echo.
pause
