@echo off
rem AXSafe: ClamAV einrichten. Fragt einmal nach Administratorrechten (UAC).
rem Funktioniert im Paket (Programm\scripts\windows) und im Repository
rem (AXSafe\scripts\windows neben dem Ordner Programm).
setlocal
set "HERE=%~dp0"
set "CLI=%HERE%..\..\cli\axsafe.exe"
set "EVID=%HERE%..\..\..\nachweise"
if not exist "%CLI%" set "CLI=%HERE%..\..\..\Programm\cli\axsafe.exe"
if not exist "%CLI%" (
  echo AXSafe-CLI nicht gefunden. ClamAV wird trotzdem eingerichtet; Nachweis e^) entfaellt.
  set "CLI="
)
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%HERE%setup-clamav.ps1\"','-EvidenceDir','\"%EVID%\"','-AxsafeCli','\"%CLI%\"'"
echo.
echo Fertig. Bericht im Ordner: %EVID%
pause
