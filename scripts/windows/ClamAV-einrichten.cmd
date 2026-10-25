@echo off
rem AXSafe: ClamAV einrichten. Fragt einmal nach Administratorrechten (UAC).
rem Nachweisbericht: Ordner "nachweise" neben dem AXSafe-Repository.
setlocal
set "HERE=%~dp0"
set "EVID=%HERE%..\..\..\nachweise"
set "CLI=%HERE%..\..\..\Programm\cli\axsafe.exe"
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%HERE%setup-clamav.ps1\"','-EvidenceDir','\"%EVID%\"','-AxsafeCli','\"%CLI%\"'"
echo.
echo Fertig. Bericht im Ordner: %EVID%
pause
