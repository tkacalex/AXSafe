@echo off
rem AXSafe: Hintergrunddienst (AXSafeService) installieren oder ersetzen.
rem Fragt einmal nach Administratorrechten (UAC). Deinstallation:
rem   powershell -ExecutionPolicy Bypass -File uninstall-service.ps1
setlocal
set "HERE=%~dp0"
set "SRC=%HERE%..\..\cli"
set "EVID=%HERE%..\..\..\nachweise"
if not exist "%SRC%\axsafe-service.exe" set "SRC=%HERE%..\..\..\Programm\cli"
if not exist "%SRC%\axsafe-service.exe" (
  echo axsafe-service.exe nicht gefunden. Bitte zuerst das aktuelle AXSafe-Paket entpacken.
  pause
  exit /b 1
)
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%HERE%install-service.ps1\"','-SourceDir','\"%SRC%\"','-RulesDir','\"%SRC%\rules\"','-EvidenceDir','\"%EVID%\"'"
echo.
echo Fertig. Bericht im Ordner: %EVID%
pause
