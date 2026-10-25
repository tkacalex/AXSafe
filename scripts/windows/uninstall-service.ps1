<#
.SYNOPSIS
  Entfernt den AXSafe-Dienst. Nur als Administrator (Dienststeuerung).
.PARAMETER RemoveData
  Auch Berichte und Protokolle in %ProgramData%\AXSafe\Service löschen.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AXSafe\service'),
    [switch]$RemoveData
)
$ErrorActionPreference = 'Stop'
$Name = 'AXSafeService'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Entfernen nur als Administrator.' }
$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $Name -Force; (Get-Service $Name).WaitForStatus('Stopped', '00:00:30') }
    & sc.exe delete $Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc delete fehlgeschlagen ($LASTEXITCODE)" }
    Write-Host "Dienst $Name entfernt."
} else {
    Write-Host "Dienst $Name nicht vorhanden."
}
if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir; Write-Host "Programmordner entfernt: $InstallDir" }
if ($RemoveData) {
    $d = Join-Path $env:ProgramData 'AXSafe\Service'
    if (Test-Path $d) { Remove-Item -Recurse -Force $d; Write-Host "Daten entfernt: $d" }
} else {
    Write-Host 'Berichte und Protokolle bleiben erhalten (-RemoveData zum Löschen).'
}
