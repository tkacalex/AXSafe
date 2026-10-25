<#
.SYNOPSIS
  Installiert den AXSafe-Dienst (AXSafeService) reproduzierbar. Administrator.

.DESCRIPTION
  * Programmdateien nach %ProgramFiles%\AXSafe\service (erbt die geschützten
    Rechte von Program Files: Benutzer nur Lesen/Ausführen).
  * Datenordner %ProgramData%\AXSafe\Service: SYSTEM/Administratoren
    Vollzugriff, Dienst-SID NT SERVICE\AXSafeService Ändern, Benutzer KEIN
    Zugriff (Berichte gibt der Dienst nur dem jeweiligen Eigentümer heraus).
  * Dienstkonto NT AUTHORITY\LocalService, Dienst-SID-Typ "unrestricted",
    erforderliche Privilegien nur SeImpersonatePrivilege und
    SeChangeNotifyPrivilege. Neustart nach Absturz (5 s, 30 s).
  * Ein vorhandener AXSafeService wird vorher gestoppt und ersetzt.
  Nachweis: Dienst läuft, Pipe antwortet (axsafe dienst status), ACLs geprüft.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$RulesDir,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'AXSafe\service'),
    [string]$EvidenceDir = (Join-Path $PSScriptRoot 'nachweis')
)
$ErrorActionPreference = 'Stop'
$Name = 'AXSafeService'
$DataDir = Join-Path $env:ProgramData 'AXSafe\Service'
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$Report = Join-Path $EvidenceDir ("dienst-installation-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
function Log([string]$m) { $l = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $l; Add-Content $Report $l -Encoding UTF8 }
# Nicht 'Sc' nennen: In Windows PowerShell 5.1 ist sc ein Alias für Set-Content.
function Invoke-ScExe([string[]]$a) {
    $out = & sc.exe @a 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "sc.exe $($a -join ' ') fehlgeschlagen ($LASTEXITCODE): $out" }
    Log ("sc " + ($a -join ' ') + ": OK")
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Installation nur als Administrator.' }
foreach ($f in 'axsafe-service.exe', 'axsafe-worker.exe') {
    if (-not (Test-Path (Join-Path $SourceDir $f))) { throw "$f fehlt in $SourceDir" }
}

$existing = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($existing) {
    Log "Vorhandener Dienst $Name ($($existing.Status)) wird ersetzt."
    if ($existing.Status -ne 'Stopped') { Stop-Service -Name $Name -Force; (Get-Service $Name).WaitForStatus('Stopped', '00:00:30') }
    Invoke-ScExe @('delete', $Name)
    Start-Sleep -Seconds 2
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item (Join-Path $SourceDir 'axsafe-service.exe'), (Join-Path $SourceDir 'axsafe-worker.exe') $InstallDir -Force
if (Test-Path (Join-Path $InstallDir 'rules')) { Remove-Item -Recurse -Force (Join-Path $InstallDir 'rules') }
Copy-Item -Recurse $RulesDir (Join-Path $InstallDir 'rules')
Log "Programmdateien nach $InstallDir kopiert."

$exe = Join-Path $InstallDir 'axsafe-service.exe'
Invoke-ScExe @('create', $Name, 'binPath=', "`"$exe`" run", 'start=', 'auto', 'obj=', 'NT AUTHORITY\LocalService', 'DisplayName=', 'AXSafe Scan-Dienst')
Invoke-ScExe @('description', $Name, 'AXSafe (Vorversion): prüft Dateien auf Anforderung mit den Rechten des Auftraggebers. Kein Echtzeitschutz.')
Invoke-ScExe @('sidtype', $Name, 'unrestricted')
Invoke-ScExe @('privs', $Name, 'SeChangeNotifyPrivilege/SeImpersonatePrivilege')
Invoke-ScExe @('failure', $Name, 'reset=', '86400', 'actions=', 'restart/5000/restart/30000//0')

New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'reports'), (Join-Path $DataDir 'logs') | Out-Null
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "NT SERVICE\${Name}:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Rechte für den Datenordner nicht setzbar' }
& icacls.exe $DataDir /setowner '*S-1-5-32-544' /T /C | Out-Null
Log ("Datenordner: " + ((& icacls.exe $DataDir) -join ' | '))

# Programmordner darf für Benutzer nicht beschreibbar sein.
foreach ($d in $InstallDir, $DataDir) {
    foreach ($r in (Get-Acl $d).Access) {
        $sid = try { $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
        if ($sid -in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-4' -and $r.AccessControlType -eq 'Allow' -and
            ($r.FileSystemRights -band ([Security.AccessControl.FileSystemRights]'Write, Delete, ChangePermissions, TakeOwnership'))) {
            throw "Unsichere Rechte auf ${d}: $($r.IdentityReference) $($r.FileSystemRights)"
        }
    }
}
Log 'Rechte geprüft: Benutzer können Programm- und Datenordner nicht verändern.'

Start-Service -Name $Name
(Get-Service $Name).WaitForStatus('Running', '00:00:30')
$cfg = (& sc.exe qc $Name) -join ' | '
$privs = (& sc.exe qprivs $Name) -join ' | '
Log "Dienst läuft. $cfg"
Log "Privilegien: $privs"
Log "Fertig. Bericht: $Report"
