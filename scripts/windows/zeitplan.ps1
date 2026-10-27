<#
.SYNOPSIS
  Geplante AXSafe-Prüfung für den angemeldeten Benutzer einrichten, anzeigen
  oder entfernen (AXS-026). Keine Administratorrechte nötig.

.DESCRIPTION
  Legt in der Aufgabenplanung die Aufgabe \AXSafe\Pruefung-<Art> an. Sie läuft
  mit den Rechten des Benutzers (nur wenn er angemeldet ist), startet die CLI
  minimiert und schreibt jeden Bericht als neue Datei in den Berichtsordner
  der Oberfläche (%LOCALAPPDATA%\AXSafe\reports). Der Bericht nennt
  „Zeitplan“ als Auslöser. Kein Echtzeitschutz; verpasste Läufe werden beim
  nächsten Start nachgeholt (StartWhenAvailable).

.EXAMPLE
  zeitplan.ps1 -Art schnell -Uhrzeit 12:30            # täglich
  zeitplan.ps1 -Art voll -Uhrzeit 20:00 -Wochentag Sunday
  zeitplan.ps1 -Art schnell -Entfernen
  zeitplan.ps1 -Anzeigen
#>
[CmdletBinding()]
param(
    [ValidateSet('schnell', 'voll', 'wechsel', 'benutzer')][string]$Art = 'schnell',
    [string]$Uhrzeit = '12:30',
    [ValidateSet('', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')][string]$Wochentag = '',
    [string[]]$Pfad = @(),
    [string]$Cli,
    [string]$Berichtsordner = (Join-Path $env:LOCALAPPDATA 'AXSafe\reports'),
    [switch]$MitClamav,
    [switch]$Entfernen,
    [switch]$Anzeigen
)
$ErrorActionPreference = 'Stop'
$Ordner = '\AXSafe\'
$Name = "Pruefung-$Art"

if ($Anzeigen) {
    Get-ScheduledTask -TaskPath $Ordner -ErrorAction SilentlyContinue |
        ForEach-Object {
            $i = $_ | Get-ScheduledTaskInfo
            '{0}{1}  Zustand={2}  Nächster Lauf={3}  Letzter Lauf={4} (Ergebnis {5})' -f $_.TaskPath, $_.TaskName, $_.State, $i.NextRunTime, $i.LastRunTime, $i.LastTaskResult
        }
    exit 0
}
if ($Entfernen) {
    if (Get-ScheduledTask -TaskPath $Ordner -TaskName $Name -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskPath $Ordner -TaskName $Name -Confirm:$false
    }
    if (Get-ScheduledTask -TaskPath $Ordner -TaskName $Name -ErrorAction SilentlyContinue) { throw "Aufgabe nicht entfernt" }
    Write-Host "Geplante Prüfung $Name entfernt."
    exit 0
}

if (-not $Cli) { $Cli = Join-Path $PSScriptRoot '..\..\cli\axsafe.exe' }
$Cli = [IO.Path]::GetFullPath($Cli)
if (-not (Test-Path -LiteralPath $Cli -PathType Leaf)) { throw "axsafe.exe nicht gefunden: $Cli" }
if ($Art -eq 'benutzer' -and $Pfad.Count -eq 0) { throw "-Art benutzer braucht -Pfad" }
# cmd.exe wertet " & | < > ^ % aus: solche Pfade werden abgelehnt statt verfälscht.
foreach ($p in @($Pfad) + @($Berichtsordner, $Cli)) { if ($p -match '["&|<>^%]') { throw "Pfad mit Sonderzeichen nicht unterstützt: $p" } }
New-Item -ItemType Directory -Force -Path $Berichtsordner | Out-Null

$argsCli = @('scan', '--art', $Art, '--ausloeser', 'zeitplan', '--json-ordner', "`"$Berichtsordner`"")
if (-not $MitClamav) { $argsCli += '--no-clamav' }
if ($Art -eq 'benutzer') { $argsCli += '--'; $argsCli += ($Pfad | ForEach-Object { "`"$_`"" }) }
# Minimiert starten: Die CLI ist ein Konsolenprogramm.
$cmdArgs = '/c start "AXSafe geplante Prüfung" /min "{0}" {1}' -f $Cli, ($argsCli -join ' ')
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $cmdArgs
$zeit = [datetime]::ParseExact($Uhrzeit, 'HH:mm', [Globalization.CultureInfo]::InvariantCulture)
$trigger = if ($Wochentag) { New-ScheduledTaskTrigger -Weekly -DaysOfWeek $Wochentag -At $zeit } else { New-ScheduledTaskTrigger -Daily -At $zeit }
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 12) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskPath $Ordner -TaskName $Name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null

$t = Get-ScheduledTask -TaskPath $Ordner -TaskName $Name
if ($t.Principal.RunLevel -ne 'Limited') { throw "Aufgabe hätte erhöhte Rechte" }
Write-Host ("Geplante Prüfung eingerichtet: {0}{1} – {2} um {3}{4}" -f $Ordner, $Name, $Art, $Uhrzeit, $(if ($Wochentag) { " ($Wochentag)" } else { ' (täglich)' }))
Write-Host "Berichte: $Berichtsordner"
