<#
.SYNOPSIS
  Systemtest Scanarten (AXS-026) auf Windows: Ziele der Schnell-/Voll-/
  Wechseldatenträgerprüfung, Kontextmenü einrichten/entfernen, geplante
  Prüfung einrichten, auslösen, Bericht prüfen, entfernen.
  Nur harmlose, zur Laufzeit erzeugte Dateien.
#>
param(
    [Parameter(Mandatory = $true)][string]$Dist,
    [string]$EvidenceDir = (Join-Path $PWD 'scanarten-nachweis')
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $EvidenceDir | Out-Null
$Log = Join-Path $EvidenceDir 'scanarten-e2e.txt'
$pass = 0; $fail = 0
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $line = '{0} {1} {2}' -f $(if ($ok) { 'OK  ' } else { 'FEHL' }), $name, $detail
    Write-Host $line; Add-Content $Log $line -Encoding UTF8
    if ($ok) { $script:pass++ } else { $script:fail++ }
}
$Cli = (Resolve-Path "$Dist\cli\axsafe.exe").Path
$Ui = (Resolve-Path "$Dist\AXSafe.exe").Path
$Scripts = (Resolve-Path "$Dist\scripts\windows").Path

# 1) Ziele der Scanarten
$q = & $Cli ziele --art schnell --json | ConvertFrom-Json
Check 'Schnellprüfung: Temp-Ordner unter den Zielen' ([bool]($q.roots | Where-Object { $_ -ieq ([IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')) -or $_ -ieq $env:TEMP })) ($q.roots -join '; ')
Check 'Schnellprüfung: nennt, was sie nicht abdeckt' ($q.note -match 'Nicht geprüft') $q.note
$f = & $Cli ziele --art voll --json | ConvertFrom-Json
Check 'Vollprüfung: Systemlaufwerk unter den Zielen' ([bool]($f.roots -contains "$env:SystemDrive\")) ($f.roots -join '; ')
$w = & $Cli ziele --art wechsel --json | ConvertFrom-Json
Check 'Wechseldatenträger: ehrliche Liste (Runner hat keine)' ($LASTEXITCODE -eq 0) ("Ziele: " + ($w.roots -join '; '))

# 2) Kontextmenü (HKCU, ohne Adminrechte)
& powershell -NoProfile -ExecutionPolicy Bypass -File "$Scripts\kontextmenue.ps1" -Programm $Ui
Check 'Kontextmenü: Skript erfolgreich' ($LASTEXITCODE -eq 0)
foreach ($k in 'HKCU:\Software\Classes\*\shell\AXSafe.Pruefen\command', 'HKCU:\Software\Classes\Directory\shell\AXSafe.Pruefen\command') {
    $v = (Get-ItemProperty -LiteralPath $k).'(default)'
    Check "Kontextmenü-Befehl $k" ($v -eq ('"{0}" --scan "%1" --ausloeser kontextmenue' -f $Ui)) $v
}
& powershell -NoProfile -ExecutionPolicy Bypass -File "$Scripts\kontextmenue.ps1" -Entfernen
Check 'Kontextmenü: entfernt' (-not (Test-Path -LiteralPath 'HKCU:\Software\Classes\*\shell\AXSafe.Pruefen') -and -not (Test-Path -LiteralPath 'HKCU:\Software\Classes\Directory\shell\AXSafe.Pruefen'))

# 3) Geplante Prüfung: einrichten, sofort auslösen, Bericht prüfen, entfernen
$daten = Join-Path $env:RUNNER_TEMP 'axsafe-zeitplan-daten'
$berichte = Join-Path $env:RUNNER_TEMP 'axsafe-zeitplan-berichte'
New-Item -ItemType Directory -Force $daten, $berichte | Out-Null
Set-Content "$daten\brief.txt" 'harmloser Testinhalt'
& powershell -NoProfile -ExecutionPolicy Bypass -File "$Scripts\zeitplan.ps1" -Art benutzer -Pfad $daten -Cli $Cli -Berichtsordner $berichte -Uhrzeit 03:17
Check 'Zeitplan: eingerichtet' ($LASTEXITCODE -eq 0)
$t = Get-ScheduledTask -TaskPath '\AXSafe\' -TaskName 'Pruefung-benutzer'
Check 'Zeitplan: ohne erhöhte Rechte' ($t.Principal.RunLevel -eq 'Limited') $t.Principal.RunLevel
Start-ScheduledTask -TaskPath '\AXSafe\' -TaskName 'Pruefung-benutzer'
$rep = $null
for ($i = 0; $i -lt 120 -and -not $rep; $i++) {
    Start-Sleep 1
    $file = Get-ChildItem $berichte -Filter 'scan-*.json' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($file) {
        try { $rep = Get-Content $file.FullName -Raw | ConvertFrom-Json } catch { $rep = $null }
    }
}
Check 'Zeitplan: Bericht erzeugt' ($null -ne $rep)
if ($rep) {
    Check 'Zeitplan: Auslöser im Bericht' ($rep.scope.trigger -eq 'schedule') $rep.scope.trigger
    Check 'Zeitplan: Ergebnis ohne Fund' ($rep.outcome -eq 'no_detection') $rep.outcome
    Check 'Zeitplan: Datei geprüft' ([bool]($rep.files | Where-Object { $_.path -like '*brief.txt' }))
    Copy-Item $file.FullName (Join-Path $EvidenceDir 'zeitplan-bericht.json')
}
& powershell -NoProfile -ExecutionPolicy Bypass -File "$Scripts\zeitplan.ps1" -Art benutzer -Entfernen
Check 'Zeitplan: entfernt' (-not (Get-ScheduledTask -TaskPath '\AXSafe\' -TaskName 'Pruefung-benutzer' -ErrorAction SilentlyContinue))
Remove-Item -Recurse -Force $daten, $berichte

Add-Content $Log "Ergebnis: $pass bestanden, $fail fehlgeschlagen" -Encoding UTF8
Write-Host "Ergebnis: $pass bestanden, $fail fehlgeschlagen"
if ($fail -gt 0) { exit 1 }
