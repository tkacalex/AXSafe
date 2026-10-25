# Prüft die WPF-Oberfläche mit UI Automation gegen echte Daten (Befund 8:
# Screenshots ersetzen keine Assertions). Startet AXSafe.exe, liest Texte
# und Listen über ihre AutomationId (x:Name) und vergleicht sie mit einem
# unabhängigen CLI-Lauf auf denselben Ordner. Exit 1 bei Abweichung.
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Cli,
    [Parameter(Mandatory = $true)][string]$Rules,
    [string]$ScanFolder = "",
    [int]$TimeoutSeconds = 90
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$AE = [System.Windows.Automation.AutomationElement]
$failures = New-Object System.Collections.Generic.List[string]
function Check([bool]$ok, [string]$what) {
    if ($ok) { Write-Host "OK   $what" } else { Write-Host "FEHL $what"; $failures.Add($what) }
}
function Find($root, [string]$id) {
    $c = New-Object System.Windows.Automation.PropertyCondition($AE::AutomationIdProperty, $id)
    return $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
}
function WaitFor([scriptblock]$cond, [int]$seconds) {
    $end = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $end) { if (& $cond) { return $true }; Start-Sleep -Milliseconds 500 }
    return $false
}

# Erwartung unabhängig über die CLI ermitteln (gleiche Engines: ClamAV ab, da im Runner nicht vorhanden).
$expected = $null
if ($ScanFolder) {
    $json = Join-Path $env:RUNNER_TEMP ("ui-expect-" + [guid]::NewGuid().ToString("N") + ".json")
    & $Cli scan --no-clamav --rules $Rules --json $json -- $ScanFolder | Out-Null
    $expected = Get-Content $json -Raw | ConvertFrom-Json
    Write-Host "Erwartung aus CLI: outcome=$($expected.outcome) objects=$($expected.summary.objects_total)"
}

$argList = @()
if ($ScanFolder) { $argList = @('--scan', $ScanFolder) }
$startArgs = @{ FilePath = $Exe; PassThru = $true }
if ($argList.Count -gt 0) { $startArgs.ArgumentList = $argList }
$p = Start-Process @startArgs
try {
    $okWin = WaitFor { $p.Refresh(); $p.MainWindowHandle -ne 0 -or $p.HasExited } 60
    if (-not $okWin -or $p.HasExited) { throw "Kein Hauptfenster (beendet: $($p.HasExited))" }
    $win = $AE::FromHandle($p.MainWindowHandle)

    # Bereitschaft und Regelbestand getrennt (Befund 7).
    Check (WaitFor { $h = Find $win 'HealthText'; $h -and $h.Current.Name -eq 'Eingeschränkt' } 30) "Gesundheit zeigt 'Eingeschränkt' (nie grün ohne Dienst)"
    if (-not $ScanFolder) {
        # Der Hinweis steht auf der Übersicht; beim Direktscan ist die Prüfseite aktiv.
        Check (WaitFor { $t = Find $win 'TestRulesTitle'; $t -and -not $t.Current.IsOffscreen -and $t.Current.Name -like '*FUNKTIONSTEST*' } 30) "Hinweis 'nur Funktionstest-Regeln' auf der Übersicht sichtbar"
    }
    $cliVer = ((& $Cli --version) -replace '[^0-9.]', '').Split('.')
    $verText = (Find $win 'VersionText').Current.Name
    Check ($verText -eq "Vorversion $($cliVer[0]).$($cliVer[1])") "Versionsanzeige passt zur CLI (ist: '$verText')"
    $detail = Find $win 'HealthDetail'
    Check ($null -ne $detail -and $detail.Current.Name -like '*nur Testregeln*') "Statuszeile nennt 'nur Testregeln'"
    # P02: Ohne installierten Dienst muss das sichtbar sein (nie "bereit" ohne Bestätigung).
    $svcInstalled = $null -ne (Get-Service AXSafeService -ErrorAction SilentlyContinue)
    if (-not $svcInstalled) {
        Check ($detail.Current.Name -like '*Dienst fehlt*') "Statuszeile nennt 'Dienst fehlt' (ist: '$($detail.Current.Name)')"
    }

    if ($expected) {
        $prefix = @{
            'detection' = 'Fund –'; 'detection_incomplete' = 'Fund vorhanden;'; 'no_detection' = 'Nichts erkannt';
            'incomplete' = 'Unvollständig'; 'nothing_scanned' = 'Keine prüfbaren Objekte'
        }[$expected.outcome]
        $done = WaitFor { $s = Find $win 'ScanStatus'; $s -and $s.Current.Name.StartsWith($prefix) } $TimeoutSeconds
        $status = (Find $win 'ScanStatus').Current.Name
        Check $done "Ergebnistext passt zu outcome '$($expected.outcome)' (ist: '$status')"
        $list = Find $win 'ResultList'
        $CT = [System.Windows.Automation.ControlType]
        $isItem = New-Object System.Windows.Automation.OrCondition(
            (New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, $CT::ListItem)),
            (New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty, $CT::DataItem)))
        $items = $list.FindAll([System.Windows.Automation.TreeScope]::Children, $isItem)
        Check ($items.Count -eq [int]$expected.summary.objects_total) "Ergebnisliste hat $($items.Count) Einträge (erwartet $($expected.summary.objects_total))"
        $summary = (Find $win 'ScanSummary').Current.Name
        Check ($summary -like "$($expected.summary.objects_total) Objekte*" -and $summary -like "*$($expected.summary.incomplete) mit Prüflücke*") "Zähler in der Zusammenfassung stimmen (ist: '$summary')"
    }
}
finally {
    if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }
}
if ($failures.Count -gt 0) { Write-Host "$($failures.Count) UI-Prüfung(en) fehlgeschlagen."; exit 1 }
Write-Host "Alle UI-Prüfungen bestanden."
exit 0
