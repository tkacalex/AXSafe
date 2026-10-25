<#
.SYNOPSIS
  Führt die in der CI gebauten AXSafe-Testprogramme auf diesem Rechner aus
  (B-02/B-10: Nachweis auf Windows 10 LTSC). Ohne Administratorrechte.
.DESCRIPTION
  * Erwartet das Testpaket unter C:\axsafe-ltsc (die Testprogramme enthalten
    diese Pfade fest, weil die CI sie dort gebaut hat).
  * Tests, die EICAR auf die Platte schreiben oder Administratorrechte
    brauchen, werden ausgelassen und mit Grund gezählt (ltsc-skip.txt).
  * Vorher/nachher werden die Defender-Erkennungen verglichen; greift
    Defender trotzdem ein, steht das im Bericht.
#>
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2.0
$Root = 'C:\axsafe-ltsc'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $env:USERPROFILE 'Desktop\AXSafe\nachweise'
if (-not (Test-Path $outDir)) { $outDir = Join-Path $Root 'ergebnis' }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$report = Join-Path $outDir "ltsc-tests-$stamp.txt"
function Log([string]$m) { Write-Host $m; Add-Content -Path $report -Value $m -Encoding UTF8 }

if (-not (Test-Path (Join-Path $Root 'manifest.json'))) {
    Log "ABBRUCH: Testpaket nicht unter $Root gefunden (manifest.json fehlt)."
    exit 2
}
$manifest = Get-Content (Join-Path $Root 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$skips = @{}
foreach ($l in Get-Content (Join-Path $here 'ltsc-skip.txt') -Encoding UTF8) {
    if ($l -match '^\s*#' -or $l -notmatch '\|') { continue }
    $p = $l.Split('|', 2); $skips[$p[0].Trim()] = $p[1].Trim()
}
$os = Get-CimInstance Win32_OperatingSystem
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Log "AXSafe-Tests auf diesem Rechner – $(Get-Date -Format 's')"
Log "System: $($os.Caption) $($os.Version) Build $($os.BuildNumber); Benutzer $env:USERNAME; erhöht: $isAdmin"
Log "Paket: Commit $($manifest.commit), CI-Lauf $($manifest.run_id), $(@($manifest.tests).Count) Testprogramme"
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
Log "Defender-Echtzeitschutz: $(if ($mp) { $mp.RealTimeProtectionEnabled } else { 'unbekannt' }) (bleibt an)"
$before = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object { "$($_.DetectionID)" })

# ClamAV-Programme für Tests, die clamscan über PATH suchen.
$clam = Join-Path $env:ProgramFiles 'ClamAV'
if (Test-Path (Join-Path $clam 'clamscan.exe')) { $env:PATH = "$clam;$env:PATH" }

$skipArgs = @()
foreach ($k in $skips.Keys) { $skipArgs += @('--skip', $k) }
$pass = 0; $fail = 0; $ign = 0; $failed = @(); $ran = @()
foreach ($t in $manifest.tests) {
    $exe = Join-Path $Root $t.path
    if (-not (Test-Path $exe)) { Log "FEHLT: $($t.path)"; $fail++; $failed += "$($t.name) (Programm fehlt)"; continue }
    Log ""
    Log "=== $($t.name)"
    $o = & $exe --include-ignored @skipArgs 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    foreach ($line in $o) {
        if ($line -match '^test (\S+) \.\.\. (ok|FAILED|ignored)') {
            Add-Content -Path $report -Value $line -Encoding UTF8
            $ran += $Matches[1]
            switch ($Matches[2]) { 'ok' { $pass++ } 'FAILED' { $fail++; $failed += "$($t.name)::$($Matches[1])" } 'ignored' { $ign++ } }
        } elseif ($line -match 'panicked at|^---- ') {
            Add-Content -Path $report -Value $line -Encoding UTF8
        }
    }
    if ($code -ne 0 -and -not ($o -match 'test result')) { $fail++; $failed += "$($t.name) (Start fehlgeschlagen, Exit $code)"; Log ($o | Select-Object -First 5 | Out-String) }
}
$skipped = @($skips.Keys | Where-Object { $ran -notcontains $_ })
$after = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $before -notcontains "$($_.DetectionID)" })
Log ""
Log "=== Ergebnis"
Log "bestanden: $pass, fehlgeschlagen: $fail, ausgelassen ohne Lauf: $ign, bewusst ausgelassen (mit Grund): $($skipped.Count)"
foreach ($s in $skipped) { Log "  ausgelassen: $s – $($skips[$s])" }
foreach ($f in $failed) { Log "  FEHLGESCHLAGEN: $f" }
if ($after.Count -gt 0) {
    foreach ($d in $after) { Log "  DEFENDER-ERKENNUNG während der Tests: $($d.ThreatID) $($d.Resources -join ', ')" }
} else { Log "Defender: keine neue Erkennung während der Tests" }
Log "Bericht: $report"
@{ commit = $manifest.commit; run_id = $manifest.run_id; system = "$($os.Caption) $($os.Version)"; passed = $pass; failed = $fail; ignored = $ign; skipped = $skipped; failures = $failed; defender_new = @($after | ForEach-Object { "$($_.ThreatID)" }) } |
    ConvertTo-Json -Depth 4 | Set-Content -Path ($report -replace '\.txt$', '.json') -Encoding UTF8
if ($fail -gt 0) { exit 1 } else { exit 0 }
