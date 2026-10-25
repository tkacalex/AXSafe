# Gemeinsamer Integrationstest auf EINER Wegwerf-Windows-Maschine (CI):
# AXSafeService + echte ClamAV-Engine (vorher mit setup-clamav.ps1 eingerichtet,
# offizielle Signaturen). Prüft eine harmlose Datei und EICAR über den Dienst.
# Auf dem Runner ist der Defender-Echtzeitschutz aus; auf Alltagsrechnern
# bleibt Defender an – dort NICHT ausführen (Testbenutzerrechte, EICAR-Datei).
param(
    [Parameter(Mandatory = $true)][string]$BinDir,
    [Parameter(Mandatory = $true)][string]$RulesDir,
    [Parameter(Mandatory = $true)][string]$EvidenceDir
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$log = Join-Path $EvidenceDir 'dienst-clamav-e2e.txt'
$results = [ordered]@{}
function Log([string]$m) { $l = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $l; Add-Content $log $l -Encoding UTF8 }
function Check([string]$id, [bool]$ok, [string]$detail) {
    $results[$id] = [ordered]@{ ok = $ok; detail = $detail }
    Log ("{0} {1}: {2}" -f $(if ($ok) { 'OK  ' } else { 'FEHL' }), $id, $detail)
}
$cli = Join-Path $BinDir 'axsafe.exe'
function Dienst([string[]]$a) {
    $ErrorActionPreference = 'Continue'
    $out = & $cli dienst @a 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out; Json = $(try { $out | ConvertFrom-Json } catch { $null }) }
}
$root = 'C:\axsafe-dienst-clamav'
try {
    $rt = Get-MpComputerStatus -ErrorAction SilentlyContinue
    Log "Defender-Echtzeitschutz auf dem Runner: $(if ($rt) { $rt.RealTimeProtectionEnabled } else { 'unbekannt' })"
    & (Join-Path $PSScriptRoot '..\windows\install-service.ps1') -SourceDir $BinDir -RulesDir $RulesDir -EvidenceDir $EvidenceDir
    $deadline = (Get-Date).AddMinutes(3)
    do { Start-Sleep -Seconds 3; $s = Dienst @('status') } while ((-not $s.Json -or $s.Json.result.engines.state -ne 'geprüft') -and (Get-Date) -lt $deadline)
    $c = $s.Json.result.engines.list | Where-Object { $_.name -eq 'clamav' }
    Check 'dienst_sieht_clamav' ($c -and $c.health.state -eq 'ready' -and $c.content_kind -eq 'official_signatures' -and $c.isolation.enforced) "Dienst-Sicht: clamav $($c.health.state) / $($c.content_kind) / $($c.content_version) / isoliert=$($c.isolation.enforced)"

    New-Item -ItemType Directory -Force -Path $root | Out-Null
    Set-Content "$root\brief.txt" 'Sehr geehrte Damen und Herren, harmlose Testdatei.' -Encoding ASCII
    [IO.File]::WriteAllBytes("$root\eicar.com", [Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'))
    $r = Dienst @('scan', $root, '--clamav', '--warten')
    $rep = $r.Json.result.report
    $rep | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $EvidenceDir 'dienst-clamav-bericht.json') -Encoding UTF8
    Check 'ausgefuehrt_vom_dienst' ($rep.executed_by.kind -eq 'dienst' -and $rep.executed_by.name -eq 'AXSafeService' -and $rep.executed_by.account -match 'LOCAL SERVICE') "executed_by: $($rep.executed_by | ConvertTo-Json -Compress)"
    $sc = $rep.scope.engines | Where-Object { $_.name -eq 'clamav' }
    Check 'auftrag_clamav_offiziell' ($sc -and $sc.health.state -eq 'ready' -and $sc.content_kind -eq 'official_signatures') "Auftrag: clamav $($sc.health.state) $($sc.content_kind) $($sc.content_version)"
    $brief = $rep.files | Where-Object { $_.path -like '*brief.txt' }
    $bc = $brief.engines | Where-Object { $_.engine -eq 'clamav' }
    Check 'harmlos_ohne_fund' ($bc -and $bc.verdict -eq 'NoDetection' -and @($bc.gaps).Count -eq 0 -and @($brief.gaps).Count -eq 0) "brief.txt: clamav $($bc.verdict), Lücken $(@($brief.gaps).Count)"
    $ei = $rep.files | Where-Object { $_.path -like '*eicar.com' }
    $ec = $ei.engines | Where-Object { $_.engine -eq 'clamav' }
    $names = @($ec.detections | ForEach-Object { $_.name }) -join ', '
    Check 'eicar_durch_clamav' ($ec -and $ec.verdict -eq 'Malicious' -and $names -match 'Eicar' -and $names -notmatch 'AXSafe' -and @($ec.gaps).Count -eq 0) "eicar.com: clamav $($ec.verdict) ($names), Inhalt $($ec.content_version)"
    Check 'keine_luecken' ($rep.complete -eq $true -and @($rep.job_gaps).Count -eq 0 -and $rep.summary.incomplete -eq 0) "outcome $($rep.outcome), complete $($rep.complete), Auftragslücken $(@($rep.job_gaps).Count), Objekte mit Lücke $($rep.summary.incomplete)"
    # B-18: dauerhaft geladene Engine im Dienst.
    Check 'dauerhaft_geladen' ($sc.content_note -match 'dauerhaft geladen im ClamAV-Worker' -and $sc.isolation.enforced) "Auftrag: $($sc.content_note) / $($sc.isolation.detail)"
    $cw = Join-Path $env:ProgramFiles 'AXSafe\service\axsafe-clamav-worker.exe'
    $fw = @(Get-NetFirewallApplicationFilter -Program $cw -ErrorAction SilentlyContinue | Get-NetFirewallRule | Where-Object { "$($_.Action)" -eq 'Block' -and "$($_.Direction)" -eq 'Outbound' -and "$($_.Enabled)" -eq 'True' })
    Check 'worker_ohne_netz' ($fw.Count -ge 1) "Firewall-Sperrregel für ${cw}: $(($fw | ForEach-Object { $_.DisplayName }) -join ', ')"
    $dur1 = @($rep.files | ForEach-Object { ($_.engines | Where-Object { $_.engine -eq 'clamav' }).duration_ms })
    Log "ClamAV-Dauer je Datei im ersten Auftrag (ms): $($dur1 -join ', ')"

    # Zwei Aufträge gleichzeitig: jeder bekommt seine eigenen Ergebnisse,
    # die Datenbank wird nicht neu geladen (Worker-Start Nr. bleibt gleich).
    New-Item -ItemType Directory -Force -Path "$root\a", "$root\b" | Out-Null
    1..15 | ForEach-Object { Set-Content "$root\a\harmlos$_.txt" ("Auftrag A Datei $_ " * 50) -Encoding ASCII }
    1..15 | ForEach-Object { Set-Content "$root\b\harmlos$_.txt" ("Auftrag B Datei $_ " * 50) -Encoding ASCII }
    Copy-Item "$root\eicar.com" "$root\b\eicar-b.com"
    $pa = Start-Process $cli -ArgumentList @('dienst', 'scan', "$root\a", '--clamav', '--warten') -PassThru -WindowStyle Hidden -RedirectStandardOutput "$root\a.json"
    $pb = Start-Process $cli -ArgumentList @('dienst', 'scan', "$root\b", '--clamav', '--warten') -PassThru -WindowStyle Hidden -RedirectStandardOutput "$root\b.json"
    $pa.WaitForExit(600000) | Out-Null; $pb.WaitForExit(600000) | Out-Null
    $ra = (Get-Content "$root\a.json" -Raw -Encoding UTF8 | ConvertFrom-Json).result.report
    $rb = (Get-Content "$root\b.json" -Raw -Encoding UTF8 | ConvertFrom-Json).result.report
    $ra | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $EvidenceDir 'dienst-clamav-parallel-a.json') -Encoding UTF8
    $rb | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $EvidenceDir 'dienst-clamav-parallel-b.json') -Encoding UTF8
    $aOk = $ra -and $ra.outcome -eq 'no_detection' -and $ra.complete -and @($ra.files).Count -eq 15 -and -not ($ra.files | Where-Object { $_.path -notlike "*axsafe-dienst-clamav\a\*" })
    $bFund = @($rb.files | Where-Object { @($_.engines | Where-Object { $_.engine -eq 'clamav' -and $_.verdict -eq 'Malicious' }).Count -gt 0 } | ForEach-Object { Split-Path $_.path -Leaf })
    $bOk = $rb -and $rb.outcome -eq 'detection' -and $rb.complete -and @($rb.files).Count -eq 16 -and ($bFund -join ',') -eq 'eicar-b.com' -and -not ($rb.files | Where-Object { $_.path -notlike "*axsafe-dienst-clamav\b\*" })
    Check 'parallel_eigene_ergebnisse' ($aOk -and $bOk -and $ra.job_id -ne $rb.job_id) "A: $($ra.outcome) $(@($ra.files).Count) Dateien; B: $($rb.outcome) $(@($rb.files).Count) Dateien, ClamAV-Fund nur in $($bFund -join ',')"
    $na = ($ra.scope.engines | Where-Object { $_.name -eq 'clamav' }).content_note
    $nb = ($rb.scope.engines | Where-Object { $_.name -eq 'clamav' }).content_note
    $start0 = if ($sc.content_note -match 'Worker-Start Nr\. (\d+)') { $Matches[1] } else { '?' }
    $startA = if ($na -match 'Worker-Start Nr\. (\d+)') { $Matches[1] } else { '?' }
    $startB = if ($nb -match 'Worker-Start Nr\. (\d+)') { $Matches[1] } else { '?' }
    Check 'datenbank_einmal_geladen' ($start0 -ne '?' -and $start0 -eq $startA -and $startA -eq $startB) "Worker-Start Nr.: erster Auftrag $start0, parallel A $startA, B $startB"
    $durA = @($ra.files | ForEach-Object { ($_.engines | Where-Object { $_.engine -eq 'clamav' }).duration_ms })
    Log "ClamAV-Dauer je Datei, Auftrag A (ms): $($durA -join ', ')"

    # Abbruch eines laufenden Auftrags; danach arbeitet die gemeinsame Engine weiter.
    New-Item -ItemType Directory -Force -Path "$root\viele" | Out-Null
    1..200 | ForEach-Object { Set-Content "$root\viele\f$_.txt" ("x$_ " * 500) -Encoding ASCII }
    $st = Dienst @('scan', "$root\viele", '--clamav')
    $jid = $st.Json.result.job_id
    Start-Sleep -Milliseconds 300
    $c = Dienst @('abbrechen', $jid)
    $deadline = (Get-Date).AddSeconds(120)
    do { Start-Sleep -Milliseconds 500; $j = Dienst @('auftrag', $jid) } while ($j.Json.result.state -in 'queued', 'running' -and (Get-Date) -lt $deadline)
    $cr = (Dienst @('bericht', $jid)).Json.result.report
    Check 'abbruch' ($c.Code -eq 0 -and $cr.cancelled -eq $true -and $cr.complete -eq $false -and $cr.outcome -ne 'no_detection') "Bericht: cancelled=$($cr.cancelled), complete=$($cr.complete), outcome=$($cr.outcome), geprüft $(@($cr.files).Count) von 200"
    $r2 = Dienst @('scan', "$root\eicar.com", '--clamav', '--warten')
    $e2 = ($r2.Json.result.report.files[0].engines | Where-Object { $_.engine -eq 'clamav' })
    Check 'nach_abbruch_weiter' ($e2.verdict -eq 'Malicious' -and @($e2.gaps).Count -eq 0) "eicar.com nach Abbruch: clamav $($e2.verdict) $($e2.duration_ms) ms"

    $svcLog = Get-Content "$env:ProgramData\AXSafe\Service\logs\service.log" -Raw -Encoding UTF8
    $line = ($svcLog -split "`n" | Where-Object { $_ -match [regex]::Escape($rep.job_id) }) -join ' '
    Check 'dienstprotokoll' ($line -match 'clamav' -and $line -match 'main-\d+') "Protokoll: $line"
} catch {
    Log "ABBRUCH: $($_.Exception.Message) $($_.ScriptStackTrace)"
    $results['abbruch'] = [ordered]@{ ok = $false; detail = $_.Exception.Message }
} finally {
    if (Test-Path "$env:ProgramData\AXSafe\Service\logs") { Copy-Item "$env:ProgramData\AXSafe\Service\logs\*" $EvidenceDir -ErrorAction SilentlyContinue }
    try { & (Join-Path $PSScriptRoot '..\windows\uninstall-service.ps1') -RemoveData } catch { Log "Deinstallation: $($_.Exception.Message)" }
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
    $results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $EvidenceDir 'dienst-clamav-e2e.json') -Encoding UTF8
    $bad = @($results.GetEnumerator() | Where-Object { -not $_.Value.ok }).Count
    Log "$($results.Count) Prüfungen, $bad fehlgeschlagen"
}
if (@($results.GetEnumerator() | Where-Object { -not $_.Value.ok }).Count -gt 0) { exit 1 }
exit 0
