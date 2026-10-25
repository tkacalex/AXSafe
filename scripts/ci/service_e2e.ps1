# Ende-zu-Ende-Systemtest des AXSafe-Dienstes auf einem WEGWERF-Windows-Runner
# (Administrator). Installiert den Dienst, prüft IPC, Identität,
# Impersonation, Eigentum, Absturz/Wiederanlauf und Deinstallation.
# Legt dafür einen temporären lokalen Testbenutzer mit zufälligem Kennwort an
# und entfernt ihn am Ende wieder. NICHT auf einem Alltagsrechner ausführen.
param(
    [Parameter(Mandatory = $true)][string]$BinDir,
    [Parameter(Mandatory = $true)][string]$RulesDir,
    [Parameter(Mandatory = $true)][string]$EvidenceDir,
    # Optional: Pfad zu ui/AXSafe.Client.Tests – dann laufen die C#-Dienst-Tests
    # (Kategorie=Dienst) gegen den installierten Dienst.
    [string]$ClientTests = ''
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$log = Join-Path $EvidenceDir 'dienst-e2e.txt'
$results = [ordered]@{}
function Log([string]$m) { $l = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $l; Add-Content $log $l -Encoding UTF8 }
function Check([string]$id, [bool]$ok, [string]$detail) {
    $results[$id] = [ordered]@{ ok = $ok; detail = $detail }
    Log ("{0} {1}: {2}" -f $(if ($ok) { 'OK  ' } else { 'FEHL' }), $id, $detail)
}
$cli = Join-Path $BinDir 'axsafe.exe'
function Dienst([string[]]$a) {
    $out = & $cli dienst @a 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = $out; Json = $(try { $out | ConvertFrom-Json } catch { $null }) }
}

$root = 'C:\axsafe-e2e'
$user = 'axsafe-e2e-test'
try {
    # --- Installation ------------------------------------------------------
    & (Join-Path $PSScriptRoot '..\windows\install-service.ps1') -SourceDir $BinDir -RulesDir $RulesDir -EvidenceDir $EvidenceDir
    $svc = Get-CimInstance Win32_Service -Filter "Name='AXSafeService'"
    Check 'installiert_konto' ($svc.StartName -eq 'NT AUTHORITY\LocalService' -and $svc.State -eq 'Running') "Konto $($svc.StartName), Zustand $($svc.State)"
    $privs = (& sc.exe qprivs AXSafeService) -join ' '
    Check 'privilegien_minimal' ($privs -match 'SeImpersonatePrivilege' -and $privs -match 'SeChangeNotifyPrivilege' -and $privs -notmatch 'SeDebug|SeTcb|SeBackup|SeRestore|SeTakeOwnership|SeLoadDriver') $privs

    # --- Status, Engines (Worker unter LocalService im AppContainer) ---------
    $deadline = (Get-Date).AddMinutes(3)
    do { Start-Sleep -Seconds 3; $s = Dienst @('status') } while ((-not $s.Json -or $s.Json.result.engines.state -ne 'geprüft') -and (Get-Date) -lt $deadline)
    Check 'status' ($s.Code -eq 0 -and $s.Json.ok -and $s.Json.result.service -eq 'bereit') "Exit $($s.Code); Client $($s.Json.result.client.display), Sitzung $($s.Json.result.client.session_id)"
    $y = $s.Json.result.engines.list | Where-Object { $_.name -eq 'yara-x' }
    Check 'dienst_worker_isoliert' ($y.health.state -eq 'ready' -and $y.isolation.enforced) "yara-x: $($y.health.state) / $($y.isolation.kind) / $($y.isolation.detail) $($y.health.reason)"

    # --- Testdaten -----------------------------------------------------------
    New-Item -ItemType Directory -Force -Path "$root\offen", "$root\privat" | Out-Null
    Set-Content "$root\offen\brief.txt" 'Sehr geehrte Damen und Herren' -Encoding ASCII
    [IO.File]::WriteAllBytes("$root\offen\eicar.com", [Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'))
    Set-Content "$root\privat\geheim.txt" 'nur fuer den Runner' -Encoding ASCII
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe "$root\privat" /inheritance:r /grant:r "${me}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    & icacls.exe $root /grant '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    $hashBefore = Get-ChildItem $root -Recurse -File | ForEach-Object { "$($_.FullName)=$((Get-FileHash $_.FullName).Hash)" }

    # --- Scan durch den Dienst (eigene Rechte) ------------------------------
    $r = Dienst @('scan', "$root\offen", '--warten')
    $rep = $r.Json.result.report
    Check 'scan_ende_zu_ende' ($r.Code -eq 0 -and $rep.outcome -eq 'detection' -and $rep.summary.with_detection -eq 1) "outcome $($rep.outcome), Funde $($rep.summary.with_detection), Objekte $($rep.summary.objects_total)"
    $kinds = ($rep.files | ForEach-Object { $_.file_kind }) | ConvertTo-Json -Compress
    Check 'typ_im_worker' ($null -ne $rep.files[0].file_kind) "Dateitypen aus dem Worker: $kinds"
    $ownJob = $rep.job_id

    # --- Abbruch -------------------------------------------------------------
    1..40 | ForEach-Object { Set-Content "$root\offen\f$_.txt" ("x" * 1000) -Encoding ASCII }
    $st = Dienst @('scan', "$root\offen")
    $jid = $st.Json.result.job_id
    $c = Dienst @('abbrechen', $jid)
    Start-Sleep -Seconds 3
    $j = Dienst @('auftrag', $jid)
    Check 'abbruch' ($c.Code -eq 0 -or $j.Json.result.state -eq 'finished') "Abbruch-Exit $($c.Code), Zustand $($j.Json.result.state) $($j.Json.result.outcome)"

    # --- Zweiter Benutzer ----------------------------------------------------
    Add-Type -AssemblyName System.Web
    $pw = [System.Web.Security.Membership]::GeneratePassword(24, 4) + 'aA1!'
    $sec = ConvertTo-SecureString $pw -AsPlainText -Force
    New-LocalUser -Name $user -Password $sec -AccountNeverExpires -PasswordNeverExpires | Out-Null
    $cred = New-Object System.Management.Automation.PSCredential(".\$user", $sec)
    $out = 'C:\Users\Public\axsafe-e2e'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    & icacls.exe $out /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
    # CLI an einen für den Testbenutzer lesbaren Ort kopieren.
    Copy-Item $cli "$out\axsafe.exe"
    $script = @"
`$cli = '$out\axsafe.exe'
function D([string[]]`$a, [string]`$name) { `$o = & `$cli dienst @a 2>&1 | Out-String; Set-Content -Path ('$out\' + `$name + '.txt') -Value ("EXIT=`$LASTEXITCODE`n" + `$o) -Encoding UTF8 }
D @('status') 'status'
D @('bericht', '$ownJob') 'fremder_bericht'
D @('abbrechen', '$jid') 'fremder_abbruch'
D @('auftrag', '$ownJob') 'fremder_auftrag'
D @('scan', '$root\privat', '--warten') 'privat_scan'
`$sc = & sc.exe stop AXSafeService 2>&1 | Out-String; Set-Content '$out\sc_stop.txt' ("EXIT=`$LASTEXITCODE`n" + `$sc) -Encoding UTF8
`$sd = & sc.exe delete AXSafeService 2>&1 | Out-String; Set-Content '$out\sc_delete.txt' ("EXIT=`$LASTEXITCODE`n" + `$sd) -Encoding UTF8
"@
    Set-Content "$out\als-testbenutzer.ps1" $script -Encoding UTF8
    $p = Start-Process powershell.exe -Credential $cred -LoadUserProfile -WorkingDirectory $out -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "$out\als-testbenutzer.ps1") -Wait -PassThru -WindowStyle Hidden
    Log "Testbenutzer-Prozess beendet mit $($p.ExitCode)"
    function ReadOut([string]$n) { if (Test-Path "$out\$n.txt") { Get-Content "$out\$n.txt" -Raw } else { "FEHLT" } }
    $st2 = ReadOut 'status'
    Check 'zweiter_benutzer_status' ($st2 -match 'EXIT=0' -and $st2 -match $user) ($st2 -split "`n" | Select-Object -First 1)
    foreach ($n in 'fremder_bericht', 'fremder_abbruch', 'fremder_auftrag') {
        $t = ReadOut $n
        Check $n ($t -match 'EXIT=7' -and $t -match 'not_found') (($t -replace '\s+', ' ').Substring(0, [Math]::Min(160, $t.Length)))
    }
    $ps = ReadOut 'privat_scan'
    Check 'unberechtigter_dateizugriff' ($ps -match 'EXIT=0' -and $ps -match '"access_denied"' -and $ps -notmatch 'nur fuer den Runner') "Scan eines nicht lesbaren Ordners als Testbenutzer: $(if ($ps -match '"access_denied"') { 'AccessDenied-Lücke' } else { ($ps -replace '\s+',' ').Substring(0, [Math]::Min(200, $ps.Length)) })"
    foreach ($n in 'sc_stop', 'sc_delete') {
        $t = ReadOut $n
        Check "nicht_admin_$n" ($t -notmatch 'EXIT=0' -and (Get-Service AXSafeService).Status -eq 'Running') (($t -replace '\s+', ' ').Substring(0, [Math]::Min(120, $t.Length)))
    }

    # --- Dienstabsturz während eines Scans: Wiederanlauf, Dateien unverändert ---
    $st = Dienst @('scan', "$root\offen")
    $pid0 = (Get-CimInstance Win32_Service -Filter "Name='AXSafeService'").ProcessId
    Stop-Process -Id $pid0 -Force
    $deadline = (Get-Date).AddSeconds(60)
    do { Start-Sleep -Seconds 2; $svc = Get-CimInstance Win32_Service -Filter "Name='AXSafeService'" } while (($svc.State -ne 'Running' -or $svc.ProcessId -eq $pid0) -and (Get-Date) -lt $deadline)
    Start-Sleep -Seconds 2
    $s2 = Dienst @('status')
    Check 'absturz_wiederanlauf' ($svc.State -eq 'Running' -and $svc.ProcessId -ne $pid0 -and $s2.Code -eq 0) "alter Prozess $pid0, neuer $($svc.ProcessId), Status-Exit $($s2.Code)"
    $old = Dienst @('bericht', $ownJob)
    Check 'bericht_nach_neustart' ($old.Code -eq 0 -and $old.Json.result.report.job_id -eq $ownJob) "Bericht $ownJob nach Neustart lesbar"
    $hashAfter = Get-ChildItem $root -Recurse -File | Where-Object { $_.Name -notlike 'f*.txt' } | ForEach-Object { "$($_.FullName)=$((Get-FileHash $_.FullName).Hash)" }
    $before = $hashBefore | Where-Object { $_ -notmatch '\\f\d+\.txt=' }
    Check 'nutzdateien_unveraendert' ((Compare-Object $before $hashAfter).Count -eq 0) "$(@($before).Count) Dateien, Hashes vor/nach Scans und Absturz verglichen"

    # --- Oberflächen-Client (C#) gegen den echten Dienst --------------------
    if ($ClientTests) {
        $env:AXSAFE_SERVICE_TEST = '1'
        $trx = Join-Path $EvidenceDir 'trx'
        $o = & dotnet test $ClientTests -p:RestoreLockedMode=true --filter 'Kategorie=Dienst' --logger 'trx;LogFileName=dienst-client.trx' --results-directory $trx 2>&1 | Out-String
        $code = $LASTEXITCODE
        Add-Content (Join-Path $EvidenceDir 'dienst-client-tests.txt') $o -Encoding UTF8
        $sum = ($o -split "`n" | Where-Object { $_ -match 'Passed!|Failed!|Bestanden!|Fehler!|Total tests|Gesamtzahl' }) -join ' '
        Check 'oberflaechen_client_dienst' ($code -eq 0 -and $o -notmatch 'No test matches') "dotnet test Kategorie=Dienst: Exit $code; $($sum.Trim())"
        Remove-Item Env:AXSAFE_SERVICE_TEST
    }

    # --- Kontrollierter Stopp/Start -----------------------------------------
    Stop-Service AXSafeService; (Get-Service AXSafeService).WaitForStatus('Stopped', '00:00:30')
    $down = Dienst @('status')
    Check 'gestoppt_nicht_erreichbar' ($down.Code -eq 6) "Exit $($down.Code): $($down.Text.Trim())"
    Start-Service AXSafeService; (Get-Service AXSafeService).WaitForStatus('Running', '00:00:30')
    Start-Sleep -Seconds 1
    Check 'neustart' ((Dienst @('status')).Code -eq 0) 'nach Start wieder erreichbar'
} catch {
    Log "ABBRUCH: $($_.Exception.Message) $($_.ScriptStackTrace)"
    $results['abbruch'] = [ordered]@{ ok = $false; detail = $_.Exception.Message }
} finally {
    # --- Deinstallation und Aufräumen ---------------------------------------
    if (Test-Path "$env:ProgramData\AXSafe\Service\logs") { Copy-Item "$env:ProgramData\AXSafe\Service\logs\*" $EvidenceDir -ErrorAction SilentlyContinue }
    try {
        & (Join-Path $PSScriptRoot '..\windows\uninstall-service.ps1') -RemoveData
        Check 'deinstallation' ($null -eq (Get-Service AXSafeService -ErrorAction SilentlyContinue) -and -not (Test-Path "$env:ProgramFiles\AXSafe\service")) 'Dienst und Programmordner entfernt'
    } catch { Check 'deinstallation' $false $_.Exception.Message }
    if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $user }
    Get-ChildItem 'C:\Users\Public\axsafe-e2e' -Filter *.txt -ErrorAction SilentlyContinue | Copy-Item -Destination $EvidenceDir
    Remove-Item -Recurse -Force $root, 'C:\Users\Public\axsafe-e2e' -ErrorAction SilentlyContinue
    $results | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $EvidenceDir 'dienst-e2e.json') -Encoding UTF8
}
$bad = @($results.GetEnumerator() | Where-Object { -not $_.Value.ok })
Log ("{0} Prüfungen, {1} fehlgeschlagen" -f $results.Count, $bad.Count)
if ($bad.Count -gt 0) { exit 1 }
exit 0
