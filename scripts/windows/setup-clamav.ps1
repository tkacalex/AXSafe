<#
.SYNOPSIS
  Richtet ClamAV (offizielles Windows-Paket) mit FreshClam und automatischen
  Signaturupdates für AXSafe ein und weist das Ergebnis nach.

.DESCRIPTION
  Muss als Administrator laufen (Installation nach Program Files, geschützte
  Datenordner, geplanter Auftrag als SYSTEM). Ablauf:
    1. System und vorhandene ClamAV-Installation erfassen (nichts überschreiben,
       vorhandene Konfiguration wird gesichert).
    2. Offizielles MSI aus dem Cisco-Talos-Release laden; SHA-256 muss dem
       festgelegten Wert entsprechen. Ist gpg vorhanden, wird zusätzlich die
       Talos-Signatur gegen den festgelegten Fingerabdruck geprüft.
       Hinweis: Das ClamAV-MSI und seine Programme tragen KEINE
       Authenticode-Signatur; Herkunftsnachweis ist die Talos-PGP-Signatur
       (vom AXSafe-Projekt geprüft, siehe docs/evidence) plus die SHA-256-Bindung.
    3. MSI installieren (C:\Program Files\ClamAV). Kein clamd-Dienst, kein TCP-Port.
    4. Geschützte Datenordner unter %ProgramData%\AXSafe\ClamAV
       (database, logs, state): SYSTEM/Administratoren Vollzugriff,
       Benutzer nur Lesen.
    5. freshclam.conf mit den offiziellen Quellen; Signaturen laden.
    6. Geplanter Auftrag "AXSafe ClamAV Signaturupdate" (SYSTEM, alle 4 Stunden,
       keine Überlappung, Zeitlimit) mit Statusdatei state\last-update.json.
    7. Nachweise: Versionen, Datenbankstand, harmlose Datei, EICAR über stdin
       (keine Datei), optional EICAR als Datei (Defender darf sie abfangen),
       AXSafe-Engines, erneuter Updatelauf, geplanter Auftrag.
  Programm-Updates (neue ClamAV-Version) laufen getrennt über dieses Skript mit
  neuem, geprüftem Versions-/Hash-Paar; Signaturupdates über den geplanten Auftrag.

.PARAMETER EvidenceDir
  Ordner für den Nachweisbericht (wird angelegt).
.PARAMETER AxsafeCli
  Pfad zu axsafe.exe für die Abnahme e). Leer = Abnahme e) wird als nicht
  ausführbar vermerkt.
#>
[CmdletBinding()]
param(
    [string]$EvidenceDir = (Join-Path $PSScriptRoot 'nachweis'),
    [string]$AxsafeCli = '',
    [string]$Version = '1.5.4',
    [string]$MsiSha256 = 'a025fa23a4b9d64fce448d5a211afcf30dc26ba6528186e6223d1b945f9d95d6',
    [string]$TalosFingerprint = '5BADCA2665EF59DCF8A23D8B707F0DB480836771',
    [switch]$SkipFileEicar
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$InstallDir = Join-Path $env:ProgramFiles 'ClamAV'
$DataRoot   = Join-Path $env:ProgramData 'AXSafe\ClamAV'
$DbDir      = Join-Path $DataRoot 'database'
$LogDir     = Join-Path $DataRoot 'logs'
$StateDir   = Join-Path $DataRoot 'state'
$ConfFile   = Join-Path $DataRoot 'freshclam.conf'
$Updater    = Join-Path $DataRoot 'update-clamav-signatures.ps1'
$TaskName   = 'AXSafe ClamAV Signaturupdate'
$MsiName    = "clamav-$Version.win.x64.msi"
$MsiUrl     = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$Version/$MsiName"

New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ReportFile = Join-Path $EvidenceDir "clamav-setup-$stamp.txt"
$JsonFile   = Join-Path $EvidenceDir "clamav-setup-$stamp.json"
$result = [ordered]@{ started = (Get-Date).ToUniversalTime().ToString('o'); checks = [ordered]@{} }

function Log([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    Add-Content -Path $ReportFile -Value $line -Encoding UTF8
}
function Check([string]$id, [bool]$ok, [string]$detail) {
    $result.checks[$id] = [ordered]@{ ok = $ok; detail = $detail }
    Log ("{0} {1}: {2}" -f ($(if ($ok) { 'OK  ' } else { 'FEHL' })), $id, $detail)
}
function Save { $result.finished = (Get-Date).ToUniversalTime().ToString('o')
    $result | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonFile -Encoding UTF8 }

# Führt ein Programm aus und liefert Exitcode + Ausgabe (ohne Shell).
function Run([string]$exe, [string[]]$argv, [byte[]]$stdin = $null, [int]$timeoutSec = 900) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (($argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = ($null -ne $stdin)
    $psi.CreateNoWindow = $true
    # .NET Framework legt um stdin einen StreamWriter mit Console.InputEncoding;
    # bei UTF-8 schreibt er ein BOM (3 Bytes) VOR die Nutzdaten. Gemessen:
    # "Data read: 71 B" statt 68 B, EICAR dadurch nicht am Dateianfang.
    # ASCII hat kein BOM; die Nutzdaten gehen ohnehin roh über BaseStream.
    $oldIn = $null
    if ($null -ne $stdin) {
        try { $oldIn = [Console]::InputEncoding; [Console]::InputEncoding = [Text.Encoding]::ASCII } catch { $oldIn = $null }
    }
    try { $p = [System.Diagnostics.Process]::Start($psi) }
    finally { if ($null -ne $oldIn) { try { [Console]::InputEncoding = $oldIn } catch { } } }
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if ($null -ne $stdin) {
        $p.StandardInput.BaseStream.Write($stdin, 0, $stdin.Length)
        $p.StandardInput.Close()
    }
    if (-not $p.WaitForExit($timeoutSec * 1000)) { $p.Kill(); throw "${exe}: Zeitüberschreitung" }
    $p.WaitForExit()
    [pscustomobject]@{ Code = $p.ExitCode; Out = $outTask.Result; Err = $errTask.Result }
}

# Liest den Kopf einer CVD/CLD (512 Bytes): ClamAV-VDB:Datum:Version:Signaturen:...
function DbHeader([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    $fs = [IO.File]::OpenRead($path)
    try { $b = New-Object byte[] 512; [void]$fs.Read($b, 0, 512) } finally { $fs.Dispose() }
    $h = [Text.Encoding]::ASCII.GetString($b).TrimEnd([char]0, ' ')
    $f = $h.Split(':')
    if ($f[0] -ne 'ClamAV-VDB') { return $null }
    [pscustomobject]@{ File = (Split-Path $path -Leaf); Built = $f[1]; Version = [int]$f[2]; Signatures = [int]$f[3] }
}
function DbState {
    foreach ($n in 'main', 'daily', 'bytecode') {
        $h = $null
        foreach ($ext in 'cld', 'cvd') { if (-not $h) { $h = DbHeader (Join-Path $DbDir "$n.$ext") } }
        if ($h) { $h }
    }
}

try {
    # --- 0. Rechte --------------------------------------------------------
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'Dieses Skript muss als Administrator laufen (Installation und geschützte Ordner).' }

    # --- 1. System und Bestand --------------------------------------------
    $os = Get-CimInstance Win32_OperatingSystem
    $result.system = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber
        arch = $env:PROCESSOR_ARCHITECTURE; os64 = [Environment]::Is64BitOperatingSystem; computer = $env:COMPUTERNAME }
    Log "System: $($os.Caption) $($os.Version) (Build $($os.BuildNumber)), $env:PROCESSOR_ARCHITECTURE"
    if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        throw "Nur x64 wird unterstützt (gefunden: $env:PROCESSOR_ARCHITECTURE)."
    }
    $defender = $null
    try { $defender = Get-MpComputerStatus -ErrorAction Stop } catch { }
    if ($defender) {
        $result.system.defender = [ordered]@{ realtime = $defender.RealTimeProtectionEnabled; antivirus = $defender.AntivirusEnabled }
        Log "Microsoft Defender: Echtzeitschutz=$($defender.RealTimeProtectionEnabled) (wird nicht verändert)"
    }

    $existing = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        $existing += Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'ClamAV*' }
    }
    foreach ($e in $existing) { Log "Vorhanden: $($e.DisplayName) $($e.DisplayVersion) $($e.InstallLocation)" }
    $onPath = Get-Command clamscan.exe -ErrorAction SilentlyContinue
    if ($onPath) { Log "clamscan im PATH gefunden: $($onPath.Source) (AXSafe nutzt den PATH nicht)" }
    $result.existing = @($existing | ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" })
    $installed = $existing | Where-Object { $_.DisplayVersion -eq $Version }

    # --- 2./3. Paket prüfen und installieren -------------------------------
    if ($installed -and (Test-Path (Join-Path $InstallDir 'clamscan.exe'))) {
        Log "ClamAV $Version ist bereits installiert – keine Neuinstallation."
    } else {
        $dl = Join-Path $env:TEMP "axsafe-clamav-$stamp"
        New-Item -ItemType Directory -Force -Path $dl | Out-Null
        $msi = Join-Path $dl $MsiName
        Log "Lade $MsiUrl"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $MsiUrl -OutFile $msi -UseBasicParsing
        Invoke-WebRequest -Uri "$MsiUrl.sig" -OutFile "$msi.sig" -UseBasicParsing
        $hash = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant()
        Check 'paket_sha256' ($hash -eq $MsiSha256.ToLowerInvariant()) "SHA-256 $hash (erwartet $MsiSha256)"
        if ($hash -ne $MsiSha256.ToLowerInvariant()) { throw 'Paket weicht vom geprüften Stand ab – Abbruch ohne Installation.' }
        $cands = @("$env:ProgramFiles\Git\usr\bin\gpg.exe", "${env:ProgramFiles(x86)}\GnuPG\bin\gpg.exe", "$env:ProgramFiles\GnuPG\bin\gpg.exe")
        $gc = Get-Command gpg.exe -ErrorAction SilentlyContinue
        if ($gc) { $cands = @($gc.Source) + $cands }
        $gpg = $cands | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if ($gpg) {
            # gpg aus Git für Windows (MSYS) erwartet Pfade wie /d/a/x; GnuPG für
            # Windows versteht beide Formen nicht immer gleich. Deshalb je nach
            # Herkunft umwandeln.
            $msys = $gpg -like '*\Git\usr\bin\gpg.exe'
            function GPath([string]$p) {
                if ($msys -and $p -match '^([A-Za-z]):\\(.*)$') { return '/' + $Matches[1].ToLower() + '/' + ($Matches[2] -replace '\\', '/') }
                return $p
            }
            $home2 = Join-Path $dl 'gnupg'; New-Item -ItemType Directory -Force -Path $home2 | Out-Null
            $h = GPath $home2
            $keyFile = GPath (Join-Path $PSScriptRoot 'talos-clamav-signing-key.asc')
            $imp = Run $gpg @('--batch', '--homedir', $h, '--import', $keyFile)
            Log "gpg --import (Exitcode $($imp.Code)): $($imp.Err.Trim() -replace '\r?\n', ' | ')"
            $v = Run $gpg @('--batch', '--homedir', $h, '--status-fd', '1', '--verify', (GPath "$msi.sig"), (GPath $msi))
            $ok = ($v.Code -eq 0) -and ($v.Out -match "VALIDSIG $TalosFingerprint")
            Check 'paket_pgp' $ok "Talos-Signatur (gpg: $gpg): $(if ($ok) { 'gültig, Fingerabdruck ' + $TalosFingerprint } else { $v.Out + $v.Err })"
            if (-not $ok) { throw 'PGP-Signatur ungültig – Abbruch ohne Installation.' }
        } else {
            Check 'paket_pgp' $true 'gpg nicht vorhanden – Prüfung über die festgelegte SHA-256 (vom Projekt nach PGP-Prüfung festgelegt)'
        }
        $auth = Get-AuthenticodeSignature $msi
        Log "Authenticode des MSI: $($auth.Status) (ClamAV signiert Windows-Pakete nicht mit Authenticode)"
        Log "Installiere $MsiName nach $InstallDir"
        $msiLog = Join-Path $EvidenceDir "clamav-msi-$stamp.log"
        $p = Start-Process msiexec.exe -ArgumentList @('/i', "`"$msi`"", '/qn', '/norestart', '/l*v', "`"$msiLog`"") -Wait -PassThru
        Check 'installation' ($p.ExitCode -in 0, 3010) "msiexec Exitcode $($p.ExitCode)"
        if ($p.ExitCode -notin 0, 3010) { throw 'Installation fehlgeschlagen' }
        Remove-Item -Recurse -Force $dl
    }
    $clamscan = Join-Path $InstallDir 'clamscan.exe'
    $freshclam = Join-Path $InstallDir 'freshclam.exe'
    if (-not (Test-Path $clamscan) -or -not (Test-Path $freshclam)) { throw "clamscan/freshclam fehlen in $InstallDir" }

    # --- 4. Geschützte Datenordner -----------------------------------------
    foreach ($d in $DataRoot, $DbDir, $LogDir, $StateDir) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    # Vererbung aus ProgramData (Benutzer dürften dort Dateien anlegen) entfernen.
    & icacls.exe $DataRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    & icacls.exe $DataRoot /setowner '*S-1-5-32-544' /T /C | Out-Null
    # Prüfen: Benutzer, Authentifizierte Benutzer und Jeder haben kein Schreibrecht.
    $weak = @()
    foreach ($d in $DataRoot, $DbDir, $LogDir, $StateDir) {
        foreach ($rule in (Get-Acl $d).Access) {
            $sid = try { $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
            if ($sid -in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0' -and $rule.AccessControlType -eq 'Allow' -and
                ($rule.FileSystemRights -band ([Security.AccessControl.FileSystemRights]'Write, Delete, ChangePermissions, TakeOwnership'))) {
                $weak += "$d -> $($rule.IdentityReference) $($rule.FileSystemRights)"
            }
        }
    }
    Check 'datenordner_acl' ($weak.Count -eq 0) $(if ($weak) { 'Schreibrechte für Benutzer: ' + ($weak -join '; ') } else { "${DataRoot}: nur SYSTEM/Administratoren schreiben, Benutzer lesen" })

    # AXSafe startet clamscan mit eingeschränktem Token (Integrität Niedrig,
    # Einschränkungs-SIDs RESTRICTED/Jeder/Benutzer). Ein AppContainer ist für
    # ClamAV 1.5 nicht möglich (Zertifikatsordner nicht auflösbar, in CI
    # gemessen). Lesen genügt über "Benutzer: Lesen" auf Programm- und
    # Datenbankordner – keine zusätzlichen Rechte.
    # Frühere Einrichtungen gaben einem AppContainer Leserecht; das wird
    # nicht mehr gebraucht und entfernt.
    $acSid = 'S-1-15-2-437281945-175377220-1217961313-1461987920-2239197068-1208018344-3536562919'
    foreach ($d in $DbDir, $InstallDir) {
        if (((& icacls.exe $d) -join ' ') -match [regex]::Escape($acSid)) {
            & icacls.exe $d /remove:g "*$acSid" | Out-Null
            Log "Nicht mehr benötigtes AppContainer-Leserecht entfernt: $d"
        }
    }
    $usersRead = { param($dir) @((Get-Acl $dir).Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-545' -and (($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute) }).Count -gt 0 }
    Check 'eingeschraenkt_lesbar' ((& $usersRead $DbDir) -and (& $usersRead (Join-Path $InstallDir 'certs'))) "Benutzer (und damit das eingeschränkte Token) lesen $DbDir und $InstallDir\certs"

    # Netzwerk: Das eingeschränkte Token sperrt kein Netzwerk. Ausgehende
    # Verbindungen von clamscan.exe sperrt eine eigene Firewall-Regel
    # (freshclam.exe ist ein anderes Programm und bleibt erlaubt).
    $fwName = 'AXSafe: clamscan ohne Netzwerk'
    Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $fwName -Direction Outbound -Action Block -Program $clamscan -Profile Any -Description 'AXSafe: clamscan prüft nur übergebene Daten und braucht kein Netzwerk.' | Out-Null
    $fw = Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue
    $fwApp = if ($fw) { ($fw | Get-NetFirewallApplicationFilter).Program } else { '' }
    $fwOn = (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -eq 0
    Check 'firewall_clamscan' ($fw -and $fw.Enabled -eq 'True' -and $fw.Action -eq 'Block' -and $fwApp -eq $clamscan) "Ausgehend gesperrt: $fwApp (Regel '$fwName'; Firewall-Profile alle aktiv: $fwOn)"
    if (-not $fwOn) { Log 'WARNUNG: Mindestens ein Firewall-Profil ist ausgeschaltet – dort wirkt die Sperrregel nicht.' }

    # --- 5. FreshClam-Konfiguration ----------------------------------------
    if (Test-Path $ConfFile) {
        $bak = "$ConfFile.bak-$stamp"
        Copy-Item $ConfFile $bak
        Log "Vorhandene freshclam.conf gesichert: $bak"
    }
    foreach ($legacy in (Join-Path $InstallDir 'freshclam.conf')) {
        if (Test-Path $legacy) { Log "Hinweis: $legacy existiert und bleibt unverändert; AXSafe nutzt $ConfFile ausdrücklich." }
    }
    @(
        '# AXSafe: FreshClam-Konfiguration (offizielle ClamAV-Signaturen).',
        '# Erzeugt von scripts/windows/setup-clamav.ps1. Änderungen bitte dort.',
        "DatabaseDirectory $DbDir",
        "UpdateLogFile $(Join-Path $LogDir 'freshclam.log')",
        'LogTime yes',
        'LogFileMaxSize 2M',
        'LogRotate yes',
        'DatabaseMirror database.clamav.net',
        'ConnectTimeout 30',
        'ReceiveTimeout 300',
        'TestDatabases yes',
        'Bytecode yes'
    ) | Set-Content -Path $ConfFile -Encoding ASCII
    Copy-Item (Join-Path $PSScriptRoot 'update-clamav-signatures.ps1') $Updater -Force

    # --- Signaturen laden (über denselben Ablauf wie der geplante Auftrag) ---
    $u1 = Run 'powershell.exe' @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Updater)
    Add-Content -Path $ReportFile -Value $u1.Out -Encoding UTF8
    $state = Get-Content (Join-Path $StateDir 'last-update.json') -Raw | ConvertFrom-Json
    Check 'b_erstes_update' ($state.result -in 'updated', 'up_to_date') "Ergebnis $($state.result), Exitcode $($state.exit_code), $($state.message)"
    $db = @(DbState)
    $result.database = $db
    $daily = $db | Where-Object { $_.File -like 'daily.*' }
    Check 'b_datenbank' ($null -ne $daily -and @($db).Count -ge 2) (($db | ForEach-Object { "$($_.File) v$($_.Version) ($($_.Signatures) Signaturen, $($_.Built))" }) -join '; ')

    # --- a) Versionen -------------------------------------------------------
    $cv = Run $clamscan @("--database=$DbDir", '--version')
    $fv = Run $freshclam @("--config-file=$ConfFile", '--version')
    $result.versions = [ordered]@{ clamscan = $cv.Out.Trim(); freshclam = $fv.Out.Trim() }
    Check 'a_versionen' ($cv.Code -eq 0 -and $cv.Out -match "ClamAV $([regex]::Escape($Version))") "clamscan: $($cv.Out.Trim()) | freshclam: $($fv.Out.Trim())"

    # --- c) harmlose Datei, d) EICAR ----------------------------------------
    $t = Join-Path $env:TEMP ("axsafe-clamav-selbsttest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $t | Out-Null
    try {
        $benign = Join-Path $t 'brief.txt'
        Set-Content -Path $benign -Value 'Sehr geehrte Damen und Herren, dies ist eine harmlose Testdatei.' -Encoding UTF8
        $r = Run $clamscan @("--database=$DbDir", '--no-summary', $benign)
        Check 'c_harmlos' ($r.Code -eq 0) "Exitcode $($r.Code): $($r.Out.Trim())"

        # EICAR nur zur Laufzeit aus zwei Teilen, über stdin – keine Datei.
        $eicar = [Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        $r = Run $clamscan @("--database=$DbDir", '--no-summary', '-') $eicar
        Check 'd_eicar_stdin' ($r.Code -eq 1 -and $r.Out -match 'FOUND') "Exitcode $($r.Code): $($r.Out.Trim())"
        if ($r.Code -ne 1) {
            # Diagnose (nur bei Fehlschlag): Wie viele Bytes kamen über stdin an, was hat clamscan geprüft?
            $dbg = Run $clamscan @("--database=$DbDir", '--debug', '-') $eicar
            $lines = (($dbg.Out + "`n" + $dbg.Err) -split "`r?`n") | Where-Object { $_ -match 'Data read|Data scanned|Scanning|stdin|size|tmp|temp|Infected|FOUND|ERROR' } | Select-Object -First 25
            Log ("Diagnose stdin (Exitcode $($dbg.Code)): " + ($lines -join ' | '))
        }

        if (-not $SkipFileEicar) {
            $ef = Join-Path $t 'eicar-test.com'
            $wrote = $true
            try { [IO.File]::WriteAllBytes($ef, $eicar) } catch { $wrote = $false; Log "EICAR-Datei: Schreiben verweigert ($($_.Exception.Message)) – vermutlich Defender." }
            Start-Sleep -Seconds 3
            if ($wrote -and (Test-Path $ef)) {
                $r = Run $clamscan @("--database=$DbDir", '--no-summary', $ef)
                if ($r.Code -eq 1) {
                    Check 'd_eicar_datei' $true "Exitcode 1: $($r.Out.Trim())"
                } elseif ($r.Out -match 'Access denied|denied|cannot|Can.t open' -or -not (Test-Path $ef)) {
                    Check 'd_eicar_datei' $true "Datei während der Prüfung von Defender gesperrt/entfernt (erwartet bei aktivem Defender): $($r.Out.Trim()) $($r.Err.Trim())"
                } else {
                    Check 'd_eicar_datei' $false "Exitcode $($r.Code): $($r.Out.Trim()) $($r.Err.Trim())"
                }
            } else {
                Check 'd_eicar_datei' $true 'Defender hat die EICAR-Datei vor der ClamAV-Prüfung abgefangen (erwartet; Defender bleibt aktiv). Engine-Nachweis über stdin (d_eicar_stdin).'
            }
        }
    } finally {
        Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue
        Check 'testdaten_entfernt' (-not (Test-Path $t)) $t
    }

    # --- 6. Geplanter Auftrag ----------------------------------------------
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Updater`""
    $t1 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15) -RepetitionInterval (New-TimeSpan -Hours 4)
    $t1.RandomDelay = 'PT20M'
    $t2 = New-ScheduledTaskTrigger -AtStartup
    $t2.Delay = 'PT10M'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) { Log "Geplanter Auftrag '$TaskName' existiert – wird mit gleicher Definition aktualisiert." }
    Register-ScheduledTask -TaskName $TaskName -Description 'AXSafe: ClamAV-Signaturen über FreshClam aktualisieren (offizielle Quellen). Status: %ProgramData%\AXSafe\ClamAV\state\last-update.json' -Action $action -Trigger @($t1, $t2) -Principal $principal -Settings $settings -Force | Out-Null

    # f) erneuter Updateaufruf direkt
    $u2 = Run 'powershell.exe' @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Updater)
    $state2 = Get-Content (Join-Path $StateDir 'last-update.json') -Raw | ConvertFrom-Json
    Check 'f_erneutes_update' ($state2.result -in 'updated', 'up_to_date') "Ergebnis $($state2.result), letzte Erfolgszeit $($state2.last_success_utc)"

    # g) geplanten Auftrag tatsächlich ausführen
    $before = $state2.last_attempt_utc
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddMinutes(10)
    do { Start-Sleep -Seconds 5; $info = Get-ScheduledTaskInfo -TaskName $TaskName; $task = Get-ScheduledTask -TaskName $TaskName }
    while ($task.State -eq 'Running' -and (Get-Date) -lt $deadline)
    $state3 = Get-Content (Join-Path $StateDir 'last-update.json') -Raw | ConvertFrom-Json
    $ran = $state3.last_attempt_utc -ne $before
    Check 'g_geplanter_auftrag' ($info.LastTaskResult -eq 0 -and $ran -and $state3.result -in 'updated', 'up_to_date') "LastTaskResult $($info.LastTaskResult), Lauf um $($state3.last_attempt_utc), Ergebnis $($state3.result), nächster Lauf $($info.NextRunTime)"

    # --- e) AXSafe ----------------------------------------------------------
    if ($AxsafeCli -and (Test-Path $AxsafeCli)) {
        $ax = Run $AxsafeCli @('engines', '--json')
        $engines = $ax.Out | ConvertFrom-Json
        $c = $engines | Where-Object { $_.name -eq 'clamav' }
        $ok = $c -and $c.health.state -eq 'ready' -and $c.content_kind -eq 'official_signatures'
        Check 'e_axsafe' $ok "axsafe engines: clamav=$($c.health.state) $($c.content_kind) $($c.content_version) – $($c.content_note) $($c.health.reason)"
        Check 'e_axsafe_abschottung' ($c -and $c.isolation.enforced) "ClamAV-Isolation: $($c.isolation.kind) / $($c.isolation.detail)"
        $running = Get-Process AXSafe -ErrorAction SilentlyContinue
        if ($running) { Log 'Hinweis: Die AXSafe-Oberfläche läuft bereits; sie prüft Engines beim Start – bitte neu starten.' }
    } else {
        Check 'e_axsafe' $false "axsafe.exe nicht angegeben oder nicht gefunden ('$AxsafeCli') – Abnahme e) nicht ausgeführt"
    }
} catch {
    Log "ABBRUCH: $($_.Exception.Message)"
    $result.error = $_.Exception.Message
} finally {
    Save
    $failed = @($result.checks.GetEnumerator() | Where-Object { -not $_.Value.ok }).Count
    Log ("Fertig: {0} Prüfungen, {1} fehlgeschlagen{2}. Bericht: {3}" -f $result.checks.Count, $failed, $(if ($result.Contains('error')) { ', ABGEBROCHEN' } else { '' }), $ReportFile)
}
if ($result.Contains('error') -or @($result.checks.GetEnumerator() | Where-Object { -not $_.Value.ok }).Count -gt 0) { exit 1 }
exit 0
