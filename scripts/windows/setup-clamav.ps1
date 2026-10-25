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
    [switch]$SkipFileEicar,
    # Fenster am Ende offen halten (Start per Doppelklick über ClamAV-einrichten.cmd).
    [switch]$Pause
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Pfad normalisieren: Der Starter übergibt '...\scripts\windows\..\..\cli\axsafe.exe'.
# Firewall-Regeln sollen den echten Programmpfad tragen, nicht einen mit '..'
# (auf dem Zielrechner am 25.10.2026 so beobachtet).
if ($AxsafeCli) { $AxsafeCli = [IO.Path]::GetFullPath($AxsafeCli) }
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
    # axsafe.exe schreibt UTF-8; ohne diese Angabe entstünden Umlautfehler im Bericht.
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
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
    # Ob das eingeschränkte Token Datenbank, Zertifikate und Arbeitsordner
    # wirklich nutzen kann, prüft AXSafe weiter unten MIT DIESEM TOKEN
    # (axsafe clamav-abschottung) – nicht anhand von ACL-Einträgen.

    # Netzwerk: Das eingeschränkte Token sperrt kein Netzwerk. Ausgehende
    # Verbindungen von clamscan.exe sperrt eine eigene Firewall-Regel
    # (freshclam.exe ist ein anderes Programm und bleibt erlaubt).
    $fwName = 'AXSafe: clamscan ohne Netzwerk'
    Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $fwName -Direction Outbound -Action Block -Program $clamscan -Profile Any -Description 'AXSafe: clamscan prüft nur übergebene Daten und braucht kein Netzwerk.' | Out-Null
    $fw = @(Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue)
    $fwApp = if ($fw.Count -eq 1) { ($fw[0] | Get-NetFirewallApplicationFilter).Program } else { '' }
    Check 'firewall_regel_clamscan' ($fw.Count -eq 1 -and "$($fw[0].Enabled)" -eq 'True' -and "$($fw[0].Action)" -eq 'Block' -and "$($fw[0].Direction)" -eq 'Outbound' -and $fwApp -eq $clamscan) "Regel '$fwName': ausgehend gesperrt für $fwApp"
    # Eine Regel wirkt nur in eingeschalteten Profilen. AXSafe schaltet die
    # Firewall NICHT selbst ein; ein ausgeschaltetes Profil ist ein Fehler.
    $profiles = @(Get-NetFirewallProfile)
    $off = @($profiles | Where-Object { "$($_.Enabled)" -ne 'True' } | ForEach-Object { $_.Name })
    Check 'firewall_profile_aktiv' ($profiles.Count -gt 0 -and $off.Count -eq 0) $(if ($off.Count -gt 0) { "Ausgeschaltete Firewall-Profile: $($off -join ', ') – dort wirkt die Sperrregel NICHT. Bitte in den Windows-Sicherheitseinstellungen einschalten." } else { 'Domäne, Privat und Öffentlich eingeschaltet' })
    $fc = @(Get-NetFirewallApplicationFilter -Program $freshclam -ErrorAction SilentlyContinue | Get-NetFirewallRule | Where-Object { "$($_.Action)" -eq 'Block' -and "$($_.Direction)" -eq 'Outbound' -and "$($_.Enabled)" -eq 'True' })
    Check 'freshclam_nicht_gesperrt' ($fc.Count -eq 0) $(if ($fc.Count) { 'Sperrregel für freshclam.exe: ' + (($fc | ForEach-Object { $_.DisplayName }) -join ', ') } else { 'keine ausgehende Sperrregel für freshclam.exe' })

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

        # d) Fund durch die echte ClamAV-Engine, unabhängig von Defender:
        # harmlose Zufallsdatei + eigene Testsignatur (MD5), zusammen mit den
        # offiziellen Signaturen geladen. Datei- und stdin-Weg (stdin nutzt
        # AXSafe).
        $probe = Join-Path $t 'axsafe-selbsttest.txt'
        Set-Content -Path $probe -Value ("AXSafe Selbsttest " + [guid]::NewGuid().ToString('N')) -Encoding ASCII
        $pb = [IO.File]::ReadAllBytes($probe)
        $md5 = ([BitConverter]::ToString([Security.Cryptography.MD5]::Create().ComputeHash($pb)) -replace '-', '').ToLowerInvariant()
        $hdb = Join-Path $t 'axsafe-selbsttest.hdb'
        Set-Content -Path $hdb -Value "${md5}:$($pb.Length):AXSafe.Selbsttest" -Encoding ASCII
        $r = Run $clamscan @("--database=$DbDir", "--database=$hdb", '--no-summary', $probe)
        Check 'd_engine_fund_datei' ($r.Code -eq 1 -and $r.Out -match 'AXSafe\.Selbsttest(\.UNOFFICIAL)? FOUND') "Exitcode $($r.Code): $($r.Out.Trim())"
        $r = Run $clamscan @("--database=$DbDir", "--database=$hdb", '--no-summary', '-') $pb
        $stdinOk = ($r.Code -eq 1 -and $r.Out -match 'stdin: AXSafe\.Selbsttest(\.UNOFFICIAL)? FOUND')
        Check 'd_engine_fund_stdin' $stdinOk "Exitcode $($r.Code): $($r.Out.Trim())"

        # EICAR nur zur Laufzeit aus zwei Teilen. Bei aktivem Defender kann
        # Defender die Daten abfangen, bevor ClamAV sie liest (clamscan legt
        # stdin als temporäre Datei ab). Das ist KEIN Erfolg von ClamAV und
        # KEIN Fehler der Einrichtung: Es wird nur dann als "von Defender
        # abgefangen" gewertet, wenn Defender selbst die EICAR-Erkennung
        # protokolliert UND der stdin-Weg mit der harmlosen Testsignatur geht.
        $eicar = [Text.Encoding]::ASCII.GetBytes('X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        # Vorhandene Defender-Erkennungen merken; danach zählen nur NEUE.
        $knownDet = @{}
        try { Get-MpThreatDetection -ErrorAction Stop | ForEach-Object { $knownDet["$($_.DetectionID)"] = 1 } } catch { }
        $outs = @()
        $r = Run $clamscan @("--database=$DbDir", '--no-summary', '-') $eicar
        $outs += "stdin: Exitcode $($r.Code): $($r.Out.Trim()) $($r.Err.Trim())"
        $found = ($r.Code -eq 1 -and $r.Out -match 'Eicar.*FOUND')
        if (-not $found -and -not $SkipFileEicar) {
            $ef = Join-Path $t 'eicar-test.com'
            try { [IO.File]::WriteAllBytes($ef, $eicar) } catch { $outs += "Datei: Schreiben verweigert ($($_.Exception.Message))" }
            Start-Sleep -Seconds 3
            if (Test-Path $ef) {
                $r = Run $clamscan @("--database=$DbDir", '--no-summary', $ef)
                $outs += "Datei: Exitcode $($r.Code): $($r.Out.Trim()) $($r.Err.Trim())"
                $found = ($r.Code -eq 1 -and $r.Out -match 'Eicar.*FOUND')
            } else {
                $outs += 'Datei: vor der Prüfung entfernt'
            }
        }
        if ($found) {
            Check 'd_eicar' $true ("ClamAV erkennt EICAR – " + ($outs -join ' | '))
        } else {
            $mp = @()
            # Defender protokolliert mit Verzögerung: bis zu 20 s nachsehen.
            for ($k = 0; $k -lt 10 -and $mp.Count -eq 0; $k++) {
                Start-Sleep -Seconds 2
                try {
                    $mp = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { -not $knownDet.ContainsKey("$($_.DetectionID)") } |
                        ForEach-Object { $id = $_.ThreatID; $n = (Get-MpThreat -ThreatID $id -ErrorAction SilentlyContinue).ThreatName; "$n ($($_.InitialDetectionTime.ToString('HH:mm:ss')), $(@($_.Resources) -join ', '))" } |
                        Where-Object { $_ -match 'EICAR' })
                } catch { $outs += "Defender-Protokoll nicht lesbar: $($_.Exception.Message)"; break }
            }
            if ($mp.Count -gt 0 -and $stdinOk) {
                $result.defender_abgefangen = @($mp)
                Log ("HINWEIS d_eicar: Von Microsoft Defender abgefangen, bevor ClamAV die Daten lesen konnte. Defender meldet: " + ($mp -join '; ') + ". ClamAV-Erkennung von EICAR ist auf diesem PC deshalb nicht nachweisbar (Nachweis: Windows-CI ohne Defender-Echtzeitschutz). Engine-Fund mit Testsignatur: siehe d_engine_fund_*. Ausgaben: " + ($outs -join ' | '))
            } else {
                Check 'd_eicar' $false ("weder ClamAV-Fund noch protokollierte Defender-Erkennung – " + ($outs -join ' | '))
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
        # B-18: dauerhaft geladene Engine im eigenen Worker. Wie clamscan
        # braucht er kein Netzwerk: eigene ausgehende Sperrregel.
        $clamWorker = Join-Path (Split-Path $AxsafeCli) 'axsafe-clamav-worker.exe'
        if (Test-Path $clamWorker) {
            $wfName = 'AXSafe: ClamAV-Worker ohne Netzwerk'
            Get-NetFirewallRule -DisplayName $wfName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            New-NetFirewallRule -DisplayName $wfName -Direction Outbound -Action Block -Program $clamWorker -Profile Any -Description 'AXSafe: Der ClamAV-Worker prüft nur übergebene Daten und braucht kein Netzwerk.' | Out-Null
            $wf = @(Get-NetFirewallRule -DisplayName $wfName -ErrorAction SilentlyContinue)
            $wfApp = if ($wf.Count -eq 1) { ($wf[0] | Get-NetFirewallApplicationFilter).Program } else { '' }
            Check 'firewall_regel_clamav_worker' ($wf.Count -eq 1 -and "$($wf[0].Enabled)" -eq 'True' -and "$($wf[0].Action)" -eq 'Block' -and "$($wf[0].Direction)" -eq 'Outbound' -and $wfApp -eq $clamWorker) "Regel '$wfName': ausgehend gesperrt für $wfApp"
        } else {
            Check 'firewall_regel_clamav_worker' $false "axsafe-clamav-worker.exe fehlt neben $AxsafeCli – dauerhaft geladene Engine nicht verfügbar"
        }
        $ax = Run $AxsafeCli @('engines', '--json', '--clamav-modus', 'dauerhaft')
        $engines = $ax.Out | ConvertFrom-Json
        $c = $engines | Where-Object { $_.name -eq 'clamav' }
        $ok = $c -and $c.health.state -eq 'ready' -and $c.content_kind -eq 'official_signatures'
        Check 'e_axsafe' $ok "axsafe engines (dauerhaft): clamav=$($c.health.state) $($c.content_kind) $($c.content_version) – $($c.content_note) $(if ($c -and $c.health.PSObject.Properties['reason']) { $c.health.reason })"
        Check 'e_axsafe_abschottung' ($c -and $c.isolation.enforced) "ClamAV-Worker-Isolation: $($c.isolation.kind) / $($c.isolation.detail)"
        $axc = Run $AxsafeCli @('engines', '--json', '--clamav-modus', 'clamscan')
        $cc = ($axc.Out | ConvertFrom-Json) | Where-Object { $_.name -eq 'clamav' }
        Check 'e_axsafe_clamscan' ($cc -and $cc.health.state -eq 'ready' -and $cc.isolation.enforced) "axsafe engines (clamscan je Objekt): clamav=$($cc.health.state) $($cc.content_version) / $($cc.isolation.detail)"

        # Mit GENAU dem Token, das clamscan bekommt: Datenbank und Zertifikate
        # lesbar, eigener Arbeitsordner beschreibbar, Benutzerdateien und
        # Programmordner nicht.
        $pr = Run $AxsafeCli @('clamav-abschottung', '--json', '--clamscan', $clamscan, '--clamav-db', $DbDir)
        $pj = $null; try { $pj = $pr.Out | ConvertFrom-Json } catch { }
        foreach ($k in @($(if ($pj) { $pj.checks } else { @() }))) {
            Check ("token_" + $k.id) ([bool]$k.ok) ("{0}: {1} (erwartet {2}) – {3}" -f $k.probe, $(if ($k.allowed) { 'erlaubt' } else { 'verweigert' }), $(if ($k.expected_allowed) { 'erlaubt' } else { 'verweigert' }), $k.detail)
        }
        Check 'token_probe_vollstaendig' ($pr.Code -eq 0 -and $pj -and $pj.ok -and @($pj.notes).Count -eq 0) ("Exitcode {0}; Hinweise: {1} {2}" -f $pr.Code, $(if ($pj) { @($pj.notes) -join '; ' } else { '' }), $pr.Err.Trim())

        # Netzsperre wirksam nachweisen. Die Firewall wirkt nicht auf
        # Loopback, deshalb ein echtes Ziel (das auch FreshClam nutzt). Die
        # Probe läuft mit demselben Token wie clamscan; eine vorübergehende,
        # gleich gebaute Regel für die Probe zeigt, dass die Regelart greift.
        $target = 'database.clamav.net:443'
        $probeExe = Join-Path (Split-Path $AxsafeCli) 'axsafe-worker.exe'
        $base = Run $AxsafeCli @('clamav-abschottung', '--json', '--nur-netz', '--netz-ziel', $target, '--netz-erwartet', 'erlaubt')
        $bj = $null; try { $bj = $base.Out | ConvertFrom-Json } catch { }
        $baseOpen = $bj -and @($bj.checks).Count -eq 1 -and $bj.checks[0].allowed
        $tmpRule = 'AXSafe: Probe Netzsperre (vorübergehend)'
        Get-NetFirewallRule -DisplayName $tmpRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        $kj = $null
        New-NetFirewallRule -DisplayName $tmpRule -Direction Outbound -Action Block -Program $probeExe -Profile Any | Out-Null
        try {
            Start-Sleep -Seconds 2
            $blk = Run $AxsafeCli @('clamav-abschottung', '--json', '--nur-netz', '--netz-ziel', $target, '--netz-erwartet', 'gesperrt')
            $kj = $null; try { $kj = $blk.Out | ConvertFrom-Json } catch { }
        } finally {
            Get-NetFirewallRule -DisplayName $tmpRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        }
        $blocked = $kj -and @($kj.checks).Count -eq 1 -and -not $kj.checks[0].allowed
        $detail = "ohne Regel: $(if ($bj -and @($bj.checks).Count) { $bj.checks[0].detail } else { 'keine Messung ' + (@($bj.notes) -join '; ') }) | mit gleich gebauter Regel: $(if ($kj -and @($kj.checks).Count) { $kj.checks[0].detail } else { 'keine Messung' })"
        if (-not $bj -or @($bj.checks).Count -ne 1) {
            Check 'netzsperre_wirksam' $false "Netzprüfung nicht ausführbar (Ziel $target nicht erreichbar oder nicht auflösbar): $detail"
        } elseif ($baseOpen) {
            Check 'netzsperre_wirksam' ($blocked -and (Test-Path $probeExe)) "Ziel $target – $detail"
        } else {
            Check 'netzsperre_wirksam' $blocked "Ziel $target bereits ohne Regel nicht erreichbar (Token oder Netz): $detail"
        }
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
    $intercept = if ($result.Contains('defender_abgefangen')) { '; EICAR von Defender abgefangen (siehe HINWEIS)' } else { '' }
    Log ("Fertig: {0} Prüfungen, {1} fehlgeschlagen{2}{3}. Bericht: {4}" -f $result.checks.Count, $failed, $intercept, $(if ($result.Contains('error')) { ', ABGEBROCHEN' } else { '' }), $ReportFile)
}
$bad = $result.Contains('error') -or @($result.checks.GetEnumerator() | Where-Object { -not $_.Value.ok }).Count -gt 0
if ($Pause) {
    Write-Host ''
    if ($bad) { Write-Host 'ERGEBNIS: NICHT ERFOLGREICH – Einzelheiten im Bericht (FEHL-Zeilen).' -ForegroundColor Red }
    else { Write-Host 'ERGEBNIS: ERFOLGREICH – alle Prüfungen bestanden.' -ForegroundColor Green }
    if ($result.Contains('defender_abgefangen')) { Write-Host 'Hinweis: Microsoft Defender hat den EICAR-Test abgefangen (erwartet bei aktivem Defender, siehe HINWEIS im Bericht).' -ForegroundColor Yellow }
    Write-Host "Bericht: $ReportFile"
    [void](Read-Host 'Eingabetaste drücken, um dieses Fenster zu schließen')
}
if ($bad) { exit 1 }
exit 0
