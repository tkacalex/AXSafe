<#
.SYNOPSIS
  Aktualisiert die ClamAV-Signaturen für AXSafe über FreshClam (offizielle
  Quellen) und schreibt den Zustand nach state\last-update.json.

.DESCRIPTION
  Läuft als geplanter Auftrag "AXSafe ClamAV Signaturupdate" (SYSTEM) und aus
  setup-clamav.ps1. Liegt in %ProgramData%\AXSafe\ClamAV (nur Administratoren
  und SYSTEM dürfen schreiben).
  * Überlappung: systemweites Mutex; ein zweiter Lauf endet sofort mit
    Ergebnis "already_running" (zusätzlich MultipleInstances=IgnoreNew).
  * Zeitgrenze: FreshClam wird nach 25 Minuten beendet (Auftrag: 30 Minuten).
  * Status: letzter Versuch, letzter Erfolg (bleibt bei Fehlern erhalten),
    Exitcode, Datenbankstände, Meldung. Protokoll: logs\freshclam.log.
  FreshClam-Exitcodes: 0 = aktualisiert, 1 = bereits aktuell, sonst Fehler.
#>
$ErrorActionPreference = 'Stop'
$root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$conf      = Join-Path $root 'freshclam.conf'
$dbDir     = Join-Path $root 'database'
$stateDir  = Join-Path $root 'state'
$stateFile = Join-Path $stateDir 'last-update.json'
$runLog    = Join-Path $root 'logs\update-runs.log'
$freshclam = Join-Path $env:ProgramFiles 'ClamAV\freshclam.exe'
New-Item -ItemType Directory -Force -Path $stateDir, (Split-Path $runLog) | Out-Null

function Header([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    $fs = [IO.File]::OpenRead($path)
    try { $b = New-Object byte[] 512; [void]$fs.Read($b, 0, 512) } finally { $fs.Dispose() }
    $f = [Text.Encoding]::ASCII.GetString($b).TrimEnd([char]0, ' ').Split(':')
    if ($f[0] -ne 'ClamAV-VDB') { return $null }
    [ordered]@{ file = (Split-Path $path -Leaf); built = $f[1]; version = [int]$f[2]; signatures = [int]$f[3] }
}
function DbVersions {
    $o = [ordered]@{}
    foreach ($n in 'main', 'daily', 'bytecode') {
        foreach ($ext in 'cld', 'cvd') {
            $h = Header (Join-Path $dbDir "$n.$ext")
            if ($h) { $o[$n] = $h; break }
        }
    }
    $o
}

$prev = $null
if (Test-Path $stateFile) { try { $prev = Get-Content $stateFile -Raw | ConvertFrom-Json } catch { } }
$state = [ordered]@{
    last_attempt_utc = (Get-Date).ToUniversalTime().ToString('o')
    last_success_utc = $(if ($prev -and $prev.PSObject.Properties['last_success_utc']) { $prev.last_success_utc } else { $null })
    result           = 'error'
    exit_code        = $null
    message          = ''
    databases        = $null
    run_as           = [Security.Principal.WindowsIdentity]::GetCurrent().Name
}

$mutex = New-Object System.Threading.Mutex($false, 'Global\AXSafe.ClamAV.FreshClam')
$have = $false
try {
    try { $have = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $have = $true }
    if (-not $have) {
        # Kein Statuswechsel: Der laufende Updater schreibt sein Ergebnis selbst.
        Add-Content $runLog "$($state.last_attempt_utc) übersprungen: anderer Updatelauf aktiv" -Encoding UTF8
        Write-Output 'already_running'
        exit 0
    }
    if (-not (Test-Path $freshclam)) { throw "freshclam.exe fehlt: $freshclam" }
    if (-not (Test-Path $conf)) { throw "Konfiguration fehlt: $conf" }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $freshclam
    $psi.Arguments = "--config-file=`"$conf`" --stdout"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEndAsync(); $err = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(25 * 60 * 1000)) {
        $p.Kill()
        throw 'FreshClam überschritt 25 Minuten und wurde beendet'
    }
    $p.WaitForExit()
    $state.exit_code = $p.ExitCode
    $text = ($out.Result + $err.Result).Trim()
    $state.message = (($text -split "`r?`n") | Where-Object { $_ -match 'ERROR|WARNING|updated|up.to.date|up-to-date|Database' } | Select-Object -Last 6) -join ' | '
    switch ($p.ExitCode) {
        0 { $state.result = 'updated' }
        1 { $state.result = 'up_to_date' }
        default { $state.result = 'error' }
    }
    $state.databases = DbVersions
    if ($state.result -ne 'error') {
        if (-not $state.databases.Contains('daily') -or -not $state.databases.Contains('main')) {
            $state.result = 'error'
            $state.message = "FreshClam meldete Erfolg, aber main/daily fehlen in $dbDir. " + $state.message
        } else {
            $state.last_success_utc = $state.last_attempt_utc
        }
    }
    Write-Output $text
} catch {
    $state.result = 'error'
    $state.message = $_.Exception.Message
    $state.databases = DbVersions
} finally {
    if ($have) {
        $state | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -Encoding UTF8
        Add-Content $runLog ("{0} {1} exit={2} daily={3} {4}" -f $state.last_attempt_utc, $state.result, $state.exit_code,
            $(if ($state.databases -and $state.databases.Contains('daily')) { $state.databases.daily.version } else { '-' }), $state.message) -Encoding UTF8
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
if ($state.result -eq 'error') { exit 2 }
exit 0
