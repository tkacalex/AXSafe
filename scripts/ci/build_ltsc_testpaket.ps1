<#
.SYNOPSIS
  Baut das LTSC-Testpaket (B-02/B-10): alle Rust-Testprogramme im
  Release-Profil, gebaut unter C:\axsafe-ltsc (die Programme enthalten diese
  Pfade fest), samt benötigtem Quellbaum (Regeln, Testdaten) und Startskript.
  Ergebnis: <Out>\axsafe-ltsc-testpaket.zip
#>
param([Parameter(Mandatory = $true)][string]$Out, [string]$Commit = '', [string]$RunId = '')
$ErrorActionPreference = 'Stop'
$Root = 'C:\axsafe-ltsc'
$src = Join-Path $Root 'src'
if (Test-Path $Root) { Remove-Item -Recurse -Force $Root }
New-Item -ItemType Directory -Force -Path $src | Out-Null
& robocopy.exe (Get-Location).Path $src /E /XD .git target ui\AXSafe.Desktop\bin ui\AXSafe.Desktop\obj /NFL /NDL /NJH /NJS | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy fehlgeschlagen ($LASTEXITCODE)" }
$env:CARGO_TARGET_DIR = Join-Path $Root 'target'
Push-Location $src
try {
    $json = cargo test --release --locked --workspace --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'cargo test --no-run fehlgeschlagen' }
    cargo build --release --locked --workspace --bins
    if ($LASTEXITCODE -ne 0) { throw 'cargo build fehlgeschlagen' }
} finally { Pop-Location }
$tests = @()
foreach ($l in $json) {
    if ($l -notmatch '"reason":"compiler-artifact"') { continue }
    $a = $l | ConvertFrom-Json
    if ($a.profile.test -and $a.executable) {
        $rel = $a.executable.Substring($Root.Length + 1)
        $crate = (($a.package_id -replace '#.*$', '') -split '[/\\]')[-1]
        $tests += [ordered]@{ name = "$crate/$($a.target.name)"; path = $rel }
    }
}
if ($tests.Count -lt 10) { throw "zu wenige Testprogramme gefunden: $($tests.Count)" }
[ordered]@{ commit = $Commit; run_id = $RunId; built_utc = (Get-Date).ToUniversalTime().ToString('s') + 'Z'; tests = $tests } |
    ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Root 'manifest.json') -Encoding UTF8
Copy-Item (Join-Path $src 'scripts\ltsc\*') $Root
# Paket: Quellbaum (ohne Build-Ausgabe), Programme und Testprogramme.
$stage = Join-Path $env:RUNNER_TEMP 'ltsc-stage\axsafe-ltsc'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path "$stage\target\release\deps" | Out-Null
& robocopy.exe $src "$stage\src" /E /NFL /NDL /NJH /NJS | Out-Null
Copy-Item (Join-Path $Root '*.json'), (Join-Path $Root '*.ps1'), (Join-Path $Root '*.cmd'), (Join-Path $Root '*.txt') $stage
Get-ChildItem (Join-Path $Root 'target\release') -Filter *.exe | Copy-Item -Destination "$stage\target\release"
foreach ($t in $tests) { Copy-Item (Join-Path $Root $t.path) (Join-Path $stage $t.path) }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$zip = Join-Path $Out 'axsafe-ltsc-testpaket.zip'
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal
Write-Host "LTSC-Testpaket: $zip ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB), $($tests.Count) Testprogramme"
# robocopy meldet 1 = "Dateien kopiert"; das ist kein Fehler.
exit 0
