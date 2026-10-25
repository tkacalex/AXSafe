# Stellt das Windows-Paket zusammen (CI und Release identisch).
# Erwartet: dotnet publish nach $Dist, target/release/axsafe.exe gebaut.
# Legt Lizenzhinweise bei (Befund 8): THIRD-PARTY-NOTICES.txt aus dem echten
# Abhängigkeitsgraphen der CLI und die Hinweise der mitgelieferten .NET-Laufzeit.
param([Parameter(Mandatory = $true)][string]$Dist)
$ErrorActionPreference = 'Stop'

# CLI in Unterordner: Windows unterscheidet axsafe.exe und AXSafe.exe nicht.
New-Item -ItemType Directory "$Dist/cli/rules" -Force | Out-Null
# axsafe-clamav-worker.exe lädt libclamav (GPL-2.0-only) aus der separat
# installierten ClamAV-Installation; ClamAV selbst wird NICHT mitgeliefert
# (docs/LICENSE-REVIEW-libclamav.md).
Copy-Item target/release/axsafe.exe, target/release/axsafe-worker.exe, target/release/axsafe-clamav-worker.exe, target/release/axsafe-service.exe "$Dist/cli/"
Copy-Item -Recurse rules/* "$Dist/cli/rules/"
# Einrichtungsskripte (Dienst, ClamAV) – laufen nur nach ausdrücklicher UAC-Bestätigung.
New-Item -ItemType Directory "$Dist/scripts/windows" -Force | Out-Null
Copy-Item scripts/windows/*.ps1, scripts/windows/*.cmd, scripts/windows/*.asc "$Dist/scripts/windows/"
if (-not (Test-Path "$Dist/AXSafe.dll")) { throw "Oberfläche fehlt im Paket" }
Copy-Item README.md, CHANGELOG.md, SECURITY.md $Dist
Get-ChildItem *.pdb -Path $Dist -Recurse | Remove-Item

python scripts/gen_third_party_notices.py x86_64-pc-windows-msvc "$Dist/THIRD-PARTY-NOTICES.txt"
if ($LASTEXITCODE -ne 0) { throw "Lizenzhinweise unvollständig" }

# Hinweise der tatsächlich eingebetteten .NET-Laufzeitpakete (self-contained):
# Versionen aus AXSafe.runtimeconfig.json, Dateien aus den NuGet-Runtime-Packs.
$cfg = Get-Content "$Dist/AXSafe.runtimeconfig.json" -Raw | ConvertFrom-Json
$nuget = $env:NUGET_PACKAGES
if (-not $nuget) { $nuget = Join-Path $HOME '.nuget/packages' }
foreach ($fw in $cfg.runtimeOptions.includedFrameworks) {
    $pack = Join-Path $nuget ("{0}.runtime.win-x64/{1}" -f $fw.name.ToLowerInvariant(), $fw.version)
    $files = Get-ChildItem $pack -File | Where-Object { $_.Name -match '^(LICENSE|THIRD-PARTY-NOTICES)' }
    if (-not $files) { throw "Keine Lizenzdateien im Runtime-Pack $pack" }
    $dst = "$Dist/licenses/dotnet/$($fw.name)"
    New-Item -ItemType Directory $dst -Force | Out-Null
    $files | Copy-Item -Destination $dst
    Set-Content "$dst/VERSION.txt" "$($fw.name) $($fw.version) (NuGet-Runtime-Pack win-x64)"
}
Write-Host "Paket zusammengestellt: $Dist"
